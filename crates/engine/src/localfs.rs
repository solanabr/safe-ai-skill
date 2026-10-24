//! Filesystem lookups for paths the gates take from tool input.
//!
//! On Windows a UNC path (`\\host\share\…`, also `//host/share/…`, `\\?\UNC\…`, `\\.\UNC\…`
//! and `\\?\GLOBALROOT\Device\Mup\…`, any case) is a network share: touching it makes Windows
//! contact `host` (SMB, then WebDAV), which can take longer than the gate's deadline and hands
//! the host the user's NTLM credentials. Model-chosen words spell such paths easily:
//! `git clone https://h/x` carries `//h/x`, and `npm config set //registry.npmjs.org/:_authToken`
//! one too. So a share is looked up only when it is this machine (`localhost`, `127.x.x.x`,
//! `::1`, `%COMPUTERNAME%`, `wsl$`, `wsl.localhost`) or one the session already lives on: the
//! hook payload's `cwd` ([`trust_share_of`]), `HOME`, `USERPROFILE`, `CLAUDE_PROJECT_DIR`,
//! `CLAUDE_PLUGIN_DATA`, `CLAUDE_CONFIG_DIR`, the process working dir, a configured wallet, or
//! a share a local spelling (a mapped drive letter, a symlink) already resolved onto.
//!
//! A refused lookup is **unknown, not missing**: it fails with [`io::ErrorKind::Other`] (never
//! `NotFound`), so callers that fail closed on an unreadable file still do, and [`is_foreign`]
//! lets a gate pick its unknown-path verdict. Off Windows these are the `std::fs` calls they wrap.

use std::borrow::Cow;
use std::fs::{Metadata, ReadDir};
use std::io;
use std::path::{Path, PathBuf};

/// Trust the share `path` lies on (the hook payload's `cwd`, a configured wallet). No effect
/// off Windows or for a local path.
pub fn trust_share_of(path: &Path) {
    imp::trust(path);
}

/// Whether `path` is on a network share that is not looked up (never off Windows).
pub fn is_foreign(path: &Path) -> bool {
    imp::is_foreign(path)
}

/// Whether `err` is a refused lookup (see the module docs).
pub fn is_refused(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::Other && err.to_string().ends_with(REFUSED)
}

const REFUSED: &str = "network share not looked up";

fn refused(path: &Path) -> io::Error {
    io::Error::other(format!("{}: {REFUSED}", path.display()))
}

/// [`std::fs::canonicalize`], refusing a foreign share. A local spelling that resolves onto a
/// share (a mapped drive, a symlink) has already reached it, so that share is trusted from then
/// on and the resolved path can be read like the spelling.
pub fn canonicalize(path: impl AsRef<Path>) -> io::Result<PathBuf> {
    let path = path.as_ref();
    if is_foreign(path) {
        return Err(refused(path));
    }
    let real = std::fs::canonicalize(path)?;
    imp::trust(&real);
    Ok(real)
}

/// [`std::fs::metadata`], refusing a foreign share.
pub fn metadata(path: impl AsRef<Path>) -> io::Result<Metadata> {
    let path = path.as_ref();
    if is_foreign(path) {
        return Err(refused(path));
    }
    std::fs::metadata(path)
}

/// [`std::fs::symlink_metadata`], refusing a foreign share.
pub fn symlink_metadata(path: impl AsRef<Path>) -> io::Result<Metadata> {
    let path = path.as_ref();
    if is_foreign(path) {
        return Err(refused(path));
    }
    std::fs::symlink_metadata(path)
}

/// [`std::fs::read_dir`], refusing a foreign share.
pub fn read_dir(path: impl AsRef<Path>) -> io::Result<ReadDir> {
    let path = path.as_ref();
    if is_foreign(path) {
        return Err(refused(path));
    }
    std::fs::read_dir(path)
}

/// [`Path::exists`]: false on a foreign share (callers that must not treat that as missing
/// check [`is_foreign`]).
pub fn exists(path: impl AsRef<Path>) -> bool {
    metadata(path).is_ok()
}

/// [`Path::is_dir`]: false on a foreign share (see [`exists`]).
pub fn is_dir(path: impl AsRef<Path>) -> bool {
    metadata(path).is_ok_and(|m| m.is_dir())
}

/// [`Path::is_file`]: false on a foreign share (see [`exists`]).
pub fn is_file(path: impl AsRef<Path>) -> bool {
    metadata(path).is_ok_and(|m| m.is_file())
}

fn refused_pattern() -> glob::PatternError {
    glob::PatternError {
        pos: 0,
        msg: REFUSED,
    }
}

/// [`glob::glob`], with a pattern on a foreign share an error (callers judge its text).
pub fn glob(pattern: &str) -> Result<glob::Paths, glob::PatternError> {
    if is_foreign(Path::new(pattern)) {
        return Err(refused_pattern());
    }
    glob::glob(pattern)
}

/// [`glob::glob_with`], with a pattern on a foreign share an error (callers judge its text).
pub fn glob_with(
    pattern: &str,
    options: glob::MatchOptions,
) -> Result<glob::Paths, glob::PatternError> {
    if is_foreign(Path::new(pattern)) {
        return Err(refused_pattern());
    }
    glob::glob_with(pattern, options)
}

/// `text` without the verbatim prefix `canonicalize` puts on Windows paths (`\\?\C:\…` →
/// `C:\…`; `\\?\UNC\h\s\…` and `\\?\GLOBALROOT\Device\Mup\h\s\…` → `\\h\s\…`; either
/// separator, any case), so a resolved spelling compares equal to the one a user or a command
/// writes. Unchanged off Windows, where `//?/` is an ordinary (if odd) directory name.
pub fn without_verbatim(text: &str) -> Cow<'_, str> {
    if cfg!(windows) {
        strip_verbatim(text)
    } else {
        Cow::Borrowed(text)
    }
}

fn is_sep(c: u8) -> bool {
    matches!(c, b'\\' | b'/')
}

fn strip_verbatim(text: &str) -> Cow<'_, str> {
    let b = text.as_bytes();
    let sep = |i: usize| b.get(i).copied().filter(|c| is_sep(*c));
    if !(sep(0).is_some() && sep(1).is_some() && b.get(2) == Some(&b'?') && sep(3).is_some()) {
        return Cow::Borrowed(text);
    }
    for network in ["unc", "globalroot\\device\\mup"] {
        let end = 4 + network.len();
        let named = text
            .get(4..end)
            .is_some_and(|u| u.replace('/', "\\").eq_ignore_ascii_case(network));
        if let Some(s) = sep(end).filter(|_| named) {
            // `\\?\UNC\h\s` → `\\h\s`.
            return Cow::Owned(format!("{0}{0}{1}", s as char, &text[end + 1..]));
        }
    }
    Cow::Borrowed(&text[4..])
}

/// Where a path lives, by Win32 rules on its text.
#[cfg_attr(not(windows), allow(dead_code))] // Unit-tested everywhere, used on Windows.
#[derive(Debug, PartialEq)]
enum Share {
    /// A drive, a volume, a local device, a relative path, or a share on this machine.
    Local,
    /// `host\share`, lowercased.
    Unc(String),
    /// A device path that may reach the network (`\\?\GLOBALROOT\…` other than `Device\Mup`).
    Device,
}

#[cfg_attr(not(windows), allow(dead_code))] // Unit-tested everywhere, used on Windows.
fn classify(text: &str, computer: Option<&str>) -> Share {
    let b = text.as_bytes();
    if !(b.len() >= 2 && is_sep(b[0]) && is_sep(b[1])) {
        return Share::Local;
    }
    let norm = text.replace('/', "\\");
    let mut parts = norm[2..].split('\\');
    let first = parts.next().unwrap_or("");
    let device = matches!(first, "?" | ".");
    if device {
        let kind = parts.next().unwrap_or("");
        if kind.eq_ignore_ascii_case("unc") {
            return unc(parts, computer);
        }
        if kind.eq_ignore_ascii_case("globalroot") {
            let dev = parts.next().unwrap_or("");
            let mup = parts.next().unwrap_or("");
            if dev.eq_ignore_ascii_case("device") && mup.eq_ignore_ascii_case("mup") {
                return unc(parts, computer);
            }
            return Share::Device;
        }
        // `C:`, `Volume{…}`, `pipe`, other local devices.
        return Share::Local;
    }
    unc(std::iter::once(first).chain(parts), computer)
}

#[cfg_attr(not(windows), allow(dead_code))] // Unit-tested everywhere, used on Windows.
fn unc<'a>(mut parts: impl Iterator<Item = &'a str>, computer: Option<&str>) -> Share {
    let host = parts.next().unwrap_or("").to_lowercase();
    let share = parts.next().unwrap_or("").to_lowercase();
    if is_this_machine(&host, computer) {
        return Share::Local;
    }
    Share::Unc(format!("{host}\\{share}"))
}

#[cfg_attr(not(windows), allow(dead_code))] // Unit-tested everywhere, used on Windows.
fn is_this_machine(host: &str, computer: Option<&str>) -> bool {
    matches!(
        host,
        "localhost" | "::1" | "[::1]" | "0--1.ipv6-literal.net" | "wsl$" | "wsl.localhost"
    ) || (host.starts_with("127.") && host.parse::<std::net::Ipv4Addr>().is_ok())
        || computer.is_some_and(|c| !c.is_empty() && c.eq_ignore_ascii_case(host))
}

#[cfg(not(windows))]
mod imp {
    use std::path::Path;

    pub fn trust(_: &Path) {}

    pub fn is_foreign(_: &Path) -> bool {
        false
    }
}

#[cfg(windows)]
mod imp {
    use super::{classify, Share};
    use std::path::Path;
    use std::sync::{Mutex, OnceLock};

    fn share(path: &Path) -> Share {
        static COMPUTER: OnceLock<Option<String>> = OnceLock::new();
        let computer = COMPUTER.get_or_init(|| std::env::var("COMPUTERNAME").ok());
        classify(&path.to_string_lossy(), computer.as_deref())
    }

    fn trusted() -> &'static Mutex<Vec<String>> {
        static TRUSTED: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
        TRUSTED.get_or_init(|| {
            let mut out = Vec::new();
            let env = [
                "HOME",
                "USERPROFILE",
                "CLAUDE_PROJECT_DIR",
                "CLAUDE_PLUGIN_DATA",
                "CLAUDE_CONFIG_DIR",
            ]
            .iter()
            .filter_map(std::env::var_os)
            .map(std::path::PathBuf::from);
            for path in env.chain(std::env::current_dir().ok()) {
                if let Share::Unc(s) = share(&path) {
                    if !out.contains(&s) {
                        out.push(s);
                    }
                }
            }
            Mutex::new(out)
        })
    }

    pub fn trust(path: &Path) {
        if let Share::Unc(s) = share(path) {
            if let Ok(mut list) = trusted().lock() {
                if !list.contains(&s) {
                    list.push(s);
                }
            }
        }
    }

    pub fn is_foreign(path: &Path) -> bool {
        match share(path) {
            Share::Local => false,
            Share::Device => true,
            Share::Unc(s) => !trusted().lock().is_ok_and(|list| list.contains(&s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_paths_are_looked_up() {
        let here = std::env::temp_dir();
        assert!(!is_foreign(&here));
        assert!(is_dir(&here));
        assert!(canonicalize(&here).is_ok());
        assert!(!is_foreign(Path::new("relative/x")));
    }

    #[test]
    fn a_refusal_is_not_not_found() {
        let err = refused(Path::new(r"\\h\s\x"));
        assert_ne!(err.kind(), io::ErrorKind::NotFound);
        assert!(is_refused(&err));
        assert!(!is_refused(&io::Error::other("x")));
    }

    #[test]
    fn the_verbatim_prefix_is_stripped() {
        for (given, want) in [
            (r"\\?\C:\Users\x", r"C:\Users\x"),
            ("//?/c:/users/x", "c:/users/x"),
            (r"\\?\UNC\host\share\x", r"\\host\share\x"),
            (r"\\?\unc\host\share\x", r"\\host\share\x"),
            ("//?/unc/host/share", "//host/share"),
            (r"\\?\GLOBALROOT\Device\Mup\host\s\x", r"\\host\s\x"),
            (r"\\?\globalroot\device\mup\host\s", r"\\host\s"),
            (r"C:\Users\x", r"C:\Users\x"),
            (r"\\host\share", r"\\host\share"),
            (r"\\?\", ""),
            ("/?/x", "/?/x"),
        ] {
            assert_eq!(strip_verbatim(given), want, "{given}");
        }
        if !cfg!(windows) {
            assert_eq!(without_verbatim("//?/x"), "//?/x");
        }
    }

    #[test]
    fn shares_are_classified_by_win32_rules() {
        let unc = |s: &str| Share::Unc(s.to_string());
        for (text, want) in [
            (r"\\github.com\solanabr\x", unc(r"github.com\solanabr")),
            (
                "//registry.npmjs.org/:_authToken",
                unc(r"registry.npmjs.org\:_authtoken"),
            ),
            (r"\\?\UNC\Host\Share\x", unc(r"host\share")),
            (r"\\?\unc\host\share\x", unc(r"host\share")),
            (r"\\.\UNC\host\share\x", unc(r"host\share")),
            ("//?/UnC/host/share", unc(r"host\share")),
            (
                r"\\?\GLOBALROOT\Device\Mup\host\share\x",
                unc(r"host\share"),
            ),
            (r"\\.\globalroot\device\mup\host\share", unc(r"host\share")),
            (r"\\?\GLOBALROOT\Device\HarddiskVolume1\x", Share::Device),
            (r"\\localhost\c$\Users\me", Share::Local),
            (r"\\127.0.0.1\c$\Users\me", Share::Local),
            (r"\\127.1.2.3\c$", Share::Local),
            (r"\\127.evil.com\s", unc(r"127.evil.com\s")),
            (r"\\[::1]\c$", Share::Local),
            (r"\\wsl$\Ubuntu\home\me", Share::Local),
            (r"\\wsl.localhost\Ubuntu\home\me", Share::Local),
            (r"\\?\UNC\localhost\c$\x", Share::Local),
            (r"\\BUILDBOX\c$\x", Share::Local),
            (r"C:\Users\x", Share::Local),
            (r"\\?\C:\Users\x", Share::Local),
            (r"\\?\Volume{1234}\x", Share::Local),
            (r"\\.\pipe\x", Share::Local),
            ("relative/x", Share::Local),
            ("/work/x", Share::Local),
        ] {
            assert_eq!(classify(text, Some("buildbox")), want, "{text}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn unc_paths_are_looked_up_only_on_a_trusted_share() {
        for p in [
            r"\\github.com\solanabr\safe-ai-skill",
            "//registry.npmjs.org/:_authToken",
            r"\\?\UNC\host\share\x",
            r"\\?\unc\host\share\x",
            r"\\.\UNC\host\share\x",
            r"\\?\GLOBALROOT\Device\Mup\host\share\x",
        ] {
            assert!(is_foreign(Path::new(p)), "{p}");
            let err = canonicalize(p).unwrap_err();
            assert!(is_refused(&err), "{p}");
            assert!(glob(&format!("{p}\\*")).is_err(), "{p}");
        }
        trust_share_of(Path::new(r"\\fileserver\proj\repo"));
        assert!(!is_foreign(Path::new(r"\\FILESERVER\Proj\repo\src")));
        assert!(!is_foreign(Path::new(r"\\?\UNC\fileserver\proj\x")));
        assert!(is_foreign(Path::new(r"\\fileserver\other\x")));
        assert!(!is_foreign(Path::new(r"\\localhost\c$\x")));
        assert!(!is_foreign(Path::new(r"C:\Users\x")));
        assert!(!is_foreign(Path::new(r"\\?\C:\Users\x")));
    }
}
