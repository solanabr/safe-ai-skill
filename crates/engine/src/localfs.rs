//! Filesystem lookups for paths the gates take from tool input.
//!
//! On Windows a UNC path (`\\host\share\…`, also `//host/share/…` and the `\\?\UNC\` and
//! `\\.\UNC\` forms) is a network share: touching it makes Windows contact `host` (SMB, then
//! WebDAV), which can take longer than the gate's deadline and hands the host the user's
//! NTLM credentials. Model-chosen words spell such paths easily: `git clone https://h/x`
//! carries `//h/x`, and `npm config set //registry.npmjs.org/:_authToken` one too. So a UNC
//! path is looked up only when its share is one the session already lives on: the hook
//! payload's `cwd` ([`trust_share_of`]) or `HOME`, `USERPROFILE`, `CLAUDE_PROJECT_DIR`,
//! `CLAUDE_PLUGIN_DATA`, `CLAUDE_CONFIG_DIR` and the process working dir. Any other share
//! reads as missing: the gates still judge the path by its text, they only lose what the
//! filesystem would add (symlink targets, glob matches, existence).
//!
//! Everywhere else these are the `std::fs` calls they wrap.

use std::borrow::Cow;
use std::fs::{Metadata, ReadDir};
use std::io;
use std::path::{Path, PathBuf};

/// Trust the share `path` lies on (the hook payload's `cwd`). No effect off Windows or for a
/// local path.
pub fn trust_share_of(path: &Path) {
    imp::trust(path);
}

/// Whether `path` is on a network share this session does not live on (never off Windows).
pub fn is_foreign(path: &Path) -> bool {
    imp::is_foreign(path)
}

fn refused(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("{}: network share not looked up", path.display()),
    )
}

/// [`std::fs::canonicalize`], refusing a foreign share.
pub fn canonicalize(path: impl AsRef<Path>) -> io::Result<PathBuf> {
    let path = path.as_ref();
    if is_foreign(path) {
        return Err(refused(path));
    }
    std::fs::canonicalize(path)
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

/// [`Path::exists`]: false on a foreign share.
pub fn exists(path: impl AsRef<Path>) -> bool {
    metadata(path).is_ok()
}

/// [`Path::is_dir`]: false on a foreign share.
pub fn is_dir(path: impl AsRef<Path>) -> bool {
    metadata(path).is_ok_and(|m| m.is_dir())
}

/// [`Path::is_file`]: false on a foreign share.
pub fn is_file(path: impl AsRef<Path>) -> bool {
    metadata(path).is_ok_and(|m| m.is_file())
}

/// [`glob::glob`], with a pattern on a foreign share an error (it matches nothing).
pub fn glob(pattern: &str) -> Result<glob::Paths, glob::PatternError> {
    if is_foreign(Path::new(pattern)) {
        return Err(glob::PatternError {
            pos: 0,
            msg: "network share not looked up",
        });
    }
    glob::glob(pattern)
}

/// `text` without the verbatim prefix `canonicalize` puts on Windows paths (`\\?\C:\…` →
/// `C:\…`, `\\?\UNC\h\s\…` → `\\h\s\…`, either separator), so a resolved spelling
/// compares equal to the one a user or a command writes. Unchanged off Windows, where `//?/` is
/// an ordinary (if odd) directory name.
pub fn without_verbatim(text: &str) -> Cow<'_, str> {
    if cfg!(windows) {
        strip_verbatim(text)
    } else {
        Cow::Borrowed(text)
    }
}

fn strip_verbatim(text: &str) -> Cow<'_, str> {
    let b = text.as_bytes();
    let sep = |i: usize| b.get(i).copied().filter(|c| matches!(c, b'\\' | b'/'));
    if !(sep(0).is_some() && sep(1).is_some() && b.get(2) == Some(&b'?') && sep(3).is_some()) {
        return Cow::Borrowed(text);
    }
    let unc = text
        .get(4..7)
        .is_some_and(|u| u.eq_ignore_ascii_case("unc"));
    match sep(7).filter(|_| unc) {
        // `\\?\UNC\h\s` → `\\h\s`.
        Some(s) => Cow::Owned(format!("{0}{0}{1}", s as char, &text[8..])),
        None => Cow::Borrowed(&text[4..]),
    }
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
    use std::path::{Component, Path, Prefix};
    use std::sync::{Mutex, OnceLock};

    /// Where a path lives.
    #[derive(PartialEq)]
    enum Share {
        /// A drive, a local device or a relative path.
        Local,
        /// `\\host\share`, lowercased.
        Unc(String),
        /// `\\.\UNC\…`: remote, never trusted.
        Device,
    }

    fn share(path: &Path) -> Share {
        let Some(Component::Prefix(prefix)) = path.components().next() else {
            return Share::Local;
        };
        match prefix.kind() {
            Prefix::UNC(host, share) | Prefix::VerbatimUNC(host, share) => Share::Unc(format!(
                "{}\\{}",
                host.to_string_lossy().to_lowercase(),
                share.to_string_lossy().to_lowercase()
            )),
            Prefix::DeviceNS(name) if name.eq_ignore_ascii_case("unc") => Share::Device,
            _ => Share::Local,
        }
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
    fn the_verbatim_prefix_is_stripped() {
        for (given, want) in [
            (r"\\?\C:\Users\x", r"C:\Users\x"),
            ("//?/c:/users/x", "c:/users/x"),
            (r"\\?\UNC\host\share\x", r"\\host\share\x"),
            ("//?/unc/host/share", "//host/share"),
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

    #[cfg(windows)]
    #[test]
    fn unc_paths_are_looked_up_only_on_a_trusted_share() {
        for p in [
            r"\\github.com\solanabr\safe-ai-skill",
            "//registry.npmjs.org/:_authToken",
            r"\\?\UNC\host\share\x",
            r"\\.\UNC\host\share\x",
        ] {
            assert!(is_foreign(Path::new(p)), "{p}");
            assert!(canonicalize(p).is_err(), "{p}");
            assert!(glob(&format!("{p}\\*")).is_err(), "{p}");
        }
        trust_share_of(Path::new(r"\\fileserver\proj\repo"));
        assert!(!is_foreign(Path::new(r"\\FILESERVER\Proj\repo\src")));
        assert!(!is_foreign(Path::new(r"\\?\UNC\fileserver\proj\x")));
        assert!(is_foreign(Path::new(r"\\fileserver\other\x")));
        assert!(!is_foreign(Path::new(r"C:\Users\x")));
        assert!(!is_foreign(Path::new(r"\\?\C:\Users\x")));
    }
}
