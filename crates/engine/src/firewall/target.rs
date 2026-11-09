//! Which settings file the firewall owns a block in, and whether it may be written.
//!
//! Claude Code reads `.claude/settings.local.json` at the git repository root, and in a linked
//! worktree at the main checkout's root; outside a git repository, when the repository root is
//! the home directory, or on Windows it stays next to `.claude/settings.json` in the starting
//! directory (docs: settings.md, "Where Claude Code keeps the local file in a git repository").
//! Relative sandbox paths in that file anchor at the session's primary working directory, not
//! at the directory holding the file (settings.md, same section), so `"."` means wherever the
//! session starts; the repository root (`dir`) and its `.git` ([`Target::git_dir`]) are written
//! as absolute paths beside it.

use std::io::Read;
use std::path::{Path, PathBuf};

/// Largest settings file read.
pub const MAX_SETTINGS_BYTES: u64 = 1024 * 1024;

/// The settings file the block lives in, and the facts about its repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// `<dir>/.claude/settings.local.json`.
    pub settings: PathBuf,
    /// `<dir>/.claude`.
    pub config_dir: PathBuf,
    /// The repository (or starting) directory holding `.claude`.
    pub dir: PathBuf,
    /// Whether `dir` is a git work tree root.
    pub in_git: bool,
    /// The git common dir's real path when it lies outside the session's project root.
    pub git_common_outside: Option<PathBuf>,
    /// The repository's `.git` directory (absolute), when `dir` is the git work tree root and
    /// `.git` there is a directory (a linked worktree's `.git` file is covered by
    /// `git_common_outside` instead).
    pub git_dir: Option<PathBuf>,
}

impl Target {
    /// The key of this target in the firewall record.
    pub fn key(&self) -> String {
        self.settings.to_string_lossy().into_owned()
    }
}

/// Locate the target for a session started in `cwd`. `home` is the user's home (passwd
/// entry), used for the repository-root-is-home rule. No git process is run.
pub fn locate(cwd: &Path, home: Option<&Path>) -> Target {
    let start = real(cwd);
    let toplevel = start
        .ancestors()
        .find(|d| std::fs::symlink_metadata(d.join(".git")).is_ok())
        .map(Path::to_path_buf);
    let home = home.map(real);
    let mut git_common_outside = None;
    let mut git_dir = None;
    let dir = match &toplevel {
        Some(top) if !cfg!(windows) && home.as_deref() != Some(top.as_path()) => {
            let dotgit = top.join(".git");
            if std::fs::symlink_metadata(&dotgit).is_ok_and(|m| m.is_dir()) {
                git_dir = Some(dotgit);
            }
            let common = common_dir(top);
            if let Some(c) = &common {
                if !c.starts_with(top) {
                    git_common_outside = Some(c.clone());
                }
            }
            // A linked worktree: the local file lives at the main checkout's root.
            match &git_common_outside {
                Some(c) if c.file_name().is_some_and(|n| n == ".git") => {
                    c.parent().map_or_else(|| top.clone(), Path::to_path_buf)
                }
                _ => top.clone(),
            }
        }
        _ => start.clone(),
    };
    let in_git = toplevel.is_some();
    let config_dir = dir.join(".claude");
    Target {
        settings: config_dir.join("settings.local.json"),
        config_dir,
        dir,
        in_git,
        git_common_outside,
        git_dir,
    }
}

/// The git common dir of the work tree at `top`: `.git` itself, or for a `.git` file
/// (`gitdir: <path>`) the `commondir` named inside that gitdir, else the gitdir.
fn common_dir(top: &Path) -> Option<PathBuf> {
    let dotgit = top.join(".git");
    let meta = std::fs::symlink_metadata(&dotgit).ok()?;
    if meta.is_dir() {
        return std::fs::canonicalize(&dotgit).ok().map(simplified);
    }
    let text = read_small(&dotgit, 4096)?;
    let gitdir = text.lines().find_map(|l| l.strip_prefix("gitdir:"))?.trim();
    let gitdir = top.join(gitdir);
    let common = match read_small(&gitdir.join("commondir"), 4096) {
        Some(rel) => gitdir.join(rel.trim()),
        None => gitdir,
    };
    std::fs::canonicalize(common).ok().map(simplified)
}

/// `p`'s real path in its plain spelling, else `p` as given.
fn real(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).map_or_else(|_| p.to_path_buf(), simplified)
}

/// `p` without the Windows verbatim prefix that [`std::fs::canonicalize`] adds there
/// (`\\?\C:\x` → `C:\x`, `\\?\UNC\srv\share` → `\\srv\share`), so the paths written
/// into settings and used as keys are spelled as Claude Code and git spell them. Kept as is
/// when the plain form would name a different file ([`simplify_verbatim`]); a no-op off
/// Windows.
pub fn simplified(p: PathBuf) -> PathBuf {
    if cfg!(windows) {
        if let Some(plain) = p.to_str().and_then(simplify_verbatim) {
            return PathBuf::from(plain);
        }
    }
    p
}

/// The plain spelling of the verbatim Windows path `s`, or `None` when `s` is not a verbatim
/// disk or UNC path or its plain form would mean something else: longer than `MAX_PATH`, or
/// holding a `/`, an empty, `.` or `..` component, a component ending in `.` or space, a
/// character Win32 refuses, or a reserved device name.
pub fn simplify_verbatim(s: &str) -> Option<String> {
    let (plain, parts) = if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        let mut it = rest.split('\\');
        let (server, share) = (it.next()?, it.next()?);
        if server.is_empty() || share.is_empty() {
            return None;
        }
        (format!(r"\\{rest}"), rest)
    } else {
        let rest = s.strip_prefix(r"\\?\")?;
        let b = rest.as_bytes();
        if b.len() < 3 || !b[0].is_ascii_alphabetic() || b[1] != b':' || b[2] != b'\\' {
            return None;
        }
        (rest.to_string(), rest.get(3..)?)
    };
    if plain.len() >= 260 || parts.contains('/') {
        return None;
    }
    let comps: Vec<&str> = parts.split('\\').collect();
    let last = comps.len().saturating_sub(1);
    for (i, c) in comps.iter().enumerate() {
        if c.is_empty() {
            if i == last {
                continue;
            }
            return None;
        }
        if *c == "." || *c == ".." || c.ends_with('.') || c.ends_with(' ') {
            return None;
        }
        if c.chars()
            .any(|ch| ch < ' ' || matches!(ch, '<' | '>' | ':' | '"' | '|' | '?' | '*'))
        {
            return None;
        }
        if reserved(c) {
            return None;
        }
    }
    Some(plain)
}

/// Whether `component` names a Win32 device (`CON`, `NUL`, `COM1`, `LPT1.txt`, …).
fn reserved(component: &str) -> bool {
    let stem = component
        .split('.')
        .next()
        .unwrap_or(component)
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    match stem.as_str() {
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" => true,
        s => s
            .strip_prefix("COM")
            .or_else(|| s.strip_prefix("LPT"))
            .is_some_and(|n| {
                n.len() == 1 && n.as_bytes()[0].is_ascii_digit()
                    || matches!(n, "\u{b9}" | "\u{b2}" | "\u{b3}")
            }),
    }
}

fn read_small(path: &Path, cap: u64) -> Option<String> {
    let file = std::fs::File::open(path).ok()?;
    let mut text = String::new();
    file.take(cap).read_to_string(&mut text).ok()?;
    Some(text)
}

/// Refuse a target that would write through a link: a symlinked `.claude` dir or settings
/// file means the bytes belong to something outside this project (kit `firewall.sh` l.84–93).
pub fn check_writable(t: &Target) -> Result<(), String> {
    for p in [&t.config_dir, &t.settings] {
        match std::fs::symlink_metadata(p) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(format!(
                    "{} is a symlink, so writing it would rewrite a file outside this project; \
                     replace the link with a real file and run the command again",
                    p.display()
                ))
            }
            Ok(m) if p == &t.settings && !m.is_file() => {
                return Err(format!(
                    "{} is not a regular file; replace it with one and run the command again",
                    p.display()
                ))
            }
            Ok(m) if p == &t.config_dir && !m.is_dir() => {
                return Err(format!(
                    "{} is not a directory; remove it and run the command again",
                    p.display()
                ))
            }
            _ => {}
        }
    }
    Ok(())
}

/// The settings file's text: `Ok(None)` when it does not exist. A link is never followed.
pub fn read_settings(path: &Path) -> Result<Option<String>, String> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = match opts.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    let mut bytes = Vec::new();
    file.take(MAX_SETTINGS_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if bytes.len() as u64 > MAX_SETTINGS_BYTES {
        return Err(format!("{} is larger than 1 MiB", path.display()));
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| format!("{} is not UTF-8", path.display()))
}

/// The file's unix permission bits, or `None` when it does not exist.
pub fn mode_of(path: &Path) -> Option<u32> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Some(meta.permissions().mode() & 0o7777)
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        Some(0o644)
    }
}

/// Whether git tracks the settings file (runs `git ls-files`; CLI only, never on a hook path).
/// `None` when git cannot tell.
pub fn tracked_by_git(t: &Target) -> Option<bool> {
    if !t.in_git {
        return Some(false);
    }
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(&t.dir)
        .args([
            "ls-files",
            "--error-unmatch",
            "--",
            ".claude/settings.local.json",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .ok()?;
    Some(out.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!(
            "sas-fw-target-{tag}-{}-{nanos}-{seq}",
            std::process::id()
        ));
        std::fs::create_dir_all(&p).unwrap();
        simplified(std::fs::canonicalize(&p).unwrap())
    }

    #[test]
    fn plain_dir_uses_cwd() {
        let d = tmp("plain");
        let t = locate(&d, None);
        assert_eq!(t.settings, d.join(".claude/settings.local.json"));
        assert!(!t.in_git);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn repo_subdir_uses_toplevel() {
        let d = tmp("repo");
        std::fs::create_dir_all(d.join(".git")).unwrap();
        std::fs::create_dir_all(d.join("a/b")).unwrap();
        let t = locate(&d.join("a/b"), None);
        assert!(t.in_git);
        assert!(t.git_common_outside.is_none());
        if cfg!(windows) {
            // On Windows Claude Code keeps the local file in the starting directory.
            assert_eq!(t.dir, d.join("a/b"));
            assert_eq!(t.git_dir, None);
        } else {
            assert_eq!(t.dir, d);
            assert_eq!(t.git_dir, Some(d.join(".git")));
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn linked_worktree_uses_main_checkout() {
        let d = tmp("wt");
        let main = d.join("main");
        std::fs::create_dir_all(main.join(".git/worktrees/w")).unwrap();
        std::fs::write(main.join(".git/worktrees/w/commondir"), "../..\n").unwrap();
        let wt = d.join("w");
        std::fs::create_dir_all(&wt).unwrap();
        std::fs::write(
            wt.join(".git"),
            format!("gitdir: {}\n", main.join(".git/worktrees/w").display()),
        )
        .unwrap();
        let t = locate(&wt, None);
        assert_eq!(t.git_dir, None);
        if cfg!(windows) {
            assert_eq!(t.dir, wt);
            assert_eq!(t.git_common_outside, None);
        } else {
            assert_eq!(t.dir, main);
            assert_eq!(t.git_common_outside, Some(main.join(".git")));
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn repo_at_home_stays_in_cwd() {
        let d = tmp("home");
        std::fs::create_dir_all(d.join(".git")).unwrap();
        std::fs::create_dir_all(d.join("p")).unwrap();
        let t = locate(&d.join("p"), Some(&d));
        assert_eq!(t.dir, d.join("p"));
        assert_eq!(t.git_dir, None);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn verbatim_paths_simplify_only_when_the_plain_form_is_the_same_file() {
        let ok = |v: &str, plain: &str| assert_eq!(simplify_verbatim(v).as_deref(), Some(plain));
        ok(r"\\?\C:\Users\me\proj", r"C:\Users\me\proj");
        ok(r"\\?\d:\", r"d:\");
        ok(
            r"\\?\C:\a\.claude\settings.json",
            r"C:\a\.claude\settings.json",
        );
        ok(r"\\?\UNC\srv\share\dir", r"\\srv\share\dir");
        ok(r"\\?\UNC\srv\share", r"\\srv\share");
        ok(r"\\?\C:\RUNNER~1\console.log", r"C:\RUNNER~1\console.log");
        for keep in [
            r"C:\already\plain",
            r"\\srv\share",
            "/usr/local",
            r"\\?\C:",
            r"\\?\C:relative",
            r"\\?\Volume{0}\x",
            r"\\?\GLOBALROOT\Device\x",
            r"\\?\UNC\srv",
            r"\\?\UNC\\share",
            r"\\?\C:\a/b",
            r"\\?\C:\a\\b",
            r"\\?\C:\a\.\b",
            r"\\?\C:\a\..\b",
            r"\\?\C:\trailing.",
            r"\\?\C:\trailing \x",
            r"\\?\C:\a:b",
            r"\\?\C:\a?b",
            r"\\?\C:\dir\CON",
            r"\\?\C:\dir\nul.txt",
            r"\\?\C:\dir\com1",
            r"\\?\C:\dir\LPT9.log",
            "\\\\?\\C:\\dir\\COM\u{b9}",
        ] {
            assert_eq!(simplify_verbatim(keep), None, "{keep}");
        }
        let long = format!(r"\\?\C:\{}", "a".repeat(300));
        assert_eq!(simplify_verbatim(&long), None);
        ok(r"\\?\C:\dir\COM10", r"C:\dir\COM10");
        ok(r"\\?\C:\dir\console", r"C:\dir\console");
    }

    #[test]
    fn simplified_is_a_no_op_off_windows() {
        let p = PathBuf::from(r"\\?\C:\x");
        let want = if cfg!(windows) {
            PathBuf::from(r"C:\x")
        } else {
            p.clone()
        };
        assert_eq!(simplified(p), want);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_targets_refused() {
        let d = tmp("link");
        let other = tmp("other");
        std::os::unix::fs::symlink(&other, d.join(".claude")).unwrap();
        assert!(check_writable(&locate(&d, None)).is_err());
        std::fs::remove_file(d.join(".claude")).unwrap();
        std::fs::create_dir_all(d.join(".claude")).unwrap();
        std::os::unix::fs::symlink(other.join("x"), d.join(".claude/settings.local.json")).unwrap();
        assert!(check_writable(&locate(&d, None)).is_err());
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&other);
    }
}
