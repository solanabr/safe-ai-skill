//! Key material and home credential stores by path (D8 v2 spec §4; owned by F1).
//!
//! [`is_credential`] matches a path against every `credentials.list` record (contract §1.3
//! dialect; classes and the `sb` column are ignored: every class is denied at every tier, `!`
//! exceptions stay readable). The 1.1.0 trees in [`crate::gates::secretpath`] still apply
//! after it. Matching is deliberately wider than the list in three ways, all tightening:
//! every OS section applies on every host, case is always folded (the caller lowercases),
//! and `~` also means any other user's home (`/home/*`, `/Users/*`, `/root`, `X:/Users/*`).
//! Command-form readers (`gh auth token`, `pass show`, …) live in [`crate::gates::creddump`].
//!
//! Call lines (shared files; F1 edits only this file):
//! - `secretpath::classify_with_homes` → [`is_credential`] (Read, file Grep, MCP path args,
//!   Bash readers and sinks all classify through it);
//! - `read::decide_grep` → [`grep_root`] and, through `read::grep_exclusion`,
//!   [`grep_exclusions`].

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use crate::gate::Verdict;
use crate::gates::secretpath;
use crate::lists::{self, Credential};

/// Appended to a directory Grep's `glob`: env-class names, key files and the hard-deny trees
/// (1.1.0 list). Template and schema files fall under `.env.*` too, so a directory Grep never
/// searches `.env.example` or `.env.schema` (read them directly); re-including them would turn
/// the glob list into a whitelist.
const GREP_EXCLUDED: &[&str] = &[
    "**/.env",
    "**/.env.*",
    "**/*.env",
    "**/.envrc",
    "**/.dev.vars",
    "**/.dev.vars.*",
    "**/.varlock-frozen-env",
    "**/*-keypair.json",
    "**/id.json",
    "**/*.pem",
    "**/*.key",
    "**/.ssh/id_*",
    "**/.config/solana/**",
    "**/.superstack/**",
    "**/.config/varlock/**",
    "**/.varlock/**",
    "**/.claude/projects/**",
];

/// Where a glob is anchored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Root {
    /// `~/…`: under a home directory.
    Home,
    /// `${CLAUDE_CONFIG_DIR:-~/.claude}/…`: the config dir (when set) and `~/.claude`.
    ConfigDir,
    /// `/…`: an absolute path.
    Abs,
    /// `**/…` or a relative glob: anywhere.
    Anywhere,
}

/// One compiled `credentials.list` record.
struct Entry {
    exception: bool,
    root: Root,
    /// Lowercased segments after the root.
    segs: Vec<String>,
    /// Trailing `/`: the directory and everything below it.
    dir: bool,
    /// The glob as written, for exclusion globs.
    source: &'static str,
}

/// The compiled list, `None` when the embedded lists failed to parse.
fn entries() -> Option<&'static [Entry]> {
    static COMPILED: OnceLock<Option<Vec<Entry>>> = OnceLock::new();
    COMPILED
        .get_or_init(|| {
            lists::credentials()
                .ok()
                .map(|c| c.iter().map(compile).collect())
        })
        .as_deref()
}

const CONFIG_DIR_PREFIX: &str = "${CLAUDE_CONFIG_DIR:-~/.claude}/";

fn compile(c: &'static Credential) -> Entry {
    let glob = c.glob.as_str();
    let (root, rest) = if let Some(rest) = glob.strip_prefix(CONFIG_DIR_PREFIX) {
        (Root::ConfigDir, rest)
    } else if let Some(rest) = glob.strip_prefix("~/") {
        (Root::Home, rest)
    } else if let Some(rest) = glob.strip_prefix('/') {
        (Root::Abs, rest)
    } else {
        (Root::Anywhere, glob)
    };
    Entry {
        exception: c.exception,
        root,
        segs: segments(&rest.to_ascii_lowercase()),
        dir: glob.ends_with('/'),
        source: glob,
    }
}

fn segments(text: &str) -> Vec<String> {
    text.split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// `*` (any run) and `?` (one char) within one path segment.
fn seg_match(pat: &str, text: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (pat.chars().collect(), text.chars().collect());
    let (mut pi, mut ti, mut star, mut mark) = (0, 0, None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) && p[pi] != '*' {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

/// Whole-segment match of `pat` (with `**`) against `path`; `dir` lets `path` run on below.
fn segs_match(pat: &[String], path: &[&str], dir: bool) -> bool {
    match pat.split_first() {
        None => dir || path.is_empty(),
        Some((p, rest)) if p == "**" => (0..=path.len()).any(|i| segs_match(rest, &path[i..], dir)),
        Some((p, rest)) => {
            path.first().is_some_and(|s| seg_match(p, s)) && segs_match(rest, &path[1..], dir)
        }
    }
}

/// Home roots as segment lists: `$HOME`, `%USERPROFILE%`, the passwd home and their canonical
/// forms, then the patterns for any other user's home.
fn home_roots() -> Vec<Vec<String>> {
    static PASSWD: OnceLock<Option<String>> = OnceLock::new();
    let passwd = PASSWD
        .get_or_init(|| crate::datadir::passwd_home().and_then(|p| p.to_str().map(str::to_string)));
    let mut raw: Vec<String> = ["HOME", "USERPROFILE"]
        .iter()
        .filter_map(|v| std::env::var(v).ok())
        .filter(|v| !v.is_empty())
        .collect();
    raw.extend(passwd.clone());
    let mut roots: Vec<Vec<String>> = Vec::new();
    for home in raw {
        for form in [Some(home.clone()), canonical(&home)].into_iter().flatten() {
            let segs = segments(&secretpath::normalize(&form, None));
            if !segs.is_empty() && !roots.contains(&segs) {
                roots.push(segs);
            }
        }
    }
    for other in [
        &["home", "*"][..],
        &["users", "*"],
        &["root"],
        &["*:", "users", "*"],
    ] {
        roots.push(other.iter().map(|s| s.to_string()).collect());
    }
    roots
}

/// The canonical form of `path`, cached (a temp HOME under a symlinked `/var` resolves).
fn canonical(path: &str) -> Option<String> {
    static CACHE: OnceLock<Mutex<HashMap<String, Option<String>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache.lock().ok()?;
    cache
        .entry(path.to_string())
        .or_insert_with(|| {
            std::fs::canonicalize(path)
                .ok()
                .and_then(|p| p.to_str().map(str::to_string))
        })
        .clone()
}

/// The config dirs a [`Root::ConfigDir`] entry covers.
fn config_dirs() -> Vec<Vec<String>> {
    std::env::var("CLAUDE_CONFIG_DIR")
        .ok()
        .filter(|v| !v.is_empty())
        .map(|v| segments(&secretpath::normalize(&v, None)))
        .into_iter()
        .collect()
}

/// A leading `~`, `$HOME`, `${HOME}` or `%USERPROFILE%` in an already normalised path, with the
/// rest after it.
fn home_prefixed(full: &str) -> Option<&str> {
    ["~/", "$home/", "${home}/", "%userprofile%/"]
        .iter()
        .find_map(|p| full.strip_prefix(p))
        .or_else(|| {
            ["~", "$home", "${home}", "%userprofile%"]
                .contains(&full)
                .then_some("")
        })
}

/// Whether `path` (normalised: absolute, `/` separators, lowercased) is a credential store
/// entry that is not a readable exception. Fails closed when the embedded lists are unusable.
pub fn is_credential(path: &Path) -> bool {
    // Unusable embedded lists (a build defect the tests pin) fail closed.
    let Some(entries) = entries() else {
        return true;
    };
    let text = secretpath::normalize(&path.to_string_lossy(), None);
    let roots = home_roots();
    // `~/x` and `$HOME/x` are judged under every home root; anything else as written.
    let mut candidates: Vec<(bool, Vec<String>)> = Vec::new();
    match home_prefixed(&text) {
        Some(rest) => {
            for root in roots.iter().filter(|r| !r.iter().any(|s| s.contains('*'))) {
                let mut segs = root.clone();
                segs.extend(segments(rest));
                candidates.push((true, segs));
            }
        }
        None => candidates.push((is_absolute(&text), segments(&text))),
    }
    let config = config_dirs();
    let hit = |entry: &Entry| {
        candidates.iter().any(|(abs, segs)| {
            let path: Vec<&str> = segs.iter().map(String::as_str).collect();
            match entry.root {
                Root::Anywhere => segs_match(&entry.segs, &path, entry.dir),
                Root::Abs => *abs && segs_match(&entry.segs, &path, entry.dir),
                Root::Home => {
                    *abs && roots
                        .iter()
                        .any(|root| segs_match(&joined(root, &entry.segs), &path, entry.dir))
                }
                Root::ConfigDir => {
                    *abs && roots
                        .iter()
                        .map(|root| joined(root, &[".claude".to_string()]))
                        .chain(config.iter().cloned())
                        .any(|dir| segs_match(&joined(&dir, &entry.segs), &path, entry.dir))
                }
            }
        })
    };
    let mut denied = false;
    for entry in entries {
        if !hit(entry) {
            continue;
        }
        if entry.exception {
            return false;
        }
        denied = true;
    }
    denied
}

fn joined(root: &[String], rest: &[String]) -> Vec<String> {
    root.iter().chain(rest).cloned().collect()
}

fn is_absolute(normalised: &str) -> bool {
    normalised.starts_with('/') || normalised.as_bytes().get(1) == Some(&b':')
}

/// The verdict for a directory Grep rooted at `target` (as given) / `real` (canonical), before
/// any exclusion is appended; `None` lets the search proceed with [`grep_exclusions`].
/// Denies inside a credential store or a 1.1.0 hard-deny tree; a search over a directory that
/// merely contains stores (`~`, `~/.config`) proceeds with every credential glob excluded.
pub fn grep_root(target: &Path, real: &Path, homes: &[String]) -> Option<Verdict> {
    let denied = [target, real]
        .iter()
        .any(|p| secretpath::is_hard_tree(&p.to_string_lossy(), homes) || is_credential(p));
    denied.then(|| hard_deny("search inside a credential store"))
}

/// The exclusion globs for a directory Grep rooted at `dir`: the short 1.1.0 list, plus one
/// glob per credential record (exceptions cannot be re-included, so `~/.ssh/config` is not
/// searched by a directory Grep either) when `dir` lies at, above or inside a home directory.
pub fn grep_exclusions(dir: &Path) -> Vec<String> {
    let mut globs: Vec<String> = GREP_EXCLUDED.iter().map(|g| g.to_string()).collect();
    if !touches_home(dir) {
        return globs;
    }
    for entry in entries()
        .unwrap_or_default()
        .iter()
        .filter(|e| !e.exception)
    {
        for glob in exclusion_globs(entry) {
            if !globs.contains(&glob) {
                globs.push(glob);
            }
        }
    }
    globs
}

/// Whether `dir` is at or above a home directory, or inside one in a dot directory,
/// `Library` or `AppData` (where the stores live; a project under `~/dev` keeps the short list).
fn touches_home(dir: &Path) -> bool {
    let text = secretpath::normalize(&dir.to_string_lossy(), None);
    let segs = segments(&text);
    let path: Vec<&str> = segs.iter().map(String::as_str).collect();
    home_roots().iter().any(|root| {
        let shared = root.len().min(path.len());
        let prefix = root.iter().zip(&path).all(|(pat, seg)| seg_match(pat, seg));
        prefix
            && (path.len() <= root.len()
                || path.get(shared).is_some_and(|first| {
                    first.starts_with('.') || matches!(*first, "library" | "appdata")
                }))
    })
}

/// The `rg --glob` forms of one record (relative to the search root; spaces become `?`
/// because Claude Code splits the glob field on whitespace).
fn exclusion_globs(entry: &Entry) -> Vec<String> {
    let rest = entry
        .source
        .strip_prefix(CONFIG_DIR_PREFIX)
        .map(|r| format!(".claude/{r}"))
        .or_else(|| entry.source.strip_prefix("~/").map(str::to_string))
        .or_else(|| entry.source.strip_prefix('/').map(str::to_string))
        .unwrap_or_else(|| entry.source.to_string());
    let mut tails = vec![rest.clone()];
    if entry.root == Root::ConfigDir {
        if let Some(name) = std::env::var("CLAUDE_CONFIG_DIR")
            .ok()
            .and_then(|v| {
                v.trim_end_matches(['/', '\\'])
                    .rsplit(['/', '\\'])
                    .next()
                    .map(str::to_string)
            })
            .filter(|n| !n.is_empty())
        {
            tails.push(format!("{name}/{}", rest.trim_start_matches(".claude/")));
        }
    }
    tails
        .into_iter()
        .map(|tail| {
            let body = if entry.dir {
                format!("{}/**", tail.trim_end_matches('/'))
            } else {
                tail
            };
            let anchored = if body.starts_with("**") {
                body
            } else {
                format!("**/{body}")
            };
            anchored.replace(' ', "?")
        })
        .collect()
}

/// The `sandbox.filesystem.denyRead` globs for this host's credential stores: every record
/// whose `sb` column is not `never` (sandboxed subprocesses may read those), for `any` and the
/// host OS, directories as `d/**`. Used by `doctor`.
pub fn sandbox_deny_read() -> Vec<String> {
    use crate::lists::{Os, SbTier};
    let host = if cfg!(target_os = "macos") {
        Os::Macos
    } else if cfg!(windows) {
        Os::Windows
    } else {
        Os::Linux
    };
    let mut out: Vec<String> = Vec::new();
    let Ok(all) = lists::credentials() else {
        return out;
    };
    for c in all
        .iter()
        .filter(|c| !c.exception && c.sb != SbTier::Never && c.os == Os::Any || c.os == host)
    {
        let glob = c.glob.replace(CONFIG_DIR_PREFIX, "~/.claude/");
        let glob = match glob.strip_suffix('/') {
            Some(dir) => format!("{dir}/**"),
            None => glob,
        };
        if !out.contains(&glob) {
            out.push(glob);
        }
    }
    out
}

fn hard_deny(what: &str) -> Verdict {
    Verdict::Deny(format!(
        "Protected secret file blocked ({what}): reading credential material is denied."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn cred(path: &str) -> bool {
        is_credential(Path::new(path))
    }

    /// A concrete path the record's glob matches, under the generic home `/home/u`.
    fn sample(glob: &str) -> String {
        let text = glob
            .replace(CONFIG_DIR_PREFIX, "~/.claude/")
            .replace('~', "/home/u")
            .replace("**", "x")
            .replace('*', "y")
            .replace('?', "z");
        if text.ends_with('/') {
            format!("{text}child")
        } else {
            text
        }
    }

    #[test]
    fn every_record_matches_a_sample_path_and_exceptions_stay_readable() {
        let all = lists::credentials().unwrap();
        assert!(entries().is_some());
        for c in all {
            let path = sample(&c.glob);
            if c.exception {
                assert!(!cred(&path), "exception {} -> {path}", c.glob);
            } else {
                assert!(cred(&path), "{} -> {path}", c.glob);
            }
        }
    }

    #[test]
    fn tilde_forms_and_other_users_homes() {
        for p in [
            "~/.netrc",
            "$HOME/.npmrc",
            "${HOME}/.aws/credentials",
            "%USERPROFILE%/.docker/config.json",
            "/Users/bob/.aws/credentials",
            "/root/.ssh/authorized_keys",
            "C:\\Users\\Bob\\.ssh\\id_rsa",
            "/home/u/.SSH/ID_RSA",
            "/home/u/.aws",
            "/home/u/.ssh/config.d/x",
            "/home/u/.ssh/sub/key.pub",
            "/Library/Keychains/System.keychain",
            "/home/u/Library/Keychains/login.keychain-db",
            "/home/u/.config/solana/id.json",
            "wallet-keypair.json",
            "/p/deploy-Keypair.json",
            "/home/u/AppData/Local/Google/Chrome/User Data/Default/Cookies",
            "/home/u/x/Local Extension Settings/bfnae/000003.log",
            "/home/u/x/IndexedDB/chrome-extension_abc_0.indexeddb.leveldb/1",
        ] {
            assert!(cred(p), "{p}");
        }
    }

    #[test]
    fn near_misses_are_not_credentials() {
        for p in [
            "/home/u/proj/.npmrc",
            "/home/u/proj/.aws/credentials",
            "/home/u/.sshx/id_rsa",
            "/home/u/.awsx",
            "/home/u/.ssh/config",
            "/home/u/.ssh/known_hosts",
            "/home/u/.ssh/id_ed25519.pub",
            "/home/u/.config/solana/cli/config.yml",
            "/p/src/main.rs",
            "./docs/ssh.md",
            "/etc/hosts",
            "",
        ] {
            assert!(!cred(p), "{p}");
        }
    }

    #[test]
    fn segment_wildcards() {
        assert!(seg_match("*", "anything"));
        assert!(seg_match("*-keypair.json", "a-keypair.json"));
        assert!(!seg_match("*-keypair.json", "keypair.json"));
        assert!(seg_match("chrome-extension_*", "chrome-extension_abc"));
        assert!(seg_match("a?c", "abc"));
        assert!(!seg_match("a?c", "ac"));
        assert!(seg_match("*.pub", ".pub"));
        assert!(!seg_match("*.pub", "x.pubx"));
    }

    #[test]
    fn exclusions_cover_every_record_at_home_and_stay_short_in_a_project() {
        let base = grep_exclusions(Path::new("/tmp/some/project"));
        assert_eq!(base.len(), GREP_EXCLUDED.len());
        let home = grep_exclusions(Path::new("/"));
        assert!(home.len() > base.len());
        for c in lists::credentials()
            .unwrap()
            .iter()
            .filter(|c| !c.exception)
        {
            let want = exclusion_globs(&compile(c));
            for glob in want {
                assert!(home.contains(&glob), "{} -> {glob}", c.glob);
            }
        }
        for glob in &home {
            assert!(
                !glob.contains([' ', ',', '{', '}', '[', ']']),
                "claude splits the glob field on whitespace and braces: {glob}"
            );
        }
        for want in [
            "**/.ssh/**",
            "**/.aws/**",
            "**/.npmrc",
            "**/Local?Extension?Settings/**",
        ] {
            assert!(home.iter().any(|g| g == want), "{want}");
        }
        assert!(grep_exclusions(Path::new("/home/u/.config"))
            .iter()
            .any(|g| g == "**/.gnupg/**"));
        assert_eq!(
            grep_exclusions(Path::new("/home/u/dev/proj")).len(),
            base.len()
        );
    }

    #[test]
    fn grep_roots_inside_a_store_deny_and_ancestors_proceed() {
        let homes = ["/home/u".to_string()];
        for d in ["/home/u/.aws", "/home/u/.ssh", "/home/u/.config/solana/cli"] {
            let dir = PathBuf::from(d);
            assert!(grep_root(&dir, &dir, &homes).is_some(), "{d}");
        }
        for d in ["/home/u", "/home/u/.config", "/home/u/proj", "/"] {
            let dir = PathBuf::from(d);
            assert!(grep_root(&dir, &dir, &homes).is_none(), "{d}");
        }
    }

    #[test]
    fn sandbox_snippet_leaves_out_never_entries() {
        let globs = sandbox_deny_read();
        assert!(globs.iter().any(|g| g == "~/.ssh/**"));
        assert!(globs.iter().any(|g| g == "~/.npmrc"));
        assert!(globs.iter().any(|g| g == "~/.claude/.credentials.json"));
        assert!(!globs.iter().any(|g| g.contains("solana")));
        assert!(!globs.iter().any(|g| g.contains("keypair")));
        assert!(globs
            .iter()
            .all(|g| !g.starts_with('!') && !g.ends_with('/')));
        if cfg!(not(windows)) {
            assert!(!globs.iter().any(|g| g.contains("AppData")));
        }
    }
}
