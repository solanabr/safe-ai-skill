//! Key and secret file hygiene: a SessionStart sweep and a git staging gate.
//!
//! A *key file* is a file whose name (and, for some names, content) says it holds key material
//! or secrets:
//!
//! - the engine's own secret names, through [`secretpath::classify_with_homes`] (which also
//!   consults the `credpaths` list): env files with at least one `KEY=value` line (templates
//!   such as `.env.example` and `.env.schema` excluded), dotenvx key files, and the other
//!   hard-deny names;
//! - `*.pem` / `*.key` that hold a `-----BEGIN … PRIVATE KEY-----` block (certificates do not);
//! - the [`GENERAL`] patterns: OpenSSH private keys (`id_rsa`, `id_ed25519`, …), PKCS#8
//!   (`*.p8` with a key block, `*.pk8`), PKCS#12 (`*.p12`, `*.pfx`), Java keystores and PuTTY
//!   keys;
//! - the patterns of a domain pack, through the [`DOMAIN_PACKS`] extension slot (empty here).
//!
//! `*.pub` is never a key file.
//!
//! [`session_notice`] sweeps the project (bounded: depth, entry, sniff and time caps; skips
//! `.git`, `node_modules`, `target` and other dependency or build trees) and reports in one line
//! each key file that is tracked by git or not covered by `.gitignore`, and each private key
//! (not env-style files, which are routinely `0644`) that is group/world-readable, once per
//! project and finding set. [`decide_bash`] gates `git add`, `git commit -a` /
//! `git commit <paths>` that would stage such a file, and `git stash -u` / `--all` that would
//! sweep an untracked one into a stash (a plain stash of tracked files stays local):
//!
//! | Tier | Off | Relaxed | Medium | High |
//! |---|---|---|---|---|
//! | staging a key file | ask | ask | deny | deny |
//!
//! Headless turns the ask into a deny upstream. Git is never run: tracked files come from the
//! binary `.git/index` through [`gittracked::index_files`], and ignore rules from the
//! `.gitignore` files, `.git/info/exclude` and the default global ignore file. File contents are
//! never printed.
//!
//! Known misses: a pathspec held in a variable or read from a file, `core.excludesFile` set to
//! a non-default path, ignore rules git reads from elsewhere, and `cd` targets that are not
//! literal words.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::context::shell::{self, SimpleCommand, Word};
use crate::gate::Verdict;
use crate::gates::bash::MAX_PARSE_BYTES;
use crate::gates::secretpath::{self, Class, Sniffed, Suspect};
use crate::policy::tier::Tier;
use crate::verify::gittracked::{self, IndexFile};

// ---- patterns ----------------------------------------------------------------------------

/// How a pattern matches a (lowercased) file name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameMatch {
    /// The whole name.
    Exact(&'static str),
    /// A suffix of the name (`.p12`).
    Suffix(&'static str),
}

impl NameMatch {
    fn matches(self, lower: &str) -> bool {
        match self {
            NameMatch::Exact(n) => lower == n,
            NameMatch::Suffix(s) => lower.len() > s.len() && lower.ends_with(s),
        }
    }
}

/// What, beyond the name, makes a matching file a key file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evidence {
    /// The name alone (binary formats such as PKCS#12).
    Name,
    /// A PEM / OpenSSH private-key block in the file's first bytes.
    PrivateKeyBlock,
}

/// One key-file pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyPattern {
    /// The file-name match.
    pub name: NameMatch,
    /// What else must hold.
    pub evidence: Evidence,
    /// A short description for reasons and notices.
    pub what: &'static str,
}

const fn pat(name: NameMatch, evidence: Evidence, what: &'static str) -> KeyPattern {
    KeyPattern {
        name,
        evidence,
        what,
    }
}

/// The general (domain-free) key-file patterns. The engine's env, dotenvx and `*.pem`/`*.key`
/// names come from [`secretpath`] and are not repeated here.
pub const GENERAL: &[KeyPattern] = &[
    pat(
        NameMatch::Exact("id_rsa"),
        Evidence::PrivateKeyBlock,
        "SSH private key",
    ),
    pat(
        NameMatch::Exact("id_dsa"),
        Evidence::PrivateKeyBlock,
        "SSH private key",
    ),
    pat(
        NameMatch::Exact("id_ecdsa"),
        Evidence::PrivateKeyBlock,
        "SSH private key",
    ),
    pat(
        NameMatch::Exact("id_ed25519"),
        Evidence::PrivateKeyBlock,
        "SSH private key",
    ),
    pat(
        NameMatch::Exact("id_ecdsa_sk"),
        Evidence::PrivateKeyBlock,
        "SSH private key",
    ),
    pat(
        NameMatch::Exact("id_ed25519_sk"),
        Evidence::PrivateKeyBlock,
        "SSH private key",
    ),
    pat(
        NameMatch::Suffix(".p8"),
        Evidence::PrivateKeyBlock,
        "PKCS#8 private key",
    ),
    pat(
        NameMatch::Suffix(".pk8"),
        Evidence::Name,
        "PKCS#8 private key",
    ),
    pat(
        NameMatch::Suffix(".p12"),
        Evidence::Name,
        "PKCS#12 key store",
    ),
    pat(
        NameMatch::Suffix(".pfx"),
        Evidence::Name,
        "PKCS#12 key store",
    ),
    pat(NameMatch::Suffix(".jks"), Evidence::Name, "Java key store"),
    pat(
        NameMatch::Suffix(".keystore"),
        Evidence::Name,
        "Java key store",
    ),
    pat(
        NameMatch::Suffix(".ppk"),
        Evidence::Name,
        "PuTTY private key",
    ),
];

/// Extension slot: the pattern lists of domain packs (a Solana pack adds its keypair JSON
/// shapes here). Empty in the general engine.
pub const DOMAIN_PACKS: &[&[KeyPattern]] = &[];

fn patterns() -> impl Iterator<Item = &'static KeyPattern> {
    GENERAL
        .iter()
        .chain(DOMAIN_PACKS.iter().flat_map(|p| p.iter()))
}

/// Cheap name test, allocation-free: whether `name` may be a key file at all. Everything the
/// classifier can accept passes; most source files do not.
fn name_candidate(name: &str) -> bool {
    let b = name.as_bytes();
    let ends = |s: &[u8]| b.len() >= s.len() && b[b.len() - s.len()..].eq_ignore_ascii_case(s);
    let starts = |s: &[u8]| b.len() >= s.len() && b[..s.len()].eq_ignore_ascii_case(s);
    if ends(b".pub") {
        return false;
    }
    starts(b".env")
        || ends(b".env")
        || starts(b".dev.vars")
        || starts(b".varlock")
        || ends(b".keys")
        || ends(b"-keypair.json")
        || ends(b".pem")
        || ends(b".key")
        || starts(b"id_")
        || patterns().any(|p| match p.name {
            NameMatch::Exact(n) => b.eq_ignore_ascii_case(n.as_bytes()),
            NameMatch::Suffix(s) => ends(s.as_bytes()),
        })
}

/// Largest file whose content is read to decide (an env file or a PEM is far smaller).
const CONTENT_BYTES: usize = 256 * 1024;

/// A key file's description, and whether it is a private key (whose permissions the sweep
/// checks; env-style files are routinely `0644` and only their git status is reported).
type Kind = (&'static str, bool);

/// Whether the file at `full` (named `name`) is a key file, and what it is. `exists` is false
/// for an index entry with no file on disk: then only name-decided patterns count.
fn key_kind(full: &Path, name: &str, exists: bool) -> Option<Kind> {
    if !name_candidate(name) {
        return None;
    }
    let lower = name.to_ascii_lowercase();
    let text = full.to_string_lossy();
    match secretpath::classify_with_homes(&text, &secretpath::homes()) {
        Class::HardDeny(what) => return Some((what, false)),
        Class::Env => {
            if !exists || env_has_value(full) {
                return Some(("env file with values", false));
            }
            return None;
        }
        Class::Suspect(Suspect::PemKey) => {
            return (exists && has_key_block(full)).then_some(("private key", true));
        }
        Class::Suspect(Suspect::IdJson) | Class::Schema | Class::Template | Class::Plain => {}
    }
    for p in patterns() {
        if !p.name.matches(&lower) {
            continue;
        }
        let hit = match p.evidence {
            Evidence::Name => true,
            Evidence::PrivateKeyBlock => exists && has_key_block(full),
        };
        if hit {
            return Some((p.what, true));
        }
    }
    None
}

/// [`key_kind`] from the bare name alone, for when a sweep's budget is spent: no file read and
/// no full-path classification (which consults the credential-path lists and costs far more
/// per call). Names that need their content to decide (`*.pem`, `*.key`, `id_rsa`, `*.p8`)
/// do not count.
fn name_kind(name: &str) -> Option<Kind> {
    if !name_candidate(name) {
        return None;
    }
    let lower = name.to_ascii_lowercase();
    let content_only = lower.ends_with(".pem")
        || lower.ends_with(".key")
        || patterns().all(|p| !p.name.matches(&lower) || p.evidence != Evidence::Name)
            && patterns().any(|p| p.name.matches(&lower));
    if content_only {
        return None;
    }
    key_kind(Path::new(name), name, false)
}

fn has_key_block(path: &Path) -> bool {
    matches!(
        secretpath::sniff(path, CONTENT_BYTES),
        Sniffed::PrivateKey | Sniffed::Unreadable
    )
}

/// Whether an env file assigns at least one non-empty value. An unreadable one counts.
fn env_has_value(path: &Path) -> bool {
    let Ok(file) = std::fs::File::open(path) else {
        return true;
    };
    let mut buf = Vec::new();
    if file
        .take(CONTENT_BYTES as u64)
        .read_to_end(&mut buf)
        .is_err()
    {
        return true;
    }
    String::from_utf8_lossy(&buf).lines().any(|line| {
        let line = line.trim();
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let Some((key, value)) = line.split_once('=') else {
            return false;
        };
        let key = key.trim();
        let value = value.trim().trim_matches(['"', '\'']).trim();
        !key.is_empty()
            && !key.starts_with('#')
            && key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
            && !value.is_empty()
            && !value.starts_with('#')
    })
}

// ---- repository: index and ignore rules --------------------------------------------------

/// What the sweep and the gate know about the enclosing repository.
struct Repo {
    root: PathBuf,
    /// `None` when there is no index, or it cannot be parsed (nothing is claimed tracked).
    tracked: Option<Vec<IndexFile>>,
    /// Rules from outside the work tree (global ignore, `info/exclude`) and the root
    /// `.gitignore`.
    base_rules: Vec<Rule>,
}

fn find_root(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .find(|d| std::fs::symlink_metadata(d.join(".git")).is_ok())
        .map(Path::to_path_buf)
}

fn read_capped(path: &Path, cap: u64) -> Option<Vec<u8>> {
    let file = std::fs::File::open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > cap {
        return None;
    }
    let mut buf = Vec::new();
    file.take(cap).read_to_end(&mut buf).ok()?;
    Some(buf)
}

/// The common git directory of the work tree at `root`, where `info/exclude` lives (a
/// worktree's `.git` file names its own git dir, whose `commondir` names the shared one).
fn common_dir(root: &Path) -> Option<PathBuf> {
    let dot = root.join(".git");
    let git = if dot.is_dir() {
        dot
    } else {
        let bytes = read_capped(&dot, 4096)?;
        let text = String::from_utf8_lossy(&bytes);
        let target = text.lines().next()?.strip_prefix("gitdir:")?.trim();
        let target = Path::new(target);
        if target.is_absolute() {
            target.to_path_buf()
        } else {
            root.join(target)
        }
    };
    let common = read_capped(&git.join("commondir"), 4096)
        .map(|b| {
            let rel = String::from_utf8_lossy(&b).trim().to_string();
            let p = Path::new(&rel);
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                git.join(p)
            }
        })
        .unwrap_or(git);
    Some(common)
}

impl Repo {
    fn open(root: &Path) -> Repo {
        let mut base_rules = Vec::new();
        if let Some(home) = std::env::var_os("HOME").filter(|h| !h.is_empty()) {
            let global = std::env::var_os("XDG_CONFIG_HOME")
                .filter(|x| !x.is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(home).join(".config"))
                .join("git/ignore");
            load_rules(&global, "", &mut base_rules);
        }
        if let Some(common) = common_dir(root) {
            load_rules(&common.join("info/exclude"), "", &mut base_rules);
        }
        load_rules(&root.join(".gitignore"), "", &mut base_rules);
        let tracked = gittracked::index_files(root, |path| {
            name_candidate(path.rsplit('/').next().unwrap_or(path))
        });
        Repo {
            root: root.to_path_buf(),
            tracked,
            base_rules,
        }
    }

    fn tracked_entry(&self, rel: &str) -> Option<&IndexFile> {
        self.tracked
            .as_ref()?
            .iter()
            .find(|t| same_path(&t.path, rel))
    }

    /// Whether `rel` (a file) is ignored: an ignored ancestor directory, or the last matching
    /// rule along `.gitignore` files from the root down.
    fn ignored(&self, rel: &str) -> bool {
        let mut rules = self.base_rules.clone();
        let parts: Vec<&str> = rel.split('/').collect();
        let mut dir = String::new();
        for (i, part) in parts.iter().enumerate() {
            let here = if dir.is_empty() {
                part.to_string()
            } else {
                format!("{dir}/{part}")
            };
            let last = i + 1 == parts.len();
            if is_ignored(&rules, &here, !last) {
                return true;
            }
            if !last {
                load_rules(&self.root.join(&here).join(".gitignore"), &here, &mut rules);
            }
            dir = here;
        }
        false
    }
}

fn same_path(a: &str, b: &str) -> bool {
    same_bytes(a.as_bytes(), b.as_bytes())
}

fn same_bytes(a: &[u8], b: &[u8]) -> bool {
    if FOLDS_CASE {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

/// Whether `path` lies below the directory `dir` (both repository-relative). Compared as bytes:
/// `dir.len()` need not fall on a character boundary of `path`.
fn inside(path: &str, dir: &str) -> bool {
    let (path, dir) = (path.as_bytes(), dir.as_bytes());
    path.get(dir.len()) == Some(&b'/') && path.get(..dir.len()).is_some_and(|p| same_bytes(p, dir))
}

/// Whether the work-tree file differs from its index entry (size or modification second).
fn modified(full: &Path, entry: &IndexFile) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(full) else {
        return false;
    };
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as u32);
    // The index keeps both as 32-bit fields (truncated), so compare truncated values.
    meta.len() as u32 != entry.size || mtime != Some(entry.mtime)
}

/// One ignore rule.
#[derive(Debug, Clone)]
struct Rule {
    /// The directory of the `.gitignore` it came from (repository-relative, `""` for the root).
    base: String,
    pattern: String,
    negate: bool,
    dir_only: bool,
    /// Holds a `/` before its end: matched against the path below `base`, not the name.
    anchored: bool,
}

/// Largest ignore file read, and most rules taken from one.
const MAX_IGNORE_FILE: u64 = 256 * 1024;
const MAX_RULES: usize = 2048;

fn load_rules(path: &Path, base: &str, out: &mut Vec<Rule>) {
    let Some(bytes) = read_capped(path, MAX_IGNORE_FILE) else {
        return;
    };
    let text = String::from_utf8_lossy(&bytes);
    for line in text.lines().take(MAX_RULES) {
        let line = line.trim_end_matches(['\r', ' ']);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (negate, line) = match line.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, line.strip_prefix('\\').unwrap_or(line)),
        };
        let dir_only = line.ends_with('/');
        let line = line.trim_end_matches('/');
        if line.is_empty() || line.len() > 512 {
            continue;
        }
        let anchored = line.contains('/');
        out.push(Rule {
            base: base.to_string(),
            pattern: line.trim_start_matches('/').to_string(),
            negate,
            dir_only,
            anchored,
        });
    }
}

fn is_ignored(rules: &[Rule], rel: &str, is_dir: bool) -> bool {
    let mut ignored = false;
    for rule in rules {
        if rule.dir_only && !is_dir {
            continue;
        }
        let sub = if rule.base.is_empty() {
            rel
        } else {
            match rel
                .strip_prefix(rule.base.as_str())
                .and_then(|r| r.strip_prefix('/'))
            {
                Some(sub) => sub,
                None => continue,
            }
        };
        let hit = if rule.anchored {
            glob(rule.pattern.as_bytes(), sub.as_bytes(), true)
        } else {
            let name = sub.rsplit('/').next().unwrap_or(sub);
            glob(rule.pattern.as_bytes(), name.as_bytes(), true)
        };
        if hit {
            ignored = !rule.negate;
        }
    }
    ignored
}

/// Most steps one glob match may take (hostile patterns cannot stall the hook).
const GLOB_STEPS: usize = 20_000;

/// Glob match. With `slash`, `*` and `?` stop at `/` and `**` crosses it (gitignore); without,
/// `*` crosses it too (git pathspec). Case folds where the filesystem does.
fn glob(pat: &[u8], text: &[u8], slash: bool) -> bool {
    let mut steps = 0usize;
    glob_at(pat, text, slash, &mut steps)
}

/// The filesystem folds ASCII case (git's `core.ignorecase` default there).
const FOLDS_CASE: bool = cfg!(any(target_os = "macos", windows));

fn fold_eq(a: u8, b: u8) -> bool {
    if FOLDS_CASE {
        a.eq_ignore_ascii_case(&b)
    } else {
        a == b
    }
}

fn glob_at(pat: &[u8], text: &[u8], slash: bool, steps: &mut usize) -> bool {
    *steps += 1;
    if *steps > GLOB_STEPS {
        return false;
    }
    let Some(&p) = pat.first() else {
        return text.is_empty();
    };
    match p {
        b'*' => {
            let double = pat.get(1) == Some(&b'*');
            if double || !slash {
                let rest = if double { &pat[2..] } else { &pat[1..] };
                // `**/` also matches no directory at all.
                if double && rest.first() == Some(&b'/') && glob_at(&rest[1..], text, slash, steps)
                {
                    return true;
                }
                (0..=text.len()).any(|i| glob_at(rest, &text[i..], slash, steps))
            } else {
                let rest = &pat[1..];
                let stop = text.iter().position(|b| *b == b'/').unwrap_or(text.len());
                (0..=stop).any(|i| glob_at(rest, &text[i..], slash, steps))
            }
        }
        b'?' => match text.first() {
            Some(&c) if !(slash && c == b'/') => glob_at(&pat[1..], &text[1..], slash, steps),
            _ => false,
        },
        b'[' => {
            let Some(&c) = text.first() else {
                return false;
            };
            let Some(close) = pat.iter().skip(2).position(|b| *b == b']').map(|i| i + 2) else {
                return c == b'[' && glob_at(&pat[1..], &text[1..], slash, steps);
            };
            let mut set = &pat[1..close];
            let negate = matches!(set.first(), Some(b'!' | b'^'));
            if negate {
                set = &set[1..];
            }
            let mut found = false;
            let mut i = 0;
            while i < set.len() {
                if i + 2 < set.len() && set[i + 1] == b'-' {
                    let range = set[i]..=set[i + 2];
                    found |= range.contains(&c)
                        || (FOLDS_CASE
                            && (range.contains(&c.to_ascii_lowercase())
                                || range.contains(&c.to_ascii_uppercase())));
                    i += 3;
                } else {
                    found |= fold_eq(set[i], c);
                    i += 1;
                }
            }
            found != negate
                && !(slash && c == b'/')
                && glob_at(&pat[close + 1..], &text[1..], slash, steps)
        }
        b'\\' if pat.len() > 1 => match text.first() {
            Some(&c) if fold_eq(pat[1], c) => glob_at(&pat[2..], &text[1..], slash, steps),
            _ => false,
        },
        _ => match text.first() {
            Some(&c) if fold_eq(p, c) => glob_at(&pat[1..], &text[1..], slash, steps),
            _ => false,
        },
    }
}

// ---- walking -----------------------------------------------------------------------------

/// Directories never descended into: VCS data and dependency or build trees.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    ".venv",
    "venv",
    "__pycache__",
    ".next",
    ".turbo",
    ".gradle",
    "Pods",
];

/// Bounds of one walk.
#[derive(Debug, Clone, Copy)]
pub struct Caps {
    /// Deepest directory level below the start.
    pub depth: usize,
    /// Most directory entries looked at.
    pub entries: usize,
    /// Most files whose content is read.
    pub sniffs: usize,
    /// Wall-clock budget.
    pub time: Duration,
}

/// The SessionStart sweep's bounds.
pub const SESSION_CAPS: Caps = Caps {
    depth: 8,
    entries: 20_000,
    sniffs: 64,
    time: Duration::from_millis(250),
};

/// The Bash gate's bounds (it runs before a `git add .`).
pub const GATE_CAPS: Caps = Caps {
    depth: 8,
    entries: 5_000,
    sniffs: 32,
    time: Duration::from_millis(100),
};

/// A key file a walk found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// Repository- (or project-) relative, `/`-separated.
    pub rel: String,
    /// What it is.
    pub what: &'static str,
    /// A private key readable by group or others (env-style files are not checked).
    pub readable: bool,
    /// Listed in the git index.
    pub tracked: bool,
    /// Covered by an ignore rule.
    pub ignored: bool,
}

struct Walk<'a> {
    repo: &'a Repo,
    caps: Caps,
    start: Instant,
    entries: usize,
    sniffs: usize,
    /// Descend into ignored directories (`git stash --all`, `git add -f`).
    into_ignored: bool,
    out: Vec<Found>,
    capped: bool,
}

impl Walk<'_> {
    fn over(&mut self) -> bool {
        if self.entries >= self.caps.entries || self.start.elapsed() > self.caps.time {
            self.capped = true;
        }
        self.capped
    }

    fn dir(&mut self, rel: &str, depth: usize, rules: &mut Vec<Rule>) {
        if depth > self.caps.depth || self.over() {
            return;
        }
        let full = if rel.is_empty() {
            self.repo.root.clone()
        } else {
            self.repo.root.join(rel)
        };
        let mark = rules.len();
        if !rel.is_empty() {
            load_rules(&full.join(".gitignore"), rel, rules);
        }
        let Ok(read) = std::fs::read_dir(&full) else {
            rules.truncate(mark);
            return;
        };
        let mut subdirs = Vec::new();
        for entry in read.flatten() {
            self.entries += 1;
            if self.over() {
                break;
            }
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let child = if rel.is_empty() {
                name.to_string()
            } else {
                format!("{rel}/{name}")
            };
            if kind.is_dir() {
                if SKIP_DIRS.contains(&name) {
                    continue;
                }
                if !self.into_ignored && is_ignored(rules, &child, true) {
                    continue;
                }
                subdirs.push(child);
            } else if kind.is_file() && name_candidate(name) {
                if self.sniffs >= self.caps.sniffs {
                    self.capped = true;
                    continue;
                }
                self.sniffs += 1;
                let path = entry.path();
                if let Some((what, private_key)) = key_kind(&path, name, true) {
                    let ignored = is_ignored(rules, &child, false);
                    let tracked = self.repo.tracked_entry(&child).is_some();
                    self.out.push(Found {
                        readable: private_key && group_or_world_readable(&path),
                        rel: child,
                        what,
                        tracked,
                        ignored,
                    });
                }
            }
        }
        subdirs.sort();
        for sub in subdirs {
            self.dir(&sub, depth + 1, rules);
        }
        rules.truncate(mark);
    }
}

#[cfg(unix)]
fn group_or_world_readable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::symlink_metadata(path).is_ok_and(|m| m.permissions().mode() & 0o044 != 0)
}

#[cfg(not(unix))]
fn group_or_world_readable(_path: &Path) -> bool {
    false
}

/// The key files below `from`, and how many files' content the walk read.
fn walk(repo: &Repo, from: &str, caps: Caps, into_ignored: bool) -> (Vec<Found>, usize) {
    let mut w = Walk {
        repo,
        caps,
        start: Instant::now(),
        entries: 0,
        sniffs: 0,
        into_ignored,
        out: Vec::new(),
        capped: false,
    };
    let mut rules = repo.base_rules.clone();
    if from.is_empty() {
        w.dir("", 0, &mut rules);
    } else {
        // Rules of the directories above `from`.
        let mut dir = String::new();
        for part in from.split('/') {
            dir = if dir.is_empty() {
                part.to_string()
            } else {
                format!("{dir}/{part}")
            };
            if !into_ignored && is_ignored(&rules, &dir, true) {
                return (Vec::new(), 0);
            }
            if dir != from {
                load_rules(&repo.root.join(&dir).join(".gitignore"), &dir, &mut rules);
            }
        }
        w.dir(from, 0, &mut rules);
    }
    (w.out, w.sniffs)
}

// ---- SessionStart ------------------------------------------------------------------------

/// Most file names one notice lists.
const NOTICE_NAMES: usize = 5;

/// The sweep of the project at `cwd`: every key file found, with what is wrong with it.
pub fn sweep(cwd: &Path, caps: Caps) -> Vec<Found> {
    sweep_project(cwd, caps).map_or_else(Vec::new, |(_, found)| found)
}

/// [`sweep`], with the project's root (the repository's, or `cwd` outside one).
fn sweep_project(cwd: &Path, caps: Caps) -> Option<(PathBuf, Vec<Found>)> {
    let start = Instant::now();
    let base = std::fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    let root = find_root(&base);
    let in_repo = root.is_some();
    let root = root.unwrap_or(base);
    // Outside a repository, the home directory or `/` is not a project.
    let home = std::env::var_os("HOME").map(PathBuf::from);
    if !in_repo && (root.parent().is_none() || home.as_deref() == Some(root.as_path())) {
        return None;
    }
    let repo = Repo::open(&root);
    let (mut found, mut sniffs) = walk(&repo, "", caps, false);
    if !in_repo {
        for f in &mut found {
            f.ignored = true;
        }
    }
    // Tracked key files the walk did not reach (removed from the work tree, or past a cap).
    // Full checks share the walk's sniff and time budget; once it is spent, only the bare name
    // decides (env names and key stores count, a `.pem` that needs its content does not).
    if let Some(tracked) = &repo.tracked {
        for t in tracked {
            if found.iter().any(|f| same_path(&f.rel, &t.path)) {
                continue;
            }
            let full = root.join(&t.path);
            let name = t.path.rsplit('/').next().unwrap_or(&t.path);
            let (kind, exists) = if sniffs < caps.sniffs && start.elapsed() <= caps.time {
                sniffs += 1;
                let exists = full.is_file();
                (key_kind(&full, name, exists), exists)
            } else {
                (name_kind(name), false)
            };
            if let Some((what, private_key)) = kind {
                found.push(Found {
                    rel: t.path.clone(),
                    what,
                    readable: private_key && exists && group_or_world_readable(&full),
                    tracked: true,
                    ignored: true,
                });
            }
        }
    }
    found.retain(|f| f.readable || f.tracked || !f.ignored);
    Some((root, found))
}

/// The SessionStart key-hygiene notice, in two forms of one line each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionNotice {
    /// For the user (`systemMessage`): the files, what is wrong, and the remedy commands.
    pub user: String,
    /// For the model (`additionalContext`): the files and what is wrong, with no remedy to
    /// carry out (untracking or deleting a deliberately committed file is the user's call).
    pub model: String,
}

/// The SessionStart notice for the project at `cwd`, `None` when nothing needs attention or
/// this project's finding set was already reported. Names files, never their contents.
///
/// Once per project and finding set: `<plugin_data>/tips/keyfiles-<project hash>` holds the
/// hash of the last reported set, so an intentionally committed file (a debug keystore, a
/// committed `.env.development`) is reported once, and again only when the set changes. When
/// the marker cannot be written the notice is still returned (a security notice that repeats
/// beats one that is lost).
pub fn session_notice(cwd: &Path, plugin_data: &Path) -> Option<SessionNotice> {
    let (root, found) = sweep_project(cwd, SESSION_CAPS)?;
    if found.is_empty() {
        return None;
    }
    let mut set: Vec<String> = found
        .iter()
        .map(|f| {
            format!(
                "{}\0{}\0{}{}{}",
                f.rel, f.what, f.tracked as u8, f.ignored as u8, f.readable as u8
            )
        })
        .collect();
    set.sort();
    let digest = crate::audit::sha256_hex(set.join("\n").as_bytes());
    let mut project = crate::audit::sha256_hex(root.to_string_lossy().as_bytes());
    project.truncate(16);
    let marker = plugin_data.join("tips").join(format!("keyfiles-{project}"));
    if read_capped(&marker, 256).is_some_and(|seen| seen == digest.as_bytes()) {
        return None;
    }
    if let Some(parent) = marker.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&marker, &digest);

    let listed: Vec<String> = found
        .iter()
        .take(NOTICE_NAMES)
        .map(|f| {
            let mut why = Vec::new();
            if f.tracked {
                why.push("tracked by git");
            }
            if !f.tracked && !f.ignored {
                why.push("not in .gitignore");
            }
            if f.readable {
                why.push("group/world-readable");
            }
            format!("{} ({}: {})", printable(&f.rel), f.what, why.join(", "))
        })
        .collect();
    let more = found.len().saturating_sub(NOTICE_NAMES);
    let more = if more > 0 {
        format!(" and {more} more")
    } else {
        String::new()
    };
    let head = format!(
        "safe-ai-skill key hygiene: {} key or secret file{} need{} attention: {}{more}",
        found.len(),
        if found.len() == 1 { "" } else { "s" },
        if found.len() == 1 { "s" } else { "" },
        listed.join("; ")
    );
    Some(SessionNotice {
        user: format!(
            "{head}; unless committed on purpose, run chmod 600 on them, list them in \
             .gitignore, and untrack tracked ones with git rm --cached (shown once until \
             this list changes)."
        ),
        model: format!(
            "{head}; the user has been told, so leave these files as they are unless the \
             user asks, and do not print their contents."
        ),
    })
}

/// A path safe to put in a one-line message: control characters replaced, length capped.
fn printable(path: &str) -> String {
    let clean: String = path
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    if clean.chars().count() > 120 {
        let tail: String = clean
            .chars()
            .rev()
            .take(117)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        format!("...{tail}")
    } else {
        clean
    }
}

// ---- Bash gate ---------------------------------------------------------------------------

/// The byte prefilter: `git` in any case, a backslash or ANSI-C quoting (as the git guard's).
pub fn may_concern(command: &str) -> bool {
    crate::gates::gitguard::may_concern(command)
}

/// What one git command would stage.
#[derive(Debug, Default)]
struct Stage {
    /// Pathspecs (relative to `dir`); empty with `whole` means the whole tree.
    paths: Vec<String>,
    /// No pathspec limits it (`add -A`, `commit -a`, `stash`).
    whole: bool,
    /// Modified tracked files are taken (not by `stash`: a stash stays in the local repository).
    tracked: bool,
    /// Untracked files are staged.
    untracked: bool,
    /// Ignored files are staged too (`add -f`, `stash --all`).
    ignored: bool,
    verb: &'static str,
}

/// Decide a Bash `command` that stages files with git (see the module docs). `None` when it
/// stages no key file.
pub fn decide_bash(command: &str, cwd: &Path, tier: Tier) -> Option<Verdict> {
    if command.len() > MAX_PARSE_BYTES || !may_concern(command) {
        return None;
    }
    let parsed = shell::parse(command);
    let mut dir = cwd.to_path_buf();
    for cmd in &parsed.commands {
        match cmd.program().as_str() {
            "cd" | "pushd" => {
                if let Some(w) = cmd.words.get(1).filter(|w| !w.dynamic && w.text != "-") {
                    dir = dir.join(&w.text);
                }
            }
            "git" => {
                if let Some(v) = judge_git(cmd, &dir, tier) {
                    return Some(v);
                }
            }
            _ => {}
        }
    }
    None
}

fn judge_git(cmd: &SimpleCommand, cwd: &Path, tier: Tier) -> Option<Verdict> {
    let words = &cmd.words;
    let mut dir = cwd.to_path_buf();
    let mut i = 1;
    while let Some(w) = words.get(i) {
        let t = w.text.as_str();
        if !t.starts_with('-') || t == "-" || t == "--" {
            break;
        }
        let takes = matches!(
            t,
            "-C" | "-c"
                | "--git-dir"
                | "--work-tree"
                | "--namespace"
                | "--attr-source"
                | "--super-prefix"
                | "--config-env"
        );
        if t == "-C" {
            let v = words.get(i + 1)?;
            if v.dynamic {
                return None;
            }
            dir = dir.join(&v.text);
        }
        // Another work tree or git dir: not read here.
        if t.starts_with("--git-dir") || t.starts_with("--work-tree") {
            return None;
        }
        i += if takes { 2 } else { 1 };
    }
    let sub = words.get(i)?.text.as_str();
    let rest = &words[i + 1..];
    let stage = match sub {
        "add" | "stage" => stage_add(rest)?,
        "commit" => stage_commit(rest)?,
        "stash" => stage_stash(rest)?,
        _ => return None,
    };
    let hits = staged_keys(&stage, &dir);
    let first = hits.first()?;
    let tail = match hits.len() - 1 {
        0 => ", a key or secret file".to_string(),
        1 => " and 1 more key or secret file".to_string(),
        n => format!(" and {n} more key or secret files"),
    };
    let what = format!(
        "this git {} stages {} ({}){tail}",
        stage.verb,
        printable(&first.0),
        first.1
    );
    Some(if tier >= Tier::Medium {
        Verdict::Deny(format!(
            "safe-ai-skill key hygiene: {what}, which the {} tier denies; leave it out of the \
             commit and list it in .gitignore, or ask the user to commit it themselves if it \
             holds no real secret.",
            tier.label()
        ))
    } else {
        Verdict::Ask(format!(
            "safe-ai-skill key hygiene: {what}; approve only if it holds no real secret, \
             otherwise leave it out and list it in .gitignore."
        ))
    })
}

/// Split short-option clusters and long options; returns (options, paths). `value_short` and
/// `value_long` name the options that take the next word.
fn split_args<'a>(
    rest: &'a [Word],
    value_short: &[u8],
    value_long: &[&str],
) -> Option<(Vec<String>, Vec<&'a Word>)> {
    let mut opts = Vec::new();
    let mut paths = Vec::new();
    let mut i = 0;
    let mut dashdash = false;
    while let Some(w) = rest.get(i) {
        i += 1;
        let t = w.text.as_str();
        if dashdash || !t.starts_with('-') || t == "-" {
            paths.push(w);
            continue;
        }
        if t == "--" {
            dashdash = true;
            continue;
        }
        if let Some(long) = t.strip_prefix("--") {
            let name = long.split_once('=').map_or(long, |(n, _)| n);
            if !long.contains('=') && value_long.contains(&name) {
                i += 1;
            }
            opts.push(format!("--{name}"));
            continue;
        }
        for (k, c) in t.char_indices().skip(1) {
            opts.push(format!("-{c}"));
            if c.is_ascii() && value_short.contains(&(c as u8)) {
                if k + 1 == t.len() {
                    i += 1;
                }
                break;
            }
        }
    }
    Some((opts, paths))
}

fn has(opts: &[String], names: &[&str]) -> bool {
    opts.iter().any(|o| names.contains(&o.as_str()))
}

fn literal_paths(paths: &[&Word]) -> Vec<String> {
    paths
        .iter()
        .filter(|w| !w.dynamic)
        .map(|w| w.text.clone())
        .collect()
}

fn stage_add(rest: &[Word]) -> Option<Stage> {
    let (opts, paths) = split_args(rest, b"", &["--chmod", "--pathspec-from-file"])?;
    if has(&opts, &["-n", "--dry-run", "-h", "--help"]) {
        return None;
    }
    let all = has(&opts, &["-A", "--all", "--no-ignore-removal"]);
    let update = has(&opts, &["-u", "--update"]);
    let from_file = has(&opts, &["--pathspec-from-file"]);
    let paths = literal_paths(&paths);
    if paths.is_empty() && !all && !update && !from_file {
        return None;
    }
    Some(Stage {
        whole: paths.is_empty(),
        paths,
        tracked: true,
        untracked: !update,
        ignored: has(&opts, &["-f", "--force"]),
        verb: "add",
    })
}

fn stage_commit(rest: &[Word]) -> Option<Stage> {
    let (opts, paths) = split_args(
        rest,
        b"mFCctS",
        &[
            "--message",
            "--file",
            "--reuse-message",
            "--reedit-message",
            "--template",
            "--author",
            "--date",
            "--fixup",
            "--squash",
            "--cleanup",
            "--trailer",
            "--pathspec-from-file",
        ],
    )?;
    if has(&opts, &["--dry-run", "-h", "--help"]) {
        return None;
    }
    let all = has(&opts, &["-a", "--all"]);
    let paths = literal_paths(&paths);
    if !all && paths.is_empty() {
        return None;
    }
    Some(Stage {
        whole: paths.is_empty(),
        paths,
        tracked: true,
        untracked: false,
        ignored: false,
        verb: "commit",
    })
}

fn stage_stash(rest: &[Word]) -> Option<Stage> {
    let rest = match rest.first().map(|w| w.text.as_str()) {
        Some("push" | "save") => &rest[1..],
        Some(t) if !t.starts_with('-') => return None,
        _ => rest,
    };
    let (opts, paths) = split_args(rest, b"m", &["--message", "--pathspec-from-file"])?;
    if has(&opts, &["-h", "--help"]) {
        return None;
    }
    let all = has(&opts, &["-a", "--all"]);
    let paths = literal_paths(&paths);
    Some(Stage {
        whole: paths.is_empty(),
        paths,
        tracked: false,
        untracked: all || has(&opts, &["-u", "--include-untracked"]),
        ignored: all,
        verb: "stash",
    })
}

/// Repository-relative form of `path` (a pathspec relative to `dir`), `None` outside `root`.
fn repo_rel(root: &Path, dir: &Path, path: &str) -> Option<String> {
    let joined = if let Some(top) = path.strip_prefix(":/") {
        root.join(top)
    } else {
        dir.join(path)
    };
    let mut parts: Vec<String> = Vec::new();
    let root_parts = root.components().count();
    let joined = std::fs::canonicalize(&joined).unwrap_or(joined);
    for c in joined.components() {
        match c {
            std::path::Component::ParentDir => {
                parts.pop();
            }
            std::path::Component::CurDir => {}
            other => parts.push(other.as_os_str().to_string_lossy().into_owned()),
        }
    }
    let root_list: Vec<String> = root
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    if parts.len() < root_parts || parts[..root_parts] != root_list[..] {
        return None;
    }
    Some(parts[root_parts..].join("/"))
}

/// The key files `stage` would stage, as (repository-relative path, what).
fn staged_keys(stage: &Stage, dir: &Path) -> Vec<(String, &'static str)> {
    let base = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    let Some(root) = find_root(&base) else {
        return Vec::new();
    };
    let repo = Repo::open(&root);
    let mut out: Vec<(String, &'static str)> = Vec::new();
    let mut push = |rel: String, what: &'static str| {
        if !out.iter().any(|(r, _)| same_path(r, &rel)) {
            out.push((rel, what));
        }
    };
    // Scopes: the whole tree, or each pathspec (a file, a directory, or a glob below a
    // literal directory).
    let mut scopes: Vec<(String, Option<String>)> = Vec::new();
    if stage.whole {
        scopes.push((String::new(), None));
    }
    for p in &stage.paths {
        if p.starts_with(':') && !p.starts_with(":/") {
            continue;
        }
        let glob_at = p.find(['*', '?', '[']);
        let literal = match glob_at {
            Some(g) => p
                .get(..g)
                .and_then(|h| h.rsplit_once('/'))
                .map_or("", |(d, _)| d),
            None => p.as_str(),
        };
        let literal = if literal.is_empty() { "." } else { literal };
        let Some(rel) = repo_rel(&root, &base, literal) else {
            continue;
        };
        let pattern = glob_at.and_then(|_| {
            let full = repo_rel(&root, &base, ".")?;
            let spec = p.strip_prefix(":/").unwrap_or(p).trim_start_matches("./");
            Some(if full.is_empty() || p.starts_with(":/") {
                spec.to_string()
            } else {
                format!("{full}/{spec}")
            })
        });
        scopes.push((rel, pattern));
    }
    // Tracked files: staged when modified (a staging run of an unchanged file is a no-op).
    if let Some(tracked) = repo.tracked.as_ref().filter(|_| stage.tracked) {
        for t in tracked {
            let in_scope = scopes.iter().any(|(rel, pattern)| match pattern {
                Some(g) => glob(g.as_bytes(), t.path.as_bytes(), false),
                None => rel.is_empty() || same_path(&t.path, rel) || inside(&t.path, rel),
            });
            if !in_scope {
                continue;
            }
            let full = root.join(&t.path);
            if !modified(&full, t) {
                continue;
            }
            let name = t.path.rsplit('/').next().unwrap_or(&t.path);
            if let Some((what, _)) = key_kind(&full, name, true) {
                push(t.path.clone(), what);
            }
        }
    }
    if !stage.untracked {
        return out;
    }
    for (rel, pattern) in &scopes {
        let full = root.join(rel);
        let meta = std::fs::symlink_metadata(&full);
        if meta.as_ref().is_ok_and(|m| m.is_file()) {
            if repo.tracked_entry(rel).is_some() || (!stage.ignored && repo.ignored(rel)) {
                continue;
            }
            let name = rel.rsplit('/').next().unwrap_or(rel);
            if let Some((what, _)) = key_kind(&full, name, true) {
                push(rel.clone(), what);
            }
            continue;
        }
        if !meta.is_ok_and(|m| m.is_dir()) {
            continue;
        }
        let (found, _) = walk(&repo, rel, GATE_CAPS, stage.ignored);
        for f in found {
            if f.tracked || (f.ignored && !stage.ignored) {
                continue;
            }
            if pattern
                .as_ref()
                .is_some_and(|g| !glob(g.as_bytes(), f.rel.as_bytes(), false))
            {
                continue;
            }
            push(f.rel, f.what);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gitignore_globs() {
        assert!(glob(b"*.key", b"a.key", true));
        assert!(!glob(b"*.key", b"d/a.key", true));
        assert!(glob(b"**/a.key", b"a.key", true));
        assert!(glob(b"**/a.key", b"x/y/a.key", true));
        assert!(glob(b"x/**", b"x/y/z", true));
        assert!(glob(b".env*", b".env.local", true));
        assert!(glob(b"[ab].pem", b"b.pem", true));
        assert!(!glob(b"[!ab].pem", b"b.pem", true));
        assert!(glob(b"*.key", b"d/a.key", false));
    }

    #[test]
    fn hostile_globs_are_bounded() {
        let pat = "*a".repeat(40) + "b";
        let text = "a".repeat(200);
        let start = Instant::now();
        assert!(!glob(pat.as_bytes(), text.as_bytes(), true));
        assert!(start.elapsed() < Duration::from_millis(200));
    }

    #[test]
    fn name_prefilter() {
        for n in [
            ".env",
            ".env.production",
            "server.key",
            "x.pem",
            "id_rsa",
            "a.p12",
            "k.pfx",
        ] {
            assert!(name_candidate(n), "{n}");
        }
        for n in [
            "main.rs",
            "id_rsa.pub",
            "README.md",
            "Cargo.toml",
            "key.pub",
        ] {
            assert!(!name_candidate(n), "{n}");
        }
    }

    #[test]
    fn rules_negate_and_dir_only() {
        let mut rules = Vec::new();
        let dir = std::env::temp_dir().join(format!("kf-rules-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("ig");
        std::fs::write(&file, "*.key\n!keep.key\nsecrets/\n# c\n").unwrap();
        load_rules(&file, "", &mut rules);
        assert!(is_ignored(&rules, "a.key", false));
        assert!(!is_ignored(&rules, "keep.key", false));
        assert!(is_ignored(&rules, "secrets", true));
        assert!(!is_ignored(&rules, "secrets", false));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
