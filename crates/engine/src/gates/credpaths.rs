//! Key material and home credential stores by path (D8 v2 spec §4; owned by F1).
//!
//! [`is_credential`] matches a path against every `credentials.list` record (contract §1.3
//! dialect; classes and the `sb` column are ignored: every class is denied at every tier, `!`
//! exceptions stay readable). The 1.1.0 trees in [`crate::gates::secretpath`] still apply
//! after it. Matching is deliberately wider than the list in three ways, all tightening:
//! every OS section applies on every host, case is always folded (the caller lowercases),
//! and `~` also means any other user's home (`/home/*`, `/Users/*`, `/root`, `X:/Users/*`).
//! A `~`, `$HOME`, `${HOME}`, `$USERPROFILE` or `%USERPROFILE%` segment anywhere in the path
//! re-roots it at the home (a hook joins a relative `$HOME/x` to its cwd first).
//!
//! [`is_credential_glob`] is the same match for a Bash word the shell may expand: a segment
//! with `*`, `?` or `[` is a pattern, and it counts when it can match a record's segment (two
//! patterns: when their literal prefixes and suffixes are compatible). [`reaches_store`] says
//! whether a directory is at or above a credential store (a recursive search from there
//! would reach it).
//!
//! Command-form readers and the generic Bash path check live in [`crate::gates::creddump`].
//!
//! Call lines (shared files; F1 edits only this file):
//! - `secretpath::classify_with_homes` → [`is_credential`] (Read, file Grep, MCP path args,
//!   Bash readers and sinks all classify through it);
//! - `read::decide_grep` → [`grep_root`] and, through `read::grep_exclusion`,
//!   [`grep_exclusions`].

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use crate::gate::Verdict;
use crate::gates::secretpath;
use crate::lists::{self, Credential, Os, SbTier};

/// Appended to a directory Grep's `glob`: env-class names, key files and the hard-deny trees
/// (1.1.0 list). Template and schema files fall under `.env.*` too, so a directory Grep never
/// searches `.env.example` or `.env.schema` (read them directly); re-including them would turn
/// the glob list into a whitelist. The list's `**/…` records (wallet extension stores) are
/// appended to it at run time ([`grep_exclusions`]).
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

/// One element of a compiled segment pattern.
enum Tok {
    Star,
    Any,
    Lit(char),
    Class(Vec<(char, char)>, bool),
}

fn has_wild(seg: &str) -> bool {
    seg.contains(['*', '?', '['])
}

/// `*`, `?` and (when `classes`) `[a-z]`, `[!x]`, `[^x]` of one path segment.
fn tokens(pat: &str, classes: bool) -> Vec<Tok> {
    let chars: Vec<char> = pat.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '*' => out.push(Tok::Star),
            '?' => out.push(Tok::Any),
            '[' if classes => {
                let close = chars
                    .iter()
                    .enumerate()
                    .skip(i + 2)
                    .find(|(_, c)| **c == ']')
                    .map(|(j, _)| j);
                match close {
                    Some(j) => {
                        let body = &chars[i + 1..j];
                        let (neg, body) = match body.first() {
                            Some('!' | '^') => (true, &body[1..]),
                            _ => (false, body),
                        };
                        let mut ranges = Vec::new();
                        let mut k = 0;
                        while k < body.len() {
                            if body.get(k + 1) == Some(&'-') && k + 2 < body.len() {
                                ranges.push((body[k], body[k + 2]));
                                k += 3;
                            } else {
                                ranges.push((body[k], body[k]));
                                k += 1;
                            }
                        }
                        out.push(Tok::Class(ranges, neg));
                        i = j;
                    }
                    None => out.push(Tok::Lit('[')),
                }
            }
            c => out.push(Tok::Lit(c)),
        }
        i += 1;
    }
    out
}

fn tok_matches(tok: &Tok, c: char) -> bool {
    match tok {
        Tok::Any => true,
        Tok::Lit(l) => *l == c,
        Tok::Class(ranges, neg) => ranges.iter().any(|(a, b)| *a <= c && c <= *b) != *neg,
        Tok::Star => false,
    }
}

/// Whole-segment match of `pat` against the literal `text`.
fn pat_match(pat: &str, text: &str, classes: bool) -> bool {
    let toks = tokens(pat, classes);
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti, mut star, mut mark) = (0, 0, None, 0);
    while ti < t.len() {
        match toks.get(pi) {
            Some(Tok::Star) => {
                star = Some(pi);
                mark = ti;
                pi += 1;
            }
            Some(tok) if tok_matches(tok, t[ti]) => {
                pi += 1;
                ti += 1;
            }
            _ => match star {
                Some(s) => {
                    pi = s + 1;
                    mark += 1;
                    ti = mark;
                }
                None => return false,
            },
        }
    }
    toks[pi..].iter().all(|t| matches!(t, Tok::Star))
}

/// `*`/`?` of a list record against a literal path segment.
fn seg_match(pat: &str, text: &str) -> bool {
    pat_match(pat, text, false)
}

/// The literal text before the first and after the last wildcard of a segment.
fn affixes(seg: &str) -> (&str, &str) {
    let first = seg.find(['*', '?', '[']).unwrap_or(seg.len());
    let last = seg.rfind(['*', '?', ']']).map_or(0, |i| i + 1);
    (&seg[..first], &seg[last.min(seg.len())..])
}

/// Whether a record segment `rec` and a path segment `arg` can name the same file. With
/// `globbing` an `arg` wildcard is a shell pattern: against a literal `rec` it must match it
/// (a leading-dot name needs a leading literal dot, the shell default); against a `rec` that is
/// a pattern too, their literal prefixes and suffixes must be compatible.
fn seg_overlap(rec: &str, arg: &str, globbing: bool) -> bool {
    if !globbing || !has_wild(arg) {
        return seg_match(rec, arg);
    }
    if !has_wild(rec) {
        return (!rec.starts_with('.') || arg.starts_with('.')) && pat_match(arg, rec, true);
    }
    let ((ap, asu), (rp, rsu)) = (affixes(arg), affixes(rec));
    let compat = |a: &str, b: &str, prefix: bool| {
        if prefix {
            a.starts_with(b) || b.starts_with(a)
        } else {
            a.ends_with(b) || b.ends_with(a)
        }
    };
    compat(ap, rp, true) && compat(asu, rsu, false)
}

/// Whole-segment match of `pat` (with `**`) against `path`; `dir` lets `path` run on below.
fn segs_match(pat: &[String], path: &[&str], dir: bool, globbing: bool) -> bool {
    match pat.split_first() {
        None => dir || path.is_empty(),
        Some((p, rest)) if p == "**" => {
            (0..=path.len()).any(|i| segs_match(rest, &path[i..], dir, globbing))
        }
        Some((p, rest)) => {
            path.first().is_some_and(|s| seg_overlap(p, s, globbing))
                && segs_match(rest, &path[1..], dir, globbing)
        }
    }
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

/// The user's home directories as the OS and the environment name them: `$HOME`,
/// `%USERPROFILE%` and the passwd home (not canonicalised).
pub fn home_dirs() -> Vec<PathBuf> {
    static PASSWD: OnceLock<Option<PathBuf>> = OnceLock::new();
    let mut out: Vec<PathBuf> = ["HOME", "USERPROFILE"]
        .iter()
        .filter_map(std::env::var_os)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .collect();
    out.extend(PASSWD.get_or_init(crate::datadir::passwd_home).clone());
    out.dedup();
    out
}

/// Home roots as segment lists: [`home_dirs`] and their canonical forms (concrete), then the
/// patterns for any other user's home.
fn home_roots(concrete_only: bool) -> Vec<Vec<String>> {
    let mut roots: Vec<Vec<String>> = Vec::new();
    for home in home_dirs() {
        let home = home.to_string_lossy().into_owned();
        for form in [Some(home.clone()), canonical(&home)].into_iter().flatten() {
            let segs = segments(&secretpath::normalize(&form, None));
            if !segs.is_empty() && !roots.contains(&segs) {
                roots.push(segs);
            }
        }
    }
    if !concrete_only {
        for other in [
            &["home", "*"][..],
            &["users", "*"],
            &["root"],
            &["*:", "users", "*"],
        ] {
            roots.push(other.iter().map(|s| s.to_string()).collect());
        }
    }
    roots
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

/// Whether a normalised segment names the home directory (`~`, `~user`, `$HOME`, …).
fn is_home_seg(seg: &str) -> bool {
    seg.starts_with('~')
        || matches!(
            seg,
            "$home" | "${home}" | "$userprofile" | "${userprofile}" | "%userprofile%"
        )
}

/// Whether `path` (normalised: absolute, `/` separators, lowercased) is a credential store
/// entry that is not a readable exception. Fails closed when the embedded lists are unusable.
pub fn is_credential(path: &Path) -> bool {
    check(path, false)
}

/// [`is_credential`] for a word the shell may glob-expand (see the module docs).
pub fn is_credential_glob(path: &Path) -> bool {
    check(path, true)
}

fn check(path: &Path, globbing: bool) -> bool {
    // Unusable embedded lists (a build defect the tests pin) fail closed.
    let Some(entries) = entries() else {
        return true;
    };
    let text = secretpath::normalize(&path.to_string_lossy(), None);
    let all_segs = segments(&text);
    let roots = home_roots(false);
    // A home segment anywhere re-roots the rest under every concrete home.
    let mut candidates: Vec<(bool, Vec<String>)> = Vec::new();
    match all_segs.iter().position(|s| is_home_seg(s)) {
        Some(i) => {
            for root in home_roots(true) {
                let mut segs = root;
                segs.extend(all_segs[i + 1..].iter().cloned());
                candidates.push((true, segs));
            }
        }
        None => candidates.push((is_absolute(&text), all_segs)),
    }
    let config = config_dirs();
    let hit = |entry: &Entry| {
        candidates.iter().any(|(abs, segs)| {
            let path: Vec<&str> = segs.iter().map(String::as_str).collect();
            let matches = |pat: &[String]| segs_match(pat, &path, entry.dir, globbing);
            match entry.root {
                // `**/…` records are matched literally: a pattern would overlap them
                // everywhere (`*.json` vs `*-keypair.json`); the filesystem expansion of a
                // wildcard word decides those.
                Root::Anywhere => segs_match(&entry.segs, &path, entry.dir, false),
                Root::Abs => *abs && matches(&entry.segs),
                Root::Home => *abs && roots.iter().any(|root| matches(&joined(root, &entry.segs))),
                Root::ConfigDir => {
                    *abs && roots
                        .iter()
                        .map(|root| joined(root, &[".claude".to_string()]))
                        .chain(config.iter().cloned())
                        .any(|dir| matches(&joined(&dir, &entry.segs)))
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

/// Whether the directory `dir` (absolute, or home-relative with `~`) is at or above a
/// credential store: a recursive search or archive rooted there would reach one.
pub fn reaches_store(dir: &Path) -> bool {
    let Some(entries) = entries() else {
        return true;
    };
    if secretpath::data_dir_reach(&dir.to_string_lossy(), &secretpath::homes_resolved()).is_some() {
        return true;
    }
    let text = secretpath::normalize(&dir.to_string_lossy(), None);
    let mut segs = segments(&text);
    if let Some(i) = segs.iter().position(|s| is_home_seg(s)) {
        // `~` itself: every concrete home is at or above its own stores.
        return home_roots(true).iter().any(|root| {
            let mut full = root.clone();
            full.extend(segs[i + 1..].iter().cloned());
            reaches_abs(entries, &full)
        });
    }
    if !is_absolute(&text) {
        return false;
    }
    if reaches_abs(entries, &segs) {
        return true;
    }
    if let Some(real) = canonical(&dir.to_string_lossy()) {
        segs = segments(&secretpath::normalize(&real, None));
        return reaches_abs(entries, &segs);
    }
    false
}

fn reaches_abs(entries: &[Entry], dir: &[String]) -> bool {
    if dir.iter().any(|s| has_wild(s)) {
        return false;
    }
    let config = config_dirs();
    entries.iter().filter(|e| !e.exception).any(|entry| {
        let literal: Vec<String> = entry
            .segs
            .iter()
            .take_while(|s| !has_wild(s))
            .cloned()
            .collect();
        let bases: Vec<Vec<String>> = match entry.root {
            Root::Anywhere => return false,
            Root::Abs => vec![Vec::new()],
            Root::Home => home_roots(true),
            Root::ConfigDir => home_roots(true)
                .iter()
                .map(|r| joined(r, &[".claude".to_string()]))
                .chain(config.iter().cloned())
                .collect(),
        };
        bases
            .iter()
            .any(|base| joined(base, &literal).starts_with(dir))
    })
}

/// The verdict for a directory Grep rooted at `target` (as given) / `real` (canonical), before
/// any exclusion is appended; `None` lets the search proceed with [`grep_exclusions`].
/// Denies inside a credential store or a 1.1.0 hard-deny tree; a search over a directory that
/// merely contains stores (`~`, `~/.config`) proceeds with every credential glob excluded.
pub fn grep_root(target: &Path, real: &Path, homes: &[String]) -> Option<Verdict> {
    let denied = [target, real]
        .iter()
        .any(|p| secretpath::is_hard_tree(&p.to_string_lossy(), homes) || is_credential(p));
    if denied {
        return Some(hard_deny("search inside a credential store"));
    }
    let in_data = [target, real].iter().any(|p| {
        secretpath::data_dir_reach(&p.to_string_lossy(), homes)
            == Some(secretpath::DataDirReach::Inside)
    });
    in_data.then(|| hard_deny("search inside the safe-ai-skill data dir (its state key)"))
}

/// Whether the credential lists loaded; without them a directory Grep cannot be given its
/// exclusions and asks.
pub fn lists_available() -> bool {
    entries().is_some()
}

/// The exclusion globs for the state key of every data dir a Grep over `dir` reaches
/// ([`secretpath::data_dir_reach`]): `**/safe-ai-skill-*/key`, and `$CLAUDE_PLUGIN_DATA`'s
/// own directory name when it is another one.
fn data_key_globs() -> Vec<String> {
    let mut out = vec!["**/safe-ai-skill-*/key".to_string()];
    let custom = std::env::var("CLAUDE_PLUGIN_DATA").ok().and_then(|d| {
        Path::new(d.trim_end_matches(['/', '\\']))
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_string)
    });
    if let Some(name) = custom {
        let plain = !name.starts_with("safe-ai-skill-")
            && !name.is_empty()
            && !name.contains(['*', '?', '[', ']', '{', '}', ',', '!', '\\']);
        if plain {
            out.push(format!("**/{name}/key"));
        }
    }
    out
}

/// The exclusion globs for a directory Grep rooted at `dir`: the short 1.1.0 list plus the
/// list's `**/…` records (they match in a project too), and, at/above a home directory or
/// inside one in a dot directory, `Library` or `AppData`, one glob per other record (spaces as
/// `?`, directories as `d/**`, the config dir's own name too). Inside a home, records under
/// the root are also emitted relative to it, because ripgrep reports paths relative to a
/// relative search root. Exceptions cannot be re-included, so `~/.ssh/config` is not searched
/// by a directory Grep either.
pub fn grep_exclusions(dir: &Path) -> Vec<String> {
    let mut globs: Vec<String> = GREP_EXCLUDED.iter().map(|g| g.to_string()).collect();
    let all: &[Entry] = entries().unwrap_or_default();
    let push = |glob: String, globs: &mut Vec<String>| {
        if !globs.contains(&glob) {
            globs.push(glob);
        }
    };
    for entry in all
        .iter()
        .filter(|e| !e.exception && e.root == Root::Anywhere)
    {
        for glob in exclusion_globs(entry) {
            push(glob, &mut globs);
        }
    }
    let homes = secretpath::homes_resolved();
    if secretpath::data_dir_reach(&dir.to_string_lossy(), &homes).is_some() {
        for glob in data_key_globs() {
            push(glob, &mut globs);
        }
    }
    if !touches_home(dir) {
        return globs;
    }
    for entry in all.iter().filter(|e| !e.exception) {
        for glob in exclusion_globs(entry) {
            push(glob, &mut globs);
        }
        for glob in relative_globs(entry, dir) {
            push(glob, &mut globs);
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
    home_roots(false).iter().any(|root| {
        let shared = root.len().min(path.len());
        let prefix = root.iter().zip(&path).all(|(pat, seg)| seg_match(pat, seg));
        prefix
            && (path.len() <= root.len()
                || path.get(shared).is_some_and(|first| {
                    first.starts_with('.') || matches!(*first, "library" | "appdata")
                }))
    })
}

/// A record's globs for the paths of a home-rooted `dir` strictly inside a home: the part of
/// the record after the root's own segments, when the record runs through `dir`.
fn relative_globs(entry: &Entry, dir: &Path) -> Vec<String> {
    if !matches!(entry.root, Root::Home | Root::ConfigDir) {
        return Vec::new();
    }
    let text = secretpath::normalize(&dir.to_string_lossy(), None);
    let segs = segments(&text);
    let mut out = Vec::new();
    for root in home_roots(false) {
        let Some(inside) = segs.get(root.len()..) else {
            continue;
        };
        let under = root.iter().zip(&segs).all(|(pat, seg)| seg_match(pat, seg));
        if !under || inside.is_empty() {
            continue;
        }
        let record: Vec<String> = if entry.root == Root::ConfigDir {
            joined(&[".claude".to_string()], &entry.segs)
        } else {
            entry.segs.clone()
        };
        // The record as written (case kept) for the output; lowercased for the comparison.
        let mut written: Vec<&str> = entry
            .source
            .trim_start_matches(CONFIG_DIR_PREFIX)
            .trim_start_matches("~/")
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();
        if entry.root == Root::ConfigDir {
            written.insert(0, ".claude");
        }
        if record.len() > inside.len()
            && written.len() == record.len()
            && inside.iter().zip(&record).all(|(s, r)| seg_match(r, s))
        {
            let rest = written[inside.len()..].join("/");
            let rest = if entry.dir {
                format!("{rest}/**")
            } else {
                rest
            };
            out.push(rest.replace(' ', "?"));
        }
    }
    out
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

/// The recommended `sandbox.filesystem.denyRead` globs for this host's credential stores:
/// every record whose `sb` column is at most `max` (`never` records are left out: sandboxed
/// subprocesses must read them) for `any` and the host OS, directories as `d/**`. Used by
/// `doctor`, which prints the Relaxed set and the Medium-only additions separately.
pub fn sandbox_deny_read(max: SbTier) -> Vec<String> {
    let host = if cfg!(target_os = "macos") {
        Os::Macos
    } else if cfg!(windows) {
        Os::Windows
    } else {
        Os::Linux
    };
    lists::credentials()
        .map(|all| deny_read_globs(all, host, max, None))
        .unwrap_or_default()
}

/// The `denyRead` globs that name `$CLAUDE_CONFIG_DIR` by its real path (empty when unset or
/// the default `~/.claude`): the same records as [`sandbox_deny_read`] under that directory.
pub fn config_dir_deny_read(max: SbTier) -> Vec<String> {
    let Some(dir) = std::env::var("CLAUDE_CONFIG_DIR")
        .ok()
        .filter(|d| !d.is_empty())
    else {
        return Vec::new();
    };
    let host = if cfg!(target_os = "macos") {
        Os::Macos
    } else if cfg!(windows) {
        Os::Windows
    } else {
        Os::Linux
    };
    let plain = sandbox_deny_read(max);
    lists::credentials()
        .map(|all| deny_read_globs(all, host, max, Some(dir)))
        .unwrap_or_default()
        .into_iter()
        .filter(|g| !plain.contains(g))
        .collect()
}

fn sb_rank(sb: SbTier) -> u8 {
    match sb {
        SbTier::Relaxed => 0,
        SbTier::Medium => 1,
        SbTier::High => 2,
        SbTier::Never => 3,
    }
}

/// [`sandbox_deny_read`] over an explicit list, host OS and config dir.
fn deny_read_globs(
    all: &[Credential],
    host: Os,
    max: SbTier,
    config_dir: Option<String>,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let selected = all.iter().filter(|c| {
        !c.exception
            && c.sb != SbTier::Never
            && sb_rank(c.sb) <= sb_rank(max)
            && (c.os == Os::Any || c.os == host)
    });
    for c in selected {
        let mut globs = vec![c.glob.replace(CONFIG_DIR_PREFIX, "~/.claude/")];
        if let Some(dir) = config_dir.as_deref().filter(|d| !d.is_empty()) {
            if c.glob.starts_with(CONFIG_DIR_PREFIX) {
                let rest = c.glob.trim_start_matches(CONFIG_DIR_PREFIX);
                globs.push(format!("{}/{rest}", dir.trim_end_matches('/')));
            }
        }
        for glob in globs {
            let glob = match glob.strip_suffix('/') {
                Some(dir) => format!("{dir}/**"),
                None => glob,
            };
            if !out.contains(&glob) {
                out.push(glob);
            }
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
        // The two `**/…` list records (wallet extension stores) join the short list.
        assert_eq!(base.len(), GREP_EXCLUDED.len() + 2);
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
    fn sandbox_snippet_leaves_out_never_entries_and_sizes_by_tier() {
        let relaxed = sandbox_deny_read(SbTier::Relaxed);
        let all = sandbox_deny_read(SbTier::High);
        assert!(relaxed.iter().any(|g| g == "~/.ssh/**"));
        assert!(relaxed.iter().any(|g| g == "~/.claude/.credentials.json"));
        assert!(
            !relaxed.iter().any(|g| g == "~/.npmrc"),
            "medium host token"
        );
        assert!(all.iter().any(|g| g == "~/.npmrc"));
        assert!(all.iter().any(|g| g == "~/.config/gh/hosts.yml"));
        for list in [&relaxed, &all] {
            assert!(!list.iter().any(|g| g.contains("solana")));
            assert!(!list.iter().any(|g| g.contains("keypair")));
            assert!(list
                .iter()
                .all(|g| !g.starts_with('!') && !g.ends_with('/')));
        }
        if cfg!(not(windows)) {
            assert!(!all.iter().any(|g| g.contains("AppData")));
        }
    }

    fn rec(line: &str) -> Vec<Credential> {
        lists::parse_credentials(line).unwrap()
    }

    #[test]
    fn deny_read_filters_apply_to_host_os_rows_too() {
        let list = rec("key_material any relaxed ~/.a/\n\
             !key_material macos relaxed ~/.b\n\
             key_material macos never ~/.c\n\
             key_material macos medium ~/.d\n\
             key_material linux relaxed ~/.e\n\
             key_material macos relaxed ~/.f\n");
        let globs = deny_read_globs(&list, Os::Macos, SbTier::Relaxed, None);
        assert_eq!(globs, vec!["~/.a/**", "~/.f"]);
        let globs = deny_read_globs(&list, Os::Macos, SbTier::Medium, None);
        assert_eq!(globs, vec!["~/.a/**", "~/.d", "~/.f"]);
    }

    #[test]
    fn config_dir_credentials_are_named_at_their_real_path() {
        let list =
            rec("key_material any relaxed ${CLAUDE_CONFIG_DIR:-~/.claude}/.credentials.json\n");
        let globs = deny_read_globs(
            &list,
            Os::Linux,
            SbTier::Relaxed,
            Some("/cfg/claude".into()),
        );
        assert_eq!(
            globs,
            vec![
                "~/.claude/.credentials.json",
                "/cfg/claude/.credentials.json"
            ]
        );
    }

    #[test]
    fn shell_patterns_match_file_and_directory_records() {
        for p in [
            "~/.git-credential?",
            "~/.n?trc",
            "~/.npmr?",
            "~/.docker/config.js?n",
            "~/.config/gh/hosts.y*",
            "~/.kube/conf*",
            "~/.ss?/id_rsa",
            "~/.[n]etrc",
            "~/.a*/credentials",
            "~/.aws/cred*",
            "~/.*/credentials",
        ] {
            assert!(is_credential_glob(Path::new(p)), "{p}");
            // Read as literal names they are not stores (unless under a directory record).
            if !p.contains("aws") && !p.contains("ss?") && !p.contains("*/credentials") {
                assert!(!is_credential(Path::new(p)), "literal reading of {p}");
            }
        }
        for p in [
            "~/.npmrc?x",
            "~/.ssh/*.pub",
            "~/.ssh/conf*",
            "~/proj/*.json",
            "~/docs/[id].tsx",
            "/p/src/*.rs",
        ] {
            assert!(!is_credential_glob(Path::new(p)), "{p}");
        }
    }

    #[test]
    fn a_home_segment_anywhere_re_roots_the_path() {
        for p in [
            "/proj/$HOME/.aws/credentials",
            "/proj/${HOME}/.npmrc",
            "/proj/%USERPROFILE%/.netrc",
            "/proj/~/.ssh/id_rsa",
            "/proj/~bob/.aws/credentials",
            "$USERPROFILE/.aws/credentials",
        ] {
            assert!(cred(p), "{p}");
        }
        assert!(!cred("/proj/$HOME/src/main.rs"));
        assert!(!cred("/proj/$HOME/.ssh/config"));
    }

    #[test]
    fn reaches_store_is_at_or_above_a_store() {
        let home = std::env::var("HOME").unwrap_or_default();
        if home.is_empty() {
            return;
        }
        for d in ["~", "~/.config", "~/Library", "~/.ssh", "~/.config/gh", "/"] {
            assert!(reaches_store(Path::new(d)), "{d}");
        }
        for d in [
            "~/proj",
            "~/Documents",
            "/tmp/nowhere",
            "src",
            "~/.ssh/config/x",
        ] {
            assert!(!reaches_store(Path::new(d)), "{d}");
        }
    }

    #[test]
    fn project_greps_exclude_the_anywhere_records() {
        let globs = grep_exclusions(Path::new("/tmp/some/project"));
        for want in [
            "**/Local?Extension?Settings/**",
            "**/IndexedDB/chrome-extension_*/**",
        ] {
            assert!(globs.iter().any(|g| g == want), "{want}: {globs:?}");
        }
        assert!(!globs.iter().any(|g| g.contains(".aws")));
    }

    #[test]
    fn a_grep_root_inside_a_home_also_gets_root_relative_globs() {
        let Some(home) = home_dirs().into_iter().next() else {
            return;
        };
        let globs = grep_exclusions(&home.join(".config"));
        for want in [
            "gh/hosts.yml",
            "solana/**",
            "varlock/**",
            "**/.config/gh/hosts.yml",
        ] {
            assert!(globs.iter().any(|g| g == want), "{want}: {globs:?}");
        }
        let globs = grep_exclusions(&home.join("Library/Application Support"));
        assert!(globs.iter().any(|g| g == "Google/Chrome/**"), "{globs:?}");
    }
}
