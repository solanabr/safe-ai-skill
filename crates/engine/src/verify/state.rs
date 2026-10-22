//! Supply-chain state v2 (spec D2.2): `${DATA}/state.json`, one entry per pack keyed by its
//! canonical absolute path, stored authenticated through [`crate::statefile`].
//!
//! An entry's `tree_hash` is the pack's pin: the content it was first recorded at, or last
//! approved at. Drift is any difference from it, which blocks until the user approves the new
//! content. `last_scanned_hash` is the content the stored findings belong to, so an unchanged
//! pack is not re-scanned. [`decide`] is the pure state transition every caller goes through.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use super::grading::{self, Grade};
use crate::datadir::DataDir;
use crate::error::EngineError;
use crate::statefile::{self, Loaded};

/// The state file name.
pub const STATE_FILE: &str = "state.json";
/// Format version written into [`State::version`].
pub const STATE_VERSION: u32 = 2;
/// Findings kept per pack entry (the rest are counted in [`PackEntry::more_findings`]).
pub const MAX_STORED_FINDINGS: usize = 50;
/// Domain separation of [`tree_hash`].
const TREE_DOMAIN: &[u8] = b"safe-ai-skill/tree/v2\0";

/// How a pack is laid out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PackKind {
    /// A skill directory under a skills root.
    Skill,
    /// An `ext/<name>` git submodule.
    Ext,
}

impl PackKind {
    /// Label used in reports.
    pub fn label(self) -> &'static str {
        match self {
            PackKind::Skill => "skill",
            PackKind::Ext => "ext",
        }
    }
}

/// Review state of a pack, from least to most restrictive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PackStatus {
    /// Nothing above INFO, or approved / trusted by the user.
    Clean,
    /// Warnings only (documentation findings are capped here).
    Warned,
    /// A code/meta HIGH finding nobody reviewed yet: reported, not blocked.
    Unreviewed,
    /// Denied by the gates until the user approves it.
    Blocked,
}

impl PackStatus {
    /// Stable label.
    pub fn label(self) -> &'static str {
        match self {
            PackStatus::Clean => "clean",
            PackStatus::Warned => "warned",
            PackStatus::Unreviewed => "unreviewed",
            PackStatus::Blocked => "blocked",
        }
    }
}

/// Why a pack is in its state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// Single findings (HIGH or WARN).
    Heuristic,
    /// A combination rule fired.
    Combo,
    /// The content differs from its pin.
    Drift,
    /// The content differs from the project's committed `packs.lock`.
    LockMismatch,
}

impl Reason {
    /// Stable label.
    pub fn label(self) -> &'static str {
        match self {
            Reason::Heuristic => "heuristic",
            Reason::Combo => "combo",
            Reason::Drift => "drift",
            Reason::LockMismatch => "lock_mismatch",
        }
    }
}

/// Severity of a stored finding: the scanner's severities plus `block` for a combo hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StoredSev {
    /// Inventory.
    Info,
    /// Warning.
    Warn,
    /// Code/meta HIGH.
    High,
    /// A combination rule.
    Block,
}

/// One finding as stored: `{rule, sev, path, line, ctx}` (spec D2.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredFinding {
    /// Rule (or combo) id.
    pub rule: String,
    /// Severity.
    pub sev: StoredSev,
    /// Path relative to the pack root (`/`-separated).
    pub path: String,
    /// 1-based line; `0` when not line-addressable.
    #[serde(default)]
    pub line: u32,
    /// `code`, `doc` or `meta`.
    pub ctx: grading::Ctx,
}

impl StoredFinding {
    /// `path:line` (just `path` when the line is unknown).
    pub fn location(&self) -> String {
        if self.line == 0 {
            self.path.clone()
        } else {
            format!("{}:{}", self.path, self.line)
        }
    }
}

/// One pack's entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackEntry {
    /// Layout.
    pub kind: PackKind,
    /// The pin: recorded on first sight, replaced only by an approval or a v1 re-baseline. A
    /// pin carried over from a v1 lockfile that no longer matches is `v1:<identity>`.
    pub tree_hash: String,
    /// The checked-out commit of an ext submodule, for display.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
    /// Unix seconds when first recorded.
    pub first_seen: u64,
    /// Content the stored findings and grade belong to.
    pub last_scanned_hash: String,
    /// Grade of the last scan.
    pub grade: Grade,
    /// Review state.
    pub state: PackStatus,
    /// Findings of the last scan (WARN and above; combos as `block`), capped.
    #[serde(default)]
    pub findings: Vec<StoredFinding>,
    /// Findings left out by the cap.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub more_findings: usize,
    /// Every combo and HIGH rule of the last scan (what a trust entry must acknowledge).
    #[serde(default)]
    pub flagged_rules: Vec<String>,
    /// Why the pack is not clean.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<Reason>,
    /// Skill names the pack provides (its directory name and each `SKILL.md` name).
    #[serde(default)]
    pub names: Vec<String>,
    /// Where `supply_chain.on_block: move` put the pack (its key stays the origin path).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarantined_to: Option<String>,
    /// A one-off note for the next report (e.g. a v1 re-baseline), cleared once reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

/// The `state.json` body.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// [`STATE_VERSION`].
    #[serde(default)]
    pub version: u32,
    /// Packs by canonical absolute path.
    #[serde(default)]
    pub packs: BTreeMap<String, PackEntry>,
    /// v1 lockfile pins already matched to a pack: `skill:<name>` / `ext:<name>` → that
    /// pack's canonical path. A v1 pin is keyed by bare name, so a second pack of the same
    /// name elsewhere is a collision, not drift.
    #[serde(default)]
    pub v1_claims: BTreeMap<String, String>,
}

/// Outcome of [`load`].
#[derive(Debug, Clone, PartialEq)]
pub struct LoadedState {
    /// The state (empty when missing or tampered).
    pub state: State,
    /// The file existed but failed authentication: every pack is seen afresh.
    pub tampered: bool,
}

/// Load `state.json` from `dir`. A tampered file is discarded (reported by the caller).
pub fn load(dir: &DataDir) -> LoadedState {
    match statefile::load::<State>(dir, STATE_FILE) {
        Loaded::Valid(state) => LoadedState {
            state,
            tampered: false,
        },
        Loaded::Missing => LoadedState {
            state: State::default(),
            tampered: false,
        },
        Loaded::Tampered => LoadedState {
            state: State::default(),
            tampered: true,
        },
    }
}

/// Store `state` (authenticated, atomic).
pub fn store(dir: &DataDir, state: &State) -> Result<(), EngineError> {
    let mut state = state.clone();
    state.version = STATE_VERSION;
    statefile::store(dir, STATE_FILE, &state)
}

/// What a scan of the current content observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// Current [`tree_hash`].
    pub hash: String,
    /// Grade of the current content.
    pub grade: Grade,
    /// Hash the project's `packs.lock` pins this path to, if any.
    pub lock: Option<String>,
    /// The user trusts exactly this content, acknowledging every HIGH and combo rule in it.
    pub trusted: bool,
    /// The project's `packs.lock` pins exactly this content.
    pub lock_matches: bool,
}

/// The result of [`decide`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    /// New state.
    pub state: PackStatus,
    /// Why.
    pub reason: Option<Reason>,
    /// The pin to keep.
    pub pin: String,
}

/// The pure state transition (spec D2.4, D2.7, D2.8).
///
/// `pin` is the entry's current pin (`None` on first sight). `floor` raises the state for a v1
/// re-baseline (`Warned`) or a v1 pin recorded with a HIGH scan (`Unreviewed`).
///
/// In order: trusted content is clean and becomes the pin; a combo blocks; content that
/// differs from its pin blocks (drift); content that differs from the committed `packs.lock`
/// blocks; otherwise the grade decides (HIGH → unreviewed, unless `packs.lock` pins this
/// exact content, which counts as reviewed → warned).
pub fn decide(pin: Option<&str>, obs: &Observation, floor: Option<PackStatus>) -> Transition {
    let recorded = pin.unwrap_or(&obs.hash).to_string();
    if obs.trusted {
        return Transition {
            state: PackStatus::Clean,
            reason: None,
            pin: obs.hash.clone(),
        };
    }
    if obs.grade == Grade::Block {
        return blocked(Reason::Combo, recorded);
    }
    if pin.is_some_and(|p| p != obs.hash) {
        return blocked(Reason::Drift, recorded);
    }
    if obs.lock.as_deref().is_some_and(|l| l != obs.hash) {
        return blocked(Reason::LockMismatch, recorded);
    }
    let (state, reason) = match obs.grade {
        Grade::High if obs.lock_matches => (PackStatus::Warned, Some(Reason::Heuristic)),
        Grade::High => (PackStatus::Unreviewed, Some(Reason::Heuristic)),
        Grade::Warn => (PackStatus::Warned, Some(Reason::Heuristic)),
        Grade::Clean | Grade::Block => (PackStatus::Clean, None),
    };
    match floor {
        Some(f) if f > state => Transition {
            state: f,
            reason: reason.or(Some(Reason::Heuristic)),
            pin: recorded,
        },
        _ => Transition {
            state,
            reason,
            pin: recorded,
        },
    }
}

fn blocked(reason: Reason, pin: String) -> Transition {
    Transition {
        state: PackStatus::Blocked,
        reason: Some(reason),
        pin,
    }
}

/// The findings of `report` worth storing (WARN and above, combos as `block`), capped at
/// [`MAX_STORED_FINDINGS`]; returns them and how many were left out.
pub fn stored_findings(report: &grading::PackReport) -> (Vec<StoredFinding>, usize) {
    let mut all: Vec<StoredFinding> = report
        .combos
        .iter()
        .map(|c| StoredFinding {
            rule: c.rule.to_string(),
            sev: StoredSev::Block,
            path: rel_display(&c.path),
            line: c.line.unwrap_or(0),
            ctx: grading::Ctx::Meta,
        })
        .collect();
    let mut singles: Vec<StoredFinding> = report
        .findings
        .iter()
        .filter_map(|f| {
            let sev = match f.effective_sev() {
                grading::Severity::High => StoredSev::High,
                grading::Severity::Warn => StoredSev::Warn,
                grading::Severity::Info => return None,
            };
            Some(StoredFinding {
                rule: f.rule.to_string(),
                sev,
                path: rel_display(&f.path),
                line: f.line.unwrap_or(0),
                ctx: f.ctx,
            })
        })
        .collect();
    // Worst first, keeping walk order within a severity.
    singles.sort_by_key(|f| std::cmp::Reverse(f.sev));
    all.append(&mut singles);
    let more = all.len().saturating_sub(MAX_STORED_FINDINGS);
    all.truncate(MAX_STORED_FINDINGS);
    (all, more)
}

/// The rules a trust entry must acknowledge for `report`: every combo and every HIGH.
pub fn flagged_rules(report: &grading::PackReport) -> Vec<String> {
    let mut rules: Vec<String> = report
        .combos
        .iter()
        .map(|c| c.rule.to_string())
        .chain(
            report
                .findings
                .iter()
                .filter(|f| f.effective_sev() == grading::Severity::High)
                .map(|f| f.rule.to_string()),
        )
        .collect();
    rules.sort();
    rules.dedup();
    rules
}

/// A pack-relative path as stored (`/`-separated).
fn rel_display(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

// ---------------------------------------------------------------------------------------
// tree_hash (spec D2.2)
// ---------------------------------------------------------------------------------------

/// The content identity of a pack: SHA-256 over its full entry set, never running git.
///
/// Every non-directory entry below `root` counts, sorted by relative path: a regular file as
/// `(path, 'F', exec bit, sha256(content))`, a symlink as `(path, 'L', target)` (never
/// followed), anything else as `(path, 'O')`, and an unreadable entry as `(path, 'E')`. Any
/// path component named `.git` is skipped, so a `git fetch` inside a checkout is not drift.
/// Only the exec bit of the mode counts (as git tracks it), so umask differences between
/// clones and worktrees do not change the hash. A missing `root` hashes to the empty string.
pub fn tree_hash(root: &Path) -> String {
    let Ok(meta) = root.symlink_metadata() else {
        return String::new();
    };
    let mut entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    if meta.is_dir() {
        let walker = WalkDir::new(root)
            .follow_links(false)
            .min_depth(1)
            .into_iter()
            .filter_entry(|e| e.file_name() != ".git");
        for entry in walker {
            match entry {
                Ok(e) if e.file_type().is_dir() => {}
                Ok(e) => {
                    let rel = rel_bytes(e.path().strip_prefix(root).unwrap_or(e.path()));
                    entries.push((rel, entry_record(e.path())));
                }
                Err(err) => {
                    if let Some(path) = err.path() {
                        let rel = rel_bytes(path.strip_prefix(root).unwrap_or(path));
                        entries.push((rel, b"E".to_vec()));
                    }
                }
            }
        }
    } else {
        let name = root
            .file_name()
            .map(|n| rel_bytes(Path::new(n)))
            .unwrap_or_default();
        entries.push((name, entry_record(root)));
    }
    entries.sort();

    let mut hasher = Sha256::new();
    hasher.update(TREE_DOMAIN);
    for (rel, record) in &entries {
        hasher.update((rel.len() as u64).to_le_bytes());
        hasher.update(rel);
        hasher.update((record.len() as u64).to_le_bytes());
        hasher.update(record);
    }
    hex(&hasher.finalize())
}

/// The record of one non-directory entry (see [`tree_hash`]).
fn entry_record(path: &Path) -> Vec<u8> {
    let Ok(meta) = path.symlink_metadata() else {
        return b"E".to_vec();
    };
    let ft = meta.file_type();
    if ft.is_symlink() {
        return match std::fs::read_link(path) {
            Ok(target) => {
                let mut r = b"L".to_vec();
                r.extend(rel_bytes(&target));
                r
            }
            Err(_) => b"E".to_vec(),
        };
    }
    if !ft.is_file() {
        return b"O".to_vec();
    }
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return b"E".to_vec(),
    };
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(_) => return b"E".to_vec(),
        }
    }
    let mut r = vec![b'F', if is_exec(&meta) { b'x' } else { b'-' }];
    r.extend_from_slice(&hasher.finalize());
    r
}

#[cfg(unix)]
fn is_exec(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_exec(_meta: &std::fs::Metadata) -> bool {
    false
}

/// Raw path bytes, `/`-separated (lossless on unix).
fn rel_bytes(path: &Path) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        path.to_string_lossy().replace('\\', "/").into_bytes()
    }
}

/// Lowercase hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// The skill names a pack provides: its directory name, and for every `SKILL.md` in it (not
/// under `.git`, symlinks not followed) the parent directory name and the frontmatter `name:`.
pub fn skill_names(root: &Path) -> Vec<String> {
    let mut names: Vec<String> = root
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| vec![n.to_string()])
        .unwrap_or_default();
    let walker = WalkDir::new(root)
        .follow_links(false)
        .max_depth(8)
        .into_iter()
        .filter_entry(|e| e.file_name() != ".git" && e.file_name() != "node_modules");
    for entry in walker.flatten() {
        if !entry.file_type().is_file() || entry.file_name() != "SKILL.md" {
            continue;
        }
        if let Some(dir) = entry
            .path()
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
        {
            names.push(dir.to_string());
        }
        if let Some(name) = frontmatter_name(entry.path()) {
            names.push(name);
        }
    }
    names.sort();
    names.dedup();
    names
}

/// The `name:` of a `SKILL.md` YAML frontmatter, read from its first 8 KiB.
fn frontmatter_name(path: &Path) -> Option<String> {
    let mut head = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(8 * 1024)
        .read_to_end(&mut head)
        .ok()?;
    let text = String::from_utf8_lossy(&head);
    let mut lines = text.lines();
    if lines.next()?.trim() != "---" {
        return None;
    }
    for line in lines {
        if line.trim() == "---" {
            break;
        }
        if let Some(value) = line.strip_prefix("name:") {
            let value = value.trim().trim_matches(|c| c == '"' || c == '\'').trim();
            return (!value.is_empty()).then(|| value.to_string());
        }
    }
    None
}

// ---------------------------------------------------------------------------------------
// packs.lock (spec D2.7)
// ---------------------------------------------------------------------------------------

/// Project-relative location of the committed pack lock.
pub const PACKS_LOCK: &str = ".safe-ai-skill/packs.lock";

/// One `packs.lock` pin.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct LockPin {
    path: String,
    tree_hash: String,
}

/// The `packs.lock` body: `{"packs": [{"path": "<project-relative>", "tree_hash": "…"}]}`.
#[derive(Debug, Clone, Default, Deserialize)]
struct PacksLockFile {
    #[serde(default)]
    packs: Vec<LockPin>,
}

/// Pins from a project's committed `packs.lock`, by canonical absolute path.
///
/// The file can only add pins: an entry constrains its pack to one content (a mismatch is
/// `lock_mismatch` BLOCK), and nothing in it can unblock, unpin or trust anything. Entries
/// whose path leaves the project are ignored, as is an unreadable or malformed file.
pub fn packs_lock(project_dir: &Path) -> BTreeMap<String, String> {
    let mut pins = BTreeMap::new();
    let Ok(text) = std::fs::read_to_string(project_dir.join(PACKS_LOCK)) else {
        return pins;
    };
    let Ok(file) = serde_json::from_str::<PacksLockFile>(&text) else {
        return pins;
    };
    let Ok(project) = project_dir.canonicalize() else {
        return pins;
    };
    for pin in file.packs {
        let rel = Path::new(&pin.path);
        if rel.is_absolute() || pin.tree_hash.is_empty() {
            continue;
        }
        let Ok(abs) = project.join(rel).canonicalize() else {
            continue;
        };
        if abs.starts_with(&project) && abs != project {
            pins.insert(key_of(&abs), pin.tree_hash);
        }
    }
    pins
}

/// The state key of a canonical path.
pub fn key_of(canonical: &Path) -> String {
    canonical.to_string_lossy().into_owned()
}

/// The canonical path of a state key.
pub fn path_of(key: &str) -> PathBuf {
    PathBuf::from(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "ssai-state-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn obs(hash: &str, grade: Grade) -> Observation {
        Observation {
            hash: hash.into(),
            grade,
            lock: None,
            trusted: false,
            lock_matches: false,
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlink_retarget_is_drift() {
        let d = tmp("symlink");
        fs::write(d.join("a"), "a").unwrap();
        fs::write(d.join("b"), "b").unwrap();
        std::os::unix::fs::symlink("a", d.join("link")).unwrap();
        let before = tree_hash(&d);
        fs::remove_file(d.join("link")).unwrap();
        std::os::unix::fs::symlink("b", d.join("link")).unwrap();
        assert_ne!(before, tree_hash(&d));
    }

    #[cfg(unix)]
    #[test]
    fn exec_bit_is_drift_but_other_mode_bits_are_not() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmp("mode");
        fs::write(d.join("run.sh"), "echo hi").unwrap();
        fs::set_permissions(d.join("run.sh"), fs::Permissions::from_mode(0o644)).unwrap();
        let before = tree_hash(&d);
        fs::set_permissions(d.join("run.sh"), fs::Permissions::from_mode(0o664)).unwrap();
        assert_eq!(before, tree_hash(&d), "group-write (umask) is not content");
        fs::set_permissions(d.join("run.sh"), fs::Permissions::from_mode(0o755)).unwrap();
        assert_ne!(before, tree_hash(&d), "chmod +x is drift");
    }

    #[test]
    fn git_dir_changes_are_not_drift() {
        let d = tmp("git");
        fs::write(d.join("SKILL.md"), "# s").unwrap();
        fs::create_dir_all(d.join(".git")).unwrap();
        fs::write(d.join(".git/HEAD"), "1111").unwrap();
        let before = tree_hash(&d);
        fs::write(d.join(".git/FETCH_HEAD"), "abcd").unwrap();
        fs::write(d.join(".git/HEAD"), "2222").unwrap();
        assert_eq!(before, tree_hash(&d));
        fs::write(d.join("SKILL.md"), "# s2").unwrap();
        assert_ne!(before, tree_hash(&d));
    }

    #[test]
    fn hash_is_independent_of_location_and_sensitive_to_names() {
        let a = tmp("loc-a");
        let b = tmp("loc-b");
        for d in [&a, &b] {
            fs::create_dir_all(d.join("sub")).unwrap();
            fs::write(d.join("sub/x"), "x").unwrap();
        }
        assert_eq!(tree_hash(&a), tree_hash(&b));
        fs::rename(b.join("sub/x"), b.join("sub/y")).unwrap();
        assert_ne!(tree_hash(&a), tree_hash(&b));
        assert_eq!(tree_hash(&a.join("missing")), "");
    }

    #[test]
    fn decide_first_sight_by_grade() {
        assert_eq!(
            decide(None, &obs("h", Grade::Clean), None).state,
            PackStatus::Clean
        );
        assert_eq!(
            decide(None, &obs("h", Grade::Warn), None).state,
            PackStatus::Warned
        );
        let t = decide(None, &obs("h", Grade::High), None);
        assert_eq!((t.state, t.pin.as_str()), (PackStatus::Unreviewed, "h"));
        let t = decide(None, &obs("h", Grade::Block), None);
        assert_eq!(
            (t.state, t.reason),
            (PackStatus::Blocked, Some(Reason::Combo))
        );
    }

    #[test]
    fn decide_drift_blocks_and_keeps_the_pin() {
        let t = decide(Some("old"), &obs("new", Grade::Clean), None);
        assert_eq!(
            (t.state, t.reason, t.pin.as_str()),
            (PackStatus::Blocked, Some(Reason::Drift), "old")
        );
        let t = decide(Some("new"), &obs("new", Grade::Clean), None);
        assert_eq!(t.state, PackStatus::Clean);
    }

    #[test]
    fn decide_lock_mismatch_blocks_and_a_lock_match_counts_as_reviewed() {
        let mut o = obs("h", Grade::Clean);
        o.lock = Some("other".into());
        let t = decide(None, &o, None);
        assert_eq!(
            (t.state, t.reason),
            (PackStatus::Blocked, Some(Reason::LockMismatch))
        );
        let mut o = obs("h", Grade::High);
        o.lock = Some("h".into());
        o.lock_matches = true;
        assert_eq!(decide(None, &o, None).state, PackStatus::Warned);
        // A lock match never clears a combo.
        let mut o = obs("h", Grade::Block);
        o.lock = Some("h".into());
        o.lock_matches = true;
        assert_eq!(decide(None, &o, None).state, PackStatus::Blocked);
    }

    #[test]
    fn decide_trust_clears_and_repins() {
        let mut o = obs("new", Grade::Block);
        o.trusted = true;
        let t = decide(Some("old"), &o, None);
        assert_eq!((t.state, t.pin.as_str()), (PackStatus::Clean, "new"));
    }

    #[test]
    fn decide_floor_raises_but_never_lowers() {
        let t = decide(Some("h"), &obs("h", Grade::Clean), Some(PackStatus::Warned));
        assert_eq!(t.state, PackStatus::Warned);
        let t = decide(
            Some("h"),
            &obs("h", Grade::Clean),
            Some(PackStatus::Unreviewed),
        );
        assert_eq!(t.state, PackStatus::Unreviewed);
        let t = decide(Some("x"), &obs("h", Grade::Clean), Some(PackStatus::Warned));
        assert_eq!(t.state, PackStatus::Blocked);
    }

    #[test]
    fn skill_names_reads_dirs_and_frontmatter() {
        let d = tmp("names").join("pack");
        fs::create_dir_all(d.join("skills/inner")).unwrap();
        fs::write(d.join("SKILL.md"), "---\nname: \"top-name\"\n---\n# x").unwrap();
        fs::write(d.join("skills/inner/SKILL.md"), "# no frontmatter").unwrap();
        assert_eq!(skill_names(&d), vec!["inner", "pack", "top-name"]);
    }

    #[test]
    fn packs_lock_only_inside_the_project() {
        let p = tmp("lock");
        fs::create_dir_all(p.join(".claude/skills/a")).unwrap();
        fs::create_dir_all(p.join(".safe-ai-skill")).unwrap();
        fs::write(
            p.join(PACKS_LOCK),
            r#"{"packs":[{"path":".claude/skills/a","tree_hash":"h1"},
                {"path":"../outside","tree_hash":"h2"},{"path":"/etc","tree_hash":"h3"}]}"#,
        )
        .unwrap();
        let pins = packs_lock(&p);
        assert_eq!(pins.len(), 1);
        let key = key_of(&p.join(".claude/skills/a").canonicalize().unwrap());
        assert_eq!(pins.get(&key).map(String::as_str), Some("h1"));
    }

    #[test]
    fn same_name_packs_in_two_projects_do_not_collide() {
        let a = tmp("p1").join(".claude/skills/foo");
        let b = tmp("p2").join(".claude/skills/foo");
        fs::create_dir_all(&a).unwrap();
        fs::create_dir_all(&b).unwrap();
        let ka = key_of(&a.canonicalize().unwrap());
        let kb = key_of(&b.canonicalize().unwrap());
        assert_ne!(ka, kb);
        let mut s = State::default();
        for (k, h) in [(&ka, "ha"), (&kb, "hb")] {
            s.packs.insert(
                k.clone(),
                PackEntry {
                    kind: PackKind::Skill,
                    tree_hash: h.into(),
                    head: None,
                    first_seen: 0,
                    last_scanned_hash: h.into(),
                    grade: Grade::Clean,
                    state: PackStatus::Clean,
                    findings: vec![],
                    more_findings: 0,
                    flagged_rules: vec![],
                    reason: None,
                    names: vec!["foo".into()],
                    quarantined_to: None,
                    note: None,
                },
            );
        }
        assert_eq!(s.packs.len(), 2);
        assert_eq!(s.packs[&ka].tree_hash, "ha");
        assert_eq!(s.packs[&kb].tree_hash, "hb");
    }
}
