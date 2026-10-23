//! The dependency pin (issue #11): what a pack's dependency set was when it was pinned, and
//! what the project's MCP servers launched last session.
//!
//! The pack pin ([`super::state::PackEntry::tree_hash`]) already covers every file, so a changed
//! manifest or lockfile is drift and blocks. What it cannot say is *which* part of the pack
//! moved. Next to each pin this records a dependency fingerprint: SHA-256 over the pack's
//! dependency files ([`rules::deps::kind_of`]: manifests, lockfiles, build scripts,
//! package-manager and MCP configs), each by path and content hash. While the pin stands and the
//! current set differs from the pinned one, the sweep's report for that pack says so and names
//! the files ("dependency set differs from the pin: changed package-lock.json, added
//! Cargo.lock"). The set is re-recorded whenever the pin is (first sight, approval, trust).
//!
//! The project's `.mcp.json` has no pin. Its servers' launch lines are recorded here each
//! session, and a launch that changed since the last session is reported once (INFO): a server
//! moved from `pkg@1.2.0` to `pkg@latest`, a new `docker run`, a removed server.
//!
//! Stored in the authenticated `deps.json` ([`crate::statefile`]). It is explanatory: a missing
//! or tampered file is started afresh (no detail until the next pin), and drift still blocks
//! through `state.json`. Offline, never follows symlinks (a linked dependency file is recorded
//! by its target text), never opens anything but a regular file (a FIFO, socket or device is
//! recorded by its type), skips `node_modules/` and the pack-root `.git`, and is bounded by
//! [`MAX_WALK`] entries, the deps family's per-file caps and a deadline checked on every entry
//! and every 64 KiB hashed: [`WALK_BUDGET`], within the sweep's own budget. A snapshot the
//! deadline cuts records the pack as unscanned, like a scan the sweep's budget cuts
//! (`scan_budget_exceeded`): denied below Off until a later sweep completes it. A sweep whose
//! budget is already spent skips the snapshot and keeps the last one.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use super::rules::deps;
use super::state::{self, PackEntry};
use super::{escape_for_report, SessionResult};
use crate::datadir::DataDir;
use crate::statefile::{self, Loaded};

/// The authenticated file the pins live in.
pub const DEPS_FILE: &str = "deps.json";
/// Directory entries one snapshot walks before it stops (and is marked truncated).
const MAX_WALK: usize = 50_000;
/// Time one snapshot may take (the per-pack scan allowance); past it the pack is unscanned.
const WALK_BUDGET: Duration = Duration::from_secs(2);
/// Pack pins and project `.mcp.json` records kept, so `deps.json` stays far below the state
/// file size limit.
const MAX_PACK_PINS: usize = 1024;
const MAX_MCP_PROJECTS: usize = 128;
/// Files whose individual hashes a stored set keeps (the fingerprint covers up to
/// [`deps::MAX_DEP_FILES`]).
const MAX_STORED_FILES: usize = 128;
/// Files a report line names before counting the rest.
const MAX_NAMED: usize = 5;
/// Bytes of the project `.mcp.json` read, and servers recorded from it.
const MAX_MCP_BYTES: u64 = 1024 * 1024;
const MAX_MCP_SERVERS: usize = 256;
/// Bytes of one launch line kept.
const MAX_LAUNCH_BYTES: usize = 512;

/// A pack's dependency files at one content state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepSet {
    /// SHA-256 over every recorded `(path, content hash)`, sorted by path; empty for a pack
    /// with no dependency files.
    pub fingerprint: String,
    /// Path → content hash, for the first [`MAX_STORED_FILES`] files.
    #[serde(default)]
    pub files: BTreeMap<String, String>,
    /// The walk stopped early or the set has more files than [`Self::files`] keeps.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

/// One pack's dependency pin.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackDeps {
    /// The pack pin ([`PackEntry::tree_hash`]) [`Self::pinned`] was recorded for.
    pub tree_pin: String,
    /// The dependency set at pin time (`None` when the pinned content was never seen, e.g. a
    /// pin carried over from v1 or recorded before this file existed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned: Option<DepSet>,
    /// Content hash [`Self::seen`] was taken from (spares the walk while it stands).
    pub seen_hash: String,
    /// The dependency set at [`Self::seen_hash`].
    pub seen: DepSet,
}

/// The `deps.json` body.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepPins {
    /// By pack state key ([`state::key_of`]).
    #[serde(default)]
    pub packs: BTreeMap<String, PackDeps>,
    /// By project `.mcp.json` path: server name → launch line.
    #[serde(default)]
    pub mcp: BTreeMap<String, BTreeMap<String, String>>,
}

/// The pins as one sweep reads and updates them.
pub struct Pins {
    data: DepPins,
    observed: BTreeSet<String>,
    dirty: bool,
}

impl Pins {
    /// Load `deps.json` (a missing or tampered file starts empty).
    pub fn load(dir: &DataDir) -> Pins {
        let data = match statefile::load::<DepPins>(dir, DEPS_FILE) {
            Loaded::Valid(d) => d,
            Loaded::Missing | Loaded::Tampered => DepPins::default(),
        };
        Pins {
            data,
            observed: BTreeSet::new(),
            dirty: false,
        }
    }

    /// Record the dependency set of the pack at `canonical` (whose entry the sweep just
    /// evaluated) and, while its pin stands and the set differs from the pinned one, add the
    /// difference to the entry's one-off report note.
    ///
    /// The snapshot runs until [`WALK_BUDGET`] from now or `sweep_until`, whichever is first.
    /// When the sweep's budget is already spent it is skipped (the last one is kept); when the
    /// deadline cuts it, the pack is recorded unscanned (see the module docs).
    pub fn observe(
        &mut self,
        canonical: &Path,
        entry: &mut PackEntry,
        sweep_until: Option<Instant>,
    ) {
        let current = entry.last_scanned_hash.clone();
        if current.is_empty() {
            return;
        }
        let key = state::key_of(canonical);
        self.observed.insert(key.clone());
        let prev = self.data.packs.get(&key);
        let seen = match prev {
            Some(p) if p.seen_hash == current => p.seen.clone(),
            _ => {
                let now = Instant::now();
                if sweep_until.is_some_and(|d| now >= d) {
                    return;
                }
                let mut deadline = now + WALK_BUDGET;
                if let Some(d) = sweep_until {
                    deadline = deadline.min(d);
                }
                match snapshot_until(canonical, deadline) {
                    Some(set) => set,
                    None => {
                        mark_unscanned(entry);
                        return;
                    }
                }
            }
        };
        let mut next = prev.cloned().unwrap_or_default();
        if prev.map(|p| p.tree_pin.as_str()) != Some(entry.tree_hash.as_str()) {
            next.tree_pin = entry.tree_hash.clone();
            next.pinned = (entry.tree_hash == current).then(|| seen.clone());
        }
        next.seen_hash = current;
        next.seen = seen;
        if let Some(pinned) = &next.pinned {
            if pinned.fingerprint != next.seen.fingerprint {
                let diff = describe_change(pinned, &next.seen);
                entry.note = Some(match entry.note.take() {
                    Some(note) => format!("{note}; {diff}"),
                    None => diff,
                });
            }
        }
        if self.data.packs.get(&key) != Some(&next) {
            self.data.packs.insert(key, next);
            self.dirty = true;
        }
    }

    /// Compare the project's `.mcp.json` launches with last session's, append a report line for
    /// any change to `result`, forget pins of packs that no longer exist, and store the pins.
    pub fn finish(mut self, dir: &DataDir, project_dir: &Path, result: &mut SessionResult) {
        let path = project_dir.join(".mcp.json");
        let key = path
            .canonicalize()
            .unwrap_or_else(|_| path.clone())
            .to_string_lossy()
            .into_owned();
        let key = &key;
        let current = project_launches(&path);
        let lines = match (self.data.mcp.get(key), &current) {
            (Some(prev), Some(now)) => launch_changes(prev, now),
            (Some(prev), None) if !prev.is_empty() => launch_changes(prev, &BTreeMap::new()),
            _ => Vec::new(),
        };
        match current {
            Some(now) if self.data.mcp.get(key) != Some(&now) => {
                self.data.mcp.insert(key.clone(), now);
                self.dirty = true;
            }
            None if self.data.mcp.remove(key).is_some() => self.dirty = true,
            _ => {}
        }
        if !lines.is_empty() {
            let shown: Vec<String> = lines.iter().take(MAX_NAMED * 2).cloned().collect();
            let more = lines.len().saturating_sub(shown.len());
            let more = if more > 0 {
                format!("; and {more} more")
            } else {
                String::new()
            };
            let line = format!(
                "safe-ai-skill: INFO .mcp.json server launch changed since the last session \
                 (the new command runs at the next start; pin an exact version to review it \
                 once): {}{more}",
                shown.join("; ")
            );
            for text in [&mut result.system_message, &mut result.additional_context] {
                if !text.is_empty() {
                    text.push('\n');
                }
                text.push_str(&line);
            }
        }
        let observed = &self.observed;
        let before = (self.data.packs.len(), self.data.mcp.len());
        self.data
            .packs
            .retain(|k, _| observed.contains(k) || state::path_of(k).exists());
        self.data.mcp.retain(|k, _| Path::new(k).exists());
        // Past the caps, keep what this sweep saw and drop the rest (oldest keys first).
        while self.data.packs.len() > MAX_PACK_PINS {
            let Some(k) = self
                .data
                .packs
                .keys()
                .find(|k| !observed.contains(*k))
                .cloned()
            else {
                break;
            };
            self.data.packs.remove(&k);
        }
        while self.data.mcp.len() > MAX_MCP_PROJECTS {
            let Some(k) = self.data.mcp.keys().find(|k| *k != key).cloned() else {
                break;
            };
            self.data.mcp.remove(&k);
        }
        self.dirty |= (self.data.packs.len(), self.data.mcp.len()) != before;
        if self.dirty {
            if let Err(e) = statefile::store(dir, DEPS_FILE, &self.data) {
                audit_store_failure(dir, &e.to_string());
            }
        }
    }
}

/// `path` with backticks escaped, for a note `escape_detail` keeps backticks in.
fn plain(path: &str) -> String {
    escape_for_report(path)
}

/// "dependency set differs from the pin: changed a, added b, removed c".
fn describe_change(pinned: &DepSet, now: &DepSet) -> String {
    let mut parts: Vec<String> = Vec::new();
    for (path, hash) in &now.files {
        match pinned.files.get(path) {
            Some(h) if h == hash => {}
            Some(_) => parts.push(format!("changed {}", plain(path))),
            None => parts.push(format!("added {}", plain(path))),
        }
    }
    for path in pinned.files.keys() {
        if !now.files.contains_key(path) {
            parts.push(format!("removed {}", plain(path)));
        }
    }
    let total = parts.len();
    parts.truncate(MAX_NAMED);
    let mut text = "dependency set differs from the pin".to_string();
    if !parts.is_empty() {
        text.push_str(": ");
        text.push_str(&parts.join(", "));
    }
    if total > MAX_NAMED {
        text.push_str(&format!(" and {} more", total - MAX_NAMED));
    } else if pinned.truncated || now.truncated {
        text.push_str(" (more files than are listed)");
    }
    text
}

/// Record `entry` as unscanned, like the sweep records a pack its budget cut: `unreviewed`
/// with a HIGH `scan_budget_exceeded` (a blocked pack stays blocked), and nothing cached, so
/// the next sweep evaluates it again.
fn mark_unscanned(entry: &mut PackEntry) {
    use super::grading::{Ctx, Grade};
    use state::{PackStatus, Reason, StoredFinding, StoredSev, SCAN_BUDGET_RULE};
    if entry.state != PackStatus::Blocked {
        entry.state = PackStatus::Unreviewed;
        entry.reason = Some(Reason::Heuristic);
        entry.grade = entry.grade.max(Grade::High);
    }
    if !entry.findings.iter().any(|f| f.rule == SCAN_BUDGET_RULE) {
        entry.findings.insert(
            0,
            StoredFinding {
                rule: SCAN_BUDGET_RULE.to_string(),
                sev: StoredSev::High,
                path: String::new(),
                line: 0,
                ctx: Ctx::Meta,
            },
        );
        entry.findings.truncate(state::MAX_STORED_FINDINGS);
    }
    if !entry.flagged_rules.iter().any(|r| r == SCAN_BUDGET_RULE) {
        entry.flagged_rules.push(SCAN_BUDGET_RULE.to_string());
        entry.flagged_rules.sort();
    }
    entry.last_scanned_hash = String::new();
    entry.fingerprint = String::new();
}

/// An audit line for a `deps.json` that could not be stored (the detail is lost, nothing else).
fn audit_store_failure(dir: &DataDir, why: &str) {
    let reason = format!("{DEPS_FILE} not stored: {why}");
    let entry = crate::audit::AuditEntry::new(
        String::new(),
        "safe-ai-skill".to_string(),
        "deps_pin_store_failed".to_string(),
        "error".to_string(),
        reason.clone(),
        crate::audit::sha256_hex(reason.as_bytes()),
    );
    let _ = crate::audit::append(&entry, &dir.path);
}

/// The dependency files of the pack at `root` and their fingerprint, within [`WALK_BUDGET`].
/// A snapshot the budget cuts has the fingerprint `unscanned` (and `truncated`).
pub fn snapshot(root: &Path) -> DepSet {
    snapshot_until(root, Instant::now() + WALK_BUDGET).unwrap_or_else(|| DepSet {
        fingerprint: "unscanned".to_string(),
        files: BTreeMap::new(),
        truncated: true,
    })
}

/// [`snapshot`] against `deadline`, checked on every entry and every 64 KiB hashed; `None`
/// when it passes first. `root` may be a single file (a one-file pack).
pub fn snapshot_until(root: &Path, deadline: Instant) -> Option<DepSet> {
    let mut truncated = false;
    let mut found: Vec<(String, String)> = Vec::new();
    let walker = WalkDir::new(root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name();
            !(e.depth() == 1 && name == ".git")
                && !(e.file_type().is_dir() && name == "node_modules")
        });
    for (n, entry) in walker.flatten().enumerate() {
        if Instant::now() >= deadline {
            return None;
        }
        if n >= MAX_WALK {
            truncated = true;
            break;
        }
        let ft = entry.file_type();
        if ft.is_dir() {
            continue;
        }
        let rel = match entry.path().strip_prefix(root) {
            Ok(r) if !r.as_os_str().is_empty() => r.to_path_buf(),
            // A single-file pack: the root itself is the file.
            _ => match entry.path().file_name() {
                Some(name) => std::path::PathBuf::from(name),
                None => continue,
            },
        };
        if deps::kind_of(&rel).is_none() {
            continue;
        }
        if found.len() >= deps::MAX_DEP_FILES {
            truncated = true;
            break;
        }
        let hash = if ft.is_symlink() {
            let target = std::fs::read_link(entry.path()).unwrap_or_default();
            format!("link:{}", target.to_string_lossy())
        } else if ft.is_file() {
            file_hash(entry.path(), deadline)?
        } else {
            // A FIFO, socket or device: never opened (a FIFO would block).
            "other".to_string()
        };
        found.push((rel.to_string_lossy().replace('\\', "/"), hash));
    }
    let mut set = DepSet {
        truncated: truncated || found.len() > MAX_STORED_FILES,
        ..DepSet::default()
    };
    if !found.is_empty() {
        let mut h = Sha256::new();
        for (path, hash) in &found {
            h.update(path.as_bytes());
            h.update([0]);
            h.update(hash.as_bytes());
            h.update(b"\n");
        }
        set.fingerprint = hex(&h.finalize());
    }
    set.files = found.into_iter().take(MAX_STORED_FILES).collect();
    Some(set)
}

/// SHA-256 of a regular file's first [`deps::MAX_DEP_BYTES`] plus its full size (so a change
/// past the cap that changes the size still shows); `unreadable` when it is not a regular file
/// or cannot be read (see [`deps::open_regular`]). `None` when `deadline` passes mid-way.
fn file_hash(path: &Path, deadline: Instant) -> Option<String> {
    let Some(file) = deps::open_regular(path) else {
        return Some("unreadable".to_string());
    };
    let size = file.metadata().map(|m| m.len()).unwrap_or(0);
    let mut h = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut reader = file.take(deps::MAX_DEP_BYTES);
    loop {
        if Instant::now() >= deadline {
            return None;
        }
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => h.update(&buf[..n]),
            Err(_) => return Some("unreadable".to_string()),
        }
    }
    h.update(size.to_le_bytes());
    Some(hex(&h.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The dependency inventory of `root` as JSON (`verify check` prints it).
pub fn inventory_json(root: &Path) -> serde_json::Value {
    let set = snapshot(root);
    serde_json::json!({
        "fingerprint": set.fingerprint,
        "files": set.files.iter().map(|(p, h)| serde_json::json!({"path": p, "sha256": h})).collect::<Vec<_>>(),
        "truncated": set.truncated,
    })
}

/// Server name → launch line of the project `.mcp.json`, `None` when it is missing or does not
/// parse (an empty map when it has no servers).
fn project_launches(path: &Path) -> Option<BTreeMap<String, String>> {
    let text = deps::read_capped(path, MAX_MCP_BYTES)?;
    let json: serde_json::Value = serde_json::from_str(&text).ok()?;
    let mut out = BTreeMap::new();
    if let Some(map) = deps::launch::project_servers(&json) {
        for (name, cfg) in map.iter().take(MAX_MCP_SERVERS) {
            if let Some(mut line) = deps::launch::launch_line(cfg) {
                if line.len() > MAX_LAUNCH_BYTES {
                    let cut = (0..=MAX_LAUNCH_BYTES)
                        .rev()
                        .find(|&k| line.is_char_boundary(k))
                        .unwrap_or(0);
                    line.truncate(cut);
                    line.push('…');
                }
                out.insert(name.clone(), line);
            }
        }
    }
    Some(out)
}

/// One report fragment per server whose launch changed, was added or removed.
fn launch_changes(prev: &BTreeMap<String, String>, now: &BTreeMap<String, String>) -> Vec<String> {
    let mut out = Vec::new();
    for (name, line) in now {
        match prev.get(name) {
            Some(old) if old == line => {}
            Some(old) => out.push(format!(
                "`{}` `{}` -> `{}`",
                escape_for_report(name),
                escape_for_report(old),
                escape_for_report(line)
            )),
            None => out.push(format!(
                "`{}` added: `{}`",
                escape_for_report(name),
                escape_for_report(line)
            )),
        }
    }
    for name in prev.keys() {
        if !now.contains_key(name) {
            out.push(format!("`{}` removed", escape_for_report(name)));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "safe-ai-skill-deppin-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn snapshot_covers_dependency_files_only_and_skips_node_modules() {
        let d = tmp("snap");
        fs::write(d.join("SKILL.md"), "# x").unwrap();
        fs::write(d.join("package.json"), "{}").unwrap();
        fs::create_dir_all(d.join("node_modules/a")).unwrap();
        fs::write(d.join("node_modules/a/package.json"), "{}").unwrap();
        fs::create_dir_all(d.join("crate")).unwrap();
        fs::write(d.join("crate/Cargo.toml"), "[package]").unwrap();
        let s = snapshot(&d);
        let paths: Vec<&str> = s.files.keys().map(String::as_str).collect();
        assert_eq!(paths, vec!["crate/Cargo.toml", "package.json"]);
        assert_eq!(s.fingerprint.len(), 64);
        let again = snapshot(&d);
        assert_eq!(s, again);
        fs::write(d.join("package.json"), "{\"dependencies\":{}}").unwrap();
        assert_ne!(snapshot(&d).fingerprint, s.fingerprint);
        let empty = tmp("snap-empty");
        assert_eq!(snapshot(&empty).fingerprint, "");
        let _ = fs::remove_dir_all(&d);
        let _ = fs::remove_dir_all(&empty);
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_named_like_a_dependency_file_is_recorded_not_opened() {
        let d = tmp("fifo");
        fs::write(d.join("SKILL.md"), "# x").unwrap();
        crate::statefile::tests::mkfifo(&d.join("Cargo.lock"));
        crate::statefile::tests::mkfifo(&d.join("package.json"));
        let started = Instant::now();
        let s = snapshot(&d);
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(s.files.get("Cargo.lock").map(String::as_str), Some("other"));
        assert_eq!(
            s.files.get("package.json").map(String::as_str),
            Some("other")
        );
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_passed_deadline_leaves_the_snapshot_unscanned() {
        let d = tmp("late");
        fs::write(d.join("package.json"), "{}").unwrap();
        assert_eq!(snapshot_until(&d, Instant::now()), None);
        let mut entry = PackEntry {
            kind: state::PackKind::Skill,
            tree_hash: "h".into(),
            head: None,
            first_seen: 0,
            last_scanned_hash: "h".into(),
            grade: super::super::grading::Grade::Clean,
            state: state::PackStatus::Clean,
            findings: Vec::new(),
            more_findings: 0,
            flagged_rules: Vec::new(),
            reason: None,
            names: Vec::new(),
            names_incomplete: false,
            escaping: Vec::new(),
            approved: false,
            fingerprint: "f".into(),
            hashed_sweep: 0,
            quarantined_to: None,
            note: None,
        };
        let mut pins = Pins {
            data: DepPins::default(),
            observed: BTreeSet::new(),
            dirty: false,
        };
        // A spent sweep budget skips the snapshot and leaves the entry alone.
        pins.observe(&d, &mut entry, Some(Instant::now()));
        assert_eq!(entry.state, state::PackStatus::Clean);
        assert!(pins.data.packs.is_empty());
        mark_unscanned(&mut entry);
        assert!(entry.unscanned());
        assert!(entry.last_scanned_hash.is_empty());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_single_file_pack_is_inventoried() {
        let d = tmp("single");
        fs::write(d.join("Cargo.toml"), "[package]").unwrap();
        let s = snapshot(&d.join("Cargo.toml"));
        assert_eq!(s.files.keys().collect::<Vec<_>>(), vec!["Cargo.toml"]);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn change_description_names_files_and_caps() {
        let set = |pairs: &[(&str, &str)]| DepSet {
            fingerprint: format!("{pairs:?}"),
            files: pairs
                .iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect(),
            truncated: false,
        };
        let a = set(&[("package.json", "1"), ("yarn.lock", "2")]);
        let b = set(&[("package.json", "9"), ("Cargo.lock", "3")]);
        assert_eq!(
            describe_change(&a, &b),
            "dependency set differs from the pin: added Cargo.lock, changed package.json, removed yarn.lock"
        );
        let many: Vec<(String, String)> = (0..9)
            .map(|i| (format!("d{i}/go.mod"), "x".into()))
            .collect();
        let many = DepSet {
            fingerprint: "m".into(),
            files: many.into_iter().collect(),
            truncated: false,
        };
        let text = describe_change(&DepSet::default(), &many);
        assert!(text.ends_with(" and 4 more"), "{text}");
        let tick = set(&[("a`b/package.json", "1")]);
        assert!(!describe_change(&DepSet::default(), &tick).contains('`'));
    }

    #[test]
    fn launch_change_lines() {
        let prev: BTreeMap<String, String> = [
            ("a".to_string(), "npx a@1.0.0".to_string()),
            ("b".to_string(), "uvx b==1".to_string()),
        ]
        .into_iter()
        .collect();
        let now: BTreeMap<String, String> = [
            ("a".to_string(), "npx a@latest".to_string()),
            ("c`x".to_string(), "docker run c".to_string()),
        ]
        .into_iter()
        .collect();
        let lines = launch_changes(&prev, &now);
        assert_eq!(
            lines,
            vec![
                "`a` `npx a@1.0.0` -> `npx a@latest`".to_string(),
                "`c\\u{0060}x` added: `docker run c`".to_string(),
                "`b` removed".to_string(),
            ]
        );
    }
}
