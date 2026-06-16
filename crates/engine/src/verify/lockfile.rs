//! TOFU lockfile: sha256 dir-tree hashing, pin/diff, and quarantine.
//!
//! The lockfile lives at `${CLAUDE_PLUGIN_DATA}/lockfile.json` and records, per skill /
//! MCP, the content hash pinned on first use (trust-on-first-use). A later content change
//! surfaces as drift (current hash != pinned) rather than a silent update.
//!
//! Pure, hermetic helpers ([`hash_tree`], [`detect_drift`], the (de)serialization round-trip)
//! are unit-tested against tempdir fixtures; the only side effects are the atomic [`save`].

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

/// A pinned skill directory entry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SkillPin {
    /// Deterministic content hash of the skill directory tree.
    pub sha256: String,
    /// Source the skill was added from (GitHub URL, local path, etc.).
    #[serde(default)]
    pub source: String,
    /// Unix seconds when the entry was first verified / pinned.
    #[serde(default)]
    pub verified_at: u64,
    /// Highest severity observed at pin time (`"low"`/`"medium"`/`"high"`/`""`).
    #[serde(default)]
    pub scan: String,
}

/// A pinned MCP server entry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct McpPin {
    /// Package name (npm or other).
    pub pkg: String,
    /// Exact pinned version.
    #[serde(default)]
    pub version: String,
    /// Recorded `dist.shasum` / integrity, when known.
    #[serde(default)]
    pub shasum: String,
    /// Highest severity observed at pin time.
    #[serde(default)]
    pub scan: String,
}

/// A pinned `ext/<name>` git submodule entry.
///
/// Unlike [`SkillPin`] (which pins a content tree hash), a submodule is pinned at its
/// checked-out commit SHA when available, so a `resync.sh`-driven submodule bump surfaces as
/// drift. When the directory is not a git checkout, [`pin_ext`](Lockfile::pin_ext) falls back to
/// the [`hash_tree`] content hash and records `kind = "hash"`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtPin {
    /// Pinned identity: a 40-char git commit SHA, or a content tree hash on the fallback path.
    pub sha: String,
    /// Identity kind: `"git"` (commit SHA) or `"hash"` (content tree hash fallback).
    #[serde(default)]
    pub kind: String,
    /// Unix seconds when the entry was first verified / pinned.
    #[serde(default)]
    pub verified_at: u64,
    /// Highest severity observed at pin time (`"low"`/`"medium"`/`"high"`/`""`).
    #[serde(default)]
    pub scan: String,
}

/// The TOFU lockfile contents.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Lockfile {
    /// Pinned skill directories, keyed by skill name.
    #[serde(default)]
    pub skills: BTreeMap<String, SkillPin>,
    /// Pinned MCP servers, keyed by server name.
    #[serde(default)]
    pub mcps: BTreeMap<String, McpPin>,
    /// Pinned `ext/<name>` git submodules, keyed by submodule name.
    #[serde(default)]
    pub ext: BTreeMap<String, ExtPin>,
}

/// Result of comparing a current hash against the lockfile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftStatus {
    /// No pin recorded yet (first use).
    Unpinned,
    /// Pinned hash matches the current hash.
    Clean,
    /// Pinned hash differs from the current hash.
    Drifted,
}

impl Lockfile {
    /// Path of the lockfile under `plugin_data`.
    pub fn path(plugin_data: &Path) -> std::path::PathBuf {
        plugin_data.join("lockfile.json")
    }

    /// Classify a skill named `name` against its current tree `hash`.
    pub fn skill_drift(&self, name: &str, hash: &str) -> DriftStatus {
        match self.skills.get(name) {
            None => DriftStatus::Unpinned,
            Some(pin) if pin.sha256 == hash => DriftStatus::Clean,
            Some(_) => DriftStatus::Drifted,
        }
    }

    /// Record (or overwrite) a skill pin — trust-on-first-use.
    pub fn pin_skill(&mut self, name: impl Into<String>, pin: SkillPin) {
        self.skills.insert(name.into(), pin);
    }

    /// Record (or overwrite) an MCP pin.
    pub fn pin_mcp(&mut self, name: impl Into<String>, pin: McpPin) {
        self.mcps.insert(name.into(), pin);
    }

    /// Classify an `ext/<name>` submodule against its current `identity` (git SHA or hash).
    ///
    /// Identity comparison is exact: a submodule whose pinned SHA differs from the current SHA
    /// (e.g. after `resync.sh` advances the submodule) is [`DriftStatus::Drifted`].
    pub fn ext_drift(&self, name: &str, identity: &str) -> DriftStatus {
        match self.ext.get(name) {
            None => DriftStatus::Unpinned,
            Some(pin) if pin.sha == identity => DriftStatus::Clean,
            Some(_) => DriftStatus::Drifted,
        }
    }

    /// Record (or overwrite) an `ext/<name>` submodule pin — trust-on-first-use.
    pub fn pin_ext(&mut self, name: impl Into<String>, pin: ExtPin) {
        self.ext.insert(name.into(), pin);
    }
}

/// Load the lockfile from `plugin_data`, returning an empty lockfile if missing or corrupt.
///
/// Never panics: a missing or unparseable file yields [`Lockfile::default`] so a fresh
/// install behaves as "nothing pinned yet".
pub fn load(plugin_data: &Path) -> Lockfile {
    let path = Lockfile::path(plugin_data);
    match std::fs::read_to_string(&path) {
        Ok(raw) => serde_json::from_str(&raw).unwrap_or_default(),
        Err(_) => Lockfile::default(),
    }
}

/// Atomically persist `lockfile` under `plugin_data` (temp file + rename).
pub fn save(plugin_data: &Path, lockfile: &Lockfile) -> std::io::Result<()> {
    std::fs::create_dir_all(plugin_data)?;
    let path = Lockfile::path(plugin_data);
    let tmp = path.with_extension("json.tmp");
    let body = serde_json::to_string_pretty(lockfile)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, &path)
}

/// Compute a stable SHA-256 (hex) over the sorted file tree rooted at `path`.
///
/// Files are walked with [`WalkDir`], sorted by relative path for determinism, and each
/// contributes `len(rel_path) | rel_path | len(content) | content` to a single digest.
/// Directories themselves contribute nothing (only their files), so an empty tree hashes to
/// the digest of zero updates. Returns an empty string if `path` does not exist.
///
/// A single file `path` hashes just that file. Unreadable files are skipped (best effort);
/// the hash still reflects every readable file deterministically.
pub fn hash_tree(path: &Path) -> String {
    if !path.exists() {
        return String::new();
    }

    // Collect (relative-path-bytes, content) pairs, then sort by path for stable ordering.
    let mut entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

    for entry in WalkDir::new(path).follow_links(false).into_iter().flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        let rel = match entry.path().strip_prefix(path) {
            Ok(r) => r,
            // When `path` is itself a file, strip_prefix(path) fails; use the file name.
            Err(_) => Path::new(entry.file_name()),
        };
        let rel_bytes = rel.to_string_lossy().replace('\\', "/").into_bytes();
        if let Ok(content) = std::fs::read(entry.path()) {
            entries.push((rel_bytes, content));
        }
    }

    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut hasher = Sha256::new();
    for (rel, content) in &entries {
        hasher.update((rel.len() as u64).to_le_bytes());
        hasher.update(rel);
        hasher.update((content.len() as u64).to_le_bytes());
        hasher.update(content);
    }
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Detect drift for a skill directory at `dir` (name `name`) against `lockfile`.
///
/// Convenience wrapper: hashes `dir` and classifies via [`Lockfile::skill_drift`].
pub fn detect_drift(lockfile: &Lockfile, name: &str, dir: &Path) -> DriftStatus {
    let current = hash_tree(dir);
    lockfile.skill_drift(name, &current)
}

/// The resolved identity of an `ext/<name>` submodule working directory.
///
/// `kind` is `"git"` when [`resolve_git_sha`] succeeded (`sha` is a 40-char commit hash), or
/// `"hash"` when the directory is not a git checkout and we fell back to [`hash_tree`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtIdentity {
    /// Pinned identity string (git commit SHA or content tree hash).
    pub sha: String,
    /// `"git"` or `"hash"`.
    pub kind: &'static str,
}

/// Resolve the identity of a submodule working directory: its checked-out commit SHA, else a
/// content tree hash.
///
/// A git submodule's working dir contains a `.git` **file** (not a dir) of the form
/// `gitdir: <relative-or-absolute path to the real gitdir>`. We follow that to read `HEAD` and
/// resolve it to a commit SHA. A regular `.git` directory is also handled. When `dir` is not a
/// git checkout (no resolvable SHA), we fall back to [`hash_tree`] so drift detection still
/// works on plain directories.
pub fn resolve_ext_identity(dir: &Path) -> ExtIdentity {
    if let Some(sha) = resolve_git_sha(dir) {
        return ExtIdentity { sha, kind: "git" };
    }
    ExtIdentity {
        sha: hash_tree(dir),
        kind: "hash",
    }
}

/// Resolve a git checkout's `HEAD` commit SHA from its working directory `dir`.
///
/// Handles both a `.git` directory (top-level repo) and a `.git` file pointing at a real gitdir
/// (the submodule case: `gitdir: ../../../.git/modules/<path>`). Returns `None` when `dir` is
/// not a git checkout or `HEAD` cannot be resolved to a 40-hex commit SHA.
pub fn resolve_git_sha(dir: &Path) -> Option<String> {
    let dot_git = dir.join(".git");
    let git_dir = resolve_git_dir(&dot_git, dir)?;
    let head = std::fs::read_to_string(git_dir.join("HEAD")).ok()?;
    let head = head.trim();

    // Detached HEAD (the common submodule case): HEAD holds the commit SHA directly.
    if let Some(sha) = valid_sha(head) {
        return Some(sha);
    }

    // Symbolic ref: `ref: refs/heads/<branch>` → resolve to a loose or packed ref.
    let target = head.strip_prefix("ref:")?.trim();
    if let Ok(loose) = std::fs::read_to_string(git_dir.join(target)) {
        if let Some(sha) = valid_sha(loose.trim()) {
            return Some(sha);
        }
    }
    resolve_packed_ref(&git_dir, target)
}

/// Resolve the real gitdir from a `.git` path that may be a dir or a `gitdir:` pointer file.
fn resolve_git_dir(dot_git: &Path, work_dir: &Path) -> Option<std::path::PathBuf> {
    if dot_git.is_dir() {
        return Some(dot_git.to_path_buf());
    }
    if dot_git.is_file() {
        let body = std::fs::read_to_string(dot_git).ok()?;
        let rel = body.trim().strip_prefix("gitdir:")?.trim();
        let candidate = Path::new(rel);
        let resolved = if candidate.is_absolute() {
            candidate.to_path_buf()
        } else {
            work_dir.join(candidate)
        };
        // Normalize away `..` segments so the path is canonical-ish without touching the fs.
        return Some(normalize_path(&resolved));
    }
    None
}

/// Resolve a ref via the gitdir's `packed-refs`, if present.
fn resolve_packed_ref(git_dir: &Path, target: &str) -> Option<String> {
    let packed = std::fs::read_to_string(git_dir.join("packed-refs")).ok()?;
    for line in packed.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('^') {
            continue;
        }
        if let Some((sha, name)) = line.split_once(' ') {
            if name == target {
                return valid_sha(sha);
            }
        }
    }
    None
}

/// Return the lowercased SHA if `s` is a 40-char lowercase-hex git object id, else `None`.
fn valid_sha(s: &str) -> Option<String> {
    let s = s.trim();
    if s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(s.to_ascii_lowercase())
    } else {
        None
    }
}

/// Lexically normalize a path, collapsing `.` and `..` segments (no filesystem access).
fn normalize_path(path: &Path) -> std::path::PathBuf {
    use std::path::Component;
    let mut out = std::path::PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tempdir(tag: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!(
            "ssai-lockfile-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&base).unwrap();
        base
    }

    #[test]
    fn hash_tree_is_deterministic() {
        let dir = tempdir("det");
        fs::write(dir.join("a.txt"), b"hello").unwrap();
        fs::create_dir_all(dir.join("sub")).unwrap();
        fs::write(dir.join("sub/b.txt"), b"world").unwrap();

        let h1 = hash_tree(&dir);
        let h2 = hash_tree(&dir);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn hash_tree_changes_on_content_change() {
        let dir = tempdir("change");
        fs::write(dir.join("a.txt"), b"hello").unwrap();
        let before = hash_tree(&dir);
        fs::write(dir.join("a.txt"), b"hello!").unwrap();
        let after = hash_tree(&dir);
        assert_ne!(before, after);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn hash_tree_missing_is_empty() {
        assert_eq!(hash_tree(Path::new("/nonexistent/ssai/xyz")), "");
    }

    #[test]
    fn drift_detection_lifecycle() {
        let dir = tempdir("drift");
        let skill = dir.join("skills/my-skill");
        fs::create_dir_all(&skill).unwrap();
        fs::write(skill.join("SKILL.md"), b"# clean").unwrap();

        let mut lock = Lockfile::default();
        // Unpinned before first use.
        assert_eq!(
            detect_drift(&lock, "my-skill", &skill),
            DriftStatus::Unpinned
        );

        // Pin (TOFU).
        let hash = hash_tree(&skill);
        lock.pin_skill(
            "my-skill",
            SkillPin {
                sha256: hash.clone(),
                source: "local".into(),
                verified_at: 1,
                scan: "low".into(),
            },
        );
        assert_eq!(detect_drift(&lock, "my-skill", &skill), DriftStatus::Clean);

        // Tamper one byte → drift.
        fs::write(skill.join("SKILL.md"), b"# tampered").unwrap();
        assert_eq!(
            detect_drift(&lock, "my-skill", &skill),
            DriftStatus::Drifted
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn save_load_roundtrip() {
        let data = tempdir("roundtrip");
        let mut lock = Lockfile::default();
        lock.pin_skill(
            "s1",
            SkillPin {
                sha256: "abc".into(),
                source: "gh".into(),
                verified_at: 42,
                scan: "high".into(),
            },
        );
        lock.pin_mcp(
            "helius",
            McpPin {
                pkg: "helius-mcp".into(),
                version: "1.2.3".into(),
                shasum: "deadbeef".into(),
                scan: "low".into(),
            },
        );

        save(&data, &lock).unwrap();
        let loaded = load(&data);
        assert_eq!(loaded.skills.get("s1").unwrap().sha256, "abc");
        assert_eq!(loaded.skills.get("s1").unwrap().verified_at, 42);
        assert_eq!(loaded.mcps.get("helius").unwrap().version, "1.2.3");
        fs::remove_dir_all(&data).ok();
    }

    #[test]
    fn load_missing_is_empty() {
        let data = tempdir("missing");
        let loaded = load(&data);
        assert!(loaded.skills.is_empty());
        assert!(loaded.mcps.is_empty());
        assert!(loaded.ext.is_empty());
        fs::remove_dir_all(&data).ok();
    }

    /// Simulate a submodule working dir: a `.git` FILE pointing at a real gitdir holding a
    /// detached `HEAD` (the typical checked-out-submodule shape).
    fn fake_submodule(work: &Path, gitdir: &Path, sha: &str) {
        fs::create_dir_all(work).unwrap();
        fs::create_dir_all(gitdir).unwrap();
        fs::write(gitdir.join("HEAD"), format!("{sha}\n")).unwrap();
        // `.git` is a FILE: `gitdir: <path>` (use an absolute path so the test is location-free).
        fs::write(
            work.join(".git"),
            format!("gitdir: {}\n", gitdir.to_string_lossy()),
        )
        .unwrap();
    }

    #[test]
    fn resolve_git_sha_from_submodule_file_detached_head() {
        let base = tempdir("subgit");
        let work = base.join("ext/jupiter");
        let gitdir = base.join(".git/modules/ext/jupiter");
        let sha = "a".repeat(40);
        fake_submodule(&work, &gitdir, &sha);

        let id = resolve_ext_identity(&work);
        assert_eq!(id.kind, "git");
        assert_eq!(id.sha, sha);
        assert_eq!(resolve_git_sha(&work), Some(sha));
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn resolve_git_sha_symbolic_ref_via_loose_and_packed() {
        let base = tempdir("subref");
        let work = base.join("ext/helius");
        let gitdir = base.join("gd");
        fs::create_dir_all(&work).unwrap();
        fs::create_dir_all(&gitdir).unwrap();
        fs::write(work.join(".git"), format!("gitdir: {}\n", gitdir.display())).unwrap();
        fs::write(gitdir.join("HEAD"), "ref: refs/heads/main\n").unwrap();

        let sha = "b".repeat(40);
        // Loose ref first.
        fs::create_dir_all(gitdir.join("refs/heads")).unwrap();
        fs::write(gitdir.join("refs/heads/main"), format!("{sha}\n")).unwrap();
        assert_eq!(resolve_git_sha(&work), Some(sha.clone()));

        // Now drop the loose ref and resolve via packed-refs.
        fs::remove_file(gitdir.join("refs/heads/main")).unwrap();
        let packed = format!("# pack-refs with: peeled\n{sha} refs/heads/main\n");
        fs::write(gitdir.join("packed-refs"), packed).unwrap();
        assert_eq!(resolve_git_sha(&work), Some(sha));
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn resolve_falls_back_to_hash_tree_when_not_git() {
        let base = tempdir("nogit");
        let work = base.join("ext/plain");
        fs::create_dir_all(&work).unwrap();
        fs::write(work.join("SKILL.md"), b"# plain submodule").unwrap();

        let id = resolve_ext_identity(&work);
        assert_eq!(id.kind, "hash");
        assert_eq!(id.sha, hash_tree(&work));
        assert!(resolve_git_sha(&work).is_none());
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn ext_pin_drift_lifecycle_git() {
        let base = tempdir("extdrift");
        let work = base.join("ext/trailofbits");
        let gitdir = base.join(".git/modules/ext/trailofbits");
        let sha1 = "c".repeat(40);
        fake_submodule(&work, &gitdir, &sha1);

        let mut lock = Lockfile::default();
        let id1 = resolve_ext_identity(&work);
        assert_eq!(
            lock.ext_drift("trailofbits", &id1.sha),
            DriftStatus::Unpinned
        );

        lock.pin_ext(
            "trailofbits",
            ExtPin {
                sha: id1.sha.clone(),
                kind: id1.kind.into(),
                verified_at: 1,
                scan: String::new(),
            },
        );
        assert_eq!(lock.ext_drift("trailofbits", &id1.sha), DriftStatus::Clean);

        // resync.sh bumps the submodule → HEAD advances → drift.
        let sha2 = "d".repeat(40);
        fs::write(gitdir.join("HEAD"), format!("{sha2}\n")).unwrap();
        let id2 = resolve_ext_identity(&work);
        assert_eq!(id2.sha, sha2);
        assert_eq!(
            lock.ext_drift("trailofbits", &id2.sha),
            DriftStatus::Drifted
        );
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn ext_pin_drift_lifecycle_hash_fallback() {
        let base = tempdir("exthash");
        let work = base.join("ext/sendai");
        fs::create_dir_all(&work).unwrap();
        fs::write(work.join("SKILL.md"), b"# original").unwrap();

        let mut lock = Lockfile::default();
        let id = resolve_ext_identity(&work);
        assert_eq!(id.kind, "hash");
        lock.pin_ext(
            "sendai",
            ExtPin {
                sha: id.sha.clone(),
                kind: id.kind.into(),
                verified_at: 1,
                scan: String::new(),
            },
        );
        assert_eq!(lock.ext_drift("sendai", &id.sha), DriftStatus::Clean);

        // Content change → hash changes → drift.
        fs::write(work.join("SKILL.md"), b"# tampered").unwrap();
        let id2 = resolve_ext_identity(&work);
        assert_eq!(lock.ext_drift("sendai", &id2.sha), DriftStatus::Drifted);
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn ext_pins_survive_save_load_roundtrip() {
        let data = tempdir("extroundtrip");
        let mut lock = Lockfile::default();
        lock.pin_ext(
            "jupiter",
            ExtPin {
                sha: "e".repeat(40),
                kind: "git".into(),
                verified_at: 9,
                scan: "low".into(),
            },
        );
        save(&data, &lock).unwrap();
        let loaded = load(&data);
        let pin = loaded.ext.get("jupiter").unwrap();
        assert_eq!(pin.sha, "e".repeat(40));
        assert_eq!(pin.kind, "git");
        assert_eq!(pin.verified_at, 9);
        fs::remove_dir_all(&data).ok();
    }
}
