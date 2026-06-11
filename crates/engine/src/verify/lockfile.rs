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

/// The TOFU lockfile contents.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Lockfile {
    /// Pinned skill directories, keyed by skill name.
    #[serde(default)]
    pub skills: BTreeMap<String, SkillPin>,
    /// Pinned MCP servers, keyed by server name.
    #[serde(default)]
    pub mcps: BTreeMap<String, McpPin>,
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
        fs::remove_dir_all(&data).ok();
    }
}
