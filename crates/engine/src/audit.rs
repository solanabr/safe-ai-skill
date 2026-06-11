//! Append-only audit log (`${CLAUDE_PLUGIN_DATA}/audit.jsonl`).
//!
//! Every gated decision appends one JSON line. `main.rs` builds the entry (it owns the
//! raw stdin used for `input_sha256`).

use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sha2::{Digest, Sha256};

/// One audit record.
#[derive(Debug, Serialize)]
pub struct AuditEntry {
    /// Epoch seconds.
    pub ts: u64,
    /// Session id (empty when unknown).
    pub session_id: String,
    /// Tool name that triggered the gate.
    pub tool: String,
    /// Action classification (scope label).
    pub classification: String,
    /// Final decision label (`allow`/`ask`/`deny`/`defer`).
    pub decision: String,
    /// Decision reason (empty for allow/defer).
    pub reason: String,
    /// SHA-256 (hex) of the raw stdin payload.
    pub input_sha256: String,
}

impl AuditEntry {
    /// Construct an entry with `ts` set to the current epoch seconds.
    pub fn new(
        session_id: impl Into<String>,
        tool: impl Into<String>,
        classification: impl Into<String>,
        decision: impl Into<String>,
        reason: impl Into<String>,
        input_sha256: impl Into<String>,
    ) -> Self {
        AuditEntry {
            ts: now_secs(),
            session_id: session_id.into(),
            tool: tool.into(),
            classification: classification.into(),
            decision: decision.into(),
            reason: reason.into(),
            input_sha256: input_sha256.into(),
        }
    }
}

/// Hex SHA-256 of `bytes`. Used by `main.rs` to fingerprint the raw stdin payload.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Append `entry` as one JSON line to `${plugin_data}/audit.jsonl`, creating the directory
/// if needed.
pub fn append(entry: &AuditEntry, plugin_data: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(plugin_data)?;
    let path = plugin_data.join("audit.jsonl");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let line = serde_json::to_string(entry)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")
}

/// Current time in epoch seconds (0 on clock error; never panics).
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_is_stable_hex() {
        // Known vector for empty input.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn append_writes_jsonl_line() {
        let dir = std::env::temp_dir().join(format!("ssai_audit_{}", std::process::id()));
        let entry = AuditEntry::new("sess", "Bash", "transfer", "ask", "over cap", "deadbeef");
        append(&entry, &dir).unwrap();
        let body = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
        assert!(body.contains("\"decision\":\"ask\""));
        assert!(body.ends_with('\n'));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
