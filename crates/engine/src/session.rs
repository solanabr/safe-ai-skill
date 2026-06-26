//! Session keypairs (Phase 3): ephemeral, spend-capped signing keys.
//!
//! A session key is a freshly generated Ed25519 keypair written in the Solana CLI keypair
//! format (a JSON array of 64 bytes: 32-byte secret seed followed by the 32-byte public key)
//! with `0600` permissions under `${plugin_data}/session/<id>.json`. Its metadata records a
//! hard SOL cap.
//!
//! ## "autopilot" by construction
//!
//! The session key is funded once with at most `cap_sol`. Because the key can never hold
//! more than its cap, a compromised or runaway agent can lose at most that amount — so
//! per-transaction approval prompts become unnecessary *by construction* rather than by a
//! trust setting. Funding the key is itself a `solana transfer`, which passes through the
//! Phase-1 transfer gate; the cap is enforced at funding time, not on every downstream tx.

use std::path::Path;

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Persisted session metadata (written alongside the keypair, and embedded as `meta`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMeta {
    /// Session id (also the keypair filename stem).
    pub id: String,
    /// Base58 public key.
    pub pubkey: String,
    /// Hard SOL cap this session may ever hold.
    pub cap_sol: f64,
    /// Creation time (epoch seconds).
    pub created_at: u64,
    /// Whether this session is an autopilot key (cap makes per-tx prompts unnecessary).
    pub autopilot: bool,
}

/// Initialize an ephemeral session keypair capped at `cap_sol`.
///
/// Generates an Ed25519 keypair, writes it `0600` in Solana CLI keypair format to
/// `${plugin_data}/session/<id>.json`, records [`SessionMeta`] next to it, and returns a
/// human-readable summary including the funding instruction. The funding transfer
/// (`solana transfer <pubkey> <cap_sol>`) is run by the caller and itself passes through the
/// transfer gate.
///
/// A non-finite or negative `cap_sol` is rejected.
pub fn init(cap_sol: f64, plugin_data: &Path) -> Result<String> {
    if !cap_sol.is_finite() || cap_sol < 0.0 {
        return Err(Error::Other(
            "session cap must be a finite, non-negative SOL value".to_string(),
        ));
    }

    let signing = generate_keypair()?;
    let pubkey = bs58::encode(signing.verifying_key().to_bytes()).into_string();
    let created_at = now_secs();
    let id = format!("sess-{created_at:x}");

    let session_dir = plugin_data.join("session");
    std::fs::create_dir_all(&session_dir)?;

    // Solana CLI keypair: a 64-int JSON array of [secret_32 || public_32].
    let keypair_bytes = signing.to_keypair_bytes();
    let key_path = session_dir.join(format!("{id}.json"));
    write_secure(&key_path, &keypair_json(&keypair_bytes))?;

    let meta = SessionMeta {
        id: id.clone(),
        pubkey: pubkey.clone(),
        cap_sol,
        created_at,
        autopilot: true,
    };
    let meta_path = session_dir.join(format!("{id}.meta.json"));
    let meta_body =
        serde_json::to_string(&meta).map_err(|e| Error::Parse(format!("session meta: {e}")))?;
    write_secure(&meta_path, &meta_body)?;

    // Record the active session pointer for `status`.
    let active_path = plugin_data.join("session").join("active.json");
    let _ = std::fs::write(&active_path, serde_json::json!({ "id": id }).to_string());

    Ok(format!(
        "session {id} ready (pubkey {pubkey}, cap {cap_sol} SOL). \
         Fund it: solana transfer {pubkey} {cap_sol}"
    ))
}

/// Human-readable status of the active session (id, pubkey, cap).
///
/// Reads the active-session pointer and its metadata. Returns a fixed string when no session
/// is active. Balance lookups are intentionally not performed here (no network in this build).
pub fn status(plugin_data: &Path) -> Result<String> {
    let active_path = plugin_data.join("session").join("active.json");
    let active = match std::fs::read_to_string(&active_path) {
        Ok(text) => text,
        Err(_) => return Ok("no active session".to_string()),
    };
    let id = serde_json::from_str::<serde_json::Value>(&active)
        .ok()
        .and_then(|v| v.get("id").and_then(|i| i.as_str()).map(str::to_string));
    let id = match id {
        Some(id) => id,
        None => return Ok("no active session".to_string()),
    };
    match load_meta(plugin_data, &id) {
        Some(meta) => Ok(format!(
            "session {} active: pubkey {} cap {} SOL (autopilot={})",
            meta.id, meta.pubkey, meta.cap_sol, meta.autopilot
        )),
        None => Ok("no active session".to_string()),
    }
}

/// Load a session's metadata by id.
pub fn load_meta(plugin_data: &Path, id: &str) -> Option<SessionMeta> {
    let meta_path = plugin_data.join("session").join(format!("{id}.meta.json"));
    let text = std::fs::read_to_string(meta_path).ok()?;
    serde_json::from_str(&text).ok()
}

/// Generate a fresh Ed25519 signing key, seeding from the OS CSPRNG.
fn generate_keypair() -> Result<SigningKey> {
    let seed = os_random_32()?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Read 32 cryptographically secure random bytes from the OS.
///
/// Sources from `/dev/urandom` (no extra crate dependency). Any read failure is an error —
/// the engine never falls back to a weak source for key material.
fn os_random_32() -> Result<[u8; 32]> {
    use std::io::Read;
    let mut buf = [0u8; 32];
    let mut f = std::fs::File::open("/dev/urandom")
        .map_err(|e| Error::Other(format!("open /dev/urandom: {e}")))?;
    f.read_exact(&mut buf)
        .map_err(|e| Error::Other(format!("read /dev/urandom: {e}")))?;
    Ok(buf)
}

/// Render a 64-byte keypair as a Solana CLI JSON array of integers.
fn keypair_json(bytes: &[u8; 64]) -> String {
    let nums: Vec<String> = bytes.iter().map(|b| b.to_string()).collect();
    format!("[{}]", nums.join(","))
}

/// Write `contents` to `path` with `0600` permissions (owner read/write only).
fn write_secure(path: &Path, contents: &str) -> Result<()> {
    std::fs::write(path, contents)?;
    set_owner_only(path)?;
    Ok(())
}

/// Restrict `path` to owner read/write (`0600`). Unix-only; a no-op elsewhere.
#[cfg(unix)]
fn set_owner_only(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

/// Non-Unix fallback: permissions are not adjustable the same way.
#[cfg(not(unix))]
fn set_owner_only(_path: &Path) -> Result<()> {
    Ok(())
}

/// Current time in epoch seconds (0 on clock error; never panics).
fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "safe_ai_skill_session_{}_{}_{}",
            tag,
            std::process::id(),
            now_secs()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn keypair_json_is_64_ints_in_range() {
        let bytes = [0xABu8; 64];
        let json = keypair_json(&bytes);
        let parsed: Vec<i64> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 64);
        for n in parsed {
            assert!((0..=255).contains(&n));
        }
    }

    #[test]
    fn init_writes_keypair_and_metadata() {
        let dir = tmp_dir("init");
        let summary = init(1.5, &dir).unwrap();
        assert!(summary.contains("solana transfer"));

        // The keypair file parses as 64 ints, each 0..=255.
        let session_dir = dir.join("session");
        let entries: Vec<_> = std::fs::read_dir(&session_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .collect();
        let key_file = entries
            .iter()
            .find(|p| {
                let name = p.file_name().unwrap().to_string_lossy().to_string();
                name.starts_with("sess-")
                    && name.ends_with(".json")
                    && !name.ends_with(".meta.json")
                    && name != "active.json"
            })
            .expect("keypair file present");
        let key_text = std::fs::read_to_string(key_file).unwrap();
        let key_bytes: Vec<i64> = serde_json::from_str(&key_text).unwrap();
        assert_eq!(key_bytes.len(), 64);
        for n in &key_bytes {
            assert!((0..=255).contains(n));
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn keypair_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp_dir("perms");
        init(0.5, &dir).unwrap();
        let session_dir = dir.join("session");
        for entry in std::fs::read_dir(&session_dir).unwrap().flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".json") && !name.contains("meta") && name != "active.json" {
                let mode = entry.metadata().unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o600, "keypair file must be 0600");
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn metadata_roundtrip_via_status() {
        let dir = tmp_dir("status");
        init(2.0, &dir).unwrap();
        let status = status(&dir).unwrap();
        assert!(status.contains("active"));
        assert!(status.contains("cap 2 SOL"));
        assert!(status.contains("autopilot=true"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn status_no_session() {
        let dir = tmp_dir("nosession");
        assert_eq!(status(&dir).unwrap(), "no active session");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pubkey_matches_secret_half() {
        let dir = tmp_dir("pubkey");
        init(1.0, &dir).unwrap();
        // Find the meta and key, verify the public 32 bytes match the keypair tail.
        let session_dir = dir.join("session");
        let mut meta: Option<SessionMeta> = None;
        let mut key_bytes: Option<Vec<u8>> = None;
        for entry in std::fs::read_dir(&session_dir).unwrap().flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".meta.json") {
                let text = std::fs::read_to_string(entry.path()).unwrap();
                meta = serde_json::from_str(&text).ok();
            } else if name.starts_with("sess-") && name.ends_with(".json") && name != "active.json"
            {
                let text = std::fs::read_to_string(entry.path()).unwrap();
                let nums: Vec<u8> = serde_json::from_str(&text).unwrap();
                key_bytes = Some(nums);
            }
        }
        let meta = meta.unwrap();
        let key_bytes = key_bytes.unwrap();
        let pub_from_file = bs58::encode(&key_bytes[32..64]).into_string();
        assert_eq!(meta.pubkey, pub_from_file);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn negative_cap_rejected() {
        let dir = tmp_dir("negcap");
        assert!(init(-1.0, &dir).is_err());
        assert!(init(f64::NAN, &dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
