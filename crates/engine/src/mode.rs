//! Active profile selection (`${CLAUDE_PLUGIN_DATA}/mode.json`).
//!
//! The runtime profile override. Precedence at load time (see [`crate::policy::Policy::load`]):
//! the [`crate::policy::PROFILE_ENV`] env var wins; otherwise the value persisted here is
//! used; otherwise the policy file's `active_profile`.
//!
//! This module owns ONLY the grant/profile *name* persistence. The profile's *effect* (cap
//! overrides, `relax_transfer`/`relax_swap` flags) lives in [`crate::policy::Policy::effective`]
//! — `mode::get` supplies the active name, `policy.effective()` applies the overlay. The two
//! never overlap.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::policy::PROFILE_ENV;

/// The known profile names. Any other value is rejected by [`set`].
pub const KNOWN_PROFILES: [&str; 4] = ["strict", "autopilot", "paranoid", "off"];

/// Persisted active-profile record.
#[derive(Debug, Serialize, Deserialize)]
struct ModeRecord {
    /// Active profile name.
    profile: String,
    /// When it was set (epoch seconds; informational).
    set_at: u64,
}

/// Whether `profile` is one of the [`KNOWN_PROFILES`].
pub fn is_known_profile(profile: &str) -> bool {
    KNOWN_PROFILES.contains(&profile)
}

/// Read the active profile.
///
/// Precedence: the [`PROFILE_ENV`] env var (when set to a known profile) overrides the
/// persisted file; otherwise the value in `mode.json` is returned. `None` when neither a
/// valid env override nor a persisted record exists, so the caller may fall back to the
/// policy default.
pub fn get(plugin_data: &Path) -> Option<String> {
    if let Ok(env_profile) = std::env::var(PROFILE_ENV) {
        let trimmed = env_profile.trim();
        if is_known_profile(trimmed) {
            return Some(trimmed.to_string());
        }
    }
    let path = plugin_data.join("mode.json");
    let text = std::fs::read_to_string(path).ok()?;
    let record: ModeRecord = serde_json::from_str(&text).ok()?;
    if is_known_profile(&record.profile) {
        Some(record.profile)
    } else {
        None
    }
}

/// Persist `profile` as the active profile (write-temp + rename).
///
/// Returns an error if `profile` is not one of the [`KNOWN_PROFILES`].
pub fn set(plugin_data: &Path, profile: &str) -> std::io::Result<()> {
    if !is_known_profile(profile) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "unknown profile '{profile}'; expected one of {}",
                KNOWN_PROFILES.join("|")
            ),
        ));
    }
    std::fs::create_dir_all(plugin_data)?;
    let record = ModeRecord {
        profile: profile.to_string(),
        set_at: now_secs(),
    };
    let path = plugin_data.join("mode.json");
    let tmp = plugin_data.join("mode.json.tmp");
    let body = serde_json::to_string(&record).map_err(std::io::Error::other)?;
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, &path)
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
            "safe_ai_skill_mode_{}_{}_{}",
            tag,
            std::process::id(),
            now_secs()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn set_then_get_roundtrip() {
        let dir = tmp_dir("roundtrip");
        // Ensure no env override interferes.
        std::env::remove_var(PROFILE_ENV);
        set(&dir, "autopilot").unwrap();
        assert_eq!(get(&dir), Some("autopilot".to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn get_none_when_unset() {
        let dir = tmp_dir("unset");
        std::env::remove_var(PROFILE_ENV);
        assert_eq!(get(&dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalid_profile_rejected() {
        let dir = tmp_dir("invalid");
        assert!(set(&dir, "turbo").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn env_overrides_file() {
        let dir = tmp_dir("env");
        set(&dir, "strict").unwrap();
        std::env::set_var(PROFILE_ENV, "paranoid");
        assert_eq!(get(&dir), Some("paranoid".to_string()));
        // Garbage env value is ignored; file value wins.
        std::env::set_var(PROFILE_ENV, "garbage");
        assert_eq!(get(&dir), Some("strict".to_string()));
        std::env::remove_var(PROFILE_ENV);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
