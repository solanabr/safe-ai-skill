//! Active profile selection (`${CLAUDE_PLUGIN_DATA}/mode.json`).
//!
//! The runtime profile override. Precedence at load time (see
//! [`crate::policy::Policy::load_with_mode`]): the value persisted here replaces the policy
//! file's `active_profile`; the [`crate::policy::PROFILE_ENV`] env var may then only select a
//! stricter profile.
//!
//! This module owns ONLY the grant/profile *name* persistence. The profile's *effect* (cap
//! overrides, `relax_transfer`/`relax_swap` flags) lives in [`crate::policy::Policy::effective`]
//! — `mode::persisted` supplies the active name, `policy.effective()` applies the overlay. The two
//! never overlap.

use std::path::Path;

use serde::{Deserialize, Serialize};

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

/// Read the profile persisted in `mode.json`. The [`crate::policy::PROFILE_ENV`] override is
/// applied separately, in [`crate::policy::Policy::load_with_mode`]. `None` when absent or not
/// a known profile.
pub fn persisted(plugin_data: &Path) -> Option<String> {
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
    fn set_then_persisted_roundtrip() {
        let dir = tmp_dir("roundtrip");
        set(&dir, "autopilot").unwrap();
        assert_eq!(persisted(&dir), Some("autopilot".to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn persisted_none_when_unset() {
        let dir = tmp_dir("unset");
        assert_eq!(persisted(&dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalid_profile_rejected() {
        let dir = tmp_dir("invalid");
        assert!(set(&dir, "turbo").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
