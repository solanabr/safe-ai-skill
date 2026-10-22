//! Active profile selection (`${DATA}/mode.json`, authenticated, spec D4.2).
//!
//! The runtime profile override. Precedence at load time (see
//! [`crate::policy::Policy::load_with_mode`]): the value persisted here replaces the policy
//! file's `active_profile`; the [`crate::policy::PROFILE_ENV`] env var may then only select a
//! stricter profile.
//!
//! `mode.json` is a [`crate::statefile`] envelope. Moving to a stricter profile is written at
//! once ([`set`]); a looser one (`autopilot`) goes through a confirmed prompt nonce first
//! (spec D4.1, [`crate::relax::confirm_prompt`]). [`persisted`] is what gates read: `None`
//! unless the file authenticates, the data dir is trusted, and the name is known.
//!
//! This module owns ONLY the profile *name* persistence. The profile's *effect* lives in
//! [`crate::policy::Policy::effective`] and [`crate::relax`].

use serde::{Deserialize, Serialize};

use crate::datadir::DataDir;
use crate::error::{EngineError, Error};
use crate::statefile::{self, Loaded};

/// State file holding the active profile.
pub const MODE_FILE: &str = "mode.json";

/// The known profiles, loosest first. Any other value is rejected by [`set`].
pub const KNOWN_PROFILES: [&str; 3] = ["autopilot", "strict", "paranoid"];

/// The profile in effect when nothing selects another.
pub const DEFAULT_PROFILE: &str = "strict";

/// Persisted active-profile record.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModeRecord {
    /// Active profile name.
    pub profile: String,
    /// When it was set (epoch seconds; informational).
    pub set_at: u64,
}

/// Whether `profile` is one of the [`KNOWN_PROFILES`].
pub fn is_known_profile(profile: &str) -> bool {
    KNOWN_PROFILES.contains(&profile)
}

/// Rank of a known profile, loosest = 0; `None` for an unknown name.
pub fn strictness(profile: &str) -> Option<usize> {
    KNOWN_PROFILES.iter().position(|p| *p == profile)
}

/// Whether moving from `current` to `target` loosens the policy, and so needs a confirmed
/// nonce. An unknown `current` counts as [`DEFAULT_PROFILE`].
pub fn is_looser(target: &str, current: &str) -> bool {
    let current = strictness(current).or_else(|| strictness(DEFAULT_PROFILE));
    match (strictness(target), current) {
        (Some(t), Some(c)) => t < c,
        _ => true,
    }
}

/// Load and authenticate `mode.json`.
pub fn load(dir: &DataDir) -> Loaded<ModeRecord> {
    statefile::load(dir, MODE_FILE)
}

/// The profile persisted in `mode.json`, for gating: `None` unless the file authenticates,
/// the data dir is trusted and the name is a known profile.
pub fn persisted(dir: &DataDir) -> Option<String> {
    match load(dir) {
        Loaded::Valid(r) if dir.trusted && is_known_profile(&r.profile) => Some(r.profile),
        _ => None,
    }
}

/// Persist `profile` as the active profile. The caller decides whether it needed a
/// confirmation ([`is_looser`]).
///
/// Returns an error if `profile` is not one of the [`KNOWN_PROFILES`].
pub fn set(dir: &DataDir, profile: &str, now: u64) -> Result<(), EngineError> {
    if !is_known_profile(profile) {
        return Err(Error::Other(unknown_profile(profile)));
    }
    let record = ModeRecord {
        profile: profile.to_string(),
        set_at: now,
    };
    statefile::store(dir, MODE_FILE, &record)
}

/// The error for a profile name outside [`KNOWN_PROFILES`] (the name is not echoed: it may
/// be anything).
pub fn unknown_profile(profile: &str) -> String {
    let shown: String = profile
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .take(20)
        .collect();
    format!(
        "unknown profile `{shown}`; expected one of {}",
        KNOWN_PROFILES.join("|")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grants::tests::tmp_data;

    #[test]
    fn set_then_persisted_roundtrip() {
        let dir = tmp_data("mode_roundtrip");
        set(&dir, "autopilot", 7).unwrap();
        assert_eq!(persisted(&dir), Some("autopilot".to_string()));
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn none_when_unset() {
        let dir = tmp_data("mode_unset");
        assert_eq!(persisted(&dir), None);
    }

    #[test]
    fn unknown_and_deleted_profiles_rejected() {
        let dir = tmp_data("mode_invalid");
        for bad in ["turbo", "off", "", "Strict"] {
            assert!(set(&dir, bad, 0).is_err(), "{bad}");
        }
        assert!(!dir.path.join(MODE_FILE).exists());
    }

    #[test]
    fn a_hand_written_mode_json_is_ignored() {
        let dir = tmp_data("mode_forged");
        std::fs::create_dir_all(&dir.path).unwrap();
        std::fs::write(
            dir.path.join(MODE_FILE),
            r#"{"profile":"autopilot","set_at":0}"#,
        )
        .unwrap();
        assert_eq!(load(&dir), Loaded::Tampered);
        assert_eq!(persisted(&dir), None);
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn an_untrusted_data_dir_selects_nothing() {
        let mut dir = tmp_data("mode_untrusted");
        set(&dir, "autopilot", 0).unwrap();
        dir.trusted = false;
        assert_eq!(persisted(&dir), None);
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn looser_means_toward_autopilot() {
        assert!(is_looser("autopilot", "strict"));
        assert!(is_looser("autopilot", "paranoid"));
        assert!(is_looser("strict", "paranoid"));
        assert!(!is_looser("strict", "autopilot"));
        assert!(!is_looser("paranoid", "strict"));
        assert!(!is_looser("strict", "strict"));
        // An unknown current profile counts as strict; an unknown target is never "safe".
        assert!(is_looser("autopilot", "off"));
        assert!(!is_looser("paranoid", "garbage"));
        assert!(is_looser("garbage", "strict"));
    }
}
