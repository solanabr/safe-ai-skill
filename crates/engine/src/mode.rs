//! Legacy profile state (`${DATA}/mode.json`), kept as an alias shim for tiers (D8 v2).
//!
//! Profiles are gone: `safe-ai-skill mode <name>` is a deprecated alias of
//! `safe-ai-skill tier <name>` (`strict`/`autopilot` → relaxed, `paranoid` → high, see
//! [`crate::policy::tier::Tier::parse`]), and gates never read `mode.json`. What remains is
//! the record format, which [`crate::migrate`] reads once to carry a 1.0 plain file or a WS-B
//! authenticated file over to `tier.json` ([`crate::tierstate`]).

use serde::{Deserialize, Serialize};

use crate::datadir::DataDir;
use crate::policy::tier::Tier;
use crate::statefile::{self, Loaded};

/// The legacy state file.
pub const MODE_FILE: &str = "mode.json";

/// A legacy active-profile record.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModeRecord {
    /// Profile name.
    pub profile: String,
    /// When it was set (epoch seconds; informational).
    pub set_at: u64,
}

/// Load and authenticate a WS-B `mode.json`.
pub fn load(dir: &DataDir) -> Loaded<ModeRecord> {
    statefile::load(dir, MODE_FILE)
}

/// The tier a legacy profile name maps to; `None` for anything else (including the removed
/// 1.0 `off` profile, which is never carried over).
pub fn profile_tier(profile: &str) -> Option<Tier> {
    match profile {
        "strict" | "autopilot" => Some(Tier::Relaxed),
        "paranoid" => Some(Tier::High),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_map_to_tiers_and_off_is_not_carried() {
        assert_eq!(profile_tier("strict"), Some(Tier::Relaxed));
        assert_eq!(profile_tier("autopilot"), Some(Tier::Relaxed));
        assert_eq!(profile_tier("paranoid"), Some(Tier::High));
        for other in ["off", "high", "", "Strict"] {
            assert_eq!(profile_tier(other), None, "{other}");
        }
    }
}
