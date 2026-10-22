//! The SessionStart notices: the tier line and the loosenings notice (spec D4.4, D8 v2 §1.3).
//!
//! [`tier_line`] is printed at every SessionStart and by `status`:
//! `tier: <t> (<source>); sandbox: <state>`, with `(hooks only)` after the tier when the
//! sandbox is not on, and the shared lists' contract version.
//!
//! [`loosenings`] lists, for the user (`systemMessage`) and the model (`additionalContext`),
//! everything that currently loosens the firewall or undermines its state: a user tier below
//! the default, an `env_read` opt-in, live grants, state files that failed authentication, an
//! untrusted data dir, items migrated from 1.0, and a Claude Code sandbox that is off. Ignored
//! hints and repo policy are listed by the tier resolution and
//! [`crate::policy::Policy::ignored_notice`], and `SAFE_AI_SKILL_DISABLE` by the shim (the
//! engine never runs when it is set).
//!
//! The sandbox line is best-effort (it reads the settings files, see [`crate::sandbox`]). The
//! sandbox is off by default, so it is listed only next to another line or when a settings
//! file turns it off explicitly.

use std::path::Path;

use crate::datadir::DataDir;
use crate::grants;
use crate::policy::tier::{EnvRead, Resolution, Tier, TierContext};
use crate::sandbox::Declared;
use crate::spend::LedgerState;
use crate::statefile::Loaded;
use crate::tierstate;

/// Everything the notice is built from.
#[derive(Debug, Clone)]
pub struct Inputs<'a> {
    /// The resolved data dir.
    pub dir: &'a DataDir,
    /// The project root (`tier.json` key).
    pub root: &'a Path,
    /// The spend ledger as found before SessionStart repaired it.
    pub spend: LedgerState,
    /// Lines from [`crate::migrate::run`] and [`crate::migrate::mode_to_tier`].
    pub migrated: &'a [String],
    /// What the settings files declare about the sandbox.
    pub sandbox: Declared,
    /// Epoch seconds.
    pub now: u64,
}

/// The tier line: `safe-ai-skill tier: <t> (<source>); sandbox: <state>; lists: contract <v>
/// <sha12>` (the lists part reads `unavailable` when they failed to load).
pub fn tier_line(resolution: &Resolution, ctx: &TierContext) -> String {
    let lists = match crate::lists::lists() {
        Ok(l) => format!(
            "contract {} {}",
            l.contract,
            l.manifest_sha256.get(..12).unwrap_or("")
        ),
        Err(_) => "unavailable (list-based gates ask)".to_string(),
    };
    format!(
        "safe-ai-skill tier: {} ({}); sandbox: {}; lists: {lists}",
        resolution.tier.display(ctx.sandbox),
        resolution.source.label(),
        ctx.sandbox.label()
    )
}

/// The notice, or `None` when nothing is loosened.
pub fn loosenings(inputs: &Inputs<'_>) -> Option<String> {
    let dir = inputs.dir;
    let mut lines: Vec<String> = Vec::new();

    // Relaxation state in an untrusted dir is ignored; say so where there is some.
    let mut ignored_untrusted = false;
    match tierstate::load(dir) {
        Loaded::Valid(_) if !dir.trusted => ignored_untrusted = true,
        Loaded::Valid(_) => {
            let choice = tierstate::user_choice(dir, inputs.root);
            if let Some((tier, _)) = choice.tier.filter(|(t, _)| *t < Tier::Relaxed) {
                lines.push(format!(
                    "tier {} is active (your setting; every deny still holds)",
                    tier.label()
                ));
            }
            if let Some(env_read) = choice.env_read.filter(|e| *e != EnvRead::Deny) {
                lines.push(format!(
                    "secrets env_read {} is active (raw .env reads; only while the sandbox is on)",
                    env_read.label()
                ));
            }
        }
        Loaded::Tampered => lines.push(
            "tier.json failed authentication; ignored (the default tier applies)".to_string(),
        ),
        Loaded::Missing => {}
    }

    match grants::load(dir) {
        Loaded::Valid(g) => {
            let live: Vec<String> = g
                .grants
                .iter()
                .filter(|g| !g.is_expired(inputs.now))
                .map(|g| format!("live {}", g.describe(inputs.now)))
                .collect();
            if dir.trusted {
                lines.extend(live);
            } else {
                ignored_untrusted |= !live.is_empty();
            }
        }
        Loaded::Tampered => {
            lines.push("grants.json failed authentication; no grant applies".to_string())
        }
        Loaded::Missing => {}
    }

    if ignored_untrusted {
        lines.push(
            "the plugin data dir is not under ~/.claude/plugins/data (or is inside the project), \
             so the grants and tier stored there are ignored"
                .to_string(),
        );
    }

    match inputs.spend {
        LedgerState::Deleted => lines.push(
            "spend.json was missing; today's spend budget is treated as exhausted".to_string(),
        ),
        LedgerState::Tampered => lines.push(
            "spend.json failed authentication; today's spend budget is treated as exhausted"
                .to_string(),
        ),
        LedgerState::Valid | LedgerState::Fresh => {}
    }

    lines.extend(inputs.migrated.iter().cloned());

    let sandbox_off = match inputs.sandbox {
        Declared::On => false,
        Declared::ExplicitlyOff => true,
        Declared::Unset => !lines.is_empty(),
    };
    if sandbox_off {
        lines.push(
            "the Claude Code sandbox is off; it is the only hard boundary against an agent \
             running as you"
                .to_string(),
        );
    }

    if lines.is_empty() {
        return None;
    }
    Some(format!(
        "safe-ai-skill: active loosenings and state warnings:\n - {}",
        lines.join("\n - ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grants::tests::{tmp_data, transfer_grant};
    use crate::grants::Grants;
    use crate::policy::tier::TierSource;
    use crate::sandbox::SandboxState;

    const ROOT: &str = "/work/proj";

    fn inputs<'a>(dir: &'a DataDir, migrated: &'a [String]) -> Inputs<'a> {
        Inputs {
            dir,
            root: Path::new(ROOT),
            spend: LedgerState::Valid,
            migrated,
            sandbox: Declared::Unset,
            now: 100,
        }
    }

    fn set_tier(dir: &DataDir, tier: Tier, env_read: Option<EnvRead>) {
        let change = tierstate::Change {
            project: None,
            tier: Some(tier),
            env_read,
            clear: false,
        };
        tierstate::apply(dir, Tier::Relaxed, &change, 0).unwrap();
    }

    #[test]
    fn a_clean_session_is_silent() {
        let dir = tmp_data("notice_clean");
        assert_eq!(loosenings(&inputs(&dir, &[])), None);
        set_tier(&dir, Tier::High, None);
        assert_eq!(loosenings(&inputs(&dir, &[])), None);
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn lists_every_loosening() {
        let dir = tmp_data("notice_all");
        set_tier(&dir, Tier::Off, Some(EnvRead::Ask));
        grants::save(
            &dir,
            &Grants {
                grants: vec![transfer_grant("g1", 10_000), transfer_grant("old", 50)],
            },
        )
        .unwrap();
        let migrated = vec!["profile paranoid is now tier high (applied)".to_string()];
        let mut i = inputs(&dir, &migrated);
        i.spend = LedgerState::Deleted;
        let text = loosenings(&i).unwrap();
        for needle in [
            "tier off is active",
            "env_read ask is active",
            "live grant g1",
            "spend.json was missing",
            "tier high (applied)",
            "sandbox is off",
        ] {
            assert!(text.contains(needle), "{needle}: {text}");
        }
        assert!(!text.contains("grant old"), "{text}");
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn lists_authentication_failures_and_an_untrusted_dir() {
        let mut dir = tmp_data("notice_tamper");
        std::fs::create_dir_all(&dir.path).unwrap();
        std::fs::write(dir.path.join(grants::GRANTS_FILE), "{\"grants\":[]}").unwrap();
        std::fs::write(dir.path.join(tierstate::TIER_FILE), "{}").unwrap();
        let mut i = inputs(&dir, &[]);
        i.spend = LedgerState::Tampered;
        i.sandbox = Declared::On;
        let text = loosenings(&i).unwrap();
        for needle in [
            "grants.json failed authentication",
            "tier.json failed authentication",
            "spend.json failed authentication",
        ] {
            assert!(text.contains(needle), "{needle}: {text}");
        }
        assert!(!text.contains("sandbox"), "{text}");

        // An untrusted dir is mentioned only when it holds relaxation state to ignore.
        dir.trusted = false;
        let _ = std::fs::remove_dir_all(&dir.path);
        assert_eq!(loosenings(&inputs(&dir, &[])), None);
        set_tier(&dir, Tier::Off, None);
        let text = loosenings(&inputs(&dir, &[])).unwrap();
        assert!(text.contains("not under ~/.claude/plugins/data"), "{text}");
        assert!(!text.contains("tier off is active"), "{text}");
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn an_explicitly_disabled_sandbox_is_listed_alone() {
        let dir = tmp_data("notice_sandbox");
        let mut i = inputs(&dir, &[]);
        i.sandbox = Declared::ExplicitlyOff;
        assert!(loosenings(&i).unwrap().contains("sandbox is off"));
    }

    #[test]
    fn the_tier_line_names_tier_source_sandbox_and_lists() {
        let resolution = Resolution {
            tier: Tier::Relaxed,
            source: TierSource::Base,
            user: Tier::Relaxed,
            user_source: TierSource::Base,
            env_read: EnvRead::Deny,
            notes: Vec::new(),
        };
        let mut ctx = TierContext {
            sandbox: SandboxState::Off,
            ..TierContext::default()
        };
        let line = tier_line(&resolution, &ctx);
        assert!(
            line.starts_with("safe-ai-skill tier: relaxed (hooks only) (default); sandbox: off"),
            "{line}"
        );
        assert!(line.contains("lists: contract 1.0.0 "), "{line}");
        ctx.sandbox = SandboxState::On;
        assert!(tier_line(&resolution, &ctx).contains("tier: relaxed (default); sandbox: on"));
    }
}
