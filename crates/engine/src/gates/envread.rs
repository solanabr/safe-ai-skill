//! Raw project env reads by tier, `env_read` and sandbox (D8 v2 spec §2, §1.4).
//!
//! | `env_read` (user scope)       | Off  | Relaxed | Medium | High |
//! |-------------------------------|------|---------|--------|------|
//! | `deny` (default)              | deny | deny    | deny   | deny |
//! | `tier`, sandbox `On`          | n/o  | n/o     | deny   | deny |
//! | `ask`, sandbox `On`           | ask  | ask     | ask    | deny |
//! | `tier`/`ask`, sandbox not On  | deny | deny    | deny   | deny |
//!
//! Only the user's authenticated `tier.json` can set `env_read` above `deny`; the plugin
//! policy is pinned to `deny` and a repo or env can only tighten it (`policy::tier::resolve`),
//! so `env_read` here is already the effective value. The varlock value printers follow the
//! same rows. Every deny names the `safe-ai-skill env` commands, which work at every tier.
//!
//! Call lines (shared files): `read::env_verdict` (Read, file and directory Grep, MCP path
//! args, Bash readers through `secrets`) and the varlock value printers in
//! `secrets::decide_varlock`.

use crate::gate::Verdict;
use crate::io::Decision;
use crate::policy::tier::{EnvRead, Tier};
use crate::policy::Policy;
use crate::sandbox::SandboxState;

/// The reason fragment for an opt-in that does not apply because the sandbox is not on.
pub const SUSPENDED: &str = "opt-in suspended: sandbox not on";

/// The verdict for a raw read of project env values. `reason` is the actionable message (the
/// `safe-ai-skill env` commands, and the varlock hint where it applies); `None` is no opinion
/// (an opted-in read at Off or Relaxed).
pub fn verdict(
    tier: Tier,
    env_read: EnvRead,
    sandbox: SandboxState,
    reason: String,
) -> Option<Verdict> {
    let reason = with_env_commands(reason);
    if env_read == EnvRead::Deny {
        return Some(Verdict::Deny(reason));
    }
    if sandbox != SandboxState::On {
        return Some(Verdict::Deny(format!(
            "safe-ai-skill: your `env_read: {}` {SUSPENDED} (declared sandbox: {}). Raw env reads open only while the Claude Code sandbox is enabled. {reason}",
            env_read.label(),
            sandbox.label()
        )));
    }
    match (env_read, tier) {
        (EnvRead::Tier, Tier::Off | Tier::Relaxed) => None,
        (EnvRead::Ask, Tier::Off | Tier::Relaxed | Tier::Medium) => Some(Verdict::Ask(format!(
            "Raw read of an env file (secrets.env_read: ask): approving shows its values to the model. {reason}"
        ))),
        _ => Some(Verdict::Deny(format!(
            "safe-ai-skill: tier {} denies raw env reads even with your `env_read: {}`. {reason}",
            tier.label(),
            env_read.label()
        ))),
    }
}

/// [`verdict`] for the policy's runtime tier context, as a [`Decision`] (the call-line form).
pub fn decision(policy: &Policy, reason: String) -> Decision {
    let rt = &policy.runtime;
    verdict(rt.tier, rt.env_read, rt.sandbox, reason).map_or(Decision::Defer, Decision::from)
}

/// `reason` with the `env keys` / `env set` commands appended when it does not name both (the
/// varlock printer messages name only `env keys`).
fn with_env_commands(reason: String) -> String {
    let mut out = reason;
    if !out.contains("env keys") {
        out.push_str("\n  safe-ai-skill env keys <file>    (lists keys, values masked)");
    }
    if !out.contains("env set") {
        out.push_str(
            "\n  printf %s '<value>' | safe-ai-skill env set <file> KEY    (value on stdin, never in argv)",
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kind(v: Option<Verdict>) -> &'static str {
        match v {
            None | Some(Verdict::NoOpinion) => "",
            Some(Verdict::Allow(_)) => "allow",
            Some(Verdict::Ask(_)) => "ask",
            Some(Verdict::Deny(_)) => "deny",
        }
    }

    #[test]
    fn opt_ins_follow_the_tier_only_while_the_sandbox_is_on() {
        use SandboxState as S;
        let v = |t, e, s| kind(verdict(t, e, s, "env keys / env set".into()));
        assert_eq!(v(Tier::Relaxed, EnvRead::Tier, S::On), "");
        assert_eq!(v(Tier::Off, EnvRead::Tier, S::On), "");
        assert_eq!(v(Tier::Medium, EnvRead::Tier, S::On), "deny");
        assert_eq!(v(Tier::Medium, EnvRead::Ask, S::On), "ask");
        assert_eq!(v(Tier::High, EnvRead::Ask, S::On), "deny");
        assert_eq!(v(Tier::Off, EnvRead::Ask, S::Off), "deny");
        assert_eq!(v(Tier::Off, EnvRead::Tier, S::Unknown), "deny");
        assert_eq!(v(Tier::Off, EnvRead::Deny, S::On), "deny");
    }

    #[test]
    fn a_reason_without_the_env_commands_gets_them() {
        let Some(Verdict::Deny(why)) = verdict(
            Tier::High,
            EnvRead::Deny,
            SandboxState::On,
            "`varlock printenv` prints values; `safe-ai-skill env keys <file>` lists keys.".into(),
        ) else {
            panic!("expected deny");
        };
        assert_eq!(why.matches("env keys").count(), 1, "{why}");
        assert!(why.contains("env set"), "{why}");
    }
}
