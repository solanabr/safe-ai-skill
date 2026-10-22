//! Raw project env reads by tier, `env_read` and sandbox (D8 v2 spec §2/§1.4; owned by F2).
//!
//! **F0 stub:** reproduces 1.1.0 behaviour: `env_read: ask` asks, anything else denies; tier
//! and sandbox are not consulted yet. F2 implements the spec §2 rows (`tier` opt-in follows the
//! tier, `ask` asks below High, both only while the sandbox is [`SandboxState::On`]).
//!
//! Call lines (shared files; F2 edits only this file): `read::env_verdict` (Read, file and
//! directory Grep, MCP path args, Bash readers through `secrets`) and the varlock value
//! printers in `secrets::decide_varlock`.

use crate::gate::Verdict;
use crate::io::Decision;
use crate::policy::tier::{EnvRead, Tier};
use crate::policy::Policy;
use crate::sandbox::SandboxState;

/// The verdict for a raw read of project env values. `reason` is the actionable message (the
/// `safe-ai-skill env` commands); `None` is no opinion (an opted-in read).
pub fn verdict(
    tier: Tier,
    env_read: EnvRead,
    sandbox: SandboxState,
    reason: String,
) -> Option<Verdict> {
    let _ = (tier, sandbox);
    Some(match env_read {
        EnvRead::Ask => Verdict::Ask(format!(
            "Raw read of an env file (secrets.env_read: ask): approving shows its values to the model. {reason}"
        )),
        EnvRead::Deny | EnvRead::Tier => Verdict::Deny(reason),
    })
}

/// [`verdict`] for the policy's runtime tier context, as a [`Decision`] (the call-line form).
pub fn decision(policy: &Policy, reason: String) -> Decision {
    let rt = &policy.runtime;
    verdict(rt.tier, rt.env_read, rt.sandbox, reason).map_or(Decision::Defer, Decision::from)
}
