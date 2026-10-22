//! The naive-exfil tripwire, best-effort (D8 v2 spec §5; owned by F4): a network-capable
//! command that takes a secret path as payload (key material at every tier, project env from
//! Relaxed) or targets a host on the tier's list ([`crate::lists::exfil_hosts`] plus
//! `secrets.exfil_hosts_extra`).
//!
//! **Deferred (#19): no opinion in 1.1.0;** the curl/wget upload checks still run inside
//! [`crate::gates::secrets`]. Call lines: `main::cmd_gate_bash_secrets` ([`decide_bash`]) and
//! `main::cmd_gate_mcp` ([`decide_mcp`], executor payloads such as `ctx_execute`).

use std::path::Path;

use serde_json::Value;

use crate::gate::Verdict;
use crate::policy::tier::Tier;
use crate::policy::Policy;

/// The verdict for a Bash `command` run in `cwd`; `None` is no opinion.
pub fn decide_bash(command: &str, cwd: &Path, policy: &Policy, tier: Tier) -> Option<Verdict> {
    let _ = (command, cwd, policy, tier);
    None
}

/// The verdict for an MCP call `tool_name` with `payload`; `None` is no opinion.
pub fn decide_mcp(
    tool_name: &str,
    payload: Option<&Value>,
    cwd: &Path,
    policy: &Policy,
    tier: Tier,
) -> Option<Verdict> {
    let _ = (tool_name, payload, cwd, policy, tier);
    None
}
