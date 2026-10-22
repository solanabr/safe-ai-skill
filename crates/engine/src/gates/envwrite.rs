//! Writes to project env files (D8 v2 spec §2; owned by F2): Write/Edit/MultiEdit to a project
//! env file, and an agent's `safe-ai-skill env set|unset`, denied at Medium and High.
//!
//! **F0 stub:** no opinion (1.1.0 has no such rule). Call lines: `main::cmd_gate_tamper`
//! ([`decide_file`]) and `main::cmd_gate_bash_secrets` ([`decide_cli`]).

use std::path::Path;

use serde_json::Value;

use crate::gate::Verdict;
use crate::policy::tier::Tier;
use crate::policy::Policy;

/// The verdict for a Write|Edit|MultiEdit|NotebookEdit `tool_input`; `None` is no opinion.
pub fn decide_file(
    tool_input: Option<&Value>,
    cwd: &Path,
    policy: &Policy,
    tier: Tier,
) -> Option<Verdict> {
    let _ = (tool_input, cwd, policy, tier);
    None
}

/// The verdict for a Bash `command` that may run `safe-ai-skill env set|unset`; `None` is no
/// opinion.
pub fn decide_cli(command: &str, cwd: &Path, policy: &Policy, tier: Tier) -> Option<Verdict> {
    let _ = (command, cwd, policy, tier);
    None
}
