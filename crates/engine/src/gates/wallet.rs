//! Default-wallet destruction (D8 v2 spec §3.1; owned by F3): `solana-keygen new|recover` with
//! `--force/-f` and no `-o` or an outfile naming `~/.config/solana/id.json` or the CLI config's
//! `keypair_path`; Bash `rm|mv|cp|tee|dd of=|>` onto that file; Write/Edit/NotebookEdit to it.
//! Denied on every cluster at every tier.
//!
//! **F0 stub:** no opinion (1.1.0 has no such rule). Call lines: `main::cmd_gate_bash_secrets`
//! ([`decide_bash`]; `solana-keygen` is not matched by the bash gate's `if`) and
//! `main::cmd_gate_tamper` ([`decide_file`]).

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
