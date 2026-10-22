//! Command-form credential readers (D8 v2 spec §4; owned by F1): `gh auth token`,
//! `git credential fill`, `security find-generic-password -w`, `aws configure get *secret*`,
//! `npm config get *_authToken`, `docker-credential-* get`, `secret-tool lookup`, `pass show`,
//! `op read`, `bw get`, denied at every tier.
//!
//! **F0 stub:** no opinion (1.1.0 has no such rule). Call line: `main::cmd_gate_bash_secrets`
//! (the [`crate::gate::Verdict`] joins the secrets gate's decision, strictest wins).

use std::path::Path;

use crate::gate::Verdict;
use crate::policy::tier::Tier;
use crate::policy::Policy;

/// The verdict for a Bash `command` run in `cwd`; `None` is no opinion.
pub fn decide(command: &str, cwd: &Path, policy: &Policy, tier: Tier) -> Option<Verdict> {
    let _ = (command, cwd, policy, tier);
    None
}
