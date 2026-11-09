//! The one list of gates a shell command text goes through, shared by every entry that judges
//! one: `gate-bash-secrets` (and `gate-bash` for decoded payloads), code an MCP server runs
//! ([`crate::gates::mcpexec`]) and `PermissionRequest` ([`crate::gates::permreq`]). A gate
//! added here reaches all of them, so they cannot drift apart.
//!
//! Every function returns a tier verdict: an `ask` or `deny` no grant may relax, `None` for no
//! opinion. Tier gates only tighten, so an `allow` from one is dropped.
//! Gate state (the CLI cluster cache, pack state) is in the data dir the caller resolved.

use std::path::Path;

use crate::context::Context;
use crate::datadir::DataDir;
use crate::gate::Verdict;
use crate::gates::{
    bash, containers, creddump, encoded, envread, envwrite, exfil, fetchexec, gitguard, keyfiles,
    secrets, tamper, wallet,
};
use crate::io::Decision;
use crate::policy::tier::Tier;
use crate::policy::Policy;
use crate::verify;

/// How a command text is reached, which decides the parts of [`verdicts`] that differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Level {
    /// Typed by the agent: decoded payloads and git-nested commands are judged as [`Inner`].
    ///
    /// [`Inner`]: Level::Inner
    Top,
    /// Typed by the agent, the caller judging nested commands itself: the encoded-payload
    /// check, no expansion.
    Flat,
    /// Found inside another command: the bash and secrets gates join, nothing is expanded.
    Inner,
}

/// Every Bash-command tier gate on `command` (the set `gate-bash-secrets` joins with its
/// secret-read decision), decoded payloads and `git submodule foreach` / `rebase --exec`
/// strings judged by [`inner_verdict`]. The strictest wins; on a tie the later one.
pub fn tier_verdict(command: &str, cwd: &Path, policy: &Policy, dir: &DataDir) -> Option<Verdict> {
    verdicts(command, cwd, policy, dir, Level::Top)
}

/// [`tier_verdict`] without the nested commands, for a caller that walks them itself.
pub fn flat_verdict(command: &str, cwd: &Path, policy: &Policy, dir: &DataDir) -> Option<Verdict> {
    verdicts(command, cwd, policy, dir, Level::Flat)
}

/// A command text found inside another one (a decoded payload, a `git submodule foreach` or
/// `rebase --exec` string), judged by every Bash gate as if it had been typed.
pub fn inner_verdict(text: &str, cwd: &Path, policy: &Policy, dir: &DataDir) -> Option<Verdict> {
    verdicts(text, cwd, policy, dir, Level::Inner)
}

/// An encoded payload piped or eval'd into a shell, decoded and judged by [`inner_verdict`];
/// an undecodable payload asks, a deny at High.
pub fn encoded_verdict(
    command: &str,
    cwd: &Path,
    policy: &Policy,
    dir: &DataDir,
) -> Option<Verdict> {
    let mut all = vec![encoded_at_tier(command, policy.tier())];
    for decoded in encoded::expand(command) {
        all.push(inner_verdict(&decoded, cwd, policy, dir));
    }
    strictest(all)
}

/// A [`tamper::decide_nested_claude`] decision as a tier verdict: its `ask` is a deny at High.
pub fn nested_claude_verdict(decision: Decision, tier: Tier) -> Option<Verdict> {
    match decision {
        Decision::Deny { reason } => Some(Verdict::Deny(reason)),
        Decision::Ask { reason } if tier == Tier::High => {
            Some(Verdict::Deny(format!("{reason} Denied at tier high.")))
        }
        Decision::Ask { reason } => Some(Verdict::Ask(reason)),
        _ => None,
    }
}

/// A word of `command` inside a blocked pack, as the tier has it act: `Some` when it denies.
pub fn blocked_pack_verdict(
    dir: &DataDir,
    command: &str,
    cwd: &Path,
    tier: Tier,
) -> Option<Verdict> {
    match verify::tier_action(verify::enforce::bash_verdict(dir, command, cwd), tier) {
        deny @ Verdict::Deny(_) => Some(deny),
        _ => None,
    }
}

/// The strictest of `verdicts` (`deny` > `ask`, the later one on a tie); `None` when none asks
/// or denies.
pub fn strictest(verdicts: impl IntoIterator<Item = Option<Verdict>>) -> Option<Verdict> {
    verdicts
        .into_iter()
        .flatten()
        .filter(|v| matches!(v, Verdict::Ask(_) | Verdict::Deny(_)))
        .max_by_key(rank)
}

fn rank(v: &Verdict) -> u8 {
    match v {
        Verdict::NoOpinion => 0,
        Verdict::Allow(_) => 1,
        Verdict::Ask(_) => 2,
        Verdict::Deny(_) => 3,
    }
}

/// The list. Its order is the tie order of [`strictest`], kept as the entries had it.
fn verdicts(
    command: &str,
    cwd: &Path,
    policy: &Policy,
    dir: &DataDir,
    level: Level,
) -> Option<Verdict> {
    let tier = policy.tier();
    let mut all = Vec::with_capacity(16);
    if level == Level::Inner {
        let ctx = Context::build_in(command, cwd, dir);
        all.push(decision_verdict(bash::decide(command, &ctx, policy).0));
        all.push(decision_verdict(secrets::decide(command, cwd, policy)));
    }
    all.extend([
        wallet::decide_bash(command, cwd, policy, tier),
        creddump::decide(command, cwd, policy, tier),
        envwrite::decide_cli(command, cwd, policy, tier),
        exfil::decide_bash(command, cwd, policy, tier),
        fetchexec::decide(command, cwd, policy, tier),
        tamper::decide_bash_writes(command, cwd, policy, tier),
        envread::decide_bash(command),
    ]);
    match level {
        Level::Top => all.push(encoded_verdict(command, cwd, policy, dir)),
        Level::Flat => all.push(encoded_at_tier(command, tier)),
        Level::Inner => {}
    }
    all.push(gitguard::decide(command, cwd, policy, tier));
    if level == Level::Top {
        for inner in gitguard::inner_commands(command) {
            all.push(inner_verdict(&inner, cwd, policy, dir));
        }
    }
    all.extend([
        containers::decide(command, cwd, policy, tier),
        keyfiles::decide_bash(command, cwd, tier),
    ]);
    strictest(all)
}

/// [`encoded::decide`] with its ask denied at High.
fn encoded_at_tier(command: &str, tier: Tier) -> Option<Verdict> {
    encoded::decide(command).map(|v| match v {
        Verdict::Ask(reason) if tier == Tier::High => {
            Verdict::Deny(format!("{reason} Denied at tier high."))
        }
        v => v,
    })
}

fn decision_verdict(d: Decision) -> Option<Verdict> {
    match d {
        Decision::Deny { reason } => Some(Verdict::Deny(reason)),
        Decision::Ask { reason } => Some(Verdict::Ask(reason)),
        _ => None,
    }
}
