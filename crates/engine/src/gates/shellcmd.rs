//! The one list of gates a shell command text goes through, shared by every entry that judges
//! one: `gate-bash-secrets` (and `gate-bash` for decoded payloads), code an MCP server runs
//! ([`crate::gates::mcpexec`]) and `PermissionRequest` ([`crate::gates::permreq`]). A gate
//! added here reaches all of them, so they cannot drift apart.
//!
//! Every function returns a tier verdict: an `ask` or `deny` no grant may relax, `None` for no
//! opinion. Tier gates only tighten, so an `allow` from one is dropped.
//! Gate state (the CLI cluster cache, pack state) is in the data dir the caller resolved.

use std::collections::HashSet;
use std::path::Path;

use crate::context::{shell, Context};
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
/// secret-read decision), decoded payloads, the shell code it hands a shell
/// ([`recovered_verdict`]) and `git submodule foreach` / `rebase --exec` strings judged by
/// [`inner_verdict`]. The strictest wins; on a tie the later one.
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

/// Deepest nesting of recovered scripts followed, the secrets gate's own re-parse depth (it
/// asks past it).
const MAX_RECOVERED_DEPTH: usize = 4;

/// Most recovered scripts judged for one command; more asks like a command too large to check.
const MAX_RECOVERED: usize = 64;

/// The shell code `command` hands a shell without the parse listing it as commands, then the
/// same inside each, [`MAX_RECOVERED_DEPTH`] levels down: a producer's output a shell or
/// `source` runs, a dynamic here-string, launcher or `su -c` script
/// ([`shell::Parsed::opaque_shell_scripts`]), and a dynamic `-c` or `eval` script
/// ([`bash::dynamic_script`]). `None` past [`MAX_RECOVERED`] scripts or
/// [`bash::MAX_PARSE_BYTES`] of their text.
pub fn recovered_scripts(command: &str) -> Option<Vec<String>> {
    let mut found = Vec::new();
    let mut seen = HashSet::new();
    let mut bytes = 0usize;
    let mut level = vec![command.to_string()];
    for _ in 0..MAX_RECOVERED_DEPTH {
        let mut next = Vec::new();
        for text in &level {
            let parsed = shell::parse(text);
            let scripts = parsed
                .commands
                .iter()
                .filter_map(bash::dynamic_script)
                .chain(parsed.opaque_shell_scripts);
            for script in scripts {
                if !seen.insert(script.clone()) {
                    continue;
                }
                bytes = bytes.saturating_add(script.len());
                if found.len() >= MAX_RECOVERED || bytes > bash::MAX_PARSE_BYTES {
                    return None;
                }
                found.push(script.clone());
                next.push(script);
            }
        }
        if next.is_empty() {
            break;
        }
        level = next;
    }
    Some(found)
}

/// Every script [`recovered_scripts`] finds in `command`, judged by [`inner_verdict`] and, for
/// an encoded payload it runs, [`encoded_verdict`]: the verdict the code earns run directly.
/// More scripts or text than that asks like a command too large to check ([`bash::over_cap`]).
pub fn recovered_verdict(
    command: &str,
    cwd: &Path,
    policy: &Policy,
    dir: &DataDir,
) -> Option<Verdict> {
    let Some(scripts) = recovered_scripts(command) else {
        return decision_verdict(bash::over_cap(policy).0);
    };
    strictest(scripts.iter().flat_map(|script| {
        [
            inner_verdict(script, cwd, policy, dir),
            encoded_verdict(script, cwd, policy, dir),
        ]
    }))
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
        Level::Top => {
            all.push(encoded_verdict(command, cwd, policy, dir));
            all.push(recovered_verdict(command, cwd, policy, dir));
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn scripts(command: &str) -> Vec<String> {
        recovered_scripts(command).expect("under the caps")
    }

    #[test]
    fn every_kind_of_handed_script_is_recovered() {
        for (command, script) in [
            ("echo 'ls -la' | sh", "ls -la"),
            ("bash <(echo 'ls -la')", "ls -la"),
            ("source <(printf 'ls -la')", "ls -la"),
            ("sh -c \"ls $DIR\"", "ls $DIR"),
            ("eval \"ls $DIR\"", "ls $DIR"),
            ("sh <<< \"ls $DIR\"", "ls $DIR"),
            ("watch \"ls $DIR\"", "ls $DIR"),
            ("su -c \"ls $DIR\" root", "ls $DIR"),
        ] {
            assert_eq!(scripts(command), [script], "{command}");
        }
        // Code the parse lists as commands is not recovered: the gates already read it.
        for command in ["ls -la", "sh -c 'ls -la'", "sh <<< 'ls -la'", "bash ./x.sh"] {
            assert!(scripts(command).is_empty(), "{command}");
        }
    }

    #[test]
    fn scripts_inside_scripts_are_followed_to_the_depth_cap() {
        assert_eq!(
            scripts("echo \"echo 'ls -la' | sh\" | sh"),
            ["echo 'ls -la' | sh", "ls -la"]
        );
        // Each level wraps the one below in a dynamic `-c` script.
        let mut command = "ls $DIR".to_string();
        for _ in 0..MAX_RECOVERED_DEPTH + 2 {
            command = format!("sh -c {}", shell_quote(&command));
        }
        assert_eq!(scripts(&command).len(), MAX_RECOVERED_DEPTH);
    }

    #[test]
    fn repeated_scripts_count_once_and_too_many_are_none() {
        let same = "echo 'ls' | sh; ".repeat(MAX_RECOVERED * 2);
        assert_eq!(scripts(&same), ["ls"]);
        let distinct =
            |n: usize| -> String { (0..n).map(|i| format!("echo 'ls {i}' | sh; ")).collect() };
        assert_eq!(scripts(&distinct(MAX_RECOVERED)).len(), MAX_RECOVERED);
        assert_eq!(recovered_scripts(&distinct(MAX_RECOVERED + 1)), None);
        let long = format!("echo '{}' | sh", "x ".repeat(bash::MAX_PARSE_BYTES / 2 + 1));
        assert_eq!(recovered_scripts(&long), None);
    }

    /// Double quotes around `text`, escaping what a double-quoted string expands.
    fn shell_quote(text: &str) -> String {
        let mut out = String::from("\"");
        for c in text.chars() {
            if matches!(c, '"' | '\\' | '`') {
                out.push('\\');
            }
            out.push(c);
        }
        out.push('"');
        out
    }
}
