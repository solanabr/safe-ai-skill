//! `PermissionRequest`: keep a hard-guarded call from being approved without the user.
//!
//! Claude Code runs this event "when Claude Code is about to ask you for permission to use a
//! tool", and in sessions that cannot prompt "still runs these hooks, and if no hook returns a
//! decision, it denies the tool call" (hooks reference, `PermissionRequest`). The payload is
//! PreToolUse's `tool_name`/`tool_input` (no `tool_use_id`) plus `permission_mode` and
//! `permission_suggestions`; the answer is `hookSpecificOutput.decision.behavior`
//! (`allow`/`deny`, `message` for a deny). Exit 2 is ignored on this event, and a hook with
//! `onFailure: "block"` denies the request when it fails.
//!
//! The PreToolUse gates already deny or ask on every class below, so on a healthy run this
//! event sees our classes only when a PreToolUse gate did not answer (its process failed to
//! start, crashed or timed out under `onFailure: "continue"`). What can still approve such a
//! call without the user is another `PermissionRequest` hook, a `--permission-prompt-tool` /
//! `canUseTool` host ("whichever decides first applies"), or a permission mode that does not
//! wait for the user. The call is judged again with the PreToolUse gates' own decision
//! functions (nothing is re-implemented), and a hard-guard class (a deny, or an ask no grant
//! may relax) is:
//! - denied when nobody would see the prompt: the session is headless, or runs in `dontAsk`
//!   (or an unknown) mode, where only hooks and hosts answer;
//! - denied in `auto`, `acceptEdits` and `bypassPermissions` when a gate denies it: PreToolUse
//!   would have denied it too, so no flow loses anything. An ask is left to the user there,
//!   because a hook-forced prompt is still shown in auto mode (permission modes: "auto mode
//!   still shows you those prompts");
//! - otherwise left to the user with a one-line `systemMessage`. Claude Code offers no field
//!   that adds text to the dialog itself on this event.
//!
//! Anything else gets no output. This hook never allows, so it never weakens a verdict.

use std::path::Path;

use serde_json::{json, Value};

use crate::context::Context;
use crate::datadir::DataDir;
use crate::gate::{GateMeta, Scope, Verdict};
use crate::gates::{
    bash, creddump, encoded, envread, envwrite, exfil, fetchexec, gitguard, mcp, mcpexec, read,
    secrets, tamper, wallet,
};
use crate::io::Decision;
use crate::policy::tier::Tier;
use crate::policy::Policy;
use crate::verify;

/// What the gates make of the call behind a permission request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Class {
    /// No gate asks or denies, or only with a grantable ask: the user decides as usual.
    Ordinary,
    /// A deny, or an ask no grant may relax.
    HardGuard {
        /// The strictest gate's reason.
        reason: String,
        /// Whether a gate denies it (else it asks).
        denied: bool,
    },
}

/// Permission modes in which a prompt waits for the user (`manual` is `default`'s alias).
const USER_MODES: &[&str] = &["default", "manual", "plan"];

/// Modes that show a hook-forced prompt but approve other calls without one.
const AUTO_MODES: &[&str] = &["auto", "acceptEdits", "bypassPermissions"];

/// Tool names this event is wired for; anything else is [`Class::Ordinary`] before any parse.
fn gated_tool(tool: &str) -> bool {
    matches!(
        tool,
        "Bash"
            | "Write"
            | "Edit"
            | "MultiEdit"
            | "NotebookEdit"
            | "Read"
            | "Grep"
            | "Glob"
            | "WebFetch"
    ) || tool.starts_with("mcp__")
}

/// Classify a permission request's call with the PreToolUse gates' decision functions.
pub fn classify(
    tool: &str,
    tool_input: Option<&Value>,
    cwd: &Path,
    policy: &Policy,
    dir: &DataDir,
) -> Class {
    if !gated_tool(tool) {
        return Class::Ordinary;
    }
    let tier = policy.tier();
    let field = |k: &str| {
        tool_input
            .and_then(|t| t.get(k))
            .and_then(Value::as_str)
            .unwrap_or("")
    };
    let mut found = Strictest::default();
    match tool {
        "Bash" => bash_call(field("command"), cwd, policy, dir, 1, false, &mut found),
        "Read" | "Grep" | "Glob" => {
            if let Some(input) = tool_input {
                found.verdict(verify::enforce::read_verdict(dir, tool, input, cwd));
            }
            if let read::ReadVerdict::Decide(d) = read::decide_tool(tool, tool_input, cwd, policy) {
                found.hard(d);
            }
        }
        "WebFetch" => {
            found.tier(exfil::decide_webfetch(
                field("url"),
                field("prompt"),
                policy,
                tier,
            ));
        }
        t if t.starts_with("mcp__") => {
            if let Some(v) = mcp::decide_name(t, tier) {
                found.verdict(v);
            }
            found.hard(read::decide_mcp_args(tool_input, cwd, policy));
            found.tier(exfil::decide_mcp(t, tool_input, cwd, policy, tier));
            let (d, meta) = mcp::decide(t, tool_input, &Context::build_in("", cwd, dir), policy);
            // `gate-mcp` denies a value-moving MCP ask at High (no cluster is named).
            match d {
                Decision::Ask { reason } if tier == Tier::High => {
                    found.hard(Decision::Deny { reason });
                }
                d => found.meta(d, &meta),
            }
            let (d, meta) = mcpexec::decide(tool_input, cwd, policy);
            found.meta(d, &meta);
        }
        _ => {
            let protected = tamper::Protected::from_env();
            found.hard(tamper::decide_file(tool_input, cwd, &protected));
            found.tier(wallet::decide_file(tool_input, cwd, policy, tier));
            found.tier(envwrite::decide_file(tool_input, cwd, policy, tier));
            found.tier(tamper::decide_file_content(tool_input, cwd, policy, tier));
        }
    }
    found.class()
}

/// The Bash gates on `command`; decoded payloads and git-nested commands are judged the same
/// way (`nested`), `depth` levels down.
fn bash_call(
    command: &str,
    cwd: &Path,
    policy: &Policy,
    dir: &DataDir,
    depth: u8,
    nested: bool,
    found: &mut Strictest,
) {
    if command.is_empty() {
        return;
    }
    let tier = policy.tier();
    found.verdict(verify::enforce::bash_verdict(dir, command, cwd));
    found.hard(tamper::decide_nested_claude(command));
    for v in [
        wallet::decide_bash(command, cwd, policy, tier),
        creddump::decide(command, cwd, policy, tier),
        envwrite::decide_cli(command, cwd, policy, tier),
        exfil::decide_bash(command, cwd, policy, tier),
        fetchexec::decide(command, cwd, policy, tier),
        tamper::decide_bash_writes(command, cwd, policy, tier),
        envread::decide_bash(command),
        encoded::decide(command),
        gitguard::decide(command, cwd, policy, tier),
    ] {
        found.tier(v);
    }
    let (d, meta) = bash::with_indirection_prefilter(
        secrets::decide(command, cwd, policy),
        GateMeta::new(Scope::SecretRead, true),
        command,
        cwd,
        policy,
    );
    found.meta(d, &meta);
    if bash::over_work_cap(command) {
        let (d, meta) = bash::over_cap(policy);
        found.meta(d, &meta);
    } else if bash::may_concern(command) {
        let (d, meta) = bash::decide(command, &Context::build_in(command, cwd, dir), policy);
        // A command found inside another one joins as a tier verdict (no grant lifts it).
        if nested {
            found.hard(d);
        } else {
            found.meta(d, &meta);
        }
    }
    if depth == 0 {
        return;
    }
    for inner in encoded::expand(command)
        .into_iter()
        .chain(gitguard::inner_commands(command))
    {
        bash_call(&inner, cwd, policy, dir, depth - 1, true, found);
    }
}

/// The first hard-guard reasons seen (a deny beats an ask).
#[derive(Default)]
struct Strictest {
    deny: Option<String>,
    ask: Option<String>,
}

impl Strictest {
    /// A decision from a gate whose every ask and deny is a hard guard.
    fn hard(&mut self, d: Decision) {
        match d {
            Decision::Deny { reason } => {
                self.deny.get_or_insert(reason);
            }
            Decision::Ask { reason } => {
                self.ask.get_or_insert(reason);
            }
            _ => {}
        }
    }

    /// A verdict joined as a hard guard (tier gates, packs, tool-name refusals).
    fn verdict(&mut self, v: Verdict) {
        self.hard(v.into());
    }

    fn tier(&mut self, v: Option<Verdict>) {
        if let Some(v) = v {
            self.verdict(v);
        }
    }

    /// A decision under its gate's meta: a grantable ask is ordinary.
    fn meta(&mut self, d: Decision, meta: &GateMeta) {
        match d {
            Decision::Ask { .. } if !meta.hard_guard => {}
            d => self.hard(d),
        }
    }

    fn class(self) -> Class {
        match (self.deny, self.ask) {
            (Some(reason), _) => Class::HardGuard {
                reason,
                denied: true,
            },
            (None, Some(reason)) => Class::HardGuard {
                reason,
                denied: false,
            },
            (None, None) => Class::Ordinary,
        }
    }
}

/// Why a hard-guard class must be denied rather than left to the prompt, if so: nobody sees
/// the prompt (headless, `dontAsk`, an unknown mode), or a gate denies it in a mode that
/// approves calls without the user.
pub fn unattended(permission_mode: Option<&str>, headless: bool, denied: bool) -> Option<String> {
    if headless {
        return Some("the session is headless".to_string());
    }
    match permission_mode {
        None => None,
        Some(m) if USER_MODES.contains(&m) => None,
        Some(m) if AUTO_MODES.contains(&m) && !denied => None,
        Some(m) => Some(format!("the session runs in `{m}` mode")),
    }
}

/// The `PermissionRequest` output for a classified request; `None` emits nothing.
pub fn render(class: &Class, permission_mode: Option<&str>, headless: bool) -> Option<Value> {
    let Class::HardGuard { reason, denied } = class else {
        return None;
    };
    let reason = reason.trim_end().trim_end_matches('.');
    match unattended(permission_mode, headless, *denied) {
        Some(why) => Some(json!({
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": {
                    "behavior": "deny",
                    "message": format!(
                        "{reason} (safe-ai-skill hard guard: {why}, so it is not left to an \
                         automatic approval); run it yourself or approve it in an interactive \
                         Manual-mode session."
                    ),
                }
            }
        })),
        None => Some(json!({
            "systemMessage": format!(
                "safe-ai-skill hard guard: {reason}; approve only if you meant this call."
            )
        })),
    }
}

/// [`classify`] then [`render`] for one request.
pub fn decide(
    tool: &str,
    tool_input: Option<&Value>,
    permission_mode: Option<&str>,
    cwd: &Path,
    policy: &Policy,
    dir: &DataDir,
) -> Option<Value> {
    let class = classify(tool, tool_input, cwd, policy, dir);
    render(&class, permission_mode, policy.runtime.headless)
}
