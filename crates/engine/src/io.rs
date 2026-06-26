//! Hook stdin parsing and decision emitters.
//!
//! `main.rs` owns all stdin reading and stdout emission so feature modules stay pure
//! and unit-testable. This module defines the [`HookInput`] payload, the [`Decision`]
//! enum, and the emitter functions. Each public `emit_*` is backed by a pure
//! `render_*` that returns a [`serde_json::Value`] so the exact JSON can be asserted
//! in tests without capturing stdout.

use std::io::{Read, Write};

use serde::Deserialize;
use serde_json::{json, Value};

/// Deserialized Claude Code hook stdin payload.
///
/// Covers PreToolUse, PostToolUse, SessionStart and UserPromptSubmit. Every field is
/// optional: a missing field deserializes to `None` and parsing never panics.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct HookInput {
    /// Session identifier.
    pub session_id: Option<String>,
    /// Current working directory of the session.
    pub cwd: Option<String>,
    /// Permission mode (e.g. `bypassPermissions`).
    pub permission_mode: Option<String>,
    /// Hook event name (`PreToolUse`, `PostToolUse`, ...).
    pub hook_event_name: Option<String>,
    /// Tool name (`Bash`, `Read`, `mcp__helius__transferSol`, ...).
    pub tool_name: Option<String>,
    /// Tool input arguments.
    pub tool_input: Option<Value>,
    /// Tool output (PostToolUse).
    pub tool_output: Option<Value>,
    /// User prompt text (UserPromptSubmit).
    pub prompt: Option<String>,
    /// Event source (`startup`, `resume`, ...).
    pub source: Option<String>,
}

impl HookInput {
    /// Read and parse the full stdin payload.
    ///
    /// Any read or parse failure yields [`HookInput::default`] so a hook never crashes
    /// on malformed input.
    pub fn from_stdin() -> Self {
        let mut buf = String::new();
        if std::io::stdin().read_to_string(&mut buf).is_err() {
            return HookInput::default();
        }
        HookInput::parse(&buf)
    }

    /// Parse from a string slice; malformed / empty input → [`HookInput::default`].
    pub fn parse(raw: &str) -> Self {
        serde_json::from_str(raw).unwrap_or_default()
    }

    /// The Bash command (`tool_input["command"]`), if present.
    pub fn bash_command(&self) -> Option<&str> {
        self.tool_input.as_ref()?.get("command")?.as_str()
    }

    /// The read target: `tool_input["file_path"]`, then `["path"]`, then glob `["pattern"]`.
    pub fn read_path(&self) -> Option<&str> {
        let input = self.tool_input.as_ref()?;
        input
            .get("file_path")
            .and_then(Value::as_str)
            .or_else(|| input.get("path").and_then(Value::as_str))
            .or_else(|| input.get("pattern").and_then(Value::as_str))
    }

    /// The raw MCP payload (`tool_input`), if present.
    pub fn mcp_payload(&self) -> Option<&Value> {
        self.tool_input.as_ref()
    }
}

/// A gate / scan decision.
///
/// `Defer` means "this gate has no opinion" — `main.rs` translates it to an `allow`
/// permission decision so an undecided gate does not block. The relaxation layer may
/// upgrade an `Ask` to `Allow` when a matching grant exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Permit the action.
    Allow,
    /// Prompt the user to approve, with a reason.
    Ask {
        /// Human-readable reason shown to the user.
        reason: String,
    },
    /// Block the action, with a reason. Survives `bypassPermissions`.
    Deny {
        /// Human-readable reason shown to the user.
        reason: String,
    },
    /// No opinion; let the default (allow) stand.
    Defer,
}

impl Decision {
    /// Stable label used in audit logs and the PreToolUse `permissionDecision` field.
    pub fn label(&self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Ask { .. } => "ask",
            Decision::Deny { .. } => "deny",
            Decision::Defer => "defer",
        }
    }

    /// The reason string for `Ask`/`Deny`, otherwise empty.
    pub fn reason(&self) -> &str {
        match self {
            Decision::Ask { reason } | Decision::Deny { reason } => reason,
            _ => "",
        }
    }
}

/// Build the PreToolUse decision JSON value (no I/O).
///
/// Shape: `{"hookSpecificOutput":{"hookEventName":"PreToolUse",
/// "permissionDecision":"allow|ask|deny|defer","permissionDecisionReason":"…"}}`.
/// The reason key is omitted for `allow` and `defer`.
pub fn render_pretooluse(d: &Decision) -> Value {
    let mut inner = json!({
        "hookEventName": "PreToolUse",
        "permissionDecision": d.label(),
    });
    if matches!(d, Decision::Ask { .. } | Decision::Deny { .. }) {
        if let Value::Object(map) = &mut inner {
            map.insert(
                "permissionDecisionReason".to_string(),
                Value::String(d.reason().to_string()),
            );
        }
    }
    json!({ "hookSpecificOutput": inner })
}

/// Emit a PreToolUse permission decision to stdout and flush.
pub fn emit_pretooluse(d: &Decision) -> std::io::Result<()> {
    write_json(&render_pretooluse(d))
}

/// Build the PostToolUse redaction JSON value (no I/O).
///
/// `None` → empty object (no change). `Some(text)` → `updatedMCPToolOutput` when
/// `mcp` is true, else `updatedToolOutput`.
pub fn render_posttooluse_redact(updated: Option<String>, mcp: bool) -> Value {
    match updated {
        None => json!({}),
        Some(text) => {
            let key = if mcp {
                "updatedMCPToolOutput"
            } else {
                "updatedToolOutput"
            };
            json!({ key: text })
        }
    }
}

/// Emit a PostToolUse redaction result to stdout and flush.
pub fn emit_posttooluse_redact(updated: Option<String>, mcp: bool) -> std::io::Result<()> {
    write_json(&render_posttooluse_redact(updated, mcp))
}

/// Build the UserPromptSubmit JSON value (no I/O).
///
/// `Some(reason)` → `{"decision":"block","reason":…}`; `None` → empty object.
pub fn render_userpromptsubmit(block: Option<&str>) -> Value {
    match block {
        Some(reason) => json!({ "decision": "block", "reason": reason }),
        None => json!({}),
    }
}

/// Emit a UserPromptSubmit decision to stdout and flush.
pub fn emit_userpromptsubmit(block: Option<&str>) -> std::io::Result<()> {
    write_json(&render_userpromptsubmit(block))
}

/// Build the SessionStart JSON value (no I/O).
///
/// Emits `hookSpecificOutput.additionalContext` (when provided) and `reloadSkills`.
pub fn render_sessionstart(additional_context: Option<&str>, reload_skills: bool) -> Value {
    let mut inner = json!({
        "hookEventName": "SessionStart",
        "reloadSkills": reload_skills,
    });
    if let Some(ctx) = additional_context {
        if let Value::Object(map) = &mut inner {
            map.insert(
                "additionalContext".to_string(),
                Value::String(ctx.to_string()),
            );
        }
    }
    json!({ "hookSpecificOutput": inner })
}

/// Emit a SessionStart result to stdout and flush.
pub fn emit_sessionstart(
    additional_context: Option<&str>,
    reload_skills: bool,
) -> std::io::Result<()> {
    write_json(&render_sessionstart(additional_context, reload_skills))
}

/// Serialize `value` as a single line to stdout and flush.
fn write_json(value: &Value) -> std::io::Result<()> {
    let mut out = std::io::stdout().lock();
    let s = serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string());
    out.write_all(s.as_bytes())?;
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRETOOLUSE_BASH: &str = r#"{
        "session_id": "abc123",
        "cwd": "/tmp/project",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": "solana transfer DEST 0.5" }
    }"#;

    const READ_PAYLOAD: &str = r#"{
        "tool_name": "Read",
        "tool_input": { "file_path": "/home/u/.config/solana/id.json" }
    }"#;

    #[test]
    fn parses_pretooluse_bash() {
        let h = HookInput::parse(PRETOOLUSE_BASH);
        assert_eq!(h.session_id.as_deref(), Some("abc123"));
        assert_eq!(h.cwd.as_deref(), Some("/tmp/project"));
        assert_eq!(h.tool_name.as_deref(), Some("Bash"));
        assert_eq!(h.bash_command(), Some("solana transfer DEST 0.5"));
    }

    #[test]
    fn read_path_prefers_file_path_then_path_then_pattern() {
        assert_eq!(
            HookInput::parse(READ_PAYLOAD).read_path(),
            Some("/home/u/.config/solana/id.json")
        );
        let by_path = HookInput::parse(r#"{"tool_input":{"path":"/a/b"}}"#);
        assert_eq!(by_path.read_path(), Some("/a/b"));
        let by_pattern = HookInput::parse(r#"{"tool_input":{"pattern":"**/*.env"}}"#);
        assert_eq!(by_pattern.read_path(), Some("**/*.env"));
    }

    #[test]
    fn malformed_input_yields_default() {
        let h = HookInput::parse("not json at all");
        assert!(h.session_id.is_none());
        assert!(h.bash_command().is_none());
        assert!(h.read_path().is_none());
    }

    #[test]
    fn missing_fields_are_none() {
        let h = HookInput::parse("{}");
        assert!(h.tool_name.is_none());
        assert!(h.mcp_payload().is_none());
    }

    #[test]
    fn render_allow_omits_reason() {
        let v = render_pretooluse(&Decision::Allow);
        let inner = &v["hookSpecificOutput"];
        assert_eq!(inner["permissionDecision"], "allow");
        assert_eq!(inner["hookEventName"], "PreToolUse");
        assert!(inner.get("permissionDecisionReason").is_none());
    }

    #[test]
    fn render_defer_omits_reason() {
        let v = render_pretooluse(&Decision::Defer);
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "defer");
        assert!(v["hookSpecificOutput"]
            .get("permissionDecisionReason")
            .is_none());
    }

    #[test]
    fn render_ask_includes_reason() {
        let v = render_pretooluse(&Decision::Ask {
            reason: "MAINNET DEPLOY".into(),
        });
        let inner = &v["hookSpecificOutput"];
        assert_eq!(inner["permissionDecision"], "ask");
        assert_eq!(inner["permissionDecisionReason"], "MAINNET DEPLOY");
    }

    #[test]
    fn render_deny_includes_reason() {
        let v = render_pretooluse(&Decision::Deny {
            reason: "secret read".into(),
        });
        let inner = &v["hookSpecificOutput"];
        assert_eq!(inner["permissionDecision"], "deny");
        assert_eq!(inner["permissionDecisionReason"], "secret read");
    }

    #[test]
    fn render_redact_variants() {
        assert_eq!(render_posttooluse_redact(None, false), json!({}));
        assert_eq!(
            render_posttooluse_redact(Some("clean".into()), false),
            json!({ "updatedToolOutput": "clean" })
        );
        assert_eq!(
            render_posttooluse_redact(Some("clean".into()), true),
            json!({ "updatedMCPToolOutput": "clean" })
        );
    }

    #[test]
    fn render_prompt_block_and_pass() {
        assert_eq!(render_userpromptsubmit(None), json!({}));
        assert_eq!(
            render_userpromptsubmit(Some("contains seed phrase")),
            json!({ "decision": "block", "reason": "contains seed phrase" })
        );
    }

    #[test]
    fn render_sessionstart_shape() {
        let v = render_sessionstart(Some("warning"), true);
        let inner = &v["hookSpecificOutput"];
        assert_eq!(inner["additionalContext"], "warning");
        assert_eq!(inner["reloadSkills"], true);
        let v2 = render_sessionstart(None, false);
        assert!(v2["hookSpecificOutput"].get("additionalContext").is_none());
    }

    #[test]
    fn decision_labels() {
        assert_eq!(Decision::Allow.label(), "allow");
        assert_eq!(Decision::Defer.label(), "defer");
        assert_eq!(Decision::Ask { reason: "x".into() }.label(), "ask");
    }
}
