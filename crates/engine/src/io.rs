//! Hook stdin parsing and decision emitters.
//!
//! `main.rs` owns all stdin reading and stdout emission so feature modules stay pure
//! and unit-testable. This module defines the [`HookInput`] payload and its bounded reader,
//! the [`Decision`] enum, and the emitter functions. Each public `emit_*` is backed by a
//! pure `render_*` that builds the [`serde_json::Value`] so the exact JSON can be asserted
//! in tests without capturing stdout.

use std::io::{Read, Write};

use serde::Deserialize;
use serde_json::{json, Value};

/// Largest hook stdin payload the engine parses (1 MiB). Anything bigger is
/// [`Unreadable::Oversized`] and is never parsed.
pub const MAX_STDIN_BYTES: usize = 1024 * 1024;

/// Why a hook payload could not be read.
///
/// The model shapes `tool_input`, so it can force `Oversized` and `Malformed`: every
/// PreToolUse gate asks on both. Only `Empty`, which Claude Code never sends, is benign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unreadable {
    /// Nothing but whitespace: no hook payload at all.
    Empty,
    /// Larger than [`MAX_STDIN_BYTES`]; never parsed, so padding cannot hide a call.
    Oversized,
    /// Not a JSON hook object: bad JSON or UTF-8, a lone surrogate escape, nesting past
    /// serde's recursion limit, or a fragment cut short by a read error.
    Malformed,
}

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
    /// Tool output (legacy field name; Claude Code sends `tool_response`).
    pub tool_output: Option<Value>,
    /// Tool output (PostToolUse), shaped per tool.
    pub tool_response: Option<Value>,
    /// User prompt text (UserPromptSubmit).
    pub prompt: Option<String>,
    /// Event source (`startup`, `resume`, ...).
    pub source: Option<String>,
}

impl HookInput {
    /// Read and parse the stdin payload, bounded at [`MAX_STDIN_BYTES`].
    ///
    /// Any read or parse failure, or an oversized payload, yields [`HookInput::default`] so
    /// a hook never crashes on malformed input.
    pub fn from_stdin() -> Self {
        read_payload(std::io::stdin()).1.unwrap_or_default()
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

/// Read one hook payload from `reader`, bounded at [`MAX_STDIN_BYTES`].
///
/// Returns the bytes received (kept for the audit hash) and their parse. Size is checked
/// before content, and reading stops one byte past the bound, so an oversized or endless
/// stream is never buffered whole.
pub fn read_payload(reader: impl Read) -> (Vec<u8>, Result<HookInput, Unreadable>) {
    read_payload_bounded(reader, MAX_STDIN_BYTES)
}

/// [`read_payload`] with a caller-chosen bound (the redact hook scans larger tool output).
pub fn read_payload_bounded(
    reader: impl Read,
    max: usize,
) -> (Vec<u8>, Result<HookInput, Unreadable>) {
    let mut bytes = Vec::new();
    // A read error keeps the bytes that arrived; the checks below classify them.
    let _ = reader
        .take(u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes);
    let parsed = if bytes.len() > max {
        Err(Unreadable::Oversized)
    } else if bytes.trim_ascii().is_empty() {
        Err(Unreadable::Empty)
    } else {
        serde_json::from_slice(&bytes).map_err(|_| Unreadable::Malformed)
    };
    (bytes, parsed)
}

/// A gate / scan decision.
///
/// `Defer` means "this gate has no opinion": it is emitted as nothing at all (empty stdout,
/// exit 0), which leaves Claude Code's normal permission flow in charge. It is never sent as
/// a `defer` permission decision, which Claude Code treats as "stop this tool call". The
/// relaxation layer may upgrade an `Ask` to `Allow` when a matching grant exists.
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
    /// No opinion; emits nothing, so the normal permission flow decides.
    Defer,
}

impl Decision {
    /// Stable label used in audit logs and the PreToolUse `permissionDecision` field
    /// (`defer` is audit-only: a `Defer` emits nothing).
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
/// "permissionDecision":"allow|ask|deny","permissionDecisionReason":"…"}}`.
/// The reason key is omitted for `allow`. [`Decision::Defer`] renders to `None`: no
/// opinion is no output.
pub fn render_pretooluse(d: &Decision) -> Option<Value> {
    if matches!(d, Decision::Defer) {
        return None;
    }
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
    Some(json!({ "hookSpecificOutput": inner }))
}

/// Emit a PreToolUse permission decision to stdout and flush; a `Defer` writes nothing.
pub fn emit_pretooluse(d: &Decision) -> std::io::Result<()> {
    write_opinion(render_pretooluse(d))
}

/// Build a PreToolUse input rewrite with no permission decision (no I/O):
/// `{"hookSpecificOutput":{"hookEventName":"PreToolUse","updatedInput":…}}`. Claude Code
/// applies `updatedInput` without an `allow`, so the normal permission flow still decides.
pub fn render_updated_input(updated: Value) -> Value {
    json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "updatedInput": updated,
        }
    })
}

/// Emit a PreToolUse input rewrite (see [`render_updated_input`]) and flush.
pub fn emit_updated_input(updated: Value) -> std::io::Result<()> {
    write_json(&render_updated_input(updated))
}

/// Build the PostToolUse redaction JSON value (no I/O).
///
/// `None` (no change) renders to `None`: no output. `Some(response)` →
/// `{"hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":response}}`,
/// where `response` has the tool's own `tool_response` shape (every tool, MCP included).
pub fn render_posttooluse_redact(updated: Option<Value>) -> Option<Value> {
    let response = updated?;
    Some(json!({
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "updatedToolOutput": response,
        }
    }))
}

/// Emit a PostToolUse redaction result to stdout and flush; no change writes nothing.
pub fn emit_posttooluse_redact(updated: Option<Value>) -> std::io::Result<()> {
    write_opinion(render_posttooluse_redact(updated))
}

/// Build the UserPromptSubmit JSON value (no I/O).
///
/// `Some(reason)` → `{"decision":"block","reason":…}`; `None` → `None` (no output).
pub fn render_userpromptsubmit(block: Option<&str>) -> Option<Value> {
    block.map(|reason| json!({ "decision": "block", "reason": reason }))
}

/// Emit a UserPromptSubmit decision to stdout and flush; a pass writes nothing.
pub fn emit_userpromptsubmit(block: Option<&str>) -> std::io::Result<()> {
    write_opinion(render_userpromptsubmit(block))
}

/// Write `value` like [`write_json`]; `None` (no opinion) writes nothing.
fn write_opinion(value: Option<Value>) -> std::io::Result<()> {
    match value {
        Some(value) => write_json(&value),
        None => Ok(()),
    }
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
    fn read_payload_parses_a_hook_object() {
        let (raw, parsed) = read_payload(PRETOOLUSE_BASH.as_bytes());
        assert_eq!(raw, PRETOOLUSE_BASH.as_bytes());
        let input = parsed.expect("readable payload");
        assert_eq!(input.bash_command(), Some("solana transfer DEST 0.5"));
    }

    #[test]
    fn read_payload_treats_blank_input_as_empty() {
        for body in [&b""[..], b" \n\t"] {
            assert_eq!(read_payload(body).1.err(), Some(Unreadable::Empty));
        }
    }

    #[test]
    fn read_payload_rejects_malformed_payloads() {
        let nest = |depth: usize| {
            format!(
                r#"{{"tool_input":{{"x":{}{}}}}}"#,
                "[".repeat(depth),
                "]".repeat(depth)
            )
        };
        let lone = r#"{"tool_input":{"x":"\ud800"}}"#.to_string();
        let bad: Vec<Vec<u8>> = vec![
            b"not json at all".to_vec(),
            vec![0xff, 0xfe, b'{', b'}'],
            nest(127).into_bytes(),
            nest(200).into_bytes(),
            lone.into_bytes(),
        ];
        for body in bad {
            assert_eq!(read_payload(&body[..]).1.err(), Some(Unreadable::Malformed));
        }
        assert!(read_payload(nest(100).as_bytes()).1.is_ok());
    }

    #[test]
    fn read_payload_is_bounded_at_one_mib() {
        // A payload of exactly the bound is read; one byte more is oversized, and only the
        // bound plus one byte is ever buffered.
        let fill = MAX_STDIN_BYTES - r#"{"prompt":""}"#.len();
        let at_bound = format!(r#"{{"prompt":"{}"}}"#, "a".repeat(fill));
        assert_eq!(at_bound.len(), MAX_STDIN_BYTES);
        assert!(read_payload(at_bound.as_bytes()).1.is_ok());
        let over = format!(r#"{{"prompt":"{}"}}"#, "a".repeat(fill + 10));
        let (raw, parsed) = read_payload(over.as_bytes());
        assert_eq!(parsed.err(), Some(Unreadable::Oversized));
        assert_eq!(raw.len(), MAX_STDIN_BYTES + 1);
    }

    #[test]
    fn read_payload_checks_size_before_content() {
        // Past the bound a payload is oversized even when it is not UTF-8, JSON or text.
        let junk = vec![0xff_u8; MAX_STDIN_BYTES + 1];
        assert_eq!(read_payload(&junk[..]).1.err(), Some(Unreadable::Oversized));
        let blank = vec![b' '; MAX_STDIN_BYTES + 1];
        assert_eq!(
            read_payload(&blank[..]).1.err(),
            Some(Unreadable::Oversized)
        );
    }

    #[test]
    fn render_allow_omits_reason() {
        let v = render_pretooluse(&Decision::Allow).expect("allow renders");
        let inner = &v["hookSpecificOutput"];
        assert_eq!(inner["permissionDecision"], "allow");
        assert_eq!(inner["hookEventName"], "PreToolUse");
        assert!(inner.get("permissionDecisionReason").is_none());
    }

    #[test]
    fn render_defer_is_nothing() {
        // No opinion is no output at all: a `defer` decision would stop the tool call.
        assert!(render_pretooluse(&Decision::Defer).is_none());
    }

    #[test]
    fn render_ask_includes_reason() {
        let v = render_pretooluse(&Decision::Ask {
            reason: "MAINNET DEPLOY".into(),
        })
        .expect("ask renders");
        let inner = &v["hookSpecificOutput"];
        assert_eq!(inner["permissionDecision"], "ask");
        assert_eq!(inner["permissionDecisionReason"], "MAINNET DEPLOY");
    }

    #[test]
    fn render_deny_includes_reason() {
        let v = render_pretooluse(&Decision::Deny {
            reason: "secret read".into(),
        })
        .expect("deny renders");
        let inner = &v["hookSpecificOutput"];
        assert_eq!(inner["permissionDecision"], "deny");
        assert_eq!(inner["permissionDecisionReason"], "secret read");
    }

    #[test]
    fn render_redact_variants() {
        // No change is no output, not `{}`.
        assert_eq!(render_posttooluse_redact(None), None);
        let response = json!({ "stdout": "clean", "stderr": "" });
        assert_eq!(
            render_posttooluse_redact(Some(response.clone())),
            Some(json!({
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "updatedToolOutput": response
                }
            }))
        );
    }

    #[test]
    fn render_updated_input_has_no_decision() {
        let v = render_updated_input(json!({ "pattern": "x", "glob": "!{a}" }));
        let inner = &v["hookSpecificOutput"];
        assert_eq!(inner["hookEventName"], "PreToolUse");
        assert_eq!(inner["updatedInput"]["glob"], "!{a}");
        assert!(inner.get("permissionDecision").is_none());
    }

    #[test]
    fn read_payload_bounded_uses_its_bound() {
        let body = format!(r#"{{"prompt":"{}"}}"#, "a".repeat(100));
        assert!(read_payload_bounded(body.as_bytes(), 200).1.is_ok());
        assert_eq!(
            read_payload_bounded(body.as_bytes(), 50).1.err(),
            Some(Unreadable::Oversized)
        );
    }

    #[test]
    fn render_prompt_block_and_pass() {
        // A pass is no output, not `{}`.
        assert_eq!(render_userpromptsubmit(None), None);
        assert_eq!(
            render_userpromptsubmit(Some("contains seed phrase")),
            Some(json!({ "decision": "block", "reason": "contains seed phrase" }))
        );
    }

    #[test]
    fn decision_labels() {
        assert_eq!(Decision::Allow.label(), "allow");
        assert_eq!(Decision::Defer.label(), "defer");
        assert_eq!(Decision::Ask { reason: "x".into() }.label(), "ask");
    }
}
