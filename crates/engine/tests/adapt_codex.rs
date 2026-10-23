//! `adapt codex <gate>` end to end (experimental, issue #23).
//!
//! Payloads follow the Codex CLI PreToolUse stdin contract (openai/codex
//! `codex-rs/hooks/src/events/pre_tool_use.rs` and `codex-rs/core/tests/suite/hooks.rs`):
//! shell calls arrive as `tool_name: "Bash"` with `tool_input.command`, file edits as
//! `tool_name: "apply_patch"` with the patch text in `tool_input.command`, MCP calls as
//! `mcp__<server>__<tool>` with the raw arguments. Codex honours only `deny`: an `ask` or a
//! bare `allow` fails open there, so `adapt codex` must never print either.

mod common;

use common::{permission_decision, Invocation, Run, TempDir};
use serde_json::{json, Value};

const MAINNET_DEPLOY: &str = "solana program deploy x.so --url mainnet-beta";
const DEST: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";

struct World {
    home: TempDir,
    proj: TempDir,
    data: TempDir,
}

impl World {
    fn new(tag: &str) -> World {
        World {
            home: TempDir::new(&format!("{tag}-home")),
            proj: TempDir::new(&format!("{tag}-proj")),
            data: TempDir::new(&format!("{tag}-data")),
        }
    }

    /// A Codex PreToolUse payload with every field Codex sends.
    fn payload(&self, tool: &str, tool_input: Value) -> String {
        json!({
            "session_id": "019a0000-0000-7000-8000-000000000000",
            "transcript_path": null,
            "cwd": self.proj.path(),
            "hook_event_name": "PreToolUse",
            "model": "gpt-5-codex",
            "permission_mode": "default",
            "turn_id": "turn-1",
            "tool_name": tool,
            "tool_use_id": "call_1",
            "tool_input": tool_input,
        })
        .to_string()
    }

    fn run(&self, args: &[&str], body: String) -> Run {
        let no_tools = TempDir::new("adapt-path");
        Invocation::new(args)
            .plugin_data(self.data.path())
            .home(self.home.path())
            .cwd(self.proj.path())
            .env("PATH", no_tools.path().to_str().unwrap())
            .stdin(body)
            .run()
    }

    fn codex(&self, gate: &str, tool: &str, tool_input: Value) -> Run {
        self.run(&["adapt", "codex", gate], self.payload(tool, tool_input))
    }

    fn claude(&self, gate: &str, tool: &str, tool_input: Value) -> Run {
        self.run(&[gate], self.payload(tool, tool_input))
    }
}

/// The decision label (`""` for no output), checking exit 0 and that Codex never sees an
/// `ask` or an `allow`.
fn codex_label(run: &Run) -> String {
    assert_eq!(run.code, Some(0), "stderr: {}", run.stderr);
    if run.stdout.is_empty() {
        return String::new();
    }
    let label = permission_decision(&run.json()).unwrap_or_default();
    assert_eq!(
        label, "deny",
        "Codex output must be deny or nothing: {}",
        run.stdout
    );
    label
}

fn reason(run: &Run) -> String {
    run.json()["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

fn patch(headers: &[&str]) -> Value {
    let mut text = String::from("*** Begin Patch\n");
    for h in headers {
        text.push_str(h);
        text.push_str("\n+x\n");
    }
    text.push_str("*** End Patch\n");
    json!({ "command": text })
}

#[test]
fn bash_ask_becomes_deny_with_the_codex_reason() {
    let w = World::new("adapt-ask");
    let input = json!({ "command": MAINNET_DEPLOY });
    let claude = w.claude("gate-bash", "Bash", input.clone());
    let claude_label = permission_decision(&claude.json()).unwrap_or_default();
    assert!(
        claude_label == "ask" || claude_label == "deny",
        "{}",
        claude.stdout
    );
    let codex = w.codex("gate-bash", "Bash", input);
    assert_eq!(codex_label(&codex), "deny");
    if claude_label == "ask" {
        assert!(
            reason(&codex).ends_with(safe_ai_skill::adapt::CODEX_ASK_SUFFIX),
            "{}",
            codex.stdout
        );
    }
}

#[test]
fn benign_bash_is_no_output() {
    let w = World::new("adapt-benign");
    for gate in ["gate-bash", "gate-bash-secrets"] {
        let run = w.codex(gate, "Bash", json!({ "command": "ls -la" }));
        assert_eq!(codex_label(&run), "", "{gate}");
    }
}

#[test]
fn wallet_secret_read_through_the_shell_denies() {
    let w = World::new("adapt-secret");
    let run = w.codex(
        "gate-bash-secrets",
        "Bash",
        json!({ "command": "cat ~/.config/solana/id.json" }),
    );
    assert_eq!(codex_label(&run), "deny");
}

#[test]
fn value_moving_mcp_call_denies_on_codex_and_asks_on_claude() {
    let w = World::new("adapt-mcp");
    let input = json!({ "destination": DEST, "lamports": 1_000_000_000u64 });
    let tool = "mcp__helius__heliusWrite.sendSol";
    let claude = w.claude("gate-mcp", tool, input.clone());
    assert_eq!(permission_decision(&claude.json()).as_deref(), Some("ask"));
    let codex = w.codex("gate-mcp", tool, input);
    assert_eq!(codex_label(&codex), "deny");
    assert!(reason(&codex).ends_with(safe_ai_skill::adapt::CODEX_ASK_SUFFIX));
    let read = w.codex("gate-mcp", "mcp__helius__getBalance", json!({}));
    assert_eq!(codex_label(&read), "");
}

#[test]
fn apply_patch_into_the_data_dir_denies() {
    let w = World::new("adapt-tamper");
    let target = w.data.join("grants.json");
    let header = format!("*** Add File: {}", target.display());
    let run = w.codex(
        "gate-tamper",
        "apply_patch",
        patch(&["*** Add File: src/ok.rs", &header]),
    );
    assert_eq!(codex_label(&run), "deny");
}

#[test]
fn apply_patch_to_codex_hook_config_denies() {
    let w = World::new("adapt-codexcfg");
    for header in [
        "*** Update File: .codex/hooks.json",
        "*** Delete File: .codex/config.toml",
        "*** Update File: notes.md\n*** Move to: .codex/hooks.json",
    ] {
        let run = w.codex("gate-tamper", "apply_patch", patch(&[header]));
        assert_eq!(codex_label(&run), "deny", "{header}");
        assert!(reason(&run).contains("Codex hook config"), "{}", run.stdout);
    }
}

#[test]
fn benign_apply_patch_is_no_output() {
    let w = World::new("adapt-patch-ok");
    let run = w.codex(
        "gate-tamper",
        "apply_patch",
        patch(&["*** Add File: src/new.rs", "*** Update File: README.md"]),
    );
    assert_eq!(codex_label(&run), "");
}

#[test]
fn unreadable_payloads_deny_instead_of_asking() {
    let w = World::new("adapt-malformed");
    for gate in ["gate-bash", "gate-mcp", "gate-tamper"] {
        let run = w.run(&["adapt", "codex", gate], "{not json".to_string());
        assert_eq!(codex_label(&run), "deny", "{gate}");
    }
    let run = w.codex("gate-tamper", "apply_patch", json!({ "patch": "x" }));
    assert_eq!(codex_label(&run), "deny");
}

#[test]
fn usage_errors_exit_3_with_no_output() {
    let w = World::new("adapt-usage");
    let body = w.payload("Bash", json!({ "command": "ls" }));
    for args in [
        &["adapt"][..],
        &["adapt", "codex"],
        &["adapt", "opencode", "gate-bash"],
        &["adapt", "codex", "gate-read"],
        &["adapt", "codex", "redact"],
        &["adapt", "codex", "gate-nope"],
        &["adapt", "codex", "gate-bash", "extra"],
    ] {
        let run = w.run(args, body.clone());
        assert_eq!(run.code, Some(3), "{args:?}");
        assert!(run.stdout.is_empty(), "{args:?}: {}", run.stdout);
    }
}

/// The shipped template wires only gates `adapt codex` offers, on Codex's tool names.
#[test]
fn codex_hooks_template_names_offered_gates() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../adapters/codex/hooks.json"
    );
    let text = std::fs::read_to_string(path).expect("read adapters/codex/hooks.json");
    let v: Value = serde_json::from_str(&text).expect("template is JSON");
    let groups = v["hooks"]["PreToolUse"]
        .as_array()
        .expect("PreToolUse groups");
    let mut gates = Vec::new();
    for group in groups {
        for hook in group["hooks"].as_array().expect("hooks array") {
            let command = hook["command"].as_str().expect("command");
            let gate = command
                .strip_prefix("safe-ai-skill adapt codex ")
                .unwrap_or_else(|| panic!("unexpected command {command}"));
            assert!(safe_ai_skill::adapt::CODEX_GATES.contains(&gate), "{gate}");
            gates.push(gate.to_string());
        }
    }
    for gate in safe_ai_skill::adapt::CODEX_GATES {
        assert!(gates.iter().any(|g| g == gate), "{gate} not wired");
    }
}
