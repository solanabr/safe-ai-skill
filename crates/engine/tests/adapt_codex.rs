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

/// The shipped template wires only gates `adapt codex` offers, through the wrapper.
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
                .strip_prefix("safe-ai-skill-codex ")
                .unwrap_or_else(|| panic!("unexpected command {command}"));
            assert!(safe_ai_skill::adapt::CODEX_GATES.contains(&gate), "{gate}");
            gates.push(gate.to_string());
        }
    }
    for gate in safe_ai_skill::adapt::CODEX_GATES {
        assert!(gates.iter().any(|g| g == gate), "{gate} not wired");
    }
}

#[test]
fn apply_patch_run_through_the_shell_gets_the_patch_checks() {
    let w = World::new("adapt-shell-patch");
    for command in [
        "apply_patch <<'EOF'\n*** Begin Patch\n*** Add File: ~/.config/solana/id.json\n+[]\n*** End Patch\nEOF",
        "apply_patch <<'EOF'\n*** Begin Patch\n*** Update File: .codex/hooks.json\n@@\n-a\n+b\n*** End Patch\nEOF",
        "applypatch \"*** Begin Patch\n*** Delete File: ~/.config/solana/id.json\n*** End Patch\"",
        "printf '%s' \"$P\" | apply_patch $'*** Begin Patch\\n*** Delete File: .codex/config.toml\\n*** End Patch'",
    ] {
        let run = w.codex("gate-bash-secrets", "Bash", json!({ "command": command }));
        assert_eq!(codex_label(&run), "deny", "{command}");
    }
    let ok =
        "apply_patch <<'EOF'\n*** Begin Patch\n*** Add File: src/new.rs\n+x\n*** End Patch\nEOF";
    let run = w.codex("gate-bash-secrets", "Bash", json!({ "command": ok }));
    assert_eq!(codex_label(&run), "");
}

#[test]
fn relative_state_writes_deny_whatever_the_workdir() {
    let w = World::new("adapt-workdir");
    for command in ["rm tier.json", "rm -f grants.json", "echo {} > tier.json"] {
        let run = w.codex("gate-bash-secrets", "Bash", json!({ "command": command }));
        assert_eq!(codex_label(&run), "deny", "{command}");
    }
    let run = w.codex(
        "gate-tamper",
        "apply_patch",
        patch(&["*** Delete File: tier.json"]),
    );
    assert_eq!(codex_label(&run), "deny");
}

#[test]
fn a_workdir_in_the_payload_is_where_relative_paths_resolve() {
    let w = World::new("adapt-workdir-field");
    let data = w.data.path().to_str().unwrap().to_string();
    let run = w.codex(
        "gate-bash-secrets",
        "Bash",
        json!({ "command": "rm -rf ./quarantine", "workdir": data }),
    );
    assert_eq!(codex_label(&run), "deny", "{}", run.stdout);
}

#[test]
fn claude_settings_and_the_engine_binary_are_protected() {
    let w = World::new("adapt-settings");
    let engine = common::bin().to_string();
    for header in [
        "*** Update File: .claude/settings.local.json".to_string(),
        "*** Add File: .claude/settings.json".to_string(),
        format!(
            "*** Update File: {}/.claude/settings.json",
            w.home.path().display()
        ),
        format!("*** Delete File: {engine}"),
        format!("*** Add File: {engine}-codex"),
    ] {
        let run = w.codex("gate-tamper", "apply_patch", patch(&[&header]));
        assert_eq!(codex_label(&run), "deny", "{header}");
    }
    for command in [
        format!("rm -f {engine}"),
        format!("cp /tmp/x {engine}"),
        "echo '{}' > .claude/settings.local.json".to_string(),
    ] {
        let run = w.codex("gate-bash-secrets", "Bash", json!({ "command": command }));
        assert_eq!(codex_label(&run), "deny", "{command}");
    }
}

#[test]
fn codex_home_from_the_environment_is_protected() {
    let w = World::new("adapt-codexhome");
    let codex_home = TempDir::new("adapt-codexhome-dir");
    let target = codex_home.join("hooks.json");
    let header = format!("*** Update File: {}", target.display());
    let no_tools = TempDir::new("adapt-path");
    let run = Invocation::new(&["adapt", "codex", "gate-tamper"])
        .plugin_data(w.data.path())
        .home(w.home.path())
        .cwd(w.proj.path())
        .env("PATH", no_tools.path().to_str().unwrap())
        .env("CODEX_HOME", codex_home.path().to_str().unwrap())
        .stdin(w.payload("apply_patch", patch(&[&header])))
        .run();
    assert_eq!(codex_label(&run), "deny");
}

#[test]
fn the_discovered_data_dir_is_protected_without_claude_plugin_data() {
    let home = TempDir::new("adapt-disc-home");
    let proj = TempDir::new("adapt-disc-proj");
    let data = home.join(".claude/plugins/data/safe-ai-skill-safe-ai-skill");
    std::fs::create_dir_all(&data).unwrap();
    let header = format!("*** Add File: {}", data.join("grants.json").display());
    let payload = json!({
        "cwd": proj.path(), "hook_event_name": "PreToolUse", "tool_name": "apply_patch",
        "tool_input": patch(&[&header]),
    });
    let no_tools = TempDir::new("adapt-path");
    let run = Invocation::new(&["adapt", "codex", "gate-tamper"])
        .home(home.path())
        .cwd(proj.path())
        .env("PATH", no_tools.path().to_str().unwrap())
        .stdin(payload.to_string())
        .run();
    assert_eq!(codex_label(&run), "deny", "{}", run.stdout);
}

#[test]
fn oversized_patches_deny_with_a_clear_reason() {
    let w = World::new("adapt-bigpatch");
    let headers: Vec<String> = (0..=safe_ai_skill::adapt::MAX_PATCH_PATHS)
        .map(|i| format!("*** Add File: src/f{i}.rs"))
        .collect();
    let refs: Vec<&str> = headers.iter().map(String::as_str).collect();
    let run = w.codex("gate-tamper", "apply_patch", patch(&refs));
    assert_eq!(codex_label(&run), "deny");
    assert!(reason(&run).contains("split it"), "{}", reason(&run));
}

#[test]
fn the_ask_reason_reads_cleanly() {
    let w = World::new("adapt-reason");
    let input = json!({ "destination": DEST, "lamports": 1_000_000_000u64 });
    let run = w.codex("gate-mcp", "mcp__helius__heliusWrite.sendSol", input);
    let r = reason(&run);
    assert!(!r.contains("approve to proceed"), "{r}");
    assert!(
        r.contains(&format!(". {}", safe_ai_skill::adapt::CODEX_ASK_SUFFIX)),
        "{r}"
    );
}

#[cfg(feature = "test-hooks")]
#[test]
fn a_panic_still_denies_with_exit_0() {
    let w = World::new("adapt-panic");
    let no_tools = TempDir::new("adapt-path");
    let run = Invocation::new(&["adapt", "codex", "gate-bash"])
        .plugin_data(w.data.path())
        .home(w.home.path())
        .cwd(w.proj.path())
        .env("PATH", no_tools.path().to_str().unwrap())
        .env("SAFE_AI_SKILL_TEST_PANIC", "1")
        .stdin(w.payload("Bash", json!({ "command": "ls" })))
        .run();
    assert_eq!(codex_label(&run), "deny", "{}", run.stderr);
}

/// Re-review R1: directory, glob, `cd`, `find` and `git` writes reaching protected files.
#[test]
fn directory_glob_cd_find_and_git_writes_to_protected_files_deny() {
    let w = World::new("adapt-r1");
    std::fs::create_dir_all(w.home.join(".codex")).unwrap();
    std::fs::write(w.home.join(".codex/hooks.json"), "{}").unwrap();
    std::fs::create_dir_all(w.proj.join(".codex")).unwrap();
    std::fs::write(w.proj.join(".codex/hooks.json"), "{}").unwrap();
    let engine = std::path::Path::new(common::bin());
    let bin_dir = engine.parent().unwrap().display().to_string();
    for command in [
        format!("mv {bin_dir} {bin_dir}.off"),
        format!("rm -rf {bin_dir}"),
        format!("rm {bin_dir}/safe-ai-*"),
        format!("rm {bin_dir}/safe-ai-skil?"),
        format!("find {bin_dir} -name 'safe*' -delete"),
        format!("chmod -x {}", engine.display()),
        "mv .codex .codex.off".to_string(),
        "rm -rf .codex".to_string(),
        "mv ~/.codex ~/.codex.bak".to_string(),
        "rm .codex/*".to_string(),
        "cd .codex && rm hooks.json".to_string(),
        "git checkout -- .codex".to_string(),
        "git clean -fdx".to_string(),
        "find . -name hooks.json -exec rm {} +".to_string(),
    ] {
        let run = w.codex("gate-bash-secrets", "Bash", json!({ "command": command }));
        assert_eq!(codex_label(&run), "deny", "{command}");
    }
    for command in [
        "rm -rf target",
        "git status",
        "find . -name '*.rs'",
        "git stash",
    ] {
        let run = w.codex("gate-bash-secrets", "Bash", json!({ "command": command }));
        assert_eq!(codex_label(&run), "", "{command}: {}", run.stdout);
    }
}

/// Re-review R2: an interactive shell or REPL would take `write_stdin` input unchecked.
#[test]
fn interactive_shells_and_repls_deny() {
    let w = World::new("adapt-r2");
    for command in ["bash", "sh -i", "python3", "node", "psql mydb"] {
        let run = w.codex("gate-bash-secrets", "Bash", json!({ "command": command }));
        assert_eq!(codex_label(&run), "deny", "{command}");
        assert!(reason(&run).contains("write_stdin"), "{}", run.stdout);
    }
    for command in ["bash -c 'ls'", "python3 script.py", "echo ls | sh"] {
        let run = w.codex("gate-bash-secrets", "Bash", json!({ "command": command }));
        assert_eq!(codex_label(&run), "", "{command}");
    }
}

/// Re-review R4: a literal protected path inside interpreter code.
#[test]
fn protected_paths_in_interpreter_code_deny() {
    let w = World::new("adapt-r4");
    let engine = common::bin();
    let command = format!("python3 -c \"import os;os.remove('{engine}')\"");
    let run = w.codex("gate-bash-secrets", "Bash", json!({ "command": command }));
    assert_eq!(codex_label(&run), "deny");
}
