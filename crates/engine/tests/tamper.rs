//! End-to-end tests for the self-grant / state-tamper tripwire (spec D4.3).
//!
//! The tripwire has two entry points, both driven through the real binary:
//! - `gate-bash-secrets` (the unconditional Bash hook) denies a command that references
//!   safe-ai-skill state or runs the binary with a mutating subcommand;
//! - `gate-tamper` (the `Write|Edit|MultiEdit|NotebookEdit` hook) denies a write whose target is
//!   safe-ai-skill state.
//!
//! Every run is hermetic: `HOME`, `CLAUDE_PLUGIN_DATA`, `CLAUDE_PLUGIN_ROOT` and the session cwd
//! are fresh temp dirs.

mod common;

use common::{permission_decision, Invocation, Run, TempDir};
use serde_json::{json, Value};

/// Isolated HOME, plugin data dir, plugin root and project dir for one test.
struct Sandbox {
    home: TempDir,
    data: TempDir,
    root: TempDir,
    project: TempDir,
}

impl Sandbox {
    fn new(tag: &str) -> Self {
        Sandbox {
            home: TempDir::new(&format!("{tag}-home")),
            data: TempDir::new(&format!("{tag}-data")),
            root: TempDir::new(&format!("{tag}-root")),
            project: TempDir::new(&format!("{tag}-proj")),
        }
    }

    fn home(&self) -> String {
        self.home.path().display().to_string()
    }

    fn data(&self) -> String {
        self.data.path().display().to_string()
    }

    fn root(&self) -> String {
        self.root.path().display().to_string()
    }

    fn project(&self) -> String {
        self.project.path().display().to_string()
    }

    fn run(&self, sub: &str, tool: &str, tool_input: Value) -> Run {
        let payload = json!({
            "session_id": "it-tamper",
            "cwd": self.project(),
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": tool_input,
        });
        Invocation::new(&[sub])
            .plugin_data(self.data.path())
            .home(self.home.path())
            .env("CLAUDE_PLUGIN_ROOT", &self.root())
            .stdin(payload.to_string())
            .run()
    }

    /// Run the unconditional Bash hook (`gate-bash-secrets`) on `command`.
    fn bash(&self, command: &str) -> Run {
        self.run("gate-bash-secrets", "Bash", json!({ "command": command }))
    }

    /// Run the file-tool tripwire (`gate-tamper`) for `tool` with `tool_input`.
    fn file(&self, tool: &str, tool_input: Value) -> Run {
        self.run("gate-tamper", tool, tool_input)
    }

    /// `Write` of `path` (content is irrelevant to the tripwire).
    fn write(&self, path: &str) -> Run {
        self.file("Write", json!({ "file_path": path, "content": "{}" }))
    }
}

/// The emitted decision, or `None` when the gate had no opinion. No opinion is empty stdout;
/// the pre-H1 `defer` rendering is accepted as the same verdict.
fn verdict(run: &Run) -> Option<String> {
    if run.stdout.trim().is_empty() {
        return None;
    }
    let label = permission_decision(&run.json())
        .unwrap_or_else(|| panic!("no permissionDecision in {}", run.stdout));
    (label != "defer").then_some(label)
}

fn reason(run: &Run) -> String {
    run.json()["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

fn assert_deny(run: &Run, what: &str) {
    assert_eq!(
        verdict(run).as_deref(),
        Some("deny"),
        "expected deny for {what}\nstdout: {}\nstderr: {}",
        run.stdout,
        run.stderr
    );
}

fn assert_no_opinion(run: &Run, what: &str) {
    assert_eq!(
        verdict(run),
        None,
        "expected no opinion for {what}\nstdout: {}",
        run.stdout
    );
}

// ---------------------------------------------------------------------------------------
// Bash: binary + mutating subcommand
// ---------------------------------------------------------------------------------------

#[test]
fn bash_self_grant_denies() {
    let sb = Sandbox::new("tw-allow");
    let run = sb.bash("safe-ai-skill allow --scope transfer --for 24h");
    assert_deny(&run, "safe-ai-skill allow");
}

#[test]
fn bash_npx_scoped_package_allow_denies() {
    let sb = Sandbox::new("tw-npx");
    assert_deny(
        &sb.bash("npx @stbr/safe-ai-skill allow"),
        "npx @stbr/safe-ai-skill allow",
    );
}

#[test]
fn bash_env_prefixed_absolute_mode_denies() {
    let sb = Sandbox::new("tw-mode");
    assert_deny(
        &sb.bash("FOO=1 /x/safe-ai-skill mode autopilot"),
        "FOO=1 /x/safe-ai-skill mode autopilot",
    );
}

#[test]
fn bash_mutating_subcommands_deny() {
    let sb = Sandbox::new("tw-mut");
    for cmd in [
        "safe-ai-skill verify approve evil-skill",
        "safe-ai-skill verify trust evil-skill",
        "safe-ai-skill revoke",
        "safe-ai-skill confirm 1234-5678",
        "safe-ai-skill grant transfer",
        "bash -c 'safe-ai-skill allow --scope swap --for 1h'",
        "SAFE=1 env safe-ai-skill-darwin-arm64 mode autopilot",
        "npx -y @stbr/safe-ai-skill@1.0.1 'allow' --scope transfer",
        "python3 -c \"import subprocess; subprocess.run(['safe-ai-skill','allow','--scope','transfer'])\"",
        "node -e \"require('child_process').execSync('safe-ai-skill mode autopilot')\"",
        "cargo run -q -p safe-ai-skill -- allow --scope transfer --for 1h",
        "safe-ai-skill $(echo allow) --scope transfer",
        "Safe-AI-Skill ALLOW --scope transfer",
    ] {
        assert_deny(&sb.bash(cmd), cmd);
    }
}

#[test]
fn bash_env_subcommand_has_no_opinion() {
    // Placeholder for WS-C: the `env` subcommand is the sanctioned way to touch `.env`.
    let sb = Sandbox::new("tw-env");
    assert_no_opinion(
        &sb.bash("safe-ai-skill env keys .env"),
        "safe-ai-skill env keys .env",
    );
}

#[test]
fn bash_read_only_subcommands_have_no_opinion() {
    let sb = Sandbox::new("tw-ro");
    for cmd in [
        "safe-ai-skill status",
        "safe-ai-skill verify check ./skills/foo",
        "safe-ai-skill --version",
        "safe-ai-skill mode",
        "npx @stbr/safe-ai-skill status",
    ] {
        assert_no_opinion(&sb.bash(cmd), cmd);
    }
}

#[test]
fn bash_runs_plugin_binary_from_cache_path_read_only() {
    let sb = Sandbox::new("tw-cachebin");
    let bin = format!(
        "{}/.claude/plugins/cache/stbr/safe-ai-skill/1.0.1/bin/safe-ai-skill",
        sb.home()
    );
    assert_no_opinion(
        &sb.bash(&format!("{bin} env keys .env")),
        "cache binary env",
    );
    assert_no_opinion(
        &sb.bash(&format!("\"{bin}\" status")),
        "cache binary status",
    );
    assert_deny(&sb.bash(&format!("{bin} allow")), "cache binary allow");
}

// ---------------------------------------------------------------------------------------
// Bash: references to protected state
// ---------------------------------------------------------------------------------------

#[test]
fn bash_python_write_to_data_dir_denies() {
    let sb = Sandbox::new("tw-py");
    let cmd = format!(
        "python3 -c \"open('{}/.claude/plugins/data/safe-ai-skill-stbr/grants.json','w')\"",
        sb.home()
    );
    assert_deny(&sb.bash(&cmd), &cmd);
}

#[test]
fn bash_python_write_to_custom_plugin_data_denies() {
    let sb = Sandbox::new("tw-pydata");
    let cmd = format!(
        "python3 -c \"import json; json.dump({{}}, open('{}/grants.json','w'))\"",
        sb.data()
    );
    assert_deny(&sb.bash(&cmd), &cmd);
}

#[test]
fn bash_state_references_deny() {
    let sb = Sandbox::new("tw-paths");
    let home = sb.home();
    let root = sb.root();
    for cmd in [
        "cat \"$HOME/.Safe-AI-Skill/grants.json\"".to_string(),
        "echo '{}' > \"${HOME}\"/.claude/plugins/data/safe-ai-skill-stbr/mode.json".to_string(),
        "rm -f $CLAUDE_PLUGIN_DATA/spend.json".to_string(),
        "rm ~/.safe-ai-skill/lockfile.json".to_string(),
        "cp evil.json .safe-ai-skill/grants.json".to_string(),
        "cd .safe-ai-skill && echo '{}' > netcache.json".to_string(),
        "ln -s /tmp/x ~/.claude/plugins/data/safe-ai-skill-stbr".to_string(),
        format!("tail {home}/.claude/plugins/data/safe-ai-skill-stbr/audit.jsonl"),
        format!("cat {home}/.claude/plugins/data/x/../safe-ai-skill-stbr/grants.json"),
        "sed -i '' s/x/y/ ~/.claude/plugins/cache/stbr/safe-ai-skill/1.0.1/hooks/hooks.json"
            .to_string(),
        format!(
            "cp /tmp/evil {home}/.claude/plugins/cache/stbr/safe-ai-skill/1.0.1/bin/safe-ai-skill"
        ),
        format!("echo '{{}}' > {root}/hooks/hooks.json"),
    ] {
        assert_deny(&sb.bash(&cmd), &cmd);
    }
}

#[test]
fn bash_unrelated_commands_have_no_opinion() {
    let sb = Sandbox::new("tw-benign");
    for cmd in [
        "cargo test",
        "grep -rn grants.json crates/engine/src",
        "cat .safe-ai-skill/policy.yaml",
        "mkdir -p .safe-ai-skill",
        "ls ~/.claude/plugins/data",
        "git log -- plugins/safe-ai-skill/bin/safe-ai-skill",
        "git clone https://github.com/solanabr/safe-ai-skill",
    ] {
        assert_no_opinion(&sb.bash(cmd), cmd);
    }
}

#[test]
fn deny_reason_tells_model_the_user_must_run_it() {
    let sb = Sandbox::new("tw-reason");
    let grant = sb.bash("safe-ai-skill allow --scope transfer --for 24h");
    let write = sb.write(&format!("{}/.safe-ai-skill/grants.json", sb.home()));
    for run in [grant, write] {
        assert_deny(&run, "reason probe");
        let reason = reason(&run);
        assert!(
            reason.contains("user") && reason.contains("themselves"),
            "reason must tell the model the user has to run it: {reason}"
        );
    }
}

// ---------------------------------------------------------------------------------------
// Write|Edit|MultiEdit|NotebookEdit (gate-tamper)
// ---------------------------------------------------------------------------------------

#[test]
fn write_data_dir_grants_denies() {
    let sb = Sandbox::new("tw-write");
    let path = format!(
        "{}/.claude/plugins/data/safe-ai-skill-stbr/grants.json",
        sb.home()
    );
    assert_deny(&sb.write(&path), &path);
    assert_deny(
        &sb.write("~/.claude/plugins/data/safe-ai-skill-stbr/grants.json"),
        "tilde data dir",
    );
}

#[test]
fn file_tools_on_protected_state_deny() {
    let sb = Sandbox::new("tw-files");
    let home = sb.home();
    let cases = [
        (
            "Edit",
            json!({ "file_path": format!("{home}/.safe-ai-skill/mode.json"), "old_string": "a", "new_string": "b" }),
        ),
        (
            "MultiEdit",
            json!({ "file_path": format!("{}/.safe-ai-skill/spend.json", sb.project()), "edits": [] }),
        ),
        (
            "NotebookEdit",
            json!({ "notebook_path": format!("{}/x.ipynb", sb.data()), "new_source": "" }),
        ),
        (
            "Write",
            json!({ "file_path": format!("{}/hooks/hooks.json", sb.root()), "content": "{}" }),
        ),
        (
            "Write",
            json!({ "file_path": format!("{home}/.claude/plugins/cache/stbr/safe-ai-skill/1.0.1/policy/default.policy.yaml"), "content": "" }),
        ),
        (
            "Write",
            json!({ "file_path": format!("{}/.safe-ai-skill/audit.jsonl", sb.project()), "content": "" }),
        ),
        (
            "Write",
            json!({ "file_path": format!("{home}/.Claude/Plugins/Data/Safe-AI-Skill-stbr/Grants.json"), "content": "" }),
        ),
        (
            "Write",
            json!({ "file_path": "C:\\Users\\u\\.claude\\plugins\\data\\safe-ai-skill-stbr\\grants.json", "content": "" }),
        ),
        (
            "Write",
            json!({ "file_path": format!("{home}/.claude/plugins/data/x/../safe-ai-skill-stbr/mode.json"), "content": "" }),
        ),
    ];
    for (tool, input) in cases {
        let what = format!("{tool} {input}");
        assert_deny(&sb.file(tool, input), &what);
    }
}

#[test]
fn project_policy_and_ordinary_files_have_no_opinion() {
    let sb = Sandbox::new("tw-okfiles");
    for path in [
        format!("{}/.safe-ai-skill/policy.yaml", sb.project()),
        format!("{}/src/main.rs", sb.project()),
        format!("{}/README.md", sb.root()),
    ] {
        assert_no_opinion(&sb.write(&path), &path);
    }
}

#[cfg(unix)]
#[test]
fn write_through_symlink_into_data_dir_denies() {
    let sb = Sandbox::new("tw-link");
    let target = sb.home.join(".claude/plugins/data/safe-ai-skill-stbr");
    std::fs::create_dir_all(&target).unwrap();
    std::os::unix::fs::symlink(&target, sb.project.join("state")).unwrap();
    let path = format!("{}/state/grants.json", sb.project());
    assert_deny(&sb.write(&path), &path);
}

#[test]
fn tamper_deny_is_audited() {
    let sb = Sandbox::new("tw-audit");
    let run = sb.write(&format!("{}/.safe-ai-skill/grants.json", sb.home()));
    assert_deny(&run, "audit probe");
    let audit = std::fs::read_to_string(sb.data.join("audit.jsonl")).expect("audit.jsonl");
    assert!(
        audit.contains("\"tamper\"") && audit.contains("deny"),
        "tamper deny not audited: {audit}"
    );
}

// ---------------------------------------------------------------------------------------
// Hook wiring
// ---------------------------------------------------------------------------------------

#[test]
fn hooks_json_wires_tamper_gate_for_file_tools() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../plugins/safe-ai-skill/hooks/hooks.json");
    let hooks: Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("read hooks.json"))
            .expect("hooks.json is JSON");
    let entry = hooks["hooks"]["PreToolUse"]
        .as_array()
        .expect("PreToolUse array")
        .iter()
        .find(|e| e["matcher"] == "Write|Edit|MultiEdit|NotebookEdit")
        .expect("Write|Edit|MultiEdit|NotebookEdit matcher");
    let hook = &entry["hooks"][0];
    assert!(
        hook["command"]
            .as_str()
            .unwrap_or("")
            .ends_with("/bin/safe-ai-skill gate-tamper"),
        "{hook}"
    );
    assert_eq!(hook["timeout"], 10, "{hook}");
    assert_eq!(hook["onFailure"], "continue", "{hook}");
    assert!(
        hook.get("if").is_none(),
        "tripwire must be unconditional: {hook}"
    );
}
