//! A gate that panics still answers `ask` (fix round 2). Release builds abort on panic, so a
//! panic hook writes the answer before the abort. Needs the `test-hooks` feature:
//! `cargo test --features test-hooks --test panic_hook` (add `--release` for the abort path).
#![cfg(feature = "test-hooks")]

mod common;

use common::{permission_decision, Invocation, TempDir};

#[test]
fn panicking_gates_answer_ask() {
    for sub in [
        "gate-bash",
        "gate-bash-secrets",
        "gate-read",
        "gate-mcp",
        "gate-skill",
    ] {
        let data = TempDir::new("panic-data");
        let home = TempDir::new("panic-home");
        let payload = serde_json::json!({
            "session_id": "it-panic",
            "cwd": home.path().to_str().unwrap(),
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": "ls" }
        })
        .to_string();
        let run = Invocation::new(&[sub])
            .plugin_data(data.path())
            .home(home.path())
            .env("SAFE_AI_SKILL_TEST_PANIC", "1")
            .stdin(payload)
            .run();
        // Unwinding builds exit 0; `panic = "abort"` builds die by SIGABRT. Either way the
        // single line on stdout is the ask.
        let line = run.stdout.lines().next().unwrap_or_default();
        let json: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("{sub}: {e}: {:?} {}", run.stdout, run.stderr));
        assert_eq!(permission_decision(&json).as_deref(), Some("ask"), "{sub}");
        assert_eq!(run.stdout.lines().count(), 1, "{sub}: {}", run.stdout);
        assert!(run.stderr.contains("test panic"), "{sub}: {}", run.stderr);
    }
}
