//! `adapters/codex/safe-ai-skill-codex` (experimental, issue #23): the POSIX wrapper the Codex
//! hooks template runs. Codex runs the tool call when a hook exits with anything but 0 or 2,
//! is killed, or prints what it cannot parse, so the wrapper must turn every engine failure
//! into a deny printed with exit 0. Fake engines stand in for each failure; the real engine
//! checks the pass-through.

#![cfg(unix)]

mod common;

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use common::TempDir;
use serde_json::json;

const WRAPPER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../adapters/codex/safe-ai-skill-codex"
);

struct Out {
    code: Option<i32>,
    stdout: String,
}

/// A dir holding a copy of the wrapper and, when given, an engine next to it.
fn install(tag: &str, engine: Option<&str>) -> (TempDir, PathBuf) {
    let dir = TempDir::new(tag);
    let wrapper = dir.join("safe-ai-skill-codex");
    std::fs::copy(WRAPPER, &wrapper).unwrap();
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
    if let Some(body) = engine {
        let path = dir.join("safe-ai-skill");
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    (dir, wrapper)
}

fn run(wrapper: &Path, gate: &str, stdin: &str, env: &[(&str, &str)]) -> Out {
    let empty = TempDir::new("wrapper-path");
    let mut cmd = Command::new("/bin/sh");
    cmd.arg(wrapper)
        .arg(gate)
        .env_clear()
        .env("PATH", empty.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap();
    let _ = child.stdin.take().unwrap().write_all(stdin.as_bytes());
    let out = child.wait_with_output().unwrap();
    Out {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
    }
}

fn assert_deny(out: &Out, what: &str) {
    assert_eq!(out.code, Some(0), "{what}");
    let v: serde_json::Value = serde_json::from_str(&out.stdout)
        .unwrap_or_else(|e| panic!("{what}: not JSON ({e}): {}", out.stdout));
    assert_eq!(
        v["hookSpecificOutput"]["permissionDecision"], "deny",
        "{what}: {}",
        out.stdout
    );
    assert!(v["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .is_some_and(|r| !r.is_empty()));
}

const DENY_JSON: &str = r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"x"}}"#;

#[test]
fn engine_failures_become_a_deny_with_exit_0() {
    for (tag, body) in [
        ("abort", format!("#!/bin/sh\nprintf '%s' '{DENY_JSON}'\nkill -ABRT $$\n")),
        ("exit134", format!("#!/bin/sh\nprintf '%s' '{DENY_JSON}'\nexit 134\n")),
        ("exit1", "#!/bin/sh\nexit 1\n".to_string()),
        ("exit2", "#!/bin/sh\necho no >&2\nexit 2\n".to_string()),
        ("usage", "#!/bin/sh\nexit 3\n".to_string()),
        ("garbage", "#!/bin/sh\necho 'not json'\n".to_string()),
        (
            "ask",
            "#!/bin/sh\nprintf '%s' '{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"ask\",\"permissionDecisionReason\":\"r\"}}'\n"
                .to_string(),
        ),
        (
            "allow",
            "#!/bin/sh\nprintf '%s' '{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"allow\"}}'\n"
                .to_string(),
        ),
        ("notexec", "this is not a script".to_string()),
        (
            "two-lines",
            format!("#!/bin/sh\nprintf '%s\\n%s' '{DENY_JSON}' '{{\"hookSpecificOutput\":{{\"permissionDecision\":\"allow\"}}}}'\n"),
        ),
    ] {
        let (_dir, wrapper) = install(&format!("wrapper-{tag}"), Some(&body));
        assert_deny(&run(&wrapper, "gate-bash", "{}", &[]), tag);
    }
}

#[test]
fn a_missing_engine_denies() {
    let (_dir, wrapper) = install("wrapper-missing", None);
    assert_deny(&run(&wrapper, "gate-mcp", "{}", &[]), "missing");
}

#[test]
fn an_unknown_gate_denies() {
    let (_dir, wrapper) = install("wrapper-gate", Some("#!/bin/sh\nexit 0\n"));
    for gate in ["", "gate-read", "redact", "gate-bash; rm -rf /"] {
        assert_deny(&run(&wrapper, gate, "{}", &[]), gate);
    }
}

#[test]
fn silence_and_deny_pass_through() {
    let (_d1, quiet) = install("wrapper-quiet", Some("#!/bin/sh\ncat >/dev/null\nexit 0\n"));
    let out = run(&quiet, "gate-bash", "{}", &[]);
    assert_eq!((out.code, out.stdout.as_str()), (Some(0), ""));
    let (_d2, denies) = install(
        "wrapper-denies",
        Some(&format!("#!/bin/sh\nprintf '%s' '{DENY_JSON}'\n")),
    );
    let out = run(&denies, "gate-bash", "{}", &[]);
    assert_eq!((out.code, out.stdout.as_str()), (Some(0), DENY_JSON));
}

/// The wrapper finds the engine on `PATH` when none sits next to it, and the real engine's
/// answers come through: a mainnet deploy denies, `ls` is silent.
#[test]
fn the_real_engine_through_the_wrapper() {
    let (dir, wrapper) = install("wrapper-real", None);
    let bin_dir = TempDir::new("wrapper-real-bin");
    std::os::unix::fs::symlink(common::bin(), bin_dir.join("safe-ai-skill")).unwrap();
    let home = TempDir::new("wrapper-real-home");
    let proj = TempDir::new("wrapper-real-proj");
    let data = TempDir::new("wrapper-real-data");
    let payload = |command: &str| {
        json!({"cwd": proj.path(), "hook_event_name": "PreToolUse", "tool_name": "Bash",
               "tool_input": {"command": command}})
        .to_string()
    };
    let path = bin_dir.path().to_str().unwrap().to_string();
    let env = [
        ("PATH", path.as_str()),
        ("HOME", home.path().to_str().unwrap()),
        ("CLAUDE_PLUGIN_DATA", data.path().to_str().unwrap()),
    ];
    let deploy = run(
        &wrapper,
        "gate-bash",
        &payload("solana program deploy x.so --url mainnet-beta"),
        &env,
    );
    assert_deny(&deploy, "mainnet deploy");
    let ls = run(&wrapper, "gate-bash", &payload("ls"), &env);
    assert_eq!((ls.code, ls.stdout.as_str()), (Some(0), ""));
    drop(dir);
}

/// With `test-hooks`, a forced engine panic still reaches Codex as a deny with exit 0.
#[cfg(feature = "test-hooks")]
#[test]
fn an_engine_panic_through_the_wrapper_denies() {
    let (_dir, wrapper) = install("wrapper-panic", None);
    let bin_dir = TempDir::new("wrapper-panic-bin");
    std::os::unix::fs::symlink(common::bin(), bin_dir.join("safe-ai-skill")).unwrap();
    let home = TempDir::new("wrapper-panic-home");
    let path = bin_dir.path().to_str().unwrap().to_string();
    let out = run(
        &wrapper,
        "gate-tamper",
        r#"{"hook_event_name":"PreToolUse","tool_name":"apply_patch","tool_input":{"command":"x"}}"#,
        &[
            ("PATH", path.as_str()),
            ("HOME", home.path().to_str().unwrap()),
            ("SAFE_AI_SKILL_TEST_PANIC", "1"),
        ],
    );
    assert_deny(&out, "panic");
}
