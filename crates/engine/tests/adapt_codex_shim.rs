//! Codex hooks run `safe-ai-skill adapt codex …` through the plugin shim
//! (`plugins/safe-ai-skill/bin/safe-ai-skill`), the one entry point for every client: it finds
//! and checks the engine, and turns any engine failure into Codex's deny (or, for the opt-in
//! redaction, a block) with exit 0. These tests install the real shim beside the engine under
//! test, stamped as a release would, and run it the way Codex does (`sh -c "<command>"`, the
//! shim found on `PATH`). The fake-engine failure matrix lives in `scripts/test-shim.sh`.

#![cfg(unix)]

mod common;

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use common::TempDir;
use serde_json::{json, Value};

const SHIM: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../plugins/safe-ai-skill/bin/safe-ai-skill"
);
const STAMP: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../scripts/stamp-shim.sh");

/// The shim's name for this machine's prebuilt, when the shim supports it.
fn platform() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Some("darwin-arm64"),
        ("macos", "x86_64") => Some("darwin-x64"),
        ("linux", "x86_64") => Some("linux-x64"),
        ("linux", "aarch64") => Some("linux-arm64"),
        _ => None,
    }
}

struct Layout {
    _dir: TempDir,
    bin: PathBuf,
    home: TempDir,
    proj: TempDir,
}

/// A bin dir holding the shim and the engine under test as its prebuilt, stamped.
fn install(tag: &str) -> Option<Layout> {
    let plat = platform()?;
    let dir = TempDir::new(tag);
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::copy(SHIM, bin.join("safe-ai-skill")).unwrap();
    std::fs::copy(common::bin(), bin.join(format!("safe-ai-skill-{plat}"))).unwrap();
    for f in ["safe-ai-skill".to_string(), format!("safe-ai-skill-{plat}")] {
        std::fs::set_permissions(bin.join(f), std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let ok = Command::new("/bin/sh")
        .arg(STAMP)
        .arg(&bin)
        .stdout(Stdio::null())
        .status()
        .unwrap()
        .success();
    assert!(ok, "stamp-shim.sh failed");
    Some(Layout {
        _dir: dir,
        bin,
        home: TempDir::new(&format!("{tag}-home")),
        proj: TempDir::new(&format!("{tag}-proj")),
    })
}

struct Out {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Out {
    fn json(&self) -> Value {
        serde_json::from_str(self.stdout.trim())
            .unwrap_or_else(|e| panic!("not JSON ({e}): {}\n{}", self.stdout, self.stderr))
    }
}

impl Layout {
    fn payload(&self, event: &str, extra: Value) -> String {
        let mut v = json!({
            "session_id": "019a0000-0000-7000-8000-000000000000",
            "transcript_path": null,
            "cwd": self.proj.path(),
            "hook_event_name": event,
            "model": "gpt-5-codex",
            "permission_mode": "default",
            "turn_id": "turn-1",
        });
        if let (Some(v), Some(extra)) = (v.as_object_mut(), extra.as_object()) {
            v.extend(extra.clone());
        }
        v.to_string()
    }

    /// Run `command` as Codex does: through a shell, with the bin dir on `PATH`.
    fn sh(&self, command: &str, stdin: &str, env: &[(&str, &str)]) -> Out {
        let path = format!("{}:/usr/bin:/bin", self.bin.display());
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg(command)
            .current_dir(self.proj.path())
            .env_clear()
            .env("PATH", path)
            .env("HOME", self.home.path())
            .env("CLAUDE_CONFIG_DIR", self.home.join(".claude"))
            .env(
                "SAFE_AI_SKILL_DATA",
                common::standalone_data(self.home.path()),
            )
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
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    fn bash(&self, gate: &str, command: &str) -> Out {
        let body = self.payload(
            "PreToolUse",
            json!({"tool_name": "Bash", "tool_use_id": "c1", "tool_input": {"command": command}}),
        );
        self.sh(&format!("safe-ai-skill adapt codex {gate}"), &body, &[])
    }
}

fn deny_reason(out: &Out) -> String {
    assert_eq!(out.code, Some(0), "{}", out.stderr);
    let v = out.json();
    assert_eq!(
        v["hookSpecificOutput"]["permissionDecision"], "deny",
        "{}",
        out.stdout
    );
    v["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

#[test]
fn the_template_commands_run_through_the_shim() {
    let Some(l) = install("shim-template") else {
        return;
    };
    let deploy = l.bash("gate-bash", "solana program deploy x.so --url mainnet-beta");
    assert!(
        deny_reason(&deploy).ends_with(safe_ai_skill::adapt::CODEX_ASK_SUFFIX),
        "{}",
        deploy.stdout
    );
    let benign = l.bash("gate-bash", "ls -la");
    assert_eq!(
        (benign.code, benign.stdout.as_str()),
        (Some(0), ""),
        "{}",
        benign.stderr
    );
    let shell = l.bash("gate-bash-secrets", "cat | bash");
    assert!(deny_reason(&shell).contains("write_stdin"));
}

#[test]
fn a_usage_error_reaches_codex_as_a_deny() {
    let Some(l) = install("shim-usage") else {
        return;
    };
    let body = l.payload(
        "PreToolUse",
        json!({"tool_name": "Bash", "tool_input": {"command": "ls"}}),
    );
    let out = l.sh("safe-ai-skill adapt codex gate-read", &body, &[]);
    assert!(deny_reason(&out).contains("exit 3"), "{}", out.stdout);
}

#[test]
fn a_tampered_engine_never_runs_and_denies() {
    let Some(l) = install("shim-tamper") else {
        return;
    };
    let plat = platform().unwrap();
    let engine = l.bin.join(format!("safe-ai-skill-{plat}"));
    std::fs::OpenOptions::new()
        .append(true)
        .open(&engine)
        .unwrap()
        .write_all(b"\0")
        .unwrap();
    let out = l.bash("gate-bash", "ls");
    assert!(deny_reason(&out).contains("sha256"), "{}", out.stdout);
}

#[test]
fn a_missing_engine_denies() {
    let Some(l) = install("shim-missing") else {
        return;
    };
    std::fs::remove_file(l.bin.join(format!("safe-ai-skill-{}", platform().unwrap()))).unwrap();
    let out = l.bash("gate-mcp", "ls");
    assert!(
        deny_reason(&out).contains("no engine binary"),
        "{}",
        out.stdout
    );
}

#[test]
fn session_start_answers_in_the_codex_shape() {
    let Some(l) = install("shim-session") else {
        return;
    };
    let body = l.payload("SessionStart", json!({"source": "startup"}));
    let out = l.sh("safe-ai-skill adapt codex session-start", &body, &[]);
    assert_eq!(out.code, Some(0), "{}", out.stderr);
    if out.stdout.trim().is_empty() {
        return;
    }
    let v = out.json();
    let obj = v.as_object().unwrap();
    assert!(
        obj.keys()
            .all(|k| k == "systemMessage" || k == "hookSpecificOutput"),
        "Codex rejects unknown fields: {}",
        out.stdout
    );
    if let Some(h) = obj.get("hookSpecificOutput") {
        let h = h.as_object().unwrap();
        assert_eq!(h["hookEventName"], "SessionStart");
        assert!(h
            .keys()
            .all(|k| k == "hookEventName" || k == "additionalContext"));
    }
    assert!(
        !out.stdout.contains("Claude Code sandbox"),
        "{}",
        out.stdout
    );
}

#[test]
fn opt_in_redaction_blocks_with_the_redacted_text() {
    let Some(l) = install("shim-redact") else {
        return;
    };
    let secret = "AKIAIOSFODNN7EXAMPLE";
    let body = l.payload(
        "PostToolUse",
        json!({"tool_name": "Bash", "tool_use_id": "c1", "tool_input": {"command": "cat creds"},
               "tool_response": format!("key: {secret}\nok\n")}),
    );
    let out = l.sh(
        "safe-ai-skill adapt codex redact --block-with-redaction",
        &body,
        &[],
    );
    assert_eq!(out.code, Some(0), "{}", out.stderr);
    let v = out.json();
    assert_eq!(v["decision"], "block");
    let reason = v["reason"].as_str().unwrap();
    assert!(
        reason.starts_with(safe_ai_skill::adapt::codex::REDACTED_PREFIX),
        "{reason}"
    );
    assert!(
        reason.contains("ok") && !reason.contains(secret),
        "{reason}"
    );
    let clean = l.payload(
        "PostToolUse",
        json!({"tool_name": "Bash", "tool_input": {"command": "ls"}, "tool_response": "a\nb\n"}),
    );
    let out = l.sh(
        "safe-ai-skill adapt codex redact --block-with-redaction",
        &clean,
        &[],
    );
    assert_eq!(
        (out.code, out.stdout.as_str()),
        (Some(0), ""),
        "{}",
        out.stderr
    );
}

#[cfg(feature = "test-hooks")]
#[test]
fn a_panicking_engine_still_denies_through_the_shim() {
    let Some(l) = install("shim-panic") else {
        return;
    };
    let body = l.payload(
        "PreToolUse",
        json!({"tool_name": "Bash", "tool_input": {"command": "ls"}}),
    );
    let out = l.sh(
        "safe-ai-skill adapt codex gate-bash",
        &body,
        &[("SAFE_AI_SKILL_TEST_PANIC", "1")],
    );
    deny_reason(&out);
}

/// The shim keeps `$0`'s directory: a copy reached through a symlinked dir still finds its
/// engine.
#[test]
fn the_shim_is_found_by_path_lookup() {
    let Some(l) = install("shim-path") else {
        return;
    };
    let link = l.home.join("bin-link");
    std::os::unix::fs::symlink(&l.bin, &link).unwrap();
    let body = l.payload(
        "PreToolUse",
        json!({"tool_name": "Bash", "tool_input": {"command": "bash"}}),
    );
    let out = l.sh(
        &format!(
            "PATH={}:/usr/bin:/bin safe-ai-skill adapt codex gate-bash-secrets",
            common::sh_path(Path::new(&link))
        ),
        &body,
        &[],
    );
    deny_reason(&out);
}
