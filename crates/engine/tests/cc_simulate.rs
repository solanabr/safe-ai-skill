//! The 1.1.0 live checks, run through `scripts/cc-simulate` (an offline model of Claude Code's
//! hook runtime, built from the Claude Code docs): the plugin's real hooks.json, the real shim
//! and the binary under test, in a throwaway HOME, `CLAUDE_CONFIG_DIR` and project.
//!
//! In a `test-hooks` build the throwaway data dir is trusted, so confirmed relaxations take
//! effect and the trust-dependent items run; otherwise they report UNPROVABLE. Set
//! `CCSIM_KIT_DIR` to a solana-ai-kit checkout to add the side-by-side kit rows.
//! Whether the engine can read the process table is the machine's: in a sandbox that denies
//! `ps` the simulated sessions are the "ancestry unknown" case (only requests made inside a
//! session confirm), otherwise the interactive case, and check S forces the other one through
//! the test-hooks switch.
//! Unix only (the shim is POSIX sh); needs python3 and git, skips without them.
#![cfg(unix)]

mod common;

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn available(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn run_script(script: &str, extra: &[String]) -> (bool, String) {
    let out = Command::new("python3")
        .arg("-I")
        .arg("-B")
        .arg(repo_root().join("scripts/cc-simulate").join(script))
        .args(extra)
        .output()
        .expect("run python3");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

#[test]
fn simulator_models_the_documented_hook_contract() {
    if !available("python3") || !available("git") {
        eprintln!("skip: python3 or git missing");
        return;
    }
    let (ok, text) = run_script("selftest.py", &[]);
    assert!(ok, "ccsim selftest failed:\n{text}");
}

#[test]
fn live_checks_pass_in_the_simulated_session() {
    if !available("python3") || !available("git") {
        eprintln!("skip: python3 or git missing");
        return;
    }
    let mut args = vec!["--engine".to_string(), common::bin().to_string()];
    if common::TEST_HOOKS {
        args.push("--trusted".to_string());
    }
    if let Ok(kit) = std::env::var("CCSIM_KIT_DIR") {
        args.push("--kit".to_string());
        args.push(kit);
    }
    let (ok, text) = run_script("live_checks.py", &args);
    assert!(ok, "live checks failed in the simulator:\n{text}");
    let summary = text.lines().last().unwrap_or_default();
    assert!(summary.contains("PASS"), "no check passed: {summary}");
}
