//! W5b (full coverage, usability floor): `anchor test` on a positively identified
//! localnet/devnet/testnet gets no opinion; mainnet and an unidentified cluster keep the ask.
//!
//! The fixture `fixtures/fc/w5b-onchain.jsonl` runs through the real `gate-bash` binary with a
//! fake home, an isolated data dir, a stub `solana` printing the CLI config's RPC URL, and the
//! row's `proj/` files (`Anchor.toml`) in the project dir.

mod common;

use common::{decision_label, Invocation, TempDir, Tier};
use serde_json::{json, Value};

fn fixture() -> Vec<Value> {
    include_str!("fixtures/fc/w5b-onchain.jsonl")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("fixture line is JSON"))
        .collect()
}

fn tier_of(word: &str) -> Tier {
    match word {
        "relaxed" => Tier::Relaxed,
        "medium" => Tier::Medium,
        "high" => Tier::High,
        other => panic!("fixture tier {other} is not supported through the binary"),
    }
}

fn run_case(case: &Value) -> String {
    let home = TempDir::new("w5b-home");
    let proj = TempDir::new("w5b-proj");
    let data = TempDir::new("w5b-data");
    let bin = TempDir::new("w5b-path");
    let files = case["cwd_files"].as_object().cloned().unwrap_or_default();
    for (rel, body) in &files {
        if let Some(rel) = rel.strip_prefix("proj/") {
            std::fs::write(proj.join(rel), body.as_str().unwrap_or_default()).unwrap();
        }
    }
    let url = files
        .get("~/.config/solana/cli/config.yml")
        .and_then(Value::as_str)
        .and_then(|t| {
            t.lines()
                .find_map(|l| l.trim().strip_prefix("json_rpc_url:"))
                .map(|u| u.trim().to_string())
        });
    let path = match url {
        Some(url) => {
            let stub = bin.join("solana");
            std::fs::write(
                &stub,
                format!("#!/bin/sh\necho \"Config File: x\"\necho \"RPC URL: {url}\"\n"),
            )
            .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            format!("{}:/usr/bin:/bin", bin.path().display())
        }
        None => bin.path().display().to_string(),
    };
    let payload = json!({
        "session_id": "it-fc-w5b",
        "hook_event_name": "PreToolUse",
        "tool_name": case["tool"],
        "cwd": proj.path(),
        "tool_input": case["tool_input"],
    });
    let run = Invocation::new(&["gate-bash"])
        .plugin_data(data.path())
        .home(home.path())
        .cwd(proj.path())
        .env("PATH", &path)
        .tier(tier_of(case["tier"].as_str().unwrap_or("relaxed")))
        .headless(case["headless"].as_bool().unwrap_or(false))
        .stdin(payload.to_string())
        .run();
    decision_label(&run)
}

#[cfg(unix)]
#[test]
fn fixture_cases_reach_their_verdict() {
    let mut failures = Vec::new();
    for case in fixture() {
        let want = case["want"].as_str().unwrap_or("?");
        let got = run_case(&case);
        if got != want {
            failures.push(format!(
                "{}: want {want:?}, got {got:?}: {}",
                case["id"], case["tool_input"]["command"]
            ));
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}
