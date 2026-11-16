//! The process-kill guard (`gates::kill`): the other fixtures' benign commands stay silent, and
//! the guard reaches `gate-bash-secrets` and inner git commands end to end.

mod common;

use std::path::Path;

use common::{decision_label, Invocation, TempDir};
use safe_ai_skill::gates::kill;
use safe_ai_skill::policy::tier::Tier;
use safe_ai_skill::policy::Policy;
use serde_json::Value;

/// Other writers' fixtures, read as a benign check: no case this guard fires on may want none.
const OTHERS: &[&str] = &[
    include_str!("fixtures/gap/w1-tamper.jsonl"),
    include_str!("fixtures/gap/w2-exfil.jsonl"),
    include_str!("fixtures/gap/w3-envdump.jsonl"),
    include_str!("fixtures/gap/w4-fetchexec.jsonl"),
    include_str!("fixtures/gap/w5-onchain.jsonl"),
    include_str!("fixtures/gap/w6-mcp-encoded.jsonl"),
    include_str!("fixtures/fc/w4b-fetchexec.jsonl"),
    include_str!("fixtures/fc/w5b-onchain.jsonl"),
    include_str!("fixtures/fc/w8-git.jsonl"),
    include_str!("fixtures/fc/w10-tamper2.jsonl"),
    include_str!("fixtures/fc/w14-reads.jsonl"),
    include_str!("fixtures/ex/g9-containers.jsonl"),
];

fn bash_cases(text: &str) -> Vec<Value> {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .filter(|c| c["tool"] == "Bash" && c["tool_input"]["command"].is_string())
        .collect()
}

#[test]
fn other_fixtures_wanting_none_stay_silent() {
    let mut fired = Vec::new();
    for text in OTHERS {
        for case in bash_cases(text) {
            if case["want"] != "-" {
                continue;
            }
            let command = case["tool_input"]["command"].as_str().unwrap();
            if let Some(v) = kill::decide(command, Path::new("."), &Policy::default(), Tier::High) {
                fired.push(format!("{}: {v:?}", case["id"]));
            }
        }
    }
    assert!(fired.is_empty(), "{}", fired.join("\n"));
}

/// `gate-bash-secrets` on `command` at the default tier.
fn gate(command: &str) -> String {
    let data = TempDir::new("kill-data");
    let home = TempDir::new("kill-home");
    let payload = serde_json::json!({
        "session_id": "it-kill",
        "cwd": home.path(),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command }
    })
    .to_string();
    let run = Invocation::new(&["gate-bash-secrets"])
        .plugin_data(data.path())
        .home(home.path())
        .stdin(payload)
        .run();
    decision_label(&run)
}

#[test]
fn a_broad_kill_is_denied_end_to_end() {
    assert_eq!(gate("kill -9 -1"), "deny");
    assert_eq!(gate("pkill -f claude"), "deny");
    assert_eq!(gate("git submodule foreach 'killall -u me'"), "deny");
    assert_eq!(gate("pkill -f vitest"), "");
}
