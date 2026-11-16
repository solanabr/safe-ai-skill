//! The package publish gate (`gates::publish`): the other fixtures' benign commands stay silent,
//! and the gate reaches `gate-bash-secrets`, inner git commands and headless runs end to end.

mod common;

use std::path::Path;

use common::{decision_label, Invocation, TempDir};
use safe_ai_skill::gates::publish;
use safe_ai_skill::policy::tier::Tier;
use safe_ai_skill::policy::Policy;
use serde_json::Value;

/// Other writers' fixtures, read as a benign check: no case this gate fires on may want none.
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
            if let Some(v) =
                publish::decide(command, Path::new("."), &Policy::default(), Tier::High)
            {
                fired.push(format!("{}: {v:?}", case["id"]));
            }
        }
    }
    assert!(fired.is_empty(), "{}", fired.join("\n"));
}

/// `gate-bash-secrets` on `command` at `tier` (`None`: the default), optionally headless.
fn gate(command: &str, tier: Option<Tier>, headless: bool) -> String {
    let data = TempDir::new("publish-data");
    let home = TempDir::new("publish-home");
    let payload = serde_json::json!({
        "session_id": "it-publish",
        "cwd": home.path(),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command }
    })
    .to_string();
    let mut inv = Invocation::new(&["gate-bash-secrets"])
        .plugin_data(data.path())
        .home(home.path())
        .headless(headless)
        .stdin(payload);
    if let Some(tier) = tier {
        inv = inv.tier(tier);
    }
    decision_label(&inv.run())
}

#[test]
fn a_publish_asks_by_default_and_is_denied_headless_or_from_medium() {
    assert_eq!(gate("npm publish", None, false), "ask");
    assert_eq!(gate("cargo publish", None, true), "deny");
    assert_eq!(gate("npm publish", Some(Tier::Medium), false), "deny");
    assert_eq!(gate("cargo publish --dry-run", None, true), "");
}

#[test]
fn a_publish_git_runs_as_shell_code_is_seen() {
    assert_eq!(
        gate("git submodule foreach 'npm publish'", None, false),
        "ask"
    );
    assert_eq!(
        gate("git rebase --exec 'cargo publish' main", None, false),
        "ask"
    );
}
