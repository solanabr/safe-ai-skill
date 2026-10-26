//! W8 fixture: git and gh guards (`gates::gitguard`), headless conversion included.

use std::path::Path;
use std::time::Instant;

use safe_ai_skill::gates::gitguard;
use safe_ai_skill::headless;
use safe_ai_skill::io::Decision;
use safe_ai_skill::policy::tier::Tier;
use safe_ai_skill::policy::Policy;
use serde_json::Value;

const FIXTURE: &str = include_str!("fixtures/fc/w8-git.jsonl");

/// Other writers' fixtures, read as a benign check: no case this gate fires on may want none.
const GAP: &[&str] = &[
    include_str!("fixtures/gap/w1-tamper.jsonl"),
    include_str!("fixtures/gap/w2-exfil.jsonl"),
    include_str!("fixtures/gap/w3-envdump.jsonl"),
    include_str!("fixtures/gap/w4-fetchexec.jsonl"),
    include_str!("fixtures/gap/w5-onchain.jsonl"),
    include_str!("fixtures/gap/w6-mcp-encoded.jsonl"),
];

fn label(decision: &Decision) -> &'static str {
    match decision {
        Decision::Ask { .. } => "A",
        Decision::Deny { .. } => "D",
        _ => "-",
    }
}

fn run(command: &str, tier: Tier, headless_session: bool) -> Decision {
    let verdict = gitguard::decide(command, Path::new("."), &Policy::default(), tier);
    let decision = verdict.map(Decision::from).unwrap_or(Decision::Defer);
    headless::apply(decision, headless_session)
}

fn bash_cases(text: &str) -> Vec<Value> {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .filter(|c| c["tool"] == "Bash" && c["tool_input"]["command"].is_string())
        .collect()
}

#[test]
fn fixture_cases() {
    let mut failures = Vec::new();
    for case in bash_cases(FIXTURE) {
        let id = case["id"].as_str().unwrap();
        let command = case["tool_input"]["command"].as_str().unwrap();
        let tier = Tier::parse(case["tier"].as_str().unwrap()).unwrap();
        let got = run(command, tier, case["headless"].as_bool().unwrap());
        if label(&got) != case["want"].as_str().unwrap() {
            failures.push(format!("{id}: want {}, got {got:?}", case["want"]));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn reasons_are_one_sentence_ending_in_a_remedy() {
    for case in bash_cases(FIXTURE) {
        let command = case["tool_input"]["command"].as_str().unwrap();
        let tier = Tier::parse(case["tier"].as_str().unwrap()).unwrap();
        if let Decision::Ask { reason } | Decision::Deny { reason } = run(command, tier, false) {
            assert!(reason.ends_with('.'), "{reason}");
            assert_eq!(reason.matches(". ").count(), 0, "{reason}");
        }
    }
}

#[test]
fn other_fixtures_wanting_none_stay_silent() {
    let mut fired = Vec::new();
    for text in GAP {
        for case in bash_cases(text) {
            if case["want"] != "-" {
                continue;
            }
            let command = case["tool_input"]["command"].as_str().unwrap();
            let tier = Tier::parse(case["tier"].as_str().unwrap()).unwrap();
            let got = run(command, tier, case["headless"].as_bool().unwrap_or(false));
            if label(&got) != "-" {
                fired.push(format!("{}: {got:?}", case["id"]));
            }
        }
    }
    assert!(fired.is_empty(), "{}", fired.join("\n"));
}

/// Release micro-benchmark over this fixture and the gap fixtures:
/// `cargo test --release --test fc_w8-git -- --ignored --nocapture`.
#[test]
#[ignore]
fn bench() {
    let mut commands: Vec<String> = Vec::new();
    for text in std::iter::once(FIXTURE).chain(GAP.iter().copied()) {
        for case in bash_cases(text) {
            commands.push(case["tool_input"]["command"].as_str().unwrap().to_string());
        }
    }
    let policy = Policy::default();
    let iterations = 200;
    let start = Instant::now();
    for _ in 0..iterations {
        for command in &commands {
            std::hint::black_box(gitguard::decide(
                command,
                Path::new("."),
                &policy,
                Tier::High,
            ));
        }
    }
    let total = start.elapsed();
    let calls = iterations * commands.len();
    let silent = commands
        .iter()
        .filter(|c| !gitguard::may_concern(c))
        .count();
    println!(
        "bench: {} payloads ({silent} prefiltered out) x {iterations} = {calls} calls in \
         {total:?} ({:.2} us/call)",
        commands.len(),
        total.as_secs_f64() * 1e6 / calls as f64
    );
}
