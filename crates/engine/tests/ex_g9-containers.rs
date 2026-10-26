//! G9 fixture: container privilege guard (`gates::containers`), headless conversion included.

use std::path::PathBuf;
use std::time::Instant;

use safe_ai_skill::gates::containers;
use safe_ai_skill::headless;
use safe_ai_skill::io::Decision;
use safe_ai_skill::policy::tier::Tier;
use safe_ai_skill::policy::Policy;
use serde_json::Value;

const FIXTURE: &str = include_str!("fixtures/ex/g9-containers.jsonl");

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
];

fn case_dir(id: &str, files: Option<&Value>) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ex-g9-{}-{id}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    if let Some(files) = files.and_then(Value::as_object) {
        for (name, body) in files {
            let path = dir.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, body.as_str().unwrap()).unwrap();
        }
    }
    dir
}

fn label(decision: &Decision) -> &'static str {
    match decision {
        Decision::Ask { .. } => "A",
        Decision::Deny { .. } => "D",
        _ => "-",
    }
}

fn run(case: &Value, headless_session: bool) -> Decision {
    let id = case["id"].as_str().unwrap();
    let command = case["tool_input"]["command"].as_str().unwrap();
    let tier = Tier::parse(case["tier"].as_str().unwrap()).unwrap();
    let dir = case_dir(id, case.get("cwd_files"));
    let verdict = containers::decide(command, &dir, &Policy::default(), tier);
    let _ = std::fs::remove_dir_all(&dir);
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
        let got = run(&case, case["headless"].as_bool().unwrap());
        if label(&got) != case["want"].as_str().unwrap() {
            failures.push(format!(
                "{}: want {}, got {got:?}",
                case["id"], case["want"]
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn reasons_are_one_sentence_ending_in_a_remedy() {
    for case in bash_cases(FIXTURE) {
        if let Decision::Ask { reason } | Decision::Deny { reason } = run(&case, false) {
            assert!(reason.ends_with('.'), "{reason}");
            assert_eq!(reason.matches(". ").count(), 0, "{reason}");
        }
    }
}

#[test]
fn other_fixtures_wanting_none_stay_silent() {
    let mut fired = Vec::new();
    for text in OTHERS {
        for case in bash_cases(text) {
            if case["want"] != "-" {
                continue;
            }
            let got = run(&case, case["headless"].as_bool().unwrap_or(false));
            if label(&got) != "-" {
                fired.push(format!("{}: {got:?}", case["id"]));
            }
        }
    }
    assert!(fired.is_empty(), "{}", fired.join("\n"));
}

/// Release micro-benchmark over this fixture and the other fixtures:
/// `cargo test --release --test ex_g9-containers -- --ignored --nocapture`.
#[test]
#[ignore]
fn bench() {
    let mut commands: Vec<String> = Vec::new();
    for text in std::iter::once(FIXTURE).chain(OTHERS.iter().copied()) {
        for case in bash_cases(text) {
            commands.push(case["tool_input"]["command"].as_str().unwrap().to_string());
        }
    }
    let dir = std::env::temp_dir();
    let policy = Policy::default();
    let iterations = 200;
    let start = Instant::now();
    for _ in 0..iterations {
        for command in &commands {
            std::hint::black_box(containers::decide(command, &dir, &policy, Tier::High));
        }
    }
    let total = start.elapsed();
    let calls = iterations * commands.len();
    let silent = commands
        .iter()
        .filter(|c| !containers::may_concern(c))
        .count();
    println!(
        "bench: {} payloads ({silent} prefiltered out) x {iterations} = {calls} calls in \
         {total:?} ({:.2} us/call)",
        commands.len(),
        total.as_secs_f64() * 1e6 / calls as f64
    );
}
