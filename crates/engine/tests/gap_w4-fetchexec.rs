//! W4 fixture: download-and-run gate (`gates::fetchexec`), headless conversion included.

use std::path::{Path, PathBuf};
use std::time::Instant;

use safe_ai_skill::gates::fetchexec;
use safe_ai_skill::headless;
use safe_ai_skill::io::Decision;
use safe_ai_skill::policy::tier::Tier;
use safe_ai_skill::policy::Policy;
use serde_json::Value;

const FIXTURE: &str = include_str!("fixtures/gap/w4-fetchexec.jsonl");

fn case_dir(id: &str, files: Option<&Value>) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("gap-w4-{}-{id}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    // A `.git` marker ends the manifest search at the case dir.
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    if let Some(files) = files.and_then(Value::as_object) {
        for (name, body) in files {
            std::fs::write(dir.join(name), body.as_str().unwrap()).unwrap();
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

fn run(command: &str, cwd: &Path, tier: Tier, headless_session: bool) -> Decision {
    let verdict = fetchexec::decide(command, cwd, &Policy::default(), tier);
    let decision = verdict.map(Decision::from).unwrap_or(Decision::Defer);
    headless::apply(decision, headless_session)
}

#[test]
fn fixture_cases() {
    let mut failures = Vec::new();
    for line in FIXTURE.lines().filter(|l| !l.trim().is_empty()) {
        let case: Value = serde_json::from_str(line).unwrap();
        let id = case["id"].as_str().unwrap();
        let command = case["tool_input"]["command"].as_str().unwrap();
        let tier = Tier::parse(case["tier"].as_str().unwrap()).unwrap();
        let headless_session = case["headless"].as_bool().unwrap();
        let want = case["want"].as_str().unwrap();
        let dir = case_dir(id, case.get("cwd_files"));
        let got = run(command, &dir, tier, headless_session);
        let _ = std::fs::remove_dir_all(&dir);
        if label(&got) != want {
            failures.push(format!("{id}: want {want}, got {got:?}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Benign-set check and micro-benchmark over the difftest payloads:
/// `GAP_RESULTS=…/results2.json cargo test --release --test gap_w4-fetchexec -- --ignored`.
#[test]
#[ignore]
fn difftest_payloads() {
    let Ok(path) = std::env::var("GAP_RESULTS") else {
        return;
    };
    let rows: Vec<Value> = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let dir = case_dir("bench", None);
    let commands: Vec<(String, String, String)> = rows
        .iter()
        .filter(|r| r["case"]["tool"] == "Bash")
        .map(|r| {
            let c = &r["case"];
            (
                c["id"].as_str().unwrap().to_string(),
                c["input"]["command"].as_str().unwrap().to_string(),
                c["want"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    let policy = Policy::default();
    for (id, command, want) in &commands {
        let v = fetchexec::decide(command, &dir, &policy, Tier::Relaxed);
        println!(
            "{id}\twant={want}\tgot={}",
            v.as_ref().map_or("none", |v| v.label())
        );
    }
    let iterations = 200;
    let start = Instant::now();
    for _ in 0..iterations {
        for (_, command, _) in &commands {
            std::hint::black_box(fetchexec::decide(command, &dir, &policy, Tier::Relaxed));
        }
    }
    let total = start.elapsed();
    let calls = iterations * commands.len();
    println!(
        "bench: {} payloads x {iterations} = {calls} calls in {total:?} ({:.2} us/call)",
        commands.len(),
        total.as_secs_f64() * 1e6 / calls as f64
    );
    let _ = std::fs::remove_dir_all(&dir);
}
