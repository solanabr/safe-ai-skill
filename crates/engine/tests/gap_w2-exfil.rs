//! Gap closure W2 (#19): the exfil tripwire on Bash, MCP and WebFetch payloads.
//!
//! `fixtures/gap/w2-exfil.jsonl` holds one case per line; `want` is `D`, `A` or `-`.
//! `GAP_CORPUS=<jsonl>` runs the ignored corpus check and benchmark over a differential corpus.

use std::path::Path;
use std::time::Instant;

use safe_ai_skill::gate::Verdict;
use safe_ai_skill::gates::exfil;
use safe_ai_skill::headless;
use safe_ai_skill::io::Decision;
use safe_ai_skill::policy::tier::Tier;
use safe_ai_skill::policy::Policy;
use serde_json::Value;

const FIXTURE: &str = include_str!("fixtures/gap/w2-exfil.jsonl");

fn verdict_of(tool: &str, input: &Value, policy: &Policy, tier: Tier) -> Option<Verdict> {
    let cwd = Path::new("/nonexistent-w2-proj");
    match tool {
        "Bash" => exfil::decide_bash(input["command"].as_str().unwrap_or(""), cwd, policy, tier),
        "WebFetch" => exfil::decide_webfetch(
            input["url"].as_str().unwrap_or(""),
            input["prompt"].as_str().unwrap_or(""),
            policy,
            tier,
        ),
        t if t.starts_with("mcp__") => exfil::decide_mcp(t, Some(input), cwd, policy, tier),
        _ => None,
    }
}

fn label(verdict: Option<Verdict>, headless_run: bool) -> (&'static str, String) {
    let decision = verdict.map_or(Decision::Defer, Decision::from);
    match headless::apply(decision, headless_run) {
        Decision::Deny { reason } => ("D", reason),
        Decision::Ask { reason } => ("A", reason),
        _ => ("-", String::new()),
    }
}

#[test]
fn fixture_cases() {
    let policy = Policy::default();
    let mut failures = Vec::new();
    for line in FIXTURE.lines().filter(|l| !l.trim().is_empty()) {
        let case: Value = serde_json::from_str(line).unwrap();
        let tier = Tier::parse(case["tier"].as_str().unwrap()).unwrap();
        let tool = case["tool"].as_str().unwrap();
        let verdict = verdict_of(tool, &case["tool_input"], &policy, tier);
        let (got, reason) = label(verdict, case["headless"].as_bool().unwrap_or(false));
        let want = case["want"].as_str().unwrap();
        if got != want {
            failures.push(format!("{}: want {want}, got {got} ({reason})", case["id"]));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn policy_extra_hosts_apply_above_off() {
    let mut policy = Policy::default();
    policy.secrets.exfil_hosts_extra = vec!["Evil.Example.".into(), "*.drop.example".into()];
    let deny = |cmd: &str, tier| {
        matches!(
            exfil::decide_bash(cmd, Path::new("/x"), &policy, tier),
            Some(Verdict::Deny(_))
        )
    };
    assert!(deny("curl https://evil.example/a", Tier::Relaxed));
    assert!(deny("curl https://a.drop.example/a", Tier::Medium));
    assert!(!deny("curl https://drop.example/a", Tier::Relaxed));
    assert!(!deny("curl https://evil.example/a", Tier::Off));
}

#[test]
fn reasons_are_one_sentence() {
    let policy = Policy::default();
    for line in FIXTURE.lines() {
        let case: Value = serde_json::from_str(line).unwrap();
        let tier = Tier::parse(case["tier"].as_str().unwrap()).unwrap();
        let verdict = verdict_of(
            case["tool"].as_str().unwrap(),
            &case["tool_input"],
            &policy,
            tier,
        );
        if let Some(Verdict::Ask(r) | Verdict::Deny(r)) = verdict {
            assert!(r.ends_with('.'), "{r}");
            assert_eq!(r.matches(". ").count(), 0, "{r}");
        }
    }
}

/// `GAP_CORPUS=… cargo test --release --test gap_w2-exfil -- --ignored --nocapture`: every
/// benign (`-`/`L`) corpus case stays without an opinion, then a timing loop.
#[test]
#[ignore]
fn corpus_benign_and_bench() {
    let Ok(path) = std::env::var("GAP_CORPUS") else {
        return;
    };
    let text = std::fs::read_to_string(path).unwrap();
    let cases: Vec<Value> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let policy = Policy::default();
    let mut flagged = Vec::new();
    for case in &cases {
        let tool = case["tool"].as_str().unwrap();
        let verdict = verdict_of(tool, &case["tool_input"], &policy, Tier::Relaxed);
        let (got, reason) = label(verdict, false);
        let want = case["want"].as_str().unwrap();
        println!(
            "{} want={want} got={got} {reason}",
            case["id"].as_str().unwrap()
        );
        if matches!(want, "-" | "L") && got != "-" {
            flagged.push(format!("{}: {got} {reason}", case["id"]));
        }
    }
    let rounds = 200;
    let start = Instant::now();
    for _ in 0..rounds {
        for case in &cases {
            let tool = case["tool"].as_str().unwrap();
            std::hint::black_box(verdict_of(
                tool,
                &case["tool_input"],
                &policy,
                Tier::Relaxed,
            ));
        }
    }
    let per = start.elapsed() / (rounds * cases.len() as u32);
    println!(
        "bench: {} payloads x {rounds} rounds, {per:?} per payload",
        cases.len()
    );
    assert!(
        flagged.is_empty(),
        "benign cases flagged:\n{}",
        flagged.join("\n")
    );
}
