//! Full coverage W11: ai-kit's MCP tool-name denies (P17, P18, P19), through the real
//! `gate-mcp` binary.
//!
//! `fixtures/fc/w11-mcpnames.jsonl` holds one case per line; `want` is `D`, `A` or `-`.
//! Tier `off` cases need `--features test-hooks` and are skipped without it.
//! `cargo test --release --test fc_w11-mcpnames -- --ignored` runs the benchmark.

mod common;

use std::time::Instant;

use common::{decision_label, Invocation, TempDir, TEST_HOOKS};
use safe_ai_skill::context::Context;
use safe_ai_skill::gates::mcp;
use safe_ai_skill::policy::tier::Tier;
use safe_ai_skill::policy::Policy;
use serde_json::{json, Value};

const FIXTURE: &str = include_str!("fixtures/fc/w11-mcpnames.jsonl");

fn cases() -> Vec<Value> {
    FIXTURE
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("valid fixture json"))
        .collect()
}

fn short(label: &str) -> &'static str {
    match label {
        "deny" => "D",
        "ask" => "A",
        "" => "-",
        _ => "?",
    }
}

#[test]
fn fixture_cases() {
    let home = TempDir::new("fc-w11-home");
    let proj = TempDir::new("fc-w11-proj");
    std::fs::write(proj.join("README.md"), "readme\n").unwrap();
    std::fs::create_dir_all(proj.join("src")).unwrap();
    let mut failures = Vec::new();
    for case in cases() {
        let tier = Tier::parse(case["tier"].as_str().unwrap()).unwrap();
        if tier == Tier::Off && !TEST_HOOKS {
            continue;
        }
        let data = TempDir::new("fc-w11-data");
        let tool = case["tool"].as_str().unwrap();
        let payload = json!({
            "session_id": "fc-w11", "hook_event_name": "PreToolUse",
            "cwd": proj.path(), "tool_name": tool, "tool_input": case["tool_input"],
        })
        .to_string();
        let run = Invocation::new(&["gate-mcp"])
            .plugin_data(data.path())
            .home(home.path())
            .cwd(proj.path())
            .tier(tier)
            .headless(case["headless"].as_bool().unwrap_or(false))
            .stdin(payload)
            .run();
        let got = short(&decision_label(&run));
        let want = case["want"].as_str().unwrap();
        if got != want {
            failures.push(format!(
                "{}: want {want}, got {got} ({})",
                case["id"],
                run.stdout.trim()
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn name_rules_follow_the_kit_matrix() {
    let medium_up = [
        "mcp__context-mode__ctx_execute",
        "mcp__context-mode__ctx_execute_file",
        "mcp__context-mode__ctx_batch_execute",
        "mcp__context-mode__ctx_fetch_and_index",
        "mcp__context-mode__ctx_index",
        "mcp__playwright__browser_run_code_unsafe",
        "mcp__playwright__browser_network_request",
    ];
    let high_only = [
        "mcp__playwright__browser_evaluate",
        "mcp__cloudflare__execute",
    ];
    for tool in medium_up {
        for (tier, denied) in [
            (Tier::Off, false),
            (Tier::Relaxed, false),
            (Tier::Medium, true),
            (Tier::High, true),
        ] {
            assert_eq!(
                mcp::decide_name(tool, tier).is_some(),
                denied,
                "{tool} at {}",
                tier.label()
            );
        }
    }
    for tool in high_only {
        for (tier, denied) in [
            (Tier::Off, false),
            (Tier::Relaxed, false),
            (Tier::Medium, false),
            (Tier::High, true),
        ] {
            assert_eq!(
                mcp::decide_name(tool, tier).is_some(),
                denied,
                "{tool} at {}",
                tier.label()
            );
        }
    }
}

#[test]
fn a_name_deny_is_a_hard_guard_from_decide() {
    let mut policy = Policy::default();
    policy.runtime.tier = Tier::Medium;
    let ctx = Context::build("", std::path::Path::new("."));
    let payload = json!({ "language": "shell", "code": "ls" });
    let (decision, meta) = mcp::decide(
        "mcp__context-mode__ctx_execute",
        Some(&payload),
        &ctx,
        &policy,
    );
    assert_eq!(decision.label(), "deny");
    assert!(meta.hard_guard);
}

/// Release micro-benchmark of the name rule and of `mcp::decide` over the fixture's tools.
#[test]
#[ignore]
fn bench_name_rule() {
    let cases = cases();
    let tools: Vec<(String, Value, Tier)> = cases
        .iter()
        .map(|c| {
            (
                c["tool"].as_str().unwrap().to_string(),
                c["tool_input"].clone(),
                Tier::parse(c["tier"].as_str().unwrap()).unwrap(),
            )
        })
        .collect();
    let rounds = 20_000usize;
    let start = Instant::now();
    let mut hits = 0usize;
    for _ in 0..rounds {
        for (tool, _, tier) in &tools {
            hits += usize::from(mcp::decide_name(std::hint::black_box(tool), *tier).is_some());
        }
    }
    let calls = rounds * tools.len();
    let per = start.elapsed().as_nanos() as f64 / calls as f64;
    println!("decide_name: {calls} calls, {per:.1} ns/call ({hits} denies)");

    let ctx = Context::build("", std::path::Path::new("."));
    let policies: Vec<Policy> = Tier::ALL
        .iter()
        .map(|t| {
            let mut p = Policy::default();
            p.runtime.tier = *t;
            p
        })
        .collect();
    let rounds = 2_000usize;
    let start = Instant::now();
    for _ in 0..rounds {
        for (tool, input, tier) in &tools {
            let policy = &policies[*tier as usize];
            std::hint::black_box(mcp::decide(tool, Some(input), &ctx, policy));
        }
    }
    let calls = rounds * tools.len();
    let per = start.elapsed().as_nanos() as f64 / calls as f64;
    println!("mcp::decide: {calls} calls, {per:.1} ns/call");
}
