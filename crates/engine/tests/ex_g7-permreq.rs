//! G7 fixture: `PermissionRequest` hardening (`gates::permreq`).

mod common;

use std::path::Path;
use std::time::Instant;

use safe_ai_skill::datadir;
use safe_ai_skill::gates::permreq::{self, Class};
use safe_ai_skill::policy::tier::Tier;
use safe_ai_skill::policy::Policy;
use serde_json::Value;

const FIXTURE: &str = include_str!("fixtures/fc/g7-permreq.jsonl");

fn cases() -> Vec<Value> {
    FIXTURE
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn policy(tier: Tier, headless: bool) -> Policy {
    let mut policy = Policy::default();
    policy.runtime.tier = tier;
    policy.runtime.headless = headless;
    policy
}

fn substitute(value: &Value, cwd: &Path) -> Value {
    match value {
        Value::String(s) => Value::String(s.replace("{CWD}", &cwd.to_string_lossy())),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), substitute(v, cwd)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Lay out the case's `cwd_files` in `proj` and decide it there.
fn run_in(case: &Value, proj: &Path) -> Option<Value> {
    if let Some(files) = case["cwd_files"].as_object() {
        for (name, body) in files {
            let path = proj.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, body.as_str().unwrap()).unwrap();
        }
    }
    let tier = Tier::parse(case["tier"].as_str().unwrap()).unwrap();
    permreq::decide(
        case["tool"].as_str().unwrap(),
        Some(&substitute(&case["tool_input"], proj)),
        case["mode"].as_str(),
        proj,
        &policy(tier, case["headless"].as_bool().unwrap()),
        &datadir::unresolved(),
    )
}

fn run(case: &Value) -> Option<Value> {
    let dir = common::TempDir::outside_home("ex-g7");
    let proj = dir.join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    run_in(case, &proj)
}

fn label(out: &Option<Value>) -> &'static str {
    match out {
        None => "-",
        Some(v) if v["hookSpecificOutput"]["decision"]["behavior"] == "deny" => "deny",
        Some(v) if v["systemMessage"].is_string() => "msg",
        Some(_) => "?",
    }
}

#[test]
fn fixture_cases() {
    let mut failures = Vec::new();
    for case in cases() {
        let got = run(&case);
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
fn output_matches_the_documented_shape_and_never_allows() {
    for case in cases() {
        let Some(out) = run(&case) else { continue };
        let text = out.to_string();
        assert!(!text.contains("\"allow\""), "{text}");
        if let Some(hso) = out.get("hookSpecificOutput") {
            assert_eq!(hso["hookEventName"], "PermissionRequest");
            let message = hso["decision"]["message"].as_str().unwrap();
            assert!(message.ends_with('.'), "{message}");
            assert!(hso["decision"].get("updatedInput").is_none());
            assert!(hso["decision"].get("updatedPermissions").is_none());
        } else {
            let line = out["systemMessage"].as_str().unwrap();
            assert!(!line.contains('\n') && line.ends_with('.'), "{line}");
        }
    }
}

#[test]
fn modes_that_wait_for_the_user_never_deny() {
    let hard = Class::HardGuard {
        reason: "x.".into(),
        denied: true,
    };
    for mode in [None, Some("default"), Some("manual"), Some("plan")] {
        assert!(permreq::unattended(mode, false, true).is_none());
        assert!(permreq::render(&hard, mode, false).unwrap()["systemMessage"].is_string());
    }
    for mode in ["auto", "acceptEdits", "bypassPermissions"] {
        assert!(permreq::unattended(Some(mode), false, false).is_none());
        assert!(permreq::unattended(Some(mode), false, true).is_some());
    }
    assert!(permreq::unattended(Some("dontAsk"), false, false).is_some());
    assert!(permreq::unattended(Some("default"), true, false).is_some());
    assert!(permreq::render(&Class::Ordinary, Some("dontAsk"), true).is_none());
}

#[test]
fn bench_fixture() {
    let all = cases();
    let dir = common::TempDir::outside_home("ex-g7-bench");
    let proj = dir.join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    for case in &all {
        run_in(case, &proj);
    }
    let rounds = 50;
    let start = Instant::now();
    for _ in 0..rounds {
        for case in &all {
            std::hint::black_box(run_in(case, &proj));
        }
    }
    let per = start.elapsed() / (rounds * all.len() as u32);
    eprintln!("permreq: {} cases x {rounds}, {per:?} per case", all.len());
}

/// Other writers' fixtures (w1/w10 need their own project layout): every self-contained row their gate denies is a hard-guard
/// deny here too (the same decision functions answer), so an unattended request is denied.
const OTHERS: &[&str] = &[
    include_str!("fixtures/fc/w4b-fetchexec.jsonl"),
    include_str!("fixtures/fc/w5b-onchain.jsonl"),
    include_str!("fixtures/fc/w8-git.jsonl"),
    include_str!("fixtures/fc/w11-mcpnames.jsonl"),
    include_str!("fixtures/fc/w14-reads.jsonl"),
    include_str!("fixtures/gap/w2-exfil.jsonl"),
    include_str!("fixtures/gap/w3-envdump.jsonl"),
    include_str!("fixtures/gap/w4-fetchexec.jsonl"),
    include_str!("fixtures/gap/w5-onchain.jsonl"),
    include_str!("fixtures/gap/w6-mcp-encoded.jsonl"),
];

#[test]
fn other_fixtures_denials_stay_denied_when_unattended() {
    let mut missed = Vec::new();
    let mut checked = 0;
    for text in OTHERS {
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let case: Value = serde_json::from_str(line).unwrap();
            let self_contained = case.get("cwd_files").is_none_or(|f| f == &Value::Null)
                && !line.contains("{CWD}")
                && !line.contains("{HOME}")
                && case.get("env").is_none();
            let tool = case["tool"].as_str().unwrap_or("");
            let wants_deny = matches!(case["want"].as_str(), Some("D" | "deny"));
            let Some(tier) = case["tier"].as_str().and_then(Tier::parse) else {
                continue;
            };
            if !self_contained || !wants_deny || !(tool == "Bash" || tool.starts_with("mcp__")) {
                continue;
            }
            checked += 1;
            let headless = case["headless"].as_bool().unwrap_or(false);
            let out = permreq::decide(
                tool,
                Some(&case["tool_input"]),
                Some("auto"),
                Path::new("."),
                &policy(tier, headless),
                &datadir::unresolved(),
            );
            if label(&out) != "deny" {
                missed.push(format!("{}: {out:?}", case["id"]));
            }
        }
    }
    eprintln!("checked {checked} denied rows");
    assert!(missed.is_empty(), "{}", missed.join("\n"));
}

/// The gates' state (the spend ledger) goes to the data dir the hook hands in, never to one
/// resolved again from the environment (which in a test is the real home's standalone dir).
#[test]
fn state_goes_to_the_given_data_dir() {
    let tmp = common::TempDir::outside_home("ex-g7-dir");
    let proj = tmp.join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let dir = datadir::DataDir {
        path: tmp.join("data"),
        trusted: true,
    };
    let command =
        "solana transfer 9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin 1 --url mainnet-beta";
    permreq::decide(
        "Bash",
        Some(&serde_json::json!({ "command": command })),
        Some("dontAsk"),
        &proj,
        &policy(Tier::Medium, false),
        &dir,
    );
    assert!(
        dir.path.join("spend.json").is_file(),
        "the spend ledger was not read from the given dir"
    );
}
