//! FC W10 (tamper extensions and the ConfigChange guard), driven by
//! `fixtures/fc/w10-tamper2.jsonl`: nested-claude escapes (F3, F4), code-on-next-build and
//! managed-settings writes (P3, P5), the user-scope policy surface at High (P8), and the
//! `ConfigChange` hook. Each row runs in a fresh project and home, then the headless conversion.

mod common;

use std::path::Path;

use safe_ai_skill::gate::Verdict;
use safe_ai_skill::gates::configchange;
use safe_ai_skill::gates::tamper::{self, ConfigHomes};
use safe_ai_skill::headless;
use safe_ai_skill::io::Decision;
use safe_ai_skill::policy::tier::Tier;
use serde_json::Value;

const FIXTURE: &str = include_str!("fixtures/fc/w10-tamper2.jsonl");

fn substitute(value: &Value, cwd: &Path, home: &Path) -> Value {
    match value {
        Value::String(s) => Value::String(
            s.replace("{CWD}", &cwd.to_string_lossy())
                .replace("{HOME}", &home.to_string_lossy()),
        ),
        Value::Array(a) => Value::Array(a.iter().map(|v| substitute(v, cwd, home)).collect()),
        Value::Object(o) => Value::Object(
            o.iter()
                .map(|(k, v)| (k.clone(), substitute(v, cwd, home)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn verdict_for(
    tool: &str,
    input: &Value,
    proj: &Path,
    homes: &ConfigHomes,
    tier: Tier,
) -> Option<Verdict> {
    match tool {
        "Bash" => {
            let command = input["command"].as_str().unwrap();
            tamper::decide_nested_claude_flags(command, tier)
                .or_else(|| tamper::decide_bash_writes_at(command, proj, homes, tier))
        }
        "ConfigChange" => configchange::decide_in(input, homes),
        _ => tamper::decide_file_content_at(Some(input), proj, homes, tier),
    }
}

fn run_row(row: &Value) -> (String, Decision) {
    let id = row["id"].as_str().unwrap().to_string();
    let dir = common::TempDir::outside_home("fc-w10");
    let proj = dir.join("proj");
    let home = dir.join("home");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::create_dir_all(home.join(".claude")).unwrap();
    if let Some(files) = row["cwd_files"].as_object() {
        for (name, body) in files {
            let path = match name.strip_prefix("~/") {
                Some(rest) => home.join(rest),
                None => dir.join(name),
            };
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, body.as_str().unwrap()).unwrap();
        }
    }
    let homes = ConfigHomes {
        home: Some(home.clone()),
        config_dir: None,
        project_dir: Some(proj.clone()),
    };
    let tier: Tier = serde_json::from_value(row["tier"].clone()).unwrap();
    let input = substitute(&row["tool_input"], &proj, &home);
    let tool = row["tool"].as_str().unwrap();
    let decision =
        verdict_for(tool, &input, &proj, &homes, tier).map_or(Decision::Defer, Decision::from);
    let headless = row["headless"].as_bool().unwrap_or(false);
    (id, headless::apply(decision, headless))
}

#[test]
fn fixture_rows_get_their_verdicts() {
    let mut failures = Vec::new();
    let mut count = 0;
    for line in FIXTURE.lines().filter(|l| !l.trim().is_empty()) {
        let row: Value = serde_json::from_str(line).unwrap();
        // A macOS system path: on Windows it resolves under the drive root instead.
        if row["unix_only"].as_bool() == Some(true) && !cfg!(unix) {
            continue;
        }
        let want = row["want"].as_str().unwrap();
        let (id, got) = run_row(&row);
        let label = match got {
            Decision::Deny { .. } => "deny",
            Decision::Ask { .. } => "ask",
            _ => "none",
        };
        if label != want {
            failures.push(format!("{id}: want {want}, got {got:?}"));
        }
        count += 1;
    }
    assert!(count >= 100, "fixture has {count} rows");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn reasons_are_one_sentence_ending_with_the_remediation() {
    for line in FIXTURE.lines().filter(|l| !l.trim().is_empty()) {
        let row: Value = serde_json::from_str(line).unwrap();
        if row["headless"].as_bool().unwrap_or(false) {
            continue;
        }
        let (id, got) = run_row(&row);
        let reason = match &got {
            Decision::Deny { reason } | Decision::Ask { reason } => reason,
            _ => continue,
        };
        assert!(reason.starts_with("safe-ai-skill"), "{id}: {reason}");
        assert!(reason.ends_with('.'), "{id}: {reason}");
        assert_eq!(reason.matches(". ").count(), 0, "{id}: {reason}");
        assert!(
            reason.contains("user")
                || reason.contains("administrator")
                || reason.contains("confirmation code"),
            "{id}: {reason}"
        );
    }
}

#[test]
fn benchmark() {
    let dir = common::TempDir::outside_home("fc-w10-bench");
    let proj = dir.join("proj");
    std::fs::create_dir_all(proj.join(".claude")).unwrap();
    let homes = ConfigHomes {
        home: Some(dir.join("home")),
        config_dir: None,
        project_dir: None,
    };
    let rows: Vec<Value> = FIXTURE
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|r| r["tool"] != "ConfigChange")
        .collect();
    let start = std::time::Instant::now();
    let mut calls = 0u32;
    while calls < 2310 {
        for r in &rows {
            let input = substitute(&r["tool_input"], &proj, &dir.join("home"));
            let _ = verdict_for(
                r["tool"].as_str().unwrap(),
                &input,
                &proj,
                &homes,
                Tier::High,
            );
            calls += 1;
        }
    }
    eprintln!(
        "fc-w10: {calls} calls, {:?} per call",
        start.elapsed() / calls
    );
}
