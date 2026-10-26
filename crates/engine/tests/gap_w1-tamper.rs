//! Gap W1 (tamper): content-aware settings and hook-file checks, driven by
//! `fixtures/gap/w1-tamper.jsonl`. Each row runs through `decide_file_content_in` (file tools)
//! or `decide_bash_writes_in` (Bash) in a fresh project and home, then the headless conversion.

mod common;

use std::path::Path;

use safe_ai_skill::gates::tamper::{self, ConfigHomes};
use safe_ai_skill::headless;
use safe_ai_skill::io::Decision;
use serde_json::Value;

const FIXTURE: &str = include_str!("fixtures/gap/w1-tamper.jsonl");

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

fn run_row(row: &Value) -> (String, Decision) {
    let id = row["id"].as_str().unwrap().to_string();
    let dir = common::TempDir::outside_home("gap-w1");
    let proj = dir.join("proj");
    let home = dir.join("home");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::create_dir_all(home.join(".claude")).unwrap();
    for (name, body) in row["cwd_files"].as_object().unwrap() {
        let path = match name.strip_prefix("~/") {
            Some(rest) => home.join(rest),
            None => dir.join(name),
        };
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, body.as_str().unwrap()).unwrap();
    }
    let homes = ConfigHomes {
        home: Some(home.clone()),
        config_dir: Some(home.join(".claude")),
        project_dir: Some(proj.clone()),
    };
    let input = substitute(&row["tool_input"], &proj, &home);
    let verdict = if row["tool"] == "Bash" {
        tamper::decide_bash_writes_in(input["command"].as_str().unwrap(), &proj, &homes)
    } else {
        tamper::decide_file_content_in(Some(&input), &proj, &homes)
    };
    let decision = verdict.map_or(Decision::Defer, Decision::from);
    let headless = row["headless"].as_bool().unwrap_or(false);
    (id, headless::apply(decision, headless))
}

#[test]
fn fixture_rows_get_their_verdicts() {
    let mut failures = Vec::new();
    let mut count = 0;
    for line in FIXTURE.lines().filter(|l| !l.trim().is_empty()) {
        let row: Value = serde_json::from_str(line).unwrap();
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
    assert!(count > 90, "fixture has {count} rows");
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
        assert!(
            reason.starts_with("safe-ai-skill tamper tripwire:"),
            "{id}: {reason}"
        );
        assert!(reason.ends_with('.'), "{id}: {reason}");
        assert!(
            reason.contains("user") || reason.contains("Edit tool"),
            "{id}: {reason}"
        );
    }
}

#[test]
fn bash_writes_benchmark() {
    // 231-payload style loop: the fixture's Bash rows, repeated, against a project with files.
    let dir = common::TempDir::outside_home("gap-w1-bench");
    let proj = dir.join("proj");
    std::fs::create_dir_all(proj.join(".claude")).unwrap();
    std::fs::write(proj.join(".claude/settings.json"), "{}").unwrap();
    let homes = ConfigHomes {
        home: Some(dir.join("home")),
        config_dir: None,
        project_dir: None,
    };
    let commands: Vec<String> = FIXTURE
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|r| r["tool"] == "Bash")
        .filter_map(|r| r["tool_input"]["command"].as_str().map(String::from))
        .collect();
    let start = std::time::Instant::now();
    let mut calls = 0u32;
    while calls < 2310 {
        for c in &commands {
            let _ = tamper::decide_bash_writes_in(c, &proj, &homes);
            calls += 1;
        }
    }
    let per_call = start.elapsed() / calls;
    eprintln!("decide_bash_writes_in: {calls} calls, {per_call:?} per call");
}
