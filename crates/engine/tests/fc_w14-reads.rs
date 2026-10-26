//! FC W14 (credential-store read coverage and two false positives), driven by
//! `fixtures/fc/w14-reads.jsonl`: cloud CLI token printers (S1), gh's host file through a hard
//! link or a config-dir variable (S3), context-mode `path` arguments reaching a store (S7), the
//! Bitwarden data directory (P1), a here-document that writes prose naming a keypair, and a
//! JSON-RPC POST split by a line continuation. Each row runs the real binary the way
//! hooks.json does (Bash: `gate-bash` and `gate-bash-secrets`, strictest wins; Read/Grep:
//! `gate-read`; `mcp__*`: `gate-mcp`) in a fresh project and home.
//!
//! Row fields beyond the common ones: `env` (extra variables, `{HOME}`/`{CWD}` substituted),
//! `links` (`[kind, from, to]`, kind `hard` or `sym`, `~/` the home) and, for a Grep the gate
//! rewrites, `want: "rewrite"` with `glob_has` (text the rewritten glob must exclude).

mod common;

use std::path::{Path, PathBuf};

use common::{Invocation, TempDir, Tier};
use serde_json::{json, Value};

const FIXTURE: &str = include_str!("fixtures/fc/w14-reads.jsonl");

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

fn place(name: &str, proj: &Path, home: &Path) -> PathBuf {
    match name.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None => proj.join(name),
    }
}

/// The label of one gate run: `deny`, `ask`, `allow`, `rewrite` (an `updatedInput` with no
/// decision) or `none`, and the rewritten Grep glob.
fn label(run: &common::Run) -> (String, Option<String>) {
    assert_eq!(
        run.code,
        Some(0),
        "gate exited {:?}: {}",
        run.code,
        run.stderr
    );
    if run.stdout.trim().is_empty() {
        return ("none".into(), None);
    }
    let v = run.json();
    if let Some(d) = common::permission_decision(&v) {
        return (d, None);
    }
    let glob = v["hookSpecificOutput"]["updatedInput"]["glob"]
        .as_str()
        .map(str::to_string);
    match glob {
        Some(g) => ("rewrite".into(), Some(g)),
        None => ("none".into(), None),
    }
}

fn rank(label: &str) -> u8 {
    match label {
        "deny" => 4,
        "ask" => 3,
        "rewrite" => 2,
        "allow" => 1,
        _ => 0,
    }
}

fn run_row(row: &Value) -> (String, String, Option<String>) {
    let id = row["id"].as_str().unwrap().to_string();
    let dir = TempDir::outside_home("fc-w14");
    let proj = dir.join("proj");
    let home = dir.join("home");
    let data = dir.join("data");
    for d in [&proj, &home, &data] {
        std::fs::create_dir_all(d).unwrap();
    }
    if let Some(files) = row["cwd_files"].as_object() {
        for (name, body) in files {
            let path = place(name, &proj, &home);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, body.as_str().unwrap()).unwrap();
        }
    }
    if let Some(links) = row["links"].as_array() {
        for link in links {
            let kind = link[0].as_str().unwrap();
            let from = place(link[1].as_str().unwrap(), &proj, &home);
            let to = place(link[2].as_str().unwrap(), &proj, &home);
            std::fs::create_dir_all(to.parent().unwrap()).unwrap();
            if kind == "hard" {
                std::fs::hard_link(&from, &to).unwrap();
            } else {
                #[cfg(unix)]
                std::os::unix::fs::symlink(&from, &to).unwrap();
            }
        }
    }
    let mut tier: Tier = serde_json::from_value(row["tier"].clone()).unwrap();
    if tier == Tier::Off && !common::TEST_HOOKS {
        // Off is reachable through the binary only with test-hooks; these gates are
        // tier-independent, so Relaxed stands in.
        tier = Tier::Relaxed;
    }
    let headless = row["headless"].as_bool().unwrap_or(false);
    let tool = row["tool"].as_str().unwrap();
    let input = substitute(&row["tool_input"], &proj, &home);
    let env: Vec<(String, String)> = row["env"]
        .as_object()
        .map(|o| {
            o.iter()
                .map(|(k, v)| {
                    let v = substitute(v, &proj, &home);
                    (k.clone(), v.as_str().unwrap().to_string())
                })
                .collect()
        })
        .unwrap_or_default();
    let payload = json!({
        "hook_event_name": "PreToolUse",
        "session_id": "fc-w14",
        "cwd": proj.to_string_lossy(),
        "tool_name": tool,
        "tool_input": input,
    })
    .to_string();
    let gates: &[&str] = match tool {
        "Bash" => &["gate-bash", "gate-bash-secrets"],
        "Read" | "Grep" | "Glob" => &["gate-read"],
        _ => &["gate-mcp"],
    };
    let mut best = ("none".to_string(), None);
    for gate in gates {
        let mut inv = Invocation::new(&[gate])
            .stdin(payload.clone())
            .plugin_data(&data)
            .home(&home)
            .cwd(&proj)
            .tier(tier)
            .headless(headless);
        for (k, v) in &env {
            inv = inv.env(k, v);
        }
        let got = label(&inv.run());
        if rank(&got.0) > rank(&best.0) {
            best = got;
        }
    }
    (id, best.0, best.1)
}

fn unbracket(glob: &str) -> String {
    // `[hH][oO]` → `h`: the gate writes each letter as a two-case class.
    let mut out = String::new();
    let mut chars = glob.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '[' {
            let a = chars.next();
            let b = chars.next();
            if let (Some(a), Some(b), Some(']')) = (a, b, chars.peek().copied()) {
                if a.eq_ignore_ascii_case(&b) {
                    chars.next();
                    out.push(a.to_ascii_lowercase());
                    continue;
                }
            }
            out.push('[');
            out.extend(a);
            out.extend(b);
            continue;
        }
        out.push(c.to_ascii_lowercase());
    }
    out
}

#[test]
fn fixture_rows_get_their_verdicts() {
    let mut failures = Vec::new();
    let mut count = 0;
    for line in FIXTURE.lines().filter(|l| !l.trim().is_empty()) {
        let row: Value = serde_json::from_str(line).unwrap();
        if row["unix_only"].as_bool() == Some(true) && !cfg!(unix) {
            continue;
        }
        let want = row["want"].as_str().unwrap();
        let (id, got, glob) = run_row(&row);
        if got != want {
            failures.push(format!("{id}: want {want}, got {got}"));
        } else if let Some(has) = row["glob_has"].as_str() {
            let glob = unbracket(glob.as_deref().unwrap_or(""));
            if !glob.contains(has) {
                failures.push(format!("{id}: rewritten glob lacks {has}: {glob}"));
            }
        }
        count += 1;
    }
    assert!(count >= 60, "fixture has {count} rows");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// In-process cost of the three gates these rows exercise, over the fixture's commands and
/// paths (no process per call).
#[test]
fn benchmark() {
    use safe_ai_skill::gates::{creddump, read, secrets};
    use safe_ai_skill::policy::Policy;
    let dir = TempDir::outside_home("fc-w14-bench");
    let proj = dir.join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let home = dir.join("home");
    let policy = Policy::default();
    let rows: Vec<Value> = FIXTURE
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .collect();
    let start = std::time::Instant::now();
    let mut calls = 0u32;
    while calls < 2310 {
        for r in &rows {
            let input = substitute(&r["tool_input"], &proj, &home);
            match r["tool"].as_str().unwrap() {
                "Bash" => {
                    let c = input["command"].as_str().unwrap();
                    let _ = secrets::decide(c, &proj, &policy);
                    let _ = creddump::decide(c, &proj, &policy, Tier::Relaxed);
                }
                "Read" | "Grep" => {
                    let _ = read::decide_tool(
                        r["tool"].as_str().unwrap(),
                        Some(&input),
                        &proj,
                        &policy,
                    );
                }
                _ => {
                    let _ = read::decide_mcp_args(Some(&input), &proj, &policy);
                }
            }
            calls += 1;
        }
    }
    eprintln!(
        "fc-w14: {calls} calls, {:?} per call",
        start.elapsed() / calls
    );
}
