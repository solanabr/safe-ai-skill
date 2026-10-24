//! Golden I/O conformance: `tests/conformance/*.json` cases of (subcommand, stdin) → expected
//! stdout and exit status, run through the built binary.
//!
//! A case file is `{"cases": [case, ...]}`; a case is
//! `{"name", "args": [..], "stdin": <hook object | raw string>, "env"?: {..}, "expect": {"exit",
//! one of "stdout" (exact text) | "stdout_json" (equal JSON) | "stdout_prefix"}}`. The token
//! `{cwd}` in `stdin` becomes the sandbox project dir.
//!
//! Each run is hermetic: a cleared environment, `PATH` an empty dir (no `solana` to shell out
//! to), a temp `HOME`, `CLAUDE_PLUGIN_DATA` under it, and a temp project as the cwd.
//!
//! `benign.json` is special: every subcommand `hooks.json` wires must have a case there, and
//! every case there must expect no opinion (empty stdout, exit 0).

mod common;

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use common::{bin, TempDir};
use serde_json::Value;

fn conformance_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/conformance")
}

fn hooks_json() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../plugins/safe-ai-skill/hooks/hooks.json")
}

fn load_cases(path: &Path) -> Vec<Value> {
    let text = std::fs::read_to_string(path).unwrap();
    let v: Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("{}: invalid JSON: {e}", path.display()));
    v["cases"]
        .as_array()
        .unwrap_or_else(|| panic!("{}: no `cases` array", path.display()))
        .clone()
}

fn case_files() -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(conformance_dir())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    files
}

struct Outcome {
    stdout: String,
    stderr: String,
    code: Option<i32>,
}

fn run_case(case: &Value) -> Outcome {
    let sandbox = TempDir::new("conformance");
    let home = sandbox.join("home");
    let project = sandbox.join("proj");
    let empty_path = sandbox.join("empty-path");
    for d in [&home, &project, &empty_path] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(project.join("README.md"), "hello\n").unwrap();
    let plugin_data = home.join(".claude/plugins/data/safe-ai-skill-conformance");

    let stdin = match &case["stdin"] {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    };
    let cwd_json = Value::String(project.display().to_string()).to_string();
    let stdin = stdin.replace("\"{cwd}\"", &cwd_json);

    let args: Vec<String> = case["args"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a.as_str().unwrap().to_string())
        .collect();
    let mut cmd = Command::new(bin());
    cmd.args(&args)
        .current_dir(&project)
        .env_clear()
        .env("PATH", &empty_path)
        .env("HOME", &home)
        .env("TMPDIR", sandbox.path())
        .env("CLAUDE_PLUGIN_DATA", &plugin_data)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(root) = std::env::var_os("SYSTEMROOT") {
        cmd.env("SYSTEMROOT", root);
    }
    if let Some(env) = case["env"].as_object() {
        for (k, v) in env {
            cmd.env(k, v.as_str().unwrap());
        }
    }
    let mut child = cmd.spawn().unwrap();
    match child.stdin.take().unwrap().write_all(stdin.as_bytes()) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
        Err(e) => panic!("write stdin: {e}"),
    }
    let out = child.wait_with_output().unwrap();
    let mut stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if cfg!(windows) && args.len() >= 2 && args[..2] == ["verify", "session"] {
        stdout = common::without_windows_notice(&stdout);
    }
    Outcome {
        stdout,
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        code: out.status.code(),
    }
}

/// `None` when `out` meets `expect`, else what went wrong.
fn mismatch(expect: &Value, out: &Outcome) -> Option<String> {
    let want_exit = expect["exit"].as_i64().unwrap_or(0) as i32;
    if out.code != Some(want_exit) {
        return Some(format!("exit {:?}, want {want_exit}", out.code));
    }
    if let Some(want) = expect.get("stdout").and_then(Value::as_str) {
        if out.stdout != want {
            return Some(format!("stdout {:?}, want {want:?}", out.stdout));
        }
    }
    if let Some(want) = expect.get("stdout_json") {
        match serde_json::from_str::<Value>(out.stdout.trim()) {
            Ok(got) if &got == want => {}
            _ => return Some(format!("stdout {:?}, want JSON {want}", out.stdout)),
        }
    }
    if let Some(want) = expect.get("stdout_prefix").and_then(Value::as_str) {
        if !out.stdout.starts_with(want) {
            return Some(format!("stdout {:?}, want prefix {want:?}", out.stdout));
        }
    }
    None
}

#[test]
fn golden_cases_hold() {
    let mut failures = Vec::new();
    let mut count = 0;
    for file in case_files() {
        for case in load_cases(&file) {
            count += 1;
            let out = run_case(&case);
            if let Some(why) = mismatch(&case["expect"], &out) {
                failures.push(format!(
                    "{} :: {}: {why}\n  stderr: {}",
                    file.file_name().unwrap().to_string_lossy(),
                    case["name"].as_str().unwrap_or("?"),
                    out.stderr.trim()
                ));
            }
        }
    }
    assert!(count > 0, "no conformance cases found");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Every subcommand `hooks.json` runs (`gate-bash`, `verify session`, ...).
fn wired_subcommands() -> BTreeSet<String> {
    let cfg: Value = serde_json::from_str(&std::fs::read_to_string(hooks_json()).unwrap()).unwrap();
    let prefix = "\"${CLAUDE_PLUGIN_ROOT}\"/bin/safe-ai-skill ";
    let mut subs = BTreeSet::new();
    for groups in cfg["hooks"].as_object().unwrap().values() {
        for group in groups.as_array().unwrap() {
            for hook in group["hooks"].as_array().unwrap() {
                let cmd = hook["command"].as_str().unwrap();
                let sub = cmd
                    .strip_prefix(prefix)
                    .unwrap_or_else(|| panic!("unexpected hook command {cmd:?}"));
                subs.insert(sub.to_string());
            }
        }
    }
    subs
}

#[test]
fn benign_golden_covers_every_wired_subcommand_with_no_opinion() {
    let benign = load_cases(&conformance_dir().join("benign.json"));
    let mut covered = BTreeSet::new();
    for case in &benign {
        let name = case["name"].as_str().unwrap_or("?");
        assert_eq!(
            case["expect"],
            serde_json::json!({"exit": 0, "stdout": ""}),
            "benign case {name:?} must expect no opinion"
        );
        let args: Vec<&str> = case["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap())
            .collect();
        covered.insert(args.join(" "));
    }
    let missing: Vec<String> = wired_subcommands().difference(&covered).cloned().collect();
    assert!(
        missing.is_empty(),
        "hooks.json subcommands with no benign case: {missing:?}"
    );
}

/// The `(matcher, hook)` pairs `hooks.json` registers for `event`.
fn entries(event: &str) -> Vec<(String, Value)> {
    let cfg: Value = serde_json::from_str(&std::fs::read_to_string(hooks_json()).unwrap()).unwrap();
    let mut out = Vec::new();
    for group in cfg["hooks"][event].as_array().cloned().unwrap_or_default() {
        let matcher = group["matcher"].as_str().unwrap_or("").to_string();
        for hook in group["hooks"].as_array().unwrap() {
            out.push((matcher.clone(), hook.clone()));
        }
    }
    out
}

#[test]
fn hooks_json_wires_the_shared_contract_hooks() {
    let wired = |event: &str, matcher: &str, sub: &str, on_failure: &str| {
        entries(event).into_iter().any(|(m, h)| {
            m == matcher
                && h["command"]
                    .as_str()
                    .unwrap_or("")
                    .ends_with(&format!(" {sub}"))
                && h["onFailure"] == on_failure
        })
    };
    let runs = |event: &str, matcher: &str, sub: &str| wired(event, matcher, sub, "continue");
    // The Skill gate fails closed: failing open would run a blocked pack's !`cmd` (D6.2 as
    // amended for WS-D1).
    assert!(wired("PreToolUse", "Skill", "gate-skill", "block"));
    assert!(runs("UserPromptExpansion", "", "gate-prompt-expansion"));
    // A typed `/name` is also checked at UserPromptSubmit, for versions without the event.
    assert!(runs("UserPromptSubmit", "", "gate-prompt-expansion"));
    assert!(runs(
        "SessionStart",
        "startup|resume|clear|compact",
        "verify session"
    ));
}

/// The final shape: `onFailure: block` on the unconditional Bash `gate-bash` entry and the Skill
/// matcher only, `continue` everywhere else, and every hook the workstreams added is present.
#[test]
fn hooks_json_final_shape() {
    let events = [
        "PreToolUse",
        "PostToolUse",
        "UserPromptSubmit",
        "UserPromptExpansion",
        "SessionStart",
    ];
    let mut blocking = Vec::new();
    for event in events {
        for (matcher, hook) in entries(event) {
            let cmd = hook["command"].as_str().unwrap_or("").to_string();
            match hook["onFailure"].as_str() {
                Some("block") => blocking.push((
                    matcher.clone(),
                    cmd.rsplit(' ').next().unwrap_or("").to_string(),
                    hook["if"].as_str().unwrap_or("").to_string(),
                )),
                Some("continue") => {}
                other => panic!("{event} {matcher} {cmd}: onFailure {other:?}"),
            }
        }
    }
    blocking.sort();
    let want: Vec<(String, String, String)> =
        [("Bash", "gate-bash", ""), ("Skill", "gate-skill", "")]
            .iter()
            .map(|(a, b, c)| (a.to_string(), b.to_string(), c.to_string()))
            .collect();
    assert_eq!(blocking, want);
    let has = |event: &str, matcher: &str, sub: &str| {
        entries(event).into_iter().any(|(m, h)| {
            m == matcher
                && h["command"]
                    .as_str()
                    .unwrap_or("")
                    .ends_with(&format!(" {sub}"))
        })
    };
    assert!(has(
        "PreToolUse",
        "Write|Edit|MultiEdit|NotebookEdit",
        "gate-tamper"
    ));
    assert!(has("PostToolUse", "Bash", "pending-notice"));
    assert!(has(
        "PostToolUseFailure",
        "Bash|Read|Grep|mcp__.*",
        "failure-notice"
    ));
    assert!(has("PreToolUse", "Skill", "gate-skill"));
    assert!(has("UserPromptExpansion", "", "gate-prompt-expansion"));
    assert!(has(
        "SessionStart",
        "startup|resume|clear|compact",
        "verify session"
    ));
}
