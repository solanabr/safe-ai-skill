//! `safe-ai-skill doctor --codex`: run each configured Codex hook the way Codex does and check
//! that it answers.
//!
//! Codex runs a tool call unchecked when a hook command cannot start at all (exit 127 from
//! `$SHELL -lc`: the shim is not on the login-shell `PATH`, its path went away with an update,
//! a typo in the command). Nothing in the hook can catch that, so this check runs every
//! safe-ai-skill entry found in `$CODEX_HOME/hooks.json` (or `~/.codex/hooks.json`) and in each
//! `.codex/hooks.json` from the working dir up, with a probe payload that must be denied (and,
//! for the gates, one that must pass).
//!
//! Only commands of the template's shape are run (`<path>/safe-ai-skill adapt codex <entry>
//! [--block-with-redaction] [|| <fallback>]`, the path made of plain characters), and only
//! their `safe-ai-skill …` part, rebuilt here: a project's hook file can't make this run
//! anything else. Probes are audited like any hook call.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

/// Longest a probe may take when the hook sets no timeout.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// One hook command found in a hooks file.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    /// The hooks file it came from.
    pub file: PathBuf,
    /// The Codex event (`PreToolUse`, `SessionStart`, …).
    pub event: String,
    /// The command as configured.
    pub command: String,
    /// The hook's timeout.
    pub timeout: Duration,
}

/// A configured command split into what this check runs: the program word and the `adapt
/// codex` arguments. `None` when the command is not of the template's shape.
pub fn parse_command(command: &str) -> Option<(String, Vec<String>)> {
    let head = command.split(" || ").next()?.trim();
    let words: Vec<&str> = head.split_whitespace().collect();
    let (program, rest) = words.split_first()?;
    let plain = program
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-' | '~'));
    let name = program.rsplit('/').next().unwrap_or(program);
    if !plain || name != "safe-ai-skill" {
        return None;
    }
    match rest {
        ["adapt", "codex", entry] => Some((program.to_string(), vec![entry.to_string()])),
        ["adapt", "codex", "redact", flag] => Some((
            program.to_string(),
            vec!["redact".to_string(), flag.to_string()],
        )),
        _ => None,
    }
}

/// The hooks files Codex reads for a session in `cwd`: the user's and each project layer.
pub fn hook_files(home: Option<&Path>, codex_home: Option<&Path>, cwd: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    match (codex_home, home) {
        (Some(c), _) => files.push(c.join("hooks.json")),
        (None, Some(h)) => files.push(h.join(".codex").join("hooks.json")),
        _ => {}
    }
    for dir in cwd.ancestors() {
        let f = dir.join(".codex").join("hooks.json");
        if !files.contains(&f) {
            files.push(f);
        }
    }
    files.into_iter().filter(|f| f.is_file()).collect()
}

/// The commands in one hooks file that mention safe-ai-skill.
pub fn entries(file: &Path, text: &str) -> Result<Vec<Entry>, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("not JSON: {e}"))?;
    let mut out = Vec::new();
    let Some(events) = v.get("hooks").and_then(Value::as_object) else {
        return Ok(out);
    };
    for (event, groups) in events {
        for group in groups.as_array().into_iter().flatten() {
            for hook in group
                .get("hooks")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let Some(command) = hook.get("command").and_then(Value::as_str) else {
                    continue;
                };
                if !command.contains("safe-ai-skill") {
                    continue;
                }
                let timeout = hook
                    .get("timeout")
                    .and_then(Value::as_u64)
                    .map_or(DEFAULT_TIMEOUT, Duration::from_secs);
                out.push(Entry {
                    file: file.to_path_buf(),
                    event: event.clone(),
                    command: command.to_string(),
                    timeout,
                });
            }
        }
    }
    Ok(out)
}

/// A probe: the payload and what a working hook answers.
struct Probe {
    what: &'static str,
    payload: Value,
    expect: Expect,
}

#[derive(Clone, Copy, PartialEq)]
enum Expect {
    Deny,
    Pass,
    Block,
    SessionShape,
}

fn payload(cwd: &Path, event: &str, extra: Value) -> Value {
    let mut v = json!({
        "session_id": "safe-ai-skill-doctor",
        "transcript_path": null,
        "cwd": cwd,
        "hook_event_name": event,
        "model": "doctor",
        "permission_mode": "default",
        "turn_id": "doctor",
    });
    if let (Some(map), Some(extra)) = (v.as_object_mut(), extra.as_object()) {
        map.extend(extra.clone());
    }
    v
}

fn bash(cwd: &Path, command: &str) -> Value {
    payload(
        cwd,
        "PreToolUse",
        json!({"tool_name": "Bash", "tool_use_id": "doctor", "tool_input": {"command": command}}),
    )
}

fn probes(entry: &str, cwd: &Path) -> Vec<Probe> {
    match entry {
        "gate-bash" => vec![
            Probe {
                what: "a mainnet deploy is denied",
                payload: bash(cwd, "solana program deploy x.so --url mainnet-beta"),
                expect: Expect::Deny,
            },
            Probe {
                what: "`ls` passes",
                payload: bash(cwd, "ls"),
                expect: Expect::Pass,
            },
        ],
        "gate-bash-secrets" => vec![
            Probe {
                what: "an interactive `bash` is denied",
                payload: bash(cwd, "bash"),
                expect: Expect::Deny,
            },
            Probe {
                what: "`ls` passes",
                payload: bash(cwd, "ls"),
                expect: Expect::Pass,
            },
        ],
        "gate-tamper" => {
            let patch = |path: &str| {
                payload(
                    cwd,
                    "PreToolUse",
                    json!({"tool_name": "apply_patch", "tool_use_id": "doctor", "tool_input": {
                        "command": format!("*** Begin Patch\n*** Update File: {path}\n@@\n-a\n+b\n*** End Patch\n")
                    }}),
                )
            };
            vec![
                Probe {
                    what: "a patch to .codex/hooks.json is denied",
                    payload: patch(".codex/hooks.json"),
                    expect: Expect::Deny,
                },
                Probe {
                    what: "a patch to src/lib.rs passes",
                    payload: patch("src/lib.rs"),
                    expect: Expect::Pass,
                },
            ]
        }
        "gate-mcp" => vec![Probe {
            what: "an MCP SOL transfer is denied",
            payload: payload(
                cwd,
                "PreToolUse",
                json!({"tool_name": "mcp__helius__heliusWrite.sendSol", "tool_use_id": "doctor",
                       "tool_input": {"destination": "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",
                                      "lamports": 1_000_000_000u64}}),
            ),
            expect: Expect::Deny,
        }],
        "session-start" => vec![Probe {
            what: "it answers in Codex's SessionStart shape",
            payload: payload(cwd, "SessionStart", json!({"source": "startup"})),
            expect: Expect::SessionShape,
        }],
        "redact" => vec![Probe {
            what: "a result holding an API key is blocked",
            payload: payload(
                cwd,
                "PostToolUse",
                json!({"tool_name": "Bash", "tool_use_id": "doctor",
                       "tool_input": {"command": "cat creds"},
                       "tool_response": "key: AKIAIOSFODNN7EXAMPLE\n"}),
            ),
            expect: Expect::Block,
        }],
        _ => Vec::new(),
    }
}

struct Ran {
    code: Option<i32>,
    stdout: String,
    timed_out: bool,
}

/// Run `program adapt codex <args>` through `$SHELL -lc`, as Codex does, feeding `stdin`.
fn run(program: &str, args: &[String], cwd: &Path, stdin: &str, timeout: Duration) -> Ran {
    let shell = std::env::var("SHELL")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/bin/sh".to_string());
    let line = format!("{program} adapt codex {}", args.join(" "));
    let spawned = Command::new(shell)
        .arg("-lc")
        .arg(&line)
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let Ok(mut child) = spawned else {
        return Ran {
            code: None,
            stdout: String::new(),
            timed_out: false,
        };
    };
    if let Some(mut input) = child.stdin.take() {
        let _ = input.write_all(stdin.as_bytes());
    }
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if started.elapsed() < timeout => {
                std::thread::sleep(Duration::from_millis(20));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let mut stdout = String::new();
    if let Some(mut out) = child.stdout.take() {
        let _ = out.read_to_string(&mut stdout);
    }
    Ran {
        code: status.and_then(|s| s.code()),
        timed_out: status.is_none(),
        stdout,
    }
}

/// Why a probe's answer is wrong, or `None` when it is right.
fn judge(ran: &Ran, expect: Expect) -> Option<String> {
    if ran.timed_out {
        return Some("timed out: Codex would kill it and run the call".to_string());
    }
    match ran.code {
        Some(0) => {}
        Some(127) => {
            return Some(
                "exit 127: the command was not found, so Codex runs every call unchecked"
                    .to_string(),
            )
        }
        Some(c) => return Some(format!("exit {c}: Codex treats the hook as failed")),
        None => return Some("killed by a signal".to_string()),
    }
    let out = ran.stdout.trim();
    let v: Option<Value> = serde_json::from_str(out).ok();
    let decision = v
        .as_ref()
        .and_then(|v| v.pointer("/hookSpecificOutput/permissionDecision"))
        .and_then(Value::as_str);
    let reason = v
        .as_ref()
        .and_then(|v| v.pointer("/hookSpecificOutput/permissionDecisionReason"))
        .and_then(Value::as_str)
        .unwrap_or("");
    match expect {
        Expect::Deny if decision == Some("deny") && reason.contains("could not run") => Some(
            "the fallback answered: the safe-ai-skill command itself could not run".to_string(),
        ),
        Expect::Deny if decision == Some("deny") => None,
        Expect::Deny => Some(format!("expected a deny, got `{}`", short(out))),
        Expect::Pass if out.is_empty() => None,
        Expect::Pass => Some(format!("expected no output, got `{}`", short(out))),
        Expect::Block
            if v.as_ref()
                .is_some_and(|v| v["decision"] == "block" && !out.contains("AKIAIOSFODNN7")) =>
        {
            None
        }
        Expect::Block => Some(format!("expected a redacting block, got `{}`", short(out))),
        Expect::SessionShape => {
            let ok = out.is_empty()
                || v.as_ref().and_then(Value::as_object).is_some_and(|m| {
                    m.keys()
                        .all(|k| k == "systemMessage" || k == "hookSpecificOutput")
                });
            (!ok).then(|| format!("not Codex's SessionStart shape: `{}`", short(out)))
        }
    }
}

fn short(s: &str) -> String {
    let s: String = s.chars().take(160).collect();
    if s.is_empty() {
        "nothing".to_string()
    } else {
        s
    }
}

/// Whether the program word resolves (in a login shell) to the plugin shim, which turns
/// engine failures into blocks; `None` when it can't be told.
fn is_shim(program: &str, cwd: &Path) -> Option<bool> {
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
    let out = Command::new(shell)
        .arg("-lc")
        .arg(format!("command -v {program}"))
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let mut head = vec![0u8; 512];
    let n = std::fs::File::open(&path).ok()?.read(&mut head).ok()?;
    let text = String::from_utf8_lossy(&head[..n]);
    Some(text.starts_with("#!/bin/sh") && text.contains("safe-ai-skill platform-dispatch shim"))
}

/// The report and whether every check passed.
pub fn report(home: Option<&Path>, codex_home: Option<&Path>, cwd: &Path) -> (String, bool) {
    let mut lines = vec!["safe-ai-skill doctor --codex: Codex hook check".to_string()];
    let mut ok = true;
    let files = hook_files(home, codex_home, cwd);
    if files.is_empty() {
        lines.push(
            "  FAIL no Codex hooks.json with safe-ai-skill found (user or project); copy \
             adapters/codex/hooks.json (docs/adapters.md)"
                .to_string(),
        );
        return (lines.join("\n") + "\n", false);
    }
    let mut wired: Vec<String> = Vec::new();
    for file in &files {
        lines.push(format!("  {}", file.display()));
        let text = match std::fs::read_to_string(file) {
            Ok(t) => t,
            Err(e) => {
                lines.push(format!("    FAIL unreadable: {e}"));
                ok = false;
                continue;
            }
        };
        let found = match entries(file, &text) {
            Ok(f) => f,
            Err(e) => {
                lines.push(format!("    FAIL {e}"));
                ok = false;
                continue;
            }
        };
        for entry in found {
            let Some((program, args)) = parse_command(&entry.command) else {
                lines.push(format!(
                    "    WARN not run (not of the template's shape): {}",
                    entry.command
                ));
                continue;
            };
            let name = args.first().cloned().unwrap_or_default();
            wired.push(name.clone());
            if !entry.command.contains(" || ") && entry.event != "SessionStart" {
                lines.push(format!(
                    "    WARN {} {name}: no `|| printf …` fallback, so a command that cannot \
                     start fails open",
                    entry.event
                ));
            }
            if is_shim(&program, cwd) == Some(false) {
                lines.push(format!(
                    "    FAIL {} {name}: `{program}` is not the safe-ai-skill shim (the npm \
                     launcher or a bare engine?); an engine failure would fail open",
                    entry.event
                ));
                ok = false;
            }
            let checks = probes(&name, cwd);
            if checks.is_empty() {
                lines.push(format!("    FAIL {} {name}: unknown entry", entry.event));
                ok = false;
            }
            for probe in checks {
                let ran = run(
                    &program,
                    &args,
                    cwd,
                    &probe.payload.to_string(),
                    entry.timeout,
                );
                match judge(&ran, probe.expect) {
                    None => lines.push(format!("    ok   {} {name}: {}", entry.event, probe.what)),
                    Some(why) => {
                        ok = false;
                        lines.push(format!(
                            "    FAIL {} {name}: {}: {why}",
                            entry.event, probe.what
                        ));
                    }
                }
            }
        }
    }
    for gate in super::CODEX_GATES.iter().chain(["session-start"].iter()) {
        if !wired.iter().any(|w| w == gate) {
            lines.push(format!("  WARN `{gate}` is not wired in any hooks file"));
        }
    }
    lines.push(if ok {
        "  all hooks answered. Run this again after every safe-ai-skill or Codex update."
            .to_string()
    } else {
        "  some hooks would let Codex run calls unchecked; fix them, then re-approve with /hooks."
            .to_string()
    });
    (lines.join("\n") + "\n", ok)
}

/// `safe-ai-skill doctor --codex`: exit 0 when every check passes, 1 otherwise.
pub fn main() -> ExitCode {
    let var = |k: &str| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let (text, ok) = report(var("HOME").as_deref(), var("CODEX_HOME").as_deref(), &cwd);
    let _ = std::io::stdout().lock().write_all(text.as_bytes());
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_template_shaped_commands_are_run() {
        assert_eq!(
            parse_command("safe-ai-skill adapt codex gate-bash || printf x"),
            Some(("safe-ai-skill".into(), vec!["gate-bash".into()]))
        );
        assert_eq!(
            parse_command(
                "/home/u/.local/bin/safe-ai-skill adapt codex redact --block-with-redaction"
            ),
            Some((
                "/home/u/.local/bin/safe-ai-skill".into(),
                vec!["redact".into(), "--block-with-redaction".into()]
            ))
        );
        for bad in [
            "rm -rf ~; safe-ai-skill adapt codex gate-bash",
            "$(evil)/safe-ai-skill adapt codex gate-bash",
            "safe-ai-skill adapt codex gate-bash; evil",
            "evil adapt codex gate-bash",
            "safe-ai-skill gate-bash",
        ] {
            assert_eq!(parse_command(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_missing_command_is_reported_as_failing_open() {
        let ran = Ran {
            code: Some(127),
            stdout: String::new(),
            timed_out: false,
        };
        assert!(judge(&ran, Expect::Deny).unwrap().contains("127"));
        let fallback = Ran {
            code: Some(0),
            stdout: r#"{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"safe-ai-skill: the hook command could not run"}}"#.into(),
            timed_out: false,
        };
        assert!(judge(&fallback, Expect::Deny).is_some());
    }
}
