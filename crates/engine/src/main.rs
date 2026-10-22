//! `safe-ai-skill` binary — subcommand dispatch.
//!
//! This binary owns ALL stdin parsing, policy loading, context building, audit appends and
//! stdout emission so the feature modules stay pure and unit-testable. A gate returns a
//! `(Decision, GateMeta)`; this dispatcher runs the relaxation layer, audits, then emits the
//! authoritative JSON decision (nothing at all for no opinion) and exits 0. It never panics
//! on bad input: a payload it cannot read (over 1 MiB or malformed) is an `ask` on every
//! PreToolUse gate; empty stdin is no opinion except on `gate-bash`. An unknown or missing
//! subcommand prints nothing on stdout and exits 3.
//!
//! Subcommands are registered in [`SUBCOMMANDS`]: adding one is one line there plus its
//! handler.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{mpsc, Mutex};
use std::time::Duration;

use safe_ai_skill::audit::{self, AuditEntry};
use safe_ai_skill::context::{self, Context};
use safe_ai_skill::gate::{GateMeta, Scope};
use safe_ai_skill::io::{self, Decision, HookInput, Unreadable};
use safe_ai_skill::policy::Policy;
use safe_ai_skill::{grants, mode, promptguard, redact, registry, relax, session, verify};

/// Exit status for an invocation error (unknown or missing subcommand), distinct from a verdict.
const EXIT_USAGE: u8 = 3;

/// Reason for the `ask` on a PreToolUse payload over [`io::MAX_STDIN_BYTES`].
const OVERSIZED_REASON: &str =
    "safe-ai-skill: hook input exceeds 1 MiB and was not inspected; review this call manually.";

/// Reason for the `ask` on a PreToolUse payload the engine cannot parse.
const MALFORMED_REASON: &str =
    "safe-ai-skill: hook input is malformed and was not inspected; review this call manually.";

/// Bound on every PreToolUse gate (spec D1.3): past it the gate answers `ask`, well before
/// Claude Code's hook timeout.
const GATE_DEADLINE: Duration = Duration::from_secs(8);

/// Env var that may shorten (never lengthen) [`GATE_DEADLINE`], in milliseconds.
const DEADLINE_ENV: &str = "SAFE_AI_SKILL_DEADLINE_MS";

/// Lowest deadline [`DEADLINE_ENV`] can set outside unit tests.
const DEADLINE_FLOOR: Duration = Duration::from_secs(2);

/// Stack size of the gate worker thread.
const WORKER_STACK_BYTES: usize = 8 * 1024 * 1024;

/// Reason for the `ask` when a gate panics.
const CRASH_REASON: &str =
    "safe-ai-skill: the gate failed while inspecting this call; review this call manually.";

/// Reason for the `ask` when a gate misses its deadline.
const DEADLINE_REASON: &str =
    "safe-ai-skill: the gate did not finish within its time limit; review this call manually.";

/// The PreToolUse gates run under [`GATE_DEADLINE`].
const DEADLINE_GATES: &[&str] = &[
    "gate-bash",
    "gate-bash-secrets",
    "gate-read",
    "gate-mcp",
    "gate-skill",
];

/// The PreToolUse gates whose panic writes a hard-guard `ask` before the process ends
/// (release builds abort on panic, so the deadline path never sees it).
const PANIC_ASK_GATES: &[&str] = &[
    "gate-bash",
    "gate-bash-secrets",
    "gate-read",
    "gate-mcp",
    "gate-tamper",
    "gate-skill",
];

/// A subcommand handler: gets the arguments after the subcommand name.
type Handler = fn(&[String]) -> ExitCode;

/// The subcommand registry. A new subcommand is one line here. Names not listed exit 3
/// ([`cmd_unknown`]).
const SUBCOMMANDS: &[(&str, Handler)] = &[
    ("gate-bash", |_| cmd_gate_bash()),
    ("gate-bash-secrets", |_| cmd_gate_bash_secrets()),
    ("gate-read", |_| cmd_gate_read()),
    ("gate-mcp", |_| cmd_gate_mcp()),
    ("gate-tamper", |_| cmd_gate_tamper()),
    ("gate-skill", |_| cmd_no_opinion()),
    ("gate-prompt-expansion", |_| cmd_no_opinion()),
    ("redact", |_| cmd_redact()),
    ("prompt-guard", |_| cmd_prompt_guard()),
    ("verify", cmd_verify),
    ("add", cmd_add),
    ("install", cmd_install),
    ("registry", cmd_registry),
    ("session", cmd_session),
    ("allow", cmd_allow),
    ("mode", cmd_mode),
    ("revoke", |_| cmd_revoke()),
    ("status", |_| cmd_status()),
    ("--version", |_| cmd_version()),
];

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let sub = args.get(1).map(String::as_str).unwrap_or("");
    let rest: &[String] = if args.len() > 2 { &args[2..] } else { &[] };

    if PANIC_ASK_GATES.contains(&sub) {
        install_panic_ask();
    }
    match SUBCOMMANDS.iter().find(|(name, _)| *name == sub) {
        Some((name, handler)) if DEADLINE_GATES.contains(name) => {
            run_with_deadline(gate_deadline(), *handler, rest.to_vec())
        }
        Some((_, handler)) => handler(rest),
        None => cmd_unknown(sub),
    }
}

/// [`GATE_DEADLINE`], shortened by [`DEADLINE_ENV`] when it is set lower.
fn gate_deadline() -> Duration {
    deadline_from(std::env::var(DEADLINE_ENV).ok().as_deref())
}

/// The deadline for a [`DEADLINE_ENV`] value: milliseconds, capped at [`GATE_DEADLINE`] and
/// floored at [`DEADLINE_FLOOR`] (outside unit tests), so the environment cannot cut a gate
/// short enough to turn its deny into the deadline's ask.
fn deadline_from(value: Option<&str>) -> Duration {
    let floor = if cfg!(test) {
        Duration::ZERO
    } else {
        DEADLINE_FLOOR
    };
    value
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_millis)
        .map_or(GATE_DEADLINE, |d| d.clamp(floor, GATE_DEADLINE))
}

/// The decision the running gate reached, recorded before it audits and emits, so a
/// deadline that fires in between still emits a deny as a deny.
static DECIDED: Mutex<Option<Decision>> = Mutex::new(None);

/// Record the gate's final decision for the deadline path.
fn record_decision(decision: &Decision) {
    if let Ok(mut slot) = DECIDED.lock() {
        *slot = Some(decision.clone());
    }
}

/// What the deadline emits: the gate's deny if it already reached one, else an `ask` with
/// `reason`.
fn deadline_decision(reason: &str) -> Decision {
    match DECIDED.lock().ok().and_then(|slot| slot.clone()) {
        Some(deny @ Decision::Deny { .. }) => deny,
        _ => Decision::Ask {
            reason: reason.to_string(),
        },
    }
}

/// Run a gate under `budget`. Past it, or when the gate panics, emit an `ask` (the gate's
/// deny if it already decided one; nothing if it already answered) and exit 0: no gate fails
/// open.
fn run_with_deadline(budget: Duration, handler: Handler, rest: Vec<String>) -> ExitCode {
    let reason = match within(budget, move || {
        // Test-only crash trigger (the `test-hooks` feature is never built for release).
        #[cfg(feature = "test-hooks")]
        if std::env::var_os("SAFE_AI_SKILL_TEST_PANIC").is_some() {
            panic!("safe-ai-skill test panic");
        }
        handler(&rest)
    }) {
        Ok(code) => return code,
        Err(mpsc::RecvTimeoutError::Timeout) => DEADLINE_REASON,
        Err(mpsc::RecvTimeoutError::Disconnected) => CRASH_REASON,
    };
    let _ = io::emit_pretooluse(&deadline_decision(reason));
    std::process::exit(0)
}

/// On a panic, write the hard-guard `ask` (the gate's deny if it already reached one) before
/// the default report and the abort. Best effort: a write error is ignored, and a decision
/// already written is never followed by a second one.
fn install_panic_ask() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = io::emit_pretooluse(&deadline_decision(CRASH_REASON));
        default(info);
    }));
}

/// Run `f` on a worker thread (8 MiB stack) and wait at most `budget` for it: `Timeout`
/// when it is still running, `Disconnected` when it panicked or could not be started.
fn within<T: Send + 'static>(
    budget: Duration,
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, mpsc::RecvTimeoutError> {
    let (tx, rx) = mpsc::channel();
    let spawned = std::thread::Builder::new()
        .stack_size(WORKER_STACK_BYTES)
        .spawn(move || {
            let _ = tx.send(f());
        });
    if spawned.is_err() {
        return Err(mpsc::RecvTimeoutError::Disconnected);
    }
    rx.recv_timeout(budget)
}

/// A wired hook whose gate is not implemented yet: drain the payload, no opinion.
fn cmd_no_opinion() -> ExitCode {
    let _ = read_input();
    ExitCode::SUCCESS
}

/// What `--version` prints. One literal, so the release's binary version check
/// (`scripts/check-binary-versions.sh`) can also find it in a binary it can't run.
const VERSION_LINE: &str = concat!("safe-ai-skill ", env!("CARGO_PKG_VERSION"));

/// `--version` — one plain line, never hook JSON.
fn cmd_version() -> ExitCode {
    let _ = writeln!(std::io::stdout(), "{VERSION_LINE}");
    ExitCode::SUCCESS
}

/// The plugin data dir for a CLI command run from the user's terminal: the hooks' dir
/// ([`context::resolve_plugin_data_dir`]). When it can't be found, prints the guidance (JSON
/// on stdout, a line on stderr) and returns `None`; state is never put anywhere else.
fn cli_data_dir(command: &str) -> Option<PathBuf> {
    match context::resolve_plugin_data_dir() {
        Ok(dir) => Some(dir),
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "{e}");
            print_json(&serde_json::json!({
                "command": command,
                "status": "error",
                "error": e,
            }));
            None
        }
    }
}

/// Unknown or missing subcommand: nothing on stdout (a mis-wired hook has no opinion), the
/// error on stderr, and exit 3 so the shim and CI can tell it from a verdict.
fn cmd_unknown(sub: &str) -> ExitCode {
    let msg = if sub.is_empty() {
        "safe-ai-skill: missing subcommand".to_string()
    } else {
        format!("safe-ai-skill: unknown subcommand `{sub}`")
    };
    let _ = writeln!(std::io::stderr(), "{msg}");
    ExitCode::from(EXIT_USAGE)
}

/// Read the hook payload from stdin once, bounded at [`io::MAX_STDIN_BYTES`]: the bytes
/// received and their parse.
///
/// [`Unreadable::Oversized`] and [`Unreadable::Malformed`] are an `ask` on every PreToolUse
/// gate, since the model can force either through `tool_input`. [`Unreadable::Empty`] (no
/// payload, never sent by Claude Code) is no opinion except on `gate-bash`. The scanners
/// (`redact`, `prompt-guard`) have no opinion on any of them.
fn read_input() -> (Vec<u8>, Result<HookInput, Unreadable>) {
    io::read_payload(std::io::stdin())
}

/// Emit the fail-closed `ask` for a PreToolUse payload the engine could not inspect.
///
/// It runs under the hard-guard [`GateMeta::unreadable`], so no grant relaxes it, and is
/// audited as `unreadable` with the hash of the bytes received.
fn ask_unreadable(why: Unreadable, input: &HookInput, raw: &[u8]) -> ExitCode {
    let reason = match why {
        Unreadable::Oversized => OVERSIZED_REASON,
        Unreadable::Empty | Unreadable::Malformed => MALFORMED_REASON,
    };
    let cwd = cwd_of(input);
    let plugin_data = context::plugin_data_dir();
    let effective = load_effective_policy(&cwd, &plugin_data);
    let ask = Decision::Ask {
        reason: reason.to_string(),
    };
    let decision = relax::apply(ask, &GateMeta::unreadable(), &effective, &plugin_data);
    record_decision(&decision);
    write_audit(
        &effective,
        &plugin_data,
        input,
        raw,
        "unreadable",
        &decision,
    );
    let _ = io::emit_pretooluse(&decision);
    ExitCode::SUCCESS
}

/// Load the policy for `cwd` and resolve it to its EFFECTIVE form (profile overlay applied).
///
/// The persistent runtime override written by `safe-ai-skill mode <profile>` (`mode.json`)
/// replaces the policy's profile; the `SAFE_AI_SKILL_PROFILE` env var may then only select a
/// stricter one (see [`Policy::load_with_mode`]). This is what makes `safe-ai-skill mode
/// autopilot` actually take effect for every subsequent gate.
fn load_effective_policy(cwd: &Path, plugin_data: &Path) -> Policy {
    Policy::load_with_mode(cwd, mode::persisted(plugin_data).as_deref()).effective()
}

/// Resolve the session cwd from the hook payload, defaulting to the process cwd.
fn cwd_of(input: &HookInput) -> PathBuf {
    input
        .cwd
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

/// Run the full PreToolUse pipeline for a gate result: relax → audit → emit.
fn finish_pretooluse(
    natural: Decision,
    meta: &GateMeta,
    effective: &Policy,
    plugin_data: &Path,
    input: &HookInput,
    raw: &[u8],
) -> ExitCode {
    let decision = relax::apply(natural, meta, effective, plugin_data);
    record_decision(&decision);

    // Commit-on-allow: once the FINAL (post-relaxation) decision for a transfer with a
    // known amount is `Allow`, debit the daily spend ledger. The gate evaluated the
    // candidate with the non-committing `spend::check`, so this neither re-decides nor
    // double-counts. Grant-relaxed transfers debit the grant budget inside `relax::apply`;
    // they still count against the daily ledger here so the daily cap stays authoritative.
    if matches!(decision, Decision::Allow) && meta.scope == Scope::Transfer {
        if let Some(amount) = meta.amount_sol {
            safe_ai_skill::spend::commit(plugin_data, amount);
        }
    }

    write_audit(
        effective,
        plugin_data,
        input,
        raw,
        meta.scope.label(),
        &decision,
    );
    let _ = io::emit_pretooluse(&decision);
    ExitCode::SUCCESS
}

/// Current Unix time in seconds (`0` on clock error; never panics).
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Create a fresh `safe-ai-skill-install-<pid>-<nanos>[-n]` dir under the temp dir.
///
/// `create_dir` (not `_all`) fails on an existing dir, so a concurrent install never shares
/// (or removes) another's staging dir; a taken name is retried with a counter suffix.
fn create_staging_dir() -> std::io::Result<PathBuf> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let base = format!("safe-ai-skill-install-{}-{nanos}", std::process::id());
    let tmp = std::env::temp_dir();
    std::fs::create_dir_all(&tmp)?;
    let mut last = std::io::Error::from(std::io::ErrorKind::AlreadyExists);
    for n in 0..100u32 {
        let name = if n == 0 {
            base.clone()
        } else {
            format!("{base}-{n}")
        };
        let dir = tmp.join(name);
        match std::fs::create_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => last = e,
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

/// Audit a non-gate management event (grant create, mode change, revoke, …).
///
/// Unlike [`write_audit`] this is not tied to a hook payload; it records the CLI action with
/// a stable classification and a human-readable reason. Best-effort: a write failure is
/// swallowed so a management command never fails on an audit error.
fn audit_event(plugin_data: &Path, classification: &str, decision: &str, reason: &str) {
    let entry = AuditEntry::new(
        String::new(),
        "safe-ai-skill".to_string(),
        classification.to_string(),
        decision.to_string(),
        reason.to_string(),
        audit::sha256_hex(reason.as_bytes()),
    );
    let _ = audit::append(&entry, plugin_data);
}

/// Append an audit entry when auditing is enabled; `raw` is the stdin bytes received.
fn write_audit(
    policy: &Policy,
    plugin_data: &Path,
    input: &HookInput,
    raw: &[u8],
    classification: &str,
    decision: &Decision,
) {
    if !policy.audit.enabled {
        return;
    }
    let entry = AuditEntry::new(
        input.session_id.clone().unwrap_or_default(),
        input.tool_name.clone().unwrap_or_default(),
        classification.to_string(),
        decision.label().to_string(),
        decision.reason().to_string(),
        audit::sha256_hex(raw),
    );
    let _ = audit::append(&entry, plugin_data);
}

fn cmd_gate_bash() -> ExitCode {
    // The Solana surface fails closed: a payload it cannot read is an `ask`, even empty.
    let (raw, parsed) = read_input();
    let input = match parsed {
        Ok(input) => input,
        Err(why) => return ask_unreadable(why, &HookInput::default(), &raw),
    };
    let Some(command) = input.bash_command() else {
        return ask_unreadable(Unreadable::Malformed, &input, &raw);
    };
    let cwd = cwd_of(&input);
    let plugin_data = context::plugin_data_dir();
    let effective = load_effective_policy(&cwd, &plugin_data);
    let ctx = Context::build(command, &cwd);
    let (decision, meta) = safe_ai_skill::gates::bash::decide(command, &ctx, &effective);
    finish_pretooluse(decision, &meta, &effective, &ctx.plugin_data, &input, &raw)
}

fn cmd_gate_bash_secrets() -> ExitCode {
    let (raw, parsed) = read_input();
    let input = match parsed {
        Ok(input) => input,
        Err(Unreadable::Empty) => return ExitCode::SUCCESS,
        Err(why) => return ask_unreadable(why, &HookInput::default(), &raw),
    };
    let cwd = cwd_of(&input);
    let plugin_data = context::plugin_data_dir();
    let effective = load_effective_policy(&cwd, &plugin_data);
    let command = input.bash_command().unwrap_or("");
    // Secret reads are always a hard guard. A solana command the bash gate's `if` filters miss
    // is decided here too, under the bash gate's own meta.
    let (decision, meta) = safe_ai_skill::gates::bash::with_indirection_prefilter(
        safe_ai_skill::gates::secrets::decide(command, &cwd, &effective),
        GateMeta::new(Scope::SecretRead, true),
        command,
        &cwd,
        &effective,
    );
    finish_pretooluse(decision, &meta, &effective, &plugin_data, &input, &raw)
}

fn cmd_gate_read() -> ExitCode {
    let (raw, parsed) = read_input();
    let input = match parsed {
        Ok(input) => input,
        Err(Unreadable::Empty) => return ExitCode::SUCCESS,
        Err(why) => return ask_unreadable(why, &HookInput::default(), &raw),
    };
    let cwd = cwd_of(&input);
    let plugin_data = context::plugin_data_dir();
    let effective = load_effective_policy(&cwd, &plugin_data);
    let path = input.read_path().unwrap_or("");
    let decision = match safe_ai_skill::gates::read::decide(path, &effective) {
        Decision::Defer => safe_ai_skill::gates::read::guard_env_schema(path, &cwd),
        decided => decided,
    };
    let meta = GateMeta::new(Scope::SecretRead, true);
    finish_pretooluse(decision, &meta, &effective, &plugin_data, &input, &raw)
}

fn cmd_gate_mcp() -> ExitCode {
    let (raw, parsed) = read_input();
    let input = match parsed {
        Ok(input) => input,
        Err(Unreadable::Empty) => return ExitCode::SUCCESS,
        Err(why) => return ask_unreadable(why, &HookInput::default(), &raw),
    };
    let cwd = cwd_of(&input);
    let plugin_data = context::plugin_data_dir();
    let effective = load_effective_policy(&cwd, &plugin_data);
    let tool = input.tool_name.clone().unwrap_or_default();
    let payload = input.mcp_payload();
    let ctx = Context::build("", &cwd);
    let (decision, meta) = safe_ai_skill::gates::mcp::decide(&tool, payload, &ctx, &effective);
    finish_pretooluse(decision, &meta, &effective, &ctx.plugin_data, &input, &raw)
}

/// `Write|Edit|MultiEdit|NotebookEdit` tripwire: deny writes into safe-ai-skill's own state.
fn cmd_gate_tamper() -> ExitCode {
    let (raw, parsed) = read_input();
    let input = match parsed {
        Ok(input) => input,
        Err(Unreadable::Empty) => return ExitCode::SUCCESS,
        Err(why) => return ask_unreadable(why, &HookInput::default(), &raw),
    };
    let cwd = cwd_of(&input);
    let plugin_data = context::plugin_data_dir();
    let effective = load_effective_policy(&cwd, &plugin_data);
    let protected = safe_ai_skill::gates::tamper::Protected::from_env();
    let decision =
        safe_ai_skill::gates::tamper::decide_file(input.tool_input.as_ref(), &cwd, &protected);
    // A tamper verdict is final: no grant or profile relaxes it, so it skips `relax::apply`.
    write_audit(&effective, &plugin_data, &input, &raw, "tamper", &decision);
    let _ = io::emit_pretooluse(&decision);
    ExitCode::SUCCESS
}

fn cmd_redact() -> ExitCode {
    let Ok(input) = read_input().1 else {
        return ExitCode::SUCCESS;
    };
    let is_mcp = input
        .tool_name
        .as_deref()
        .map(|t| t.starts_with("mcp__"))
        .unwrap_or(false);
    let text = input
        .tool_output
        .as_ref()
        .and_then(|v| v.as_str().map(str::to_string))
        .or_else(|| input.tool_output.as_ref().map(|v| v.to_string()))
        .unwrap_or_default();
    let updated = redact::scrub(&text);
    let _ = io::emit_posttooluse_redact(updated, is_mcp);
    ExitCode::SUCCESS
}

fn cmd_prompt_guard() -> ExitCode {
    let Ok(input) = read_input().1 else {
        return ExitCode::SUCCESS;
    };
    let prompt = input.prompt.clone().unwrap_or_default();
    let block = promptguard::check(&prompt);
    let _ = io::emit_userpromptsubmit(block.as_deref());
    ExitCode::SUCCESS
}

fn cmd_verify(rest: &[String]) -> ExitCode {
    let action = rest.first().map(String::as_str).unwrap_or("session");
    match action {
        "session" => cmd_verify_session(),
        "approve" => cmd_verify_approve(rest.get(1).map(String::as_str).unwrap_or("")),
        "check" => {
            let target = rest.get(1).map(String::as_str).unwrap_or("");
            let report = verify::pipeline_dir(Path::new(target), None);
            print_json(&serde_json::json!({
                "command": "verify check",
                "target": target,
                "verdict": verify::verdict(&report).label(),
                "findings": report.findings,
            }));
            ExitCode::SUCCESS
        }
        _ => {
            print_json(&serde_json::json!({ "error": "unknown verify subcommand" }));
            ExitCode::SUCCESS
        }
    }
}

/// `verify session` — the SessionStart supply-chain sweep (report-only, nothing is moved).
///
/// Runs [`verify::run_session`] (skill packs + the project `.mcp.json`) and emits the
/// SessionStart report (`systemMessage` for the user + `additionalContext` for the model) — or
/// nothing when there is nothing to report.
fn cmd_verify_session() -> ExitCode {
    // SessionStart hooks may carry a cwd on stdin; fall back to the process cwd.
    let input = read_input().1.unwrap_or_default();
    let cwd = cwd_of(&input);
    let plugin_data = context::plugin_data_dir();
    let effective = load_effective_policy(&cwd, &plugin_data);

    let mut res = verify::run_session(&plugin_data, &cwd, &effective);

    // Overrides the policy ratchet refused (project overlay, looser profile env var): shown to
    // the user and given to the model.
    if let Some(notice) = effective.ignored_notice() {
        for field in [&mut res.system_message, &mut res.additional_context] {
            if !field.is_empty() {
                field.push('\n');
            }
            field.push_str(&notice);
        }
    }

    if let Some(out) = res.hook_output() {
        print_json(&out);
    }
    ExitCode::SUCCESS
}

/// `verify approve <name>` — accept a pack: restore one an earlier version quarantined, or
/// re-pin a drifted one where it is.
fn cmd_verify_approve(name: &str) -> ExitCode {
    if name.is_empty() {
        print_json(&serde_json::json!({
            "command": "verify approve",
            "status": "error",
            "error": "usage: verify approve <skill-name>",
        }));
        return ExitCode::SUCCESS;
    }
    let Some(plugin_data) = cli_data_dir("verify approve") else {
        return ExitCode::FAILURE;
    };
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    // `.gitmodules` and the swept roots resolve at the repo root, from any subdirectory.
    let project = verify::project_root(&cwd);
    let effective = load_effective_policy(&project, &plugin_data);

    match verify::approve(&plugin_data, &project, name, &effective) {
        Ok(approval) => {
            audit_event(
                &plugin_data,
                "verify_approve",
                "approve",
                &format!("skill={name}"),
            );
            let (key, value) = match approval {
                verify::Approval::Restored(path) => {
                    ("restored_to", serde_json::json!(path.display().to_string()))
                }
                verify::Approval::PinnedInPlace(paths) => (
                    "pinned_in_place",
                    serde_json::json!(paths
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect::<Vec<_>>()),
                ),
            };
            let mut out = serde_json::json!({
                "command": "verify approve",
                "status": "approved",
                "skill": name,
            });
            if let Some(map) = out.as_object_mut() {
                map.insert(key.to_string(), value);
            }
            print_json(&out);
        }
        Err(e) => {
            print_json(&serde_json::json!({
                "command": "verify approve",
                "status": "error",
                "skill": name,
                "error": e.to_string(),
            }));
        }
    }
    ExitCode::SUCCESS
}

fn cmd_add(rest: &[String]) -> ExitCode {
    let kind = rest.first().map(String::as_str).unwrap_or("");
    let source = rest.get(1).map(String::as_str).unwrap_or("");
    // `add` is a user-invoked install, so the (otherwise isolated) network steps are allowed:
    // an `--online` flag (default on for `add`) lets provenance hit the npm/osv registries.
    let online = !rest.iter().any(|a| a == "--offline");
    let force = rest.iter().any(|a| a == "--yes" || a == "--force");

    if source.is_empty() {
        print_json(&serde_json::json!({
            "command": "add",
            "status": "error",
            "error": "usage: add skill|mcp|repo <source>",
        }));
        return ExitCode::SUCCESS;
    }

    let Some(plugin_data) = cli_data_dir("add") else {
        return ExitCode::FAILURE;
    };

    // Catalog high-risk gate (runs BEFORE the verify/install pipeline). If the target resolves
    // to a known high-risk registry entry (`phantom-mcp` wallet signing, `x402-proxy-mcp` key
    // custody, …), force the class decision (`ask`/`deny`) and refuse to emit the install
    // command — the verify pipeline never even runs. A `deny` blocks outright; an `ask` holds
    // unless `--yes`.
    if let Some((entry_id, risk_class, decision)) = resolve_high_risk_target(&plugin_data, source) {
        let blocked = decision == "deny" || (decision == "ask" && !force);
        if blocked {
            audit_event(
                &plugin_data,
                "add_high_risk_gate",
                decision,
                &format!("id={entry_id} class={risk_class} source={source}"),
            );
            print_json(&serde_json::json!({
                "command": "add",
                "kind": kind,
                "source": source,
                "verdict": "high_risk",
                "status": if decision == "deny" { "high_risk_deny" } else { "high_risk_ask" },
                "risk_class": risk_class,
                "decision": decision,
                "entry_id": entry_id,
                "reason": high_risk_add_reason(risk_class, &entry_id),
                "proceed": false,
                "run": serde_json::Value::Null,
            }));
            return ExitCode::SUCCESS;
        }
        // `ask` + `--yes`: the user explicitly confirmed; record it and fall through to verify.
        audit_event(
            &plugin_data,
            "add_high_risk_confirm",
            "ask",
            &format!("id={entry_id} class={risk_class} source={source} confirmed=true"),
        );
    }

    // mcp → npm package provenance (+ osv); skill/repo → directory/source heuristics.
    let report = match kind {
        "mcp" => verify::pipeline_npm(source, online),
        _ => {
            let dir = verify::expand_home(source);
            if dir.is_dir() {
                verify::pipeline_dir(&dir, Some(source))
            } else {
                // A non-local source (e.g. a GitHub URL): provenance-only, no tree to scan.
                verify::pipeline_npm(source, online)
            }
        }
    };

    let verdict = verify::verdict(&report);
    let findings: Vec<serde_json::Value> = report
        .findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "severity": verify::severity_label(f.severity),
                "kind": f.kind,
                "detail": f.detail,
            })
        })
        .collect();

    // The underlying install command emitted on pass (or warn + confirm).
    let install_cmd = underlying_install_cmd(kind, source);

    let (status, proceed) = match verdict {
        verify::Verdict::Block => ("blocked", false),
        // Warn proceeds only with an explicit confirm flag; default is the safe refusal.
        verify::Verdict::Warn => {
            if force {
                ("warn_proceed", true)
            } else {
                ("warn_hold", false)
            }
        }
        verify::Verdict::Pass => ("pass", true),
    };

    if proceed {
        audit_event(
            &plugin_data,
            "add_approve",
            "add",
            &format!("kind={kind} source={source} verdict={}", verdict.label()),
        );
    }

    print_json(&serde_json::json!({
        "command": "add",
        "kind": kind,
        "source": source,
        "verdict": verdict.label(),
        "status": status,
        "findings": findings,
        "proceed": proceed,
        "run": if proceed { serde_json::Value::String(install_cmd) } else { serde_json::Value::Null },
    }));
    ExitCode::SUCCESS
}

/// Resolve an `add <source>` target against the project catalog and classify it.
///
/// Loads the project `skill-registry.json` (path from `policy.catalog.registry_path`) and tries
/// to match `source` to a [`registry::RegistryEntry`] — first by exact `id`, then by exact
/// `source` URL. If the matched entry is high-risk (per [`registry::Registry::high_risk`]),
/// returns `(entry_id, class_kind, forced_decision)` where `forced_decision` is `ask`/`deny`
/// from [`registry::Registry::decision_for_kind`]. Returns `None` when there is no catalog, no
/// matching entry, or the entry is not high-risk — in which case `add` proceeds to its normal
/// verify pipeline. Never panics; a missing/unparseable catalog yields `None`.
fn resolve_high_risk_target(
    plugin_data: &Path,
    source: &str,
) -> Option<(String, &'static str, &'static str)> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let policy = load_effective_policy(&cwd, plugin_data);
    let reg_path = cwd.join(&policy.catalog.registry_path);
    let reg = registry::Registry::load(&reg_path).ok()?;

    let entry = reg
        .entry_by_id(source)
        .or_else(|| reg.entries.iter().find(|e| e.source == source))?;

    let kind = registry::Registry::high_risk(entry, &policy)?;
    let decision = registry::Registry::decision_for_kind(&policy, &kind).unwrap_or("ask");
    // Intern the dynamic strings to &'static via a small known set so the caller can pass them
    // into JSON without lifetime juggling.
    Some((
        entry.id.clone(),
        intern_class(&kind),
        intern_decision(decision),
    ))
}

/// Map a class kind string to a stable `&'static str` (falls back to a generic label).
fn intern_class(kind: &str) -> &'static str {
    match kind {
        "wallet_signing" => "wallet_signing",
        "key_custody" => "key_custody",
        "installer_script" => "installer_script",
        _ => "high_risk",
    }
}

/// Map a forced-decision string to a stable `&'static str` (`deny` only when explicit).
fn intern_decision(decision: &str) -> &'static str {
    match decision {
        "deny" => "deny",
        _ => "ask",
    }
}

/// A human-readable reason for a high-risk `add` gate.
fn high_risk_add_reason(kind: &str, entry_id: &str) -> String {
    match kind {
        "wallet_signing" => format!(
            "`{entry_id}` is a high-risk wallet-signing catalog entry (can sign/submit transactions) — re-run with --yes to confirm"
        ),
        "key_custody" => format!(
            "`{entry_id}` is a high-risk key-custody catalog entry (holds/derives private keys) — re-run with --yes to confirm"
        ),
        "installer_script" => format!(
            "`{entry_id}` runs a download-and-execute installer (`curl … | bash`) — re-run with --yes to confirm"
        ),
        other => format!(
            "`{entry_id}` is a high-risk catalog entry ({other}) — re-run with --yes to confirm"
        ),
    }
}

/// The underlying installer command `add` emits on a pass (the user runs it to install).
fn underlying_install_cmd(kind: &str, source: &str) -> String {
    match kind {
        "skill" => format!("npx skills add {source}"),
        "repo" => format!("git clone {source}"),
        "mcp" => format!("claude mcp add {source}"),
        _ => format!("install {source}"),
    }
}

/// `install` — hub-agnostic secure skills installer / in-place verifier.
///
/// Runs the intrinsic verification pipeline over each skill directory in a LOCAL source,
/// neutralizes any telemetry preamble in its `SKILL.md`, and installs ONLY the skills that
/// pass. There is NO hardcoded download URL: the remote `skills.tar.gz` tarball path is
/// retired (decision 2026-06-16). The source is always local.
///
/// - `--from <dir-or-tarball>`: install from a local extracted directory or a local
///   `.tar.gz`/`.tgz`. A local directory is used directly; a local tarball is extracted via
///   `tar` (subprocess is acceptable here — `install` is a one-shot user-invoked command, not
///   a gate hot path, so shelling out keeps the binary zero-new-dep).
/// - no `--from`: operate on the current project's `.claude/skills` (verify-in-place) — no
///   download, no copy; each immediate skill subdirectory is scanned and pinned (TOFU) in
///   place. This is the post-`install.sh` audit path for the kit's project layout.
/// - `--home <dir>` (or the `SAFE_AI_SKILL_HOME` env var): write installed skills under
///   `<dir>/.claude/skills` instead of the real `~/.claude/skills`, so a sandboxed test never
///   touches the user's home. `--from`/`--home` are independent and composable. Ignored in the
///   verify-in-place (no `--from`) mode, which never copies.
///
/// Never widens `settings.json`. A skill with a High finding is held unless `--yes`.
fn cmd_install(rest: &[String]) -> ExitCode {
    let force = rest.iter().any(|a| a == "--yes" || a == "--force");
    let Some(plugin_data) = cli_data_dir("install") else {
        return ExitCode::FAILURE;
    };

    // Optional local source (`--from`) and test home override (`--home` / env).
    let from = flag_value(rest, "--from");
    let home_override = flag_value(rest, "--home")
        .or_else(|| std::env::var("SAFE_AI_SKILL_HOME").ok())
        .filter(|s| !s.trim().is_empty());

    // No `--from`: verify the current project's `.claude/skills` in place (no download/copy).
    if from.is_none() {
        return install_verify_in_place(&plugin_data, force);
    }

    // Stage under a unique temp dir we own (never /tmp directly; honor TMPDIR).
    let stage = match create_staging_dir() {
        Ok(stage) => stage,
        Err(e) => return install_err(&format!("could not create staging dir: {e}")),
    };
    let extract = stage.join("extract");
    let _ = std::fs::create_dir_all(&extract);

    // Resolve the source dir holding skill subdirectories from a LOCAL source only:
    //   (a) `--from <dir>`     → use the local directory directly (no tar).
    //   (b) `--from <tarball>` → extract the local tarball.
    let extract_dir: PathBuf = {
        let src = from.as_deref().unwrap_or_default();
        let src_path = verify::expand_home(src);
        if src_path.is_dir() {
            src_path
        } else if src_path.is_file() {
            let tar = std::process::Command::new("tar")
                .args([
                    "-xzf",
                    &src_path.display().to_string(),
                    "-C",
                    &extract.display().to_string(),
                ])
                .status();
            match tar {
                Ok(s) if s.success() => extract.clone(),
                Ok(s) => {
                    let _ = std::fs::remove_dir_all(&stage);
                    return install_err(&format!("tar failed with status {s}"));
                }
                Err(e) => {
                    let _ = std::fs::remove_dir_all(&stage);
                    return install_err(&format!("could not run tar: {e}"));
                }
            }
        } else {
            let _ = std::fs::remove_dir_all(&stage);
            return install_err(&format!("--from source not found: {src}"));
        }
    };

    // Verify + neutralize + install each skill directory.
    //
    // The install root honors `--home`/`SAFE_AI_SKILL_HOME` (`<home>/.claude/skills`) so a
    // sandboxed test never touches the real `~/.claude/skills`. `install` intentionally never
    // writes/widens `<home>/.claude/settings.json` (unlike a typical kit `setup.sh`).
    let install_root = match &home_override {
        Some(home) => PathBuf::from(home).join(".claude").join("skills"),
        None => verify::expand_home("~/.claude/skills"),
    };
    let _ = std::fs::create_dir_all(&install_root);
    let mut lock = verify::lockfile::load(&plugin_data);

    let mut installed: Vec<String> = Vec::new();
    let mut held: Vec<serde_json::Value> = Vec::new();
    let mut flagged: Vec<serde_json::Value> = Vec::new();

    for dir in skill_dirs_under(&extract_dir) {
        let name = match dir.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };

        // Scan the ORIGINAL (pre-neutralization) content first so the telemetry curl and
        // any other danger are reported to the user. Then neutralize the telemetry preamble
        // in SKILL.md before the installed copy is written.
        let pre_report = verify::pipeline_dir(&dir, None);
        for f in &pre_report.findings {
            flagged.push(serde_json::json!({
                "skill": name,
                "severity": verify::severity_label(f.severity),
                "kind": f.kind,
                "detail": f.detail,
            }));
        }

        // Neutralize telemetry in SKILL.md before scanning/installing.
        let skill_md = dir.join("SKILL.md");
        if let Ok(body) = std::fs::read_to_string(&skill_md) {
            let (cleaned, changed) = verify::neutralize_telemetry(&body);
            if changed {
                let _ = std::fs::write(&skill_md, cleaned);
            }
        }

        // Re-scan the neutralized content: this is the verdict the install gate uses, so a
        // skill whose ONLY danger was the (now-removed) telemetry preamble installs cleanly.
        let report = verify::pipeline_dir(&dir, None);
        let verdict = verify::verdict(&report);

        let proceed = match verdict {
            verify::Verdict::Pass => true,
            verify::Verdict::Warn => force,
            verify::Verdict::Block => false,
        };

        if !proceed {
            held.push(serde_json::json!({
                "skill": name,
                "verdict": verdict.label(),
                "findings": report.findings.len(),
            }));
            continue;
        }

        let dest = install_root.join(&name);
        if dest.exists() {
            let _ = std::fs::remove_dir_all(&dest);
        }
        if let Err(e) = copy_dir_recursive(&dir, &dest) {
            held.push(serde_json::json!({
                "skill": name,
                "verdict": verdict.label(),
                "error": format!("install failed: {e}"),
            }));
            continue;
        }

        // Pin the installed content (TOFU), marked as an install so the session sweep checks it.
        // The recorded source is the canonical local `--from` path.
        let pin_source = from
            .as_deref()
            .and_then(|src| std::fs::canonicalize(verify::expand_home(src)).ok())
            .map(|path| path.display().to_string())
            .or_else(|| from.clone())
            .unwrap_or_default();
        let hash = verify::lockfile::hash_tree(&dest);
        lock.pin_skill(
            &name,
            verify::lockfile::SkillPin {
                sha256: hash,
                source: pin_source,
                verified_at: now_secs(),
                scan: report
                    .max_severity()
                    .map(verify::severity_label)
                    .unwrap_or("")
                    .to_string(),
                origin: verify::lockfile::ORIGIN_INSTALL.to_string(),
            },
        );
        installed.push(name);
    }

    let _ = verify::lockfile::save(&plugin_data, &lock);
    let _ = std::fs::remove_dir_all(&stage);

    audit_event(
        &plugin_data,
        "install",
        "install",
        &format!("installed={} held={}", installed.len(), held.len()),
    );

    print_json(&serde_json::json!({
        "command": "install",
        "status": "done",
        "installed": installed,
        "held": held,
        "flagged": flagged,
        "install_root": install_root.display().to_string(),
    }));
    ExitCode::SUCCESS
}

/// Emit an install error result line.
fn install_err(msg: &str) -> ExitCode {
    print_json(&serde_json::json!({
        "command": "install",
        "status": "error",
        "error": msg,
    }));
    ExitCode::SUCCESS
}

/// `install` with no `--from`: verify the current project's `.claude/skills` in place.
///
/// No download, no copy: each immediate skill subdirectory under `<cwd>/.claude/skills` is
/// scanned (and its telemetry preamble neutralized in place), then pinned (TOFU) in the
/// lockfile. A High finding holds the skill (reported, not installed) unless `--yes`. This is
/// the post-`install.sh` audit path for the kit's project layout.
fn install_verify_in_place(plugin_data: &Path, force: bool) -> ExitCode {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let skills_root = cwd.join(".claude").join("skills");
    if !skills_root.is_dir() {
        return install_err(&format!(
            "no --from and no project skills dir at {}",
            skills_root.display()
        ));
    }

    let mut lock = verify::lockfile::load(plugin_data);
    let mut verified: Vec<String> = Vec::new();
    let mut held: Vec<serde_json::Value> = Vec::new();
    let mut flagged: Vec<serde_json::Value> = Vec::new();

    for dir in skill_dirs_under(&skills_root) {
        let name = match dir.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };

        let pre_report = verify::pipeline_dir(&dir, None);
        for f in &pre_report.findings {
            flagged.push(serde_json::json!({
                "skill": name,
                "severity": verify::severity_label(f.severity),
                "kind": f.kind,
                "detail": f.detail,
            }));
        }

        let skill_md = dir.join("SKILL.md");
        if let Ok(body) = std::fs::read_to_string(&skill_md) {
            let (cleaned, changed) = verify::neutralize_telemetry(&body);
            if changed {
                let _ = std::fs::write(&skill_md, cleaned);
            }
        }

        let report = verify::pipeline_dir(&dir, None);
        let verdict = verify::verdict(&report);
        let proceed = match verdict {
            verify::Verdict::Pass => true,
            verify::Verdict::Warn => force,
            verify::Verdict::Block => false,
        };
        if !proceed {
            held.push(serde_json::json!({
                "skill": name,
                "verdict": verdict.label(),
                "findings": report.findings.len(),
            }));
            continue;
        }

        let hash = verify::lockfile::hash_tree(&dir);
        lock.pin_skill(
            &name,
            verify::lockfile::SkillPin {
                sha256: hash,
                source: skills_root.display().to_string(),
                verified_at: now_secs(),
                scan: report
                    .max_severity()
                    .map(verify::severity_label)
                    .unwrap_or("")
                    .to_string(),
                origin: verify::lockfile::ORIGIN_IN_PLACE.to_string(),
            },
        );
        verified.push(name);
    }

    let _ = verify::lockfile::save(plugin_data, &lock);
    audit_event(
        plugin_data,
        "install",
        "verify_in_place",
        &format!("verified={} held={}", verified.len(), held.len()),
    );

    print_json(&serde_json::json!({
        "command": "install",
        "status": "done",
        "mode": "verify_in_place",
        "verified": verified,
        "held": held,
        "flagged": flagged,
        "skills_root": skills_root.display().to_string(),
    }));
    ExitCode::SUCCESS
}

/// `registry verify|list` — opt-in catalog audit / listing.
///
/// Loads the project `.claude/skills/skill-registry.json` (path from
/// `policy.catalog.registry_path`) via [`registry::Registry::load`] and either:
/// - `list`: prints every entry with its opt-in status and derived `risk_class`; or
/// - `verify`: additionally resolves each high-risk entry to its forced class decision
///   (`ask`/`deny`) via [`registry::Registry::decision_for_kind`] and writes one audit entry
///   per high-risk entry so the catalog's dangerous opt-ins (`phantom-mcp`, `x402-proxy-mcp`,
///   …) leave a loud record.
///
/// A missing registry file degrades to an empty catalog (count 0), so both actions are safe to
/// run on a project that has not opted into the catalog.
fn cmd_registry(rest: &[String]) -> ExitCode {
    let action = rest.first().map(String::as_str).unwrap_or("list");
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let Some(plugin_data) = cli_data_dir("registry") else {
        return ExitCode::FAILURE;
    };
    let policy = load_effective_policy(&cwd, &plugin_data);
    let reg_path = cwd.join(&policy.catalog.registry_path);

    if action != "verify" && action != "list" {
        print_json(&serde_json::json!({
            "command": "registry",
            "status": "error",
            "error": "usage: registry verify|list",
        }));
        return ExitCode::SUCCESS;
    }

    let reg = registry::Registry::load(&reg_path).unwrap_or_default();
    let auditing = action == "verify";
    let mut high_risk_count = 0usize;
    let entries: Vec<serde_json::Value> = reg
        .entries
        .iter()
        .map(|e| {
            let risk = registry::Registry::high_risk(e, &policy);
            // `verify` surfaces the forced class decision (ask/deny) and audits the entry.
            let decision = risk
                .as_deref()
                .and_then(|kind| registry::Registry::decision_for_kind(&policy, kind));
            if auditing && risk.is_some() {
                high_risk_count += 1;
                audit_event(
                    &plugin_data,
                    "registry_high_risk",
                    decision.unwrap_or("ask"),
                    &format!(
                        "id={} class={} opt_in={}",
                        e.id,
                        risk.as_deref().unwrap_or(""),
                        e.is_opt_in()
                    ),
                );
            }
            serde_json::json!({
                "id": e.id,
                "title": e.title,
                "category": e.category,
                "opt_in": e.is_opt_in(),
                "default_installed": e.default_installed,
                "risk_class": risk,
                "decision": decision,
            })
        })
        .collect();

    print_json(&serde_json::json!({
        "command": "registry",
        "action": action,
        "registry_path": reg_path.display().to_string(),
        "count": entries.len(),
        "high_risk": high_risk_count,
        "entries": entries,
    }));
    ExitCode::SUCCESS
}

/// Immediate child directories of `root` that look like skills (contain a `SKILL.md`),
/// or any immediate child directory when none carry one (flat tarball layouts).
fn skill_dirs_under(root: &Path) -> Vec<PathBuf> {
    let mut with_md: Vec<PathBuf> = Vec::new();
    let mut all_dirs: Vec<PathBuf> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                all_dirs.push(p.clone());
                if p.join("SKILL.md").is_file() {
                    with_md.push(p);
                }
            }
        }
    }
    if with_md.is_empty() {
        all_dirs
    } else {
        with_md
    }
}

/// Recursively copy `src` directory into `dst` (creating `dst`). Best-effort, no symlink follow.
fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        let ft = entry.file_type()?;
        if ft.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else if ft.is_file() {
            std::fs::copy(&from, &to)?;
        }
        // Symlinks are intentionally skipped (avoid escaping the install root).
    }
    Ok(())
}

fn cmd_session(rest: &[String]) -> ExitCode {
    let action = rest.first().map(String::as_str).unwrap_or("status");
    let Some(plugin_data) = cli_data_dir("session") else {
        return ExitCode::FAILURE;
    };
    let result = match action {
        "init" => {
            let cap = rest
                .iter()
                .position(|a| a == "--cap")
                .and_then(|i| rest.get(i + 1))
                .and_then(|v| v.parse::<f64>().ok())
                .unwrap_or(0.0);
            session::init(cap, &plugin_data).unwrap_or_default()
        }
        _ => session::status(&plugin_data).unwrap_or_default(),
    };
    print_json(&serde_json::json!({ "command": "session", "action": action, "result": result }));
    ExitCode::SUCCESS
}

fn cmd_allow(rest: &[String]) -> ExitCode {
    // Parse --scope --for --max-tx --budget --programs --to --danger, build a grant, and
    // persist it. Creating a grant is an authority-granting action, so it is always audited.
    let scope = flag_value(rest, "--scope").unwrap_or_default();
    let for_dur = flag_value(rest, "--for").unwrap_or_default();
    let max_tx = flag_value(rest, "--max-tx")
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.0);
    let budget = flag_value(rest, "--budget")
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.0);
    let programs = flag_value(rest, "--programs").unwrap_or_default();
    let to = flag_value(rest, "--to").unwrap_or_default();
    let danger = rest.iter().any(|a| a == "--danger");

    let Some(plugin_data) = cli_data_dir("allow") else {
        return ExitCode::FAILURE;
    };
    let now = now_secs();

    let grant = match grants::Grant::from_args(
        &scope, &for_dur, max_tx, budget, &programs, &to, danger, now,
    ) {
        Some(g) => g,
        None => {
            print_json(&serde_json::json!({
                "command": "allow",
                "status": "error",
                "error": "could not parse --scope / --for; expected e.g. --scope swap --for 30m",
            }));
            return ExitCode::SUCCESS;
        }
    };

    let mut store = grants::load(&plugin_data);
    let grant_id = grant.id.clone();
    let grant_scope = grant.scope.label();
    let grant_expiry = grant.expires_at;
    store.grants.push(grant);
    let _ = grants::save(&plugin_data, &store);

    // Audit the grant creation.
    audit_event(
        &plugin_data,
        "grant_create",
        "allow",
        &format!(
            "scope={grant_scope} max_tx={max_tx} budget={budget} expires_at={grant_expiry} danger={danger}"
        ),
    );

    print_json(&serde_json::json!({
        "command": "allow",
        "status": "granted",
        "id": grant_id,
        "scope": grant_scope,
        "for": for_dur,
        "max_tx_sol": max_tx,
        "budget_sol": budget,
        "programs": programs,
        "to": to,
        "danger": danger,
        "expires_at": grant_expiry,
    }));
    ExitCode::SUCCESS
}

fn cmd_mode(rest: &[String]) -> ExitCode {
    let Some(plugin_data) = cli_data_dir("mode") else {
        return ExitCode::FAILURE;
    };
    match rest.first() {
        Some(profile) => match mode::set(&plugin_data, profile) {
            Ok(()) => {
                audit_event(
                    &plugin_data,
                    "mode_set",
                    "mode",
                    &format!("active_profile={profile}"),
                );
                print_json(&serde_json::json!({
                    "command": "mode",
                    "status": "set",
                    "active_profile": profile,
                }));
            }
            Err(e) => {
                print_json(&serde_json::json!({
                    "command": "mode",
                    "status": "error",
                    "error": e.to_string(),
                }));
            }
        },
        None => {
            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            let current = load_effective_policy(&cwd, &plugin_data).active_profile;
            print_json(&serde_json::json!({ "command": "mode", "active_profile": current }));
        }
    }
    ExitCode::SUCCESS
}

fn cmd_revoke() -> ExitCode {
    let Some(plugin_data) = cli_data_dir("revoke") else {
        return ExitCode::FAILURE;
    };
    let cleared = grants::load(&plugin_data).grants.len();
    let _ = grants::save(&plugin_data, &grants::Grants::default());
    audit_event(
        &plugin_data,
        "grant_revoke",
        "revoke",
        &format!("cleared={cleared}"),
    );
    print_json(&serde_json::json!({
        "command": "revoke",
        "status": "grants cleared",
        "cleared": cleared,
    }));
    ExitCode::SUCCESS
}

fn cmd_status() -> ExitCode {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let Some(plugin_data) = cli_data_dir("status") else {
        return ExitCode::FAILURE;
    };
    let effective = load_effective_policy(&cwd, &plugin_data);

    // Live grants with derived remaining-budget / time-left.
    let now = now_secs();
    let live = grants::load(&plugin_data);
    let grants_view: Vec<serde_json::Value> = live
        .grants
        .iter()
        .map(|g| {
            let time_left = g.expires_at.saturating_sub(now);
            serde_json::json!({
                "id": g.id,
                "scope": g.scope.label(),
                "remaining_sol": g.remaining_sol(),
                "budget_sol": g.budget_sol,
                "max_tx_sol": g.max_tx_sol,
                "time_left_secs": time_left,
                "expired": g.is_expired(now),
                "danger": g.danger,
            })
        })
        .collect();

    // Today's spend against the effective caps.
    let ledger = safe_ai_skill::spend::SpendLedger::load(&plugin_data);
    let spend_view = serde_json::json!({
        "today_sol": ledger.total_sol,
        "per_tx_sol_max": effective.spend.per_tx_sol_max,
        "hard_tx_sol_max": effective.spend.hard_tx_sol_max,
        "daily_sol_max": effective.spend.daily_sol_max,
    });

    print_json(&serde_json::json!({
        "command": "status",
        "plugin_data": plugin_data.display().to_string(),
        "active_profile": effective.active_profile,
        "grants": grants_view,
        "spend": spend_view,
        "recent_audit": recent_audit_lines(&plugin_data, 5),
    }));
    ExitCode::SUCCESS
}

/// Tail the last `n` audit lines (parsed JSON) from `audit.jsonl`. Best-effort; `[]` on error.
///
/// `main.rs` owns all I/O, so reading the audit log here (rather than in the `audit` module)
/// keeps that module a pure append-only writer.
fn recent_audit_lines(plugin_data: &Path, n: usize) -> Vec<serde_json::Value> {
    let path = plugin_data.join("audit.jsonl");
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    text.lines()
        .rev()
        .take(n)
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}

/// Read a `--flag value` style argument from `args`.
fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

/// Print a JSON value as a single line to stdout.
fn print_json(value: &serde_json::Value) {
    println!("{}", serde_json::to_string(value).unwrap_or_default());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn within_returns_a_fast_result() {
        assert_eq!(within(Duration::from_secs(5), || 7), Ok(7));
    }

    #[test]
    fn within_times_out_on_a_slow_path() {
        let started = Instant::now();
        let r = within(Duration::from_millis(50), || {
            std::thread::sleep(Duration::from_secs(5));
            7
        });
        assert_eq!(r, Err(mpsc::RecvTimeoutError::Timeout));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn worker_has_a_large_stack() {
        // Deep recursion that overflows a 2 MiB default stack but fits in 8 MiB.
        fn depth(n: u32) -> u32 {
            let pad = [n as u8; 4096];
            if n == 0 {
                u32::from(pad[0])
            } else {
                depth(n - 1).wrapping_add(u32::from(std::hint::black_box(&pad)[1]))
            }
        }
        assert!(within(Duration::from_secs(10), || depth(1000)).is_ok());
    }

    #[test]
    fn within_reports_a_panic() {
        let r: Result<u8, _> = within(Duration::from_secs(5), || panic!("boom"));
        assert_eq!(r, Err(mpsc::RecvTimeoutError::Disconnected));
    }

    #[test]
    fn deadline_env_only_shortens() {
        assert_eq!(deadline_from(None), GATE_DEADLINE);
        assert_eq!(deadline_from(Some("250")), Duration::from_millis(250));
        assert_eq!(deadline_from(Some("999999999")), GATE_DEADLINE);
        assert_eq!(deadline_from(Some("soon")), GATE_DEADLINE);
    }

    #[test]
    fn deadline_keeps_a_deny_already_decided() {
        assert!(matches!(deadline_decision("r"), Decision::Ask { .. }));
        record_decision(&Decision::Allow);
        assert!(matches!(deadline_decision("r"), Decision::Ask { .. }));
        record_decision(&Decision::Deny {
            reason: "mainnet --final".into(),
        });
        assert_eq!(
            deadline_decision("r"),
            Decision::Deny {
                reason: "mainnet --final".into()
            }
        );
    }
}
