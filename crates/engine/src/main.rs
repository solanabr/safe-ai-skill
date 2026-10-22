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
use safe_ai_skill::confirm::{self, PendingKind};
use safe_ai_skill::context::Context;
use safe_ai_skill::datadir::{self, DataDir};
use safe_ai_skill::gate::Verdict;
use safe_ai_skill::gate::{GateMeta, Scope};
use safe_ai_skill::gates::{creddump, envwrite, exfil, read, wallet};
use safe_ai_skill::io::{self, Decision, HookInput, Unreadable};
use safe_ai_skill::policy::tier::{self, EnvRead, Tier};
use safe_ai_skill::policy::{self, Policy};
use safe_ai_skill::spend::{self, SpendLedger};
use safe_ai_skill::statefile::Loaded;
use safe_ai_skill::tierstate::{self, Plan};
use safe_ai_skill::{
    grants, headless, migrate, notice, platform, promptguard, redact, registry, relax, sandbox,
    session, verify,
};

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
    "gate-tamper",
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
    ("gate-skill", |_| cmd_gate_skill()),
    ("gate-prompt-expansion", |_| cmd_gate_prompt_expansion()),
    ("redact", |_| cmd_redact()),
    ("prompt-guard", |_| cmd_prompt_guard()),
    ("pending-notice", |_| cmd_pending_notice()),
    ("verify", cmd_verify),
    ("add", cmd_add),
    ("install", cmd_install),
    ("registry", cmd_registry),
    ("session", cmd_session),
    ("allow", cmd_allow),
    ("tier", cmd_tier),
    ("mode", cmd_mode),
    ("revoke", |_| cmd_revoke()),
    ("status", |_| cmd_status()),
    ("env", safe_ai_skill::env::main),
    ("doctor", safe_ai_skill::doctor::main),
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
/// `reason` (a `deny` when headless).
fn deadline_decision(reason: &str) -> Decision {
    match DECIDED.lock().ok().and_then(|slot| slot.clone()) {
        Some(deny @ Decision::Deny { .. }) => deny,
        _ => headless::apply(
            Decision::Ask {
                reason: reason.to_string(),
            },
            headless::detect(),
        ),
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

/// What `--version` prints. One literal, so the release's binary version check
/// (`scripts/check-binary-versions.sh`) can also find it in a binary it can't run.
const VERSION_LINE: &str = concat!("safe-ai-skill ", env!("CARGO_PKG_VERSION"));

/// `--version` — one plain line, never hook JSON.
fn cmd_version() -> ExitCode {
    let _ = writeln!(std::io::stdout(), "{VERSION_LINE}");
    ExitCode::SUCCESS
}

/// The plugin data dir for a CLI command run from the user's terminal: the hooks' dir
/// ([`datadir::data_dir_with_cwd`]). When it can't be found, prints the guidance (JSON on
/// stdout, a line on stderr) and returns `None`; state is never put anywhere else.
fn cli_state_dir(command: &str, cwd: &Path) -> Option<DataDir> {
    match datadir::data_dir_with_cwd(Some(cwd)) {
        Ok(dir) => Some(dir),
        Err(e) => {
            let e = format!("safe-ai-skill: {e}");
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

/// [`cli_state_dir`] from the process cwd, as a path.
fn cli_data_dir(command: &str) -> Option<PathBuf> {
    cli_state_dir(command, &process_cwd()).map(|d| d.path)
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
    let dir = state_dir(&cwd);
    let effective = load_effective_policy(&cwd, &dir);
    let ask = Decision::Ask {
        reason: reason.to_string(),
    };
    let decision = relax::apply(ask, &GateMeta::unreadable(), &effective, &dir);
    let decision = headless::apply(decision, effective.runtime.headless);
    record_decision(&decision);
    write_audit(&effective, &dir.path, input, raw, "unreadable", &decision);
    let _ = io::emit_pretooluse(&decision);
    ExitCode::SUCCESS
}

/// Load the policy for `cwd` with its runtime tier context ([`load_runtime`]).
fn load_effective_policy(cwd: &Path, dir: &DataDir) -> Policy {
    load_runtime(cwd, dir).0
}

/// Load the policy for `cwd` and resolve the tier (the user's authenticated `tier.json` in a
/// trusted data dir, raised by the kit, repo and env hints), the sandbox state of the project
/// root and the headless rule ([`policy::load_runtime`]).
fn load_runtime(cwd: &Path, dir: &DataDir) -> (Policy, tier::Resolution) {
    let root = tier::project_root(cwd);
    policy::load_runtime(
        cwd,
        dir,
        &|k| std::env::var(k).ok(),
        sandbox::state(&root),
        headless::detect(),
    )
}

/// The strictest of the tier gates' verdicts (`deny` > `ask`); `None` when none asks or
/// denies. Tier gates only tighten: an `allow` from one is ignored.
fn strictest(verdicts: impl IntoIterator<Item = Option<Verdict>>) -> Option<Verdict> {
    verdicts
        .into_iter()
        .flatten()
        .filter(|v| matches!(v, Verdict::Ask(_) | Verdict::Deny(_)))
        .max_by_key(verdict_rank)
}

fn verdict_rank(v: &Verdict) -> u8 {
    match v {
        Verdict::NoOpinion => 0,
        Verdict::Allow(_) => 1,
        Verdict::Ask(_) => 2,
        Verdict::Deny(_) => 3,
    }
}

fn decision_rank(d: &Decision) -> u8 {
    match d {
        Decision::Defer => 0,
        Decision::Allow => 1,
        Decision::Ask { .. } => 2,
        Decision::Deny { .. } => 3,
    }
}

/// Join a tier gate's verdict with a gate's decision: an `ask` or `deny` from a tier gate wins
/// when it is at least as strict, under a hard-guard meta, so no grant can relax it (on an ask
/// tie the gate's grantable meta is dropped). A tier gate's `allow` is ignored: tier gates only
/// tighten, and an allow outside a grant or the spend caps never comes from them.
fn join_tier(
    tier_verdict: Option<Verdict>,
    decision: Decision,
    meta: GateMeta,
) -> (Decision, GateMeta) {
    match tier_verdict {
        Some(v @ (Verdict::Ask(_) | Verdict::Deny(_)))
            if verdict_rank(&v) >= decision_rank(&decision) =>
        {
            (v.into(), GateMeta::new(Scope::SecretRead, true))
        }
        _ => (decision, meta),
    }
}

/// A blocked-pack verdict as the tier has it act ([`verify::tier_action`]): `Some` when it
/// still denies.
fn blocked_pack(verdict: Verdict, tier: Tier) -> Option<Verdict> {
    match verify::tier_action(verdict, tier) {
        deny @ Verdict::Deny(_) => Some(deny),
        _ => None,
    }
}

/// The plugin data dir for a session rooted at `cwd`, resolved exactly as for a hook
/// (`cwd` is the payload's, or the process cwd for the CLI). Unresolvable → the sentinel,
/// which stores nothing and relaxes nothing.
fn state_dir(cwd: &Path) -> DataDir {
    datadir::data_dir_with_cwd(Some(cwd)).unwrap_or_else(|_| datadir::unresolved())
}

/// The process cwd, for CLI subcommands.
fn process_cwd() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
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
    dir: &DataDir,
    input: &HookInput,
    raw: &[u8],
) -> ExitCode {
    let plugin_data = dir.path.as_path();
    let decision = relax::apply(natural, meta, effective, dir);
    // Headless (contract §3.3): every remaining ask becomes a deny; a grant the user confirmed
    // earlier has already become an allow above.
    let decision = headless::apply(decision, effective.runtime.headless);
    record_decision(&decision);

    // Commit-on-allow: once the FINAL (post-relaxation) decision for a transfer with a
    // known amount is `Allow`, debit the daily spend ledger. The gate evaluated the
    // candidate with the non-committing `spend::check`, so this neither re-decides nor
    // double-counts. Grant-relaxed transfers debit the grant budget inside `relax::apply`;
    // they still count against the daily ledger here so the daily cap stays authoritative.
    if matches!(decision, Decision::Allow) && meta.scope == Scope::Transfer {
        if let Some(amount) = meta.amount_sol {
            spend::commit(plugin_data, amount);
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
    let dir = state_dir(&cwd);
    let effective = load_effective_policy(&cwd, &dir);
    let ctx = Context::build(command, &cwd);
    let (decision, meta) = safe_ai_skill::gates::bash::decide(command, &ctx, &effective);
    finish_pretooluse(decision, &meta, &effective, &dir, &input, &raw)
}

fn cmd_gate_bash_secrets() -> ExitCode {
    let (raw, parsed) = read_input();
    let input = match parsed {
        Ok(input) => input,
        Err(Unreadable::Empty) => return ExitCode::SUCCESS,
        Err(why) => return ask_unreadable(why, &HookInput::default(), &raw),
    };
    let cwd = cwd_of(&input);
    let dir = state_dir(&cwd);
    let effective = load_effective_policy(&cwd, &dir);
    let command = input.bash_command().unwrap_or("");
    let tier = effective.tier();
    if let Some(deny) = blocked_pack(verify::enforce::bash_verdict(&dir, command, &cwd), tier) {
        return finish_blocked_pack(deny, &effective, &dir, &input, &raw);
    }
    // The D8 v2 tier gates (one call line each); the strictest joins the secrets decision.
    let tier_verdict = strictest([
        wallet::decide_bash(command, &cwd, &effective, tier),
        creddump::decide(command, &cwd, &effective, tier),
        envwrite::decide_cli(command, &cwd, &effective, tier),
        exfil::decide_bash(command, &cwd, &effective, tier),
    ]);
    // Secret reads are always a hard guard. A solana command the bash gate's `if` filters miss
    // is decided here too, under the bash gate's own meta.
    let (decision, meta) = safe_ai_skill::gates::bash::with_indirection_prefilter(
        safe_ai_skill::gates::secrets::decide(command, &cwd, &effective),
        GateMeta::new(Scope::SecretRead, true),
        command,
        &cwd,
        &effective,
    );
    let (decision, meta) = join_tier(tier_verdict, decision, meta);
    finish_pretooluse(decision, &meta, &effective, &dir, &input, &raw)
}

fn cmd_gate_read() -> ExitCode {
    let (raw, parsed) = read_input();
    let input = match parsed {
        Ok(input) => input,
        Err(Unreadable::Empty) => return ExitCode::SUCCESS,
        Err(why) => return ask_unreadable(why, &HookInput::default(), &raw),
    };
    let cwd = cwd_of(&input);
    let dir = state_dir(&cwd);
    let effective = load_effective_policy(&cwd, &dir);
    let tool = input.tool_name.as_deref().unwrap_or("Read");
    if let Some(tool_input) = input.tool_input.as_ref() {
        let pack = verify::enforce::read_verdict(&dir, tool, tool_input, &cwd);
        if let Some(deny) = blocked_pack(pack, effective.tier()) {
            return finish_blocked_pack(deny, &effective, &dir, &input, &raw);
        }
    }
    let verdict = read::decide_tool(tool, input.tool_input.as_ref(), &cwd, &effective);
    let decision = match verdict {
        read::ReadVerdict::Decide(decision) => decision,
        read::ReadVerdict::Rewrite(updated) => {
            write_audit(
                &effective,
                &dir.path,
                &input,
                &raw,
                "secret_read_rewrite",
                &Decision::Defer,
            );
            let _ = io::emit_updated_input(updated);
            return ExitCode::SUCCESS;
        }
    };
    let meta = GateMeta::new(Scope::SecretRead, true);
    finish_pretooluse(decision, &meta, &effective, &dir, &input, &raw)
}

fn cmd_gate_mcp() -> ExitCode {
    let (raw, parsed) = read_input();
    let input = match parsed {
        Ok(input) => input,
        Err(Unreadable::Empty) => return ExitCode::SUCCESS,
        Err(why) => return ask_unreadable(why, &HookInput::default(), &raw),
    };
    let cwd = cwd_of(&input);
    let dir = state_dir(&cwd);
    let effective = load_effective_policy(&cwd, &dir);
    let tool = input.tool_name.clone().unwrap_or_default();
    let payload = input.mcp_payload();
    // Path-like arguments get the read check first (`ctx_execute_file {path:".env"}`).
    let secret = read::decide_mcp_args(payload, &cwd, &effective);
    if !matches!(secret, Decision::Defer) {
        let meta = GateMeta::new(Scope::SecretRead, true);
        return finish_pretooluse(secret, &meta, &effective, &dir, &input, &raw);
    }
    let ctx = Context::build("", &cwd);
    let tier_verdict = exfil::decide_mcp(&tool, payload, &cwd, &effective, effective.tier());
    let (decision, meta) = safe_ai_skill::gates::mcp::decide(&tool, payload, &ctx, &effective);
    let (decision, meta) = join_tier(tier_verdict, decision, meta);
    finish_pretooluse(decision, &meta, &effective, &dir, &input, &raw)
}

/// Emit a blocked-pack denial (a hard guard: no grant relaxes it).
fn finish_blocked_pack(
    verdict: Verdict,
    effective: &Policy,
    dir: &DataDir,
    input: &HookInput,
    raw: &[u8],
) -> ExitCode {
    let meta = GateMeta::new(Scope::Other, true);
    finish_pretooluse(verdict.into(), &meta, effective, dir, input, raw)
}

/// PreToolUse `Skill`: deny a skill whose pack is blocked (re-hashed on the spot).
fn cmd_gate_skill() -> ExitCode {
    let (raw, parsed) = read_input();
    let input = match parsed {
        Ok(input) => input,
        Err(Unreadable::Empty) => return ExitCode::SUCCESS,
        Err(why) => return ask_unreadable(why, &HookInput::default(), &raw),
    };
    let cwd = cwd_of(&input);
    let dir = state_dir(&cwd);
    let effective = load_effective_policy(&cwd, &dir);
    let verdict =
        safe_ai_skill::gates::skill::decide(input.tool_input.as_ref(), &cwd, &dir, &effective);
    let meta = GateMeta::new(Scope::Other, true);
    finish_pretooluse(verdict.into(), &meta, &effective, &dir, &input, &raw)
}

/// `UserPromptExpansion` (and a raw `/name` in `UserPromptSubmit`): block a typed slash
/// command whose skill pack is blocked. A typed `/name` never reaches the Skill tool.
fn cmd_gate_prompt_expansion() -> ExitCode {
    let (raw, parsed) = read_input();
    let payload = match (&parsed, serde_json::from_slice::<serde_json::Value>(&raw)) {
        (Ok(_), Ok(payload)) => payload,
        (Err(Unreadable::Empty), _) => return ExitCode::SUCCESS,
        // Oversized or malformed: judge the raw head (a blocked slash command, or one whose
        // name cannot be read while a pack in scope is blocked, is blocked).
        _ => {
            let cwd = verify::enforce::raw_cwd(&raw).unwrap_or_else(process_cwd);
            let dir = state_dir(&cwd);
            let effective = load_effective_policy(&cwd, &dir);
            let block = verify::enforce::unreadable_prompt_verdict(&dir, &cwd, &effective, &raw);
            let _ = io::emit_userpromptsubmit(block.as_deref());
            return ExitCode::SUCCESS;
        }
    };
    if verify::enforce::slash_skill_name(&payload).is_none() {
        return ExitCode::SUCCESS;
    }
    let input = parsed.unwrap_or_default();
    let cwd = cwd_of(&input);
    let dir = state_dir(&cwd);
    let effective = load_effective_policy(&cwd, &dir);
    let block = safe_ai_skill::gates::skill::decide_prompt(&payload, &cwd, &dir, &effective);
    let _ = io::emit_userpromptsubmit(block.as_deref());
    ExitCode::SUCCESS
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
    let dir = state_dir(&cwd);
    let effective = load_effective_policy(&cwd, &dir);
    let protected = safe_ai_skill::gates::tamper::Protected::from_env();
    let tool_input = input.tool_input.as_ref();
    let decision = safe_ai_skill::gates::tamper::decide_file(tool_input, &cwd, &protected);
    let tier = effective.tier();
    let tier_verdict = strictest([
        wallet::decide_file(tool_input, &cwd, &effective, tier),
        envwrite::decide_file(tool_input, &cwd, &effective, tier),
    ]);
    let (decision, _) = join_tier(tier_verdict, decision, GateMeta::new(Scope::Other, true));
    // A tamper verdict is final: no grant or tier relaxes it, so it skips `relax::apply`.
    let decision = headless::apply(decision, effective.runtime.headless);
    record_decision(&decision);
    write_audit(&effective, &dir.path, &input, &raw, "tamper", &decision);
    let _ = io::emit_pretooluse(&decision);
    ExitCode::SUCCESS
}

fn cmd_redact() -> ExitCode {
    // Fails open: an unreadable or oversized payload passes unchanged (spec D3.5).
    let Ok(input) = io::read_payload_bounded(std::io::stdin(), redact::MAX_SCAN_BYTES).1 else {
        return ExitCode::SUCCESS;
    };
    let Some(response) = input.tool_response.as_ref() else {
        return ExitCode::SUCCESS;
    };
    let cwd = cwd_of(&input);
    if !load_effective_policy(&cwd, &state_dir(&cwd)).redact.enabled {
        return ExitCode::SUCCESS;
    }
    let values = safe_ai_skill::env::values::load(&cwd);
    let _ = io::emit_posttooluse_redact(redact::scrub_response(response, &values));
    ExitCode::SUCCESS
}

/// `prompt-guard` — the UserPromptSubmit hook: block a prompt carrying a raw secret, else
/// handle a `safe-ai-skill confirm <nonce>` prompt (spec D4.1). The nonce is read from the
/// UserPromptSubmit `prompt` alone ([`confirm::user_prompt`]).
fn cmd_prompt_guard() -> ExitCode {
    let Ok(input) = read_input().1 else {
        return ExitCode::SUCCESS;
    };
    let prompt = input.prompt.clone().unwrap_or_default();
    if let Some(block) = promptguard::check(&prompt) {
        let _ = io::emit_userpromptsubmit(Some(&block));
        return ExitCode::SUCCESS;
    }
    let Some(user_prompt) = confirm::user_prompt(&input) else {
        return ExitCode::SUCCESS;
    };
    let dir = state_dir(&cwd_of(&input));
    let now = now_secs();
    let outcome = relax::confirm_prompt(&dir, user_prompt, now);
    // Codes for requests made outside a Bash tool call (a terminal, `!` mode): shown to the
    // user only, in the systemMessage.
    let codes = relax::announce(&dir, now);
    let mut out = match (outcome, &codes) {
        (Some(o), _) => o.hook_output(),
        (None, Some(_)) => serde_json::json!({}),
        (None, None) => return ExitCode::SUCCESS,
    };
    if let (Some(codes), Some(map)) = (codes, out.as_object_mut()) {
        let msg = match map.get("systemMessage").and_then(|m| m.as_str()) {
            Some(prev) => format!("{prev}\n{codes}"),
            None => codes,
        };
        map.insert("systemMessage".to_string(), serde_json::Value::String(msg));
    }
    print_json(&out);
    ExitCode::SUCCESS
}

/// `pending-notice` — the PostToolUse (Bash) hook that shows the user the confirmation code
/// of a request the tool call just made. The code goes in `systemMessage` only (never
/// `additionalContext`), and each request is announced once. Nothing pending → no output.
/// `pending-notice` — the PostToolUse hook on Bash: show the user (in `systemMessage` only) the
/// codes of requests a Bash call just made. Anything but a PostToolUse/Bash payload gets nothing.
fn cmd_pending_notice() -> ExitCode {
    let Ok(input) = read_input().1 else {
        return ExitCode::SUCCESS;
    };
    if input.hook_event_name.as_deref() != Some("PostToolUse")
        || input.tool_name.as_deref() != Some("Bash")
    {
        return ExitCode::SUCCESS;
    }
    let dir = state_dir(&cwd_of(&input));
    if let Some(codes) = relax::announce(&dir, now_secs()) {
        print_json(&serde_json::json!({ "systemMessage": codes }));
    }
    ExitCode::SUCCESS
}

fn cmd_verify(rest: &[String]) -> ExitCode {
    let action = rest.first().map(String::as_str).unwrap_or("session");
    let arg = rest.get(1).map(String::as_str).unwrap_or("");
    match action {
        "session" => cmd_verify_session(),
        "approve" => cmd_verify_request("approve", arg),
        "trust" => cmd_verify_request("trust", arg),
        "check" => {
            let report = verify::pipeline_dir(Path::new(arg), None);
            print_json(&serde_json::json!({
                "command": "verify check",
                "target": arg,
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

/// `verify session` — the SessionStart supply-chain sweep (state v2; blocked packs are denied
/// in place by the gates, nothing moves unless `supply_chain.on_block: move`).
///
/// Runs [`verify::run_session`] (skill packs + the project `.mcp.json`) and emits the
/// SessionStart report (`systemMessage` for the user + `additionalContext` for the model) — or
/// nothing when there is nothing to report.
fn cmd_verify_session() -> ExitCode {
    // SessionStart hooks may carry a cwd on stdin; fall back to the process cwd.
    let input = read_input().1.unwrap_or_default();
    let cwd = cwd_of(&input);
    let dir = state_dir(&cwd);
    let plugin_data = dir.path.clone();
    let now = now_secs();

    // 1.0 state is migrated once, before anything creates the state key; then the spend
    // ledger is started (or repaired), which creates the key on a first run.
    let mut migrated = migrate::run(&dir, now);
    migrated.extend(migrate::mode_to_tier(&dir, now));
    let spend_state = spend::ledger_state(&plugin_data);
    let _ = SpendLedger::load(&plugin_data);

    let (effective, resolution) = load_runtime(&cwd, &dir);
    let mut res = verify::run_session(&dir, &cwd, &effective);

    // The tier line and the hints the resolution ignored, overrides the policy ratchet refused
    // (project overlay, removed settings), then the active loosenings (spec D4.4): shown to the
    // user and given to the model.
    let root = tier::project_root(&cwd);
    let loosenings = notice::loosenings(&notice::Inputs {
        dir: &dir,
        root: &root,
        spend: spend_state,
        migrated: &migrated,
        sandbox: sandbox::declared(&root),
        now,
    });
    let notices: Vec<String> = [effective.ignored_notice(), loosenings]
        .into_iter()
        .flatten()
        .chain(platform::session_notices())
        .collect();
    // The tier line leads whenever there is anything to say, or the tier is not the plain
    // default; a clean default session stays silent.
    let plain_default = resolution.tier == Tier::Relaxed
        && resolution.source == tier::TierSource::Base
        && resolution.notes.is_empty();
    let quiet = plain_default
        && notices.is_empty()
        && res.system_message.is_empty()
        && res.additional_context.is_empty();
    if !quiet {
        let tier_text = std::iter::once(notice::tier_line(&resolution, &effective.runtime))
            .chain(resolution.notes.iter().map(|n| format!(" - {n}")))
            .collect::<Vec<_>>()
            .join("\n");
        for field in [&mut res.system_message, &mut res.additional_context] {
            *field = if field.is_empty() {
                tier_text.clone()
            } else {
                format!("{tier_text}\n{field}")
            };
        }
    }
    // Then install and platform notices (duplicate install, old Claude Code, Windows scope).
    for text in notices {
        for field in [&mut res.system_message, &mut res.additional_context] {
            if !field.is_empty() {
                field.push('\n');
            }
            field.push_str(&text);
        }
    }
    // Confirmation codes (1.0 grants kept as requests, requests made from a terminal): the
    // user's systemMessage only.
    if let Some(codes) = relax::announce(&dir, now) {
        if !res.system_message.is_empty() {
            res.system_message.push('\n');
        }
        res.system_message.push_str(&codes);
    }

    // One-time tip (per project) when env files exist without a `.env.schema` (spec D3.8.6).
    if let Some(tip) = safe_ai_skill::env::schema_tip(&cwd, &dir.path) {
        if !res.system_message.is_empty() {
            res.system_message.push('\n');
        }
        res.system_message.push_str(&tip);
    }

    if let Some(out) = res.hook_output() {
        print_json(&out);
    }
    ExitCode::SUCCESS
}

/// `verify approve <name|path>` / `verify trust <path>`: create a pending request and print its
/// id, never a code. Nothing changes until the user types the code safe-ai-skill shows them as
/// their next prompt (spec D4.1); the UserPromptSubmit hook then applies it
/// ([`verify::apply_confirmed`]).
fn cmd_verify_request(action: &str, target: &str) -> ExitCode {
    let command = format!("verify {action}");
    if target.is_empty() {
        let usage = if action == "trust" {
            "usage: verify trust <pack dir>"
        } else {
            "usage: verify approve <skill-name | pack dir>"
        };
        print_json(&serde_json::json!({
            "command": command,
            "status": "error",
            "error": usage,
        }));
        return ExitCode::SUCCESS;
    }
    let cwd = process_cwd();
    let Some(dir) = cli_state_dir(&command, &cwd) else {
        return ExitCode::FAILURE;
    };
    let request = if action == "trust" {
        verify::request_trust(&dir, Path::new(target))
    } else {
        let project = verify::project_root(&cwd);
        let effective = load_effective_policy(&project, &dir);
        verify::request_approve(&dir, &cwd, target, &effective)
    };
    match request {
        Ok(req) => {
            audit_event(
                &dir.path,
                &format!("verify_{action}_requested"),
                "pending",
                &format!("target={target}"),
            );
            // The request id only: the code reaches the user alone, in a hook `systemMessage`.
            let message = format!(
                "Pending request {} created: {}. Nothing has changed yet. safe-ai-skill will show \
                 YOU (not the agent) a confirmation code; type it as your entire next prompt in \
                 Claude Code to approve (valid {} minutes after it is shown).",
                req.id,
                req.summary,
                confirm::TTL_SECS / 60
            );
            let _ = writeln!(std::io::stderr(), "{message}");
            print_json(&serde_json::json!({
                "command": command,
                "status": "pending",
                "target": target,
                "request": req.id,
                "summary": req.summary,
                "data_dir_trusted": dir.trusted,
                "message": message,
            }));
        }
        Err(e) => {
            print_json(&serde_json::json!({
                "command": command,
                "status": "error",
                "target": target,
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
    if let Some((entry_id, risk_class, decision)) = resolve_high_risk_target(source) {
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
fn resolve_high_risk_target(source: &str) -> Option<(String, &'static str, &'static str)> {
    let cwd = process_cwd();
    let policy = load_effective_policy(&cwd, &state_dir(&cwd));
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
    let cwd = process_cwd();
    let Some(dir) = cli_state_dir("registry", &cwd) else {
        return ExitCode::FAILURE;
    };
    let plugin_data = dir.path.clone();
    let policy = load_effective_policy(&cwd, &dir);
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
    let Some(dir) = cli_state_dir("session", &process_cwd()) else {
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
            session::init(cap, &dir).unwrap_or_default()
        }
        _ => session::status(&dir).unwrap_or_default(),
    };
    print_json(&serde_json::json!({ "command": "session", "action": action, "result": result }));
    ExitCode::SUCCESS
}

/// A CLI argument error: JSON on stdout, exit 1.
fn cli_error(command: &str, error: &str) -> ExitCode {
    print_json(&serde_json::json!({
        "command": command,
        "status": "error",
        "error": error,
    }));
    ExitCode::FAILURE
}

/// Park a relaxing action for confirmation (spec D4.1). The output names the request but
/// carries **no code**: safe-ai-skill shows the code to the user alone, in a `systemMessage`
/// (the PostToolUse `pending-notice` hook, or the next prompt or session start).
fn park_pending(
    command: &str,
    dir: &DataDir,
    kind: PendingKind,
    summary: &str,
    payload: serde_json::Value,
) -> ExitCode {
    let id = match confirm::create_pending(dir, kind, summary, payload) {
        Ok(id) => id,
        Err(e) => return cli_error(command, &format!("could not record the request: {e}")),
    };
    let minutes = confirm::TTL_SECS / 60;
    let mut message = format!(
        "Pending request {id} created: {summary}. Nothing has changed yet. safe-ai-skill will \
         show YOU (not the agent) a confirmation code; type it as your entire next prompt in \
         Claude Code to approve (valid {minutes} minutes after it is shown)."
    );
    if !dir.trusted {
        message.push_str(
            " Warning: the plugin data dir is not in a trusted location, so this will not take \
             effect even once confirmed.",
        );
    }
    let _ = writeln!(std::io::stderr(), "{message}");
    audit_event(&dir.path, kind_label(kind), "pending", summary);
    print_json(&serde_json::json!({
        "command": command,
        "status": "pending",
        "request": id.as_str(),
        "summary": summary,
        "data_dir_trusted": dir.trusted,
        "message": message,
    }));
    ExitCode::SUCCESS
}

/// Audit classification of a pending kind.
fn kind_label(kind: PendingKind) -> &'static str {
    match kind {
        PendingKind::Grant => "grant_create",
        PendingKind::Mode | PendingKind::Tier => "tier_set",
        PendingKind::Trust => "verify_trust",
        PendingKind::Approve => "verify_approve",
    }
}

/// `allow --scope <s> --for <dur> [--max-tx N] [--budget N] [--programs a,b] [--to a,b]
/// [--danger]` — request a grant. It is only parked; the user confirms it with the prompt
/// nonce. An unknown scope (including the removed `other`) is an error.
fn cmd_allow(rest: &[String]) -> ExitCode {
    let scope = flag_value(rest, "--scope").unwrap_or_default();
    let for_dur = flag_value(rest, "--for").unwrap_or_default();
    let amount = |flag: &str| -> Result<f64, String> {
        match flag_value(rest, flag) {
            None => Ok(0.0),
            Some(v) => v
                .parse::<f64>()
                .map_err(|_| format!("{flag}: expected a SOL amount")),
        }
    };
    let (max_tx, budget) = match (amount("--max-tx"), amount("--budget")) {
        (Ok(m), Ok(b)) => (m, b),
        (Err(e), _) | (_, Err(e)) => return cli_error("allow", &e),
    };
    let programs = flag_value(rest, "--programs").unwrap_or_default();
    let to = flag_value(rest, "--to").unwrap_or_default();
    let danger = rest.iter().any(|a| a == "--danger");

    let request = match grants::GrantRequest::from_args(
        &scope, &for_dur, max_tx, budget, &programs, &to, danger,
    ) {
        Ok(r) => r,
        Err(e) => return cli_error("allow", &e),
    };
    let payload = match serde_json::to_value(&request) {
        Ok(v) => v,
        Err(e) => return cli_error("allow", &e.to_string()),
    };
    let Some(dir) = cli_state_dir("allow", &process_cwd()) else {
        return ExitCode::FAILURE;
    };
    park_pending(
        "allow",
        &dir,
        PendingKind::Grant,
        &request.summary(),
        payload,
    )
}

/// `mode [<name>]` — deprecated alias of [`cmd_tier`] (profile names are tier aliases).
fn cmd_mode(rest: &[String]) -> ExitCode {
    let _ = writeln!(
        std::io::stderr(),
        "safe-ai-skill: `mode` is deprecated; use `safe-ai-skill tier` (strict/autopilot = \
         relaxed, paranoid = high)."
    );
    cmd_tier(rest)
}

/// `tier [<name>] [--project] [--env-read deny|ask|tier] | --clear [--project]` — show the
/// tier (no argument), or change the user's choice in `tier.json` (D8 v2 spec §1.3). Raising
/// the tier or tightening `env_read` applies at once; lowering or loosening is parked for the
/// user's whole-prompt confirmation (the code reaches the user alone).
fn cmd_tier(rest: &[String]) -> ExitCode {
    let cwd = process_cwd();
    let Some(dir) = cli_state_dir("tier", &cwd) else {
        return ExitCode::FAILURE;
    };
    let mut name: Option<&str> = None;
    let mut env_read: Option<EnvRead> = None;
    let (mut project, mut clear) = (false, false);
    let mut args = rest.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--project" => project = true,
            "--clear" => clear = true,
            "--env-read" => match args.next().map(|v| EnvRead::parse(v)) {
                Some(Some(v)) => env_read = Some(v),
                _ => return cli_error("tier", "--env-read: expected deny|ask|tier"),
            },
            a if a.starts_with('-') || name.is_some() => return cli_error(
                "tier",
                "usage: tier [<off|relaxed|medium|high>] [--project] [--env-read deny|ask|tier] \
                     | tier --clear [--project]",
            ),
            a => name = Some(a),
        }
    }
    let tier = match name.map(Tier::parse) {
        Some(None) => return cli_error("tier", &tierstate::unknown_tier().to_string()),
        Some(Some(t)) => Some(t),
        None => None,
    };
    if clear && (tier.is_some() || env_read.is_some()) {
        return cli_error("tier", "--clear takes no tier or --env-read");
    }
    if tier.is_none() && env_read.is_none() && !clear {
        return print_tier(&cwd, &dir, "tier");
    }
    let root = tier::project_root(&cwd);
    let change = tierstate::Change {
        project: project.then(|| tierstate::root_key(&root)),
        tier,
        env_read,
        clear,
    };
    let summary = tierstate::summary(&change);
    match tierstate::plan(&dir, &change) {
        Plan::NeedsConfirm => park_pending(
            "tier",
            &dir,
            PendingKind::Tier,
            &summary,
            tierstate::to_payload(&change),
        ),
        Plan::NoChange => {
            print_json(&serde_json::json!({
                "command": "tier",
                "status": "unchanged",
                "summary": summary,
            }));
            ExitCode::SUCCESS
        }
        Plan::Immediate => match tierstate::apply(&dir, &change, now_secs()) {
            Ok(()) => {
                audit_event(&dir.path, "tier_set", "tier", &summary);
                let (effective, resolution) = load_runtime(&cwd, &dir);
                print_json(&serde_json::json!({
                    "command": "tier",
                    "status": "set",
                    "summary": summary,
                    "tier": resolution.tier.label(),
                    "line": notice::tier_line(&resolution, &effective.runtime),
                    "data_dir_trusted": dir.trusted,
                }));
                ExitCode::SUCCESS
            }
            Err(e) => cli_error("tier", &e.to_string()),
        },
    }
}

/// Print the effective tier for `cwd`: where it comes from, the user's choice, `env_read`,
/// the sandbox state, and every ignored hint.
fn print_tier(cwd: &Path, dir: &DataDir, command: &str) -> ExitCode {
    let (effective, resolution) = load_runtime(cwd, dir);
    print_json(&serde_json::json!({
        "command": command,
        "tier": resolution.tier.label(),
        "source": resolution.source.label(),
        "user": resolution.user.label(),
        "user_source": resolution.user_source.label(),
        "env_read": resolution.env_read.label(),
        "sandbox": effective.runtime.sandbox.label(),
        "headless": effective.runtime.headless,
        "line": notice::tier_line(&resolution, &effective.runtime),
        "notes": resolution.notes,
        "policy_notes": effective.ignored_overrides,
        "tier_state": state_label(&tierstate::load(dir)),
        "data_dir_trusted": dir.trusted,
    }));
    ExitCode::SUCCESS
}

/// `revoke` — clear every grant (tightening, so it takes effect at once).
fn cmd_revoke() -> ExitCode {
    let Some(dir) = cli_state_dir("revoke", &process_cwd()) else {
        return ExitCode::FAILURE;
    };
    let cleared = match grants::load(&dir) {
        Loaded::Valid(g) => g.grants.len(),
        _ => 0,
    };
    if let Err(e) = grants::save(&dir, &grants::Grants::default()) {
        return cli_error("revoke", &e.to_string());
    }
    audit_event(
        &dir.path,
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

/// The label of a state file's authentication result.
fn state_label<T>(loaded: &Loaded<T>) -> &'static str {
    match loaded {
        Loaded::Valid(_) => "valid",
        Loaded::Missing => "missing",
        Loaded::Tampered => "failed authentication",
    }
}

fn cmd_status() -> ExitCode {
    let cwd = process_cwd();
    let Some(dir) = cli_state_dir("status", &cwd) else {
        return ExitCode::FAILURE;
    };
    let plugin_data = dir.path.clone();
    let (effective, resolution) = load_runtime(&cwd, &dir);

    // Grants with derived remaining-budget / time-left (authenticated file only).
    let now = now_secs();
    let loaded = grants::load(&dir);
    let grants_state = state_label(&loaded);
    let live = match loaded {
        Loaded::Valid(g) => g,
        _ => grants::Grants::default(),
    };
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
    let ledger = SpendLedger::load(&plugin_data);
    let spend_view = serde_json::json!({
        "today_sol": if ledger.is_exhausted() { serde_json::Value::Null } else { serde_json::json!(ledger.total_sol) },
        "exhausted": ledger.is_exhausted(),
        "per_tx_sol_max": effective.spend.per_tx_sol_max,
        "hard_tx_sol_max": effective.spend.hard_tx_sol_max,
        "daily_sol_max": effective.spend.daily_sol_max,
    });

    print_json(&serde_json::json!({
        "command": "status",
        "plugin_data": plugin_data.display().to_string(),
        "tier": resolution.tier.label(),
        "tier_source": resolution.source.label(),
        "tier_line": notice::tier_line(&resolution, &effective.runtime),
        "tier_notes": resolution.notes,
        "env_read": resolution.env_read.label(),
        "sandbox": effective.runtime.sandbox.label(),
        "data_dir_trusted": dir.trusted,
        "grants_state": grants_state,
        "tier_state": state_label(&tierstate::load(&dir)),
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

    fn trusted_dir_with_transfer_grant(tag: &str) -> DataDir {
        let path = std::env::temp_dir().join(format!("main_join_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        let dir = DataDir {
            path,
            trusted: true,
        };
        let grant = grants::Grant {
            id: "g1".into(),
            scope: Scope::Transfer,
            programs: Vec::new(),
            to: Vec::new(),
            max_tx_sol: 10.0,
            budget_sol: 10.0,
            spent_sol: 0.0,
            expires_at: u64::MAX,
            danger: false,
        };
        let all = grants::Grants {
            grants: vec![grant],
        };
        grants::save(&dir, &all).unwrap();
        dir
    }

    #[test]
    fn a_tier_gate_ask_is_never_relaxed_by_a_grant() {
        let dir = trusted_dir_with_transfer_grant("tie");
        let policy = Policy::from_sources(policy::DEFAULT_POLICY_YAML, None);
        let mut grantable = GateMeta::new(Scope::Transfer, false);
        grantable.amount_sol = Some(0.5);
        let gate_ask = || Decision::Ask {
            reason: "transfer over cap".into(),
        };
        // Without a tier verdict the grant relaxes the gate's own ask.
        let (d, m) = join_tier(None, gate_ask(), grantable.clone());
        assert_eq!(relax::apply(d, &m, &policy, &dir), Decision::Allow);
        // A tier-gate ask on a tie keeps the ask (and denies headless).
        let stub = Some(Verdict::Ask("exfil host".into()));
        for headless in [false, true] {
            let (d, m) = join_tier(stub.clone(), gate_ask(), grantable.clone());
            assert!(m.hard_guard);
            let out = headless::apply(relax::apply(d, &m, &policy, &dir), headless);
            let want = if headless { "deny" } else { "ask" };
            assert_eq!(out.label(), want, "headless={headless}");
            assert!(out.reason().starts_with("exfil host"), "{out:?}");
        }
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn a_tier_gate_allow_is_ignored() {
        let dir = trusted_dir_with_transfer_grant("allow");
        let allow = || {
            relax::apply_verdict(
                Verdict::Ask("x".into()),
                &GateMeta::new(Scope::Transfer, false),
                &Policy::default(),
                &dir,
            )
        };
        assert!(matches!(allow(), Verdict::Allow(_)));
        assert_eq!(strictest([Some(Verdict::NoOpinion), None]), None);
        assert_eq!(strictest([Some(allow())]), None);
        let (d, _) = join_tier(Some(allow()), Decision::Defer, GateMeta::unknown());
        assert_eq!(d, Decision::Defer);
        let _ = std::fs::remove_dir_all(&dir.path);
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
