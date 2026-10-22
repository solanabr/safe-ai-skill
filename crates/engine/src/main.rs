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

use safe_ai_skill::audit::{self, AuditEntry};
use safe_ai_skill::confirm::{self, PendingKind};
use safe_ai_skill::context::{self, Context};
use safe_ai_skill::datadir::{self, DataDir};
use safe_ai_skill::gate::{GateMeta, Scope};
use safe_ai_skill::io::{self, Decision, HookInput, Unreadable};
use safe_ai_skill::policy::Policy;
use safe_ai_skill::spend::{self, SpendLedger};
use safe_ai_skill::statefile::Loaded;
use safe_ai_skill::{
    grants, migrate, mode, notice, promptguard, redact, registry, relax, session, verify,
};

/// Exit status for an invocation error (unknown or missing subcommand), distinct from a verdict.
const EXIT_USAGE: u8 = 3;

/// Reason for the `ask` on a PreToolUse payload over [`io::MAX_STDIN_BYTES`].
const OVERSIZED_REASON: &str =
    "safe-ai-skill: hook input exceeds 1 MiB and was not inspected; review this call manually.";

/// Reason for the `ask` on a PreToolUse payload the engine cannot parse.
const MALFORMED_REASON: &str =
    "safe-ai-skill: hook input is malformed and was not inspected; review this call manually.";

/// A subcommand handler: gets the arguments after the subcommand name.
type Handler = fn(&[String]) -> ExitCode;

/// The subcommand registry. A new subcommand is one line here. Names not listed exit 3
/// ([`cmd_unknown`]).
const SUBCOMMANDS: &[(&str, Handler)] = &[
    ("gate-bash", |_| cmd_gate_bash()),
    ("gate-bash-secrets", |_| cmd_gate_bash_secrets()),
    ("gate-read", |_| cmd_gate_read()),
    ("gate-mcp", |_| cmd_gate_mcp()),
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

    match SUBCOMMANDS.iter().find(|(name, _)| *name == sub) {
        Some((_, handler)) => handler(rest),
        None => cmd_unknown(sub),
    }
}

/// A wired hook whose gate is not implemented yet: drain the payload, no opinion.
fn cmd_no_opinion() -> ExitCode {
    let _ = read_input();
    ExitCode::SUCCESS
}

/// `--version` — one plain line, never hook JSON.
fn cmd_version() -> ExitCode {
    let _ = writeln!(
        std::io::stdout(),
        "safe-ai-skill {}",
        env!("CARGO_PKG_VERSION")
    );
    ExitCode::SUCCESS
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
    write_audit(&effective, &dir.path, input, raw, "unreadable", &decision);
    let _ = io::emit_pretooluse(&decision);
    ExitCode::SUCCESS
}

/// Load the policy for `cwd` and resolve it to its EFFECTIVE form (profile overlay applied).
///
/// The persistent runtime override written by `safe-ai-skill mode <profile>` (`mode.json`)
/// replaces the policy's profile; the `SAFE_AI_SKILL_PROFILE` env var may then only select a
/// stricter one (see [`Policy::load_with_mode`]). Only an authenticated `mode.json` in a
/// trusted data dir counts ([`mode::persisted`]).
fn load_effective_policy(cwd: &Path, dir: &DataDir) -> Policy {
    Policy::load_with_mode(cwd, mode::persisted(dir).as_deref()).effective()
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
    let (mut decision, meta) = safe_ai_skill::gates::bash::decide(command, &ctx, &effective);
    // paranoid: every Solana CLI command asks, including the ones with no opinion.
    if matches!(decision, Decision::Defer) && effective.active_overlay().ask_all {
        decision = Decision::Ask {
            reason: relax::ASK_ALL_REASON.to_string(),
        };
    }
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
    let decision = safe_ai_skill::gates::secrets::decide(command, &effective);
    // Secret reads are always a hard guard.
    let meta = GateMeta::new(Scope::SecretRead, true);
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
    let path = input.read_path().unwrap_or("");
    let decision = safe_ai_skill::gates::read::decide(path, &effective);
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
    let ctx = Context::build("", &cwd);
    let (decision, meta) = safe_ai_skill::gates::mcp::decide(&tool, payload, &ctx, &effective);
    finish_pretooluse(decision, &meta, &effective, &dir, &input, &raw)
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
    if let Some(outcome) = relax::confirm_prompt(&dir, user_prompt, now_secs()) {
        print_json(&outcome.hook_output());
    }
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
    let dir = state_dir(&cwd);
    let plugin_data = dir.path.clone();
    let now = now_secs();

    // 1.0 state is migrated once, before anything creates the state key; then the spend
    // ledger is started (or repaired), which creates the key on a first run.
    let migrated = migrate::run(&dir, now);
    let spend_state = spend::ledger_state(&plugin_data);
    let _ = SpendLedger::load(&plugin_data);

    let effective = load_effective_policy(&cwd, &dir);
    let mut res = verify::run_session(&plugin_data, &cwd, &effective);

    // Overrides the policy ratchet refused (project overlay, looser profile env var, removed
    // settings), then the active loosenings (spec D4.4): shown to the user and given to the
    // model.
    let env_profile = std::env::var(safe_ai_skill::policy::PROFILE_ENV).ok();
    let project = std::env::var_os("CLAUDE_PROJECT_DIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| cwd.clone());
    let loosenings = notice::loosenings(&notice::Inputs {
        dir: &dir,
        env_profile: env_profile.as_deref(),
        spend: spend_state,
        migrated: &migrated,
        sandbox: notice::sandbox_state(&project),
        now,
    });
    for text in [effective.ignored_notice(), loosenings]
        .into_iter()
        .flatten()
    {
        for field in [&mut res.system_message, &mut res.additional_context] {
            if !field.is_empty() {
                field.push('\n');
            }
            field.push_str(&text);
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
    let cwd = process_cwd();
    let dir = state_dir(&cwd);
    let plugin_data = dir.path.clone();
    // `.gitmodules` and the swept roots resolve at the repo root, from any subdirectory.
    let project = verify::project_root(&cwd);
    let effective = load_effective_policy(&project, &dir);

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

    let plugin_data = context::plugin_data_dir();

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
    let _ = plugin_data;
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
    let plugin_data = context::plugin_data_dir();

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
    let dir = state_dir(&cwd);
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
    let dir = state_dir(&process_cwd());
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

/// Park a relaxing action for prompt-nonce confirmation (spec D4.1) and tell whoever ran
/// the command exactly what to type: JSON on stdout, plain text on stderr. Nothing takes
/// effect until the user's own next prompt is `safe-ai-skill confirm <nonce>`.
fn park_pending(
    command: &str,
    dir: &DataDir,
    kind: PendingKind,
    summary: &str,
    payload: serde_json::Value,
) -> ExitCode {
    // Start the spend ledger first: creating the state key without it would make the ledger
    // look deleted (budget exhausted) at the next session.
    let _ = SpendLedger::load(&dir.path);
    let nonce = match confirm::create_pending(dir, kind, summary, payload) {
        Ok(n) => n,
        Err(e) => return cli_error(command, &format!("could not record the request: {e}")),
    };
    let line = format!("safe-ai-skill confirm {nonce}");
    let minutes = confirm::TTL_SECS / 60;
    let untrusted = !dir.trusted;
    let mut message = format!(
        "Nothing has changed yet. Requested: {summary}.\n\
         To approve it, type this line as your entire next prompt in Claude Code \
         (valid {minutes} minutes, single use):\n\n    {line}\n"
    );
    if untrusted {
        message.push_str(
            "\nWarning: the plugin data dir is not in a trusted location, so this will not \
             take effect even once confirmed.\n",
        );
    }
    let _ = writeln!(std::io::stderr(), "{message}");
    audit_event(&dir.path, kind_label(kind), "pending", summary);
    print_json(&serde_json::json!({
        "command": command,
        "status": "pending",
        "summary": summary,
        "confirm": line,
        "expires_in_secs": confirm::TTL_SECS,
        "data_dir_trusted": !untrusted,
        "message": message,
    }));
    ExitCode::SUCCESS
}

/// Audit classification of a pending kind.
fn kind_label(kind: PendingKind) -> &'static str {
    match kind {
        PendingKind::Grant => "grant_create",
        PendingKind::Mode => "mode_set",
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
    let dir = state_dir(&process_cwd());
    park_pending(
        "allow",
        &dir,
        PendingKind::Grant,
        &request.summary(),
        payload,
    )
}

/// `mode [<profile>]` — show the active profile, or select one. A stricter profile is
/// written at once; a looser one (`autopilot`) is parked for prompt-nonce confirmation.
fn cmd_mode(rest: &[String]) -> ExitCode {
    let cwd = process_cwd();
    let dir = state_dir(&cwd);
    let Some(profile) = rest.first() else {
        let current = load_effective_policy(&cwd, &dir).active_profile;
        print_json(&serde_json::json!({ "command": "mode", "active_profile": current }));
        return ExitCode::SUCCESS;
    };
    if !mode::is_known_profile(profile) {
        return cli_error("mode", &mode::unknown_profile(profile));
    }
    let current = Policy::load_with_mode(&cwd, mode::persisted(&dir).as_deref()).active_profile;
    if mode::is_looser(profile, &current) {
        return park_pending(
            "mode",
            &dir,
            PendingKind::Mode,
            &format!("mode {profile} (from {current})"),
            serde_json::json!({ "profile": profile }),
        );
    }
    let _ = SpendLedger::load(&dir.path);
    match mode::set(&dir, profile, now_secs()) {
        Ok(()) => {
            audit_event(
                &dir.path,
                "mode_set",
                "mode",
                &format!("active_profile={profile}"),
            );
            print_json(&serde_json::json!({
                "command": "mode",
                "status": "set",
                "active_profile": profile,
            }));
            ExitCode::SUCCESS
        }
        Err(e) => cli_error("mode", &e.to_string()),
    }
}

/// `revoke` — clear every grant (tightening, so it takes effect at once).
fn cmd_revoke() -> ExitCode {
    let dir = state_dir(&process_cwd());
    let cleared = match grants::load(&dir) {
        Loaded::Valid(g) => g.grants.len(),
        _ => 0,
    };
    let _ = SpendLedger::load(&dir.path);
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
    let dir = state_dir(&cwd);
    let plugin_data = dir.path.clone();
    let effective = load_effective_policy(&cwd, &dir);

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
        "active_profile": effective.active_profile,
        "data_dir_trusted": dir.trusted,
        "grants_state": grants_state,
        "mode_state": state_label(&mode::load(&dir)),
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
