//! `safe-ai-skill firewall apply|show|check`: the Claude Code sandbox and permission block.
//!
//! A plugin cannot ship `permissions` or `sandbox` settings, so these protections (coverage map
//! X1–X9, P14, P21) only exist when a user-run CLI writes them. This module writes a
//! safe-ai-skill-owned block into the project's `.claude/settings.local.json` (it outranks the
//! shared `.claude/settings.json` for scalars, and every list merges across files; docs:
//! settings.md "Settings precedence", "Lists merge instead of overriding"), the same block
//! ai-kit's `.claude/bin/firewall.sh` generates per tier ([`rules`]).
//!
//! Rules this writer keeps:
//! - It never writes `sandbox.enabled: false`, and only ever adds deny rules and sandbox
//!   restrictions (plus the kit's shippability carve-outs that a sandbox needs to be usable).
//! - It owns only what it recorded writing ([`merge`]); every user-authored rule and key is
//!   left as it is, in its place.
//! - Raising applies at once; lowering below the tier last applied (or the user tier, when a
//!   tier is named) is parked for the user's confirmation code, like `safe-ai-skill tier`.
//! - The write is atomic, keeps the file's key order and indentation, and refuses a symlinked
//!   `.claude` dir or settings file.
//!
//! The record of what was written (tier, rule-set version, entries, scalars) is the MAC'd state
//! file [`RECORD_FILE`] in the data dir, never a key in the settings file, so Claude Code never
//! sees an unknown key and the agent cannot forge ownership with a file tool.
//!
//! Drift (T3): [`check`] and [`session_note`] compare the declared tier (the engine's effective
//! tier) with the enforced one, and the recorded entries with the live file. Versioning (T6):
//! [`rules::RULE_SET_VERSION`]; [`session_resync`] re-applies an older record at SessionStart.

pub mod json;
pub mod merge;
pub mod rules;
pub mod target;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{json as j, Value};
use sha2::{Digest, Sha256};

use crate::datadir::DataDir;
use crate::policy::tier::{self as ptier, Tier};
use crate::statefile::{self, Loaded};
use crate::tierstate;

use self::json::Json;
use self::rules::{Block, MachineInputs, RULE_SET_VERSION};
use self::target::Target;

/// The record's state file in the data dir.
pub const RECORD_FILE: &str = "firewall.json";

/// The CLI usage line.
pub const USAGE: &str =
    "usage: firewall apply [<off|relaxed|medium|high>] [--project] [--dry-run] | firewall show \
     | firewall check";

/// The record of every target this engine wrote a block into.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordFile {
    /// Keyed by the settings file's absolute path.
    #[serde(default)]
    pub targets: BTreeMap<String, Record>,
}

/// What the last apply wrote into one settings file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// The tier applied.
    pub tier: Tier,
    /// [`RULE_SET_VERSION`] at the time.
    pub rule_set_version: u32,
    /// The entries written, per list.
    #[serde(default)]
    pub rule_ids: BTreeMap<String, Vec<String>>,
    /// The scalars written.
    #[serde(default)]
    pub scalars: Vec<String>,
    /// sha256 of the generated block.
    pub sha256: String,
    /// Unix seconds.
    pub applied_at: u64,
}

/// A parsed `firewall` command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `apply [<tier>] [--project] [--dry-run]`.
    Apply {
        /// The tier named, else the effective tier.
        tier: Option<Tier>,
        /// Record a named tier for this project only (as `tier --project`).
        project: bool,
        /// Report, write nothing.
        dry_run: bool,
    },
    /// `show`.
    Show,
    /// `check`.
    Check,
}

/// Parse the arguments after `firewall`.
pub fn parse_args(rest: &[String]) -> Result<Command, String> {
    let mut it = rest.iter().map(String::as_str);
    match it.next() {
        Some("show") if it.next().is_none() => Ok(Command::Show),
        Some("check") if it.next().is_none() => Ok(Command::Check),
        Some("apply") => {
            let (mut tier, mut project, mut dry_run) = (None, false, false);
            for a in it {
                match a {
                    "--project" => project = true,
                    "--dry-run" | "-n" => dry_run = true,
                    w if !w.starts_with('-') && tier.is_none() => {
                        tier = Some(Tier::parse(w).ok_or_else(|| {
                            "unknown tier (expected off, relaxed, medium or high)".to_string()
                        })?)
                    }
                    _ => return Err(USAGE.to_string()),
                }
            }
            if project && tier.is_none() {
                return Err("--project needs a tier name".to_string());
            }
            Ok(Command::Apply {
                tier,
                project,
                dry_run,
            })
        }
        _ => Err(USAGE.to_string()),
    }
}

/// What a command needs from its caller.
#[derive(Debug, Clone)]
pub struct Ctx<'a> {
    /// The plugin data dir.
    pub dir: &'a DataDir,
    /// The process working directory.
    pub cwd: &'a Path,
    /// The engine's effective tier for `cwd` (the declared tier).
    pub effective: Tier,
    /// The user's home (passwd entry), for locating the settings file.
    pub home: Option<&'a Path>,
    /// Unix seconds.
    pub now: u64,
}

/// The result of a command.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// Done; print the JSON, exit 0.
    Ok(Value),
    /// `check` found drift; print the JSON, exit 1.
    Drift(Value),
    /// Lowering: park this for confirmation (`PendingKind::Firewall`), nothing was written.
    Park {
        /// The human summary.
        summary: String,
        /// For [`apply_confirmed`].
        payload: Value,
    },
    /// Refused or failed; print the JSON, exit 1.
    Error(String),
}

/// Run a parsed command.
pub fn run(cmd: &Command, ctx: &Ctx<'_>) -> Outcome {
    match cmd {
        Command::Show => Outcome::Ok(show(ctx)),
        Command::Check => {
            let report = check(ctx);
            if report.drift.is_empty() {
                Outcome::Ok(report.to_json())
            } else {
                Outcome::Drift(report.to_json())
            }
        }
        Command::Apply {
            tier,
            project,
            dry_run,
        } => apply_cmd(ctx, *tier, *project, *dry_run),
    }
}

/// What the previous apply to a target says, for the lowering decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prior {
    /// Never applied here.
    None,
    /// The authenticated record (trusted data dir).
    Applied(Record),
    /// The record of an untrusted data dir, which the agent may have written: it can only raise
    /// the floor, and lowering is refused.
    Untrusted(Option<Record>),
    /// A trusted record that failed authentication or was deleted after being stored: lowering
    /// from it counts as lowering from High.
    FailClosed,
}

impl Prior {
    /// The record, trusted or not (ownership is also bounded by [`rules::emittable`]).
    pub fn record(&self) -> Option<&Record> {
        match self {
            Prior::Applied(r) | Prior::Untrusted(Some(r)) => Some(r),
            _ => None,
        }
    }

    /// The tier a lowering is measured from, by the record alone.
    pub fn floor(&self) -> Option<Tier> {
        match self {
            Prior::None | Prior::Untrusted(None) => None,
            Prior::Applied(r) | Prior::Untrusted(Some(r)) => Some(r.tier),
            Prior::FailClosed => Some(Tier::High),
        }
    }
}

/// The previous apply to `key`.
pub fn prior(dir: &DataDir, key: &str) -> Prior {
    let loaded = statefile::load::<RecordFile>(dir, RECORD_FILE);
    if !dir.trusted {
        return Prior::Untrusted(match loaded {
            Loaded::Valid(f) => f.targets.get(key).cloned(),
            _ => None,
        });
    }
    match loaded {
        Loaded::Valid(f) => f
            .targets
            .get(key)
            .cloned()
            .map_or(Prior::None, Prior::Applied),
        Loaded::Tampered => Prior::FailClosed,
        Loaded::Missing if statefile::was_stored(dir, RECORD_FILE) => Prior::FailClosed,
        Loaded::Missing => Prior::None,
    }
}

/// The tier the live settings file already enforces, judged from its content alone (so a
/// deleted or forged record cannot make a lowering look like a raise): High's fence, Medium's
/// `bash -c` deny or host-token read denies, or an enabled sandbox.
pub fn inferred_tier(doc: &Json) -> Option<Tier> {
    let has = |path: &str, e: &str| doc.at(path).is_some_and(|v| v.strings().contains(&e));
    if doc.at("permissions.blockReadsOutsideWorkingDirectories") == Some(&Json::Bool(true))
        || has("sandbox.filesystem.denyRead", "~/")
    {
        Some(Tier::High)
    } else if has("permissions.deny", rules::DENY_BASH_C[0])
        || has("sandbox.filesystem.denyRead", "~/.npmrc")
    {
        Some(Tier::Medium)
    } else if doc.at("sandbox.enabled") == Some(&Json::Bool(true)) {
        Some(Tier::Relaxed)
    } else {
        None
    }
}

fn live_doc(t: &Target) -> Option<Json> {
    target::read_settings(&t.settings)
        .ok()
        .flatten()
        .and_then(|text| json::parse(&text).ok())
}

fn tier_change(ctx: &Ctx<'_>, tier: Tier, project: bool) -> tierstate::Change {
    tierstate::Change {
        project: project.then(|| tierstate::root_key(&ptier::project_root(ctx.cwd))),
        tier: Some(tier),
        env_read: None,
        clear: false,
    }
}

fn apply_cmd(ctx: &Ctx<'_>, named: Option<Tier>, project: bool, dry_run: bool) -> Outcome {
    let t = target::locate(ctx.cwd, ctx.home);
    if let Err(e) = target::check_writable(&t) {
        return Outcome::Error(e);
    }
    let tier = named.unwrap_or(ctx.effective);
    let change = named.map(|n| tier_change(ctx, n, project));
    let tier_plan = change.as_ref().map(|c| tierstate::plan(ctx.dir, c));
    let prior = prior(ctx.dir, &t.key());
    let floor = prior
        .floor()
        .max(live_doc(&t).as_ref().and_then(inferred_tier));
    let lowering_block = floor.is_some_and(|f| tier < f);
    let lowering_tier = tier_plan == Some(tierstate::Plan::NeedsConfirm);
    let needs_confirm = lowering_block || lowering_tier;

    if dry_run || needs_confirm {
        let preview = match compute(&t, tier, &prior) {
            Ok(p) => p,
            Err(e) => return Outcome::Error(e),
        };
        if dry_run {
            let mut v = preview.to_json(&t, tier, "dry-run");
            v["needs_confirmation"] = Value::Bool(needs_confirm);
            return Outcome::Ok(v);
        }
        if lowering_block && !ctx.dir.trusted {
            return Outcome::Error(
                "the plugin data dir is untrusted, so the firewall's record cannot prove what it \
                 last applied and lowering is refused; run safe-ai-skill doctor to fix the data \
                 dir, then run the command again"
                    .to_string(),
            );
        }
        let summary = format!("firewall apply {} ({})", tier.label(), t.settings.display());
        let payload = j!({
            "tier": tier.label(),
            "project": change.as_ref().and_then(|c| c.project.clone()),
            "named": named.is_some(),
            "cwd": ctx.cwd.to_string_lossy(),
            "settings": t.key(),
        });
        return Outcome::Park { summary, payload };
    }

    if let (Some(c), Some(tierstate::Plan::Immediate)) = (&change, tier_plan) {
        if let Err(e) = tierstate::apply(ctx.dir, c, ctx.now) {
            return Outcome::Error(format!("could not record the tier: {e}"));
        }
    }
    match write(ctx.dir, &t, tier, &prior, ctx.now) {
        Ok(applied) => Outcome::Ok(applied),
        Err(e) => Outcome::Error(e),
    }
}

/// Perform a confirmed `firewall apply` (the `PendingKind::Firewall` activation): record the
/// named tier (as `tier` would) and write the block. Returns the summary for the user.
pub fn apply_confirmed(
    dir: &DataDir,
    payload: &Value,
    home: Option<&Path>,
    now: u64,
) -> Result<String, String> {
    let bad = || "the pending firewall change is invalid".to_string();
    let tier = payload
        .get("tier")
        .and_then(Value::as_str)
        .and_then(Tier::parse)
        .ok_or_else(bad)?;
    let cwd = PathBuf::from(payload.get("cwd").and_then(Value::as_str).ok_or_else(bad)?);
    let t = target::locate(&cwd, home);
    if payload.get("settings").and_then(Value::as_str) != Some(t.key().as_str()) {
        return Err("the project's settings file moved since the request; run it again".into());
    }
    target::check_writable(&t)?;
    if payload.get("named").and_then(Value::as_bool) == Some(true) {
        let change = tierstate::Change {
            project: payload
                .get("project")
                .and_then(Value::as_str)
                .map(str::to_string),
            tier: Some(tier),
            env_read: None,
            clear: false,
        };
        tierstate::apply(dir, &change, now).map_err(|e| format!("could not store it: {e}"))?;
    }
    let p = prior(dir, &t.key());
    write(dir, &t, tier, &p, now)?;
    Ok(format!(
        "firewall {} applied to {}; it takes effect in the next session",
        tier.label(),
        t.settings.display()
    ))
}

/// A computed apply, before anything is written.
#[derive(Debug, Clone)]
struct Preview {
    original: Option<String>,
    text: Option<String>,
    merged: merge::Merged,
    block: Block,
    warnings: Vec<String>,
}

impl Preview {
    fn changed(&self) -> bool {
        self.text.is_some()
    }

    fn to_json(&self, t: &Target, tier: Tier, status: &str) -> Value {
        let rules: usize = self.merged.rule_ids.values().map(Vec::len).sum();
        j!({
            "command": "firewall",
            "action": "apply",
            "status": status,
            "tier": tier.label(),
            "target": t.key(),
            "rule_set_version": RULE_SET_VERSION,
            "rules_owned": rules,
            "scalars_owned": self.merged.scalars,
            "changes": self.merged.changes,
            "left_as_is": self.merged.user_held,
            "warnings": self.warnings,
            "created": self.original.is_none() && self.changed(),
            "message": "Claude Code reads these settings at session start, so the change takes \
                        effect in the next session.",
        })
    }
}

fn domains(tier: Tier) -> Result<Vec<&'static str>, String> {
    crate::lists::exfil_hosts(tier).map_err(|e| e.to_string())
}

fn machine(t: &Target) -> MachineInputs {
    MachineInputs {
        git_common_outside: t
            .git_common_outside
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned()),
    }
}

fn compute(t: &Target, tier: Tier, prior: &Prior) -> Result<Preview, String> {
    let original = target::read_settings(&t.settings)?;
    let doc = match &original {
        Some(text) if !text.trim().is_empty() => json::parse(text).map_err(|e| {
            format!(
                "{} is not valid JSON ({e}); fix it and run the command again",
                t.settings.display()
            )
        })?,
        _ => Json::Obj(Vec::new()),
    };
    if !matches!(doc, Json::Obj(_)) {
        return Err(format!(
            "{} does not hold a JSON object; fix it and run the command again",
            t.settings.display()
        ));
    }
    let m = machine(t);
    let block = rules::plan(tier, &domains(tier)?, &m);
    let high = domains(Tier::High)?;
    let emit = |path: &str| rules::emittable(path, &high, &m);
    let rec = prior.record();
    let owned = merge::Owned {
        rule_ids: rec.map(|r| &r.rule_ids),
        scalars: rec.map_or(&[], |r| r.scalars.as_slice()),
    };
    let merged = merge::merge(&doc, &block, &owned, &emit);
    let text = (merged.doc != doc).then(|| {
        let unit = original
            .as_deref()
            .map_or_else(|| "  ".to_string(), json::detect_indent);
        json::to_text_with(&merged.doc, &unit)
    });
    let warnings = warnings(t, tier);
    Ok(Preview {
        original,
        text,
        merged,
        block,
        warnings,
    })
}

/// Facts that limit what the written block can do.
fn warnings(t: &Target, tier: Tier) -> Vec<String> {
    let mut out = Vec::new();
    if tier == Tier::Off {
        return out;
    }
    if !crate::sandbox::platform_supported() {
        out.push(
            "Claude Code cannot run its sandbox on this platform (macOS, or Linux/WSL2 with \
             bubblewrap), so the sandbox settings are declared only; the permission rules still \
             apply."
                .to_string(),
        );
    }
    if managed_sandbox_off() {
        out.push(
            "managed settings set sandbox.enabled to false, which outranks this file, so the \
             sandbox stays off; ask your administrator to enable it."
                .to_string(),
        );
    }
    if tier == Tier::High && (!t.in_git || target::tracked_by_git(t) != Some(false)) {
        out.push(
            "at high, Claude Code ignores allowRead and allowWrite from repository settings, and \
             it counts settings.local.json as repository settings outside a git repository or \
             when git tracks it, so the toolchain carve-outs will not apply and cargo or anchor \
             may fail to read their caches; add them to ~/.claude/settings.json if they do."
                .to_string(),
        );
    }
    out
}

fn managed_sandbox_off() -> bool {
    [
        "/Library/Application Support/ClaudeCode/managed-settings.json",
        "/etc/claude-code/managed-settings.json",
    ]
    .iter()
    .filter_map(|p| target::read_settings(Path::new(p)).ok().flatten())
    .filter_map(|t| serde_json::from_str::<Value>(&t).ok())
    .any(|v| v["sandbox"]["enabled"] == Value::Bool(false))
}

fn fingerprint(tier: Tier, block: &Block) -> String {
    let lists: BTreeMap<&str, &Vec<String>> = block.lists.iter().map(|(p, v)| (*p, v)).collect();
    let body = j!({
        "ruleSetVersion": RULE_SET_VERSION,
        "tier": tier.label(),
        "lists": lists,
        "scalars": block.scalars,
    });
    let digest = Sha256::digest(body.to_string().as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Compute, record and write `tier` for `t`. The record is stored first, so a failed file write
/// leaves a record that only names entries the next apply will not find (reported as drift),
/// never a written entry the record does not name.
fn write(dir: &DataDir, t: &Target, tier: Tier, prior: &Prior, now: u64) -> Result<Value, String> {
    let preview = compute(t, tier, prior)?;
    let record = Record {
        tier,
        rule_set_version: RULE_SET_VERSION,
        rule_ids: preview.merged.rule_ids.clone(),
        scalars: preview.merged.scalars.clone(),
        sha256: fingerprint(tier, &preview.block),
        applied_at: now,
    };
    let mut file = match statefile::load::<RecordFile>(dir, RECORD_FILE) {
        Loaded::Valid(f) => f,
        _ => RecordFile::default(),
    };
    file.targets.insert(t.key(), record);
    statefile::store(dir, RECORD_FILE, &file)
        .map_err(|e| format!("could not store the firewall record: {e}"))?;
    if let Some(text) = &preview.text {
        target::check_writable(t)?;
        let result = match target::mode_of(&t.settings) {
            Some(mode) => crate::env::write::atomic_replace(&t.settings, text.as_bytes(), mode),
            None => {
                if std::fs::symlink_metadata(&t.config_dir).is_err() {
                    std::fs::create_dir(&t.config_dir)
                        .map_err(|e| format!("cannot create {}: {e}", t.config_dir.display()))?;
                }
                target::check_writable(t)?;
                crate::env::write::create_new_atomic(&t.settings, text.as_bytes(), 0o600)
            }
        };
        result.map_err(|e| format!("cannot write {}: {e}", t.settings.display()))?;
    }
    let status = if preview.changed() {
        "applied"
    } else {
        "unchanged"
    };
    Ok(preview.to_json(t, tier, status))
}

/// One drift finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Drift {
    /// A stable id: `not-applied`, `tier`, `absent`, `rule-set`, `record`.
    pub kind: &'static str,
    /// One sentence ending with the remedy.
    pub message: String,
}

/// The state of a target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The settings file.
    pub target: String,
    /// The declared (effective engine) tier.
    pub declared: Tier,
    /// The record, when there is one.
    pub enforced: Option<Record>,
    /// Recorded entries missing from the live file.
    pub absent: Vec<String>,
    /// Every finding.
    pub drift: Vec<Drift>,
}

impl Report {
    /// The report as JSON.
    pub fn to_json(&self) -> Value {
        j!({
            "command": "firewall",
            "action": "check",
            "status": if self.drift.is_empty() { "ok" } else { "drift" },
            "target": self.target,
            "declared": self.declared.label(),
            "enforced": self.enforced.as_ref().map(|r| r.tier.label()),
            "rule_set_version": self.enforced.as_ref().map(|r| r.rule_set_version),
            "shipped_rule_set_version": RULE_SET_VERSION,
            "absent": self.absent.len(),
            "drift": self.drift,
        })
    }
}

/// Compare declared and enforced for the project at `ctx.cwd` (T3). Reads one settings file
/// and the record; writes nothing.
pub fn check(ctx: &Ctx<'_>) -> Report {
    let t = target::locate(ctx.cwd, ctx.home);
    let p = prior(ctx.dir, &t.key());
    let mut drift = Vec::new();
    let mut absent = Vec::new();
    if matches!(p, Prior::FailClosed | Prior::Untrusted(_)) {
        drift.push(Drift {
            kind: "record",
            message: "the firewall record failed authentication, was deleted, or sits in an \
                      untrusted data dir; run safe-ai-skill firewall apply to rewrite it"
                .to_string(),
        });
    }
    let enforced = p.record().cloned();
    match &enforced {
        None => {
            if ctx.effective != Tier::Off {
                drift.push(Drift {
                    kind: "not-applied",
                    message: format!(
                        "tier {} is declared but no firewall block was applied to {}; run \
                         safe-ai-skill firewall apply",
                        ctx.effective.label(),
                        t.settings.display()
                    ),
                });
            }
        }
        Some(r) => {
            if r.tier != ctx.effective {
                drift.push(Drift {
                    kind: "tier",
                    message: format!(
                        "tier {} is declared but the firewall block enforces {}; run \
                         safe-ai-skill firewall apply",
                        ctx.effective.label(),
                        r.tier.label()
                    ),
                });
            }
            if r.rule_set_version < RULE_SET_VERSION {
                drift.push(Drift {
                    kind: "rule-set",
                    message: format!(
                        "the block was written by rule set {} and this engine ships {}; run \
                         safe-ai-skill firewall apply",
                        r.rule_set_version, RULE_SET_VERSION
                    ),
                });
            }
            let live = live_doc(&t);
            for (path, entries) in &r.rule_ids {
                let have: Vec<&str> = live
                    .as_ref()
                    .and_then(|d| d.at(path))
                    .map(Json::strings)
                    .unwrap_or_default();
                absent.extend(
                    entries
                        .iter()
                        .filter(|e| !have.contains(&e.as_str()))
                        .map(|e| format!("{path}: {e}")),
                );
            }
            for s in &r.scalars {
                if live.as_ref().and_then(|d| d.at(s)) != Some(&Json::Bool(true)) {
                    absent.push(format!("{s}: true"));
                }
            }
            if !absent.is_empty() {
                drift.push(Drift {
                    kind: "absent",
                    message: format!(
                        "{} setting(s) the last apply wrote are missing from {}; run \
                         safe-ai-skill firewall apply to restore them",
                        absent.len(),
                        t.settings.display()
                    ),
                });
            }
        }
    }
    Report {
        target: t.key(),
        declared: ctx.effective,
        enforced,
        absent,
        drift,
    }
}

/// `firewall show`: the report plus the block the declared tier would write.
pub fn show(ctx: &Ctx<'_>) -> Value {
    let report = check(ctx);
    let mut v = report.to_json();
    v["action"] = Value::String("show".to_string());
    v["absent_entries"] = j!(report.absent);
    let m = machine(&target::locate(ctx.cwd, ctx.home));
    if let Ok(d) = domains(ctx.effective) {
        let block = rules::plan(ctx.effective, &d, &m);
        let counts: BTreeMap<&str, usize> =
            block.lists.iter().map(|(p, e)| (*p, e.len())).collect();
        v["declared_block"] = j!({ "lists": counts, "scalars": block.scalars });
    }
    v
}

/// The SessionStart drift line (T3), or `None` when nothing was ever applied here or nothing
/// drifted. One short sentence per finding, joined; never file content.
pub fn session_note(ctx: &Ctx<'_>) -> Option<String> {
    let report = check(ctx);
    if report.enforced.is_none() && !report.drift.iter().any(|d| d.kind == "record") {
        // Never applied here: the user has not opted in, so nothing to nag about.
        return None;
    }
    if report.drift.is_empty() {
        return None;
    }
    let lines: Vec<&str> = report.drift.iter().map(|d| d.message.as_str()).collect();
    Some(format!("safe-ai-skill firewall: {}.", lines.join("; ")))
}

/// At SessionStart, re-apply a trusted record when the shipped rule set is newer (T6) or the
/// declared tier is higher than the enforced one. It never lowers. Returns a note when it wrote.
pub fn session_resync(ctx: &Ctx<'_>) -> Option<String> {
    if !ctx.dir.trusted {
        return None;
    }
    let t = target::locate(ctx.cwd, ctx.home);
    let p = prior(ctx.dir, &t.key());
    let Prior::Applied(rec) = &p else {
        return None;
    };
    let tier = rec.tier.max(ctx.effective);
    if rec.rule_set_version >= RULE_SET_VERSION && tier == rec.tier {
        return None;
    }
    target::check_writable(&t).ok()?;
    match write(ctx.dir, &t, tier, &p, ctx.now) {
        Ok(_) => Some(format!(
            "safe-ai-skill firewall: re-applied tier {} (rule set {}) to {}; it takes effect in \
             the next session.",
            tier.label(),
            RULE_SET_VERSION,
            t.settings.display()
        )),
        Err(e) => Some(format!("safe-ai-skill firewall: re-apply failed: {e}.")),
    }
}
