//! The shared conformance corpus (`policy/shared/corpus/*.jsonl`, contract §2) and its engine
//! runner.
//!
//! - `shared_corpus_schema` (always on): every row parses against the schema, ids are unique,
//!   verdict strings are well formed, `combined` equals `combine(plugin, kit)`, and the contract
//!   invariants 1 to 3 hold on the file itself.
//! - `shared_corpus_plugin_column`: drives the built binary through the hook entry the plugin wires for the row's tool, once per
//!   tier, and asserts the `plugin` column. It also asserts invariants 1 to 3 on the actual
//!   verdicts combined with the row's `kit` column, and that no-opinion cells print nothing.
//!   Rows that need an authenticated `tier.json`, a grant or a sandbox override need
//!   `--features test-hooks`: without it the run fails (naming the feature), unless
//!   `SHARED_CORPUS_ALLOW_SKIP=1` accepts the skipped cells. A filter matching nothing fails.
//!   It assumes `gate-bash` is wired unconditionally (no `hooks.json` `if` filter). A row whose
//!   `interim.plugin` is set (the shipped engine differs from the end state, with a reason) is
//!   held to that interim verdict, unless the build has its `interim.until_feature`.
//! - `conformance_diff_fails_on_bad_input` (always on, unix): `scripts/conformance-diff.sh` exits
//!   non-zero on empty, garbage, partial and duplicate input.
//! - `runner_plumbing_smoke` (always on): four rows the 1.1.0 gates already satisfy, so a broken
//!   materialiser shows up in a plain `cargo test`.
//!
//! Run the full matrix: `cargo test --features test-hooks --test shared_corpus` (add
//! `env-read-opt-in` for the opt-in rows' end state).
//! `SHARED_CORPUS_FILTER=<id substring>[,..]` narrows it; `SHARED_CORPUS_RESULTS=<path>` writes
//! one `{"id","plugin"}` line per row for `scripts/conformance-diff.sh` (`?` marks a tier that was
//! skipped or errored).
//!
//! Nothing here touches the real HOME: every run gets a temporary root with `home/`, the project
//! dir, a plugin-data dir and a `PATH` holding nothing, or only a stub `solana` that answers
//! `config get` from the temp HOME's CLI config file when the row writes one. No network.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use common::{EnvRead, Invocation, SandboxMode, TempDir, Tier, TEST_HOOKS};
use safe_ai_skill::datadir::DataDir;
use safe_ai_skill::grants::{self, Grant, Grants};
use serde_json::Value;

const TIERS: [Tier; 4] = [Tier::Off, Tier::Relaxed, Tier::Medium, Tier::High];
const TIER_WORDS: [&str; 4] = ["off", "relaxed", "medium", "high"];

/// The corpus files, one per topic (contract §2.1, split spec F6).
const FILES: [&str; 8] = [
    "cluster",
    "wrappers",
    "irreversible",
    "credentials",
    "exfil",
    "env",
    "tier",
    "headless",
];

const MIN_ROWS: usize = 120;

/// The contract 3.3 headless signal variables.
const HEADLESS_SIGNALS: [&str; 7] = [
    "SAFE_AI_SKILL_HEADLESS",
    "KIT_FIREWALL_HEADLESS",
    "CI",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "BUILDKITE",
    "JENKINS_URL",
];

/// Env names the runner owns; a row may not set them.
const RESERVED_ENV: [&str; 7] = [
    "HOME",
    "PATH",
    "CLAUDE_PLUGIN_ROOT",
    "CLAUDE_PLUGIN_DATA",
    "CLAUDE_CONFIG_DIR",
    "SAFE_AI_SKILL_HOME",
    "SAFE_AI_SKILL_DISABLE",
];

type Verdicts = [char; 4];

#[derive(Debug, Clone, PartialEq)]
enum UserTier {
    /// `null`: the column tier is the user's selection.
    Column,
    /// `"default"`: no `tier.json` at all.
    Default,
    /// A fixed user selection; all four columns must then be equal.
    Fixed(Tier),
}

#[derive(Debug, Clone)]
struct GrantSpec {
    scope: String,
    max_tx_sol: f64,
    budget_sol: f64,
    danger: bool,
}

#[derive(Debug, Clone)]
struct Ctx {
    sandbox: SandboxMode,
    headless: bool,
    user_policy: Value,
    repo_policy: Value,
    user_tier: UserTier,
    repo_tier: Option<Tier>,
    grants: Vec<GrantSpec>,
    pre_cli: Vec<Vec<String>>,
}

#[derive(Debug, Clone)]
struct Interim {
    plugin: Option<Verdicts>,
    kit: Option<Verdicts>,
    combined: Verdicts,
    /// Why the plugin's shipped verdict differs from its end state (required with `plugin`).
    reason: Option<String>,
    /// A cargo feature that already gives the end state: built with it, the runner asserts
    /// `expect.plugin` instead of `interim.plugin`.
    until_feature: Option<String>,
}

#[derive(Debug, Clone)]
struct Expect {
    plugin: Verdicts,
    kit: Verdicts,
    combined: Verdicts,
    owner: String,
    interim: Option<Interim>,
    updated_input: bool,
}

#[derive(Debug, Clone)]
struct Row {
    file: String,
    id: String,
    tool: String,
    input: Value,
    cwd: String,
    env: Vec<(String, String)>,
    files: Vec<(String, String)>,
    ctx: Ctx,
    expect: Expect,
    os: Option<Vec<String>>,
}

// ------------------------------------------------------------------ schema and loading

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../policy/shared/corpus")
}

fn check_keys(
    obj: &serde_json::Map<String, Value>,
    allowed: &[&str],
    what: &str,
) -> Result<(), String> {
    for key in obj.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(format!("{what}: unknown key `{key}`"));
        }
    }
    Ok(())
}

fn verdicts(value: &Value, what: &str, allow_unknown: bool) -> Result<Verdicts, String> {
    let text = value
        .as_str()
        .ok_or_else(|| format!("{what}: not a string"))?;
    let chars: Vec<char> = text.chars().collect();
    if chars.len() != 4 {
        return Err(format!(
            "{what}: `{text}` is not four characters (Off Relaxed Medium High)"
        ));
    }
    let mut out = ['-'; 4];
    for (slot, c) in out.iter_mut().zip(&chars) {
        let ok = matches!(c, 'D' | 'A' | 'L' | '-') || (allow_unknown && *c == '?');
        if !ok {
            return Err(format!(
                "{what}: `{text}` has the invalid verdict character `{c}`"
            ));
        }
        *slot = *c;
    }
    Ok(out)
}

fn rank(c: char) -> u8 {
    match c {
        'D' => 3,
        'A' => 2,
        'L' => 1,
        _ => 0,
    }
}

/// `combined = max(plugin, kit)` per tier with `D > A > L > -`. A kit `?` (not asserted) leaves
/// the tier unknown unless the plugin already denies.
fn combine(plugin: Verdicts, kit: Verdicts) -> Verdicts {
    let mut out = ['-'; 4];
    for i in 0..4 {
        out[i] = match (plugin[i], kit[i]) {
            (p, '?') => {
                if p == 'D' {
                    'D'
                } else {
                    '?'
                }
            }
            (p, k) => {
                if rank(p) >= rank(k) {
                    p
                } else {
                    k
                }
            }
        };
    }
    out
}

fn text_of(v: Verdicts) -> String {
    v.iter().collect()
}

/// Contract §2.2 invariants 1 to 3 for one tier: `Some(message)` on a violation.
fn invariant(plugin: char, kit: char, headless: bool) -> Option<String> {
    if headless && (plugin == 'A' || kit == 'A') {
        return Some("invariant 3: an ask in a headless row".into());
    }
    if kit == '?' {
        return None;
    }
    if plugin == 'A' && kit == 'A' {
        return Some("invariant 1: plugin ask and kit ask (double prompt)".into());
    }
    if plugin == 'L' && kit == 'A' {
        return Some("invariant 2: plugin allow neutralised by a kit ask".into());
    }
    None
}

fn str_field<'a>(
    obj: &'a serde_json::Map<String, Value>,
    key: &str,
    what: &str,
) -> Result<&'a str, String> {
    obj.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{what}: `{key}` missing or not a string"))
}

fn parse_tier_word(word: &str) -> Option<Tier> {
    TIER_WORDS.iter().position(|w| *w == word).map(|i| TIERS[i])
}

fn relative_ok(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.split('/').any(|seg| seg == ".." || seg.is_empty())
}

fn parse_ctx(v: &Value, what: &str) -> Result<Ctx, String> {
    let obj = v
        .as_object()
        .ok_or_else(|| format!("{what}: ctx not an object"))?;
    check_keys(
        obj,
        &[
            "sandbox",
            "headless",
            "user_policy",
            "repo_policy",
            "user_tier",
            "repo_tier",
            "grants",
            "pre_cli",
        ],
        &format!("{what} ctx"),
    )?;
    let sandbox = match obj.get("sandbox").and_then(Value::as_str) {
        Some("on") => SandboxMode::On,
        Some("off") => SandboxMode::Off,
        Some("unset") => SandboxMode::Unset,
        other => {
            return Err(format!(
                "{what}: ctx.sandbox must be on|off|unset, got {other:?}"
            ))
        }
    };
    let headless = obj
        .get("headless")
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("{what}: ctx.headless must be a boolean"))?;
    for key in ["user_policy", "repo_policy"] {
        match obj.get(key) {
            Some(Value::Object(_)) => {}
            _ => return Err(format!("{what}: ctx.{key} must be an object")),
        }
    }
    let user_policy = obj["user_policy"].clone();
    if let Some(word) = user_policy.pointer("/secrets/env_read") {
        let ok = word.as_str().and_then(EnvRead::parse).is_some();
        if !ok {
            return Err(format!(
                "{what}: ctx.user_policy.secrets.env_read must be deny|ask|tier"
            ));
        }
    }
    let user_tier = match obj.get("user_tier") {
        Some(Value::Null) => UserTier::Column,
        Some(Value::String(s)) if s == "default" => UserTier::Default,
        Some(Value::String(s)) => UserTier::Fixed(
            parse_tier_word(s)
                .ok_or_else(|| format!("{what}: ctx.user_tier `{s}` is not a tier"))?,
        ),
        _ => {
            return Err(format!(
                "{what}: ctx.user_tier must be null, \"default\" or a tier"
            ))
        }
    };
    let repo_tier = match obj.get("repo_tier") {
        Some(Value::Null) => None,
        Some(Value::String(s)) => Some(
            parse_tier_word(s)
                .ok_or_else(|| format!("{what}: ctx.repo_tier `{s}` is not a tier"))?,
        ),
        _ => return Err(format!("{what}: ctx.repo_tier must be null or a tier")),
    };
    let mut grants = Vec::new();
    for g in obj
        .get("grants")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let go = g
            .as_object()
            .ok_or_else(|| format!("{what}: grant not an object"))?;
        check_keys(
            go,
            &["scope", "max_tx_sol", "budget_sol", "danger"],
            &format!("{what} grant"),
        )?;
        let scope = str_field(go, "scope", what)?.to_string();
        if grants::grantable_scope(&scope).is_err() {
            return Err(format!("{what}: grant scope `{scope}` is not grantable"));
        }
        grants.push(GrantSpec {
            scope,
            max_tx_sol: go.get("max_tx_sol").and_then(Value::as_f64).unwrap_or(0.0),
            budget_sol: go.get("budget_sol").and_then(Value::as_f64).unwrap_or(0.0),
            danger: go.get("danger").and_then(Value::as_bool).unwrap_or(false),
        });
    }
    let mut pre_cli = Vec::new();
    for cmd in obj
        .get("pre_cli")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let args = cmd
            .as_array()
            .ok_or_else(|| format!("{what}: pre_cli entries are argument arrays"))?;
        let args: Option<Vec<String>> = args
            .iter()
            .map(|a| a.as_str().map(str::to_string))
            .collect();
        pre_cli.push(args.ok_or_else(|| format!("{what}: pre_cli arguments must be strings"))?);
    }
    Ok(Ctx {
        sandbox,
        headless,
        user_policy,
        repo_policy: obj["repo_policy"].clone(),
        user_tier,
        repo_tier,
        grants,
        pre_cli,
    })
}

fn parse_expect(v: &Value, what: &str) -> Result<Expect, String> {
    let obj = v
        .as_object()
        .ok_or_else(|| format!("{what}: expect not an object"))?;
    check_keys(
        obj,
        &[
            "plugin",
            "kit",
            "combined",
            "owner",
            "interim",
            "updated_input",
            "note",
        ],
        &format!("{what} expect"),
    )?;
    let get = |key: &str, unknown: bool| -> Result<Verdicts, String> {
        verdicts(
            obj.get(key).unwrap_or(&Value::Null),
            &format!("{what} expect.{key}"),
            unknown,
        )
    };
    let owner = str_field(obj, "owner", what)?.to_string();
    if owner != "plugin" && owner != "kit" {
        return Err(format!("{what}: expect.owner must be plugin|kit"));
    }
    let interim = match obj.get("interim") {
        None => None,
        Some(Value::Object(io)) => {
            check_keys(
                io,
                &["plugin", "kit", "combined", "reason", "until_feature"],
                &format!("{what} interim"),
            )?;
            let text = |key: &str| -> Result<Option<String>, String> {
                match io.get(key) {
                    None => Ok(None),
                    Some(Value::String(t)) if !t.is_empty() => Ok(Some(t.clone())),
                    Some(_) => Err(format!("{what}: interim.{key} must be a non-empty string")),
                }
            };
            if io.contains_key("plugin") && !io.contains_key("reason") {
                return Err(format!("{what}: interim.plugin needs interim.reason"));
            }
            let until_feature = text("until_feature")?;
            if until_feature
                .as_deref()
                .is_some_and(|f| !KNOWN_FEATURES.contains(&f))
            {
                return Err(format!(
                    "{what}: interim.until_feature names an unknown feature"
                ));
            }
            let opt = |key: &str, unknown: bool| -> Result<Option<Verdicts>, String> {
                io.get(key)
                    .map(|x| verdicts(x, &format!("{what} interim.{key}"), unknown))
                    .transpose()
            };
            Some(Interim {
                plugin: opt("plugin", false)?,
                kit: opt("kit", true)?,
                combined: verdicts(
                    io.get("combined").unwrap_or(&Value::Null),
                    &format!("{what} interim.combined"),
                    true,
                )?,
                reason: text("reason")?,
                until_feature,
            })
        }
        Some(_) => return Err(format!("{what}: expect.interim must be an object")),
    };
    Ok(Expect {
        plugin: get("plugin", false)?,
        kit: get("kit", true)?,
        combined: get("combined", true)?,
        owner,
        interim,
        updated_input: obj
            .get("updated_input")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

fn parse_row(file: &str, line_no: usize, line: &str) -> Result<Row, String> {
    let v: Value = serde_json::from_str(line)
        .map_err(|e| format!("{file}.jsonl:{line_no}: invalid JSON: {e}"))?;
    let obj = v
        .as_object()
        .ok_or_else(|| format!("{file}.jsonl:{line_no}: not an object"))?;
    let id = str_field(obj, "id", &format!("{file}.jsonl:{line_no}"))?.to_string();
    let what = format!("{file}.jsonl:{line_no} ({id})");
    check_keys(
        obj,
        &[
            "id", "rows", "tool", "input", "cwd", "env", "files", "ctx", "expect", "os",
        ],
        &what,
    )?;
    let id_ok = !id.is_empty()
        && id
            .split('-')
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_alphanumeric()));
    if !id_ok {
        return Err(format!(
            "{what}: id must be alphanumeric parts joined by `-`"
        ));
    }
    match obj.get("rows").and_then(Value::as_array) {
        Some(rows) if rows.iter().all(|r| r.as_u64().is_some()) => {}
        _ => {
            return Err(format!(
                "{what}: rows must be an array of overlap-matrix row numbers"
            ))
        }
    }
    let tool = str_field(obj, "tool", &what)?.to_string();
    let known_tool = matches!(
        tool.as_str(),
        "Bash"
            | "Read"
            | "Grep"
            | "Glob"
            | "Write"
            | "Edit"
            | "MultiEdit"
            | "NotebookEdit"
            | "Skill"
    ) || tool.starts_with("mcp__");
    if !known_tool {
        return Err(format!("{what}: unknown tool `{tool}`"));
    }
    let input = obj
        .get("input")
        .filter(|i| i.is_object())
        .cloned()
        .ok_or_else(|| format!("{what}: input must be an object"))?;
    if tool == "Bash" && input.get("command").and_then(Value::as_str).is_none() {
        return Err(format!("{what}: a Bash row needs input.command"));
    }
    let cwd = str_field(obj, "cwd", &what)?.to_string();
    if !relative_ok(&cwd) {
        return Err(format!("{what}: cwd must be a relative directory name"));
    }
    let mut env = Vec::new();
    for (k, val) in obj
        .get("env")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{what}: env must be an object"))?
    {
        let val = val
            .as_str()
            .ok_or_else(|| format!("{what}: env values are strings"))?;
        if RESERVED_ENV.contains(&k.as_str()) || k.starts_with("SAFE_AI_SKILL_TEST_") {
            return Err(format!("{what}: env `{k}` is owned by the runner"));
        }
        env.push((k.clone(), val.to_string()));
    }
    let mut files = Vec::new();
    for (k, val) in obj
        .get("files")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{what}: files must be an object"))?
    {
        let val = val
            .as_str()
            .ok_or_else(|| format!("{what}: file contents are strings"))?;
        let path_ok = match k.strip_prefix("~/") {
            Some(rest) => relative_ok(rest),
            None => relative_ok(k),
        };
        if !path_ok {
            return Err(format!(
                "{what}: files key `{k}` must be relative (or `~/…`) without `..`"
            ));
        }
        files.push((k.clone(), val.to_string()));
    }
    let ctx = parse_ctx(obj.get("ctx").unwrap_or(&Value::Null), &what)?;
    let expect = parse_expect(obj.get("expect").unwrap_or(&Value::Null), &what)?;
    let os = match obj.get("os") {
        None => None,
        Some(Value::Array(list)) => {
            let names: Option<Vec<String>> = list
                .iter()
                .map(|x| x.as_str().map(str::to_string))
                .collect();
            let names = names.ok_or_else(|| format!("{what}: os entries are strings"))?;
            if names.is_empty()
                || names
                    .iter()
                    .any(|n| !["macos", "linux", "windows"].contains(&n.as_str()))
            {
                return Err(format!("{what}: os must list macos|linux|windows"));
            }
            Some(names)
        }
        Some(_) => return Err(format!("{what}: os must be an array")),
    };
    Ok(Row {
        file: file.to_string(),
        id,
        tool,
        input,
        cwd,
        env,
        files,
        ctx,
        expect,
        os,
    })
}

fn load_rows() -> Result<Vec<Row>, Vec<String>> {
    let dir = corpus_dir();
    let mut errors = Vec::new();
    let mut rows = Vec::new();
    let mut present = BTreeSet::new();
    match std::fs::read_dir(&dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                present.insert(entry.file_name().to_string_lossy().into_owned());
            }
        }
        Err(e) => return Err(vec![format!("{}: {e}", dir.display())]),
    }
    for name in &present {
        let known = name == "README.md" || FILES.iter().any(|f| *name == format!("{f}.jsonl"));
        if !known {
            errors.push(format!(
                "corpus/{name}: not a corpus file (expected {FILES:?} plus README.md)"
            ));
        }
    }
    for file in FILES {
        let path = dir.join(format!("{file}.jsonl"));
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                errors.push(format!("{}: {e}", path.display()));
                continue;
            }
        };
        if text.contains('\r') || !text.ends_with('\n') {
            errors.push(format!(
                "{file}.jsonl: must be LF-only and end with a newline"
            ));
        }
        for (i, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                errors.push(format!("{file}.jsonl:{}: blank line", i + 1));
                continue;
            }
            match parse_row(file, i + 1, line) {
                Ok(row) => rows.push(row),
                Err(e) => errors.push(e),
            }
        }
    }
    if errors.is_empty() {
        Ok(rows)
    } else {
        Err(errors)
    }
}

fn validate(rows: &[Row]) -> Vec<String> {
    let mut errors = Vec::new();
    let mut seen = BTreeSet::new();
    for row in rows {
        let at = format!("{}.jsonl {}", row.file, row.id);
        if !seen.insert(row.id.clone()) {
            errors.push(format!("{at}: duplicate id"));
        }
        let e = &row.expect;
        if combine(e.plugin, e.kit) != e.combined {
            errors.push(format!(
                "{at}: combined {} != combine(plugin {}, kit {}) = {}",
                text_of(e.combined),
                text_of(e.plugin),
                text_of(e.kit),
                text_of(combine(e.plugin, e.kit))
            ));
        }
        if let Some(i) = &e.interim {
            let p = i.plugin.unwrap_or(e.plugin);
            let k = i.kit.unwrap_or(e.kit);
            if combine(p, k) != i.combined {
                errors.push(format!(
                    "{at}: interim combined {} != combine(plugin {}, kit {})",
                    text_of(i.combined),
                    text_of(p),
                    text_of(k)
                ));
            }
        }
        for (t, word) in TIER_WORDS.iter().enumerate() {
            if let Some(why) = invariant(e.plugin[t], e.kit[t], row.ctx.headless) {
                errors.push(format!("{at} [{word}]: {why}"));
            }
        }
        if row.ctx.headless && e.combined.contains(&'A') {
            errors.push(format!("{at}: headless row with an ask in combined"));
        }
        if row.ctx.user_tier != UserTier::Column && !e.plugin.iter().all(|c| *c == e.plugin[0]) {
            errors.push(format!(
                "{at}: a fixed user_tier ignores the column tier, so plugin must be four equal characters"
            ));
        }
        if row.ctx.user_tier != UserTier::Column && !e.kit.iter().all(|c| *c == e.kit[0]) {
            errors.push(format!(
                "{at}: a fixed user_tier needs four equal kit characters"
            ));
        }
        if e.owner == "kit" && e.kit.iter().all(|c| *c == '-') {
            errors.push(format!("{at}: owner kit but the kit column has no verdict"));
        }
        if e.updated_input && e.plugin.iter().any(|c| *c != '-') {
            errors.push(format!("{at}: updated_input rows carry no decision"));
        }
    }
    if rows.len() < MIN_ROWS {
        errors.push(format!(
            "only {} rows, need at least {MIN_ROWS}",
            rows.len()
        ));
    }
    for file in FILES {
        if !rows.iter().any(|r| r.file == file) {
            errors.push(format!("{file}.jsonl has no rows"));
        }
    }
    errors
}

#[test]
fn shared_corpus_schema() {
    let rows = match load_rows() {
        Ok(rows) => rows,
        Err(errors) => panic!("corpus does not parse:\n{}", errors.join("\n")),
    };
    let errors = validate(&rows);
    assert!(
        errors.is_empty(),
        "corpus is inconsistent:\n{}",
        errors.join("\n")
    );
}

// ------------------------------------------------------------------ runner

fn hooks_for(tool: &str) -> &'static [&'static str] {
    match tool {
        "Bash" => &["gate-bash", "gate-bash-secrets"],
        "Read" | "Grep" | "Glob" => &["gate-read"],
        "Write" | "Edit" | "MultiEdit" | "NotebookEdit" => &["gate-tamper"],
        "Skill" => &["gate-skill"],
        _ => &["gate-mcp"],
    }
}

fn current_os() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(windows) {
        "windows"
    } else {
        "linux"
    }
}

fn env_read_of(row: &Row) -> Option<EnvRead> {
    row.ctx
        .user_policy
        .pointer("/secrets/env_read")
        .and_then(Value::as_str)
        .and_then(EnvRead::parse)
}

/// Why a (row, tier) cell cannot run with the features this binary was built with.
fn skip_reason(row: &Row, tier: Tier) -> Option<&'static str> {
    if let Some(os) = &row.os {
        if !os.iter().any(|o| o == current_os()) {
            return Some("os");
        }
    }
    if TEST_HOOKS {
        return None;
    }
    if row.ctx.user_tier == UserTier::Fixed(Tier::Off)
        || (row.ctx.user_tier == UserTier::Column && tier == Tier::Off)
    {
        return Some("Tier::Off needs test-hooks");
    }
    if env_read_of(row).is_some_and(|e| e != EnvRead::Deny) {
        return Some("a loosened env_read needs test-hooks");
    }
    if !row.ctx.grants.is_empty() {
        return Some("grants need a trusted data dir (test-hooks)");
    }
    if !row.ctx.pre_cli.is_empty() {
        return Some("pre_cli needs a trusted data dir (test-hooks)");
    }
    None
}

struct Paths {
    root: TempDir,
    home: PathBuf,
    proj: PathBuf,
    data: PathBuf,
    tools: PathBuf,
    plugin_root: Option<PathBuf>,
}

fn subst(text: &str, paths: &Paths) -> String {
    text.replace("{HOME}", &paths.home.display().to_string())
        .replace("{CWD}", &paths.proj.display().to_string())
}

fn subst_value(value: &Value, paths: &Paths) -> Value {
    match value {
        Value::String(s) => Value::String(subst(s, paths)),
        Value::Array(items) => Value::Array(items.iter().map(|v| subst_value(v, paths)).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), subst_value(v, paths)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn merge_yaml(base: serde_yaml::Value, overlay: serde_yaml::Value) -> serde_yaml::Value {
    match (base, overlay) {
        (serde_yaml::Value::Mapping(mut base_map), serde_yaml::Value::Mapping(over)) => {
            for (k, v) in over {
                let merged = match base_map.remove(&k) {
                    Some(old) => merge_yaml(old, v),
                    None => v,
                };
                base_map.insert(k, merged);
            }
            serde_yaml::Value::Mapping(base_map)
        }
        (_, over) => over,
    }
}

fn is_empty_object(v: &Value) -> bool {
    v.as_object().is_some_and(|o| o.is_empty())
}

#[cfg(unix)]
fn make_symlink(target: &Path, link: &Path) -> Result<(), String> {
    std::os::unix::fs::symlink(target, link).map_err(|e| format!("symlink {}: {e}", link.display()))
}

#[cfg(not(unix))]
fn make_symlink(_target: &Path, link: &Path) -> Result<(), String> {
    Err(format!(
        "symlink {}: unsupported on this platform",
        link.display()
    ))
}

fn materialise(row: &Row) -> Result<Paths, String> {
    let root = TempDir::new("corpus");
    let home = root.join("home");
    let proj = root.join(&row.cwd);
    let data = root.join("data");
    let tools = root.join("empty-path");
    for dir in [&home, &proj, &data, &tools] {
        std::fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    }
    let mut paths = Paths {
        root,
        home,
        proj,
        data,
        tools,
        plugin_root: None,
    };
    let place = |key: &str, paths: &Paths| -> PathBuf {
        match key.strip_prefix("~/") {
            Some(rest) => paths.home.join(rest),
            None => paths.root.join(key),
        }
    };
    for (key, content) in &row.files {
        let path = place(key, &paths);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        }
        if let Some(target) = content.strip_prefix("@symlink:") {
            let target = place(target, &paths);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
            }
            if !target.exists() {
                std::fs::write(&target, "")
                    .map_err(|e| format!("write {}: {e}", target.display()))?;
            }
            make_symlink(&target, &path)?;
        } else {
            std::fs::write(&path, subst(content, &paths))
                .map_err(|e| format!("write {}: {e}", path.display()))?;
        }
    }
    // A row writing the CLI config gets a stub `solana` answering `config get` from it, as
    // the real CLI would (the engine reads the default cluster only through the CLI).
    #[cfg(unix)]
    {
        let config = paths.home.join(".config/solana/cli/config.yml");
        if config.exists() {
            use std::os::unix::fs::PermissionsExt;
            let stub = paths.tools.join("solana");
            std::fs::write(
                &stub,
                "#!/bin/sh\n[ \"$1\" = config ] && [ \"$2\" = get ] || exit 1\n\
                 url=\nwhile IFS= read -r line; do\n  case \"$line\" in\n    \
                 json_rpc_url:*) url=${line#json_rpc_url:} ;;\n  esac\ndone \
                 < \"$HOME/.config/solana/cli/config.yml\"\nurl=${url# }\n\
                 echo \"Config File: $HOME/.config/solana/cli/config.yml\"\n\
                 echo \"RPC URL: $url\"\n",
            )
            .map_err(|e| format!("write solana stub: {e}"))?;
            std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755))
                .map_err(|e| format!("chmod solana stub: {e}"))?;
        }
    }
    if !is_empty_object(&row.ctx.repo_policy) {
        let dir = paths.proj.join(".safe-ai-skill");
        std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
        std::fs::write(dir.join("policy.yaml"), row.ctx.repo_policy.to_string())
            .map_err(|e| format!("write repo policy: {e}"))?;
    }
    // user_policy: everything but secrets.env_read lands in the base policy file the plugin
    // reads from $CLAUDE_PLUGIN_ROOT (env_read is the user's tier.json choice, set by the builder).
    let mut user = row.ctx.user_policy.clone();
    if let Some(secrets) = user.get_mut("secrets").and_then(Value::as_object_mut) {
        secrets.remove("env_read");
        if secrets.is_empty() {
            if let Some(map) = user.as_object_mut() {
                map.remove("secrets");
            }
        }
    }
    if !is_empty_object(&user) {
        let base: serde_yaml::Value =
            serde_yaml::from_str(safe_ai_skill::policy::DEFAULT_POLICY_YAML)
                .map_err(|e| format!("default policy: {e}"))?;
        let overlay = serde_yaml::to_value(&user).map_err(|e| format!("user policy: {e}"))?;
        let merged = serde_yaml::to_string(&merge_yaml(base, overlay))
            .map_err(|e| format!("user policy: {e}"))?;
        let root = paths.root.join("plugin");
        std::fs::create_dir_all(root.join("policy"))
            .map_err(|e| format!("mkdir plugin root: {e}"))?;
        std::fs::write(root.join("policy").join("default.policy.yaml"), merged)
            .map_err(|e| format!("write user policy: {e}"))?;
        paths.plugin_root = Some(root);
    }
    if TEST_HOOKS && !row.ctx.grants.is_empty() {
        let dir = DataDir {
            path: paths.data.clone(),
            trusted: true,
        };
        let mut list = Vec::new();
        for (n, spec) in row.ctx.grants.iter().enumerate() {
            let scope = grants::grantable_scope(&spec.scope)?;
            list.push(Grant {
                id: format!("g-corpus-{n}"),
                scope,
                programs: Vec::new(),
                to: Vec::new(),
                max_tx_sol: spec.max_tx_sol,
                budget_sol: spec.budget_sol,
                spent_sol: 0.0,
                expires_at: u64::MAX,
                danger: spec.danger,
            });
        }
        grants::save(&dir, &Grants { grants: list }).map_err(|e| format!("write grants: {e:?}"))?;
    }
    Ok(paths)
}

/// One invocation of `args` configured for `row` at the column `tier`.
fn invocation<'a>(args: &[&str], row: &Row, tier: Tier, paths: &'a Paths) -> Invocation<'a> {
    let mut inv = Invocation::new(args)
        .plugin_data(&paths.data)
        .home(&paths.home)
        .cwd(&paths.proj)
        .sandbox(row.ctx.sandbox)
        .env("PATH", &paths.tools.display().to_string());
    // A row that names a contract 3.3 signal in its env is testing that signal alone; do not
    // add the blanket SAFE_AI_SKILL_HEADLESS on top of it.
    if row.ctx.headless
        && !row
            .env
            .iter()
            .any(|(k, _)| HEADLESS_SIGNALS.contains(&k.as_str()))
    {
        inv = inv.headless(true);
    }
    match row.ctx.user_tier {
        UserTier::Column => inv = inv.tier(tier),
        UserTier::Fixed(t) => inv = inv.tier(t),
        UserTier::Default => {}
    }
    if let Some(er) = env_read_of(row) {
        inv = inv.env_read(er);
    }
    if let Some(t) = row.ctx.repo_tier {
        let w = t.label();
        inv = inv.kit_security(format!(
            r#"{{"tier":"{w}","declared":{{"tier":"{w}"}},"enforced":{{"tier":"{w}","ruleSetVersion":7}}}}"#
        ));
    }
    if let Some(root) = &paths.plugin_root {
        inv = inv.env("CLAUDE_PLUGIN_ROOT", &root.display().to_string());
    }
    for (k, v) in &row.env {
        inv = inv.env(k, &subst(v, paths));
    }
    inv
}

struct Outcome {
    verdict: char,
    updated_input: bool,
}

fn parse_stdout(hook: &str, stdout: &str) -> Result<(char, bool), String> {
    if stdout.trim().is_empty() {
        return Ok(('-', false));
    }
    let v: Value = serde_json::from_str(stdout.trim())
        .map_err(|e| format!("{hook}: stdout is not JSON: {e}"))?;
    let out = &v["hookSpecificOutput"];
    let updated = out.get("updatedInput").is_some();
    let verdict = match out["permissionDecision"].as_str() {
        Some("deny") => 'D',
        Some("ask") => 'A',
        Some("allow") => 'L',
        None => '-',
        Some(other) => return Err(format!("{hook}: unexpected permissionDecision `{other}`")),
    };
    if verdict == '-' {
        // No opinion is empty stdout; the only other accepted shapes carry no decision at all.
        let top_ok = v.as_object().is_some_and(|o| {
            o.keys()
                .all(|k| k == "systemMessage" || k == "hookSpecificOutput")
        });
        let inner_ok = out.as_object().is_none_or(|o| {
            o.keys().all(|k| {
                ["hookEventName", "updatedInput", "additionalContext"].contains(&k.as_str())
            })
        });
        if !top_ok || !inner_ok {
            return Err(format!(
                "{hook}: no-opinion must be empty stdout, got {}",
                stdout.trim()
            ));
        }
    }
    Ok((verdict, updated))
}

fn execute(row: &Row, tier: Tier) -> Result<Outcome, String> {
    let paths = materialise(row)?;
    for args in &row.ctx.pre_cli {
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        let run = invocation(&argv, row, tier, &paths).run();
        if run.code != Some(0) {
            return Err(format!(
                "pre_cli {args:?}: exit {:?}: {}",
                run.code,
                run.stderr.trim()
            ));
        }
    }
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": row.tool,
        "cwd": paths.proj,
        "tool_input": subst_value(&row.input, &paths),
    })
    .to_string();
    let mut verdict = '-';
    let mut updated_input = false;
    for hook in hooks_for(&row.tool) {
        let run = invocation(&[hook], row, tier, &paths)
            .stdin(payload.clone())
            .run();
        if run.code != Some(0) {
            return Err(format!(
                "{hook}: exit {:?}: {}",
                run.code,
                run.stderr.trim()
            ));
        }
        let (v, upd) = parse_stdout(hook, &run.stdout)?;
        if rank(v) > rank(verdict) {
            verdict = v;
        }
        updated_input |= upd;
    }
    Ok(Outcome {
        verdict,
        updated_input,
    })
}

struct Cell {
    row: usize,
    tier: usize,
    result: Result<Outcome, String>,
}

/// Cells run, cells skipped for the OS, cells skipped for a missing build feature.
fn run_cells(rows: &[Row], work: Vec<(usize, usize)>) -> (Vec<Cell>, usize, usize) {
    let cells = Mutex::new(Vec::new());
    let skipped = Mutex::new((0usize, 0usize));
    let next = Mutex::new(work.into_iter());
    let threads = std::thread::available_parallelism().map_or(2, |n| n.get().min(8));
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| loop {
                let item = match next.lock() {
                    Ok(mut it) => it.next(),
                    Err(_) => None,
                };
                let Some((r, t)) = item else { break };
                let row = &rows[r];
                if let Some(why) = skip_reason(row, TIERS[t]) {
                    if let Ok(mut n) = skipped.lock() {
                        if why == "os" {
                            n.0 += 1;
                        } else {
                            n.1 += 1;
                        }
                    }
                    continue;
                }
                let result = execute(row, TIERS[t]);
                if let Ok(mut all) = cells.lock() {
                    all.push(Cell {
                        row: r,
                        tier: t,
                        result,
                    });
                }
            });
        }
    });
    let cells = cells.into_inner().unwrap_or_default();
    let (os_skipped, feature_skipped) = skipped.into_inner().unwrap_or((0, 0));
    (cells, os_skipped, feature_skipped)
}

/// Fixed-tier rows ignore the column: run one column and reuse it for the other three.
fn work_for(rows: &[Row], filter: &[String]) -> Vec<(usize, usize)> {
    let mut work = Vec::new();
    for (i, row) in rows.iter().enumerate() {
        if !filter.is_empty() && !filter.iter().any(|f| row.id.contains(f.as_str())) {
            continue;
        }
        if row.ctx.user_tier == UserTier::Column {
            work.extend((0..4).map(|t| (i, t)));
        } else {
            work.push((i, 1));
        }
    }
    work
}

/// Cargo features an interim row may name in `until_feature`, and whether this build has them.
const KNOWN_FEATURES: [&str; 1] = ["env-read-opt-in"];

fn built_with(feature: &str) -> bool {
    feature == "env-read-opt-in" && cfg!(feature = "env-read-opt-in")
}

/// The plugin verdict this build must give: the interim one while the row says the shipped
/// engine differs from the end state (unless the named feature is built), else the end state.
fn expected_at(row: &Row, tier: usize) -> char {
    match &row.expect.interim {
        Some(Interim {
            plugin: Some(p),
            until_feature,
            ..
        }) if !until_feature.as_deref().is_some_and(built_with) => p[tier],
        _ => row.expect.plugin[tier],
    }
}

#[test]
#[cfg_attr(
    not(feature = "test-hooks"),
    ignore = "needs --features test-hooks (Off, opt-ins, grants and sandbox states)"
)]
fn shared_corpus_plugin_column() {
    let rows = load_rows().unwrap_or_else(|e| panic!("corpus does not parse:\n{}", e.join("\n")));
    let filter: Vec<String> = std::env::var("SHARED_CORPUS_FILTER")
        .map(|f| {
            f.split(',')
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let allow_skip = std::env::var("SHARED_CORPUS_ALLOW_SKIP").is_ok_and(|v| v == "1");
    assert!(
        TEST_HOOKS || allow_skip,
        "the full corpus run needs the trusted-data-dir and sandbox overrides: run with \
         `--features test-hooks` (or set SHARED_CORPUS_ALLOW_SKIP=1 to run the subset that \
         works without them; skipped cells are then reported, not hidden)"
    );
    let (cells, os_skipped, feature_skipped) = run_cells(&rows, work_for(&rows, &filter));
    assert!(
        !cells.is_empty(),
        "no cell ran (SHARED_CORPUS_FILTER={filter:?} matched nothing, or every cell was skipped)"
    );
    assert!(
        feature_skipped == 0 || allow_skip,
        "{feature_skipped} cells were skipped for a missing build feature; run with \
         `--features test-hooks`, or set SHARED_CORPUS_ALLOW_SKIP=1 to accept the gap"
    );

    let mut red: Vec<String> = Vec::new();
    let mut by_file: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut per_row: BTreeMap<usize, [char; 4]> = BTreeMap::new();
    for cell in &cells {
        let row = &rows[cell.row];
        let word = TIER_WORDS[cell.tier];
        let entry = by_file.entry(row.file.clone()).or_default();
        entry.0 += 1;
        let want = expected_at(row, cell.tier);
        match &cell.result {
            Err(why) => {
                entry.1 += 1;
                red.push(format!(
                    "RED {:<12} {:<8} want {want} got ERROR {why}",
                    row.id, word
                ));
                per_row.entry(cell.row).or_insert(['?'; 4])[cell.tier] = '?';
            }
            Ok(out) => {
                per_row.entry(cell.row).or_insert(['?'; 4])[cell.tier] = out.verdict;
                if out.verdict != want {
                    entry.1 += 1;
                    red.push(format!(
                        "RED {:<12} {:<8} want {want} got {}",
                        row.id, word, out.verdict
                    ));
                } else if row.expect.updated_input && !out.updated_input {
                    entry.1 += 1;
                    red.push(format!(
                        "RED {:<12} {:<8} want updatedInput, none emitted",
                        row.id, word
                    ));
                } else if out.updated_input && !row.expect.updated_input {
                    entry.1 += 1;
                    red.push(format!(
                        "RED {:<12} {:<8} unexpected updatedInput",
                        row.id, word
                    ));
                } else if row.expect.interim.is_none() {
                    if let Some(why) =
                        invariant(out.verdict, row.expect.kit[cell.tier], row.ctx.headless)
                    {
                        entry.1 += 1;
                        red.push(format!("RED {:<12} {:<8} {why}", row.id, word));
                    }
                }
            }
        }
    }
    // Fixed-tier rows ran once; the columns are equal by validation.
    for (idx, verdicts) in per_row.iter_mut() {
        if rows[*idx].ctx.user_tier != UserTier::Column {
            let v = verdicts[1];
            *verdicts = [v; 4];
        }
    }
    if let Ok(path) = std::env::var("SHARED_CORPUS_RESULTS") {
        let mut out = String::new();
        for (idx, v) in &per_row {
            out.push_str(&format!(
                r#"{{"id":"{}","plugin":"{}"}}"#,
                rows[*idx].id,
                text_of(*v)
            ));
            out.push('\n');
        }
        std::fs::write(&path, out).unwrap_or_else(|e| panic!("write {path}: {e}"));
    }

    eprintln!(
        "shared corpus: {} rows, {} cells run, {os_skipped} skipped for the OS, \
         {feature_skipped} skipped for a missing feature",
        rows.len(),
        cells.len(),
    );
    for (file, (cells, bad)) in &by_file {
        eprintln!("  {file:<13} {cells:>4} cells, {bad:>4} red");
    }
    let mut interim: BTreeMap<&str, usize> = BTreeMap::new();
    for idx in per_row.keys() {
        if let Some(Interim {
            plugin: Some(p),
            reason: Some(why),
            until_feature,
            ..
        }) = &rows[*idx].expect.interim
        {
            if *p != rows[*idx].expect.plugin && !until_feature.as_deref().is_some_and(built_with) {
                *interim.entry(why.as_str()).or_default() += 1;
            }
        }
    }
    for (why, n) in &interim {
        eprintln!("  interim (held to the shipped verdict): {n:>3} rows: {why}");
    }
    assert!(
        red.is_empty(),
        "{} red cells:\n{}",
        red.len(),
        red.join("\n")
    );
}

#[test]
fn runner_plumbing_smoke() {
    let rows = load_rows().unwrap_or_else(|e| panic!("corpus does not parse:\n{}", e.join("\n")));
    for id in ["SOL-4", "ENV-1", "CRD-26", "CC-18"] {
        let row = rows
            .iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("smoke row {id} is missing"));
        let out = execute(row, Tier::Relaxed).unwrap_or_else(|e| panic!("{id}: {e}"));
        assert_eq!(out.verdict, expected_at(row, 1), "{id} at relaxed");
    }
}

// ------------------------------------------------------------------ conformance-diff.sh

#[cfg(unix)]
fn diff_script(results: &str, args: &[&str]) -> (Option<i32>, String) {
    let dir = TempDir::new("conformance-diff");
    let corpus = dir.join("corpus");
    std::fs::create_dir_all(&corpus).expect("mkdir corpus");
    let row = |id: &str, kit: &str| {
        format!(
            r#"{{"id":"{id}","expect":{{"plugin":"----","kit":"{kit}","combined":"{kit}","owner":"plugin"}}}}"#
        )
    };
    std::fs::write(
        corpus.join("x.jsonl"),
        format!("{}\n{}\n", row("A-1", "DDDD"), row("A-2", "-AAD")),
    )
    .expect("write corpus");
    let file = dir.join("results.jsonl");
    std::fs::write(&file, results).expect("write results");
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/conformance-diff.sh");
    let out = std::process::Command::new("sh")
        .arg(script)
        .args(args)
        .arg(&file)
        .env("CORPUS_DIR", &corpus)
        .output()
        .expect("run conformance-diff.sh");
    (
        out.status.code(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

#[cfg(unix)]
#[test]
fn conformance_diff_fails_on_bad_input() {
    let full = "{\"id\":\"A-1\",\"kit\":\"DDDD\"}\n{\"id\":\"A-2\",\"kit\":\"-AAD\"}\n";
    let (code, out) = diff_script(full, &[]);
    assert_eq!(code, Some(0), "{out}");

    let (code, out) = diff_script(
        "{\"id\":\"A-1\",\"kit\":\"DDDD\"}\n{\"id\":\"A-2\",\"kit\":\"-A?D\"}\n",
        &[],
    );
    assert_eq!(code, Some(0), "a `?` tier is skipped: {out}");

    let (code, out) = diff_script(
        "{\"id\":\"A-1\",\"kit\":\"----\"}\n{\"id\":\"A-2\",\"kit\":\"-AAD\"}\n",
        &[],
    );
    assert_eq!(code, Some(1), "{out}");
    assert!(out.contains("DIVERGE A-1"), "{out}");

    for (what, input, needle) in [
        ("empty file", "", "no corpus row was compared"),
        ("garbage", "not json\n\u{1}\u{2}\n", "MALFORMED"),
        ("truncated line", "{\"id\":\"A-1\"\n", "MALFORMED"),
        (
            "partial results",
            "{\"id\":\"A-1\",\"kit\":\"DDDD\"}\n",
            "MISSING A-2",
        ),
        (
            "duplicate id",
            "{\"id\":\"A-1\",\"kit\":\"DDDD\"}\n{\"id\":\"A-1\",\"kit\":\"DDDD\"}\n{\"id\":\"A-2\",\"kit\":\"-AAD\"}\n",
            "duplicate id",
        ),
        (
            "unknown id",
            "{\"id\":\"A-1\",\"kit\":\"DDDD\"}\n{\"id\":\"A-2\",\"kit\":\"-AAD\"}\n{\"id\":\"Z-9\",\"kit\":\"----\"}\n",
            "UNKNOWN Z-9",
        ),
        (
            "all tiers unasserted",
            "{\"id\":\"A-1\",\"kit\":\"????\"}\n{\"id\":\"A-2\",\"kit\":\"????\"}\n",
            "no corpus row was compared",
        ),
    ] {
        let (code, out) = diff_script(input, &[]);
        assert_eq!(code, Some(1), "{what}: {out}");
        assert!(out.contains(needle), "{what}: {out}");
    }

    let (code, out) = diff_script("{\"id\":\"A-1\",\"kit\":\"DDDD\"}\n", &["--allow-missing"]);
    assert_eq!(code, Some(0), "a partial run is accepted on request: {out}");

    let (code, _) = diff_script(full, &["--column", "bogus"]);
    assert_eq!(code, Some(2));
}
