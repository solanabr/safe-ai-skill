//! Read / Grep / Glob / MCP-path secret gate (spec D3.1, D3.2, D3.3, D3.8.1).
//!
//! A path is judged on two candidates, the path as given (relative paths join the hook `cwd`)
//! and its symlink-resolved form, by the built-in classes of [`secretpath`] plus the policy's
//! `secrets` globs; the stricter verdict wins. Then a bounded content sniff catches keypairs and
//! private keys under any name. Precedence, strongest first:
//!
//! 1. hard-deny class or key-material content: `deny`, never relaxed by any glob or setting;
//! 2. `allow_read_globs` match: readable (a `.env.schema` still passes its content guard);
//! 3. env class (`.env`, `.env.*`, templates and schemas not allow-listed, …): `deny` with the
//!    `safe-ai-skill env` commands, or `ask` under the user's `safe-ai-skill tier --env-read ask`;
//! 4. `deny_read_globs` match: `deny`;
//! 5. `id.json` / `*.pem` / `*.key` that cannot be read (or a `*.pem`/`*.key` too large to scan):
//!    `deny`;
//! 6. otherwise no opinion.
//!
//! Grep is judged on `path` and `glob`, never on its regex `pattern`. A directory Grep gets an
//! `updatedInput` that appends env/key exclusions to `glob` (no permission decision: Claude
//! Code applies it without `allow`, research hooks-empirical-2.1.304 Q10). Glob is never gated.
//! MCP tools get the path check on every single-line string argument.

use std::path::{Path, PathBuf};

use glob::{MatchOptions, Pattern};
use serde_json::Value;

use crate::env::render::Shown;
use crate::env::schema::{self, Schema, ValueKind};
use crate::gates::secretpath::{self, Class, Sniffed, Suspect};
use crate::gates::{credpaths, envread};
use crate::io::Decision;
use crate::policy::Policy;
use crate::redact;

/// Names a Grep `glob` is tried against: one that matches a secret probe and no benign probe
/// is an explicit search of secret files.
const SECRET_PROBES: &[&str] = &[
    ".env",
    ".env.local",
    ".envrc",
    "prod.env",
    ".dev.vars",
    ".varlock-frozen-env",
    "wallet-keypair.json",
];
const BENIGN_PROBES: &[&str] = &[
    "main.rs",
    "src/main.rs",
    "README.md",
    "index.ts",
    "package.json",
    "config.yml",
    "Cargo.toml",
];

/// Most string arguments of one MCP call that are path-checked; more asks.
const MAX_MCP_PATHS: usize = 1024;
/// Longest MCP string argument treated as a path.
const MAX_MCP_PATH_LEN: usize = 4096;

/// A `gate-read` verdict: a permission decision, or a rewritten Grep input.
#[derive(Debug, Clone, PartialEq)]
pub enum ReadVerdict {
    Decide(Decision),
    /// Emit `updatedInput` with no permission decision.
    Rewrite(Value),
}

/// Judge one `Read|Grep|Glob` call (`tool_input` of tool `tool`).
pub fn decide_tool(tool: &str, input: Option<&Value>, cwd: &Path, policy: &Policy) -> ReadVerdict {
    let field = |k: &str| input.and_then(|i| i.get(k)).and_then(Value::as_str);
    match tool {
        "Glob" => ReadVerdict::Decide(Decision::Defer),
        "Grep" => decide_grep(input, cwd, policy),
        _ => {
            let path = field("file_path").or_else(|| field("path")).unwrap_or("");
            ReadVerdict::Decide(decide_path(path, cwd, policy))
        }
    }
}

/// Judge a read of `path` (see the module docs for precedence).
pub fn decide_path(path: &str, cwd: &Path, policy: &Policy) -> Decision {
    if path.trim().is_empty() {
        return Decision::Defer;
    }
    let homes = secretpath::homes_resolved();
    let raw = absolute(path, cwd, &homes);
    let resolved = std::fs::canonicalize(&raw).ok();
    let mut candidates = vec![raw.to_string_lossy().into_owned()];
    if let Some(real) = &resolved {
        let real = real.to_string_lossy().into_owned();
        if !candidates.contains(&real) {
            candidates.push(real);
        }
    }

    let verdicts: Vec<Verdict> = candidates
        .iter()
        .map(|c| name_verdict(c, &homes, policy))
        .collect();
    if let Some(Verdict::Hard(what)) = verdicts.iter().find(|v| matches!(v, Verdict::Hard(_))) {
        return hard_deny(what);
    }

    // Content: keypairs and private keys are hard denies under any name.
    let file = resolved.as_deref().unwrap_or(&raw);
    let pem = verdicts.contains(&Verdict::Suspect(Suspect::PemKey));
    let limit = if pem {
        secretpath::PEM_SCAN_BYTES
    } else {
        secretpath::SNIFF_BYTES
    };
    let sniffed = secretpath::sniff(file, limit);
    match sniffed {
        Sniffed::Keypair => return hard_deny("file content is a Solana keypair"),
        Sniffed::PrivateKey => return hard_deny("file content holds a private key"),
        _ => {}
    }

    if verdicts.contains(&Verdict::Env) {
        return env_verdict(path, policy, varlock_hint(cwd, &raw));
    }
    if let Some(Verdict::PolicyDeny(what)) = verdicts
        .iter()
        .find(|v| matches!(v, Verdict::PolicyDeny(_)))
    {
        return hard_deny(what);
    }
    let suspect = verdicts.iter().any(|v| matches!(v, Verdict::Suspect(_)));
    if suspect && sniffed == Sniffed::Unreadable {
        return hard_deny("possible key file that could not be checked");
    }
    if pem && sniffed == Sniffed::TooLarge {
        return hard_deny("key file too large to check (over 1 MiB)");
    }
    if verdicts.contains(&Verdict::Schema) {
        return guard_env_schema(file);
    }
    Decision::Defer
}

/// Whether the absolute `candidate` names a project env file whose raw read the env gate
/// decides: env class and not allow-listed (`.env.example`, `.env.schema` stay readable).
pub(crate) fn is_env_file(candidate: &str, homes: &[String], policy: &Policy) -> bool {
    name_verdict(candidate, homes, policy) == Verdict::Env
}

/// Name-level verdict for one candidate path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Hard(&'static str),
    Env,
    /// An allow-listed `.env.schema`: readable after [`guard_env_schema`].
    Schema,
    PolicyDeny(&'static str),
    Suspect(Suspect),
    Pass,
}

fn name_verdict(candidate: &str, homes: &[String], policy: &Policy) -> Verdict {
    let class = secretpath::classify_with_homes(candidate, homes);
    if let Class::HardDeny(what) = class {
        return Verdict::Hard(what);
    }
    let suspect_or_pass = match class {
        Class::Suspect(s) => Verdict::Suspect(s),
        _ => Verdict::Pass,
    };
    if allowed(candidate, policy) {
        return if class == Class::Schema {
            Verdict::Schema
        } else {
            suspect_or_pass
        };
    }
    if class.is_env_family() {
        return Verdict::Env;
    }
    if let Some(glob) = denied_by_glob(candidate, policy) {
        return Verdict::PolicyDeny(describe_class(glob));
    }
    suspect_or_pass
}

/// Whether the policy allow-list covers `candidate` (case-sensitive: an allow never widens
/// by case folding).
fn allowed(candidate: &str, policy: &Policy) -> bool {
    let text = fold_case_kept(candidate);
    policy
        .secrets
        .allow_read_globs
        .iter()
        .any(|g| glob_matches(g, &text, true))
}

/// The first `deny_read_globs` entry matching `candidate`, case-insensitively.
fn denied_by_glob<'a>(candidate: &str, policy: &'a Policy) -> Option<&'a str> {
    let text = fold_case_kept(candidate);
    policy
        .secrets
        .deny_read_globs
        .iter()
        .find(|g| glob_matches(g, &text, false))
        .map(String::as_str)
}

/// `candidate` with separators, streams, trailing dots and `.`/`..` normalised, case kept.
fn fold_case_kept(candidate: &str) -> String {
    secretpath::fold(candidate, None)
}

/// Match a glob `pattern` against `candidate`, expanding a leading `~`, and also against the
/// final component so that `**/foo` patterns match bare filenames.
fn glob_matches(pattern: &str, candidate: &str, case_sensitive: bool) -> bool {
    let expanded = expand_home(pattern);
    let Ok(compiled) = Pattern::new(&expanded) else {
        return false;
    };
    let options = MatchOptions {
        case_sensitive,
        require_literal_separator: false,
        require_literal_leading_dot: false,
    };
    if compiled.matches_with(candidate, options) {
        return true;
    }
    match candidate.rsplit('/').next() {
        Some(base) if base != candidate => compiled.matches_with(base, options),
        _ => false,
    }
}

/// Expand a leading `~` (or `~/`) to the home directory. Other `~` uses are left intact.
fn expand_home(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{}/{}", home.trim_end_matches('/'), rest);
        }
    } else if path == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return home;
        }
    }
    path.to_string()
}

/// `path` with `~` expanded and, when relative, joined to `cwd`.
fn absolute(path: &str, cwd: &Path, homes: &[String]) -> PathBuf {
    let expanded = match (path.strip_prefix("~/"), homes.first()) {
        (Some(rest), Some(home)) => PathBuf::from(home).join(rest),
        (None, Some(home)) if path == "~" => PathBuf::from(home),
        _ => PathBuf::from(path),
    };
    if expanded.is_absolute() || is_windows_absolute(path) {
        expanded
    } else {
        cwd.join(expanded)
    }
}

fn is_windows_absolute(path: &str) -> bool {
    let b = path.as_bytes();
    (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && matches!(b[2], b'\\' | b'/'))
        || path.starts_with("\\\\")
}

/// A short, non-sensitive description of the matched secret class for the deny reason.
fn describe_class(glob: &str) -> &'static str {
    let g = glob.to_ascii_lowercase();
    if g.contains("keypair") || g.contains("id.json") {
        "Solana keypair"
    } else if g.contains(".env") {
        "environment file"
    } else if g.contains(".pem") {
        "PEM private key"
    } else if g.contains("solana") {
        "Solana config directory"
    } else if g.contains("superstack") {
        "superstack config (credential token)"
    } else {
        "credential file"
    }
}

fn hard_deny(what: &str) -> Decision {
    Decision::Deny {
        reason: format!(
            "Protected secret file blocked ({what}): reading credential material is denied."
        ),
    }
}

/// The verdict for a raw read of an env-class file, by tier, `env_read` and sandbox
/// ([`envread::verdict`]): `deny` with the `safe-ai-skill env` commands by default.
pub fn env_verdict(file: &str, policy: &Policy, varlock: bool) -> Decision {
    envread::decision(policy, env_reason(file, varlock))
}

/// The actionable env-class message (spec D3.3, D3.8.6). `varlock` adds the varlock hint.
pub fn env_reason(file: &str, varlock: bool) -> String {
    let label = shell_label(file);
    let mut out = format!(
        "safe-ai-skill: {label} is an env file; raw reads are blocked so secret values stay out of the transcript. Use instead:\n  \
         safe-ai-skill env keys {label}    (lists keys, values masked)\n  \
         printf %s '<value>' | safe-ai-skill env set {label} KEY    (value on stdin, never in argv)\n  \
         safe-ai-skill env unset {label} KEY"
    );
    if varlock {
        out.push_str(
            "\nThis project uses varlock: `varlock load --agent` shows the config redacted, and `varlock run -- <cmd>` runs a tool with the values injected.",
        );
    }
    out
}

/// `file` as a copy-pasteable shell word (single-quoted when needed), or its final component
/// when it is too long to be a real path.
fn shell_label(file: &str) -> String {
    let file = file.trim();
    let file = if file.len() > 256 {
        file.rsplit(['/', '\\']).next().unwrap_or("FILE")
    } else {
        file
    };
    let file = if file.is_empty() { ".env" } else { file };
    let plain = file
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"._-/~+@%,:".contains(&b));
    if plain {
        file.to_string()
    } else {
        format!("'{}'", file.replace('\'', r"'\''"))
    }
}

/// Whether the varlock hint applies: a `.env.schema` next to the file or in `cwd`, or a
/// `varlock` executable on `PATH`.
pub fn varlock_hint(cwd: &Path, file: &Path) -> bool {
    let schema_in = |dir: &Path| dir.join(".env.schema").is_file();
    if schema_in(cwd) || file.parent().is_some_and(schema_in) {
        return true;
    }
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| {
        ["varlock", "varlock.exe", "varlock.cmd"]
            .iter()
            .any(|name| dir.join(name).is_file())
    })
}

/// Content guard for an allow-listed `.env.schema` (spec D3.8.1): denied when it resolves to a
/// file not itself named `.env.schema`, is not a regular file, is larger than 64 KiB, or holds key material, a high-confidence API key, or a
/// literal secret-looking value for a sensitive key. A missing schema is no opinion. The schema
/// is parsed natively ([`Schema`]); nothing in it is evaluated.
pub fn guard_env_schema(file: &Path) -> Decision {
    let meta = match std::fs::metadata(file) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Decision::Defer,
        Err(_) => return schema_denied("could not be resolved"),
    };
    // A schema name that resolves (symlink) to some other file is that file, not a schema.
    if !file
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(is_env_schema)
    {
        return schema_denied("resolves to a different file");
    }
    if !meta.is_file() {
        return schema_denied("is not a regular file");
    }
    let mut buf = Vec::new();
    let read = std::fs::File::open(file).and_then(|f| {
        use std::io::Read;
        f.take(schema::MAX_SCHEMA_BYTES as u64 + 1)
            .read_to_end(&mut buf)
    });
    if read.is_err() {
        return schema_denied("could not be read");
    }
    if buf.len() > schema::MAX_SCHEMA_BYTES {
        return schema_denied("is larger than 64 KiB");
    }
    let parsed = Schema::parse(&buf);
    for item in &parsed.items {
        let ValueKind::Literal(value) = &item.value else {
            continue;
        };
        let secret_looking = matches!(Shown::of(value), Shown::Set { len, .. } if len >= 16);
        if secret_looking && parsed.is_sensitive(&item.key) {
            return Decision::Deny {
                reason: format!(
                    "Protected secret file blocked (.env.schema): the schema contains a secret value for sensitive key {} at L{}. \
                     A schema holds keys and decorators only; move the value to `.env.local` \
                     (`printf %s '<value>' | safe-ai-skill env set .env.local {}`).",
                    item.key, item.line, item.key
                ),
            };
        }
    }
    let text = String::from_utf8_lossy(&buf);
    if redact::contains_key_material(&text) {
        return Decision::Deny {
            reason:
                "Protected secret file blocked (.env.schema): the schema contains a secret value. \
                     A schema holds keys and decorators only; move the value to `.env.local` \
                     (`printf %s '<value>' | safe-ai-skill env set .env.local KEY`)."
                    .into(),
        };
    }
    Decision::Defer
}

/// Whether a file name is `.env.schema` (case-insensitive: the same file on a case-insensitive
/// filesystem).
fn is_env_schema(name: &str) -> bool {
    name.eq_ignore_ascii_case(".env.schema")
}

fn schema_denied(why: &str) -> Decision {
    Decision::Deny {
        reason: format!("Protected secret file blocked (.env.schema): the schema {why}."),
    }
}

// ---------------------------------------------------------------------------------------
// Grep
// ---------------------------------------------------------------------------------------

fn decide_grep(input: Option<&Value>, cwd: &Path, policy: &Policy) -> ReadVerdict {
    let Some(input) = input.and_then(Value::as_object) else {
        return ReadVerdict::Decide(Decision::Defer);
    };
    let path = input.get("path").and_then(Value::as_str).unwrap_or("");
    let glob = input.get("glob").and_then(Value::as_str).unwrap_or("");
    let homes = secretpath::homes_resolved();
    let target = if path.trim().is_empty() {
        cwd.to_path_buf()
    } else {
        absolute(path, cwd, &homes)
    };

    if !target.is_dir() {
        // A single file (or nothing): judged like a Read; the glob does not apply.
        if path.trim().is_empty() {
            return ReadVerdict::Decide(Decision::Defer);
        }
        return ReadVerdict::Decide(decide_path(path, cwd, policy));
    }

    let real = std::fs::canonicalize(&target).unwrap_or_else(|_| target.clone());
    if let Some(verdict) = credpaths::grep_root(&target, &real, &homes) {
        return ReadVerdict::Decide(verdict.into());
    }
    if !credpaths::lists_available() {
        return ReadVerdict::Decide(Decision::Ask {
            reason: "safe-ai-skill: the credential lists failed to load, so this directory \
                     search cannot exclude credential files — approve to proceed"
                .into(),
        });
    }
    // An env glob the user's opt-in leaves open (no opinion) still gets the key-material
    // exclusion, minus the env-file globs it opted into.
    let mut keep_env = false;
    if glob_targets_secrets(glob) {
        let first = glob.split_whitespace().next().unwrap_or(glob);
        let verdict = env_verdict(first, policy, varlock_hint(cwd, &real));
        if !matches!(verdict, Decision::Defer) {
            return ReadVerdict::Decide(verdict);
        }
        keep_env = true;
    }

    let exclusion = if keep_env {
        grep_exclusion_keeping_env(&real)
    } else {
        grep_exclusion(&real)
    };
    let new_glob = if glob.trim().is_empty() {
        exclusion
    } else {
        format!("{} {exclusion}", glob.trim_end())
    };
    let mut updated = input.clone();
    updated.insert("glob".into(), Value::String(new_glob));
    ReadVerdict::Rewrite(Value::Object(updated))
}

/// The ` !{…}` negated brace group appended to a Grep's glob over `dir`
/// ([`credpaths::grep_exclusions`]).
pub fn grep_exclusion(dir: &Path) -> String {
    let alts: Vec<String> = credpaths::grep_exclusions(dir)
        .iter()
        .map(|g| case_insensitive(g))
        .collect();
    format!("!{{{}}}", alts.join(","))
}

/// [`grep_exclusion`] without the env-file globs, for an opted-in env Grep.
fn grep_exclusion_keeping_env(dir: &Path) -> String {
    let alts: Vec<String> = credpaths::grep_exclusions(dir)
        .iter()
        .filter(|g| {
            let last = g.rsplit('/').next().unwrap_or(g);
            secretpath::classify(last) != Class::Env
        })
        .map(|g| case_insensitive(g))
        .collect();
    format!("!{{{}}}", alts.join(","))
}

/// `**/.env` → `**/.[eE][nN][vV]`: letters become two-case classes (`rg --glob` is
/// case-sensitive and Claude Code never passes `--glob-case-insensitive`).
fn case_insensitive(glob: &str) -> String {
    glob.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                format!("[{}{}]", c.to_ascii_lowercase(), c.to_ascii_uppercase())
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// Whether a Grep `glob` explicitly targets secret files: some positive glob in it matches a
/// secret probe name and no benign one. Claude Code splits the field on whitespace and on
/// commas outside braces; braces are expanded here.
fn glob_targets_secrets(glob: &str) -> bool {
    glob.split_whitespace()
        .flat_map(|tok| {
            if tok.contains('{') && tok.contains('}') {
                vec![tok.to_string()]
            } else {
                tok.split(',').map(str::to_string).collect()
            }
        })
        .filter(|tok| !tok.is_empty() && !tok.starts_with('!'))
        .flat_map(|tok| expand_braces(&tok, 0))
        .any(|alt| {
            let Ok(p) = Pattern::new(&alt) else {
                return false;
            };
            let options = MatchOptions {
                case_sensitive: false,
                require_literal_separator: false,
                require_literal_leading_dot: false,
            };
            let hits = |names: &[&str]| {
                names.iter().any(|n| {
                    p.matches_with(n, options) || p.matches_with(&format!("sub/dir/{n}"), options)
                })
            };
            hits(SECRET_PROBES) && !hits(BENIGN_PROBES)
        })
}

/// Expand the first `{a,b}` group (recursively, bounded) into alternatives.
fn expand_braces(glob: &str, depth: usize) -> Vec<String> {
    if depth > 4 {
        return vec![glob.to_string()];
    }
    let Some(open) = glob.find('{') else {
        return vec![glob.to_string()];
    };
    let Some(close_rel) = glob[open..].find('}') else {
        return vec![glob.to_string()];
    };
    let close = open + close_rel;
    let (head, body, tail) = (&glob[..open], &glob[open + 1..close], &glob[close + 1..]);
    body.split(',')
        .take(32)
        .flat_map(|alt| expand_braces(&format!("{head}{alt}{tail}"), depth + 1))
        .collect()
}

// ---------------------------------------------------------------------------------------
// MCP
// ---------------------------------------------------------------------------------------

/// Run the read check on every path-like string argument of an MCP call (spec D3.2): every
/// single-line string up to [`MAX_MCP_PATH_LEN`] bytes, spaces included. The first non-`Defer`
/// verdict wins. A payload with more strings than [`MAX_MCP_PATHS`], or nested deeper than
/// [`MAX_MCP_DEPTH`], cannot be checked whole: a hard-guard ask (deny at High).
pub fn decide_mcp_args(input: Option<&Value>, cwd: &Path, policy: &Policy) -> Decision {
    let mut strings = Vec::new();
    let mut complete = true;
    if let Some(value) = input {
        complete = collect_path_strings(value, 0, &mut strings);
    }
    for s in strings {
        let decision = decide_path(s, cwd, policy);
        if !matches!(decision, Decision::Defer) {
            return decision;
        }
    }
    if complete {
        return Decision::Defer;
    }
    let reason = "safe-ai-skill: this MCP call has too many or too deeply nested arguments to \
                  check for secret paths";
    if policy.tier() == crate::policy::tier::Tier::High {
        Decision::Deny {
            reason: format!("{reason} — denied at tier high"),
        }
    } else {
        Decision::Ask {
            reason: format!("{reason} — approve to proceed"),
        }
    }
}

/// Deepest MCP argument nesting that is path-checked.
const MAX_MCP_DEPTH: usize = 32;

/// Collect the path candidates of `value` into `out`; `false` when a limit cut the walk short.
fn collect_path_strings<'a>(value: &'a Value, depth: usize, out: &mut Vec<&'a str>) -> bool {
    if depth > MAX_MCP_DEPTH {
        return false;
    }
    match value {
        Value::String(s) => {
            // Multi-line text is code or prose, never a path (executor code is judged by
            // `mcpexec`); a string longer than any path is not one either.
            let looks_like_path =
                !s.trim().is_empty() && s.len() <= MAX_MCP_PATH_LEN && !s.contains(['\n', '\r']);
            if !looks_like_path {
                return true;
            }
            if out.len() >= MAX_MCP_PATHS {
                return false;
            }
            out.push(s);
            true
        }
        Value::Array(items) => items
            .iter()
            .all(|v| collect_path_strings(v, depth + 1, out)),
        Value::Object(map) => map
            .values()
            .all(|v| collect_path_strings(v, depth + 1, out)),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;

    fn policy() -> Policy {
        Policy::default()
    }

    fn here() -> PathBuf {
        PathBuf::from("/nonexistent-cwd")
    }

    fn decide(path: &str) -> Decision {
        decide_path(path, &here(), &policy())
    }

    #[test]
    fn deny_solana_tree_and_keypairs() {
        assert!(matches!(
            decide("/Users/dev/.config/solana/id.json"),
            Decision::Deny { .. }
        ));
        assert!(matches!(
            decide("/home/me/wallet-keypair.json"),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn deny_dotenv_with_actionable_reason() {
        for p in [".env", "/srv/app/.env.local"] {
            let d = decide(p);
            assert!(matches!(d, Decision::Deny { .. }), "{p}");
            assert!(
                d.reason().contains(&format!("safe-ai-skill env keys {p}")),
                "{}",
                d.reason()
            );
            assert!(
                d.reason().contains("safe-ai-skill env unset"),
                "{}",
                d.reason()
            );
        }
    }

    #[test]
    fn missing_id_json_outside_the_solana_tree_is_no_opinion() {
        assert_eq!(decide("/Users/dev/project/id.json"), Decision::Defer);
    }

    #[test]
    fn deny_superstack_config() {
        std::env::set_var("HOME", "/home/tester");
        let d = decide("/home/tester/.superstack/config.json");
        assert!(matches!(d, Decision::Deny { .. }));
    }

    #[test]
    fn allow_templates_and_schema_by_default() {
        for p in [
            ".env.example",
            "/proj/.env.example",
            ".env.sample",
            "/nope/.env.schema",
        ] {
            assert_eq!(decide(p), Decision::Defer, "{p}");
        }
    }

    #[test]
    fn allow_env_schema_but_not_its_siblings() {
        assert_eq!(decide(".env.schema"), Decision::Defer);
        assert_eq!(decide("/proj/sub/.env.schema"), Decision::Defer);
        for name in [".env.schema.bak", ".env.schema.local", ".env.local"] {
            assert!(matches!(decide(name), Decision::Deny { .. }), "{name}");
        }
    }

    #[test]
    fn guard_ignores_missing_files() {
        for p in ["/nonexistent/.env.example", "/nonexistent/.env.schema"] {
            assert_eq!(guard_env_schema(Path::new(p)), Decision::Defer, "{p}");
        }
    }

    #[test]
    fn guard_denies_a_schema_name_resolving_elsewhere() {
        let dir = std::env::temp_dir().join(format!("sas-schema-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let other = dir.join("notes.txt");
        std::fs::write(&other, "HELLO=world\n").unwrap();
        assert!(matches!(guard_env_schema(&other), Decision::Deny { .. }));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn allow_normal_source_file() {
        assert_eq!(decide("/proj/src/main.rs"), Decision::Defer);
    }

    #[test]
    fn tilde_expansion_solana_config() {
        std::env::set_var("HOME", "/home/tester");
        assert!(matches!(
            decide("~/.config/solana/id.json"),
            Decision::Deny { .. }
        ));
    }

    #[cfg(feature = "env-read-opt-in")]
    #[test]
    fn env_read_ask_policy() {
        let mut p = policy();
        p.runtime.env_read = crate::policy::tier::EnvRead::Ask;
        p.runtime.sandbox = crate::sandbox::SandboxState::On;
        assert!(matches!(
            decide_path(".env", &here(), &p),
            Decision::Ask { .. }
        ));
        assert!(matches!(
            decide_path("x-keypair.json", &here(), &p),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn user_allow_glob_never_reaches_hard_classes() {
        let mut p = policy();
        p.secrets.allow_read_globs.push("**".into());
        assert_eq!(decide_path(".env", &here(), &p), Decision::Defer);
        assert!(matches!(
            decide_path("~/.config/solana/id.json", &here(), &p),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn extra_deny_globs_apply_case_insensitively() {
        let mut p = policy();
        p.secrets.deny_read_globs.push("**/*.secret".into());
        assert!(matches!(
            decide_path("/a/B.SECRET", &here(), &p),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn shell_labels() {
        assert_eq!(shell_label(".env"), ".env");
        assert_eq!(shell_label("/a b/.env"), "'/a b/.env'");
        assert_eq!(shell_label("it's/.env"), r"'it'\''s/.env'");
        assert_eq!(shell_label(".env::$DATA"), "'.env::$DATA'");
    }

    #[test]
    fn exclusion_is_the_q10_recipe_extended() {
        let ex = grep_exclusion(Path::new("/"));
        assert!(
            ex.starts_with("!{**/.[eE][nN][vV],**/.[eE][nN][vV].*,"),
            "{ex}"
        );
        assert!(ex.ends_with('}'));
        assert!(!ex.contains(' '));
    }

    #[test]
    fn grep_glob_targeting() {
        for g in [
            ".env*",
            "**/.env",
            "*.env",
            "{.envrc,*.md}",
            ".ENV.local",
            "*-keypair.json",
        ] {
            assert!(glob_targets_secrets(g), "{g}");
        }
        for g in [
            "",
            "*",
            "**/*",
            "*.rs",
            "*.json",
            "*.{ts,tsx}",
            "!**/.env",
            "src/**",
        ] {
            assert!(!glob_targets_secrets(g), "{g}");
        }
    }

    #[test]
    fn brace_expansion() {
        assert_eq!(expand_braces("a{b,c}d", 0), vec!["abd", "acd"]);
        assert_eq!(expand_braces("{x,y}{1,2}", 0).len(), 4);
        assert_eq!(expand_braces("plain", 0), vec!["plain"]);
    }

    #[test]
    fn mcp_path_strings() {
        let v = serde_json::json!({
            "path": ".env",
            "code": "cat .env | head",
            "n": 3,
            "nested": {"list": ["a.txt", "b c"]},
        });
        let mut out = Vec::new();
        assert!(collect_path_strings(&v, 0, &mut out));
        out.sort_unstable();
        assert_eq!(out, vec![".env", "a.txt", "b c", "cat .env | head"]);
    }

    #[test]
    fn mcp_paths_with_spaces_are_checked() {
        let v = serde_json::json!({ "path": "my dir/.env" });
        assert!(matches!(
            decide_mcp_args(Some(&v), &here(), &policy()),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn mcp_args_past_the_limits_ask() {
        let mut padded = serde_json::Map::new();
        padded.insert(
            "a".into(),
            Value::Array(vec![Value::String("x".into()); MAX_MCP_PATHS + 1]),
        );
        padded.insert("z".into(), Value::String("notes.txt".into()));
        let v = Value::Object(padded);
        assert!(matches!(
            decide_mcp_args(Some(&v), &here(), &policy()),
            Decision::Ask { .. }
        ));
        // A secret path inside the checked part still denies.
        let v = serde_json::json!({ "a": vec!["x"; MAX_MCP_PATHS + 1], "b": ".env" });
        let first = serde_json::json!({ "0": ".env", "a": vec!["x"; MAX_MCP_PATHS + 1] });
        assert!(matches!(
            decide_mcp_args(Some(&first), &here(), &policy()),
            Decision::Deny { .. }
        ));
        assert!(!matches!(
            decide_mcp_args(Some(&v), &here(), &policy()),
            Decision::Defer
        ));
        let mut deep = serde_json::json!(".env");
        for _ in 0..=MAX_MCP_DEPTH + 1 {
            deep = serde_json::json!([deep]);
        }
        assert!(matches!(
            decide_mcp_args(Some(&deep), &here(), &policy()),
            Decision::Ask { .. }
        ));
        let mut high = Policy::default();
        high.runtime.tier = crate::policy::tier::Tier::High;
        assert!(matches!(
            decide_mcp_args(Some(&deep), &here(), &high),
            Decision::Deny { .. }
        ));
    }
}
