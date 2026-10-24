//! Output redaction (PostToolUse).
//!
//! Scans tool output for high-signal secrets and replaces each match with a
//! `***REDACTED:<kind>***` marker. This module also hosts the shared secret
//! *detectors* (`find_keypair_array`, `is_base58_secret_key`, `find_seed_phrases`, the last
//! backed by [`crate::seedphrase`]) reused by [`crate::promptguard`].
//!
//! Everything is pure in-memory byte/char scanning with no compiled-regex dependency,
//! so it stays cheap enough to run on every tool output.
//!
//! Hook contract (spec D3.5): the input is the PostToolUse `tool_response`, whose shape differs
//! per tool (Read `{type:"text",file:{filePath,content,…}}`, Bash `{stdout,stderr,…}`, Grep
//! `{mode,filenames,content,…}`, MCP content blocks or a string). [`scrub_response`] rewrites
//! the string leaves in place and keeps every other field, so the output has the tool's exact
//! shape: Claude Code silently ignores a mismatched `updatedToolOutput` and the original, with
//! the secret, reaches the model. Two passes run on each string: exact project env values
//! ([`scrub_values`], `«redacted:KEY»`), then the pattern detectors ([`scrub`]).
//!
//! The hook fails open: a `tool_response` larger than [`MAX_SCAN_BYTES`] (stdin payload) is not
//! parsed and passes unchanged. Claude Code already truncates Bash output and pages Read output
//! well below that, so the bound only matters for unusually large MCP results.

use std::path::Path;

use serde_json::Value;

use crate::env::values::KnownValue;
use crate::gates::read::{self, ReadVerdict};
use crate::gates::secretpath::{self, Class};
use crate::io::{Decision, HookInput};
use crate::policy::Policy;
use crate::seedphrase;

/// Largest PostToolUse payload the redact hook parses (8 MiB). Larger payloads pass unscanned.
pub const MAX_SCAN_BYTES: usize = 8 * 1024 * 1024;

/// Scrub one `tool_response` value: every string leaf goes through [`scrub_values`] and then
/// [`scrub`]; keys, numbers, booleans and structure are kept. `None` when nothing changed.
pub fn scrub_response(response: &Value, values: &[KnownValue]) -> Option<Value> {
    scrub_value(response, values)
}

/// Whether `text` carries a redaction marker this module writes (`***REDACTED:` or
/// `«redacted:`).
pub fn contains_marker(text: &str) -> bool {
    text.contains("***REDACTED:") || text.contains("«redacted:")
}

/// The PostToolUse redact decision for one hook payload: [`scrub_response`], except that the
/// response of a raw env Read the tier permits (a project `.env`/`.env.*` at Off, Relaxed or
/// Medium, [`crate::gates::envread`]) skips the value scrub, since a value-scrubbed copy would
/// be written back over the real values by the next Edit or Write.
/// Pattern redaction (keys, seeds, PEM, vendor tokens) still applies to it at every tier; the
/// write gate refuses to write a redaction marker back into an env file. The exemption is
/// verified here, not inferred from the response having arrived: the tool is `Read`, both the
/// requested file and the response's file are env class (by name or resolved target), and the
/// read gate, re-run on the request with this `policy` (its runtime tier and `env_read`), lets
/// it through (no opinion, or an ask the user approved). When the read gate crashed or was
/// bypassed on a read it would deny, the response is scrubbed. Bash output (`cat .env`) is
/// always value-scrubbed: only the Read tool's response feeds an Edit.
pub fn scrub_tool_response(
    input: &HookInput,
    response: &Value,
    values: &[KnownValue],
    cwd: &Path,
    policy: &Policy,
) -> Option<Value> {
    if is_permitted_env_read(input, response, cwd, policy) {
        return scrub_response(response, &[]);
    }
    scrub_response(response, values)
}

fn is_permitted_env_read(input: &HookInput, response: &Value, cwd: &Path, policy: &Policy) -> bool {
    if input.tool_name.as_deref() != Some("Read")
        || response.get("type").and_then(Value::as_str) != Some("text")
    {
        return false;
    }
    let requested = input
        .tool_input
        .as_ref()
        .and_then(|i| i.get("file_path"))
        .and_then(Value::as_str);
    let served = response
        .get("file")
        .and_then(|f| f.get("filePath"))
        .and_then(Value::as_str);
    let (Some(requested), Some(served)) = (requested, served) else {
        return false;
    };
    if !is_env_file(requested, cwd) || !is_env_file(served, cwd) {
        return false;
    }
    matches!(
        read::decide_tool("Read", input.tool_input.as_ref(), cwd, policy),
        ReadVerdict::Decide(Decision::Defer | Decision::Ask { .. })
    )
}

/// Whether `file` (absolute or relative to `cwd`) is env class by name or resolved target.
fn is_env_file(file: &str, cwd: &Path) -> bool {
    let is_env = |p: &str| secretpath::classify(p) == Class::Env;
    is_env(file)
        || std::fs::canonicalize(cwd.join(file)).is_ok_and(|r| is_env(&r.to_string_lossy()))
}

fn scrub_value(response: &Value, values: &[KnownValue]) -> Option<Value> {
    if is_binary_payload(response) {
        return None;
    }
    match response {
        Value::String(text) if is_base64_blob(text) => None,
        Value::String(text) => {
            let after_values = scrub_values(text, values);
            let base = after_values.as_deref().unwrap_or(text);
            match scrub(base) {
                Some(out) => Some(Value::String(out)),
                None => after_values.map(Value::String),
            }
        }
        Value::Array(items) => {
            let scrubbed: Vec<Option<Value>> =
                items.iter().map(|v| scrub_value(v, values)).collect();
            if scrubbed.iter().all(Option::is_none) {
                return None;
            }
            Some(Value::Array(
                scrubbed
                    .into_iter()
                    .zip(items)
                    .map(|(new, old)| new.unwrap_or_else(|| old.clone()))
                    .collect(),
            ))
        }
        Value::Object(map) => {
            // Bash `{isImage:true,…}`: `stdout` holds the image; `stderr` is still text.
            let image_stdout = map.get("isImage").and_then(Value::as_bool) == Some(true);
            let mut changed = false;
            let mut out = map.clone();
            for (key, value) in map {
                if image_stdout && key == "stdout" {
                    continue;
                }
                if let Some(new) = scrub_value(value, values) {
                    out.insert(key.clone(), new);
                    changed = true;
                }
            }
            changed.then_some(Value::Object(out))
        }
        _ => None,
    }
}

/// Image / PDF payloads are left alone: their base64 data would trip the base58 detector
/// (about once per 200 KB of random base64) and a changed byte corrupts the file. Read
/// `{type:"image"|"pdf",file:{…}}`, MCP `{type:"image",data:…}`. Bash `{isImage:true,…}`
/// skips only its `stdout` (see [`scrub_value`]).
fn is_binary_payload(value: &Value) -> bool {
    let Value::Object(map) = value else {
        return false;
    };
    map.get("type")
        .and_then(Value::as_str)
        .is_some_and(|t| matches!(t, "image" | "pdf" | "document" | "audio"))
}

/// One unbroken base64 / base64url run longer than 1 KiB (an inline file, not text), bare or
/// as a `data:<mime>;base64,` URI.
fn is_base64_blob(text: &str) -> bool {
    let text = match text
        .strip_prefix("data:")
        .and_then(|r| r.split_once(";base64,"))
    {
        Some((mime, body)) if !mime.contains(char::is_whitespace) => body,
        _ => text,
    };
    text.len() > 1024
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_'))
}

/// Replace each occurrence of a known env value with `«redacted:KEY»`. `values` should be
/// longest first (as [`crate::env::values::load`] returns them) so a value containing another
/// is replaced whole. `None` when nothing matched.
/// Only whole tokens match: the characters on both sides of an occurrence must not be
/// `[A-Za-z0-9_]` (so `postgres` is not replaced inside `postgresql`).
pub fn scrub_values(text: &str, values: &[KnownValue]) -> Option<String> {
    let mut out: Option<String> = None;
    for known in values {
        if known.value.is_empty() {
            continue;
        }
        let current = out.as_deref().unwrap_or(text);
        if let Some(replaced) = replace_tokens(current, &known.value, &known.key) {
            out = Some(replaced);
        }
    }
    out
}

/// `text` with whole-token occurrences of `value` replaced, or `None` when there are none.
fn replace_tokens(text: &str, value: &str, key: &str) -> Option<String> {
    let is_word = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
    let mut out = String::new();
    let mut cursor = 0;
    let mut changed = false;
    for (start, _) in text.match_indices(value) {
        if start < cursor {
            continue;
        }
        let end = start + value.len();
        let before = text[..start].chars().next_back();
        let after = text[end..].chars().next();
        if is_word(before) || is_word(after) {
            continue;
        }
        out.push_str(&text[cursor..start]);
        out.push_str(&format!("«redacted:{key}»"));
        cursor = end;
        changed = true;
    }
    if !changed {
        return None;
    }
    out.push_str(&text[cursor..]);
    Some(out)
}

/// Key names that announce a secret (`*_KEY`, `*TOKEN*`, `*SECRET*`, `*PASSWORD*`, …), for the
/// value scrub. The one key-name table: every name [`names_secret_value`] accepts is accepted
/// here too, plus whole-segment secret words.
pub(crate) fn is_secret_key_name(key: &str) -> bool {
    // Whole `_`/`-`/`.`-delimited segments: `KEY` hits `API_KEY`, not `MONKEY`/`KEYBOARD`;
    // `AUTH` hits `GITHUB_AUTH`, not `AUTHOR`.
    const WORDS: &[&str] = &[
        "KEY",
        "KEYS",
        "APIKEY",
        "SECRET",
        "SECRETS",
        "TOKEN",
        "TOKENS",
        "PASSWORD",
        "PASSWD",
        "PASS",
        "PASSPHRASE",
        "PWD",
        "PRIVATE",
        "PRIVKEY",
        "CREDENTIAL",
        "CREDENTIALS",
        "CREDS",
        "AUTH",
        "SEED",
        "MNEMONIC",
        "JWT",
        "SIGNATURE",
        "COOKIE",
        "SESSION",
        "DSN",
        "WEBHOOK",
    ];
    let upper = key.to_ascii_uppercase();
    names_secret_value(&upper) || upper.split(['_', '-', '.']).any(|seg| WORDS.contains(&seg))
}

/// The narrow key-name set whose literal value is key material on its own (the `.env.schema`
/// content guard, [`contains_key_material`]): `*_API_KEY`, `*_SECRET`, `*_TOKEN`,
/// `*PASSWORD*`, `*PRIVATE_KEY`, and `*_KEY` naming a secret, private, auth or access key.
/// Words such as `SESSION` or `AUTH` alone don't count: a schema default like
/// `SESSION_TIMEOUT=3600` must not deny the whole file.
pub(crate) fn names_secret_value(key: &str) -> bool {
    let key = key.trim().to_ascii_uppercase();
    key.ends_with("_API_KEY")
        || key == "API_KEY"
        || key.ends_with("_SECRET")
        || key == "SECRET"
        || key.ends_with("_TOKEN")
        || key == "TOKEN"
        || key.contains("PASSWORD")
        || key.contains("_SECRET_")
        || key.ends_with("PRIVATE_KEY")
        || (key.ends_with("_KEY")
            && ["SECRET", "PRIVATE", "AUTH", "ACCESS"]
                .iter()
                .any(|w| key.contains(w)))
}

/// A single redaction span: `[start, end)` byte range and the marker kind.
struct Span {
    start: usize,
    end: usize,
    kind: &'static str,
}

/// Scrub secrets from `text`.
///
/// Returns `Some(scrubbed)` only when at least one redaction was made; `None` means the
/// text is unchanged (no `updatedToolOutput` is emitted). Detected classes:
/// - Solana keypair JSON byte arrays (`[12,34,...]` of 32 or 64 ints in `0..=255`).
/// - 64-byte base58 secret keys, plus `"secretKey"`/`"privateKey"` JSON field values.
/// - BIP-39 seed phrases ([`crate::seedphrase`]: checksum-valid runs of wordlist words, and
///   phrase-shaped runs when a mnemonic/seed/phrase/recovery/secret keyword is in the string).
/// - Common API-key shapes (`*_API_KEY=`, `PRIVATE_KEY=`, `sk-…`, `eyJ…` JWTs).
/// - PEM / OpenSSH private-key blocks (`-----BEGIN … PRIVATE KEY-----` through its `END` line).
/// - Vendor tokens ([`API_TOKEN_PREFIXES`]: GitHub, AWS, Slack, Google, Stripe, OpenAI).
///
/// Ordinary 32-byte base58 public keys are deliberately NOT redacted to avoid mangling
/// normal output (addresses appear constantly in legitimate Solana tool output).
pub fn scrub(text: &str) -> Option<String> {
    let mut spans: Vec<Span> = Vec::new();

    collect_keypair_arrays(text, &mut spans);
    collect_seed_phrases(text, &mut spans);
    collect_base58_secret_keys(text, &mut spans);
    collect_json_secret_fields(text, &mut spans);
    collect_api_keys(text, &mut spans);
    collect_pem_blocks(text, &mut spans);
    collect_vendor_tokens(text, &mut spans);

    if spans.is_empty() {
        return None;
    }

    // Resolve overlaps: sort by start, keep earliest, skip any span that overlaps a kept one.
    spans.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
    let mut kept: Vec<&Span> = Vec::with_capacity(spans.len());
    let mut last_end = 0usize;
    for s in &spans {
        if s.start >= last_end {
            kept.push(s);
            last_end = s.end;
        }
    }

    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    for s in kept {
        if s.start > cursor {
            // Safe: spans are produced on char/ASCII boundaries (see detectors).
            out.push_str(&text[cursor..s.start]);
        }
        out.push_str("***REDACTED:");
        out.push_str(s.kind);
        out.push_str("***");
        cursor = s.end;
    }
    if cursor < bytes.len() {
        out.push_str(&text[cursor..]);
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Shared detectors (also used by promptguard)
// ---------------------------------------------------------------------------

/// Find the first keypair-style JSON byte array in `text` and return its `[start, end)`
/// byte range. A match is a `[` … `]` containing exactly 32 or 64 comma-separated
/// integers, each in `0..=255` (the `id.json` keypair format). Returns `None` otherwise.
pub(crate) fn find_keypair_array(text: &str) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'[' {
            if let Some(end) = parse_int_array(bytes, i) {
                return Some((i, end));
            }
        }
        i += 1;
    }
    None
}

/// Returns `true` if `s` is a base58 string that decodes to exactly 64 bytes (an Ed25519
/// secret key). 32-byte values (public keys) intentionally return `false`.
pub(crate) fn is_base58_secret_key(s: &str) -> bool {
    // Length pre-filter: 64 raw bytes encode to ~87-88 base58 chars.
    if s.len() < 80 || s.len() > 90 {
        return false;
    }
    if !s.bytes().all(is_base58_char) {
        return false;
    }
    matches!(bs58::decode(s).into_vec(), Ok(v) if v.len() == 64)
}

/// Every seed phrase in `text` ([`crate::seedphrase::find`]).
pub(crate) fn find_seed_phrases(text: &str) -> Vec<(usize, usize)> {
    seedphrase::find(text)
}

/// Whether `text` holds key material: a keypair-style byte array, a base58-encoded 64-byte
/// secret key, a PEM/OpenSSH private-key header, a JWT, a vendor-prefixed API token
/// ([`API_TOKEN_PREFIXES`]), or a literal value on an assignment whose key
/// [`names_secret_value`] (`*_API_KEY`, `*_SECRET`, `*_TOKEN`, `*PASSWORD*`, `*PRIVATE_KEY`).
///
/// High-confidence only. Unlike [`scrub`], an assignment whose value is empty, a placeholder
/// (`<...>`, `xxx`, `changeme`, `your-...`), a reference (`$VAR`, `${VAR}`) or a function call
/// (`varlock(...)`, `exec(...)`) is not a hit, so a schema line such as
/// `HELIUS_API_KEY=varlock("local:...")` passes. `#` comment lines are skipped for assignments.
pub(crate) fn contains_key_material(text: &str) -> bool {
    if find_keypair_array(text).is_some() {
        return true;
    }
    let mut spans = Vec::new();
    collect_base58_secret_keys(text, &mut spans);
    collect_jwts(text, &mut spans);
    if !spans.is_empty() || has_secret_token(text) {
        return true;
    }
    if text.contains("-----BEGIN") && text.contains("PRIVATE KEY-----") {
        return true;
    }
    text.lines().any(has_literal_secret_assignment)
}

/// Vendor-prefixed API tokens long enough to be real, with their minimum length.
const API_TOKEN_PREFIXES: &[(&str, usize)] = &[
    ("sk_live_", 20),
    ("rk_live_", 20),
    ("sk_test_", 20),
    ("sk-", 24),
    ("ghp_", 30),
    ("gho_", 30),
    ("ghs_", 30),
    ("github_pat_", 30),
    ("xoxb-", 20),
    ("xoxp-", 20),
    ("AKIA", 20),
    ("AIza", 35),
];

/// A vendor-prefixed token ([`API_TOKEN_PREFIXES`], or `sk-`/`sk_live_`/`sk_test_` of at least
/// 20 chars) that starts a word, so prose such as `desk-lamp-description-text` is not a hit.
fn has_secret_token(text: &str) -> bool {
    let bytes = text.as_bytes();
    let short = [("sk-", 20), ("sk_live_", 20), ("sk_test_", 20)];
    for (prefix, min) in API_TOKEN_PREFIXES.iter().chain(short.iter()) {
        let mut from = 0usize;
        while let Some(rel) = text[from..].find(prefix) {
            let start = from + rel;
            let mut end = start + prefix.len();
            while end < bytes.len() && is_token_char(bytes[end]) {
                end += 1;
            }
            if (start == 0 || !is_token_char(bytes[start - 1])) && end - start >= *min {
                return true;
            }
            from = end;
        }
    }
    false
}

/// A `KEY=value` line where `KEY` is secret-named and `value` is a non-empty literal.
fn has_literal_secret_assignment(line: &str) -> bool {
    let line = line.trim();
    if line.starts_with('#') {
        return false;
    }
    let line = line.strip_prefix("export ").unwrap_or(line);
    let Some((key, value)) = line.split_once('=') else {
        return false;
    };
    names_secret_value(key) && !is_non_literal_value(strip_value(value))
}

/// The assignment value without surrounding quotes or a trailing ` # comment`: a quoted
/// value ends at its closing quote, an unquoted one at the first `#` that starts a word.
fn strip_value(value: &str) -> &str {
    let value = value.trim();
    if let Some(quote) = value
        .chars()
        .next()
        .filter(|c| matches!(c, '"' | '\'' | '`'))
    {
        let inner = &value[1..];
        return inner.split(quote).next().unwrap_or(inner);
    }
    let mut prev_ws = true;
    for (i, c) in value.char_indices() {
        if c == '#' && prev_ws {
            return value[..i].trim_end();
        }
        prev_ws = c.is_whitespace();
    }
    value
}

/// Whether an assignment value is empty, a placeholder, a reference or a function call.
fn is_non_literal_value(value: &str) -> bool {
    if value.is_empty() || value.starts_with('$') || value.starts_with('<') {
        return true;
    }
    let lower = value.to_ascii_lowercase();
    if lower.starts_with("your-")
        || lower.starts_with("your_")
        || lower.starts_with("changeme")
        || lower.starts_with("change-me")
        || lower.starts_with("change_me")
        || lower.chars().all(|c| c == 'x' || c == '*')
    {
        return true;
    }
    // `name(...)`: a resolver such as `varlock("local:...")` or `exec(...)`, never a literal.
    match value.find('(') {
        Some(open) if value.ends_with(')') => {
            let name = &value[..open];
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Collectors (scrub-only)
// ---------------------------------------------------------------------------

fn collect_keypair_arrays(text: &str, spans: &mut Vec<Span>) {
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'[' {
            if let Some(end) = parse_int_array(bytes, i) {
                spans.push(Span {
                    start: i,
                    end,
                    kind: "keypair",
                });
                i = end;
                continue;
            }
        }
        i += 1;
    }
}

fn collect_seed_phrases(text: &str, spans: &mut Vec<Span>) {
    for (start, end) in find_seed_phrases(text) {
        spans.push(Span {
            start,
            end,
            kind: "seed_phrase",
        });
    }
}

fn collect_base58_secret_keys(text: &str, spans: &mut Vec<Span>) {
    // Walk maximal base58 token runs; redact only those decoding to 64 bytes.
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if is_base58_char(bytes[i]) {
            let start = i;
            while i < bytes.len() && is_base58_char(bytes[i]) {
                i += 1;
            }
            let tok = &text[start..i];
            if is_base58_secret_key(tok) {
                spans.push(Span {
                    start,
                    end: i,
                    kind: "base58_secret_key",
                });
            }
        } else {
            i += 1;
        }
    }
}

fn collect_json_secret_fields(text: &str, spans: &mut Vec<Span>) {
    // Match `"secretKey"`/`"privateKey"` : "<value>" and redact the string value.
    for key in ["secretKey", "privateKey", "secret_key", "private_key"] {
        let needle = format!("\"{key}\"");
        let mut from = 0usize;
        while let Some(rel) = text[from..].find(&needle) {
            let key_pos = from + rel;
            // Find the colon then the opening quote of the value.
            let after = key_pos + needle.len();
            if let Some((vstart, vend)) = json_string_value_after(text, after) {
                spans.push(Span {
                    start: vstart,
                    end: vend,
                    kind: "secret_key",
                });
                from = vend;
            } else {
                from = after;
            }
        }
    }
}

fn collect_api_keys(text: &str, spans: &mut Vec<Span>) {
    // `*_API_KEY=value` and `PRIVATE_KEY=value` env-style assignments.
    collect_kv_assignments(text, spans);
    // `sk-...` OpenAI-style and `eyJ...` JWT bearer tokens.
    collect_prefixed_tokens(text, "sk-", 20, spans, "api_key");
    collect_jwts(text, spans);
}

/// Longest PEM block searched for its `END` line.
const MAX_PEM_BYTES: usize = 64 * 1024;

/// Collect `-----BEGIN … PRIVATE KEY-----` blocks through the matching `-----END …-----`. An
/// unterminated block runs over the base64 body that follows (base64 characters, whitespace
/// and `\n` escapes), so a truncated key is still covered.
fn collect_pem_blocks(text: &str, spans: &mut Vec<Span>) {
    const BEGIN: &str = "-----BEGIN ";
    const DASHES: &str = "-----";
    let bytes = text.as_bytes();
    let mut from = 0usize;
    while let Some(rel) = text[from..].find(BEGIN) {
        let start = from + rel;
        let label_from = start + BEGIN.len();
        let Some(label_len) = text[label_from..].find(DASHES) else {
            break;
        };
        let label = &text[label_from..label_from + label_len];
        let header_end = label_from + label_len + DASHES.len();
        let is_private = label.ends_with("PRIVATE KEY")
            && label.len() <= 40
            && label.bytes().all(|b| b.is_ascii_uppercase() || b == b' ');
        if !is_private {
            from = header_end;
            continue;
        }
        let window_end = (header_end + MAX_PEM_BYTES).min(text.len());
        let window = text.get(header_end..window_end).unwrap_or("");
        let end = match window.find("-----END ") {
            Some(rel_end) => {
                let after = header_end + rel_end + "-----END ".len();
                text[after..]
                    .find(DASHES)
                    .map_or(text.len(), |d| after + d + DASHES.len())
            }
            None => {
                let mut end = header_end;
                while end < bytes.len()
                    && (bytes[end].is_ascii_alphanumeric()
                        || matches!(bytes[end], b'+' | b'/' | b'=' | b'\\')
                        || bytes[end].is_ascii_whitespace())
                {
                    end += 1;
                }
                end
            }
        };
        spans.push(Span {
            start,
            end,
            kind: "private_key",
        });
        from = end.max(start + 1);
    }
}

/// Collect vendor-prefixed tokens ([`API_TOKEN_PREFIXES`]) that start a word and reach the
/// prefix's minimum length.
fn collect_vendor_tokens(text: &str, spans: &mut Vec<Span>) {
    let bytes = text.as_bytes();
    for (prefix, min) in API_TOKEN_PREFIXES {
        let mut from = 0usize;
        while let Some(rel) = text[from..].find(prefix) {
            let start = from + rel;
            let mut end = start + prefix.len();
            while end < bytes.len() && is_token_char(bytes[end]) {
                end += 1;
            }
            if (start == 0 || !is_token_char(bytes[start - 1])) && end - start >= *min {
                spans.push(Span {
                    start,
                    end,
                    kind: "api_key",
                });
            }
            from = end.max(start + 1);
        }
    }
}

// ---------------------------------------------------------------------------
// Low-level helpers
// ---------------------------------------------------------------------------

/// Parse a `[ n, n, ... ]` integer array starting at `bytes[start] == '['`. Returns the
/// index just past the closing `]` if it holds exactly 32 or 64 integers all in `0..=255`,
/// else `None`. Tolerates whitespace.
fn parse_int_array(bytes: &[u8], start: usize) -> Option<usize> {
    debug_assert_eq!(bytes[start], b'[');
    let mut i = start + 1;
    let mut count = 0usize;
    loop {
        // Skip whitespace.
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            return None;
        }
        if bytes[i] == b']' {
            break;
        }
        // Parse one unsigned integer.
        let num_start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i == num_start {
            return None; // non-digit where a number was expected
        }
        // Bound length so we can parse without overflow; >3 digits can't be <=255.
        if i - num_start > 3 {
            return None;
        }
        let mut val: u32 = 0;
        for &d in &bytes[num_start..i] {
            val = val.checked_mul(10)?.checked_add((d - b'0') as u32)?;
        }
        if val > 255 {
            return None;
        }
        count += 1;
        if count > 64 {
            return None;
        }
        // Skip whitespace, then expect ',' or ']'.
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            return None;
        }
        match bytes[i] {
            b',' => i += 1,
            b']' => break,
            _ => return None,
        }
    }
    // i is at ']'.
    if count == 32 || count == 64 {
        Some(i + 1)
    } else {
        None
    }
}

/// Given the byte index just after a JSON key token, locate the string value
/// (`: "value"`) and return its inner `[start, end)` byte range (excluding quotes).
fn json_string_value_after(text: &str, after: usize) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut i = after;
    while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b':') {
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != b'"' {
        return None;
    }
    i += 1; // past opening quote
    let vstart = i;
    while i < bytes.len() && bytes[i] != b'"' {
        // Skip escaped chars so an escaped quote does not end the value early.
        if bytes[i] == b'\\' {
            i += 1;
        }
        i += 1;
    }
    if i > bytes.len() {
        return None;
    }
    Some((vstart, i.min(bytes.len())))
}

/// Collect `KEY=value` assignments where `KEY` ends in `_API_KEY` / is `PRIVATE_KEY` /
/// `HELIUS_API_KEY`. The redacted span is the value run (to whitespace/quote).
fn collect_kv_assignments(text: &str, spans: &mut Vec<Span>) {
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'=' {
            // Walk backward to the start of the key token.
            let mut ks = i;
            while ks > 0 && is_key_char(bytes[ks - 1]) {
                ks -= 1;
            }
            let key = &text[ks..i];
            let ku = key.to_ascii_uppercase();
            if ku.ends_with("_API_KEY") || ku == "PRIVATE_KEY" || ku == "API_KEY" {
                let mut vs = i + 1;
                // Optional opening quote.
                let mut quote = 0u8;
                if vs < bytes.len() && (bytes[vs] == b'"' || bytes[vs] == b'\'') {
                    quote = bytes[vs];
                    vs += 1;
                }
                // Already replaced by the exact-value pass: keep its key-naming marker.
                if text[vs..].starts_with("«redacted:") {
                    i = vs;
                    continue;
                }
                let mut ve = vs;
                while ve < bytes.len() {
                    let b = bytes[ve];
                    if quote != 0 {
                        if b == quote {
                            break;
                        }
                    } else if b.is_ascii_whitespace() {
                        break;
                    }
                    ve += 1;
                }
                if ve > vs {
                    spans.push(Span {
                        start: vs,
                        end: ve,
                        kind: "api_key",
                    });
                }
                i = ve;
                continue;
            }
        }
        i += 1;
    }
}

/// Collect tokens beginning with `prefix` whose total length is at least `min_len`.
fn collect_prefixed_tokens(
    text: &str,
    prefix: &str,
    min_len: usize,
    spans: &mut Vec<Span>,
    kind: &'static str,
) {
    let mut from = 0usize;
    while let Some(rel) = text[from..].find(prefix) {
        let start = from + rel;
        let bytes = text.as_bytes();
        let mut end = start + prefix.len();
        while end < bytes.len() && is_token_char(bytes[end]) {
            end += 1;
        }
        // A token starts a word: `desk-lamp-…` is prose, not an `sk-` key.
        let word_start = start == 0 || !is_token_char(bytes[start - 1]);
        if word_start && end - start >= min_len {
            spans.push(Span { start, end, kind });
        }
        from = end.max(start + 1);
    }
}

/// Collect `eyJ…` JWT-shaped tokens (three base64url segments joined by `.`).
fn collect_jwts(text: &str, spans: &mut Vec<Span>) {
    let mut from = 0usize;
    while let Some(rel) = text[from..].find("eyJ") {
        let start = from + rel;
        let bytes = text.as_bytes();
        let mut end = start;
        let mut dots = 0usize;
        while end < bytes.len() {
            let b = bytes[end];
            if is_b64url_char(b) {
                end += 1;
            } else if b == b'.' {
                dots += 1;
                end += 1;
            } else {
                break;
            }
        }
        // A JWT has two dots and a reasonable length.
        if dots >= 2 && end - start >= 20 {
            spans.push(Span {
                start,
                end,
                kind: "jwt",
            });
        }
        from = end.max(start + 1);
    }
}

#[inline]
fn is_base58_char(b: u8) -> bool {
    // Bitcoin base58 alphabet: no 0, O, I, l.
    matches!(b, b'1'..=b'9' | b'A'..=b'H' | b'J'..=b'N' | b'P'..=b'Z' | b'a'..=b'k' | b'm'..=b'z')
}

#[inline]
fn is_key_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

#[inline]
fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

#[inline]
fn is_b64url_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn known(key: &str, value: &str) -> KnownValue {
        KnownValue {
            key: key.into(),
            value: value.into(),
        }
    }

    #[test]
    fn scrub_values_longest_first() {
        let values = [known("LONG", "abcdefgh-ijkl"), known("SHORT", "abcdefgh")];
        assert_eq!(
            scrub_values("x abcdefgh-ijkl y abcdefgh", &values).as_deref(),
            Some("x «redacted:LONG» y «redacted:SHORT»")
        );
        assert_eq!(scrub_values("clean", &values), None);
    }

    #[test]
    fn scrub_values_matches_whole_tokens_only() {
        let values = [known("DB", "postgres-main")];
        assert_eq!(
            scrub_values("xpostgres-main postgres-main_1", &values),
            None
        );
        assert_eq!(
            scrub_values("(postgres-main)", &values).as_deref(),
            Some("(«redacted:DB»)")
        );
        assert_eq!(
            scrub_values("postgres-main", &values).as_deref(),
            Some("«redacted:DB»")
        );
    }

    #[test]
    fn binary_payloads_are_left_alone() {
        let arr: Vec<String> = (0..64).map(|i| i.to_string()).collect();
        let keypair = format!("[{}]", arr.join(","));
        for v in [
            json!({ "type": "image", "file": { "base64": keypair, "type": "image/png" } }),
            json!({ "stdout": keypair, "isImage": true }),
            json!([{ "type": "image", "data": keypair, "mimeType": "image/png" }]),
        ] {
            assert_eq!(scrub_response(&v, &[]), None, "{v}");
        }
        let blob = bs58::encode([9u8; 64]).into_string().repeat(20);
        assert_eq!(scrub_response(&json!(blob), &[]), None);
        let uri = format!("data:image/png;base64,{blob}");
        assert_eq!(scrub_response(&json!(uri), &[]), None);
    }

    #[test]
    fn bash_image_result_still_scrubs_stderr() {
        let arr: Vec<String> = (0..64).map(|i| i.to_string()).collect();
        let keypair = format!("[{}]", arr.join(","));
        let v = json!({ "stdout": keypair, "stderr": format!("k {keypair}"), "isImage": true });
        assert_eq!(
            scrub_response(&v, &[]),
            Some(
                json!({ "stdout": keypair, "stderr": "k ***REDACTED:keypair***", "isImage": true })
            )
        );
    }

    #[test]
    fn secret_key_names_by_segment() {
        for k in [
            "API_KEY",
            "helius_api_key",
            "DB_PASSWORD",
            "GITHUB_AUTH",
            "JWT",
            "x.token",
        ] {
            assert!(is_secret_key_name(k), "{k}");
        }
        for k in [
            "MONKEY",
            "KEYBOARD_LAYOUT",
            "AUTHOR",
            "PASSPORT_ID",
            "HOST",
            "RPC_URL",
        ] {
            assert!(!is_secret_key_name(k), "{k}");
        }
    }

    #[test]
    fn scrub_response_keeps_shape() {
        let values = [known("K", "secret-value-1")];
        let response = json!({
            "stdout": "a secret-value-1 b",
            "stderr": "",
            "interrupted": false,
            "nested": [1, "secret-value-1", {"x": null}]
        });
        assert_eq!(
            scrub_response(&response, &values),
            Some(json!({
                "stdout": "a «redacted:K» b",
                "stderr": "",
                "interrupted": false,
                "nested": [1, "«redacted:K»", {"x": null}]
            }))
        );
        assert_eq!(
            scrub_response(&json!({"a": "clean", "n": 3}), &values),
            None
        );
    }

    #[test]
    fn scrub_response_applies_patterns_after_values() {
        let arr: Vec<String> = (0..64).map(|i| i.to_string()).collect();
        let text = format!("[{}] secret-value-1", arr.join(","));
        let out = scrub_response(&json!(text), &[known("K", "secret-value-1")]).unwrap();
        let out = out.as_str().unwrap();
        assert!(
            out.contains("***REDACTED:keypair***") && out.contains("«redacted:K»"),
            "{out}"
        );
    }

    #[test]
    fn key_material_flags_credential_shapes() {
        for text in [
            "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwx",
            "STRIPE=sk_\x6cive_abcdefghijklmnop1234",
            "T=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghij",
            "HELIUS_API_KEY=0a1b2c3d-4e5f-6789-abcd-ef0123456789",
            "DB_PASSWORD=hunter2",
            "export GH_TOKEN=\"ghp_abc123\"",
            "APP_SECRET='s3cr3t'",
            "SIGNER_PRIVATE_KEY=abc",
            "DB_PASSWORD=pass(word",
            "STRIPE_SECRET_KEY=abc123",
            "SECRET_KEY=abc123",
            "AUTH_KEY=abc123",
            "AWS_ACCESS_KEY=AKIA1234",
            "DB_SECRET_URL=abc123",
            "PRIVATE_SIGNING_KEY=abc123",
            "API_KEY=abc123 # note",
            "API_KEY=\"abc123\" # note",
            "API_KEY=\"abc#def\"",
        ] {
            assert!(contains_key_material(text), "{text}");
        }
    }

    #[test]
    fn key_material_passes_non_literals_and_prose() {
        for text in [
            "HELIUS_API_KEY=",
            "HELIUS_API_KEY=varlock(\"local:abc\")",
            "API_KEY=exec(`op read x`)",
            "DB_PASSWORD=$DB_PASSWORD",
            "DB_PASSWORD=${DB_PASSWORD}",
            "DB_PASSWORD=<your password>",
            "GH_TOKEN=xxxxxxxx",
            "GH_TOKEN=changeme",
            "GH_TOKEN=your-token-here",
            "# OPENAI_API_KEY=hunter2",
            "# a desk-lamp-with-a-long-description-here",
            "SOLANA_CLUSTER=devnet",
            "API_KEY= # @sensitive",
            "API_KEY=# @sensitive",
            "API_KEY=exec('op read x') # note",
            "API_KEY=varlock(\"local:x\")\t# note",
            "API_KEY=\"\" # note",
            "SECRET_KEY=",
            "STRIPE_SECRET_KEY=$STRIPE",
            "PUBLIC_KEY=abc123",
            "AUTH_KEY=<paste>",
        ] {
            assert!(!contains_key_material(text), "{text}");
        }
    }

    #[test]
    fn keypair_byte_array_redacted() {
        // 64 ints in 0..=255.
        let arr: Vec<String> = (0..64).map(|i| (i % 256).to_string()).collect();
        let text = format!("keypair = [{}]", arr.join(","));
        let out = scrub(&text).expect("should redact keypair array");
        assert!(out.contains("***REDACTED:keypair***"));
        assert!(!out.contains("[0,1,2"));
    }

    #[test]
    fn keypair_32_array_redacted() {
        let arr: Vec<String> = (0..32).map(|i| (i % 256).to_string()).collect();
        let text = format!("[{}]", arr.join(", "));
        let out = scrub(&text).expect("32-int array should redact");
        assert!(out.contains("***REDACTED:keypair***"));
    }

    #[test]
    fn non_keypair_array_not_redacted() {
        // Only 3 ints — not a keypair.
        assert_eq!(scrub("nums = [1, 2, 3]"), None);
        // Contains a value > 255.
        let arr: Vec<String> = (0..64).map(|_| "300".to_string()).collect();
        assert_eq!(scrub(&format!("[{}]", arr.join(","))), None);
    }

    #[test]
    fn base58_secret_key_redacted() {
        // 64 bytes encoded to base58.
        let secret = bs58::encode(vec![7u8; 64]).into_string();
        let text = format!("found key {secret} in logs");
        let out = scrub(&text).expect("64-byte base58 should redact");
        assert!(out.contains("***REDACTED:base58_secret_key***"));
        assert!(!out.contains(&secret));
    }

    #[test]
    fn ordinary_pubkey_not_redacted() {
        // A normal 32-byte public key (e.g. an address) must survive untouched.
        let pubkey = bs58::encode(vec![3u8; 32]).into_string();
        let text = format!("owner: {pubkey}");
        assert_eq!(scrub(&text), None, "32-byte pubkey must not be redacted");
    }

    #[test]
    fn known_wrapped_sol_mint_not_redacted() {
        // Real 32-byte mint address — must not be a false positive.
        let text = "mint So11111111111111111111111111111111111111112 balance 5";
        assert_eq!(scrub(text), None);
    }

    #[test]
    fn pem_private_key_blocks_redacted() {
        let body = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW";
        let pem = format!(
            "before\n-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n{body}\n-----END OPENSSH PRIVATE KEY-----\nafter"
        );
        let out = scrub(&pem).unwrap();
        assert_eq!(out, "before\n***REDACTED:private_key***\nafter");
        // Unterminated (truncated output): the body that follows is covered too.
        let cut = format!("-----BEGIN RSA PRIVATE KEY-----\n{body}\n{body}");
        let out = scrub(&cut).unwrap();
        assert!(!out.contains(body), "{out}");
        // A JSON-escaped block on one line.
        let escaped =
            format!("\"-----BEGIN PRIVATE KEY-----\\n{body}\\n-----END PRIVATE KEY-----\"");
        assert!(!scrub(&escaped).unwrap().contains(body));
        // A certificate or public key is not secret.
        let cert = format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----");
        assert_eq!(scrub(&cert), None);
    }

    #[test]
    fn sk_prefix_needs_a_word_start() {
        assert_eq!(scrub("desk-lamp-description-text-very-long"), None);
        assert_eq!(
            scrub("key sk-proj-abcdefghijklmnopqrstuvwxyz0123").unwrap(),
            "key ***REDACTED:api_key***"
        );
    }

    #[test]
    fn vendor_tokens_redacted() {
        for token in [
            "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
            "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz",
            "AKIAIOSFODNN7EXAMPLE",
            "xox\x62-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx",
            "AIzaSyA1234567890abcdefghijklmnopqrstuv",
        ] {
            let out = scrub(&format!("token: {token} end")).unwrap_or_default();
            assert_eq!(out, "token: ***REDACTED:api_key*** end", "{token}");
        }
        for prose in ["xAKIAIOSFODNN7EXAMPLE", "ghp_short", "the AIza prefix"] {
            assert_eq!(scrub(prose), None, "{prose}");
        }
    }

    #[test]
    fn jwt_redacted() {
        let jwt =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dummsignaturepart";
        let out = scrub(&format!("Authorization: Bearer {jwt}")).expect("jwt should redact");
        assert!(out.contains("***REDACTED:jwt***"));
    }

    #[test]
    fn api_key_assignment_redacted() {
        let out = scrub("HELIUS_API_KEY=abcdef123456 next").expect("api key should redact");
        assert!(out.contains("***REDACTED:api_key***"));
        assert!(!out.contains("abcdef123456"));
    }

    #[test]
    fn seed_phrase_redacted() {
        let text = "mnemonic: legal winner thank year wave sausage worth useful legal winner thank yellow done";
        let out = scrub(text).expect("seed phrase should redact");
        assert!(out.contains("***REDACTED:seed_phrase***"));
    }

    #[test]
    fn clean_text_returns_none() {
        assert_eq!(scrub("just a normal log line with no secrets"), None);
        assert_eq!(scrub("Balance: 5 SOL, network devnet"), None);
    }

    #[test]
    fn json_secret_key_field_redacted() {
        let text = r#"{"secretKey":"verysecretvalue123","pubkey":"abc"}"#;
        let out = scrub(text).expect("secretKey field should redact");
        assert!(out.contains("***REDACTED:secret_key***"));
        assert!(!out.contains("verysecretvalue123"));
    }
}
