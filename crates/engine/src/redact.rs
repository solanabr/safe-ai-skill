//! Output redaction (PostToolUse).
//!
//! Scans tool output for high-signal secrets and replaces each match with a
//! `***REDACTED:<kind>***` marker. This module also hosts the shared secret
//! *detectors* (`find_keypair_array`, `is_base58_secret_key`, `find_seed_phrase`)
//! reused by [`crate::promptguard`] — kept here rather than in a separate module per
//! the architecture's no-new-module constraint.
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

use serde_json::Value;

use crate::env::values::KnownValue;

/// Largest PostToolUse payload the redact hook parses (8 MiB). Larger payloads pass unscanned.
pub const MAX_SCAN_BYTES: usize = 8 * 1024 * 1024;

/// Scrub one `tool_response` value: every string leaf goes through [`scrub_values`] and then
/// [`scrub`]; keys, numbers, booleans and structure are kept. `None` when nothing changed.
pub fn scrub_response(response: &Value, values: &[KnownValue]) -> Option<Value> {
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
                items.iter().map(|v| scrub_response(v, values)).collect();
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
            let mut changed = false;
            let mut out = map.clone();
            for (key, value) in map {
                if let Some(new) = scrub_response(value, values) {
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
/// `{type:"image"|"pdf",file:{…}}`, Bash `{isImage:true,…}`, MCP `{type:"image",data:…}`.
fn is_binary_payload(value: &Value) -> bool {
    let Value::Object(map) = value else {
        return false;
    };
    let typed = map
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|t| matches!(t, "image" | "pdf" | "document" | "audio"));
    typed || map.get("isImage").and_then(Value::as_bool) == Some(true)
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

/// Key names that announce a secret (`*_KEY`, `*TOKEN*`, `*SECRET*`, `*PASSWORD*`, …).
/// Shared with the value scrub; H9's `contains_key_material` key-name set should merge here.
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
    upper.split(['_', '-', '.']).any(|seg| WORDS.contains(&seg))
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
/// - BIP-39 seed phrases (a run of 12/24 lowercase words near a mnemonic/seed hint).
/// - Common API-key shapes (`*_API_KEY=`, `PRIVATE_KEY=`, `sk-…`, `eyJ…` JWTs).
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

/// Find a BIP-39-shaped seed phrase in `text` near a `mnemonic`/`seed`/`phrase` hint and
/// return its `[start, end)` byte range. Detects a run of 12 or 24 space-separated
/// lowercase a–z words (3–8 chars each, the wordlist shape). The hint requirement keeps
/// false positives low. Returns `None` when no qualifying run is found.
pub(crate) fn find_seed_phrase(text: &str) -> Option<(usize, usize)> {
    let lower = text.to_ascii_lowercase();
    if !(lower.contains("mnemonic") || lower.contains("seed") || lower.contains("phrase")) {
        return None;
    }

    let bytes = text.as_bytes();
    let mut word_starts: Vec<(usize, usize)> = Vec::new(); // (start, end) of each lowercase word
    let mut i = 0usize;
    while i < bytes.len() {
        if is_lower_alpha(bytes[i]) {
            let start = i;
            while i < bytes.len() && is_lower_alpha(bytes[i]) {
                i += 1;
            }
            word_starts.push((start, i));
        } else {
            i += 1;
        }
    }

    // Find a maximal run of consecutive wordlist-shaped words separated only by single spaces.
    let n = word_starts.len();
    let mut idx = 0usize;
    while idx < n {
        if !is_wordlist_shape(&text[word_starts[idx].0..word_starts[idx].1]) {
            idx += 1;
            continue;
        }
        let run_start_word = idx;
        let mut j = idx;
        while j + 1 < n {
            let (_, end_cur) = word_starts[j];
            let (start_next, _) = word_starts[j + 1];
            // Words must be separated only by spaces (the seed-phrase shape).
            let gap = &text[end_cur..start_next];
            if !gap.chars().all(|c| c == ' ') || gap.is_empty() {
                break;
            }
            if !is_wordlist_shape(&text[word_starts[j + 1].0..word_starts[j + 1].1]) {
                break;
            }
            j += 1;
        }
        let count = j - run_start_word + 1;
        if count >= 12 {
            let span_start = word_starts[run_start_word].0;
            // Take the largest valid prefix: exactly 24 if available, else exactly 12.
            let take = if count >= 24 { 24 } else { 12 };
            let span_end = word_starts[run_start_word + take - 1].1;
            return Some((span_start, span_end));
        }
        idx = j + 1;
    }
    None
}

/// Whether `text` holds key material: a keypair-style byte array, a base58-encoded 64-byte
/// secret key, or a PEM/OpenSSH private-key block. Narrower than [`scrub`] on purpose (no
/// `*_API_KEY=` or JWT shapes), so a schema line such as `HELIUS_API_KEY=varlock("local:…")`
/// is not a hit.
pub(crate) fn contains_key_material(text: &str) -> bool {
    if find_keypair_array(text).is_some() {
        return true;
    }
    let mut spans = Vec::new();
    collect_base58_secret_keys(text, &mut spans);
    if !spans.is_empty() {
        return true;
    }
    crate::gates::secretpath::has_private_key_block(text)
}

/// Whether `text` holds a high-confidence API credential: a vendor-prefixed token long enough
/// to be real (`sk_live_…`, `sk-…`, `ghp_…`, `xoxb-…`, `AKIA…`, `AIza…`) or a JWT. Key names
/// alone (`*_API_KEY=`) never count.
///
/// Interim: H9 (1.0.1) extends [`contains_key_material`] with API-key/credential detectors.
/// When H9 is merged, fold this into that helper and drop the second call in
/// `gates::read::guard_env_schema`.
pub(crate) fn contains_high_confidence_token(text: &str) -> bool {
    const PREFIXES: &[(&str, usize)] = &[
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
    let mut spans = Vec::new();
    for (prefix, min) in PREFIXES {
        collect_prefixed_tokens(text, prefix, *min, &mut spans, "api_key");
    }
    collect_jwts(text, &mut spans);
    !spans.is_empty()
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
    if let Some((start, end)) = find_seed_phrase(text) {
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
        if end - start >= min_len {
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
fn is_lower_alpha(b: u8) -> bool {
    b.is_ascii_lowercase()
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

/// A BIP-39 wordlist word is 3–8 lowercase a–z characters.
#[inline]
fn is_wordlist_shape(w: &str) -> bool {
    let len = w.len();
    (3..=8).contains(&len) && w.bytes().all(|b| b.is_ascii_lowercase())
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
