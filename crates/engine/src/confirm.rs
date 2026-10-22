//! Prompt-code confirmation for relaxing actions (spec D4.1, amended in WS-B fix round 1).
//!
//! `allow`, `mode <looser>`, `verify trust` and `verify approve` do not take effect when run:
//! they call [`create_pending`], which stores a pending entry under a short request id
//! ([`PendingId`]) in the authenticated `pending.json`. **No code exists yet**, and the CLI
//! prints none: the agent that ran the command learns only the id.
//!
//! The code is made at announcement. [`announce_pending`] runs in hooks whose output the user
//! sees: the PostToolUse `pending-notice` hook right after the Bash call that created the
//! entry, `UserPromptSubmit` and `SessionStart`. It draws a fresh 8-digit code (OS CSPRNG),
//! stores only `sha256(code ‖ id ‖ salt)` (the salt is derived from the state key), marks the
//! entry announced, and returns the code for the hook's `systemMessage` — never
//! `additionalContext`, which the model reads. Each entry is announced once. PostToolUse hooks
//! run before the model gets the tool result, so the announcement normally happens before
//! the agent can act again.
//!
//! The entry activates only when the user's next prompt is `safe-ai-skill confirm <code>`:
//! the `UserPromptSubmit` hook passes the prompt to [`confirm_attempt`], which consumes the
//! entry (single use). The prompt must only ever come from the `UserPromptSubmit` payload
//! ([`user_prompt`]). Three wrong codes cancel every pending entry ([`Attempt::LockedOut`]).
//!
//! ## What this does not stop
//!
//! Code running as the user outside the Claude Code sandbox can do anything: run the hook
//! subcommands itself (`pending-notice`, `prompt-guard`), read the key, rewrite state. The
//! tripwire hook denies Bash calls that invoke the hook subcommands or `confirm`, which stops
//! the direct forms; obfuscated ones, and a nested `claude -p` session, remain. The sandbox is
//! the hard boundary. When Claude Code cannot show a `systemMessage` (headless `claude -p`), a
//! relaxation simply cannot be confirmed.
//!
//! Live entries are capped at [`MAX_PENDING`]; an announced entry is confirmable for
//! [`TTL_SECS`] after its announcement, an unannounced one is dropped [`TTL_SECS`] after
//! creation. Every read-modify-write of `pending.json` holds `pending.lock`.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::datadir::DataDir;
use crate::error::{EngineError, Error};
use crate::io::HookInput;
use crate::statefile::{self, FileLock, Loaded};

/// State file holding the pending entries.
pub const PENDING_FILE: &str = "pending.json";

/// Seconds an announced entry stays confirmable (and an unannounced one is kept).
pub const TTL_SECS: u64 = 600;

/// Digits in a code.
const NONCE_DIGITS: usize = 8;

/// Most pending entries kept; creating one more drops the oldest.
pub const MAX_PENDING: usize = 32;

/// Wrong codes tolerated before every pending entry is cancelled.
pub const MAX_FAILURES: u32 = 3;

/// The two words that start a confirmation line.
const CONFIRM_WORDS: [&str; 2] = ["safe-ai-skill", "confirm"];

/// Lock file guarding `pending.json`.
const LOCK_FILE: &str = "pending.lock";

/// Label of the key-derived salt for code hashes.
const SALT_LABEL: &[u8] = b"safe-ai-skill/pending-code/v1";

/// What a pending entry would do once confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PendingKind {
    /// `safe-ai-skill allow …`: activate a grant.
    Grant,
    /// `safe-ai-skill mode <looser profile>`.
    Mode,
    /// `safe-ai-skill verify trust …`.
    Trust,
    /// `safe-ai-skill verify approve …`.
    Approve,
}

/// A confirmation code: [`NONCE_DIGITS`] ASCII digits. Only ever held in memory between
/// [`announce_pending`] and the hook's `systemMessage`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce(String);

impl Nonce {
    /// The digits.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A pending request's public id (`r` + 6 hex digits). Safe to show to the model: it
/// confirms nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingId(String);

impl PendingId {
    /// The id.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PendingId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A pending entry the user confirmed; the caller now performs it.
#[derive(Debug, Clone, PartialEq)]
pub struct Confirmed {
    /// What to do.
    pub kind: PendingKind,
    /// The human summary given at creation.
    pub summary: String,
    /// The action's parameters, as given to [`create_pending`].
    pub payload: Value,
}

/// A code to show the user (in a `systemMessage` only).
#[derive(Debug, Clone, PartialEq)]
pub struct Announcement {
    /// The request.
    pub id: PendingId,
    /// What it does.
    pub kind: PendingKind,
    /// The human summary given at creation.
    pub summary: String,
    /// The code to type.
    pub code: Nonce,
}

/// The outcome of a prompt given to [`confirm_attempt`].
#[derive(Debug, Clone, PartialEq)]
pub enum Attempt {
    /// The prompt is not a confirmation.
    NotAnAttempt,
    /// A confirmation line inside a longer prompt: refused, not counted, nothing consumed.
    Embedded,
    /// The code matched; the entry is consumed.
    Confirmed(Confirmed),
    /// A confirmation with no matching live entry; `remaining` wrong codes before lockout.
    Wrong {
        /// Wrong codes left before every pending entry is cancelled.
        remaining: u32,
    },
    /// The [`MAX_FAILURES`]th wrong code: every pending entry was cancelled.
    LockedOut,
}

/// The shape of a prompt, by one whitespace rule (tokens split on any whitespace).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptForm<'a> {
    /// No line starts with `safe-ai-skill confirm`.
    NotAConfirm,
    /// A line does, but the trimmed prompt has more than one line.
    Embedded,
    /// The whole trimmed prompt is one such line; the code token (`""` when the line has
    /// other than exactly three tokens).
    Line(&'a str),
}

/// Classify `prompt` (see [`PromptForm`]).
pub fn classify(prompt: &str) -> PromptForm<'_> {
    let starts_confirm = |line: &str| {
        let mut t = line.split_whitespace();
        t.next() == Some(CONFIRM_WORDS[0]) && t.next() == Some(CONFIRM_WORDS[1])
    };
    let trimmed = prompt.trim();
    if !trimmed.lines().any(starts_confirm) {
        return PromptForm::NotAConfirm;
    }
    if trimmed.lines().count() != 1 {
        return PromptForm::Embedded;
    }
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    match tokens.as_slice() {
        [_, _, code] => PromptForm::Line(code),
        _ => PromptForm::Line(""),
    }
}

/// One stored pending entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Entry {
    id: PendingId,
    kind: PendingKind,
    summary: String,
    payload: Value,
    created_at: u64,
    /// When the code was shown; `None` until announced.
    announced_at: Option<u64>,
    /// Hex `sha256(code ‖ 0 ‖ id ‖ 0 ‖ salt)`; `None` until announced.
    code_hash: Option<String>,
}

/// The `pending.json` body.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
struct Pending {
    entries: Vec<Entry>,
    /// Consecutive wrong codes.
    failures: u32,
}

/// Store a pending entry and return its id. No code is made here (see the module docs).
/// Expired entries are pruned; a tampered `pending.json` is discarded.
pub fn create_pending(
    dir: &DataDir,
    kind: PendingKind,
    summary: &str,
    payload: Value,
) -> Result<PendingId, EngineError> {
    statefile::create_dir_private(&dir.path)?;
    statefile::sweep_debris(&dir.path, LOCK_FILE);
    let _lock = FileLock::acquire(&dir.path, LOCK_FILE)?;
    // Read the clock under the lock: an earlier reading would prune entries stamped by
    // whoever held the lock meanwhile as "from the future".
    let now = now_secs();
    let mut pending = load_pending(dir);
    pending.entries.retain(|e| !is_expired(e, now));
    let id = loop {
        let id = random_id()?;
        if !pending.entries.iter().any(|e| e.id == id) {
            break id;
        }
    };
    pending.entries.push(Entry {
        id: id.clone(),
        kind,
        summary: summary.to_string(),
        payload,
        created_at: now,
        announced_at: None,
        code_hash: None,
    });
    let excess = pending.entries.len().saturating_sub(MAX_PENDING);
    pending.entries.drain(..excess);
    statefile::store(dir, PENDING_FILE, &pending)?;
    Ok(id)
}

/// Make and record a code for every live, unannounced entry, and return them for a
/// `systemMessage`. Empty when there is nothing to announce or the codes cannot be persisted
/// (a code is never shown that could not be checked later). Creates nothing when there is no
/// `pending.json`.
pub fn announce_pending(dir: &DataDir, now: u64) -> Vec<Announcement> {
    if dir.is_unresolved() || std::fs::symlink_metadata(dir.path.join(PENDING_FILE)).is_err() {
        return Vec::new();
    }
    let Ok(_lock) = FileLock::acquire(&dir.path, LOCK_FILE) else {
        return Vec::new();
    };
    let Loaded::Valid(mut pending) = statefile::load::<Pending>(dir, PENDING_FILE) else {
        return Vec::new();
    };
    let Ok(salt) = statefile::derived_key(dir, SALT_LABEL) else {
        return Vec::new();
    };
    pending.entries.retain(|e| !is_expired(e, now));
    let mut out = Vec::new();
    for e in pending
        .entries
        .iter_mut()
        .filter(|e| e.announced_at.is_none() && e.created_at <= now)
    {
        let Ok(code) = random_nonce() else {
            return Vec::new();
        };
        e.code_hash = Some(code_hash(&code, &e.id, &salt));
        e.announced_at = Some(now);
        out.push(Announcement {
            id: e.id.clone(),
            kind: e.kind,
            summary: e.summary.clone(),
            code,
        });
    }
    if out.is_empty() || statefile::store(dir, PENDING_FILE, &pending).is_err() {
        return Vec::new();
    }
    out
}

/// Check a user prompt against the announced entries.
///
/// `prompt` MUST be the `UserPromptSubmit` payload's `prompt` field (see [`user_prompt`]).
/// Only a prompt that is, trimmed, the single line `safe-ai-skill confirm <code>` can confirm
/// ([`classify`]). Such a line that matches no live announced entry counts as a wrong code
/// while any entry is live; the [`MAX_FAILURES`]th cancels them all. A missing or tampered
/// `pending.json`, or a consumption that cannot be persisted, confirms nothing.
pub fn confirm_attempt(dir: &DataDir, prompt: &str, now: u64) -> Attempt {
    let code = match classify(prompt) {
        PromptForm::NotAConfirm => return Attempt::NotAnAttempt,
        PromptForm::Embedded => return Attempt::Embedded,
        PromptForm::Line(code) => code,
    };
    let wrong = Attempt::Wrong {
        remaining: MAX_FAILURES,
    };
    let Ok(_lock) = FileLock::acquire(&dir.path, LOCK_FILE) else {
        return wrong;
    };
    let Loaded::Valid(mut pending) = statefile::load::<Pending>(dir, PENDING_FILE) else {
        return wrong;
    };
    pending.entries.retain(|e| !is_expired(e, now));
    if pending.entries.is_empty() {
        pending.failures = 0;
        let _ = statefile::store(dir, PENDING_FILE, &pending);
        return wrong;
    }
    let hit = match (is_nonce(code), statefile::derived_key(dir, SALT_LABEL)) {
        (true, Ok(salt)) => pending.entries.iter().position(|e| {
            is_live(e, now)
                && e.code_hash.as_deref().is_some_and(|h| {
                    constant_time_eq(
                        h.as_bytes(),
                        code_hash(&Nonce(code.to_string()), &e.id, &salt).as_bytes(),
                    )
                })
        }),
        _ => None,
    };
    let Some(i) = hit else {
        pending.failures = pending.failures.saturating_add(1);
        if pending.failures >= MAX_FAILURES {
            pending.entries.clear();
            pending.failures = 0;
            let _ = statefile::store(dir, PENDING_FILE, &pending);
            return Attempt::LockedOut;
        }
        let remaining = MAX_FAILURES - pending.failures;
        if statefile::store(dir, PENDING_FILE, &pending).is_err() {
            // Without the count persisted, a wrong code must not be free: report lockout.
            return Attempt::LockedOut;
        }
        return Attempt::Wrong { remaining };
    };
    let entry = pending.entries.remove(i);
    pending.failures = 0;
    if statefile::store(dir, PENDING_FILE, &pending).is_err() {
        return wrong;
    }
    Attempt::Confirmed(Confirmed {
        kind: entry.kind,
        summary: entry.summary,
        payload: entry.payload,
    })
}

/// [`confirm_attempt`], keeping only a confirmation.
pub fn confirm_from_prompt(dir: &DataDir, prompt: &str, now: u64) -> Option<Confirmed> {
    match confirm_attempt(dir, prompt, now) {
        Attempt::Confirmed(c) => Some(c),
        _ => None,
    }
}

/// The prompt of a `UserPromptSubmit` payload; `None` for any other event. This is the only
/// payload text [`confirm_attempt`] may be given.
pub fn user_prompt(input: &HookInput) -> Option<&str> {
    if input.hook_event_name.as_deref() != Some("UserPromptSubmit") {
        return None;
    }
    input.prompt.as_deref()
}

/// The `systemMessage` text for announcements (user only; never give it to the model).
pub fn announcement_message(items: &[Announcement]) -> Option<String> {
    if items.is_empty() {
        return None;
    }
    let lines: Vec<String> = items
        .iter()
        .map(|a| {
            format!(
                "request {} ({}): to approve it, type `safe-ai-skill confirm {}` as your entire \
                 next prompt (valid {} minutes)",
                a.id,
                a.summary,
                a.code,
                TTL_SECS / 60
            )
        })
        .collect();
    Some(format!(
        "safe-ai-skill confirmation code (shown only to you; ignore it if you did not ask for \
         this):\n - {}",
        lines.join("\n - ")
    ))
}

fn load_pending(dir: &DataDir) -> Pending {
    match statefile::load::<Pending>(dir, PENDING_FILE) {
        Loaded::Valid(p) => p,
        Loaded::Missing | Loaded::Tampered => Pending::default(),
    }
}

fn code_hash(code: &Nonce, id: &PendingId, salt: &[u8]) -> String {
    let digest = Sha256::new()
        .chain_update(code.as_str().as_bytes())
        .chain_update([0u8])
        .chain_update(id.as_str().as_bytes())
        .chain_update([0u8])
        .chain_update(salt)
        .finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn is_nonce(s: &str) -> bool {
    s.len() == NONCE_DIGITS && s.bytes().all(|b| b.is_ascii_digit())
}

/// The clock an entry's TTL runs on: its announcement, else its creation.
fn clock(e: &Entry) -> u64 {
    e.announced_at.unwrap_or(e.created_at)
}

/// Older than [`TTL_SECS`] at `now`.
fn is_expired(e: &Entry, now: u64) -> bool {
    now.saturating_sub(clock(e)) > TTL_SECS
}

/// Confirmable at `now`: announced, not expired, not stamped in the future.
fn is_live(e: &Entry, now: u64) -> bool {
    e.announced_at
        .is_some_and(|at| at <= now && now - at <= TTL_SECS)
}

fn random_bytes<const N: usize>() -> Result<[u8; N], EngineError> {
    let mut buf = [0u8; N];
    rand_core::RngCore::try_fill_bytes(&mut rand_core::OsRng, &mut buf)
        .map_err(|e| Error::Other(format!("OS random source: {e}")))?;
    Ok(buf)
}

/// `r` + 6 hex digits.
fn random_id() -> Result<PendingId, EngineError> {
    let b = random_bytes::<3>()?;
    Ok(PendingId(format!("r{:02x}{:02x}{:02x}", b[0], b[1], b[2])))
}

/// A uniform 8-digit code from the OS CSPRNG (rejection sampling, no modulo bias).
fn random_nonce() -> Result<Nonce, EngineError> {
    const SPACE: u32 = 100_000_000;
    // Largest multiple of SPACE that fits in a u32.
    const LIMIT: u32 = (u32::MAX / SPACE) * SPACE;
    loop {
        let n = u32::from_le_bytes(random_bytes::<4>()?);
        if n < LIMIT {
            return Ok(Nonce(format!(
                "{:0width$}",
                n % SPACE,
                width = NONCE_DIGITS
            )));
        }
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    fn tmp_data(tag: &str) -> DataDir {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        DataDir {
            path: std::env::temp_dir().join(format!(
                "safe_ai_skill_confirm_{tag}_{}_{nanos}",
                std::process::id()
            )),
            trusted: true,
        }
    }

    fn grant_id(dir: &DataDir) -> PendingId {
        create_pending(
            dir,
            PendingKind::Grant,
            "transfer up to 1 SOL for 1h",
            json!({"scope": "transfer", "budget_sol": 1.0}),
        )
        .unwrap()
    }

    /// Create an entry and announce it, returning the code the user would see.
    pub(crate) fn announced(dir: &DataDir, kind: PendingKind, payload: Value) -> Nonce {
        let id = create_pending(dir, kind, "summary", payload).unwrap();
        announce_pending(dir, now_secs())
            .into_iter()
            .find(|a| a.id == id)
            .map(|a| a.code)
            .expect("announced")
    }

    fn grant(dir: &DataDir) -> Nonce {
        announced(
            dir,
            PendingKind::Grant,
            json!({"scope": "transfer", "budget_sol": 1.0}),
        )
    }

    fn confirm_line(n: &Nonce) -> String {
        format!("safe-ai-skill confirm {n}")
    }

    fn other_code(n: &Nonce) -> String {
        if n.as_str() == "00000000" {
            "00000001".into()
        } else {
            "00000000".into()
        }
    }

    #[test]
    fn create_makes_no_code_and_stores_no_code() {
        let dir = tmp_data("nocode");
        let id = grant_id(&dir);
        assert!(
            id.as_str().starts_with('r') && id.as_str().len() == 7,
            "{id}"
        );
        let text = std::fs::read_to_string(dir.path.join(PENDING_FILE)).unwrap();
        assert!(text.contains("\"code_hash\":null"), "{text}");
        // Unannounced: nothing confirms, whatever is typed.
        assert!(matches!(
            confirm_attempt(&dir, "safe-ai-skill confirm 12345678", now_secs()),
            Attempt::Wrong { .. }
        ));
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn announce_stores_only_a_hash_and_announces_once() {
        let dir = tmp_data("hash");
        grant_id(&dir);
        let first = announce_pending(&dir, now_secs());
        assert_eq!(first.len(), 1);
        let code = first[0].code.clone();
        assert!(is_nonce(code.as_str()));
        let text = std::fs::read_to_string(dir.path.join(PENDING_FILE)).unwrap();
        assert!(!text.contains(code.as_str()), "{text}");
        assert!(announce_pending(&dir, now_secs()).is_empty());
        let msg = announcement_message(&first).unwrap();
        assert!(msg.contains(code.as_str()) && msg.contains(first[0].id.as_str()));
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn announce_without_pending_creates_nothing() {
        let dir = tmp_data("noannounce");
        assert!(announce_pending(&dir, 1).is_empty());
        assert!(!dir.path.exists());
    }

    #[test]
    fn confirm_returns_the_entry_once() {
        let dir = tmp_data("once");
        let n = grant(&dir);
        let got = confirm_from_prompt(&dir, &confirm_line(&n), now_secs()).unwrap();
        assert_eq!(got.kind, PendingKind::Grant);
        assert_eq!(got.payload, json!({"scope": "transfer", "budget_sol": 1.0}));
        assert_eq!(
            confirm_from_prompt(&dir, &confirm_line(&n), now_secs()),
            None
        );
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn code_expires_after_ttl_from_announcement() {
        let dir = tmp_data("ttl");
        let n = grant(&dir);
        let late = now_secs() + TTL_SECS + 2;
        assert_eq!(confirm_from_prompt(&dir, &confirm_line(&n), late), None);
        assert_eq!(
            confirm_from_prompt(&dir, &confirm_line(&n), now_secs()),
            None
        );
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn three_wrong_codes_cancel_everything() {
        let dir = tmp_data("lockout");
        let a = grant(&dir);
        let b = grant(&dir);
        let now = now_secs();
        let wrong = format!("safe-ai-skill confirm {}", other_code(&a));
        assert_eq!(
            confirm_attempt(&dir, &wrong, now),
            Attempt::Wrong { remaining: 2 }
        );
        assert_eq!(
            confirm_attempt(&dir, "safe-ai-skill confirm nope", now),
            Attempt::Wrong { remaining: 1 }
        );
        assert_eq!(confirm_attempt(&dir, &wrong, now), Attempt::LockedOut);
        for n in [&a, &b] {
            assert_eq!(confirm_from_prompt(&dir, &confirm_line(n), now), None);
        }
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn a_right_code_resets_the_failure_count() {
        let dir = tmp_data("reset");
        let a = grant(&dir);
        let b = grant(&dir);
        let now = now_secs();
        let wrong = format!("safe-ai-skill confirm {}", other_code(&a));
        confirm_attempt(&dir, &wrong, now);
        confirm_attempt(&dir, &wrong, now);
        assert!(confirm_from_prompt(&dir, &confirm_line(&a), now).is_some());
        assert_eq!(
            confirm_attempt(&dir, &wrong, now),
            Attempt::Wrong { remaining: 2 }
        );
        assert!(confirm_from_prompt(&dir, &confirm_line(&b), now).is_some());
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn prompt_forms_share_one_whitespace_rule() {
        assert_eq!(classify("deploy it"), PromptForm::NotAConfirm);
        assert_eq!(
            classify("safe-ai-skill confirmation?"),
            PromptForm::NotAConfirm
        );
        assert_eq!(
            classify("please safe-ai-skill confirm 1"),
            PromptForm::NotAConfirm
        );
        assert_eq!(
            classify("  safe-ai-skill\tconfirm   12345678 \n"),
            PromptForm::Line("12345678")
        );
        assert_eq!(classify("safe-ai-skill confirm"), PromptForm::Line(""));
        assert_eq!(classify("safe-ai-skill confirm 1 2"), PromptForm::Line(""));
        assert_eq!(
            classify("look:\nsafe-ai-skill confirm 12345678"),
            PromptForm::Embedded
        );
    }

    #[test]
    fn embedded_lines_are_not_counted_or_consumed() {
        let dir = tmp_data("embedded");
        let n = grant(&dir);
        let now = now_secs();
        for _ in 0..5 {
            assert_eq!(
                confirm_attempt(&dir, &format!("ok\n{}\nthanks", confirm_line(&n)), now),
                Attempt::Embedded
            );
        }
        assert!(confirm_from_prompt(&dir, &confirm_line(&n), now).is_some());
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn near_misses_do_not_confirm() {
        let dir = tmp_data("exact");
        let n = grant(&dir);
        let now = now_secs();
        for prompt in [
            format!("safe-ai-skill confirm {n}0"),
            format!("safe-ai-skill confirm `{n}`"),
            format!("safe-ai-skill confirm {n} now"),
        ] {
            assert_eq!(confirm_from_prompt(&dir, &prompt, now), None, "{prompt:?}");
        }
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn tampered_or_hand_written_pending_confirms_nothing() {
        let dir = tmp_data("tampered");
        let n = grant(&dir);
        let p = dir.path.join(PENDING_FILE);
        let mut v: Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        v["body"]["entries"][0]["summary"] = "something else".into();
        std::fs::write(&p, serde_json::to_vec(&v).unwrap()).unwrap();
        assert_eq!(
            confirm_from_prompt(&dir, &confirm_line(&n), now_secs()),
            None
        );
        let _ = std::fs::remove_dir_all(&dir.path);

        let forged = tmp_data("forged");
        std::fs::create_dir_all(&forged.path).unwrap();
        std::fs::write(
            forged.path.join(PENDING_FILE),
            r#"{"entries":[{"id":"r000000","kind":"grant","summary":"s","payload":{},"created_at":0,"announced_at":0,"code_hash":null}],"failures":0}"#,
        )
        .unwrap();
        assert_eq!(
            confirm_from_prompt(&forged, "safe-ai-skill confirm 12345678", 1),
            None
        );
        let _ = std::fs::remove_dir_all(&forged.path);
    }

    #[test]
    fn code_is_only_read_from_the_user_prompt_submit_prompt() {
        let line = "safe-ai-skill confirm 12345678";
        for event in [
            "PreToolUse",
            "PostToolUse",
            "SessionStart",
            "UserPromptExpansion",
        ] {
            let other =
                HookInput::parse(&json!({ "hook_event_name": event, "prompt": line }).to_string());
            assert_eq!(user_prompt(&other), None, "{event}");
        }
        assert_eq!(
            user_prompt(&HookInput::parse(&json!({ "prompt": line }).to_string())),
            None
        );
        let real = HookInput::parse(
            &json!({ "hook_event_name": "UserPromptSubmit", "prompt": line }).to_string(),
        );
        assert_eq!(user_prompt(&real), Some(line));
    }

    #[test]
    fn pending_entries_are_capped_dropping_the_oldest() {
        let dir = tmp_data("cap");
        let ids: Vec<PendingId> = (0..MAX_PENDING + 8).map(|_| grant_id(&dir)).collect();
        let shown: Vec<PendingId> = announce_pending(&dir, now_secs())
            .into_iter()
            .map(|a| a.id)
            .collect();
        assert_eq!(shown, ids[8..].to_vec());
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn concurrent_creates_lose_no_entry() {
        let dir = tmp_data("concurrent");
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let dir = dir.clone();
                // Each create fsyncs under the lock; under a loaded parallel test run the lock
                // wait can lapse, which is not what this test is about: retry on busy.
                let create = move || loop {
                    match create_pending(&dir, PendingKind::Grant, "s", json!(null)) {
                        Ok(n) => break n,
                        Err(e) if e.to_string().contains("busy") => continue,
                        Err(e) => panic!("{e}"),
                    }
                };
                std::thread::spawn(move || (0..4).map(|_| create()).collect::<Vec<_>>())
            })
            .collect();
        let mut ids: Vec<PendingId> = handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect();
        assert_eq!(ids.len(), MAX_PENDING);
        let mut shown: Vec<PendingId> = announce_pending(&dir, now_secs())
            .into_iter()
            .map(|a| a.id)
            .collect();
        ids.sort_by(|a, b| a.0.cmp(&b.0));
        shown.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(ids, shown);
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[cfg(unix)]
    #[test]
    fn fifo_lock_is_refused_without_hanging() {
        let dir = tmp_data("lockfifo");
        let n = grant(&dir);
        std::fs::remove_file(dir.path.join(LOCK_FILE)).unwrap();
        crate::statefile::tests::mkfifo(&dir.path.join(LOCK_FILE));
        assert!(create_pending(&dir, PendingKind::Mode, "m", json!(null)).is_err());
        assert_eq!(
            confirm_from_prompt(&dir, &confirm_line(&n), now_secs()),
            None
        );
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn several_pending_entries_are_independent() {
        let dir = tmp_data("several");
        let a = grant(&dir);
        let b = announced(&dir, PendingKind::Mode, json!("autopilot"));
        assert_ne!(a, b);
        let now = now_secs();
        assert_eq!(
            confirm_from_prompt(&dir, &confirm_line(&b), now).map(|c| c.kind),
            Some(PendingKind::Mode)
        );
        assert_eq!(
            confirm_from_prompt(&dir, &confirm_line(&a), now).map(|c| c.kind),
            Some(PendingKind::Grant)
        );
        let _ = std::fs::remove_dir_all(&dir.path);
    }
}
