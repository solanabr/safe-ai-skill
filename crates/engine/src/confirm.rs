//! Prompt-nonce confirmation for relaxing actions (spec D4.1).
//!
//! `allow`, `mode <looser>`, `verify trust` and `verify approve` do not take effect when run:
//! they call [`create_pending`], which stores a pending entry under a fresh 8-digit nonce
//! (OS CSPRNG) in the authenticated `pending.json`, and print the nonce with a summary. The
//! entry activates only when the user's own next prompt contains
//! `safe-ai-skill confirm <nonce>`: the `UserPromptSubmit` hook passes the prompt to
//! [`confirm_from_prompt`], which consumes the entry (single use) and returns it.
//!
//! The model cannot author a user prompt, so the nonce must only ever be read from the
//! `UserPromptSubmit` payload's `prompt` field — use [`user_prompt`] to extract it. Tool
//! input, tool output, transcripts and every other payload field are model-influenced and
//! must never reach [`confirm_from_prompt`].
//!
//! The confirmation echo (the entry's summary) must reach the user through the hook's
//! `systemMessage`, not only `additionalContext`, so the person who typed the nonce sees what
//! they approved (spec D4.1).
//!
//! ## Guessing
//!
//! A nonce is 8 uniform digits (10^8 values). The model cannot submit a prompt, so it cannot
//! try nonces; the only way to confirm an entry the user did not mean to is for the user to
//! type a matching line themselves. With at most [`MAX_PENDING`] live entries, each
//! single-use and expiring after [`TTL_SECS`], an arbitrary 8-digit line in a prompt hits one
//! with probability at most 32 in 10^8. The nonce is not a secret against anyone who can read
//! the terminal or `pending.json`; it binds the confirmation to a human prompt.
//!
//! Every read-modify-write of `pending.json` holds an exclusive lock on `pending.lock` in the
//! data dir (`flock` on unix; an `O_EXCL` lock file with a 10 s stale timeout elsewhere).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::datadir::DataDir;
use crate::error::{EngineError, Error};
use crate::io::HookInput;
use crate::statefile::{self, Loaded};

/// State file holding the pending entries.
pub const PENDING_FILE: &str = "pending.json";

/// Seconds a pending entry stays confirmable.
pub const TTL_SECS: u64 = 600;

/// Digits in a nonce.
const NONCE_DIGITS: usize = 8;

/// Most pending entries kept; creating one more drops the oldest.
pub const MAX_PENDING: usize = 32;

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

/// A confirmation nonce: [`NONCE_DIGITS`] ASCII digits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// A pending entry the user confirmed; the caller now performs it.
#[derive(Debug, Clone, PartialEq)]
pub struct Confirmed {
    /// What to do.
    pub kind: PendingKind,
    /// The human summary printed when the entry was created (echo it back to the user).
    pub summary: String,
    /// The action's parameters, as given to [`create_pending`].
    pub payload: Value,
}

/// One stored pending entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Entry {
    nonce: Nonce,
    kind: PendingKind,
    summary: String,
    payload: Value,
    created_at: u64,
}

/// The `pending.json` body.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
struct Pending {
    entries: Vec<Entry>,
}

/// Store a pending entry and return its nonce. Expired entries are pruned; a tampered
/// `pending.json` is discarded (none of its entries could be confirmed anyway).
pub fn create_pending(
    dir: &DataDir,
    kind: PendingKind,
    summary: &str,
    payload: Value,
) -> Result<Nonce, EngineError> {
    statefile::create_dir_private(&dir.path)?;
    let _lock = PendingLock::acquire(dir)?;
    // Read the clock under the lock: an earlier reading would prune entries stamped by
    // whoever held the lock meanwhile as "from the future".
    let now = now_secs();
    let mut pending = match statefile::load::<Pending>(dir, PENDING_FILE) {
        Loaded::Valid(p) => p,
        Loaded::Missing | Loaded::Tampered => Pending::default(),
    };
    pending.entries.retain(|e| !is_expired(e, now));
    let nonce = loop {
        let n = random_nonce()?;
        if !pending.entries.iter().any(|e| e.nonce == n) {
            break n;
        }
    };
    pending.entries.push(Entry {
        nonce: nonce.clone(),
        kind,
        summary: summary.to_string(),
        payload,
        created_at: now,
    });
    let excess = pending.entries.len().saturating_sub(MAX_PENDING);
    pending.entries.drain(..excess);
    statefile::store(dir, PENDING_FILE, &pending)?;
    Ok(nonce)
}

/// Confirm the pending entry named by a line of `prompt` that, trimmed, is exactly
/// `safe-ai-skill confirm <nonce>`, consuming it.
///
/// `prompt` MUST be the `UserPromptSubmit` payload's `prompt` field (see [`user_prompt`]).
/// `None` when no live entry matches, `pending.json` is missing or tampered, or the
/// consumption cannot be persisted (an entry that could be replayed is never confirmed). An
/// entry is live while `now - created_at <= TTL_SECS`; one stamped in the future is not.
pub fn confirm_from_prompt(dir: &DataDir, prompt: &str, now: u64) -> Option<Confirmed> {
    let candidates = nonces_in(prompt);
    if candidates.is_empty() {
        return None;
    }
    let _lock = PendingLock::acquire(dir).ok()?;
    let Loaded::Valid(mut pending) = statefile::load::<Pending>(dir, PENDING_FILE) else {
        return None;
    };
    let before = pending.entries.len();
    // Prune only the expired: an entry stamped after `now` (created while the caller waited)
    // is kept, just not confirmable by this call.
    pending.entries.retain(|e| !is_expired(e, now));
    let hit = candidates.iter().find_map(|c| {
        pending
            .entries
            .iter()
            .position(|e| e.nonce.as_str() == *c && is_live(e, now))
    });
    let Some(i) = hit else {
        if pending.entries.len() != before {
            let _ = statefile::store(dir, PENDING_FILE, &pending);
        }
        return None;
    };
    let entry = pending.entries.remove(i);
    statefile::store(dir, PENDING_FILE, &pending).ok()?;
    Some(Confirmed {
        kind: entry.kind,
        summary: entry.summary,
        payload: entry.payload,
    })
}

/// The prompt of a `UserPromptSubmit` payload; `None` for any other event. This is the only
/// payload text [`confirm_from_prompt`] may be given.
pub fn user_prompt(input: &HookInput) -> Option<&str> {
    if input.hook_event_name.as_deref() != Some("UserPromptSubmit") {
        return None;
    }
    input.prompt.as_deref()
}

/// The nonce of every line that, trimmed, is exactly `safe-ai-skill confirm <nonce>`.
fn nonces_in(prompt: &str) -> Vec<&str> {
    prompt
        .lines()
        .filter_map(|line| line.trim().strip_prefix("safe-ai-skill confirm "))
        .filter(|n| is_nonce(n))
        .collect()
}

/// Lock file guarding `pending.json`.
const LOCK_FILE: &str = "pending.lock";

/// How long to wait for the pending lock before giving up.
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// An exclusive lock on [`LOCK_FILE`], released on drop.
struct PendingLock {
    #[cfg(unix)]
    _file: std::fs::File,
    #[cfg(not(unix))]
    path: std::path::PathBuf,
}

impl PendingLock {
    /// `flock(LOCK_EX)` on the lock file, retried for [`LOCK_WAIT`]. The kernel drops the
    /// lock when the process exits, so a crash leaves no stale lock.
    #[cfg(unix)]
    fn acquire(dir: &DataDir) -> Result<PendingLock, EngineError> {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::io::AsRawFd;
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(dir.path.join(LOCK_FILE))?;
        let deadline = std::time::Instant::now() + LOCK_WAIT;
        loop {
            // SAFETY: the fd is open for the lifetime of `file`.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(PendingLock { _file: file });
            }
            if std::time::Instant::now() >= deadline {
                return Err(Error::Other("pending lock is busy".to_string()));
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    /// An `O_EXCL` lock file, removed on drop; one older than 10 s is taken as stale.
    #[cfg(not(unix))]
    fn acquire(dir: &DataDir) -> Result<PendingLock, EngineError> {
        let path = dir.path.join(LOCK_FILE);
        let deadline = std::time::Instant::now() + LOCK_WAIT;
        loop {
            match statefile::open_new_private(&path) {
                Ok(_) => return Ok(PendingLock { path }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let stale = std::fs::metadata(&path)
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|m| m.elapsed().ok())
                        .is_some_and(|age| age.as_secs() > 10);
                    if stale {
                        let _ = std::fs::remove_file(&path);
                        continue;
                    }
                }
                Err(e) => return Err(e.into()),
            }
            if std::time::Instant::now() >= deadline {
                return Err(Error::Other("pending lock is busy".to_string()));
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
}

#[cfg(not(unix))]
impl Drop for PendingLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn is_nonce(s: &str) -> bool {
    s.len() == NONCE_DIGITS && s.bytes().all(|b| b.is_ascii_digit())
}

/// Older than [`TTL_SECS`] at `now`.
fn is_expired(e: &Entry, now: u64) -> bool {
    now.saturating_sub(e.created_at) > TTL_SECS
}

/// Confirmable at `now`: not expired and not stamped in the future.
fn is_live(e: &Entry, now: u64) -> bool {
    e.created_at <= now && now - e.created_at <= TTL_SECS
}

/// A uniform 8-digit nonce from the OS CSPRNG (rejection sampling, no modulo bias).
fn random_nonce() -> Result<Nonce, EngineError> {
    const SPACE: u32 = 100_000_000;
    // Largest multiple of SPACE that fits in a u32.
    const LIMIT: u32 = (u32::MAX / SPACE) * SPACE;
    loop {
        let mut buf = [0u8; 4];
        rand_core::RngCore::try_fill_bytes(&mut rand_core::OsRng, &mut buf)
            .map_err(|e| Error::Other(format!("OS random source: {e}")))?;
        let n = u32::from_le_bytes(buf);
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
mod tests {
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

    fn grant(dir: &DataDir) -> Nonce {
        create_pending(
            dir,
            PendingKind::Grant,
            "transfer up to 1 SOL for 1h",
            json!({"scope": "transfer", "budget_sol": 1.0}),
        )
        .unwrap()
    }

    fn confirm_line(n: &Nonce) -> String {
        format!("safe-ai-skill confirm {n}")
    }

    #[test]
    fn nonce_is_eight_digits() {
        let dir = tmp_data("digits");
        let n = grant(&dir);
        assert!(is_nonce(n.as_str()), "{n}");
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn confirm_returns_the_entry_once() {
        let dir = tmp_data("once");
        let n = grant(&dir);
        let got = confirm_from_prompt(&dir, &confirm_line(&n), now_secs()).unwrap();
        assert_eq!(got.kind, PendingKind::Grant);
        assert_eq!(got.summary, "transfer up to 1 SOL for 1h");
        assert_eq!(got.payload, json!({"scope": "transfer", "budget_sol": 1.0}));
        // Single use.
        assert_eq!(
            confirm_from_prompt(&dir, &confirm_line(&n), now_secs()),
            None
        );
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn confirm_inside_a_longer_prompt_matches() {
        let dir = tmp_data("longer");
        let n = grant(&dir);
        let prompt = format!("ok go ahead\nsafe-ai-skill confirm {n}\nthanks");
        assert!(confirm_from_prompt(&dir, &prompt, now_secs()).is_some());
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn nonce_expires_after_ttl() {
        let dir = tmp_data("ttl");
        let n = grant(&dir);
        let late = now_secs() + TTL_SECS + 2;
        assert_eq!(confirm_from_prompt(&dir, &confirm_line(&n), late), None);
        // And the expired entry is gone, not merely skipped.
        assert_eq!(
            confirm_from_prompt(&dir, &confirm_line(&n), now_secs()),
            None
        );
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn entry_from_the_future_is_not_live() {
        let dir = tmp_data("future");
        let n = grant(&dir);
        assert_eq!(confirm_from_prompt(&dir, &confirm_line(&n), 1), None);
        // Seen from a stale clock it is skipped, not pruned: it confirms at the real time.
        assert!(confirm_from_prompt(&dir, &confirm_line(&n), now_secs()).is_some());
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn only_the_exact_form_matches() {
        let dir = tmp_data("exact");
        let n = grant(&dir);
        let now = now_secs();
        for prompt in [
            format!("safe-ai-skill confirm {n}0"),
            format!("safe-ai-skill confirm x{n}"),
            format!("safe-ai-skill confirm `{n}`"),
            format!("`safe-ai-skill confirm {n}`"),
            format!("safe-ai-skill confirm: {n}"),
            format!("safe-ai-skill-confirm {n}"),
            format!("/safe-ai-skill confirm {n}"),
            format!("confirm {n}"),
            format!("please safe-ai-skill confirm {n}"),
            format!("safe-ai-skill confirm {n} now"),
            format!("safe-ai-skill  confirm {n}"),
            format!("safe-ai-skill confirm\n{n}"),
            n.to_string(),
        ] {
            assert_eq!(confirm_from_prompt(&dir, &prompt, now), None, "{prompt:?}");
        }
        // Still pending after all the near misses.
        assert!(confirm_from_prompt(&dir, &confirm_line(&n), now).is_some());
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn wrong_nonce_leaves_the_entry_pending() {
        let dir = tmp_data("wrong");
        let n = grant(&dir);
        let other = if n.as_str() == "00000000" {
            "00000001"
        } else {
            "00000000"
        };
        let now = now_secs();
        assert_eq!(
            confirm_from_prompt(&dir, &format!("safe-ai-skill confirm {other}"), now),
            None
        );
        assert!(confirm_from_prompt(&dir, &confirm_line(&n), now).is_some());
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn tampered_pending_file_confirms_nothing() {
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
    }

    #[test]
    fn hand_written_pending_entry_is_rejected() {
        // The model writes its own pending.json (no MAC): nothing confirms.
        let dir = tmp_data("forged");
        std::fs::create_dir_all(&dir.path).unwrap();
        std::fs::write(
            dir.path.join(PENDING_FILE),
            r#"{"entries":[{"nonce":"12345678","kind":"grant","summary":"s","payload":{},"created_at":0}]}"#,
        )
        .unwrap();
        assert_eq!(
            confirm_from_prompt(&dir, "safe-ai-skill confirm 12345678", 1),
            None
        );
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn nonce_is_only_read_from_the_user_prompt_submit_prompt() {
        let dir = tmp_data("payload");
        let n = grant(&dir);
        let line = confirm_line(&n);
        let now = now_secs();

        // The nonce sits in every field except `prompt`: nothing confirms.
        let elsewhere = HookInput::parse(
            &json!({
                "hook_event_name": "UserPromptSubmit",
                "session_id": line,
                "cwd": line,
                "tool_input": {"command": line},
                "tool_output": line,
                "source": line,
                "transcript_path": line,
                "prompt": "continue please",
            })
            .to_string(),
        );
        let prompt = user_prompt(&elsewhere).unwrap();
        assert_eq!(confirm_from_prompt(&dir, prompt, now), None);

        // The right text in `prompt` of another event is not a user prompt.
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
        let unnamed = HookInput::parse(&json!({ "prompt": line }).to_string());
        assert_eq!(user_prompt(&unnamed), None);

        // The genuine article.
        let real = HookInput::parse(
            &json!({ "hook_event_name": "UserPromptSubmit", "prompt": line }).to_string(),
        );
        assert!(confirm_from_prompt(&dir, user_prompt(&real).unwrap(), now).is_some());
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn a_trimmed_line_matches() {
        let dir = tmp_data("trimmed");
        let n = grant(&dir);
        let prompt = format!("yes\r\n   safe-ai-skill confirm {n}\t\r\nthanks");
        assert!(confirm_from_prompt(&dir, &prompt, now_secs()).is_some());
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn pending_entries_are_capped_dropping_the_oldest() {
        let dir = tmp_data("cap");
        let nonces: Vec<Nonce> = (0..MAX_PENDING + 8).map(|_| grant(&dir)).collect();
        let now = now_secs();
        for n in &nonces[..8] {
            assert_eq!(
                confirm_from_prompt(&dir, &confirm_line(n), now),
                None,
                "{n}"
            );
        }
        for n in &nonces[8..] {
            assert!(
                confirm_from_prompt(&dir, &confirm_line(n), now).is_some(),
                "{n}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn concurrent_creates_lose_no_entry() {
        let dir = tmp_data("concurrent");
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let dir = dir.clone();
                std::thread::spawn(move || (0..4).map(|_| grant(&dir)).collect::<Vec<_>>())
            })
            .collect();
        let nonces: Vec<Nonce> = handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect();
        assert_eq!(nonces.len(), MAX_PENDING);
        let now = now_secs();
        for n in &nonces {
            assert!(
                confirm_from_prompt(&dir, &confirm_line(n), now).is_some(),
                "{n}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn several_pending_entries_are_independent() {
        let dir = tmp_data("several");
        let a = grant(&dir);
        let b = create_pending(
            &dir,
            PendingKind::Mode,
            "mode autopilot",
            json!("autopilot"),
        )
        .unwrap();
        assert_ne!(a, b);
        let now = now_secs();
        let got = confirm_from_prompt(&dir, &confirm_line(&b), now).unwrap();
        assert_eq!(got.kind, PendingKind::Mode);
        assert_eq!(
            confirm_from_prompt(&dir, &confirm_line(&a), now).map(|c| c.kind),
            Some(PendingKind::Grant)
        );
        let _ = std::fs::remove_dir_all(&dir.path);
    }
}
