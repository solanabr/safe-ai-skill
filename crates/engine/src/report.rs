//! Session report: what the firewall did in one session (informational; never blocks).
//!
//! - **SessionStart** ([`session_start`]): writes a start marker for the session
//!   (`reports/<sid>.start.json`: start time, project hash, spend-ledger and grant-budget snapshot)
//!   and returns a one-line recap of the previous session in this project when it had any deny
//!   or ask, once. Silent otherwise.
//! - **SessionEnd** ([`session_end`]): reads this session's lines from `audit.jsonl` (tail
//!   first, stopping at the session's start), diffs the spend ledger and grant budgets against
//!   the start marker, and writes `reports/<sid>.json` (with a one-line `summary`) plus the
//!   per-project pointer `reports/last-<project hash>.json` the next recap reads.
//!
//! Nothing here runs on the gate hot path, and nothing new is tracked there: the sources are
//! the audit log, the spend ledger and `grants.json`, read without repairing anything. Claude
//! Code discards a SessionEnd hook's output and gives SessionEnd hooks a 1.5 s budget that a
//! plugin hook's `timeout` cannot raise (hooks reference, "SessionEnd"), so the end path is
//! bounded in bytes and wall time and prints nothing.
//!
//! Limits: the audit log does not tell a grant-relaxed allow from a natural one, so "grants
//! used" is the grants whose spent budget rose during the session (value scopes only). The
//! spend ledger and grant budgets are global, so a concurrent session's spend lands in the
//! delta too. A session that never reaches SessionEnd (killed) gets no report.

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::datadir::DataDir;
use crate::grants::{self, Grants};
use crate::spend::{SpendLedger, EXHAUSTED_SOL, SPEND_FILE};
use crate::statefile::{self, Loaded};

/// Directory under the data dir holding reports and start markers.
pub const REPORTS_DIR: &str = "reports";
/// Report schema version.
pub const SCHEMA: u32 = 1;

/// Most audit bytes read back from the end of the log.
const MAX_SCAN_BYTES: u64 = 16 << 20;
/// Read chunk for the backward scan.
const CHUNK: u64 = 64 << 10;
/// Wall-time budget for the scan (SessionEnd hooks get 1.5 s in all).
const SCAN_BUDGET: Duration = Duration::from_millis(600);
/// Without a start marker, how far back the scan looks.
const NO_MARKER_WINDOW_SECS: u64 = 86_400;
/// Audit lines from parallel hooks are not strictly ordered: scan a little past the start.
const CLOCK_SLACK_SECS: u64 = 300;
/// Reasons listed in a report.
const TOP_REASONS: usize = 3;
/// Characters kept of each reason.
const REASON_CHARS: usize = 200;
/// Session reports kept; older ones are pruned at SessionEnd.
const MAX_REPORTS: usize = 200;
/// Start markers older than this are pruned at SessionEnd.
const MARKER_MAX_AGE_SECS: u64 = 30 * 86_400;
/// Classes named in the one-line summary and recap.
const CLASSES_IN_LINE: usize = 3;

/// What SessionStart records for the session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StartMarker {
    /// Epoch seconds the session first started.
    pub started_at: u64,
    /// Hash of the project root the session ran in ([`project_key`]).
    pub project: String,
    /// The spend ledger at start: `(epoch day, total SOL)`; `None` when not authenticated.
    pub spend: Option<(u64, f64)>,
    /// Spent budget per grant id at start (authenticated `grants.json` only).
    pub grants_spent: BTreeMap<String, f64>,
}

/// One reason with how often it came up.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReasonCount {
    /// `deny` or `ask`.
    pub decision: String,
    /// Gate class (the audit classification).
    pub class: String,
    /// The reason, redacted and shortened.
    pub reason: String,
    /// Occurrences.
    pub count: u64,
}

/// A grant whose budget was drawn on during the session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GrantUse {
    /// Grant id.
    pub id: String,
    /// Grant scope label.
    pub scope: String,
    /// SOL drawn from its budget this session.
    pub sol: f64,
}

/// Spend recorded on the daily ledger.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpendSummary {
    /// SOL added to the ledger since the session started (same UTC day only).
    pub session_sol: Option<f64>,
    /// The ledger's total for today.
    pub today_sol: f64,
}

/// The per-session report (`reports/<sid>.json`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionReport {
    /// [`SCHEMA`].
    pub schema: u32,
    /// Session id.
    pub session_id: String,
    /// Hash of the project root ([`project_key`]).
    pub project: String,
    /// SessionEnd `reason` (`clear`, `resume`, `logout`, `prompt_input_exit`, `other`).
    pub end_reason: String,
    /// Start (from the marker), when known.
    pub started_at: Option<u64>,
    /// End, epoch seconds.
    pub ended_at: u64,
    /// Gate decisions by label (`deny`, `ask`, `allow`, `defer`).
    pub decisions: BTreeMap<String, u64>,
    /// Denies by gate class.
    pub denies: BTreeMap<String, u64>,
    /// Asks by gate class.
    pub asks: BTreeMap<String, u64>,
    /// Most frequent deny/ask reasons.
    pub top_reasons: Vec<ReasonCount>,
    /// Grants drawn on.
    pub grants_used: Vec<GrantUse>,
    /// Grants confirmed during the session window (any session).
    pub grants_confirmed: u64,
    /// Spend on the daily ledger, when any.
    pub spend: Option<SpendSummary>,
    /// The scan hit its byte or time cap before reaching the session start.
    pub truncated: bool,
    /// One line for a human.
    pub summary: String,
    /// The next SessionStart already showed the recap of this report.
    #[serde(default)]
    pub recapped: bool,
}

impl SessionReport {
    /// Denies plus asks.
    pub fn flagged(&self) -> u64 {
        self.denies.values().sum::<u64>() + self.asks.values().sum::<u64>()
    }
}

/// SessionStart: record the start marker (first start only) and return the recap line of the
/// previous session in this project, if it had any deny or ask and was not recapped yet.
pub fn session_start(dir: &DataDir, session_id: &str, cwd: &Path, now: u64) -> Option<String> {
    if dir.is_unresolved() {
        return None;
    }
    let reports = dir.path.join(REPORTS_DIR);
    let project = project_key(cwd);
    let sid = safe_id(session_id);
    if statefile::create_dir_private(&reports).is_ok() {
        let marker_path = reports.join(format!("{sid}.start.json"));
        if std::fs::symlink_metadata(&marker_path).is_err() {
            let marker = StartMarker {
                started_at: now,
                project: project.clone(),
                spend: ledger_snapshot(dir, now),
                grants_spent: grants_snapshot(dir),
            };
            if let Ok(bytes) = serde_json::to_vec(&marker) {
                if let Ok(mut f) = statefile::open_new_private(&marker_path) {
                    let _ = f.write_all(&bytes);
                }
            }
        }
    }
    recap(dir, &project, &sid, now)
}

/// The recap line for `project`, marking the pointer recapped. `None` when there is no previous
/// report, it is this session's, it was shown already, or it had no deny or ask.
fn recap(dir: &DataDir, project: &str, sid: &str, now: u64) -> Option<String> {
    let pointer = dir
        .path
        .join(REPORTS_DIR)
        .join(format!("last-{}.json", project_hash(project)));
    let bytes = read_small(&pointer)?;
    let mut last: SessionReport = serde_json::from_slice(&bytes).ok()?;
    if last.recapped || last.session_id == sid || last.project != project || last.flagged() == 0 {
        return None;
    }
    last.recapped = true;
    if let Ok(bytes) = serde_json::to_vec_pretty(&last) {
        let _ = write_atomic(&dir.path.join(REPORTS_DIR), &file_name(&pointer), &bytes);
    }
    let ago = ago(now.saturating_sub(last.ended_at));
    let report = dir
        .path
        .join(REPORTS_DIR)
        .join(format!("{}.json", safe_id(&last.session_id)));
    Some(format!(
        "safe-ai-skill: last session in this project ({ago} ago): {}; report: {}.",
        counts_phrase(&last),
        report.display()
    ))
}

/// SessionEnd from the raw hook payload (`session_id`, `cwd`, `reason`). Writes the report and
/// the project pointer; returns the report (for tests and a CLI), `None` when the data dir is
/// unresolved. Never fails the hook: every error is swallowed.
pub fn session_end(dir: &DataDir, raw: &[u8], now: u64) -> Option<SessionReport> {
    if dir.is_unresolved() {
        return None;
    }
    let payload: Value = serde_json::from_slice(raw).unwrap_or(Value::Null);
    let field = |k: &str| payload.get(k).and_then(Value::as_str).unwrap_or("");
    let cwd = match field("cwd") {
        "" => std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        c => PathBuf::from(c),
    };
    let report = build(dir, field("session_id"), &cwd, field("reason"), now);
    let reports = dir.path.join(REPORTS_DIR);
    if statefile::create_dir_private(&reports).is_ok() {
        if let Ok(bytes) = serde_json::to_vec_pretty(&report) {
            let sid = safe_id(&report.session_id);
            let _ = write_atomic(&reports, &format!("{sid}.json"), &bytes);
            let pointer = format!("last-{}.json", project_hash(&report.project));
            let _ = write_atomic(&reports, &pointer, &bytes);
        }
        prune(&reports, now);
    }
    Some(report)
}

/// Build the report for `session_id` without writing it.
pub fn build(
    dir: &DataDir,
    session_id: &str,
    cwd: &Path,
    end_reason: &str,
    now: u64,
) -> SessionReport {
    let sid = safe_id(session_id);
    let marker: Option<StartMarker> =
        read_small(&dir.path.join(REPORTS_DIR).join(format!("{sid}.start.json")))
            .and_then(|b| serde_json::from_slice(&b).ok());
    let project = marker
        .as_ref()
        .map(|m| m.project.clone())
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| project_key(cwd));
    let started_at = marker.as_ref().map(|m| m.started_at);
    let cutoff = match started_at {
        Some(s) => s.saturating_sub(CLOCK_SLACK_SECS),
        None => now.saturating_sub(NO_MARKER_WINDOW_SECS),
    };

    let mut report = SessionReport {
        schema: SCHEMA,
        session_id: session_id.to_string(),
        project,
        end_reason: end_reason.to_string(),
        started_at,
        ended_at: now,
        ..SessionReport::default()
    };
    let mut reasons: BTreeMap<(String, String, String), u64> = BTreeMap::new();
    let mine = format!("\"session_id\":{}", json_str(session_id));
    let window = started_at.map(|s| (s, now));
    report.truncated = scan_tail(&dir.path.join("audit.jsonl"), |line| {
        let Some(ts) = leading_ts(line) else {
            return true;
        };
        if ts < cutoff {
            return false;
        }
        let own = !session_id.is_empty() && contains(line, mine.as_bytes());
        let global = contains(line, b"\"session_id\":\"\"");
        if !own && !global {
            return true;
        }
        let Ok(entry) = serde_json::from_slice::<AuditLine>(line) else {
            return true;
        };
        if own {
            tally(&mut report, &mut reasons, entry);
        } else if let Some((start, end)) = window {
            if (start..=end).contains(&ts)
                && entry.classification == "grant_create"
                && entry.decision == "confirmed"
            {
                report.grants_confirmed += 1;
            }
        }
        true
    });

    let mut top: Vec<ReasonCount> = reasons
        .into_iter()
        .map(|((decision, class, reason), count)| ReasonCount {
            decision,
            class,
            reason,
            count,
        })
        .collect();
    top.sort_by_key(|a| std::cmp::Reverse(a.count));
    top.truncate(TOP_REASONS);
    report.top_reasons = top;

    if let Some(m) = &marker {
        report.grants_used = grants_used(dir, &m.grants_spent);
    }
    report.spend = spend_summary(dir, marker.as_ref().and_then(|m| m.spend), now);
    report.summary = summary_line(&report);
    report
}

/// The audit fields the report reads.
#[derive(Deserialize)]
struct AuditLine {
    #[serde(default)]
    classification: String,
    #[serde(default)]
    decision: String,
    #[serde(default)]
    reason: String,
}

fn tally(
    report: &mut SessionReport,
    reasons: &mut BTreeMap<(String, String, String), u64>,
    entry: AuditLine,
) {
    *report.decisions.entry(entry.decision.clone()).or_default() += 1;
    let by_class = match entry.decision.as_str() {
        "deny" => &mut report.denies,
        "ask" => &mut report.asks,
        _ => return,
    };
    *by_class.entry(entry.classification.clone()).or_default() += 1;
    let reason = shorten(&crate::redact::scrub(&entry.reason).unwrap_or(entry.reason));
    *reasons
        .entry((entry.decision, entry.classification, reason))
        .or_default() += 1;
}

/// Grants whose spent budget rose since the start snapshot.
fn grants_used(dir: &DataDir, before: &BTreeMap<String, f64>) -> Vec<GrantUse> {
    let Loaded::Valid(current) = grants::load(dir) else {
        return Vec::new();
    };
    let current: Grants = current;
    current
        .grants
        .iter()
        .filter_map(|g| {
            let was = before.get(&g.id).copied().unwrap_or(0.0);
            let drawn = g.spent_sol - was;
            (drawn.is_finite() && drawn > 0.0).then(|| GrantUse {
                id: g.id.clone(),
                scope: g.scope.label().to_string(),
                sol: drawn,
            })
        })
        .collect()
}

fn spend_summary(dir: &DataDir, start: Option<(u64, f64)>, now: u64) -> Option<SpendSummary> {
    let (day, today) = ledger_snapshot(dir, now)?;
    let session = match start {
        Some((d, before)) if d == day => Some((today - before).max(0.0)),
        _ => None,
    };
    let any = today > 0.0 || session.is_some_and(|s| s > 0.0);
    any.then_some(SpendSummary {
        session_sol: session,
        today_sol: today,
    })
}

/// The authenticated ledger as `(day, total)`, rolled to today; `None` when missing, tampered
/// or exhausted. Read only: nothing is repaired here.
fn ledger_snapshot(dir: &DataDir, now: u64) -> Option<(u64, f64)> {
    let Loaded::Valid(l) = statefile::load::<SpendLedger>(dir, SPEND_FILE) else {
        return None;
    };
    if !l.total_sol.is_finite() || l.total_sol >= EXHAUSTED_SOL || l.total_sol < 0.0 {
        return None;
    }
    let today = now / 86_400;
    Some(if l.day == today {
        (l.day, l.total_sol)
    } else {
        (today, 0.0)
    })
}

fn grants_snapshot(dir: &DataDir) -> BTreeMap<String, f64> {
    match grants::load(dir) {
        Loaded::Valid(g) => {
            let g: Grants = g;
            g.grants
                .into_iter()
                .filter(|g| g.spent_sol.is_finite())
                .map(|g| (g.id, g.spent_sol))
                .collect()
        }
        _ => BTreeMap::new(),
    }
}

/// `2 denied, 1 asked (tamper 2, secret_read 1)`.
fn counts_phrase(r: &SessionReport) -> String {
    let denied: u64 = r.denies.values().sum();
    let asked: u64 = r.asks.values().sum();
    let mut by_class: BTreeMap<&str, u64> = BTreeMap::new();
    for (class, n) in r.denies.iter().chain(r.asks.iter()) {
        *by_class.entry(class.as_str()).or_default() += n;
    }
    let mut classes: Vec<(&str, u64)> = by_class.into_iter().collect();
    classes.sort_by_key(|a| std::cmp::Reverse(a.1));
    let extra = classes.len().saturating_sub(CLASSES_IN_LINE);
    let mut named: Vec<String> = classes
        .iter()
        .take(CLASSES_IN_LINE)
        .map(|(c, n)| format!("{c} {n}"))
        .collect();
    if extra > 0 {
        named.push(format!("{extra} more"));
    }
    format!("{denied} denied, {asked} asked ({})", named.join(", "))
}

fn summary_line(r: &SessionReport) -> String {
    let head = format!("safe-ai-skill session {}", short_id(&r.session_id));
    let mut parts = Vec::new();
    if r.flagged() == 0 {
        parts.push("no denies or asks".to_string());
    } else {
        parts.push(counts_phrase(r));
    }
    if !r.grants_used.is_empty() {
        let sol: f64 = r.grants_used.iter().map(|g| g.sol).sum();
        parts.push(format!(
            "{} grant(s) drawn on for {} SOL",
            r.grants_used.len(),
            round(sol)
        ));
    }
    if r.grants_confirmed > 0 {
        parts.push(format!("{} grant(s) confirmed", r.grants_confirmed));
    }
    if let Some(s) = &r.spend {
        match s.session_sol {
            Some(x) if x > 0.0 => parts.push(format!(
                "{} SOL spent ({} SOL today)",
                round(x),
                round(s.today_sol)
            )),
            _ => parts.push(format!("{} SOL spent today", round(s.today_sol))),
        }
    }
    if r.truncated {
        parts.push("audit scan capped".to_string());
    }
    format!("{head}: {}.", parts.join("; "))
}

/// Walk `path` from the end, one complete line at a time (newest first), until `visit`
/// returns false or the log starts. Returns whether a byte or time cap stopped it first.
fn scan_tail(path: &Path, mut visit: impl FnMut(&[u8]) -> bool) -> bool {
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let Ok(len) = file.metadata().map(|m| m.len()) else {
        return false;
    };
    let deadline = Instant::now() + SCAN_BUDGET;
    let floor = len.saturating_sub(MAX_SCAN_BYTES);
    let mut pos = len;
    let mut carry: Vec<u8> = Vec::new();
    let mut buf: Vec<u8> = Vec::new();
    while pos > floor {
        if Instant::now() > deadline {
            return true;
        }
        let start = pos.saturating_sub(CHUNK).max(floor);
        let n = (pos - start) as usize;
        buf.clear();
        buf.resize(n, 0);
        if file.seek(SeekFrom::Start(start)).is_err() || file.read_exact(&mut buf).is_err() {
            return false;
        }
        buf.extend_from_slice(&carry);
        let at_start = start == 0;
        let (head, body) = if at_start {
            (&buf[..0], &buf[..])
        } else {
            match buf.iter().position(|&b| b == b'\n') {
                Some(i) => (&buf[..i], &buf[i + 1..]),
                None => (&buf[..], &buf[..0]),
            }
        };
        for line in body.rsplit(|&b| b == b'\n') {
            if line.is_empty() {
                continue;
            }
            if !visit(line) {
                return false;
            }
        }
        carry = head.to_vec();
        pos = start;
    }
    // The cap cut a line in two: anything left was not seen.
    floor > 0
}

/// `ts` from a line that starts `{"ts":<digits>` (the audit entry's first field).
fn leading_ts(line: &[u8]) -> Option<u64> {
    let rest = line.strip_prefix(b"{\"ts\":")?;
    let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
    std::str::from_utf8(&rest[..digits]).ok()?.parse().ok()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

fn json_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_default()
}

/// Remove start markers older than [`MARKER_MAX_AGE_SECS`] and all but the newest
/// [`MAX_REPORTS`] session reports. Pointers are kept.
fn prune(reports: &Path, now: u64) {
    let Ok(entries) = std::fs::read_dir(reports) else {
        return;
    };
    let mut sessions: Vec<(u64, PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let mtime = entry
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if name.ends_with(".start.json") {
            if now.saturating_sub(mtime) > MARKER_MAX_AGE_SECS {
                let _ = std::fs::remove_file(entry.path());
            }
        } else if name.ends_with(".json") && !name.starts_with("last-") {
            sessions.push((mtime, entry.path()));
        }
    }
    if sessions.len() > MAX_REPORTS {
        sessions.sort();
        let excess = sessions.len() - MAX_REPORTS;
        for (_, path) in sessions.into_iter().take(excess) {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let mut f = statefile::open_new_private(&tmp)?;
    f.write_all(bytes)?;
    drop(f);
    std::fs::rename(&tmp, dir.join(name))
}

/// Read a small regular file (reports and markers are a few KiB); `None` past 1 MiB.
fn read_small(path: &Path) -> Option<Vec<u8>> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > 1 << 20 {
        return None;
    }
    std::fs::read(path).ok()
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The project a session belongs to, as a hash of its git toplevel (else the canonical cwd):
/// reports never store a project path in the plugin data dir.
pub fn project_key(cwd: &Path) -> String {
    project_hash(&crate::policy::tier::project_root(cwd).to_string_lossy())
}

fn project_hash(project: &str) -> String {
    crate::audit::sha256_hex(project.as_bytes())[..16].to_string()
}

/// A session id safe as a file name: `[A-Za-z0-9_-]`, at most 64 chars, else `unknown`.
fn safe_id(id: &str) -> String {
    let s: String = id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(64)
        .collect();
    if s.is_empty() {
        "unknown".to_string()
    } else {
        s
    }
}

fn short_id(id: &str) -> String {
    safe_id(id).chars().take(8).collect()
}

fn shorten(reason: &str) -> String {
    let mut out: String = reason.chars().take(REASON_CHARS).collect();
    if reason.chars().count() > REASON_CHARS {
        out.push('…');
    }
    out
}

fn round(x: f64) -> f64 {
    (x * 1e6).round() / 1e6
}

/// Coarse age: `45s`, `12m`, `3h`, `2d`.
fn ago(secs: u64) -> String {
    match secs {
        s if s < 60 => format!("{s}s"),
        s if s < 3_600 => format!("{}m", s / 60),
        s if s < 86_400 => format!("{}h", s / 3_600),
        s => format!("{}d", s / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_ts_reads_the_first_field() {
        assert_eq!(leading_ts(br#"{"ts":123,"session_id":"a"}"#), Some(123));
        assert_eq!(leading_ts(br#"{"session_id":"a"}"#), None);
    }

    #[test]
    fn safe_id_strips_path_characters() {
        assert_eq!(safe_id("../../etc/passwd"), "etcpasswd");
        assert_eq!(safe_id(""), "unknown");
    }

    #[test]
    fn ago_is_coarse() {
        assert_eq!(ago(30), "30s");
        assert_eq!(ago(7_200), "2h");
        assert_eq!(ago(200_000), "2d");
    }
}
