//! G4: the session report (SessionEnd JSON + summary, SessionStart one-line recap).

use std::path::{Path, PathBuf};
use std::time::Instant;

use safe_ai_skill::audit::{self, AuditEntry};
use safe_ai_skill::datadir::DataDir;
use safe_ai_skill::gate::Scope;
use safe_ai_skill::grants::{self, Grant, Grants};
use safe_ai_skill::report::{self, SessionReport};
use safe_ai_skill::spend::{SpendLedger, SPEND_FILE};
use safe_ai_skill::statefile;

const NOW: u64 = 1_800_000_000;

fn tmp(name: &str) -> (DataDir, PathBuf) {
    let base = std::env::temp_dir().join(format!("ex_g4_{name}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let data = base.join("data");
    let project = base.join("proj");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::create_dir_all(project.join(".git")).unwrap();
    (
        DataDir {
            path: data,
            trusted: true,
        },
        project,
    )
}

fn log(dir: &DataDir, ts: u64, sid: &str, class: &str, decision: &str, reason: &str) {
    let entry = AuditEntry {
        ts,
        session_id: sid.into(),
        tool: "Bash".into(),
        classification: class.into(),
        decision: decision.into(),
        reason: reason.into(),
        input_sha256: "00".into(),
    };
    audit::append(&entry, &dir.path).unwrap();
}

fn end(dir: &DataDir, sid: &str, cwd: &Path, now: u64) -> SessionReport {
    let raw = serde_json::json!({
        "session_id": sid,
        "transcript_path": "/x.jsonl",
        "cwd": cwd,
        "hook_event_name": "SessionEnd",
        "reason": "prompt_input_exit",
    });
    report::session_end(dir, raw.to_string().as_bytes(), now).expect("a report")
}

#[test]
fn quiet_session_reports_nothing_and_recaps_nothing() {
    let (dir, proj) = tmp("quiet");
    assert_eq!(report::session_start(&dir, "s1", &proj, NOW), None);
    log(&dir, NOW + 1, "s1", "other", "defer", "");
    let r = end(&dir, "s1", &proj, NOW + 10);
    assert_eq!(r.flagged(), 0);
    assert_eq!(r.end_reason, "prompt_input_exit");
    assert!(r.summary.contains("no denies or asks"), "{}", r.summary);
    assert!(dir.path.join("reports/s1.json").is_file());
    assert_eq!(report::session_start(&dir, "s2", &proj, NOW + 20), None);
}

#[test]
fn counts_by_class_top_reasons_and_one_recap() {
    let (dir, proj) = tmp("counts");
    report::session_start(&dir, "s1", &proj, NOW);
    // Before the session (outside the slack) and another session's lines: not counted.
    log(&dir, NOW - 10_000, "s1", "tamper", "deny", "old");
    log(&dir, NOW + 1, "zz", "tamper", "deny", "theirs");
    for _ in 0..3 {
        log(
            &dir,
            NOW + 2,
            "s1",
            "tamper",
            "deny",
            "Edits that disable the firewall are denied; revert the edit.",
        );
    }
    log(
        &dir,
        NOW + 3,
        "s1",
        "secret_read",
        "ask",
        "Reading .env asks; read .env.example instead.",
    );
    log(&dir, NOW + 4, "s1", "other", "allow", "");
    let r = end(&dir, "s1", &proj, NOW + 60);
    assert_eq!(r.denies.get("tamper"), Some(&3));
    assert_eq!(r.asks.get("secret_read"), Some(&1));
    assert_eq!(r.decisions.get("allow"), Some(&1));
    assert_eq!(r.top_reasons[0].count, 3);
    assert_eq!(r.top_reasons[0].class, "tamper");
    assert!(!r.truncated);
    assert!(
        r.summary
            .contains("3 denied, 1 asked (tamper 3, secret_read 1)"),
        "{}",
        r.summary
    );

    // The same session resumed/compacted: no recap of itself.
    assert_eq!(report::session_start(&dir, "s1", &proj, NOW + 70), None);
    // A new session in the project: one line, once.
    let line = report::session_start(&dir, "s2", &proj, NOW + 3_700).expect("a recap");
    assert!(!line.contains('\n'));
    assert!(
        line.starts_with("safe-ai-skill: last session in this project (1h ago): 3 denied, 1 asked"),
        "{line}"
    );
    assert_eq!(report::session_start(&dir, "s3", &proj, NOW + 3_800), None);
    // Another project sees nothing.
    let other = proj.parent().unwrap().join("other");
    std::fs::create_dir_all(other.join(".git")).unwrap();
    assert_eq!(report::session_start(&dir, "s4", &other, NOW + 3_800), None);
}

#[test]
fn reasons_are_redacted() {
    let (dir, proj) = tmp("redact");
    report::session_start(&dir, "s1", &proj, NOW);
    let key = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
    log(
        &dir,
        NOW + 1,
        "s1",
        "other",
        "ask",
        &format!("Command carries {key}; remove it."),
    );
    let r = end(&dir, "s1", &proj, NOW + 5);
    let body = std::fs::read_to_string(dir.path.join("reports/s1.json")).unwrap();
    assert!(!body.contains(key));
    assert!(!r.top_reasons[0].reason.contains(key));
}

#[test]
fn spend_and_grant_draws_are_diffed_against_the_start() {
    let (dir, proj) = tmp("spend");
    let day = NOW / 86_400;
    statefile::store(
        &dir,
        SPEND_FILE,
        &SpendLedger {
            day,
            total_sol: 0.5,
        },
    )
    .unwrap();
    let grant = |spent: f64| Grant {
        id: "g1".into(),
        scope: Scope::Transfer,
        programs: vec![],
        to: vec![],
        max_tx_sol: 1.0,
        budget_sol: 5.0,
        spent_sol: spent,
        expires_at: NOW + 3_600,
        danger: false,
    };
    grants::save(
        &dir,
        &Grants {
            grants: vec![grant(1.0)],
        },
    )
    .unwrap();
    report::session_start(&dir, "s1", &proj, NOW);
    statefile::store(
        &dir,
        SPEND_FILE,
        &SpendLedger {
            day,
            total_sol: 1.25,
        },
    )
    .unwrap();
    grants::save(
        &dir,
        &Grants {
            grants: vec![grant(1.5)],
        },
    )
    .unwrap();
    let r = end(&dir, "s1", &proj, NOW + 30);
    let spend = r.spend.expect("spend");
    assert_eq!(spend.session_sol, Some(0.75));
    assert_eq!(spend.today_sol, 1.25);
    assert_eq!(r.grants_used.len(), 1);
    assert_eq!(r.grants_used[0].sol, 0.5);
    assert!(r.summary.contains("0.75 SOL spent"), "{}", r.summary);
}

#[test]
fn hostile_or_empty_payloads_never_fail() {
    let (dir, _proj) = tmp("hostile");
    let r = report::session_end(&dir, b"not json", NOW).expect("a report");
    assert_eq!(r.flagged(), 0);
    let raw = br#"{"session_id":"../../escape","cwd":"/nonexistent","reason":"other"}"#;
    report::session_end(&dir, raw, NOW).expect("a report");
    assert!(dir.path.join("reports/escape.json").is_file());
    assert!(report::session_end(&safe_ai_skill::datadir::unresolved(), raw, NOW).is_none());
    assert!(report::session_start(
        &safe_ai_skill::datadir::unresolved(),
        "s",
        Path::new("."),
        NOW
    )
    .is_none());
}

#[test]
fn no_marker_still_reports_the_last_day() {
    let (dir, proj) = tmp("nomarker");
    log(
        &dir,
        NOW - 100,
        "s9",
        "deploy",
        "ask",
        "Mainnet deploy asks; confirm it.",
    );
    let r = end(&dir, "s9", &proj, NOW);
    assert_eq!(r.started_at, None);
    assert_eq!(r.asks.get("deploy"), Some(&1));
}

/// A large shared log: the scan stops at the session start and stays well inside the 1.5 s
/// SessionEnd budget.
#[test]
fn large_log_is_bounded() {
    let (dir, proj) = tmp("perf");
    let mut body = String::new();
    for i in 0..200_000u64 {
        body.push_str(&format!(
            "{{\"ts\":{},\"session_id\":\"other\",\"tool\":\"Bash\",\"classification\":\"other\",\"decision\":\"defer\",\"reason\":\"\",\"input_sha256\":\"00\"}}\n",
            NOW - 400_000 + i
        ));
    }
    std::fs::write(dir.path.join("audit.jsonl"), body).unwrap();
    report::session_start(&dir, "s1", &proj, NOW);
    for _ in 0..50 {
        log(&dir, NOW + 1, "s1", "tamper", "deny", "x; y.");
    }
    let t = Instant::now();
    let r = end(&dir, "s1", &proj, NOW + 10);
    let short = t.elapsed();
    assert_eq!(r.denies.get("tamper"), Some(&50));

    // No marker: the 24 h window over the same log.
    let t = Instant::now();
    let r = end(&dir, "nomark", &proj, NOW + 10);
    let window = t.elapsed();
    assert_eq!(r.flagged(), 0);
    eprintln!(
        "G4 bench: session_end with marker {short:?}, without marker (24h window) {window:?}"
    );
    assert!(window.as_millis() < 1_000, "{window:?}");
}
