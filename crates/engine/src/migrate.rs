//! One-time conversion of 1.0 relaxation state (spec D4.2, WS-B fix round 1).
//!
//! 1.0 wrote `grants.json`, `mode.json` and `spend.json` as plain JSON. 1.1.0 reads only
//! [`crate::statefile`] envelopes, so a plain file is "tampered". [`run`] converts 1.0 files
//! once, at the first 1.1.0 SessionStart, and **never into live relaxation**:
//!
//! - each unexpired 1.0 grant in a grantable scope with valid addresses becomes a *pending*
//!   grant request for its remaining time and budget; a 1.0 `autopilot` mode becomes a pending
//!   mode request. The user sees their confirmation codes in that SessionStart's
//!   `systemMessage` and keeps what they confirm. `paranoid` (stricter) is applied as is;
//! - a 1.0 spend ledger becomes an exhausted ledger for today (fresh tomorrow);
//! - an unreadable file, and the removed `off` mode, are renamed to `<name>.v1-unmigrated`.
//!
//! Each converted file is renamed to `<name>.v1-migrated`, each item is audited and listed in
//! the SessionStart notice, and an authenticated marker [`MIGRATED_FILE`] is written.
//!
//! "First run" means no state key, no marker, and no envelope in the data dir. Staging a
//! second run (delete the key, the marker and every envelope, plant plain files) therefore
//! yields only pending requests the user must confirm with a code they alone see, and an
//! exhausted ledger. The audit log is not part of the test: every 1.0 install has one, so
//! requiring its absence would never migrate anything.

use std::path::Path;

use crate::audit::{self, AuditEntry};
use crate::confirm::{self, PendingKind, PENDING_FILE};
use crate::datadir::DataDir;
use crate::grants::{self, GrantRequest, Grants, GRANTABLE_SCOPES, GRANTS_FILE};
use crate::mode::{self, ModeRecord, MODE_FILE};
use crate::session::SESSIONS_FILE;
use crate::spend::{self, SPEND_FILE};
use crate::statefile::{self, KEY_FILE};

/// Largest 1.0 state file read.
const MAX_V1_BYTES: u64 = 1024 * 1024;

/// The authenticated marker written after a migration.
pub const MIGRATED_FILE: &str = "migrated.json";

/// Longest a converted grant request may run (the grant limit).
const MAX_GRANT_SECS: u64 = 30 * 86_400;

/// State files 1.1.0 writes as envelopes: one of them existing means 1.1.0 has run.
const ENVELOPE_FILES: [&str; 8] = [
    GRANTS_FILE,
    MODE_FILE,
    SPEND_FILE,
    PENDING_FILE,
    SESSIONS_FILE,
    MIGRATED_FILE,
    "trust.json",
    "state.json",
];

/// Convert 1.0 state in `dir`, once. Returns one human line per item (empty when there was
/// nothing to do or this is not a first run).
pub fn run(dir: &DataDir, now: u64) -> Vec<String> {
    if dir.is_unresolved() || !is_first_run(&dir.path) {
        return Vec::new();
    }
    let mut lines = Vec::new();
    migrate_spend(dir, &mut lines);
    migrate_grants(dir, now, &mut lines);
    migrate_mode(dir, now, &mut lines);
    let marker = serde_json::json!({ "at": now, "items": lines });
    let _ = statefile::store(dir, MIGRATED_FILE, &marker);
    for line in &lines {
        let entry = AuditEntry::new(
            "",
            "safe-ai-skill",
            "state_migrate",
            "migrate",
            line.clone(),
            audit::sha256_hex(line.as_bytes()),
        );
        let _ = audit::append(&entry, &dir.path);
    }
    lines
}

/// No state key, no marker, no envelope: 1.1.0 has never written here.
fn is_first_run(path: &Path) -> bool {
    let exists = |name: &str| std::fs::symlink_metadata(path.join(name)).is_ok();
    if exists(KEY_FILE) || exists(MIGRATED_FILE) {
        return false;
    }
    !ENVELOPE_FILES.iter().any(|name| {
        read_v1(&path.join(name))
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .is_some_and(|v| v.get("mac").is_some())
    })
}

fn migrate_spend(dir: &DataDir, lines: &mut Vec<String>) {
    let path = dir.path.join(SPEND_FILE);
    if read_v1(&path).is_none() {
        return;
    }
    rename_to(&path, "v1-migrated");
    if spend::store_exhausted(&dir.path).is_ok() {
        lines.push(
            "1.0 spend ledger: today's spend budget is treated as exhausted (fresh tomorrow)"
                .to_string(),
        );
    }
}

fn migrate_grants(dir: &DataDir, now: u64, lines: &mut Vec<String>) {
    let path = dir.path.join(GRANTS_FILE);
    let Some(bytes) = read_v1(&path) else {
        return;
    };
    let Ok(old) = serde_json::from_slice::<Grants>(&bytes) else {
        rename_to(&path, "v1-unmigrated");
        lines.push("grants.json from 1.0 could not be read; not migrated".to_string());
        return;
    };
    rename_to(&path, "v1-migrated");
    let mut dropped = 0usize;
    for g in &old.grants {
        let Some(request) = as_request(g, now) else {
            dropped += 1;
            continue;
        };
        let Ok(payload) = serde_json::to_value(&request) else {
            continue;
        };
        let summary = format!("{} (kept from 1.0)", request.summary());
        if let Ok(id) = confirm::create_pending(dir, PendingKind::Grant, &summary, payload) {
            lines.push(format!(
                "1.0 grant {} kept as pending request {id}; confirm it with the code shown to you",
                g.id
            ));
        }
    }
    if dropped > 0 {
        lines.push(format!(
            "grants.json from 1.0: {dropped} expired or invalid grant(s) dropped"
        ));
    }
}

/// The pending request a 1.0 grant becomes: its remaining time and budget. `None` when it is
/// expired, outside the grantable scopes, or carries bad numbers or addresses.
fn as_request(g: &grants::Grant, now: u64) -> Option<GrantRequest> {
    let valid = !g.is_expired(now)
        && GRANTABLE_SCOPES.contains(&g.scope)
        && g.max_tx_sol.is_finite()
        && g.max_tx_sol >= 0.0
        && g.budget_sol.is_finite()
        && g.budget_sol >= 0.0
        && g.programs
            .iter()
            .chain(&g.to)
            .all(|a| grants::is_address(a));
    if !valid {
        return None;
    }
    Some(GrantRequest {
        scope: g.scope,
        for_secs: g.expires_at.saturating_sub(now).clamp(1, MAX_GRANT_SECS),
        max_tx_sol: g.max_tx_sol,
        budget_sol: g.remaining_sol(),
        programs: g.programs.clone(),
        to: g.to.clone(),
        danger: g.danger,
    })
}

fn migrate_mode(dir: &DataDir, now: u64, lines: &mut Vec<String>) {
    let path = dir.path.join(MODE_FILE);
    let Some(bytes) = read_v1(&path) else {
        return;
    };
    let record = serde_json::from_slice::<ModeRecord>(&bytes).ok();
    match record.as_ref().map(|r| r.profile.as_str()) {
        Some(p) if mode::is_known_profile(p) => {
            rename_to(&path, "v1-migrated");
            if mode::is_looser(p, mode::DEFAULT_PROFILE) {
                let payload = serde_json::json!({ "profile": p });
                let summary = format!("mode {p} (kept from 1.0)");
                if let Ok(id) = confirm::create_pending(dir, PendingKind::Mode, &summary, payload) {
                    lines.push(format!(
                        "1.0 mode {p} kept as pending request {id}; confirm it with the code \
                         shown to you"
                    ));
                }
            } else if p != mode::DEFAULT_PROFILE && mode::set(dir, p, now).is_ok() {
                lines.push(format!("1.0 mode {p} applied"));
            }
        }
        Some("off") => {
            rename_to(&path, "v1-unmigrated");
            lines.push(
                "mode off from 1.0 was removed; not migrated (strict applies; to turn the hooks \
                 off use SAFE_AI_SKILL_DISABLE)"
                    .to_string(),
            );
        }
        _ => {
            rename_to(&path, "v1-unmigrated");
            lines.push("mode.json from 1.0 could not be read; not migrated".to_string());
        }
    }
}

/// Rename a 1.0 file to `<name>.<suffix>`.
fn rename_to(path: &Path, suffix: &str) {
    let mut aside = path.as_os_str().to_owned();
    aside.push(".");
    aside.push(suffix);
    let _ = std::fs::rename(path, aside);
}

/// The bytes of a regular (non-symlink, non-FIFO) file of at most [`MAX_V1_BYTES`].
fn read_v1(path: &Path) -> Option<Vec<u8>> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_V1_BYTES {
        return None;
    }
    std::fs::read(path).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grants::tests::{tmp_data, transfer_grant, ADDR};
    use crate::spend::SpendLedger;
    use crate::statefile::Loaded;

    const NOW: u64 = 1_000_000;

    fn real_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn write(dir: &DataDir, name: &str, body: &str) {
        std::fs::create_dir_all(&dir.path).unwrap();
        std::fs::write(dir.path.join(name), body).unwrap();
    }

    fn v1_grants() -> String {
        let mut to_dest = transfer_grant("live", NOW + 3_600);
        to_dest.to = vec![ADDR.into()];
        to_dest.spent_sol = 2.0;
        let mut other = transfer_grant("other", NOW + 3_600);
        other.scope = crate::gate::Scope::Other;
        serde_json::to_string(&Grants {
            grants: vec![to_dest, transfer_grant("expired", NOW - 1), other],
        })
        .unwrap()
    }

    #[test]
    fn v1_state_becomes_pending_requests_and_an_exhausted_ledger() {
        let dir = tmp_data("migrate_ok");
        write(&dir, GRANTS_FILE, &v1_grants());
        write(&dir, MODE_FILE, r#"{"profile":"autopilot","set_at":5}"#);
        write(&dir, SPEND_FILE, r#"{"day":11,"total_sol":0.0}"#);

        let lines = run(&dir, NOW);
        assert!(
            lines
                .iter()
                .any(|l| l.contains("1.0 grant live kept as pending")),
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("1.0 mode autopilot kept")),
            "{lines:?}"
        );
        assert!(lines.iter().any(|l| l.contains("exhausted")), "{lines:?}");
        assert!(
            lines.iter().any(|l| l.contains("2 expired or invalid")),
            "{lines:?}"
        );

        // Nothing is live: no grant, no autopilot.
        assert!(grants::live(&dir).grants.is_empty());
        assert_eq!(mode::persisted(&dir), None);
        match statefile::load::<SpendLedger>(&dir, SPEND_FILE) {
            Loaded::Valid(l) => assert!(l.is_exhausted()),
            other => panic!("{other:?}"),
        }
        // The requests carry the remaining time and budget; the user confirms them.
        let shown = confirm::announce_pending(&dir, real_now());
        assert_eq!(shown.len(), 2);
        let grant = shown.iter().find(|a| a.kind == PendingKind::Grant).unwrap();
        assert!(grant.summary.contains("3 SOL budget") && grant.summary.contains("1h"));
        assert!(dir.path.join("grants.json.v1-migrated").exists());
        assert!(std::fs::read_to_string(dir.path.join("audit.jsonl"))
            .unwrap()
            .contains("state_migrate"));
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn staged_rerun_is_refused_while_the_marker_or_key_exists() {
        let dir = tmp_data("migrate_once");
        write(&dir, GRANTS_FILE, &v1_grants());
        assert!(!run(&dir, NOW).is_empty());
        // Delete the key and every envelope but the marker, plant again: refused.
        std::fs::remove_file(dir.path.join(KEY_FILE)).unwrap();
        for name in [PENDING_FILE, SPEND_FILE, statefile::GEN_INDEX] {
            let _ = std::fs::remove_file(dir.path.join(name));
        }
        write(&dir, GRANTS_FILE, &v1_grants());
        assert!(run(&dir, NOW).is_empty());
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn no_migration_when_the_key_or_an_envelope_exists() {
        let dir = tmp_data("migrate_keyed");
        mode::set(&dir, "strict", 0).unwrap();
        write(&dir, GRANTS_FILE, &v1_grants());
        assert!(run(&dir, NOW).is_empty());
        std::fs::remove_file(dir.path.join(KEY_FILE)).unwrap();
        assert!(run(&dir, NOW).is_empty());
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn even_a_fully_staged_rerun_relaxes_nothing() {
        // Key, marker and every envelope deleted: the plant converts again, but only into
        // pending requests (codes go to the user) and an exhausted ledger.
        let dir = tmp_data("migrate_staged");
        write(&dir, MODE_FILE, r#"{"profile":"autopilot","set_at":5}"#);
        write(&dir, SPEND_FILE, r#"{"day":11,"total_sol":0.0}"#);
        assert!(!run(&dir, NOW).is_empty());
        assert_eq!(mode::persisted(&dir), None);
        assert!(spend::SpendLedger::load(&dir.path).is_exhausted());
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn unmigratable_files_are_set_aside_and_noted() {
        let dir = tmp_data("migrate_bad");
        write(&dir, GRANTS_FILE, "not json");
        write(&dir, MODE_FILE, r#"{"profile":"off","set_at":0}"#);
        let lines = run(&dir, NOW);
        assert!(lines
            .iter()
            .any(|l| l.contains("grants.json from 1.0 could not be read")));
        assert!(lines.iter().any(|l| l.contains("mode off")));
        assert!(dir.path.join("grants.json.v1-unmigrated").exists());
        assert!(dir.path.join("mode.json.v1-unmigrated").exists());
        assert_eq!(mode::persisted(&dir), None);
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn paranoid_is_applied_directly() {
        let dir = tmp_data("migrate_paranoid");
        write(&dir, MODE_FILE, r#"{"profile":"paranoid","set_at":5}"#);
        let lines = run(&dir, NOW);
        assert!(lines
            .iter()
            .any(|l| l.contains("1.0 mode paranoid applied")));
        assert_eq!(mode::persisted(&dir), Some("paranoid".into()));
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn nothing_to_migrate_is_silent() {
        let dir = tmp_data("migrate_none");
        assert!(run(&dir, NOW).is_empty());
        let _ = std::fs::remove_dir_all(&dir.path);
    }
}
