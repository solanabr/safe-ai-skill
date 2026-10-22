//! One-time migration of 1.0 relaxation state into authenticated envelopes (spec D4.2).
//!
//! 1.0 wrote `grants.json`, `mode.json` and `spend.json` as plain JSON. 1.1.0 reads only
//! [`crate::statefile`] envelopes, so a plain file is "tampered". [`run`] converts valid 1.0
//! files once, at the first 1.1.0 SessionStart, and returns a line per migrated item for the
//! SessionStart notice; each is also audited.
//!
//! "First run" means the state key does not exist yet and no file in the data dir is an
//! envelope. The SessionStart that migrates also creates the key (via the spend ledger), so a
//! plain file written later is never migrated: it stays tampered and relaxes nothing.
//!
//! **Trade-off:** 1.0 state was unauthenticated, so migrating it trusts whatever was on disk
//! at upgrade time, including anything the agent wrote there under 1.0. The alternative,
//! dropping it, costs users their live grants and mode. The risk is bounded: only unexpired
//! grants in a grantable scope with valid addresses carry over, `off` is not carried over,
//! and every migrated item is shown to the user at that SessionStart. An agent that deletes
//! the key *and* every envelope to stage a second migration is a same-user write the threat
//! model already concedes; the notice still shows the user what was migrated.
//!
//! A 1.0 file that cannot be migrated is renamed to `<name>.v1-unmigrated` so it does not
//! show up as an authentication failure every session.

use std::path::Path;

use crate::audit::{self, AuditEntry};
use crate::confirm::PENDING_FILE;
use crate::datadir::DataDir;
use crate::grants::{self, Grants, GRANTABLE_SCOPES, GRANTS_FILE};
use crate::mode::{self, ModeRecord, MODE_FILE};
use crate::session::SESSIONS_FILE;
use crate::spend::{SpendLedger, SPEND_FILE};
use crate::statefile::{self, KEY_FILE};

/// Largest 1.0 state file read.
const MAX_V1_BYTES: u64 = 1024 * 1024;

/// State files 1.1.0 writes as envelopes: one of them existing means 1.1.0 has run.
const ENVELOPE_FILES: [&str; 7] = [
    GRANTS_FILE,
    MODE_FILE,
    SPEND_FILE,
    PENDING_FILE,
    SESSIONS_FILE,
    "trust.json",
    "state.json",
];

/// Migrate valid 1.0 state in `dir`, once. Returns one human line per migrated or dropped
/// item (empty when there was nothing to do or this is not a first run).
pub fn run(dir: &DataDir, now: u64) -> Vec<String> {
    if dir.is_unresolved() || !is_first_run(&dir.path) {
        return Vec::new();
    }
    let mut lines = Vec::new();
    migrate_grants(dir, now, &mut lines);
    migrate_mode(dir, now, &mut lines);
    migrate_spend(dir, &mut lines);
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

/// No state key and no envelope: 1.1.0 has never written here.
fn is_first_run(path: &Path) -> bool {
    if std::fs::symlink_metadata(path.join(KEY_FILE)).is_ok() {
        return false;
    }
    !ENVELOPE_FILES.iter().any(|name| {
        read_v1(&path.join(name))
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .is_some_and(|v| v.get("mac").is_some())
    })
}

fn migrate_grants(dir: &DataDir, now: u64, lines: &mut Vec<String>) {
    let path = dir.path.join(GRANTS_FILE);
    let Some(bytes) = read_v1(&path) else {
        return;
    };
    let Ok(old) = serde_json::from_slice::<Grants>(&bytes) else {
        set_aside(
            &path,
            lines,
            "grants.json from 1.0 could not be read; not migrated",
        );
        return;
    };
    let total = old.grants.len();
    let kept: Vec<grants::Grant> = old
        .grants
        .into_iter()
        .filter(|g| migratable(g, now))
        .map(|mut g| {
            if !g.spent_sol.is_finite() || g.spent_sol < 0.0 {
                g.spent_sol = g.budget_sol;
            }
            g
        })
        .collect();
    let dropped = total - kept.len();
    if kept.is_empty() {
        set_aside(
            &path,
            lines,
            &format!("grants.json from 1.0: {dropped} grant(s) expired or invalid; not migrated"),
        );
        return;
    }
    let described: Vec<String> = kept.iter().map(|g| g.describe(now)).collect();
    if grants::save(dir, &Grants { grants: kept }).is_err() {
        return;
    }
    lines.extend(
        described
            .into_iter()
            .map(|d| format!("migrated from 1.0: {d}")),
    );
    if dropped > 0 {
        lines.push(format!(
            "grants.json from 1.0: {dropped} expired or invalid grant(s) dropped"
        ));
    }
}

/// An unexpired 1.0 grant in a grantable scope, with sane numbers and addresses.
fn migratable(g: &grants::Grant, now: u64) -> bool {
    !g.is_expired(now)
        && GRANTABLE_SCOPES.contains(&g.scope)
        && g.max_tx_sol.is_finite()
        && g.max_tx_sol >= 0.0
        && g.budget_sol.is_finite()
        && g.budget_sol >= 0.0
        && g.programs
            .iter()
            .chain(&g.to)
            .all(|a| grants::is_address(a))
}

fn migrate_mode(dir: &DataDir, now: u64, lines: &mut Vec<String>) {
    let path = dir.path.join(MODE_FILE);
    let Some(bytes) = read_v1(&path) else {
        return;
    };
    match serde_json::from_slice::<ModeRecord>(&bytes) {
        Ok(r) if mode::is_known_profile(&r.profile) => {
            let set_at = if r.set_at == 0 { now } else { r.set_at };
            if mode::set(dir, &r.profile, set_at).is_ok() {
                lines.push(format!("migrated from 1.0: mode {}", r.profile));
            }
        }
        Ok(r) if r.profile == "off" => set_aside(
            &path,
            lines,
            "mode off from 1.0 was removed; not migrated (strict applies; to turn the hooks \
             off use SAFE_AI_SKILL_DISABLE)",
        ),
        _ => set_aside(
            &path,
            lines,
            "mode.json from 1.0 could not be read; not migrated",
        ),
    }
}

fn migrate_spend(dir: &DataDir, lines: &mut Vec<String>) {
    let path = dir.path.join(SPEND_FILE);
    let Some(bytes) = read_v1(&path) else {
        return;
    };
    let Ok(old) = serde_json::from_slice::<SpendLedger>(&bytes) else {
        set_aside(
            &path,
            lines,
            "spend.json from 1.0 could not be read; not migrated",
        );
        return;
    };
    // A fresh ledger at the 1.0 totals; the day rolls over as usual.
    let total = if old.total_sol.is_finite() && old.total_sol >= 0.0 {
        old.total_sol
    } else {
        f64::MAX
    };
    let ledger = SpendLedger {
        day: old.day,
        total_sol: total,
    };
    if statefile::store(dir, SPEND_FILE, &ledger).is_ok() {
        lines.push(format!(
            "migrated from 1.0: spend ledger ({total} SOL on day {})",
            old.day
        ));
    }
}

/// Rename an unmigratable 1.0 file aside and note it.
fn set_aside(path: &Path, lines: &mut Vec<String>, note: &str) {
    let mut aside = path.as_os_str().to_owned();
    aside.push(".v1-unmigrated");
    let _ = std::fs::rename(path, aside);
    lines.push(note.to_string());
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
    use crate::statefile::Loaded;

    const NOW: u64 = 1_000_000;

    fn write(dir: &DataDir, name: &str, body: &str) {
        std::fs::create_dir_all(&dir.path).unwrap();
        std::fs::write(dir.path.join(name), body).unwrap();
    }

    fn v1_grants() -> String {
        let mut to_dest = transfer_grant("live", NOW + 3_600);
        to_dest.to = vec![ADDR.into()];
        let mut other = transfer_grant("other", NOW + 3_600);
        other.scope = crate::gate::Scope::Other;
        serde_json::to_string(&Grants {
            grants: vec![to_dest, transfer_grant("expired", NOW - 1), other],
        })
        .unwrap()
    }

    #[test]
    fn valid_v1_state_is_migrated_once_and_re_maced() {
        let dir = tmp_data("migrate_ok");
        write(&dir, GRANTS_FILE, &v1_grants());
        write(&dir, MODE_FILE, r#"{"profile":"autopilot","set_at":5}"#);
        write(&dir, SPEND_FILE, r#"{"day":11,"total_sol":2.5}"#);

        let lines = run(&dir, NOW);
        assert!(lines.iter().any(|l| l.contains("grant live")), "{lines:?}");
        assert!(
            lines.iter().any(|l| l.contains("mode autopilot")),
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("spend ledger")),
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("2 expired or invalid")),
            "{lines:?}"
        );

        let migrated = grants::live(&dir);
        assert_eq!(migrated.grants.len(), 1);
        assert_eq!(migrated.grants[0].id, "live");
        assert_eq!(mode::persisted(&dir), Some("autopilot".into()));
        match statefile::load::<SpendLedger>(&dir, SPEND_FILE) {
            Loaded::Valid(l) => assert_eq!((l.day, l.total_sol), (11, 2.5)),
            other => panic!("{other:?}"),
        }
        let audit = std::fs::read_to_string(dir.path.join("audit.jsonl")).unwrap();
        assert!(audit.contains("state_migrate"));

        // Once: a plain grants.json written afterwards is never migrated.
        write(&dir, GRANTS_FILE, &v1_grants());
        assert!(run(&dir, NOW).is_empty());
        assert!(grants::live(&dir).grants.is_empty());
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn no_migration_when_the_key_exists() {
        let dir = tmp_data("migrate_keyed");
        // Any 1.1.0 store creates the key.
        mode::set(&dir, "strict", 0).unwrap();
        write(&dir, GRANTS_FILE, &v1_grants());
        assert!(run(&dir, NOW).is_empty());
        assert!(grants::live(&dir).grants.is_empty());
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn no_migration_when_an_envelope_survives_a_deleted_key() {
        let dir = tmp_data("migrate_nokey");
        mode::set(&dir, "strict", 0).unwrap();
        std::fs::remove_file(dir.path.join(KEY_FILE)).unwrap();
        write(&dir, GRANTS_FILE, &v1_grants());
        assert!(run(&dir, NOW).is_empty());
        assert!(grants::live(&dir).grants.is_empty());
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
        assert!(!dir.path.join(GRANTS_FILE).exists());
        assert!(dir.path.join("grants.json.v1-unmigrated").exists());
        assert!(dir.path.join("mode.json.v1-unmigrated").exists());
        assert_eq!(mode::persisted(&dir), None);
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn nothing_to_migrate_is_silent() {
        let dir = tmp_data("migrate_none");
        assert!(run(&dir, NOW).is_empty());
    }
}
