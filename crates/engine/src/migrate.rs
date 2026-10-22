//! One-time conversion of 1.0 relaxation state (spec D4.2, WS-B fix round 1).
//!
//! 1.0 wrote `grants.json`, `mode.json` and `spend.json` as plain JSON. 1.1.0 reads only
//! [`crate::statefile`] envelopes, so a plain file is "tampered". [`run`] converts 1.0 files
//! once, at the first 1.1.0 SessionStart, and **never into live relaxation**:
//!
//! - each unexpired 1.0 grant in a grantable scope with valid addresses becomes a *pending*
//!   grant request for its remaining time and budget. The user sees their confirmation codes
//!   in that SessionStart's `systemMessage` and keeps what they confirm;
//! - a 1.0 mode becomes a tier (D8 v2 spec §9), never below `relaxed`: `strict` and
//!   `autopilot` are `relaxed` (the notice names what changed, and `allow --scope transfer`
//!   for autopilot users), `paranoid` is `tier.json` `high`;
//! - a 1.0 spend ledger becomes an exhausted ledger for today (fresh tomorrow);
//! - an unreadable file, and the removed `off` mode, are renamed to `<name>.v1-unmigrated`.
//!
//! [`mode_to_tier`] does the same, once, for an authenticated WS-B `mode.json` (1.1.0
//! development builds), renaming it to `mode.json.migrated`.
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
use crate::policy::tier::Tier;
use crate::session::SESSIONS_FILE;
use crate::spend::{self, SPEND_FILE};
use crate::statefile::{self, Loaded, KEY_FILE};
use crate::tierstate::{self, TIER_FILE};

/// Largest 1.0 state file read.
const MAX_V1_BYTES: u64 = 1024 * 1024;

/// The authenticated marker written after a migration.
pub const MIGRATED_FILE: &str = "migrated.json";

/// Longest a converted grant request may run (the grant limit).
const MAX_GRANT_SECS: u64 = 30 * 86_400;

/// The one-time line for users of the former default profile.
pub const STRICT_LINE: &str = "profile strict is now tier relaxed: a curl POST no longer asks \
     below High, and mainnet --final, program close and spl-token close/burn now deny";

/// State files 1.1.0 writes as envelopes: one of them existing means 1.1.0 has run.
const ENVELOPE_FILES: [&str; 9] = [
    GRANTS_FILE,
    MODE_FILE,
    TIER_FILE,
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
    let had_mode = std::fs::symlink_metadata(dir.path.join(MODE_FILE)).is_ok();
    migrate_mode(dir, now, &mut lines);
    if !had_mode && !lines.is_empty() {
        lines.push(STRICT_LINE.to_string());
    }
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
        Some("off") => {
            rename_to(&path, "v1-unmigrated");
            lines.push(OFF_LINE.to_string());
        }
        Some(p) => match mode::profile_tier(p) {
            Some(tier) => {
                rename_to(&path, "v1-migrated");
                carry_profile(dir, p, tier, now, lines);
            }
            None => {
                rename_to(&path, "v1-unmigrated");
                lines.push("mode.json from 1.0 could not be read; not migrated".to_string());
            }
        },
        None => {
            rename_to(&path, "v1-unmigrated");
            lines.push("mode.json from 1.0 could not be read; not migrated".to_string());
        }
    }
}

/// The line for a removed 1.0 `off` mode.
const OFF_LINE: &str = "mode off from 1.0 was not migrated (relaxed applies): run `safe-ai-skill \
     tier off` and confirm it, or set SAFE_AI_SKILL_DISABLE=1 to turn the hooks off";

/// Carry a known profile over as its tier (spec §9): never below `relaxed`, so nothing is
/// pending; `paranoid` raises `tier.json` to `high`.
fn carry_profile(dir: &DataDir, profile: &str, tier: Tier, now: u64, lines: &mut Vec<String>) {
    match profile {
        "paranoid" => {
            let change = tierstate::Change {
                project: None,
                tier: Some(tier),
                env_read: None,
                clear: false,
            };
            if tierstate::apply(dir, &change, now).is_ok() {
                lines.push("profile paranoid is now tier high (applied)".to_string());
            }
        }
        "autopilot" => lines.push(
            "profile autopilot is now tier relaxed (no raised cap); to approve devnet transfers \
             without prompts, run `safe-ai-skill allow --scope transfer --for <duration>` and \
             confirm it"
                .to_string(),
        ),
        _ => lines.push(STRICT_LINE.to_string()),
    }
}

/// Carry an authenticated WS-B `mode.json` over to `tier.json`, once: it is renamed to
/// `mode.json.migrated` (or `.unmigrated` when it fails authentication). Returns one line
/// per item. A trusted data dir only: an untrusted one's state was never applied.
pub fn mode_to_tier(dir: &DataDir, now: u64) -> Vec<String> {
    let path = dir.path.join(MODE_FILE);
    if dir.is_unresolved() || !dir.trusted || std::fs::symlink_metadata(&path).is_err() {
        return Vec::new();
    }
    let mut lines = Vec::new();
    match mode::load(dir) {
        Loaded::Valid(_) if std::fs::symlink_metadata(dir.path.join(TIER_FILE)).is_ok() => {
            // tier.json is newer: the user already chose a tier.
            rename_to(&path, "migrated");
        }
        Loaded::Valid(record) => {
            rename_to(&path, "migrated");
            match mode::profile_tier(&record.profile) {
                Some(tier) => carry_profile(dir, &record.profile, tier, now, &mut lines),
                None => lines.push(OFF_LINE.to_string()),
            }
        }
        Loaded::Tampered => {
            rename_to(&path, "unmigrated");
            lines.push(
                "mode.json failed authentication; not migrated (relaxed applies)".to_string(),
            );
        }
        Loaded::Missing => {}
    }
    lines
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
            lines
                .iter()
                .any(|l| l.contains("autopilot is now tier relaxed")
                    && l.contains("allow --scope transfer")),
            "{lines:?}"
        );
        assert!(lines.iter().any(|l| l.contains("exhausted")), "{lines:?}");
        assert!(
            lines.iter().any(|l| l.contains("2 expired or invalid")),
            "{lines:?}"
        );

        // Nothing is live: no grant, and no tier below relaxed.
        assert!(grants::live(&dir).grants.is_empty());
        assert_eq!(tierstate::user_choice(&dir, Path::new("/p")).tier, None);
        match statefile::load::<SpendLedger>(&dir, SPEND_FILE) {
            Loaded::Valid(l) => assert!(l.is_exhausted()),
            other => panic!("{other:?}"),
        }
        // The requests carry the remaining time and budget; the user confirms them.
        let shown = confirm::announce_pending(&dir, real_now());
        assert_eq!(shown.len(), 1);
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
        statefile::store(&dir, MODE_FILE, &ModeRecord::default()).unwrap();
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
        assert_eq!(tierstate::user_choice(&dir, Path::new("/p")).tier, None);
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
        assert!(lines
            .iter()
            .any(|l| l.contains("mode off") && l.contains("safe-ai-skill tier off")));
        assert!(dir.path.join("grants.json.v1-unmigrated").exists());
        assert!(dir.path.join("mode.json.v1-unmigrated").exists());
        assert_eq!(tierstate::user_choice(&dir, Path::new("/p")).tier, None);
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn paranoid_is_applied_directly() {
        let dir = tmp_data("migrate_paranoid");
        write(&dir, MODE_FILE, r#"{"profile":"paranoid","set_at":5}"#);
        let lines = run(&dir, NOW);
        assert!(lines.iter().any(|l| l.contains("tier high")), "{lines:?}");
        assert_eq!(
            tierstate::user_choice(&dir, Path::new("/p"))
                .tier
                .map(|t| t.0),
            Some(Tier::High)
        );
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn strict_gets_the_one_time_line() {
        let dir = tmp_data("migrate_strict");
        write(&dir, MODE_FILE, r#"{"profile":"strict","set_at":5}"#);
        let lines = run(&dir, NOW);
        assert_eq!(lines, vec![STRICT_LINE.to_string()]);
        assert!(run(&dir, NOW).is_empty());
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn an_authenticated_ws_b_mode_json_becomes_a_tier_once() {
        let dir = tmp_data("migrate_wsb");
        let record = ModeRecord {
            profile: "paranoid".into(),
            set_at: 1,
        };
        statefile::store(&dir, MODE_FILE, &record).unwrap();
        let lines = mode_to_tier(&dir, NOW);
        assert!(lines.iter().any(|l| l.contains("tier high")), "{lines:?}");
        assert!(dir.path.join("mode.json.migrated").exists());
        assert!(mode_to_tier(&dir, NOW).is_empty());
        assert_eq!(
            tierstate::user_choice(&dir, Path::new("/p"))
                .tier
                .map(|t| t.0),
            Some(Tier::High)
        );

        let auto = tmp_data("migrate_wsb_auto");
        let record = ModeRecord {
            profile: "autopilot".into(),
            set_at: 1,
        };
        statefile::store(&auto, MODE_FILE, &record).unwrap();
        let lines = mode_to_tier(&auto, NOW);
        assert!(
            lines.iter().any(|l| l.contains("allow --scope transfer")),
            "{lines:?}"
        );
        assert_eq!(tierstate::user_choice(&auto, Path::new("/p")).tier, None);

        let forged = tmp_data("migrate_wsb_forged");
        write(&forged, MODE_FILE, r#"{"profile":"paranoid","set_at":5}"#);
        statefile::store(&forged, "x.json", &ModeRecord::default()).unwrap();
        let lines = mode_to_tier(&forged, NOW);
        assert!(
            lines.iter().any(|l| l.contains("failed authentication")),
            "{lines:?}"
        );
        for d in [dir, auto, forged] {
            let _ = std::fs::remove_dir_all(&d.path);
        }
    }

    #[test]
    fn nothing_to_migrate_is_silent() {
        let dir = tmp_data("migrate_none");
        assert!(run(&dir, NOW).is_empty());
        let _ = std::fs::remove_dir_all(&dir.path);
    }
}
