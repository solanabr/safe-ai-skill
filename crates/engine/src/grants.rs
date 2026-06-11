//! Scoped, expiring, audited grants (`${CLAUDE_PLUGIN_DATA}/grants.json`).
//!
//! A grant is a user-issued escape hatch that lets the relaxation layer upgrade an `Ask`
//! into an `Allow` for actions matching its scope, within a budget and before it expires.
//! Hard guards are never relaxable, so a grant cannot cover them.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::gate::{GateMeta, Scope};

/// A single scoped grant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    /// Opaque grant id.
    pub id: String,
    /// Scope this grant applies to.
    pub scope: Scope,
    /// Program ids this grant is restricted to (empty = any).
    pub programs: Vec<String>,
    /// Destination addresses this grant is restricted to (empty = any).
    pub to: Vec<String>,
    /// Maximum SOL per matched transaction.
    pub max_tx_sol: f64,
    /// Total SOL budget for the grant.
    pub budget_sol: f64,
    /// SOL already spent against this grant.
    pub spent_sol: f64,
    /// Expiry as epoch seconds.
    pub expires_at: u64,
    /// Whether this grant covers an explicitly dangerous action the user opted into.
    pub danger: bool,
}

impl Grant {
    /// Whether this grant has expired as of `now` (epoch seconds).
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }

    /// SOL remaining in this grant's budget (never negative; guards `NaN`).
    ///
    /// A non-finite or negative `spent_sol`/`budget_sol` yields `0.0` rather than a bogus
    /// remaining, so a corrupt grant can never authorize spend.
    pub fn remaining_sol(&self) -> f64 {
        if !self.budget_sol.is_finite() || self.budget_sol < 0.0 {
            return 0.0;
        }
        let spent = if self.spent_sol.is_finite() && self.spent_sol >= 0.0 {
            self.spent_sol
        } else {
            self.budget_sol
        };
        (self.budget_sol - spent).max(0.0)
    }

    /// Whether `amount_sol` is permitted by this grant's per-tx cap and remaining budget.
    ///
    /// A missing amount (`None`) is treated as `0.0` (informational gate with no parseable
    /// value): it passes the caps but consumes no budget. A non-finite or negative amount is
    /// rejected.
    fn permits_amount(&self, amount_sol: Option<f64>) -> bool {
        let amount = amount_sol.unwrap_or(0.0);
        if !amount.is_finite() || amount < 0.0 {
            return false;
        }
        if self.max_tx_sol.is_finite() && self.max_tx_sol >= 0.0 && amount > self.max_tx_sol {
            return false;
        }
        amount <= self.remaining_sol()
    }

    /// Whether this grant matches `meta` ignoring expiry (caller checks expiry).
    fn matches(&self, meta: &GateMeta) -> bool {
        if self.scope != meta.scope {
            return false;
        }
        // Program restriction (empty = any).
        if !self.programs.is_empty() {
            match meta.program.as_deref() {
                Some(p) if self.programs.iter().any(|allowed| allowed == p) => {}
                _ => return false,
            }
        }
        // Destination restriction (empty = any).
        if !self.to.is_empty() {
            match meta.destination.as_deref() {
                Some(d) if self.to.iter().any(|allowed| allowed == d) => {}
                _ => return false,
            }
        }
        self.permits_amount(meta.amount_sol)
    }

    /// Build a grant from parsed `allow`-subcommand arguments.
    ///
    /// `for_dur` is a human duration (`30m`, `2h`, `90s`, `1d`); `expires_at` is computed as
    /// `now + parsed_seconds`. A CSV `programs`/`to` string is split on commas and trimmed;
    /// empty entries are dropped. Returns `None` if the scope or duration cannot be parsed.
    #[allow(clippy::too_many_arguments)]
    pub fn from_args(
        scope: &str,
        for_dur: &str,
        max_tx_sol: f64,
        budget_sol: f64,
        programs_csv: &str,
        to_csv: &str,
        danger: bool,
        now: u64,
    ) -> Option<Grant> {
        let secs = parse_duration_secs(for_dur)?;
        let expires_at = now.checked_add(secs)?;
        let scope = Scope::from_label(scope);
        Some(Grant {
            id: new_id(now),
            scope,
            programs: split_csv(programs_csv),
            to: split_csv(to_csv),
            max_tx_sol,
            budget_sol,
            spent_sol: 0.0,
            expires_at,
            danger,
        })
    }
}

/// All active grants, persisted as a JSON object under `grants.json`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Grants {
    /// The grants.
    pub grants: Vec<Grant>,
}

/// Load grants from `${plugin_data}/grants.json` (missing/corrupt → empty).
pub fn load(plugin_data: &Path) -> Grants {
    let path = plugin_data.join("grants.json");
    match std::fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
        Err(_) => Grants::default(),
    }
}

/// Persist grants to `${plugin_data}/grants.json` (write-temp + rename).
pub fn save(plugin_data: &Path, grants: &Grants) -> std::io::Result<()> {
    std::fs::create_dir_all(plugin_data)?;
    let path = plugin_data.join("grants.json");
    let tmp = plugin_data.join("grants.json.tmp");
    let body = serde_json::to_string(grants).map_err(std::io::Error::other)?;
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, &path)
}

/// Find a non-expired grant matching `meta` (scope + program/destination + within caps).
///
/// Returns the first matching grant. Expiry is checked against the current wall clock.
pub fn find_match<'a>(grants: &'a Grants, meta: &GateMeta) -> Option<&'a Grant> {
    let now = now_secs();
    find_match_at(grants, meta, now)
}

/// [`find_match`] with an explicit `now`, for deterministic tests.
pub fn find_match_at<'a>(grants: &'a Grants, meta: &GateMeta, now: u64) -> Option<&'a Grant> {
    grants
        .grants
        .iter()
        .find(|g| !g.is_expired(now) && g.matches(meta))
}

/// Debit `sol_amount` from the grant with `grant_id`, persisting the result.
///
/// Uses checked floating-point accumulation: a non-finite or negative `sol_amount` is
/// rejected, and the running `spent_sol` is clamped so it never exceeds the budget. A
/// missing grant id is a no-op (returns `Ok`).
pub fn debit(plugin_data: &Path, grant_id: &str, sol_amount: f64) -> std::io::Result<()> {
    if !sol_amount.is_finite() || sol_amount < 0.0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "debit amount must be a finite, non-negative SOL value",
        ));
    }
    let mut grants = load(plugin_data);
    let mut changed = false;
    for g in &mut grants.grants {
        if g.id == grant_id {
            let prior = if g.spent_sol.is_finite() && g.spent_sol >= 0.0 {
                g.spent_sol
            } else {
                0.0
            };
            // Saturating add then clamp to budget (never overshoot, never NaN).
            let next = prior + sol_amount;
            let next = if next.is_finite() { next } else { f64::MAX };
            g.spent_sol = if g.budget_sol.is_finite() && g.budget_sol >= 0.0 {
                next.min(g.budget_sol)
            } else {
                next
            };
            changed = true;
            break;
        }
    }
    if changed {
        save(plugin_data, &grants)?;
    }
    Ok(())
}

/// Drop expired grants and persist; returns the number removed.
pub fn cleanup_expired(plugin_data: &Path) -> usize {
    let now = now_secs();
    let mut grants = load(plugin_data);
    let before = grants.grants.len();
    grants.grants.retain(|g| !g.is_expired(now));
    let removed = before - grants.grants.len();
    if removed > 0 {
        let _ = save(plugin_data, &grants);
    }
    removed
}

/// Split a CSV string into trimmed, non-empty entries.
fn split_csv(csv: &str) -> Vec<String> {
    csv.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Parse a human duration like `30m`, `2h`, `90s`, `7d`, or a bare number (seconds).
///
/// Supported suffixes: `s` (seconds), `m` (minutes), `h` (hours), `d` (days). The numeric
/// part must be a non-negative integer. Returns `None` on any malformed input or on overflow.
pub fn parse_duration_secs(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num_str, mult) = match s.as_bytes().last() {
        Some(b's') | Some(b'S') => (&s[..s.len() - 1], 1u64),
        Some(b'm') | Some(b'M') => (&s[..s.len() - 1], 60u64),
        Some(b'h') | Some(b'H') => (&s[..s.len() - 1], 3_600u64),
        Some(b'd') | Some(b'D') => (&s[..s.len() - 1], 86_400u64),
        Some(c) if c.is_ascii_digit() => (s, 1u64),
        _ => return None,
    };
    let n: u64 = num_str.trim().parse().ok()?;
    n.checked_mul(mult)
}

/// Generate a short, time-seeded grant id.
fn new_id(now: u64) -> String {
    format!("grant-{now:x}")
}

/// Current time in epoch seconds (0 on clock error; never panics).
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ssai_grants_{}_{}_{}",
            tag,
            std::process::id(),
            now_secs()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn transfer_grant(id: &str, expires_at: u64) -> Grant {
        Grant {
            id: id.to_string(),
            scope: Scope::Transfer,
            programs: vec![],
            to: vec![],
            max_tx_sol: 1.0,
            budget_sol: 5.0,
            spent_sol: 0.0,
            expires_at,
            danger: false,
        }
    }

    fn transfer_meta(amount: Option<f64>) -> GateMeta {
        GateMeta {
            scope: Scope::Transfer,
            amount_sol: amount,
            program: None,
            destination: None,
            hard_guard: false,
        }
    }

    #[test]
    fn parse_duration_forms() {
        assert_eq!(parse_duration_secs("30m"), Some(1_800));
        assert_eq!(parse_duration_secs("2h"), Some(7_200));
        assert_eq!(parse_duration_secs("90s"), Some(90));
        assert_eq!(parse_duration_secs("1d"), Some(86_400));
        assert_eq!(parse_duration_secs("45"), Some(45));
        assert_eq!(parse_duration_secs(""), None);
        assert_eq!(parse_duration_secs("m"), None);
        assert_eq!(parse_duration_secs("abc"), None);
        assert_eq!(parse_duration_secs("-5m"), None);
    }

    #[test]
    fn match_by_scope_and_budget() {
        let grants = Grants {
            grants: vec![transfer_grant("g1", 10_000)],
        };
        // matching scope + amount within cap
        assert!(find_match_at(&grants, &transfer_meta(Some(0.5)), 100).is_some());
        // amount over per-tx cap
        assert!(find_match_at(&grants, &transfer_meta(Some(2.0)), 100).is_none());
        // wrong scope
        let swap = GateMeta {
            scope: Scope::Swap,
            amount_sol: Some(0.1),
            program: None,
            destination: None,
            hard_guard: false,
        };
        assert!(find_match_at(&grants, &swap, 100).is_none());
    }

    #[test]
    fn no_match_when_expired() {
        let grants = Grants {
            grants: vec![transfer_grant("g1", 50)],
        };
        // now (100) is past expiry (50)
        assert!(find_match_at(&grants, &transfer_meta(Some(0.5)), 100).is_none());
    }

    #[test]
    fn match_respects_program_and_destination() {
        let mut g = transfer_grant("g1", 10_000);
        g.programs = vec!["ProgA".into()];
        g.to = vec!["DestA".into()];
        let grants = Grants { grants: vec![g] };

        let mut meta = transfer_meta(Some(0.5));
        meta.program = Some("ProgA".into());
        meta.destination = Some("DestA".into());
        assert!(find_match_at(&grants, &meta, 100).is_some());

        meta.destination = Some("DestB".into());
        assert!(find_match_at(&grants, &meta, 100).is_none());
    }

    #[test]
    fn budget_exhaustion_blocks_match() {
        let mut g = transfer_grant("g1", 10_000);
        g.budget_sol = 1.0;
        g.spent_sol = 1.0;
        let grants = Grants { grants: vec![g] };
        // remaining is 0, so even a tiny amount fails the budget check
        assert!(find_match_at(&grants, &transfer_meta(Some(0.1)), 100).is_none());
    }

    #[test]
    fn debit_is_checked_and_clamped() {
        let dir = tmp_dir("debit");
        let grants = Grants {
            grants: vec![transfer_grant("g1", 10_000)],
        };
        save(&dir, &grants).unwrap();

        debit(&dir, "g1", 2.0).unwrap();
        let after = load(&dir);
        assert_eq!(after.grants[0].spent_sol, 2.0);

        // Debiting past the budget clamps to budget_sol, never overshoots.
        debit(&dir, "g1", 100.0).unwrap();
        let after = load(&dir);
        assert_eq!(after.grants[0].spent_sol, 5.0);

        // Negative / non-finite debits are rejected.
        assert!(debit(&dir, "g1", -1.0).is_err());
        assert!(debit(&dir, "g1", f64::NAN).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn debit_missing_grant_is_noop() {
        let dir = tmp_dir("debit_missing");
        save(&dir, &Grants::default()).unwrap();
        assert!(debit(&dir, "nope", 1.0).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cleanup_drops_expired_only() {
        let dir = tmp_dir("cleanup");
        let grants = Grants {
            grants: vec![transfer_grant("old", 50), transfer_grant("live", u64::MAX)],
        };
        save(&dir, &grants).unwrap();
        let removed = cleanup_expired(&dir);
        // "old" expired in the past; "live" survives.
        assert_eq!(removed, 1);
        let after = load(&dir);
        assert_eq!(after.grants.len(), 1);
        assert_eq!(after.grants[0].id, "live");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn from_args_builds_grant() {
        let g = Grant::from_args(
            "transfer",
            "30m",
            1.5,
            10.0,
            "ProgA, ProgB",
            "DestA",
            false,
            1_000,
        )
        .unwrap();
        assert_eq!(g.scope, Scope::Transfer);
        assert_eq!(g.expires_at, 1_000 + 1_800);
        assert_eq!(g.programs, vec!["ProgA".to_string(), "ProgB".to_string()]);
        assert_eq!(g.to, vec!["DestA".to_string()]);
        assert_eq!(g.max_tx_sol, 1.5);
        assert_eq!(g.budget_sol, 10.0);
        assert_eq!(g.spent_sol, 0.0);

        // Bad duration → None.
        assert!(Grant::from_args("transfer", "nope", 1.0, 1.0, "", "", false, 0).is_none());
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = tmp_dir("roundtrip");
        let grants = Grants {
            grants: vec![transfer_grant("g1", 999)],
        };
        save(&dir, &grants).unwrap();
        let loaded = load(&dir);
        assert_eq!(loaded.grants.len(), 1);
        assert_eq!(loaded.grants[0].id, "g1");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
