//! Daily spend ledger (`${CLAUDE_PLUGIN_DATA}/spend.json`).
//!
//! The ledger tracks SOL spent within the current UTC day. It rolls over (resets to
//! zero) when the UTC date changes. Two evaluation paths are provided so callers can
//! separate *checking* a candidate spend from *committing* it:
//!
//! - [`check`] is pure: given a ledger snapshot, an amount, and a policy, it returns the
//!   [`Decision`] without touching disk. Gates use this to decide whether to allow / ask
//!   / deny a transfer *without* debiting (an `Ask` or `Deny` must not consume budget).
//! - [`record_and_check`] is the committing path: it loads the ledger, rolls the day
//!   over, debits `sol_amount`, persists, and returns the same decision. `main.rs` calls
//!   it only once an action is actually being allowed, so the daily total reflects real
//!   spend.
//!
//! All arithmetic is guarded against `NaN`, negative, and non-finite inputs, and the
//! running total is accumulated with saturating semantics so a corrupt or adversarial
//! ledger value cannot wrap or panic.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::io::Decision;
use crate::policy::Policy;

/// Seconds in a UTC day.
const SECONDS_PER_DAY: u64 = 86_400;

/// Daily spend ledger.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SpendLedger {
    /// Day bucket (epoch days, UTC) the running total belongs to.
    pub day: u64,
    /// SOL spent so far today.
    pub total_sol: f64,
}

impl SpendLedger {
    /// Load the ledger from `${plugin_data}/spend.json`, rolling the day over.
    ///
    /// A missing, empty, or malformed file yields a fresh ledger for the current day.
    /// If the persisted day predates today (UTC), the running total is reset to zero so
    /// the daily cap restarts each calendar day.
    pub fn load(plugin_data: &Path) -> SpendLedger {
        let today = current_epoch_day();
        let mut ledger = read_ledger(plugin_data).unwrap_or_default();
        ledger.roll_over(today);
        ledger
    }

    /// Reset the running total if `today` is a different (later) day than the stored one.
    fn roll_over(&mut self, today: u64) {
        if self.day != today {
            self.day = today;
            self.total_sol = 0.0;
        }
    }

    /// Add `amount` to today's total using a saturating, finite-safe sum.
    ///
    /// Non-finite or negative amounts are treated as zero; the resulting total is clamped
    /// to be finite and non-negative.
    fn add(&mut self, amount: f64) {
        let safe_amount = sanitize_amount(amount);
        let current = sanitize_amount(self.total_sol);
        let sum = current + safe_amount;
        self.total_sol = if sum.is_finite() { sum } else { f64::MAX };
    }

    /// Persist the ledger to `${plugin_data}/spend.json` (write-temp + rename).
    fn save(&self, plugin_data: &Path) -> std::io::Result<()> {
        write_ledger(plugin_data, self)
    }
}

/// Decide a candidate spend of `amount` SOL against the policy caps, given the current
/// `ledger`, WITHOUT mutating or persisting anything.
///
/// Precedence (most restrictive first):
/// - Above `hard_tx_sol_max` → [`Decision::Deny`].
/// - Above `per_tx_sol_max`, OR would push today's running total above `daily_sol_max`
///   → [`Decision::Ask`].
/// - Otherwise → [`Decision::Allow`].
///
/// `amount` is sanitized: a non-finite or negative value is treated as zero.
pub fn check(amount: f64, ledger: &SpendLedger, policy: &Policy) -> Decision {
    let amount = sanitize_amount(amount);
    let caps = &policy.spend;

    if amount > caps.hard_tx_sol_max {
        return Decision::Deny {
            reason: format!(
                "Transfer of {amount} SOL exceeds the hard per-tx cap of {} SOL",
                caps.hard_tx_sol_max
            ),
        };
    }

    if amount > caps.per_tx_sol_max {
        return Decision::Ask {
            reason: format!(
                "Transfer of {amount} SOL exceeds the per-tx cap of {} SOL — approve to proceed",
                caps.per_tx_sol_max
            ),
        };
    }

    let projected = sanitize_amount(ledger.total_sol) + amount;
    if projected > caps.daily_sol_max {
        return Decision::Ask {
            reason: format!(
                "Transfer of {amount} SOL would push today's spend to {projected} SOL, over the daily cap of {} SOL — approve to proceed",
                caps.daily_sol_max
            ),
        };
    }

    Decision::Allow
}

/// Record a SOL spend and decide against per-tx / hard / daily caps.
///
/// Loads the ledger (rolling the day over), evaluates the candidate `sol_amount` via
/// [`check`], and — only when the decision is [`Decision::Allow`] — debits the amount and
/// persists the ledger. `Ask`/`Deny` outcomes never consume daily budget. The committed
/// decision is returned.
///
/// This is the path `main.rs` invokes when an allowed transfer is actually proceeding.
/// Gates that merely need to *predict* a decision should load the ledger and call
/// [`check`] directly to avoid debiting on a prompt.
pub fn record_and_check(plugin_data: &Path, sol_amount: f64, policy: &Policy) -> Decision {
    let mut ledger = SpendLedger::load(plugin_data);
    let decision = check(sol_amount, &ledger, policy);

    if matches!(decision, Decision::Allow) {
        ledger.add(sol_amount);
        // Best-effort persist: a write failure must not turn an allow into a block.
        let _ = ledger.save(plugin_data);
    }

    decision
}

/// Commit a SOL spend to today's ledger WITHOUT re-deciding (load → add → save).
///
/// `main.rs` calls this exactly once, after the *final* (post-relaxation) decision for a
/// transfer is [`Decision::Allow`], to debit the daily ledger. The gate already evaluated
/// the candidate with the non-committing [`check`], so committing here neither re-runs the
/// decision nor double-counts. A persist failure is swallowed (best-effort) so a disk error
/// can never escalate an allowed action into a block.
pub fn commit(plugin_data: &Path, sol_amount: f64) {
    let mut ledger = SpendLedger::load(plugin_data);
    ledger.add(sol_amount);
    let _ = ledger.save(plugin_data);
}

/// Coerce an amount to a finite, non-negative `f64` (non-finite / negative → `0.0`).
fn sanitize_amount(amount: f64) -> f64 {
    if amount.is_finite() && amount > 0.0 {
        amount
    } else {
        0.0
    }
}

/// Current epoch day (UTC). `0` on clock error; never panics.
fn current_epoch_day() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() / SECONDS_PER_DAY)
        .unwrap_or(0)
}

/// Read and deserialize the ledger file. `None` on any I/O or parse failure.
fn read_ledger(plugin_data: &Path) -> Option<SpendLedger> {
    let path = plugin_data.join("spend.json");
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

/// Persist the ledger atomically: write to a temp file, then rename over the target.
fn write_ledger(plugin_data: &Path, ledger: &SpendLedger) -> std::io::Result<()> {
    std::fs::create_dir_all(plugin_data)?;
    let path = plugin_data.join("spend.json");
    let tmp = plugin_data.join("spend.json.tmp");
    let body = serde_json::to_string(ledger).map_err(std::io::Error::other)?;
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, &path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;

    fn policy_with_caps(per_tx: f64, hard_tx: f64, daily: f64) -> Policy {
        let mut p = Policy::default();
        p.spend.per_tx_sol_max = per_tx;
        p.spend.hard_tx_sol_max = hard_tx;
        p.spend.daily_sol_max = daily;
        p
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ssai_spend_{}_{}_{}",
            tag,
            std::process::id(),
            current_epoch_day()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn under_per_tx_cap_allows() {
        let policy = policy_with_caps(1.0, 10.0, 5.0);
        let ledger = SpendLedger {
            day: current_epoch_day(),
            total_sol: 0.0,
        };
        assert_eq!(check(0.5, &ledger, &policy), Decision::Allow);
    }

    #[test]
    fn over_per_tx_cap_asks() {
        let policy = policy_with_caps(1.0, 10.0, 5.0);
        let ledger = SpendLedger {
            day: current_epoch_day(),
            total_sol: 0.0,
        };
        assert!(matches!(check(2.0, &ledger, &policy), Decision::Ask { .. }));
    }

    #[test]
    fn over_hard_cap_denies() {
        let policy = policy_with_caps(1.0, 10.0, 5.0);
        let ledger = SpendLedger {
            day: current_epoch_day(),
            total_sol: 0.0,
        };
        assert!(matches!(
            check(50.0, &ledger, &policy),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn cumulative_over_daily_cap_asks() {
        let policy = policy_with_caps(1.0, 10.0, 5.0);
        // Already spent 4.8 today; a 0.5 tx (under per-tx) pushes to 5.3 > 5.0 daily.
        let ledger = SpendLedger {
            day: current_epoch_day(),
            total_sol: 4.8,
        };
        assert!(matches!(check(0.5, &ledger, &policy), Decision::Ask { .. }));
    }

    #[test]
    fn at_daily_cap_boundary_allows() {
        let policy = policy_with_caps(1.0, 10.0, 5.0);
        // 4.5 + 0.5 = 5.0, exactly at the cap (not over) → allow.
        let ledger = SpendLedger {
            day: current_epoch_day(),
            total_sol: 4.5,
        };
        assert_eq!(check(0.5, &ledger, &policy), Decision::Allow);
    }

    #[test]
    fn record_and_check_debits_only_on_allow() {
        let dir = temp_dir("debit_allow");
        let policy = policy_with_caps(1.0, 10.0, 5.0);

        // Allowed spend debits the ledger.
        assert_eq!(record_and_check(&dir, 0.5, &policy), Decision::Allow);
        let ledger = SpendLedger::load(&dir);
        assert!((ledger.total_sol - 0.5).abs() < 1e-9);

        // An over-cap ask does NOT debit.
        assert!(matches!(
            record_and_check(&dir, 2.0, &policy),
            Decision::Ask { .. }
        ));
        let ledger = SpendLedger::load(&dir);
        assert!((ledger.total_sol - 0.5).abs() < 1e-9);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn record_accumulates_toward_daily_cap() {
        let dir = temp_dir("accumulate");
        let policy = policy_with_caps(1.0, 10.0, 2.0);

        assert_eq!(record_and_check(&dir, 0.9, &policy), Decision::Allow);
        assert_eq!(record_and_check(&dir, 0.9, &policy), Decision::Allow);
        // 0.9 + 0.9 = 1.8; another 0.9 → 2.7 > 2.0 daily cap → ask, no debit.
        assert!(matches!(
            record_and_check(&dir, 0.9, &policy),
            Decision::Ask { .. }
        ));
        let ledger = SpendLedger::load(&dir);
        assert!((ledger.total_sol - 1.8).abs() < 1e-9);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn date_rollover_resets_total() {
        let mut ledger = SpendLedger {
            day: current_epoch_day().saturating_sub(1),
            total_sol: 4.0,
        };
        ledger.roll_over(current_epoch_day());
        assert_eq!(ledger.day, current_epoch_day());
        assert_eq!(ledger.total_sol, 0.0);
    }

    #[test]
    fn same_day_does_not_reset() {
        let today = current_epoch_day();
        let mut ledger = SpendLedger {
            day: today,
            total_sol: 3.0,
        };
        ledger.roll_over(today);
        assert_eq!(ledger.total_sol, 3.0);
    }

    #[test]
    fn load_rolls_over_stale_persisted_day() {
        let dir = temp_dir("rollover_load");
        // Persist a ledger dated yesterday with a non-zero total.
        std::fs::create_dir_all(&dir).unwrap();
        let stale = SpendLedger {
            day: current_epoch_day().saturating_sub(1),
            total_sol: 9.0,
        };
        std::fs::write(
            dir.join("spend.json"),
            serde_json::to_string(&stale).unwrap(),
        )
        .unwrap();

        let ledger = SpendLedger::load(&dir);
        assert_eq!(ledger.day, current_epoch_day());
        assert_eq!(ledger.total_sol, 0.0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn non_finite_and_negative_amounts_are_zeroed() {
        let policy = policy_with_caps(1.0, 10.0, 5.0);
        let ledger = SpendLedger {
            day: current_epoch_day(),
            total_sol: 0.0,
        };
        assert_eq!(check(f64::NAN, &ledger, &policy), Decision::Allow);
        assert_eq!(check(-3.0, &ledger, &policy), Decision::Allow);
        assert_eq!(check(f64::INFINITY, &ledger, &policy), Decision::Allow);
    }

    #[test]
    fn add_saturates_on_overflow() {
        let mut ledger = SpendLedger {
            day: current_epoch_day(),
            total_sol: f64::MAX,
        };
        ledger.add(f64::MAX);
        assert!(ledger.total_sol.is_finite());
    }

    #[test]
    fn malformed_ledger_file_yields_fresh() {
        let dir = temp_dir("malformed");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("spend.json"), "not json").unwrap();
        let ledger = SpendLedger::load(&dir);
        assert_eq!(ledger.total_sol, 0.0);
        assert_eq!(ledger.day, current_epoch_day());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
