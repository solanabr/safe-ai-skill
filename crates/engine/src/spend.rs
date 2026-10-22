//! Daily spend ledger (`${CLAUDE_PLUGIN_DATA}/spend.json`, authenticated, spec D4.2).
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
//! `spend.json` is a [`crate::statefile`] envelope. A ledger that fails authentication, or
//! one missing once the state key exists (it was deleted), means **today's budget is
//! exhausted**: [`SpendLedger::load`] replaces it with an exhausted ledger dated today, so the
//! next UTC day starts fresh. With no state key there was never an authenticated ledger, so a
//! missing one is zero spent and is created then, only if still absent
//! ([`statefile::store_new`]). The audit log does not count: hooks write it before any state
//! file exists, and counting it exhausted the budget of every fresh install whose first hook
//! was not a within-cap transfer. A 1.0 ledger is migrated to an exhausted one
//! ([`store_exhausted`]). [`on_key_created`] starts the ledger at zero when any other state
//! file creates the key first, so the ledger always exists once the key does. The data dir's
//! trust does not matter here: a ledger can only tighten.
//!
//! All arithmetic is guarded against `NaN`, negative, and non-finite inputs, and the
//! running total is accumulated with saturating semantics so a corrupt or adversarial
//! ledger value cannot wrap or panic.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::audit::{self, AuditEntry};
use crate::context::Network;
use crate::datadir::DataDir;
use crate::gate::{AllowReason, Verdict};
use crate::io::Decision;
use crate::policy::Policy;
use crate::statefile::{self, Loaded};

/// Seconds in a UTC day.
const SECONDS_PER_DAY: u64 = 86_400;

/// State file holding the ledger.
pub const SPEND_FILE: &str = "spend.json";

/// The running total of an exhausted ledger: no spend fits under any daily cap.
pub const EXHAUSTED_SOL: f64 = f64::MAX;

/// What [`ledger_state`] found on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerState {
    /// An authenticated ledger.
    Valid,
    /// No ledger and no state key: no authenticated ledger ever existed (a new install).
    Fresh,
    /// No ledger although the state key exists: deleted.
    Deleted,
    /// The ledger failed authentication.
    Tampered,
}

/// Daily spend ledger.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SpendLedger {
    /// Day bucket (epoch days, UTC) the running total belongs to.
    pub day: u64,
    /// SOL spent so far today.
    pub total_sol: f64,
}

impl SpendLedger {
    /// Load the authenticated ledger from `${plugin_data}/spend.json`, rolling the day over.
    ///
    /// A brand-new install stores and returns a fresh ledger. A ledger that is missing
    /// otherwise or fails authentication is replaced by one exhausted for today (audited), and
    /// that is returned: no further spend fits today, and the next day rolls it over.
    pub fn load(plugin_data: &Path) -> SpendLedger {
        let today = current_epoch_day();
        let dir = state_dir(plugin_data);
        let (state, ledger) = read_ledger(&dir);
        let mut ledger = match (state, ledger) {
            (LedgerState::Valid, Some(l)) => l,
            (LedgerState::Fresh, _) | (LedgerState::Valid, None) => {
                let fresh = SpendLedger {
                    day: today,
                    total_sol: 0.0,
                };
                match statefile::store_new(&dir, SPEND_FILE, &fresh) {
                    // Another process created it first: use what it stored.
                    Ok(false) => match read_ledger(&dir) {
                        (LedgerState::Valid, Some(l)) => l,
                        _ => SpendLedger {
                            day: today,
                            total_sol: EXHAUSTED_SOL,
                        },
                    },
                    Ok(true) | Err(_) => fresh,
                }
            }
            (LedgerState::Deleted | LedgerState::Tampered, _) => {
                let exhausted = SpendLedger {
                    day: today,
                    total_sol: EXHAUSTED_SOL,
                };
                let what = if state == LedgerState::Deleted {
                    "missing"
                } else {
                    "failed authentication"
                };
                let entry = AuditEntry::new(
                    "",
                    "safe-ai-skill",
                    "state_tamper",
                    "ask",
                    format!("spend.json {what}; today's budget treated as exhausted"),
                    "",
                );
                let _ = audit::append(&entry, plugin_data);
                let _ = exhausted.save(plugin_data);
                exhausted
            }
        };
        ledger.roll_over(today);
        ledger
    }

    /// Whether this ledger was exhausted because the stored one was missing or tampered.
    pub fn is_exhausted(&self) -> bool {
        self.total_sol >= EXHAUSTED_SOL
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

    /// Persist the ledger to `${plugin_data}/spend.json` as an authenticated envelope.
    fn save(&self, plugin_data: &Path) -> std::io::Result<()> {
        statefile::store(&state_dir(plugin_data), SPEND_FILE, self)
            .map_err(|e| std::io::Error::other(e.to_string()))
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

    if ledger.is_exhausted() {
        return Decision::Ask {
            reason: "Today's spend ledger was missing or failed authentication, so the daily \
                     budget is treated as exhausted — approve to proceed"
                .to_string(),
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

/// The gate verdict for a transfer of `amount` SOL on `network` (predict-only, like [`check`]).
///
/// Over a cap, [`check`] decides on any cluster. Within the caps this is the only place that
/// mints [`AllowReason::WithinCapTestnet`] (spec D1.1(ii)), and only for a positively
/// identified devnet/testnet/localnet; mainnet and an unidentified network ask.
pub fn verdict(amount: f64, ledger: &SpendLedger, policy: &Policy, network: Network) -> Verdict {
    match check(amount, ledger, policy) {
        Decision::Deny { reason } => Verdict::Deny(reason),
        Decision::Ask { reason } => Verdict::Ask(reason),
        Decision::Allow | Decision::Defer => match network {
            Network::Devnet | Network::Testnet | Network::Localnet => {
                Verdict::Allow(AllowReason::WithinCapTestnet)
            }
            Network::Mainnet => Verdict::Ask("Mainnet transfer — approve to proceed".to_string()),
            Network::Unknown => {
                Verdict::Ask("Transfer on an unidentified network — approve to proceed".to_string())
            }
        },
    }
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

/// The data dir as [`statefile`] wants it. Trust is irrelevant to a ledger (it only
/// tightens), so it is not resolved.
fn state_dir(plugin_data: &Path) -> DataDir {
    DataDir {
        path: plugin_data.to_path_buf(),
        trusted: false,
    }
}

/// What is on disk for the ledger, without repairing anything.
pub fn ledger_state(plugin_data: &Path) -> LedgerState {
    read_ledger(&state_dir(plugin_data)).0
}

/// Load the ledger envelope and classify it.
fn read_ledger(dir: &DataDir) -> (LedgerState, Option<SpendLedger>) {
    match statefile::load::<SpendLedger>(dir, SPEND_FILE) {
        Loaded::Valid(l) => (LedgerState::Valid, Some(l)),
        Loaded::Tampered => (LedgerState::Tampered, None),
        Loaded::Missing if dir.is_unresolved() => (LedgerState::Tampered, None),
        Loaded::Missing => {
            let key = dir.path.join(statefile::KEY_FILE);
            if std::fs::symlink_metadata(key).is_ok() {
                (LedgerState::Deleted, None)
            } else {
                (LedgerState::Fresh, None)
            }
        }
    }
}

/// Called by [`statefile::store`] when storing `name` just created the state key: start the
/// ledger now at zero (no key means no authenticated ledger ever existed), so a ledger missing
/// later always means deleted.
pub fn on_key_created(dir: &DataDir, name: &str) {
    if name == SPEND_FILE
        || !matches!(
            statefile::load::<SpendLedger>(dir, SPEND_FILE),
            Loaded::Missing
        )
    {
        return;
    }
    let ledger = SpendLedger {
        day: current_epoch_day(),
        total_sol: 0.0,
    };
    let _ = statefile::store_new(dir, SPEND_FILE, &ledger);
}

/// Store an exhausted ledger dated today (used for a 1.0 ledger at migration).
pub fn store_exhausted(plugin_data: &Path) -> std::io::Result<()> {
    SpendLedger {
        day: current_epoch_day(),
        total_sol: EXHAUSTED_SOL,
    }
    .save(plugin_data)
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
            "safe_ai_skill_spend_{}_{}_{}",
            tag,
            std::process::id(),
            current_epoch_day()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn verdict_allows_within_cap_only_on_a_positively_identified_test_cluster() {
        use crate::context::Network;
        use crate::gate::{AllowReason, Verdict};
        let policy = policy_with_caps(1.0, 10.0, 5.0);
        let ledger = SpendLedger {
            day: current_epoch_day(),
            total_sol: 0.0,
        };
        for net in [Network::Devnet, Network::Testnet, Network::Localnet] {
            assert_eq!(
                verdict(0.5, &ledger, &policy, net),
                Verdict::Allow(AllowReason::WithinCapTestnet)
            );
        }
        assert_eq!(
            verdict(0.5, &ledger, &policy, Network::Mainnet),
            Verdict::Ask("Mainnet transfer — approve to proceed".into())
        );
        assert_eq!(
            verdict(0.5, &ledger, &policy, Network::Unknown),
            Verdict::Ask("Transfer on an unidentified network — approve to proceed".into())
        );
        // Over a cap the cap decides, on any cluster.
        assert!(matches!(
            verdict(2.0, &ledger, &policy, Network::Devnet),
            Verdict::Ask(_)
        ));
        assert!(matches!(
            verdict(20.0, &ledger, &policy, Network::Devnet),
            Verdict::Deny(_)
        ));
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
        let stale = SpendLedger {
            day: current_epoch_day().saturating_sub(1),
            total_sol: 9.0,
        };
        stale.save(&dir).unwrap();

        let ledger = SpendLedger::load(&dir);
        assert_eq!(ledger.day, current_epoch_day());
        assert_eq!(ledger.total_sol, 0.0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn first_run_starts_a_fresh_authenticated_ledger() {
        let dir = temp_dir("first_run");
        assert_eq!(ledger_state(&dir), LedgerState::Fresh);
        let ledger = SpendLedger::load(&dir);
        assert_eq!(ledger.total_sol, 0.0);
        assert!(!ledger.is_exhausted());
        // It was stored (and the key created), so a later deletion is detectable.
        assert_eq!(ledger_state(&dir), LedgerState::Valid);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_audit_log_without_a_state_key_is_still_a_fresh_install() {
        // Hooks write the audit log before any state file: that must not spend the budget.
        let dir = temp_dir("audit_first");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("audit.jsonl"), "{}\n").unwrap();
        assert_eq!(ledger_state(&dir), LedgerState::Fresh);
        let policy = policy_with_caps(1.0, 10.0, 5.0);
        assert_eq!(record_and_check(&dir, 0.5, &policy), Decision::Allow);
        let ledger = SpendLedger::load(&dir);
        assert!(!ledger.is_exhausted());
        assert_eq!(ledger.total_sol, 0.5);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn another_state_file_creating_the_key_starts_the_ledger_at_zero() {
        let dir = temp_dir("key_first");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("audit.jsonl"), "{}\n").unwrap();
        statefile::store(&state_dir(&dir), "grants.json", &serde_json::json!({})).unwrap();
        assert_eq!(ledger_state(&dir), LedgerState::Valid);
        assert_eq!(SpendLedger::load(&dir).total_sol, 0.0);
        // Once the key exists, a missing ledger is a deleted one.
        std::fs::remove_file(dir.join(SPEND_FILE)).unwrap();
        assert_eq!(ledger_state(&dir), LedgerState::Deleted);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn creating_a_fresh_ledger_never_overwrites_one_stored_meanwhile() {
        let dir = temp_dir("store_new");
        let spent = SpendLedger {
            day: current_epoch_day(),
            total_sol: 3.0,
        };
        assert!(statefile::store_new(&state_dir(&dir), SPEND_FILE, &spent).unwrap());
        let zero = SpendLedger {
            day: current_epoch_day(),
            total_sol: 0.0,
        };
        assert!(!statefile::store_new(&state_dir(&dir), SPEND_FILE, &zero).unwrap());
        assert_eq!(SpendLedger::load(&dir).total_sol, 3.0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn deleted_ledger_exhausts_todays_budget() {
        let dir = temp_dir("deleted");
        let policy = policy_with_caps(1.0, 10.0, 5.0);
        assert_eq!(record_and_check(&dir, 0.5, &policy), Decision::Allow);
        std::fs::remove_file(dir.join(SPEND_FILE)).unwrap();
        assert_eq!(ledger_state(&dir), LedgerState::Deleted);

        let ledger = SpendLedger::load(&dir);
        assert!(ledger.is_exhausted());
        match check(0.1, &ledger, &policy) {
            Decision::Ask { reason } => assert!(reason.contains("exhausted"), "{reason}"),
            other => panic!("expected ask, got {other:?}"),
        }
        // The repair is stored and audited.
        assert_eq!(ledger_state(&dir), LedgerState::Valid);
        let audit = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
        assert!(audit.contains("state_tamper"), "{audit}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tampered_ledger_exhausts_today_and_rolls_over_tomorrow() {
        let dir = temp_dir("tampered");
        SpendLedger {
            day: current_epoch_day(),
            total_sol: 4.0,
        }
        .save(&dir)
        .unwrap();
        // Hand-edit the total down to zero.
        let path = dir.join(SPEND_FILE);
        let edited = std::fs::read_to_string(&path)
            .unwrap()
            .replace("\"total_sol\":4.0", "\"total_sol\":0.0");
        std::fs::write(&path, edited).unwrap();
        assert_eq!(ledger_state(&dir), LedgerState::Tampered);

        let ledger = SpendLedger::load(&dir);
        assert!(ledger.is_exhausted());
        let policy = policy_with_caps(1.0, 10.0, 5.0);
        assert!(matches!(check(0.1, &ledger, &policy), Decision::Ask { .. }));

        // Tomorrow the repaired (exhausted, dated today) ledger rolls over.
        let mut stored = match statefile::load::<SpendLedger>(&state_dir(&dir), SPEND_FILE) {
            Loaded::Valid(l) => l,
            other => panic!("expected a repaired ledger, got {other:?}"),
        };
        assert_eq!(stored.day, current_epoch_day());
        stored.roll_over(current_epoch_day() + 1);
        assert_eq!(stored.total_sol, 0.0);
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
    fn malformed_ledger_file_is_exhausted() {
        let dir = temp_dir("malformed");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("spend.json"), "not json").unwrap();
        let ledger = SpendLedger::load(&dir);
        assert!(ledger.is_exhausted());
        assert_eq!(ledger.day, current_epoch_day());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_plain_v1_ledger_is_not_trusted() {
        let dir = temp_dir("v1");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("spend.json"),
            format!("{{\"day\":{},\"total_sol\":0.0}}", current_epoch_day()),
        )
        .unwrap();
        assert!(SpendLedger::load(&dir).is_exhausted());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
