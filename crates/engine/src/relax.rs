//! Relaxation layer: turn an `Ask` into an `Allow` when a grant permits it.
//!
//! Centralizes all grant-driven relaxation so gates stay pure. `main.rs` calls [`apply`] on
//! every gate result before auditing and emitting. Hard guards
//! ([`crate::gate::GateMeta::hard_guard`]) are NEVER relaxed.
//!
//! ## Profile vs grant split
//!
//! Relaxation has two halves and they DO NOT overlap:
//!
//! 1. **Profile half** — lives in [`crate::policy::Policy::effective`]. The active profile
//!    (`autopilot`/`paranoid`/...) adjusts caps and sets the `relax_transfer`/`relax_swap`
//!    flags. `main.rs` applies `.effective()` BEFORE the gate runs, so the gate's *natural*
//!    decision already reflects the profile (e.g. a routine transfer under the autopilot cap
//!    is `Allow` straight from the gate, never reaching here as an `Ask`).
//! 2. **Grant half** — lives HERE. A time-boxed, budgeted [`crate::grants::Grant`] can
//!    upgrade a residual `Ask` to `Allow` and debit its budget.
//!
//! `apply` therefore never re-applies profile logic — it only consults grants. This avoids
//! double-relaxation: the profile cannot both pre-allow at the gate and re-allow here.

use std::path::Path;

use crate::gate::GateMeta;
use crate::grants;
use crate::io::Decision;
use crate::policy::Policy;

/// Apply the grant-layer relaxation to a gate's natural decision.
///
/// Contract:
/// - If `natural` is not [`Decision::Ask`], return it unchanged (never relax a `Deny`,
///   never override an `Allow`/`Defer`).
/// - If `meta.hard_guard` is `true`, return `natural` unchanged. Hard guards
///   (`mainnet_deploy` / `set_authority` / `account_close` / `secret_read`) are absolute and
///   no grant may downgrade them.
/// - Otherwise consult active grants via [`grants::find_match`]; on a match within
///   budget / `max_tx_sol`, debit the grant for `meta.amount_sol` and return [`Decision::Allow`].
///   Otherwise return `natural` unchanged.
///
/// `policy` must be the EFFECTIVE policy (post-profile-overlay). It is accepted for contract
/// stability and possible future policy-gated grant rules; the grant layer itself reads only
/// the persisted grants.
pub fn apply(natural: Decision, meta: &GateMeta, policy: &Policy, plugin_data: &Path) -> Decision {
    let _ = policy;

    // 1. Only an `Ask` is ever a relaxation candidate.
    if !matches!(natural, Decision::Ask { .. }) {
        return natural;
    }

    // 2. Hard guards are never relaxed by a grant.
    if meta.hard_guard {
        return natural;
    }

    // 3. Consult active grants.
    let live = grants::load(plugin_data);
    let grant_id = match grants::find_match(&live, meta) {
        Some(g) => g.id.clone(),
        None => return natural,
    };

    // Debit the matched grant for the action's amount (best-effort: a persistence failure
    // must not flip an authorized allow back into an ask, but it also must not silently
    // over-grant — `find_match` already verified the budget covers this amount).
    let amount = meta.amount_sol.unwrap_or(0.0);
    let _ = grants::debit(plugin_data, &grant_id, amount);

    Decision::Allow
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::Scope;
    use crate::grants::{Grant, Grants};

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "safe_ai_skill_relax_{}_{}_{}",
            tag,
            std::process::id(),
            secs
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn effective_policy() -> Policy {
        Policy::fail_closed().effective()
    }

    fn transfer_meta(amount: f64, hard_guard: bool) -> GateMeta {
        GateMeta {
            scope: Scope::Transfer,
            amount_sol: Some(amount),
            program: None,
            destination: None,
            hard_guard,
        }
    }

    fn write_transfer_grant(dir: &std::path::Path, budget: f64) {
        let grant = Grant {
            id: "g1".into(),
            scope: Scope::Transfer,
            programs: vec![],
            to: vec![],
            max_tx_sol: 1.0,
            budget_sol: budget,
            spent_sol: 0.0,
            expires_at: u64::MAX,
            danger: false,
        };
        grants::save(
            dir,
            &Grants {
                grants: vec![grant],
            },
        )
        .unwrap();
    }

    #[test]
    fn ask_with_matching_grant_becomes_allow_and_debits() {
        let dir = tmp_dir("match");
        write_transfer_grant(&dir, 5.0);
        let out = apply(
            Decision::Ask {
                reason: "transfer".into(),
            },
            &transfer_meta(0.5, false),
            &effective_policy(),
            &dir,
        );
        assert_eq!(out, Decision::Allow);
        // The grant was debited by the action amount.
        let after = grants::load(&dir);
        assert_eq!(after.grants[0].spent_sol, 0.5);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ask_without_grant_stays_ask() {
        let dir = tmp_dir("nogrant");
        grants::save(&dir, &Grants::default()).unwrap();
        let ask = Decision::Ask {
            reason: "transfer".into(),
        };
        let out = apply(
            ask.clone(),
            &transfer_meta(0.5, false),
            &effective_policy(),
            &dir,
        );
        assert_eq!(out, ask);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hard_guard_never_relaxed_even_with_grant() {
        let dir = tmp_dir("hardguard");
        write_transfer_grant(&dir, 5.0);
        let ask = Decision::Ask {
            reason: "secret read".into(),
        };
        let out = apply(
            ask.clone(),
            &transfer_meta(0.5, true), // hard_guard = true
            &effective_policy(),
            &dir,
        );
        assert_eq!(out, ask);
        // No debit occurred.
        let after = grants::load(&dir);
        assert_eq!(after.grants[0].spent_sol, 0.0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn deny_passes_through_unchanged() {
        let dir = tmp_dir("deny");
        write_transfer_grant(&dir, 5.0);
        let deny = Decision::Deny {
            reason: "over hard cap".into(),
        };
        let out = apply(
            deny.clone(),
            &transfer_meta(0.5, false),
            &effective_policy(),
            &dir,
        );
        assert_eq!(out, deny);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn allow_passes_through_unchanged() {
        let dir = tmp_dir("allow");
        write_transfer_grant(&dir, 5.0);
        let out = apply(
            Decision::Allow,
            &transfer_meta(0.5, false),
            &effective_policy(),
            &dir,
        );
        assert_eq!(out, Decision::Allow);
        // No debit on a natural allow.
        let after = grants::load(&dir);
        assert_eq!(after.grants[0].spent_sol, 0.0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn defer_passes_through_unchanged() {
        let dir = tmp_dir("defer");
        let out = apply(
            Decision::Defer,
            &transfer_meta(0.5, false),
            &effective_policy(),
            &dir,
        );
        assert_eq!(out, Decision::Defer);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn amount_over_grant_cap_stays_ask() {
        let dir = tmp_dir("overcap");
        write_transfer_grant(&dir, 5.0); // max_tx_sol = 1.0
        let ask = Decision::Ask {
            reason: "transfer".into(),
        };
        let out = apply(
            ask.clone(),
            &transfer_meta(2.0, false), // over per-tx cap
            &effective_policy(),
            &dir,
        );
        assert_eq!(out, ask);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
