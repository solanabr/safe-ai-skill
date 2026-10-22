//! Scoped, expiring, audited grants (`${DATA}/grants.json`, authenticated, spec D4.2).
//!
//! A grant is a user-issued escape hatch that lets the relaxation layer upgrade an `Ask`
//! into an `Allow` for actions matching its scope, within a budget and before it expires.
//! Hard guards are never relaxable, so a grant cannot cover them.
//!
//! `grants.json` is a [`crate::statefile`] envelope. A grant only ever reaches it through a
//! confirmed prompt nonce (spec D4.1): `safe-ai-skill allow` builds a [`GrantRequest`] and
//! parks it as a pending entry; the `UserPromptSubmit` hook turns it into a [`Grant`] when the
//! user types the nonce ([`crate::relax::confirm_prompt`]). [`live`] is the only view the
//! relaxation layer reads: it is empty unless the file authenticates and the data dir is
//! trusted ([`DataDir::trusted`]).

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::datadir::DataDir;
use crate::error::{EngineError, Error};
use crate::gate::{GateMeta, Scope};
use crate::statefile::{self, Loaded};

/// State file holding the grants.
pub const GRANTS_FILE: &str = "grants.json";

/// Longest a grant may run (30 days).
const MAX_GRANT_SECS: u64 = 30 * 86_400;

/// The scopes a grant may name. `other` is gone (spec D1.9) and `secret_read` is always a
/// hard guard, so a grant could never apply to it.
pub const GRANTABLE_SCOPES: [Scope; 5] = [
    Scope::Transfer,
    Scope::Swap,
    Scope::Deploy,
    Scope::Authority,
    Scope::Destructive,
];

/// A single scoped grant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

    /// Whether this grant matches `meta` ignoring expiry (caller checks expiry). A scope
    /// outside [`GRANTABLE_SCOPES`] never matches, whatever the file says.
    fn matches(&self, meta: &GateMeta) -> bool {
        if self.scope != meta.scope || !GRANTABLE_SCOPES.contains(&self.scope) {
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

    /// One line for the user: what this grant permits and until when.
    pub fn describe(&self, now: u64) -> String {
        format!(
            "grant {}: {}, {} of {} SOL left, at most {} SOL per tx, {}; {}, expires in {}{}",
            self.id,
            self.scope.label(),
            self.remaining_sol(),
            self.budget_sol,
            self.max_tx_sol,
            list_or_any("programs", &self.programs),
            list_or_any("destinations", &self.to),
            human_secs(self.expires_at.saturating_sub(now)),
            if self.danger { " (danger)" } else { "" },
        )
    }
}

/// A grant the user asked for but has not confirmed yet: the payload of a
/// [`crate::confirm::PendingKind::Grant`] entry. The clock starts at confirmation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GrantRequest {
    /// Scope (one of [`GRANTABLE_SCOPES`]).
    pub scope: Scope,
    /// How long the grant runs once confirmed.
    pub for_secs: u64,
    /// Maximum SOL per matched transaction.
    pub max_tx_sol: f64,
    /// Total SOL budget.
    pub budget_sol: f64,
    /// Program ids (empty = any).
    pub programs: Vec<String>,
    /// Destination addresses (empty = any).
    pub to: Vec<String>,
    /// The user opted into a dangerous action.
    pub danger: bool,
}

impl GrantRequest {
    /// Validate `allow`-subcommand arguments.
    ///
    /// The scope must be one of [`GRANTABLE_SCOPES`]; the duration a positive human duration
    /// (`30m`, `2h`, `90s`, `1d`) of at most 30 days; the amounts finite and non-negative;
    /// each program/destination a base58 address. Everything here ends up in the message the
    /// user confirms, so nothing free-form is accepted.
    #[allow(clippy::too_many_arguments)]
    pub fn from_args(
        scope: &str,
        for_dur: &str,
        max_tx_sol: f64,
        budget_sol: f64,
        programs_csv: &str,
        to_csv: &str,
        danger: bool,
    ) -> Result<GrantRequest, String> {
        let scope = grantable_scope(scope)?;
        let for_secs = parse_duration_secs(for_dur)
            .filter(|s| *s > 0)
            .ok_or_else(|| {
                format!(
                    "--for: expected a duration like 30m, 2h or 1d, got `{}`",
                    printable(for_dur)
                )
            })?;
        if for_secs > MAX_GRANT_SECS {
            return Err("--for: a grant may run at most 30 days".to_string());
        }
        for (flag, v) in [("--max-tx", max_tx_sol), ("--budget", budget_sol)] {
            if !v.is_finite() || v < 0.0 {
                return Err(format!("{flag}: expected a non-negative SOL amount"));
            }
        }
        Ok(GrantRequest {
            scope,
            for_secs,
            max_tx_sol,
            budget_sol,
            programs: addresses("--programs", programs_csv)?,
            to: addresses("--to", to_csv)?,
            danger,
        })
    }

    /// The human summary shown when the request is created and echoed when it is confirmed.
    pub fn summary(&self) -> String {
        format!(
            "grant {} for {}: at most {} SOL per tx, {} SOL budget, {}; {}{}",
            self.scope.label(),
            human_secs(self.for_secs),
            self.max_tx_sol,
            self.budget_sol,
            list_or_any("programs", &self.programs),
            list_or_any("destinations", &self.to),
            if self.danger { " (danger)" } else { "" },
        )
    }

    /// The grant this request becomes when confirmed at `now`. Re-validates, because the
    /// payload came back from disk.
    pub fn activate(&self, now: u64, id: String) -> Result<Grant, String> {
        if !GRANTABLE_SCOPES.contains(&self.scope)
            || self.for_secs == 0
            || self.for_secs > MAX_GRANT_SECS
            || !self.max_tx_sol.is_finite()
            || self.max_tx_sol < 0.0
            || !self.budget_sol.is_finite()
            || self.budget_sol < 0.0
            || !self.programs.iter().chain(&self.to).all(|a| is_address(a))
        {
            return Err("the pending grant is invalid".to_string());
        }
        let expires_at = now
            .checked_add(self.for_secs)
            .ok_or_else(|| "the grant expiry overflows".to_string())?;
        Ok(Grant {
            id,
            scope: self.scope,
            programs: self.programs.clone(),
            to: self.to.clone(),
            max_tx_sol: self.max_tx_sol,
            budget_sol: self.budget_sol,
            spent_sol: 0.0,
            expires_at,
            danger: self.danger,
        })
    }
}

/// All grants, the body of `grants.json`.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct Grants {
    /// The grants.
    pub grants: Vec<Grant>,
}

/// Parse a grant scope label: one of [`GRANTABLE_SCOPES`], else an error naming them.
pub fn grantable_scope(label: &str) -> Result<Scope, String> {
    GRANTABLE_SCOPES
        .iter()
        .copied()
        .find(|s| s.label() == label)
        .ok_or_else(|| {
            let known: Vec<&str> = GRANTABLE_SCOPES.iter().map(Scope::label).collect();
            let why = if label == Scope::SecretRead.label() {
                "secret reads are a hard guard; no grant covers them".to_string()
            } else {
                format!("unknown scope `{}`", printable(label))
            };
            format!("--scope: {why}; expected one of {}", known.join("|"))
        })
}

/// Load and authenticate `grants.json`. The caller picks the fail direction.
pub fn load(dir: &DataDir) -> Loaded<Grants> {
    statefile::load(dir, GRANTS_FILE)
}

/// The grants the relaxation layer may use: the authenticated file in a trusted data dir.
/// Missing, tampered or untrusted → none.
pub fn live(dir: &DataDir) -> Grants {
    match load(dir) {
        Loaded::Valid(g) if dir.trusted => g,
        _ => Grants::default(),
    }
}

/// Persist grants as an authenticated envelope.
pub fn save(dir: &DataDir, grants: &Grants) -> Result<(), EngineError> {
    statefile::store(dir, GRANTS_FILE, grants)
}

/// Add a confirmed grant: expired grants are dropped first. A tampered file is replaced
/// (none of its grants could apply); returns whether that happened.
pub fn add(dir: &DataDir, grant: Grant, now: u64) -> Result<bool, EngineError> {
    let (mut grants, replaced) = match load(dir) {
        Loaded::Valid(g) => (g, false),
        Loaded::Missing => (Grants::default(), false),
        Loaded::Tampered => (Grants::default(), true),
    };
    grants.grants.retain(|g| !g.is_expired(now));
    grants.grants.push(grant);
    save(dir, &grants)?;
    Ok(replaced)
}

/// A fresh grant id, distinct from every id in `grants.json`.
pub fn new_id(dir: &DataDir, now: u64) -> String {
    let taken = match load(dir) {
        Loaded::Valid(g) => g.grants.into_iter().map(|g| g.id).collect(),
        _ => Vec::new(),
    };
    let mut n = 0u32;
    loop {
        let id = if n == 0 {
            format!("grant-{now:x}")
        } else {
            format!("grant-{now:x}-{n}")
        };
        if !taken.contains(&id) {
            return id;
        }
        n = n.saturating_add(1);
    }
}

/// Find a non-expired grant matching `meta` (scope + program/destination + within caps).
///
/// Returns the first matching grant. Expiry is checked against the current wall clock.
pub fn find_match<'a>(grants: &'a Grants, meta: &GateMeta) -> Option<&'a Grant> {
    find_match_at(grants, meta, now_secs())
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
/// A non-finite or negative `sol_amount` is rejected, and the running `spent_sol` is clamped
/// so it never exceeds the budget. A missing grant id is a no-op (returns `Ok`). Only an
/// authenticated file is debited.
pub fn debit(dir: &DataDir, grant_id: &str, sol_amount: f64) -> Result<(), EngineError> {
    if !sol_amount.is_finite() || sol_amount < 0.0 {
        return Err(Error::Other(
            "debit amount must be a finite, non-negative SOL value".to_string(),
        ));
    }
    let Loaded::Valid(mut grants) = load(dir) else {
        return Err(Error::Other(
            "grants.json is missing or failed authentication".to_string(),
        ));
    };
    let Some(g) = grants.grants.iter_mut().find(|g| g.id == grant_id) else {
        return Ok(());
    };
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
    save(dir, &grants)
}

/// Drop expired grants from an authenticated file and persist; returns the number removed.
pub fn cleanup_expired(dir: &DataDir) -> usize {
    let now = now_secs();
    let Loaded::Valid(mut grants) = load(dir) else {
        return 0;
    };
    let before = grants.grants.len();
    grants.grants.retain(|g| !g.is_expired(now));
    let removed = before - grants.grants.len();
    if removed > 0 {
        let _ = save(dir, &grants);
    }
    removed
}

/// Split a CSV of base58 addresses; anything else is an error.
fn addresses(flag: &str, csv: &str) -> Result<Vec<String>, String> {
    let list: Vec<String> = csv
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    match list.iter().find(|a| !is_address(a)) {
        Some(bad) => Err(format!(
            "{flag}: `{}` is not a base58 address",
            printable(bad)
        )),
        None => Ok(list),
    }
}

/// A base58 Solana address: 32 to 44 base58 characters.
pub(crate) fn is_address(s: &str) -> bool {
    (32..=44).contains(&s.len())
        && s.chars().all(
            |c| matches!(c, '1'..='9' | 'A'..='H' | 'J'..='N' | 'P'..='Z' | 'a'..='k' | 'm'..='z'),
        )
}

/// `"<what> any"` or `"<what> a, b"`.
fn list_or_any(what: &str, list: &[String]) -> String {
    if list.is_empty() {
        format!("{what} any")
    } else {
        format!("{what} {}", list.join(", "))
    }
}

/// Echo user/model input in an error with control characters and length bounded.
fn printable(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(40).collect()
}

/// `90s`, `30m`, `2h`, `1d`, or a mix for uneven values (`1h30m`).
pub fn human_secs(secs: u64) -> String {
    let (d, h, m, s) = (
        secs / 86_400,
        secs % 86_400 / 3_600,
        secs % 3_600 / 60,
        secs % 60,
    );
    let mut out = String::new();
    for (n, unit) in [(d, "d"), (h, "h"), (m, "m"), (s, "s")] {
        if n > 0 {
            out.push_str(&format!("{n}{unit}"));
        }
    }
    if out.is_empty() {
        "0s".to_string()
    } else {
        out
    }
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

/// Current time in epoch seconds (0 on clock error; never panics).
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A fresh, trusted data dir under the temp dir.
    pub(crate) fn tmp_data(tag: &str) -> DataDir {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        DataDir {
            path: std::env::temp_dir().join(format!(
                "safe_ai_skill_grants_{tag}_{}_{nanos}",
                std::process::id()
            )),
            trusted: true,
        }
    }

    pub(crate) const ADDR: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";

    pub(crate) fn transfer_grant(id: &str, expires_at: u64) -> Grant {
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
        assert!(find_match_at(&grants, &transfer_meta(Some(0.5)), 100).is_some());
        assert!(find_match_at(&grants, &transfer_meta(Some(2.0)), 100).is_none());
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
    fn an_other_scope_grant_in_the_file_never_matches() {
        let mut g = transfer_grant("g1", 10_000);
        g.scope = Scope::Other;
        let grants = Grants { grants: vec![g] };
        let meta = GateMeta::unknown();
        assert!(find_match_at(&grants, &meta, 100).is_none());
    }

    #[test]
    fn no_match_when_expired() {
        let grants = Grants {
            grants: vec![transfer_grant("g1", 50)],
        };
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
        assert!(find_match_at(&grants, &transfer_meta(Some(0.1)), 100).is_none());
    }

    #[test]
    fn debit_is_checked_and_clamped() {
        let dir = tmp_data("debit");
        save(
            &dir,
            &Grants {
                grants: vec![transfer_grant("g1", 10_000)],
            },
        )
        .unwrap();

        debit(&dir, "g1", 2.0).unwrap();
        assert_eq!(live(&dir).grants[0].spent_sol, 2.0);

        // Debiting past the budget clamps to budget_sol, never overshoots.
        debit(&dir, "g1", 100.0).unwrap();
        assert_eq!(live(&dir).grants[0].spent_sol, 5.0);

        assert!(debit(&dir, "g1", -1.0).is_err());
        assert!(debit(&dir, "g1", f64::NAN).is_err());
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn debit_missing_grant_is_noop() {
        let dir = tmp_data("debit_missing");
        save(&dir, &Grants::default()).unwrap();
        assert!(debit(&dir, "nope", 1.0).is_ok());
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn cleanup_drops_expired_only() {
        let dir = tmp_data("cleanup");
        save(
            &dir,
            &Grants {
                grants: vec![transfer_grant("old", 50), transfer_grant("live", u64::MAX)],
            },
        )
        .unwrap();
        assert_eq!(cleanup_expired(&dir), 1);
        let after = live(&dir);
        assert_eq!(after.grants.len(), 1);
        assert_eq!(after.grants[0].id, "live");
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn save_load_roundtrip_is_authenticated() {
        let dir = tmp_data("roundtrip");
        let grants = Grants {
            grants: vec![transfer_grant("g1", 999)],
        };
        save(&dir, &grants).unwrap();
        assert_eq!(load(&dir), Loaded::Valid(grants));
        // The file on disk is an envelope, not the bare grants.
        let text = std::fs::read_to_string(dir.path.join(GRANTS_FILE)).unwrap();
        assert!(text.contains("\"mac\""), "{text}");
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn hand_written_or_edited_grants_are_not_live() {
        let dir = tmp_data("forged");
        // A plain (1.0-style) grants.json written by hand.
        std::fs::create_dir_all(&dir.path).unwrap();
        let plain = serde_json::to_string(&Grants {
            grants: vec![transfer_grant("forged", u64::MAX)],
        })
        .unwrap();
        std::fs::write(dir.path.join(GRANTS_FILE), &plain).unwrap();
        assert_eq!(load(&dir), Loaded::Tampered);
        assert!(live(&dir).grants.is_empty());

        // A genuine file whose budget is then raised by hand.
        save(
            &dir,
            &Grants {
                grants: vec![transfer_grant("g1", u64::MAX)],
            },
        )
        .unwrap();
        let path = dir.path.join(GRANTS_FILE);
        let edited = std::fs::read_to_string(&path)
            .unwrap()
            .replace("\"budget_sol\":5.0", "\"budget_sol\":5000.0");
        std::fs::write(&path, edited).unwrap();
        assert!(live(&dir).grants.is_empty());
        assert!(debit(&dir, "g1", 0.1).is_err());
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn an_untrusted_data_dir_has_no_live_grants() {
        let mut dir = tmp_data("untrusted");
        save(
            &dir,
            &Grants {
                grants: vec![transfer_grant("g1", u64::MAX)],
            },
        )
        .unwrap();
        dir.trusted = false;
        assert!(matches!(load(&dir), Loaded::Valid(_)));
        assert!(live(&dir).grants.is_empty());
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn add_drops_expired_and_replaces_a_tampered_file() {
        let dir = tmp_data("add");
        save(
            &dir,
            &Grants {
                grants: vec![transfer_grant("old", 50)],
            },
        )
        .unwrap();
        assert!(!add(&dir, transfer_grant("new", 10_000), 100).unwrap());
        let ids: Vec<String> = live(&dir).grants.into_iter().map(|g| g.id).collect();
        assert_eq!(ids, vec!["new".to_string()]);

        std::fs::write(dir.path.join(GRANTS_FILE), "{\"grants\":[]}").unwrap();
        assert!(add(&dir, transfer_grant("after", 10_000), 100).unwrap());
        assert_eq!(live(&dir).grants.len(), 1);
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn new_ids_do_not_collide() {
        let dir = tmp_data("ids");
        let first = new_id(&dir, 0x10);
        add(&dir, transfer_grant(&first, u64::MAX), 0x10).unwrap();
        let second = new_id(&dir, 0x10);
        assert_ne!(first, second);
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn scopes_are_validated() {
        for ok in ["transfer", "swap", "deploy", "authority", "destructive"] {
            assert!(grantable_scope(ok).is_ok(), "{ok}");
        }
        for bad in ["other", "", "Transfer", "secret_read", "all", "transfer "] {
            let err = grantable_scope(bad).unwrap_err();
            assert!(err.contains("--scope"), "{bad}: {err}");
        }
        assert!(grantable_scope("secret_read")
            .unwrap_err()
            .contains("hard guard"));
    }

    #[test]
    fn request_from_args_validates_everything() {
        let r = GrantRequest::from_args("transfer", "30m", 1.5, 10.0, ADDR, ADDR, false).unwrap();
        assert_eq!(r.scope, Scope::Transfer);
        assert_eq!(r.for_secs, 1_800);
        assert_eq!(r.programs, vec![ADDR.to_string()]);

        let bad = [
            GrantRequest::from_args("other", "30m", 1.0, 1.0, "", "", false),
            GrantRequest::from_args("transfer", "nope", 1.0, 1.0, "", "", false),
            GrantRequest::from_args("transfer", "0m", 1.0, 1.0, "", "", false),
            GrantRequest::from_args("transfer", "31d", 1.0, 1.0, "", "", false),
            GrantRequest::from_args("transfer", "1h", f64::NAN, 1.0, "", "", false),
            GrantRequest::from_args("transfer", "1h", 1.0, -1.0, "", "", false),
            GrantRequest::from_args("transfer", "1h", 1.0, 1.0, "x\nAPPROVED", "", false),
            GrantRequest::from_args("transfer", "1h", 1.0, 1.0, "", "not an address", false),
        ];
        for (i, b) in bad.iter().enumerate() {
            assert!(b.is_err(), "case {i}: {b:?}");
        }
    }

    #[test]
    fn request_activates_with_the_clock_starting_at_confirmation() {
        let r = GrantRequest::from_args("swap", "2h", 1.0, 3.0, "", "", false).unwrap();
        let g = r.activate(1_000, "grant-x".into()).unwrap();
        assert_eq!(g.expires_at, 1_000 + 7_200);
        assert_eq!(g.scope, Scope::Swap);
        assert_eq!(g.spent_sol, 0.0);
        assert!(r.summary().contains("swap") && r.summary().contains("2h"));

        let mut forged = r.clone();
        forged.scope = Scope::Other;
        assert!(forged.activate(1_000, "g".into()).is_err());
        forged = r.clone();
        forged.programs = vec!["evil\ntext".into()];
        assert!(forged.activate(1_000, "g".into()).is_err());
    }

    #[test]
    fn human_durations() {
        assert_eq!(human_secs(90), "1m30s");
        assert_eq!(human_secs(1_800), "30m");
        assert_eq!(human_secs(86_400), "1d");
        assert_eq!(human_secs(0), "0s");
    }
}
