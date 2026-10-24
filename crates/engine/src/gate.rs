//! Gate metadata shared across gates, the relaxation layer, and grants.
//!
//! A gate returns both a [`crate::io::Decision`] (the *natural* decision under the
//! effective policy) and a [`GateMeta`] describing *what* the action is. The
//! relaxation layer ([`crate::relax`]) consumes the metadata to decide whether an
//! active grant may upgrade an `Ask` into an `Allow`. Hard guards
//! (`meta.hard_guard == true`) are NEVER relaxed.

use serde::{Deserialize, Serialize};

/// The category of a gated action, used for grant matching and audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// SOL or SPL token transfer.
    Transfer,
    /// Token swap (DEX / aggregator).
    Swap,
    /// Program deploy / write-buffer / upgrade.
    Deploy,
    /// Authority change (set-upgrade-authority, spl-token authorize).
    Authority,
    /// Destructive op (burn, close).
    Destructive,
    /// Read of a secret (keypair / `.env` / config holding credentials).
    SecretRead,
    /// Anything not otherwise classified.
    Other,
}

impl Scope {
    /// Stable lowercase label for audit logs and grant files.
    pub fn label(&self) -> &'static str {
        match self {
            Scope::Transfer => "transfer",
            Scope::Swap => "swap",
            Scope::Deploy => "deploy",
            Scope::Authority => "authority",
            Scope::Destructive => "destructive",
            Scope::SecretRead => "secret_read",
            Scope::Other => "other",
        }
    }

    /// Parse a scope from its lowercase label; unknown → [`Scope::Other`].
    pub fn from_label(s: &str) -> Scope {
        match s {
            "transfer" => Scope::Transfer,
            "swap" => Scope::Swap,
            "deploy" => Scope::Deploy,
            "authority" => Scope::Authority,
            "destructive" => Scope::Destructive,
            "secret_read" => Scope::SecretRead,
            _ => Scope::Other,
        }
    }
}

/// Structured description of a gated action.
///
/// Produced by gates, consumed by [`crate::relax`] and [`crate::grants`]. Fields are
/// best-effort: a gate fills what it can extract and leaves the rest `None`.
#[derive(Debug, Clone, PartialEq)]
pub struct GateMeta {
    /// Action category.
    pub scope: Scope,
    /// SOL amount involved, if the gate could parse one (transfers/swaps).
    pub amount_sol: Option<f64>,
    /// Program id / address involved (deploy/authority), if known.
    pub program: Option<String>,
    /// Destination address (transfer), if known.
    pub destination: Option<String>,
    /// When `true`, this action is a hard guard and MUST NOT be relaxed by any profile or grant.
    pub hard_guard: bool,
}

impl GateMeta {
    /// Build a metadata record for `scope` with all optional fields unset and
    /// `hard_guard` set as given.
    pub fn new(scope: Scope, hard_guard: bool) -> Self {
        GateMeta {
            scope,
            amount_sol: None,
            program: None,
            destination: None,
            hard_guard,
        }
    }

    /// Metadata for an unclassified action (`Scope::Other`, not a hard guard).
    pub fn unknown() -> Self {
        GateMeta::new(Scope::Other, false)
    }

    /// Metadata for a hook payload the engine could not read (malformed, oversized, or
    /// missing its command). A hard guard, so no grant relaxes the fail-closed `ask`.
    pub fn unreadable() -> Self {
        GateMeta::new(Scope::Other, true)
    }
}

/// What a gate concludes about a call (spec D1.1).
///
/// [`Verdict::NoOpinion`] emits nothing (empty stdout, exit 0) and leaves Claude Code's
/// permission flow in charge; it is never sent as `defer`. [`Verdict::Allow`] requires an
/// [`AllowReason`], and no code outside this crate can build one, so the only allows are the
/// two D1.1 permits. Convert to [`crate::io::Decision`] to render.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// No opinion.
    NoOpinion,
    /// Prompt the user, with a reason.
    Ask(String),
    /// Block, with a reason.
    Deny(String),
    /// Permit, for one of the two permitted reasons.
    Allow(AllowReason),
}

/// The only reasons a gate may allow a call.
///
/// Outside this crate neither variant can be constructed: [`GrantId`] has a private field and
/// `WithinCapTestnet` is `#[non_exhaustive]`.
///
/// ```compile_fail
/// use safe_ai_skill::gate::{AllowReason, Verdict};
/// let _ = Verdict::Allow(AllowReason::WithinCapTestnet);
/// ```
///
/// ```compile_fail
/// use safe_ai_skill::gate::{AllowReason, GrantId, Verdict};
/// let _ = Verdict::Allow(AllowReason::Grant(GrantId(String::from("g1"))));
/// ```
///
/// Matching is unrestricted:
///
/// ```
/// use safe_ai_skill::gate::{AllowReason, Verdict};
/// fn why(v: &Verdict) -> &str {
///     match v {
///         Verdict::Allow(AllowReason::Grant(id)) => id.as_str(),
///         Verdict::Allow(AllowReason::WithinCapTestnet { .. }) => "within cap",
///         _ => "",
///     }
/// }
/// assert_eq!(why(&Verdict::NoOpinion), "");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowReason {
    /// (i) An authenticated, unexpired, in-budget grant matched.
    Grant(GrantId),
    /// (ii) A transfer within the spend caps on a positively identified
    /// devnet/testnet/localnet.
    #[non_exhaustive]
    WithinCapTestnet,
}

/// Identifier of the grant behind an [`AllowReason::Grant`]; only the crate mints one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantId(String);

impl GrantId {
    /// Wrap the id of a grant that has been authenticated and matched.
    pub(crate) fn new(id: impl Into<String>) -> GrantId {
        GrantId(id.into())
    }

    /// The grant id.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Verdict {
    /// Stable label for audit logs: `allow`/`ask`/`deny`, or `none` for no opinion.
    pub fn label(&self) -> &'static str {
        match self {
            Verdict::NoOpinion => "none",
            Verdict::Ask(_) => "ask",
            Verdict::Deny(_) => "deny",
            Verdict::Allow(_) => "allow",
        }
    }
}

impl From<Verdict> for crate::io::Decision {
    /// The render path: `NoOpinion` becomes `Defer`, which emits nothing.
    fn from(v: Verdict) -> Self {
        use crate::io::Decision;
        match v {
            Verdict::NoOpinion => Decision::Defer,
            Verdict::Ask(reason) => Decision::Ask { reason },
            Verdict::Deny(reason) => Decision::Deny { reason },
            Verdict::Allow(_) => Decision::Allow,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::{render_pretooluse, Decision};

    #[test]
    fn verdicts_convert_to_the_render_path() {
        assert_eq!(Decision::from(Verdict::NoOpinion), Decision::Defer);
        assert_eq!(render_pretooluse(&Verdict::NoOpinion.into()), None);
        assert_eq!(
            Decision::from(Verdict::Ask("r".into())),
            Decision::Ask { reason: "r".into() }
        );
        assert_eq!(
            Decision::from(Verdict::Deny("r".into())),
            Decision::Deny { reason: "r".into() }
        );
        for reason in [
            AllowReason::WithinCapTestnet,
            AllowReason::Grant(GrantId::new("g1")),
        ] {
            assert_eq!(Decision::from(Verdict::Allow(reason)), Decision::Allow);
        }
    }

    #[test]
    fn labels() {
        assert_eq!(Verdict::NoOpinion.label(), "none");
        assert_eq!(Verdict::Ask(String::new()).label(), "ask");
        assert_eq!(Verdict::Deny(String::new()).label(), "deny");
        assert_eq!(
            Verdict::Allow(AllowReason::Grant(GrantId::new("g"))).label(),
            "allow"
        );
    }
}
