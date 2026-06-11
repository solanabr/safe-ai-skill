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
}
