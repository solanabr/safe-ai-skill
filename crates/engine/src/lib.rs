//! safe-ai-skill engine (`safe-ai-skill`) library root.
//!
//! This crate is the security engine behind the safe-ai-skill Claude Code plugin. It is
//! built as both a library (so tests and the binary share one module tree) and a binary
//! (`safe-ai-skill`) whose `main.rs` is a thin dispatcher over these modules.
//!
//! # Module map
//! - Foundation (FROZEN — owned by the foundation pass): [`io`], [`policy`], [`context`],
//!   [`audit`], [`error`], [`gate`].
//! - Runtime gates: [`gates`].
//! - Output / prompt guards: [`redact`], [`promptguard`].
//! - Secrets CLI: [`env`] (`safe-ai-skill env keys|set|unset`).
//! - Spend & swap: [`spend`], [`rugcheck`].
//! - Relaxation layer: [`grants`], [`relax`], plus [`migrate`] (1.0 and WS-B state) and
//!   [`notice`] (the SessionStart tier line and loosenings notice).
//! - Tiers (D8 v2): [`policy::tier`] (tier, sources, resolution), [`tierstate`] (`tier.json`),
//!   [`mode`] (legacy profile alias shim), [`sandbox`] (declared sandbox state),
//!   [`headless`] (the shared headless rule), [`lists`] (the embedded `policy/shared` lists).
//! - Supply chain & session: [`verify`], [`registry`], [`squads`], [`session`].
//! - Shared contracts (1.1.0): [`datadir`] (where state lives, and whether it is trusted),
//!   [`statefile`] (MAC'd state), [`confirm`] (prompt-nonce confirmation), and
//!   [`gate::Verdict`].
//! - Platform (1.1.0): [`platform`] (SessionStart install and platform notices).
//!
//! See `ARCHITECTURE.md` for the round-2 editing contract and ownership table.

pub mod adapt;
pub mod audit;
pub mod confirm;
pub mod context;
pub mod datadir;
pub mod doctor;
pub mod env;
pub mod error;
pub mod gate;
pub mod gates;
pub mod grants;
pub mod headless;
pub mod io;
pub mod lists;
pub mod migrate;
pub mod mode;
pub mod notice;
pub mod platform;
pub mod policy;
pub mod promptguard;
pub mod redact;
pub mod registry;
pub mod relax;
pub mod rugcheck;
pub mod sandbox;
pub mod session;
pub mod spend;
pub mod squads;
pub mod statefile;
pub mod tierstate;
pub mod verify;
