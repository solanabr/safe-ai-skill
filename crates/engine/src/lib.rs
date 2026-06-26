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
//! - Spend & swap: [`spend`], [`rugcheck`].
//! - Relaxation layer: [`grants`], [`mode`], [`relax`].
//! - Supply chain & session: [`verify`], [`registry`], [`squads`], [`session`].
//!
//! See `ARCHITECTURE.md` for the round-2 editing contract and ownership table.

pub mod audit;
pub mod context;
pub mod error;
pub mod gate;
pub mod gates;
pub mod grants;
pub mod io;
pub mod mode;
pub mod policy;
pub mod promptguard;
pub mod redact;
pub mod registry;
pub mod relax;
pub mod rugcheck;
pub mod session;
pub mod spend;
pub mod squads;
pub mod verify;
