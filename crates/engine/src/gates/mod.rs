//! Runtime gates. Each gate is a PURE function: it inspects an action and returns a
//! decision. `main.rs` owns stdin/policy/audit/emit and the relaxation step.
//!
//! The D8 v2 tier gates (`credpaths`, `creddump`, `envread`, `envwrite`, `wallet`, `exfil`)
//! each own one file and are reached through one call line in a shared file.

pub mod bash;
pub mod creddump;
pub mod credpaths;
pub mod envread;
pub mod envwrite;
pub mod exfil;
pub mod mcp;
pub mod mcpexec;
pub mod read;
pub mod secretpath;
pub mod secrets;
pub mod skill;
pub mod tamper;
pub mod wallet;
