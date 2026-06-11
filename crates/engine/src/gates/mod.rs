//! Runtime gates. Each gate is a PURE function: it inspects an action and returns a
//! decision. `main.rs` owns stdin/policy/audit/emit and the relaxation step.

pub mod bash;
pub mod mcp;
pub mod read;
pub mod secrets;
