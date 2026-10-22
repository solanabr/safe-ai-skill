//! The grading boundary between the pack scanner and the verify state machine (spec D2.4).
//!
//! The state machine grades with the rule engine ([`super::rules`]): [`PackReport`]
//! `{findings, combos, capped}`, [`Finding`] `{rule, sev, path, line, ctx}`, [`ComboHit`],
//! [`Severity`], [`Ctx`] and [`Grade`], with [`scan_pack`], [`scan_pack_until`] and [`grade`].
//! A scan cut by its deadline carries the HIGH `scan_budget_exceeded` finding, which the state
//! machine records as unscanned (its paths denied like a blocked pack's).

pub use super::rules::{
    grade, scan_pack, scan_pack_until, ComboHit, Ctx, Finding, Grade, PackReport, Severity,
};
