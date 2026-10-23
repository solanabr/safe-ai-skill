//! Skill-pack gates (spec D2.6): `gate-skill` (PreToolUse `Skill`) and `gate-prompt-expansion`
//! (`UserPromptExpansion`, and a raw `/name` in `UserPromptSubmit`). Both deny a skill whose
//! pack is blocked; the lookup and the TOCTOU re-hash live in [`crate::verify::enforce`].
//!
//! The tier decides what a bad pack gets (D8 v2 spec §6, [`crate::verify::tier_action`]): Off
//! only reports it at SessionStart, Relaxed and Medium deny a blocked or unscanned pack, High
//! also denies a pack with an unreviewed HIGH finding until the user trusts it.

use std::path::Path;

use serde_json::Value;

use crate::datadir::DataDir;
use crate::gate::Verdict;
use crate::policy::tier::Tier;
use crate::policy::Policy;
use crate::verify::{self, enforce};

/// The Skill/slash verdict for `name` at the policy's tier. Off decides nothing (and so
/// re-hashes nothing; the sweep still reports the pack).
fn verdict_for(name: &str, cwd: &Path, dir: &DataDir, policy: &Policy) -> Verdict {
    let tier = policy.tier();
    if tier == Tier::Off {
        return Verdict::NoOpinion;
    }
    verify::tier_action(enforce::skill_verdict(dir, cwd, policy, name), tier)
}

/// PreToolUse `Skill`: `tool_input` is `{"skill": "<name>", "args"?: …}`.
pub fn decide(tool_input: Option<&Value>, cwd: &Path, dir: &DataDir, policy: &Policy) -> Verdict {
    match tool_input
        .and_then(|t| t.get("skill"))
        .and_then(Value::as_str)
    {
        Some(name) => verdict_for(name, cwd, dir, policy),
        None => Verdict::NoOpinion,
    }
}

/// A prompt-time hook payload: the block reason when it invokes a blocked skill.
pub fn decide_prompt(
    payload: &Value,
    cwd: &Path,
    dir: &DataDir,
    policy: &Policy,
) -> Option<String> {
    let name = enforce::slash_skill_name(payload)?;
    match verdict_for(&name, cwd, dir, policy) {
        Verdict::Deny(reason) | Verdict::Ask(reason) => Some(reason),
        _ => None,
    }
}
