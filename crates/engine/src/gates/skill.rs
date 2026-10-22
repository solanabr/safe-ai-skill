//! Skill-pack gates (spec D2.6): `gate-skill` (PreToolUse `Skill`) and `gate-prompt-expansion`
//! (`UserPromptExpansion`, and a raw `/name` in `UserPromptSubmit`). Both deny a skill whose
//! pack is blocked; the lookup and the TOCTOU re-hash live in [`crate::verify::enforce`].

use std::path::Path;

use serde_json::Value;

use crate::datadir::DataDir;
use crate::gate::Verdict;
use crate::policy::Policy;
use crate::verify::enforce;

/// PreToolUse `Skill`: `tool_input` is `{"skill": "<name>", "args"?: …}`.
pub fn decide(tool_input: Option<&Value>, cwd: &Path, dir: &DataDir, policy: &Policy) -> Verdict {
    match tool_input
        .and_then(|t| t.get("skill"))
        .and_then(Value::as_str)
    {
        Some(name) => enforce::skill_verdict(dir, cwd, policy, name),
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
    match enforce::skill_verdict(dir, cwd, policy, &name) {
        Verdict::Deny(reason) | Verdict::Ask(reason) => Some(reason),
        _ => None,
    }
}
