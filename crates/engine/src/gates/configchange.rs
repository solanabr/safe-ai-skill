//! ConfigChange guard: Claude Code runs the `ConfigChange` hook when a settings file changes
//! during a session (`user_settings`, `project_settings`, `local_settings`, `skills`,
//! `policy_settings`). The payload carries `source` and, optionally, `file_path`, not the new
//! text, so the guard reads the file as it now is and blocks the change only when the result
//! turns protection off by the same rule as the D1 tamper deny
//! ([`tamper::settings_disable_reason`]). Anything else, a `skills` change, and every
//! `policy_settings` change (which Claude Code never lets a hook block) get no opinion.
//!
//! The confirmation-code CLI is the sanctioned way to turn safe-ai-skill down; this guard only
//! stops a settings edit from doing it behind the CLI's back.
//!
//! Limits: the payload has no previous text, so a change that removes the `safe-ai-skill@…`
//! entry or a guard hook (rather than setting a switch) is not seen; and a file that already
//! disables protection blocks every later change to it until the switch is removed.

use std::path::PathBuf;

use serde_json::Value;

use crate::gate::Verdict;
use crate::gates::tamper::{self, ConfigHomes};

/// Largest settings file read.
const MAX_SETTINGS_READ: u64 = 1024 * 1024;

/// Lowercase byte needles one of which a disabling settings text must hold.
const NEEDLES: &[&str] = &[
    "safe-ai-skill@",
    "disableallhooks",
    "allowmanagedhooksonly",
    "safe_ai_skill_disable",
    "bypasspermissions",
    "\\u",
];

/// Decide a `ConfigChange` payload, settings locations from the environment.
pub fn decide(input: &Value) -> Option<Verdict> {
    decide_in(input, &ConfigHomes::from_env())
}

/// [`decide`] with the settings locations given: `Some(Deny)` blocks the change.
pub fn decide_in(input: &Value, homes: &ConfigHomes) -> Option<Verdict> {
    let source = input.get("source").and_then(Value::as_str)?;
    let path = settings_path(input, source, homes)?;
    let text = crate::policy::tier::read_bounded(&path, MAX_SETTINGS_READ)?;
    let lower = text.to_ascii_lowercase();
    if !NEEDLES.iter().any(|n| lower.contains(n)) {
        return None;
    }
    let what = tamper::settings_disable_reason(&text)?;
    let shown: String = path.to_string_lossy().chars().take(160).collect();
    Some(Verdict::Deny(format!(
        "safe-ai-skill: blocked a settings change to `{shown}` that {what}, which turns off \
         protection; turn safe-ai-skill down with the `safe-ai-skill` CLI and its confirmation \
         code instead."
    )))
}

/// The settings file a change from `source` wrote: the payload's `file_path`, else the
/// source's standard location. `None` for `skills`, `policy_settings` and unknown sources.
fn settings_path(input: &Value, source: &str, homes: &ConfigHomes) -> Option<PathBuf> {
    if !matches!(
        source,
        "user_settings" | "project_settings" | "local_settings"
    ) {
        return None;
    }
    if let Some(p) = input.get("file_path").and_then(Value::as_str) {
        let path = PathBuf::from(p);
        return path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("json"))
            .then_some(path);
    }
    let project = || {
        input
            .get("cwd")
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .or_else(|| homes.project_dir.clone())
    };
    match source {
        "user_settings" => homes
            .config_dir
            .clone()
            .or_else(|| homes.home.as_ref().map(|h| h.join(".claude")))
            .map(|d| d.join("settings.json")),
        "project_settings" => project().map(|d| d.join(".claude/settings.json")),
        _ => project().map(|d| d.join(".claude/settings.local.json")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn run(source: &str, body: &str) -> Option<Verdict> {
        let dir = std::env::temp_dir().join(format!(
            "sas-configchange-{}-{}",
            std::process::id(),
            body.len()
        ));
        std::fs::create_dir_all(dir.join(".claude")).unwrap();
        let file = dir.join(".claude/settings.json");
        std::fs::write(&file, body).unwrap();
        let input = json!({
            "hook_event_name": "ConfigChange",
            "source": source,
            "file_path": file.to_string_lossy(),
        });
        let out = decide_in(&input, &ConfigHomes::default());
        let _ = std::fs::remove_dir_all(&dir);
        out
    }

    #[test]
    fn disabling_settings_block_and_benign_ones_do_not() {
        let off = r#"{"enabledPlugins":{"safe-ai-skill@stbr":false}}"#;
        assert!(matches!(
            run("project_settings", off),
            Some(Verdict::Deny(_))
        ));
        assert!(matches!(
            run("user_settings", r#"{"disableAllHooks":true}"#),
            Some(Verdict::Deny(_))
        ));
        assert_eq!(run("policy_settings", off), None);
        assert_eq!(run("skills", off), None);
        assert_eq!(run("local_settings", r#"{"theme":"dark"}"#), None);
        assert_eq!(
            run(
                "project_settings",
                r#"{"permissions":{"allow":["Bash(npm test)"]},"enabledPlugins":{"safe-ai-skill@stbr":true}}"#
            ),
            None
        );
    }
}
