//! ConfigChange guard: Claude Code runs the `ConfigChange` hook when a settings file changes
//! during a session (`user_settings`, `project_settings`, `local_settings`, `skills`,
//! `policy_settings`). The payload carries `source` and, optionally, `file_path`, not the new
//! text, so the guard reads the file as it now is, finds the switches in it that turn
//! protection off by the D1 rule ([`tamper::settings_disable_reasons`]), and blocks the change
//! only when one of them is new: not in the snapshot of that file's switches it kept the last
//! time it let a change through. With no snapshot (first sighting, an untrusted or unresolved
//! data dir, a tampered state file) every switch counts as new. A `skills` change and every
//! `policy_settings` change (which Claude Code never lets a hook block) get no opinion.
//!
//! The confirmation-code CLI is the sanctioned way to turn safe-ai-skill down; this guard only
//! stops a settings edit from doing it behind the CLI's back.
//!
//! The snapshot is written when a change is let through and by [`record_baseline`] at
//! session start, never on a block (or the next change would carry the blocked switch in).
//!
//! Limits: the payload has no previous text, so a change that removes the `safe-ai-skill@…`
//! entry or a guard hook (rather than setting a switch) is not seen. A switch that was in no
//! baseline and that the guard never let through keeps blocking changes to its file until it
//! is removed.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde_json::Value;

use crate::datadir::{self, DataDir};
use crate::gate::Verdict;
use crate::gates::tamper::{self, ConfigHomes};
use crate::statefile::{self, Loaded};

/// Largest settings file read.
const MAX_SETTINGS_READ: u64 = 1024 * 1024;

/// State file: settings path → the disabling switches it held when last let through.
const SNAPSHOT_FILE: &str = "configchange.json";

/// Most settings paths the snapshot keeps.
const MAX_SNAPSHOTS: usize = 64;

/// Lowercase byte needles one of which a disabling settings text must hold.
const NEEDLES: &[&str] = &[
    "safe-ai-skill@",
    "disableallhooks",
    "allowmanagedhooksonly",
    "safe_ai_skill_disable",
    "bypasspermissions",
    "\\u",
];

type Snapshots = BTreeMap<String, BTreeSet<String>>;

/// Decide a `ConfigChange` payload, settings locations and data dir from the environment
/// (the data dir resolved for the payload's `cwd`, as for every hook).
pub fn decide(input: &Value) -> Option<Verdict> {
    let cwd = input.get("cwd").and_then(Value::as_str).map(PathBuf::from);
    let dir = datadir::data_dir_with_cwd(cwd.as_deref()).unwrap_or_else(|_| datadir::unresolved());
    decide_with(input, &ConfigHomes::from_env(), &dir)
}

/// [`decide`] with the settings locations given and no snapshot: every disabling switch in
/// the file counts as new.
pub fn decide_in(input: &Value, homes: &ConfigHomes) -> Option<Verdict> {
    decide_with(input, homes, &datadir::unresolved())
}

/// [`decide`] with the settings locations and data dir given: `Some(Deny)` blocks the change.
pub fn decide_with(input: &Value, homes: &ConfigHomes, dir: &DataDir) -> Option<Verdict> {
    let source = input.get("source").and_then(Value::as_str)?;
    let path = settings_path(input, source, homes)?;
    let text = crate::policy::tier::read_bounded(&path, MAX_SETTINGS_READ).unwrap_or_default();
    let now = reasons(&text, source);
    let key = snapshot_key(&path);
    let mut snapshots = load_snapshots(dir);
    let seen = snapshots.get(&key);
    let new = now.iter().find(|w| seen.is_none_or(|s| !s.contains(*w)));
    if let Some(what) = new {
        let shown: String = key.chars().take(160).collect();
        return Some(Verdict::Deny(format!(
            "safe-ai-skill: blocked a settings change to `{shown}` that {what}, which turns off \
             protection; turn safe-ai-skill down with the `safe-ai-skill` CLI and its \
             confirmation code instead."
        )));
    }
    if dir.trusted && seen != Some(&now) {
        if snapshots.len() >= MAX_SNAPSHOTS && !snapshots.contains_key(&key) {
            snapshots.pop_first();
        }
        snapshots.insert(key, now);
        let _ = statefile::store(dir, SNAPSHOT_FILE, &snapshots);
    }
    None
}

/// Record the disabling switches the user, project and local settings files hold at session
/// start as the snapshot, so a switch the user set before the session (a user-scope
/// `bypassPermissions`, say) does not block every later change to its file. For the
/// `SessionStart` hook, before the agent acts; a no-op for an untrusted data dir.
pub fn record_baseline(cwd: Option<&std::path::Path>, homes: &ConfigHomes, dir: &DataDir) {
    if !dir.trusted {
        return;
    }
    let mut snapshots = load_snapshots(dir);
    let before = snapshots.clone();
    let input = serde_json::json!({ "cwd": cwd.map(|c| c.to_string_lossy().into_owned()) });
    for source in ["user_settings", "project_settings", "local_settings"] {
        let Some(path) = settings_path(&input, source, homes) else {
            continue;
        };
        let text = crate::policy::tier::read_bounded(&path, MAX_SETTINGS_READ).unwrap_or_default();
        let key = snapshot_key(&path);
        if snapshots.len() >= MAX_SNAPSHOTS && !snapshots.contains_key(&key) {
            snapshots.pop_first();
        }
        snapshots.insert(key, reasons(&text, source));
    }
    if snapshots != before {
        let _ = statefile::store(dir, SNAPSHOT_FILE, &snapshots);
    }
}

/// The snapshot key for a settings file: its components rejoined with the platform separator
/// and any Windows verbatim prefix dropped, so the payload's `file_path` (Claude Code may mix
/// `/` and `\\` on Windows) and the path [`settings_path`] builds name the same entry.
fn snapshot_key(path: &std::path::Path) -> String {
    let joined: PathBuf = path.components().collect();
    crate::firewall::target::simplified(joined)
        .to_string_lossy()
        .into_owned()
}

/// The disabling switches in settings `text` from `source`.
fn reasons(text: &str, source: &str) -> BTreeSet<String> {
    let lower = text.to_ascii_lowercase();
    if NEEDLES.iter().any(|n| lower.contains(n)) {
        tamper::settings_disable_reasons(text, source != "user_settings")
    } else {
        BTreeSet::new()
    }
}

/// The snapshots, when the data dir is trusted and the state file verifies; else none (every
/// switch then counts as new).
fn load_snapshots(dir: &DataDir) -> Snapshots {
    if !dir.trusted {
        return Snapshots::new();
    }
    match statefile::load::<Snapshots>(dir, SNAPSHOT_FILE) {
        Loaded::Valid(s) => s,
        Loaded::Missing | Loaded::Tampered => Snapshots::new(),
    }
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

    #[test]
    fn snapshot_keys_ignore_separator_spelling() {
        let a = std::path::Path::new("/tmp/x/.claude").join("settings.json");
        let b = std::path::Path::new("/tmp/x").join(".claude/settings.json");
        assert_eq!(snapshot_key(&a), snapshot_key(&b));
        assert_eq!(
            snapshot_key(std::path::Path::new("/tmp//x/./.claude/settings.json")),
            snapshot_key(&a)
        );
        if cfg!(windows) {
            let mixed = std::path::Path::new(r"C:\Users\me\.claude/settings.json");
            let verbatim = std::path::Path::new(r"\\?\C:\Users\me\.claude\settings.json");
            assert_eq!(snapshot_key(mixed), r"C:\Users\me\.claude\settings.json");
            assert_eq!(snapshot_key(verbatim), snapshot_key(mixed));
        }
    }

    #[test]
    fn only_newly_added_switches_block_once_a_snapshot_exists() {
        let root = std::env::temp_dir().join(format!(
            "sas-configchange-snap-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let data = DataDir {
            path: root.join("data"),
            trusted: true,
        };
        std::fs::create_dir_all(root.join(".claude")).unwrap();
        let file = root.join(".claude/settings.json");
        let input = json!({
            "hook_event_name": "ConfigChange",
            "source": "user_settings",
            "file_path": file.to_string_lossy(),
        });
        let homes = ConfigHomes::default();
        let step = |body: &str| {
            std::fs::write(&file, body).unwrap();
            decide_with(&input, &homes, &data)
        };
        let hooks_off = r#"{"disableAllHooks":true}"#;
        // First sighting judges the whole file and stores nothing on a deny.
        assert!(matches!(step(hooks_off), Some(Verdict::Deny(_))));
        assert!(matches!(
            step(r#"{"disableAllHooks":true,"theme":"dark"}"#),
            Some(Verdict::Deny(_))
        ));
        // A clean file is let through and snapshotted; adding the switch then blocks.
        assert_eq!(step(r#"{"theme":"dark"}"#), None);
        assert!(matches!(step(hooks_off), Some(Verdict::Deny(_))));
        // A switch the snapshot already holds no longer blocks unrelated edits.
        let bypass = r#"{"permissions":{"defaultMode":"bypassPermissions"}}"#;
        std::fs::write(&file, bypass).unwrap();
        let user_homes = ConfigHomes {
            config_dir: Some(root.join(".claude")),
            ..ConfigHomes::default()
        };
        record_baseline(None, &user_homes, &data);
        assert_eq!(
            step(r#"{"permissions":{"defaultMode":"bypassPermissions"},"model":"opus"}"#),
            None
        );
        assert_eq!(
            step(r#"{"permissions":{"defaultMode":"bypassPermissions"},"theme":"light"}"#),
            None
        );
        // A second, new switch still blocks.
        assert!(matches!(
            step(r#"{"permissions":{"defaultMode":"bypassPermissions"},"disableAllHooks":true}"#),
            Some(Verdict::Deny(_))
        ));
        // An untrusted data dir relaxes nothing.
        let untrusted = DataDir {
            trusted: false,
            ..data.clone()
        };
        std::fs::write(&file, bypass).unwrap();
        assert!(matches!(
            decide_with(&input, &homes, &untrusted),
            Some(Verdict::Deny(_))
        ));
        let _ = std::fs::remove_dir_all(&root);
    }
}
