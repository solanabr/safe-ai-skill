//! SessionStart notices about the install and the platform (spec D5.1, D5.3, D5.5).
//!
//! All best effort: a file that is missing, unreadable or in a format this doesn't know
//! yields no notice, never an error. Nothing here touches the network or runs a process.
//!
//! - **Duplicate install.** Claude Code registers only one copy's hooks when the plugin is
//!   installed from two marketplaces (`safe-ai-skill@safe-ai-skill` and `safe-ai-skill@stbr`),
//!   and doesn't say which, so more than one `safe-ai-skill@*` key in
//!   `installed_plugins.json` is reported. The file's format is undocumented: keys are read
//!   from its `plugins` object, or from the top level when there is none.
//! - **Claude Code version.** `onFailure` needs Claude Code 2.1.295; older versions treat a
//!   failed hook as non-blocking. The version comes from `CLAUDE_CODE_VERSION`, else from a
//!   `X.Y.Z` component of `CLAUDE_CODE_EXECPATH` (the executable's path, which carries the
//!   version in the Homebrew and native-installer layouts). When neither gives one, nothing
//!   is said: running `claude --version` on every session start costs too much. Both
//!   variables can be set by a repo's committed `.claude/settings.json` `env`, so the
//!   notice is advisory: a repo can hide it (or fake it), and nothing relies on it.
//! - **Windows.** The shell gates match the `Bash` tool (Git Bash) only; `PowerShell` tool
//!   calls are not gated in 1.1.0.

use std::io::Read;
use std::path::{Path, PathBuf};

/// The oldest Claude Code that honours `onFailure` (spec D5.5).
pub const MIN_CLAUDE_CODE: (u64, u64, u64) = (2, 1, 295);

/// `installed_plugins.json` is read only up to this size.
const MAX_INSTALLED_PLUGINS_BYTES: u64 = 4 << 20;

/// What the notices are computed from, so tests can supply it.
#[derive(Debug, Default, Clone)]
pub struct Inputs {
    /// `installed_plugins.json` contents, when readable.
    pub installed_plugins: Option<String>,
    /// `CLAUDE_CODE_VERSION`.
    pub cc_version: Option<String>,
    /// `CLAUDE_CODE_EXECPATH`.
    pub cc_execpath: Option<String>,
    /// Whether the engine runs on Windows.
    pub windows: bool,
}

impl Inputs {
    /// Read the inputs from the process environment and the user's Claude config dir.
    pub fn from_env() -> Inputs {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        Inputs {
            installed_plugins: installed_plugins_path().and_then(|p| read_small(&p)),
            cc_version: var("CLAUDE_CODE_VERSION"),
            cc_execpath: var("CLAUDE_CODE_EXECPATH"),
            windows: cfg!(windows),
        }
    }
}

/// The SessionStart notices for this install, each one line; empty when all is well.
pub fn session_notices() -> Vec<String> {
    notices(&Inputs::from_env())
}

/// [`session_notices`] over explicit inputs.
pub fn notices(inputs: &Inputs) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(json) = &inputs.installed_plugins {
        let installs = safe_ai_skill_installs(json);
        if installs.len() > 1 {
            out.push(format!(
                "safe-ai-skill is installed more than once ({}). Claude Code runs only one \
                 copy's hooks and does not say which; uninstall all but one with \
                 `claude plugin uninstall <name>@<marketplace>`.",
                installs.join(", ")
            ));
        }
    }
    let version = inputs
        .cc_version
        .as_deref()
        .and_then(parse_version)
        .or_else(|| inputs.cc_execpath.as_deref().and_then(version_in_path));
    if let Some(v) = version {
        if v < MIN_CLAUDE_CODE {
            let (a, b, c) = v;
            let (ma, mb, mc) = MIN_CLAUDE_CODE;
            out.push(format!(
                "Claude Code {a}.{b}.{c} is older than {ma}.{mb}.{mc}: a safe-ai-skill hook that \
                 fails there does not block the tool call. Update Claude Code."
            ));
        }
    }
    if inputs.windows {
        out.push(
            "safe-ai-skill on Windows: the shell gates cover the Bash tool (Git Bash) only; \
             PowerShell tool calls are not gated."
                .to_string(),
        );
    }
    out
}

/// The `safe-ai-skill@<marketplace>` keys in an `installed_plugins.json`, sorted.
fn safe_ai_skill_installs(json: &str) -> Vec<String> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let map = match value.get("plugins") {
        Some(serde_json::Value::Object(m)) => m,
        _ => match &value {
            serde_json::Value::Object(m) => m,
            _ => return Vec::new(),
        },
    };
    let mut keys: Vec<String> = map
        .keys()
        .filter(|k| k.starts_with("safe-ai-skill@"))
        .cloned()
        .collect();
    keys.sort();
    keys
}

/// `X.Y.Z` at the start of `s` (so `2.1.304 (Claude Code)` parses), ignoring a pre-release
/// or build suffix on the patch number.
fn parse_version(s: &str) -> Option<(u64, u64, u64)> {
    let word = s.split_whitespace().next()?;
    let mut parts = word.splitn(3, '.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch_text = parts.next()?;
    let digits = patch_text
        .find(|c: char| !c.is_ascii_digit())
        .map_or(patch_text, |end| &patch_text[..end]);
    Some((major, minor, digits.parse().ok()?))
}

/// The last path component of `path` that is exactly a version `X.Y.Z`.
fn version_in_path(path: &str) -> Option<(u64, u64, u64)> {
    path.split(['/', '\\'])
        .filter(|c| {
            c.split('.').count() == 3 && c.chars().all(|ch| ch.is_ascii_digit() || ch == '.')
        })
        .filter_map(parse_version)
        .next_back()
}

/// `$CLAUDE_CONFIG_DIR/plugins/installed_plugins.json`, else under `<home>/.claude`.
fn installed_plugins_path() -> Option<PathBuf> {
    let var = |k: &str| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    let config = var("CLAUDE_CONFIG_DIR")
        .or_else(|| var("HOME").map(|h| h.join(".claude")))
        .or_else(|| var("USERPROFILE").map(|h| h.join(".claude")))?;
    Some(config.join("plugins").join("installed_plugins.json"))
}

/// The contents of a regular file of at most [`MAX_INSTALLED_PLUGINS_BYTES`]; `None` for
/// anything else (so a FIFO there can't stall the session start).
fn read_small(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_INSTALLED_PLUGINS_BYTES {
        return None;
    }
    let mut text = String::new();
    std::fs::File::open(path)
        .ok()?
        .take(MAX_INSTALLED_PLUGINS_BYTES)
        .read_to_string(&mut text)
        .ok()?;
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_plugins(json: &str) -> Inputs {
        Inputs {
            installed_plugins: Some(json.to_string()),
            ..Inputs::default()
        }
    }

    #[test]
    fn nothing_to_say_by_default() {
        assert!(notices(&Inputs::default()).is_empty());
    }

    #[test]
    fn two_installs_from_different_marketplaces_warn() {
        let n = notices(&with_plugins(
            r#"{"version":2,"plugins":{"safe-ai-skill@stbr":[{}],"other@x":[{}],
               "safe-ai-skill@safe-ai-skill":[{}]}}"#,
        ));
        assert_eq!(n.len(), 1, "{n:?}");
        assert!(n[0].contains("safe-ai-skill@safe-ai-skill, safe-ai-skill@stbr"));
        assert!(n[0].contains("installed more than once"));
    }

    #[test]
    fn one_install_is_fine() {
        let n = notices(&with_plugins(
            r#"{"version":2,"plugins":{"safe-ai-skill@safe-ai-skill":[{}],"safe-ai-skill-x@y":[]}}"#,
        ));
        assert!(n.is_empty(), "{n:?}");
    }

    #[test]
    fn top_level_keys_count_when_there_is_no_plugins_object() {
        let n = notices(&with_plugins(
            r#"{"safe-ai-skill@a":{},"safe-ai-skill@b":{}}"#,
        ));
        assert_eq!(n.len(), 1, "{n:?}");
    }

    #[test]
    fn unreadable_plugin_lists_say_nothing() {
        for bad in ["", "not json", "[1,2]", r#"{"plugins":[1]}"#, "null"] {
            assert!(notices(&with_plugins(bad)).is_empty(), "{bad:?}");
        }
    }

    #[test]
    fn old_claude_code_warns_and_new_does_not() {
        let at = |v: &str| Inputs {
            cc_version: Some(v.to_string()),
            ..Inputs::default()
        };
        let old = notices(&at("2.1.294"));
        assert_eq!(old.len(), 1, "{old:?}");
        assert!(old[0].contains("2.1.294") && old[0].contains("2.1.295"));
        assert_eq!(notices(&at("1.9.999")).len(), 1);
        for ok in [
            "2.1.295",
            "2.1.304 (Claude Code)",
            "2.2.0",
            "3.0.0-beta.1",
            "2.1.295-rc",
        ] {
            assert!(notices(&at(ok)).is_empty(), "{ok}");
        }
        for unknown in ["", "garbage", "2.1", "v2.1.0"] {
            assert!(notices(&at(unknown)).is_empty(), "{unknown}");
        }
    }

    #[test]
    fn version_falls_back_to_the_executable_path() {
        let exec = |p: &str| Inputs {
            cc_execpath: Some(p.to_string()),
            ..Inputs::default()
        };
        assert_eq!(
            notices(&exec("/opt/homebrew/Caskroom/claude-code/2.1.200/claude")).len(),
            1
        );
        assert_eq!(
            notices(&exec(r"C:\Users\me\.local\share\claude\versions\2.0.1")).len(),
            1
        );
        assert!(notices(&exec("/opt/homebrew/Caskroom/claude-code/2.1.304/claude")).is_empty());
        assert!(notices(&exec("/usr/local/bin/claude")).is_empty());
        // CLAUDE_CODE_VERSION wins over the path.
        let both = Inputs {
            cc_version: Some("2.1.300".into()),
            cc_execpath: Some("/x/2.1.100/claude".into()),
            ..Inputs::default()
        };
        assert!(notices(&both).is_empty());
    }

    #[test]
    fn windows_states_the_bash_only_scope() {
        let n = notices(&Inputs {
            windows: true,
            ..Inputs::default()
        });
        assert_eq!(n.len(), 1);
        assert!(n[0].contains("Bash tool") && n[0].contains("PowerShell"));
    }

    #[test]
    fn read_small_skips_directories_and_missing_files() {
        let dir =
            std::env::temp_dir().join(format!("safe_ai_skill_platform_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(read_small(&dir).is_none());
        assert!(read_small(&dir.join("missing.json")).is_none());
        let f = dir.join("installed_plugins.json");
        std::fs::write(&f, "{}").unwrap();
        assert_eq!(read_small(&f).as_deref(), Some("{}"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
