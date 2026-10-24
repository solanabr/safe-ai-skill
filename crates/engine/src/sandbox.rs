//! Claude Code sandbox detection (D8 v2 spec §1.4).
//!
//! [`state`] reads `sandbox.enabled` from the settings files, highest precedence first —
//! managed settings, `<project>/.claude/settings.local.json`, `<project>/.claude/settings.json`,
//! then the user's `settings.json` (`$CLAUDE_CONFIG_DIR`, else the OS user-database home's
//! `.claude`, never env `HOME`, which a repo's settings `env` can set) — the first file that
//! sets it wins. [`SandboxState::On`] additionally needs a supported platform: macOS, or Linux
//! with `bwrap` at a fixed system path; never native Windows.
//!
//! This is **declared configuration, not a runtime proof**. Its only effects: the tier label
//! reads `(hooks only)` when it is not `On`, and the `doctor` snippet.

use std::path::{Path, PathBuf};

/// Largest settings file read.
const MAX_SETTINGS_BYTES: u64 = 1024 * 1024;

/// Fixed paths where a system `bwrap` counts (Linux).
const BWRAP_PATHS: [&str; 2] = ["/usr/bin/bwrap", "/bin/bwrap"];

/// Test-only override of [`state`] (`on|off|unknown`), read only in `test-hooks` builds.
pub const TEST_OVERRIDE_ENV: &str = "SAFE_AI_SKILL_TEST_SANDBOX";

/// The sandbox state gates may rely on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SandboxState {
    /// Declared enabled on a supported platform.
    On,
    /// Declared disabled, or not declared (Claude Code's default is off).
    Off,
    /// Declared enabled where it cannot be honoured or checked (Windows, Linux without a
    /// system `bwrap`, another OS), or not determined.
    #[default]
    Unknown,
}

impl SandboxState {
    /// Lowercase label.
    pub fn label(self) -> &'static str {
        match self {
            SandboxState::On => "on",
            SandboxState::Off => "off",
            SandboxState::Unknown => "unknown",
        }
    }
}

/// What the settings files declare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Declared {
    /// The highest-precedence file that sets `sandbox.enabled` sets it `true`.
    On,
    /// It sets it `false`.
    ExplicitlyOff,
    /// No settings file sets it.
    Unset,
}

/// The sandbox state for the project at `root` (see the module docs).
pub fn state(root: &Path) -> SandboxState {
    #[cfg(feature = "test-hooks")]
    if let Some(forced) = test_override() {
        return forced;
    }
    from_declared(declared(root), platform_supported())
}

#[cfg(feature = "test-hooks")]
fn test_override() -> Option<SandboxState> {
    match std::env::var(TEST_OVERRIDE_ENV).ok()?.as_str() {
        "on" => Some(SandboxState::On),
        "off" => Some(SandboxState::Off),
        "unknown" => Some(SandboxState::Unknown),
        _ => None,
    }
}

/// Combine a declaration with the platform check.
pub fn from_declared(declared: Declared, platform_supported: bool) -> SandboxState {
    match declared {
        Declared::On if platform_supported => SandboxState::On,
        Declared::On => SandboxState::Unknown,
        Declared::ExplicitlyOff | Declared::Unset => SandboxState::Off,
    }
}

/// What the settings files for `root` declare.
pub fn declared(root: &Path) -> Declared {
    declared_in(&settings_files(root))
}

/// The first of `files` that sets `sandbox.enabled` decides.
pub fn declared_in(files: &[PathBuf]) -> Declared {
    match files.iter().find_map(|f| setting(f)) {
        Some(true) => Declared::On,
        Some(false) => Declared::ExplicitlyOff,
        None => Declared::Unset,
    }
}

/// The settings files, highest precedence first.
pub fn settings_files(root: &Path) -> Vec<PathBuf> {
    let config_dir = std::env::var_os("CLAUDE_CONFIG_DIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from);
    settings_files_with(root, config_dir, crate::datadir::passwd_home())
}

/// [`settings_files`] with the user scope given: `config_dir` (`$CLAUDE_CONFIG_DIR`) replaces
/// `<passwd_home>/.claude`. Env `HOME` is never an input.
pub fn settings_files_with(
    root: &Path,
    config_dir: Option<PathBuf>,
    passwd_home: Option<PathBuf>,
) -> Vec<PathBuf> {
    let mut files = vec![
        PathBuf::from("/Library/Application Support/ClaudeCode/managed-settings.json"),
        PathBuf::from("/etc/claude-code/managed-settings.json"),
        root.join(".claude").join("settings.local.json"),
        root.join(".claude").join("settings.json"),
    ];
    if let Some(dir) = config_dir.or_else(|| passwd_home.map(|h| h.join(".claude"))) {
        files.push(dir.join("settings.json"));
    }
    files
}

/// Whether this platform can run the Claude Code sandbox.
pub fn platform_supported() -> bool {
    if cfg!(target_os = "macos") {
        true
    } else if cfg!(target_os = "linux") {
        BWRAP_PATHS.iter().any(|p| Path::new(p).is_file())
    } else {
        false
    }
}

/// `sandbox.enabled` from one settings file, when it is a regular file that sets it.
fn setting(path: &Path) -> Option<bool> {
    if !std::fs::metadata(path).ok()?.is_file() {
        return None;
    }
    let text = crate::policy::tier::read_bounded(path, MAX_SETTINGS_BYTES)?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    v.get("sandbox")?.get("enabled")?.as_bool()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sandbox_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".claude")).unwrap();
        dir
    }

    #[test]
    fn the_highest_precedence_file_that_sets_it_wins() {
        let dir = tmp("precedence");
        let local = dir.join(".claude/settings.local.json");
        let project = dir.join(".claude/settings.json");
        let files = [local.clone(), project.clone()];
        assert_eq!(declared_in(&files), Declared::Unset);
        std::fs::write(&project, r#"{"sandbox":{"enabled":true}}"#).unwrap();
        assert_eq!(declared_in(&files), Declared::On);
        std::fs::write(&local, r#"{"sandbox":{"enabled":false}}"#).unwrap();
        assert_eq!(declared_in(&files), Declared::ExplicitlyOff);
        std::fs::write(&local, r#"{"env":{}}"#).unwrap();
        assert_eq!(declared_in(&files), Declared::On);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn on_needs_a_supported_platform() {
        assert_eq!(from_declared(Declared::On, true), SandboxState::On);
        assert_eq!(from_declared(Declared::On, false), SandboxState::Unknown);
        assert_eq!(from_declared(Declared::Unset, true), SandboxState::Off);
        assert_eq!(
            from_declared(Declared::ExplicitlyOff, true),
            SandboxState::Off
        );
        if cfg!(windows) {
            assert!(!platform_supported());
        }
        if cfg!(target_os = "macos") {
            assert!(platform_supported());
        }
    }

    #[test]
    fn env_home_never_names_the_user_settings_file() {
        let root = Path::new("/proj");
        let passwd = PathBuf::from("/home/real");
        let files = settings_files_with(root, None, Some(passwd.clone()));
        assert_eq!(files.last(), Some(&passwd.join(".claude/settings.json")));
        // A repo-set HOME is not an input at all; CLAUDE_CONFIG_DIR replaces the passwd home.
        let cfg = PathBuf::from("/cfg");
        let files = settings_files_with(root, Some(cfg.clone()), Some(passwd.clone()));
        assert_eq!(files.last(), Some(&cfg.join("settings.json")));
        assert!(!files.contains(&passwd.join(".claude/settings.json")));
        assert_eq!(settings_files_with(root, None, None).len(), 4);
    }
}
