//! `safe-ai-skill doctor`: setup checks, read-only (spec D3.6).
//!
//! Secrets section: the read gate and the Bash reader list are nudges against a careless or
//! prompt-injected model; Claude Code's sandbox is the only hard boundary. `doctor` reports
//! whether the sandbox is enabled in the user / project settings and which of the recommended
//! `sandbox.filesystem.denyRead` globs are missing, and prints a snippet to add. It never reads
//! env files or keys.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde_json::Value;

/// Globs recommended for `sandbox.filesystem.denyRead`: the hard-deny and env classes.
/// `~/.config/solana/*.json` (not `**`) keeps `cli/config.yml` readable for the Solana CLI;
/// `**/.env.*` also hides `.env.example` from sandboxed commands (the Read tool still sees it).
pub const RECOMMENDED_DENY_READ: &[&str] = &[
    "**/*-keypair.json",
    "~/.config/solana/*.json",
    "~/.ssh/id_*",
    "~/.superstack/config.json",
    "~/.config/varlock/**",
    "**/.env",
    "**/.env.*",
    "**/.envrc",
    "**/.dev.vars",
];

/// Settings files read, in Claude Code's precedence order (lowest first).
fn settings_files(home: Option<&Path>, cwd: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Some(home) = home {
        files.push(home.join(".claude/settings.json"));
    }
    files.push(cwd.join(".claude/settings.json"));
    files.push(cwd.join(".claude/settings.local.json"));
    files
}

/// What the settings say about the sandbox.
#[derive(Debug, Default)]
struct SandboxState {
    /// The file that last set `sandbox.enabled`, and its value.
    enabled: Option<(PathBuf, bool)>,
    deny_read: Vec<String>,
}

fn read_state(files: &[PathBuf]) -> SandboxState {
    let mut state = SandboxState::default();
    for file in files {
        let Some(json) = std::fs::read_to_string(file)
            .ok()
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        else {
            continue;
        };
        let sandbox = &json["sandbox"];
        if let Some(on) = sandbox["enabled"].as_bool() {
            state.enabled = Some((file.clone(), on));
        }
        if let Some(list) = sandbox["filesystem"]["denyRead"].as_array() {
            state
                .deny_read
                .extend(list.iter().filter_map(Value::as_str).map(str::to_string));
        }
    }
    state
}

/// The doctor report text for `home` / `cwd`.
pub fn report(home: Option<&Path>, cwd: &Path) -> String {
    let state = read_state(&settings_files(home, cwd));
    let mut out = String::from("safe-ai-skill doctor\n\nsecrets:\n");
    match &state.enabled {
        Some((file, true)) => {
            out.push_str(&format!("  sandbox: enabled ({})\n", file.display()));
        }
        Some((file, false)) => out.push_str(&format!(
            "  sandbox: not enabled (disabled in {}). The hooks stop a careless or prompt-injected model; only the sandbox stops a command that reads secrets some other way.\n",
            file.display()
        )),
        None => out.push_str(
            "  sandbox: not enabled. The hooks stop a careless or prompt-injected model; only the sandbox stops a command that reads secrets some other way.\n",
        ),
    }
    let missing: Vec<&str> = RECOMMENDED_DENY_READ
        .iter()
        .copied()
        .filter(|g| !state.deny_read.iter().any(|d| d == g))
        .collect();
    if missing.is_empty() {
        out.push_str("  sandbox.filesystem.denyRead: all recommended globs present\n");
    } else {
        out.push_str(&format!(
            "  sandbox.filesystem.denyRead: {} of {} recommended globs missing: {}\n",
            missing.len(),
            RECOMMENDED_DENY_READ.len(),
            missing.join(", ")
        ));
    }
    let enabled = matches!(state.enabled, Some((_, true)));
    if !enabled || !missing.is_empty() {
        let snippet = serde_json::json!({
            "sandbox": {
                "enabled": true,
                "filesystem": { "denyRead": RECOMMENDED_DENY_READ },
            }
        });
        out.push_str(
            "\nrecommended (merge into ~/.claude/settings.json; sandboxed commands then cannot read these files, including your own tools run by the agent, e.g. a dev server loading .env):\n",
        );
        out.push_str(&serde_json::to_string_pretty(&snippet).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(
        "\nenv files: use `safe-ai-skill env keys|set|unset` instead of raw reads; `secrets.env_read: ask` in the plugin policy restores prompted raw reads.\n",
    );
    out
}

/// `safe-ai-skill doctor` entry point. Always exits 0 (it only reports).
pub fn main(_args: &[String]) -> ExitCode {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let text = report(home.as_deref(), &cwd);
    let _ = std::io::stdout().lock().write_all(text.as_bytes());
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn later_files_override_enabled_and_lists_merge() {
        let dir = std::env::temp_dir().join(format!("doctor-unit-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("home/.claude")).unwrap();
        std::fs::create_dir_all(dir.join("proj/.claude")).unwrap();
        std::fs::write(
            dir.join("home/.claude/settings.json"),
            r#"{"sandbox":{"enabled":true,"filesystem":{"denyRead":["**/.env"]}}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("proj/.claude/settings.local.json"),
            r#"{"sandbox":{"enabled":false,"filesystem":{"denyRead":["**/.envrc"]}}}"#,
        )
        .unwrap();
        let state = read_state(&settings_files(Some(&dir.join("home")), &dir.join("proj")));
        assert!(matches!(state.enabled, Some((_, false))));
        assert_eq!(state.deny_read, vec!["**/.env", "**/.envrc"]);
        let text = report(Some(&dir.join("home")), &dir.join("proj"));
        assert!(text.contains("sandbox: not enabled (disabled in"), "{text}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
