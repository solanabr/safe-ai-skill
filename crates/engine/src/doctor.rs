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
use std::sync::LazyLock;

use serde_json::Value;

use crate::gates::credpaths;
use crate::lists::SbTier;

/// Globs recommended for `sandbox.filesystem.denyRead` beyond the credential stores: the
/// hard-deny and env classes. `~/.config/solana/*.json` (not `**`) keeps `cli/config.yml`
/// readable for the Solana CLI; `**/.env.*` also hides `.env.example` from sandboxed commands
/// (the Read tool still sees it). Claude Code transcripts and the data dir's state key are
/// listed because transcripts record the hook messages that carry confirmation codes, and the
/// key signs safe-ai-skill's state.
const BASE_DENY_READ: &[&str] = &[
    "~/.claude/projects/**",
    "~/.claude/plugins/data/safe-ai-skill-*/key",
    "**/*-keypair.json",
    "~/.config/solana/*.json",
    "~/.ssh/id_*",
    "~/.superstack/config.json",
    "~/.config/varlock/**",
    "~/.varlock/**",
    "**/.env",
    "**/.env.*",
    "**/*.env",
    "**/.envrc",
    "**/.dev.vars",
    "**/.dev.vars.*",
    "**/.varlock-frozen-env",
];

/// The recommended `denyRead` globs: [`BASE_DENY_READ`] plus one per shared-list credential
/// record with `sb` = relaxed (the kit's Relaxed sandbox carries the same entries), generated
/// from [`crate::lists::credentials`] for this OS. Host tokens (`~/.npmrc`, `gh/hosts.yml`,
/// `~/.docker/config.json`, …) are sandbox-denied only from Medium, because denying them at
/// Relaxed breaks subprocess `gh`, `npm`, `git` and `docker`: see [`MEDIUM_DENY_READ`].
pub static RECOMMENDED_DENY_READ: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut all: Vec<String> = BASE_DENY_READ.iter().map(|g| g.to_string()).collect();
    for glob in credpaths::sandbox_deny_read(SbTier::Relaxed) {
        if !all.contains(&glob) {
            all.push(glob);
        }
    }
    all
});

/// The additional globs for a Medium or High sandbox (`sb` = medium and high records).
pub static MEDIUM_DENY_READ: LazyLock<Vec<String>> = LazyLock::new(|| {
    credpaths::sandbox_deny_read(SbTier::High)
        .into_iter()
        .filter(|g| !RECOMMENDED_DENY_READ.contains(g))
        .collect()
});

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
        .map(String::as_str)
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
        // A relocated `$CLAUDE_CONFIG_DIR` keeps its login file under that path.
        let mut deny_read: Vec<String> = RECOMMENDED_DENY_READ.clone();
        deny_read.extend(credpaths::config_dir_deny_read(SbTier::Relaxed));
        let snippet = serde_json::json!({
            "sandbox": {
                "enabled": true,
                "filesystem": { "denyRead": deny_read },
            }
        });
        out.push_str(
            "\nrecommended (merge into ~/.claude/settings.json; sandboxed commands then cannot read these files, including your own tools run by the agent, e.g. a dev server loading .env):\n",
        );
        out.push_str(&serde_json::to_string_pretty(&snippet).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(if crate::gates::envread::OPT_IN_AVAILABLE {
        "\nenv files: use `safe-ai-skill env keys|set|unset` instead of raw reads; `safe-ai-skill tier --env-read ask` (user scope, needs the sandbox on) restores prompted raw reads.\n"
    } else {
        "\nenv files: use `safe-ai-skill env keys|set|unset` instead of raw reads (raw reads are denied at every tier; the raw read opt-in is not available in this build).\n"
    });
    if !MEDIUM_DENY_READ.is_empty() {
        out.push_str(&format!(
            "\nadd for a Medium or High sandbox (host tokens: denying them also stops subprocess `gh`, `npm install` from a private registry, `git push` over a credential file, `docker pull`, and cargo/pypi/gem publish from reading their own login): {}\n",
            MEDIUM_DENY_READ.join(", ")
        ));
    }
    out.push_str(
        "\ncredential stores: the hooks deny the agent's reads of home credential stores (~/.ssh keys, ~/.aws, ~/.npmrc and other host tokens, keychains, browser profiles, wallet extension data) at every tier: Read, file Grep, MCP path arguments, any Bash command that names such a path (metadata-only commands such as `ls` excepted), a recursive search or archive rooted at or above a store, and command-form readers (gh auth token, git credential fill, security find-generic-password -w, pass show, op read, bw get, ...). Residual: the hook's analysis of a command line is incomplete (variables, eval, encodings, scripts that build the path, subprocess and compiled reads are not seen). The sandbox denyRead list above is the real control.\n",
    );
    out
}

/// `safe-ai-skill doctor` entry point. Always exits 0 (it only reports). `--codex` runs the
/// Codex hook check instead ([`crate::adapt::codex_doctor`]), which exits 1 on a failure.
pub fn main(args: &[String]) -> ExitCode {
    if args.first().map(String::as_str) == Some("--codex") {
        return crate::adapt::codex_doctor::main();
    }
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
    fn transcripts_and_state_key_are_recommended() {
        let out = report(None, std::path::Path::new("/nonexistent"));
        for glob in [
            "~/.claude/projects/**",
            "~/.claude/plugins/data/safe-ai-skill-*/key",
        ] {
            assert!(RECOMMENDED_DENY_READ.iter().any(|g| g == glob), "{glob}");
            assert!(out.contains(glob), "{out}");
        }
    }

    #[test]
    fn the_snippet_is_generated_from_the_credential_list() {
        let out = report(None, std::path::Path::new("/nonexistent"));
        for glob in ["~/.aws/**", "~/.gnupg/**", "~/.ssh/**"] {
            assert!(RECOMMENDED_DENY_READ.iter().any(|g| g == glob), "{glob}");
            assert!(out.contains(glob), "{glob}: {out}");
        }
        // Host tokens are sandbox-denied from Medium: printed apart, with what they break.
        for glob in [
            "~/.npmrc",
            "~/.docker/config.json",
            "~/.config/gh/hosts.yml",
        ] {
            assert!(!RECOMMENDED_DENY_READ.iter().any(|g| g == glob), "{glob}");
            assert!(MEDIUM_DENY_READ.iter().any(|g| g == glob), "{glob}");
            assert!(out.contains(glob), "{glob}: {out}");
        }
        assert!(out.contains("add for a Medium or High sandbox"), "{out}");
        // sb=never entries (the Solana CLI must read them) stay out of the generated part.
        assert!(!RECOMMENDED_DENY_READ
            .iter()
            .any(|g| g == "~/.config/solana/**"));
        assert!(
            out.contains("Residual: the hook's analysis of a command line is incomplete"),
            "{out}"
        );
    }

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
