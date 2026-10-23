//! Hook adapters for clients other than Claude Code (experimental, issue #23).
//!
//! `safe-ai-skill adapt codex <gate>` runs one PreToolUse gate on a Codex CLI hook payload.
//! Codex sends Claude-shaped PreToolUse JSON (`tool_name` `Bash` with `tool_input.command`,
//! MCP tools as `mcp__<server>__<tool>`), so the gates read it unchanged. Two things differ:
//!
//! - **Output.** Codex PreToolUse honours only `deny`. An `ask` or a bare `allow` is an
//!   "unsupported" output that Codex logs and then runs the call anyway, so [`render`] turns
//!   every `ask` into a `deny` (adding [`CODEX_ASK_SUFFIX`]) and an `allow` into no output.
//! - **File edits.** Codex edits files through `apply_patch`, whose `tool_input.command` is
//!   the patch text. [`patch_paths`] lists the files it touches, so the tamper gate can judge
//!   each one.
//!
//! The client is a process-wide setting chosen once by the `adapt` subcommand before the gate
//! runs; every emitter consults it through [`current`].

use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

use crate::io::Decision;

/// The hook client whose output contract applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Client {
    /// Claude Code (the default): `allow`, `ask` and `deny` are all honoured.
    ClaudeCode,
    /// Codex CLI: only `deny` blocks; `ask` and a bare `allow` fail open.
    Codex,
}

static CLIENT: OnceLock<Client> = OnceLock::new();

/// Select the client for this process. The first call wins.
pub fn set(client: Client) {
    let _ = CLIENT.set(client);
}

/// The client selected for this process ([`Client::ClaudeCode`] unless `adapt` chose another).
pub fn current() -> Client {
    CLIENT.get().copied().unwrap_or(Client::ClaudeCode)
}

/// Parse an `adapt` client name.
pub fn client_named(name: &str) -> Option<Client> {
    match name {
        "codex" => Some(Client::Codex),
        _ => None,
    }
}

/// The gates `adapt codex` runs. Codex has no `Read`/`Grep`/`Glob` or `Skill` tool, and its
/// PostToolUse cannot rewrite output, so `gate-read`, `gate-skill` and `redact` are not offered.
pub const CODEX_GATES: [&str; 4] = ["gate-bash", "gate-bash-secrets", "gate-tamper", "gate-mcp"];

/// Appended to an `ask` reason when Codex gets it as a `deny`.
pub const CODEX_ASK_SUFFIX: &str = "Codex hooks cannot ask for approval, so safe-ai-skill \
     blocked it: run it yourself, approve it in a Claude Code session, or confirm a grant there \
     first where one applies.";

/// Translate a decision for `client`: under Codex an `ask` becomes a `deny` (same reason plus
/// [`CODEX_ASK_SUFFIX`]) and an `allow` becomes no opinion, since Codex runs the call on both.
pub fn render(decision: &Decision, client: Client) -> Decision {
    match (client, decision) {
        (Client::Codex, Decision::Ask { reason }) => Decision::Deny {
            reason: format!("{reason} {CODEX_ASK_SUFFIX}"),
        },
        (Client::Codex, Decision::Allow) => Decision::Defer,
        _ => decision.clone(),
    }
}

/// The file paths an `apply_patch` patch adds, updates, deletes or moves to, in order, without
/// duplicates. Lines are matched after trimming, so an indented or CRLF patch still parses.
pub fn patch_paths(patch: &str) -> Vec<String> {
    const MARKERS: [&str; 4] = [
        "*** Add File:",
        "*** Update File:",
        "*** Delete File:",
        "*** Move to:",
    ];
    let mut paths: Vec<String> = Vec::new();
    for line in patch.lines().map(str::trim) {
        let Some(path) = MARKERS
            .iter()
            .find_map(|m| line.strip_prefix(m))
            .map(str::trim)
            .filter(|p| !p.is_empty())
        else {
            continue;
        };
        if !paths.iter().any(|p| p == path) {
            paths.push(path.to_string());
        }
    }
    paths
}

/// Whether `target` (relative to `cwd`, `~` expanded with `home`) is a Codex hook config file:
/// `.codex/hooks.json` or `.codex/config.toml` anywhere, the files that wire these gates in.
pub fn is_codex_hook_config(target: &str, cwd: &Path, home: Option<&Path>) -> bool {
    let expanded = match (target.strip_prefix("~/"), home) {
        (Some(rest), Some(home)) => home.join(rest),
        _ => PathBuf::from(target),
    };
    let full = if expanded.is_absolute() {
        expanded
    } else {
        cwd.join(expanded)
    };
    let mut parts: Vec<String> = Vec::new();
    for c in full.components() {
        match c {
            Component::ParentDir => {
                parts.pop();
            }
            Component::Normal(s) => parts.push(s.to_string_lossy().to_ascii_lowercase()),
            _ => {}
        }
    }
    match parts.as_slice() {
        [.., dir, file] => dir == ".codex" && (file == "hooks.json" || file == "config.toml"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codex_ask_becomes_deny_and_allow_becomes_no_output() {
        let ask = Decision::Ask {
            reason: "mainnet deploy".into(),
        };
        match render(&ask, Client::Codex) {
            Decision::Deny { reason } => {
                assert!(reason.starts_with("mainnet deploy "), "{reason}");
                assert!(reason.ends_with(CODEX_ASK_SUFFIX), "{reason}");
            }
            other => panic!("expected deny, got {other:?}"),
        }
        assert_eq!(render(&Decision::Allow, Client::Codex), Decision::Defer);
        let deny = Decision::Deny { reason: "x".into() };
        assert_eq!(render(&deny, Client::Codex), deny);
        assert_eq!(render(&Decision::Defer, Client::Codex), Decision::Defer);
    }

    #[test]
    fn claude_code_decisions_pass_unchanged() {
        let ask = Decision::Ask { reason: "r".into() };
        assert_eq!(render(&ask, Client::ClaudeCode), ask);
        assert_eq!(
            render(&Decision::Allow, Client::ClaudeCode),
            Decision::Allow
        );
    }

    #[test]
    fn patch_paths_lists_every_touched_file_once() {
        let patch = "*** Begin Patch\n*** Add File: a/new.txt\n+hi\n*** Update File: src/lib.rs\n\
                     *** Move to: src/core.rs\n@@\n-x\n+y\n*** Delete File: old.txt\n\
                     *** Update File: src/lib.rs\n*** End Patch";
        assert_eq!(
            patch_paths(patch),
            ["a/new.txt", "src/lib.rs", "src/core.rs", "old.txt"]
        );
    }

    #[test]
    fn patch_paths_tolerates_crlf_and_indentation_and_ignores_bodies() {
        let patch = "*** Begin Patch\r\n  *** Add File: x.json \r\n+*** Add File: not/a/header\r\n";
        assert_eq!(patch_paths(patch), ["x.json"]);
        assert!(patch_paths("no headers").is_empty());
        assert!(patch_paths("*** Add File:   \n").is_empty());
    }

    #[test]
    fn codex_hook_config_paths_are_recognized() {
        let cwd = Path::new("/w/proj");
        let home = Some(Path::new("/home/u"));
        for p in [
            ".codex/hooks.json",
            ".codex/config.toml",
            "sub/../.codex/hooks.json",
            "/w/proj/.CODEX/Hooks.json",
            "~/.codex/hooks.json",
        ] {
            assert!(is_codex_hook_config(p, cwd, home), "{p}");
        }
        for p in [".codex/notes.md", "codex/hooks.json", "hooks.json", "/"] {
            assert!(!is_codex_hook_config(p, cwd, home), "{p}");
        }
    }
}
