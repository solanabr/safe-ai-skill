//! Writes to project env files (D8 v2 spec §2): Write/Edit/MultiEdit to a project env file,
//! and an agent's `safe-ai-skill env set|unset`, are denied at Medium and High (no opinion at
//! Off and Relaxed). `env keys` and `env init-schema` are never gated.
//!
//! No Bash write coverage is claimed (`sed -i`, `perl -pi`, redirects; spec §8): only the
//! sandbox's `denyWrite` closes those. `decide_cli` recognises `safe-ai-skill env set|unset` in
//! command position: after `;`/`&&`/`|`/`$(`, assignments and the usual wrappers (`sudo`,
//! `env -u X`, `timeout 5`, `xargs`, `npx`, …), and inside `sh -c '…'` / `eval`.
//!
//! Call lines (shared files): `main::cmd_gate_tamper` ([`decide_file`]) and
//! `main::cmd_gate_bash_secrets` ([`decide_cli`]).

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::context::tokenize;
use crate::gate::Verdict;
use crate::gates::secretpath::{self, Class};
use crate::policy::tier::Tier;
use crate::policy::Policy;

/// How deep `sh -c` / `eval` nesting is followed.
const MAX_NESTING: usize = 4;

/// The verdict for a Write|Edit|MultiEdit|NotebookEdit `tool_input`; `None` is no opinion.
pub fn decide_file(
    tool_input: Option<&Value>,
    cwd: &Path,
    policy: &Policy,
    tier: Tier,
) -> Option<Verdict> {
    let _ = policy;
    if tier < Tier::Medium {
        return None;
    }
    let input = tool_input?.as_object()?;
    let file = ["file_path", "notebook_path"]
        .iter()
        .find_map(|k| input.get(*k).and_then(Value::as_str))?;
    if !is_project_env(file, cwd) {
        return None;
    }
    let label = Path::new(file)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".env".to_string());
    Some(Verdict::Deny(format!(
        "safe-ai-skill: tier {} denies agent writes to project env files ({label}). Ask the user to edit it, or to set a value in their own terminal: `printf %s '<value>' | safe-ai-skill env set {label} KEY`. `safe-ai-skill env keys {label}` lists the keys.",
        tier.label()
    )))
}

/// The verdict for a Bash `command` that may run `safe-ai-skill env set|unset`; `None` is no
/// opinion.
pub fn decide_cli(command: &str, cwd: &Path, policy: &Policy, tier: Tier) -> Option<Verdict> {
    let _ = (cwd, policy);
    if tier < Tier::Medium {
        return None;
    }
    let action = env_write_action(command, 0)?;
    Some(Verdict::Deny(format!(
        "safe-ai-skill: tier {} denies agent writes to project env files (`safe-ai-skill env {action}`). Ask the user to run it in their own terminal (`printf %s '<value>' | safe-ai-skill env set FILE KEY`), or to edit the file. `safe-ai-skill env keys FILE` still works.",
        tier.label()
    )))
}

/// Whether `file` (absolute, or relative to `cwd`) is a project env file, by its name or, for
/// an existing path or symlink, by the file it resolves to. The Solana CLI config (env class
/// for reads) is not a project env file.
fn is_project_env(file: &str, cwd: &Path) -> bool {
    let raw = expand(file, cwd);
    let mut candidates = vec![raw.clone()];
    if let Some(real) = resolve(&raw) {
        candidates.push(real);
    }
    candidates.iter().any(|path| {
        let text = path.to_string_lossy();
        secretpath::classify(&text) == Class::Env
            && !text
                .replace('\\', "/")
                .to_ascii_lowercase()
                .ends_with("/.config/solana/cli/config.yml")
    })
}

fn expand(file: &str, cwd: &Path) -> PathBuf {
    let file = file.trim();
    if let (Some(rest), Some(home)) = (file.strip_prefix("~/"), std::env::var_os("HOME")) {
        return PathBuf::from(home).join(rest);
    }
    let path = PathBuf::from(file);
    if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    }
}

/// The canonical path of `path`, or of its parent joined with its name when it does not exist.
fn resolve(path: &Path) -> Option<PathBuf> {
    if let Ok(real) = std::fs::canonicalize(path) {
        return Some(real);
    }
    let parent = std::fs::canonicalize(path.parent()?).ok()?;
    Some(parent.join(path.file_name()?))
}

/// `set` or `unset` when `command` runs `safe-ai-skill env set|unset` in command position.
fn env_write_action(command: &str, depth: usize) -> Option<&'static str> {
    if depth > MAX_NESTING {
        return None;
    }
    segments(command)
        .iter()
        .find_map(|seg| segment_action(&tokenize(seg), depth))
}

/// Split `command` at unquoted `;`, `&`, `|`, newlines, parentheses and backticks (so `$(…)`
/// and `` `…` `` bodies become segments of their own). Quotes are kept for [`tokenize`].
fn segments(command: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for c in command.chars() {
        if escaped {
            current.push(c);
            escaped = false;
            continue;
        }
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                } else if c == '\\' && q == '"' {
                    escaped = true;
                }
                current.push(c);
            }
            None => match c {
                '\\' => {
                    escaped = true;
                    current.push(c);
                }
                '\'' | '"' => {
                    quote = Some(c);
                    current.push(c);
                }
                ';' | '&' | '|' | '\n' | '(' | ')' | '`' => {
                    out.push(std::mem::take(&mut current));
                }
                _ => current.push(c),
            },
        }
    }
    out.push(current);
    out.retain(|s| !s.trim().is_empty());
    out
}

/// The action of one simple command (already tokenized, quotes removed).
fn segment_action(tokens: &[String], depth: usize) -> Option<&'static str> {
    let rest = skip_prefix(tokens);
    let (program, args) = rest.split_first()?;
    let name = base_name(program);
    if is_shell(&name) {
        let script = shell_script(args)?;
        return env_write_action(script, depth + 1);
    }
    if name == "eval" {
        return env_write_action(&args.join(" "), depth + 1);
    }
    if name != "safe-ai-skill" {
        return None;
    }
    let mut positional = args.iter().filter(|a| !a.starts_with('-'));
    if positional.next().map(String::as_str) != Some("env") {
        return None;
    }
    match positional.next().map(String::as_str) {
        Some("set") => Some("set"),
        Some("unset") => Some("unset"),
        _ => None,
    }
}

/// `tokens` without leading assignments (`FOO=1`) and wrappers that run the rest of the line,
/// with their options.
fn skip_prefix(tokens: &[String]) -> &[String] {
    let mut rest = tokens;
    loop {
        let Some((first, tail)) = rest.split_first() else {
            return rest;
        };
        if is_assignment(first) {
            rest = tail;
            continue;
        }
        let name = base_name(first);
        let takes_value: &[&str] = match name.as_str() {
            "sudo" | "doas" => &["-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U"],
            "env" => &["-u", "-C", "-S", "--unset", "--chdir"],
            "nice" => &["-n", "--adjustment"],
            "xargs" => &["-n", "-I", "-L", "-P", "-d", "-s", "-a", "-E", "-i"],
            "timeout" => &["-s", "-k", "--signal", "--kill-after"],
            "stdbuf" => &["-i", "-o", "-e"],
            "npx" | "pnpx" | "bunx" => &["-p", "--package"],
            "exec" | "nohup" | "time" | "command" | "builtin" => &[],
            "npm" | "pnpm" | "yarn" | "bun" => {
                rest = skip_runner(tail);
                continue;
            }
            _ => return rest,
        };
        rest = tail;
        // Options (and their values), then for `timeout` its duration.
        while let Some((opt, after)) = rest.split_first() {
            if is_assignment(opt) && name == "env" {
                rest = after;
            } else if opt == "--" {
                rest = after;
                break;
            } else if opt.starts_with('-') && opt.len() > 1 {
                rest = after;
                if takes_value.contains(&opt.as_str()) {
                    rest = rest.split_first().map_or(rest, |(_, r)| r);
                }
            } else {
                break;
            }
        }
        if name == "timeout" {
            rest = rest.split_first().map_or(rest, |(_, r)| r);
        }
    }
}

/// After `npm`/`pnpm`/`yarn`/`bun`: `exec`/`dlx`/`x` (and options, `--`) run the next word.
fn skip_runner(tokens: &[String]) -> &[String] {
    let Some((sub, mut rest)) = tokens.split_first() else {
        return tokens;
    };
    if !matches!(sub.as_str(), "exec" | "dlx" | "x" | "run") {
        return tokens;
    }
    while let Some((opt, after)) = rest.split_first() {
        if opt.starts_with('-') {
            rest = after;
        } else {
            break;
        }
    }
    rest
}

/// The `-c` script of a shell invocation (`-c`, `-lc`, `-ec` …).
fn shell_script(args: &[String]) -> Option<&str> {
    let i = args
        .iter()
        .position(|a| a.starts_with('-') && !a.starts_with("--") && a.contains('c'))?;
    args.get(i + 1).map(String::as_str)
}

fn is_shell(name: &str) -> bool {
    matches!(name, "sh" | "bash" | "zsh" | "dash" | "ksh" | "fish")
}

fn is_assignment(tok: &str) -> bool {
    tok.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty()
            && !name.starts_with(|c: char| c.is_ascii_digit())
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// The last path component, lowercased, without `.exe`.
fn base_name(word: &str) -> String {
    let base = word.rsplit(['/', '\\']).next().unwrap_or(word);
    let base = base.to_ascii_lowercase();
    base.strip_suffix(".exe")
        .map(str::to_string)
        .unwrap_or(base)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action(cmd: &str) -> Option<&'static str> {
        env_write_action(cmd, 0)
    }

    #[test]
    fn env_set_and_unset_in_command_position() {
        for (cmd, want) in [
            ("safe-ai-skill env set .env K", Some("set")),
            ("printf v | safe-ai-skill env set .env K", Some("set")),
            ("safe-ai-skill env unset .env K", Some("unset")),
            ("sudo -u me safe-ai-skill env unset .env K", Some("unset")),
            ("nice -n 5 /x/Safe-Ai-Skill.exe env set .env K", Some("set")),
            ("sh -lc 'safe-ai-skill env set .env K'", Some("set")),
            ("eval safe-ai-skill env unset .env K", Some("unset")),
            ("x=$(safe-ai-skill env set .env K)", Some("set")),
            ("npx -y safe-ai-skill env set .env K", Some("set")),
            ("npm exec -- safe-ai-skill env unset .env K", Some("unset")),
            ("xargs -n 1 safe-ai-skill env unset .env", Some("unset")),
            (
                "bash -c \"sh -c 'safe-ai-skill env set .env K'\"",
                Some("set"),
            ),
            ("safe-ai-skill env keys .env", None),
            ("safe-ai-skill env init-schema", None),
            ("safe-ai-skill tier medium", None),
            ("echo safe-ai-skill env set .env K", None),
            ("git commit -m 'safe-ai-skill env set'", None),
            ("sed -i s/a/b/ .env", None),
        ] {
            assert_eq!(action(cmd), want, "{cmd}");
        }
    }

    #[test]
    fn nesting_is_bounded() {
        let mut cmd = "safe-ai-skill env set .env K".to_string();
        for _ in 0..8 {
            cmd = format!("sh -c {}", shell_quote(&cmd));
        }
        assert_eq!(action(&cmd), None);
    }

    fn shell_quote(s: &str) -> String {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}
