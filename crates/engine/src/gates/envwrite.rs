//! Writes to env files by tier (solana-ai-kit's model, #16).
//!
//! | Write                                              | Off | Relaxed | Medium | High |
//! |----------------------------------------------------|-----|---------|--------|------|
//! | project `.env` / `.env.*` ([`envread::is_project_env`]) | n/o | n/o | deny | n/o  |
//! | other env files (`.envrc`, `*.env`, `.dev.vars`, outside the project) | n/o | n/o | deny | deny |
//! | a redaction marker written into any env file       | deny | deny   | deny   | deny |
//!
//! A write is Write/Edit/MultiEdit/NotebookEdit to the file ([`decide_file`]), an agent's
//! `safe-ai-skill env set|unset` ([`decide_cli`]), and a Bash command that moves, removes,
//! overwrites or edits it in place ([`bash_write`], from `creddump`: `rm`, `mv`, `cp` onto it,
//! `>`/`>>`, `tee`, `truncate`, `dd of=`, `sed -i`, `perl -i`, interpreter code naming it with a
//! write call, [`code_writes`]). Medium denies rather than asks: an ask is walked around by
//! `python3 -c`, `perl -pi` or `sed -i`. High leaves writes open, as the kit does: the model can
//! no longer read the file back. Bash coverage is a tripwire; the sandbox's `denyWrite` is the
//! control. `env keys` and `env init-schema` are never gated. `decide_cli` recognises
//! `safe-ai-skill env set|unset` in command position: after `;`/`&&`/`|`/`$(`, assignments and
//! the usual wrappers (`sudo`, `env -u X`, `timeout 5`, `xargs`, `npx`, …), and inside
//! `sh -c '…'` / `eval`.
//!
//! Call lines (shared files): `main::cmd_gate_tamper` ([`decide_file`]),
//! `main::cmd_gate_bash_secrets` ([`decide_cli`]) and `creddump::inspect` ([`bash_write`]).

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::context::tokenize;
use crate::gate::Verdict;
use crate::gates::envread;
use crate::gates::secretpath::{self, Class};
use crate::policy::tier::Tier;
use crate::policy::Policy;

/// How deep `sh -c` / `eval` nesting is followed.
const MAX_NESTING: usize = 4;

/// Lowercase write calls in interpreter code (Python, Node, Deno, Ruby, PHP), tied to a call
/// rather than a bare token: `stdout.write` and `print('w', …)` are not writes.
const CODE_WRITE_CALLS: &[&str] = &[
    ".write_text(",
    ".write_bytes(",
    "writefile",
    "appendfile",
    "createwritestream",
    "set_key(",
    "unset_key(",
    "os.replace(",
    "os.rename(",
    "os.remove(",
    "os.unlink(",
    "os.truncate(",
    "shutil.copy",
    "shutil.move",
    "fs.rm",
    "fs.unlink",
    "fs.rename",
    "fs.copyfile",
    "fs.truncate",
    "file.write(",
    "io.write(",
    "file_put_contents(",
    "deno.writetextfile",
    "deno.writefile",
    "deno.remove(",
    "deno.rename(",
    "o_wronly",
    "o_rdwr",
    "o_append",
    "o_trunc",
];

/// Whether interpreter `code` shows a file write: a write call ([`CODE_WRITE_CALLS`]) or an
/// `open(…)` (also `File.open`, `fopen`, Perl `open F, …`) whose mode string writes (`w`,
/// `a`, `x`, `+`, or Perl's `>`, `>>`, `+<`). Code that names an env file and writes is an env
/// write (it may also read it). Callers pass the code strings only.
pub fn code_writes(code: &str) -> bool {
    let lower = code.to_ascii_lowercase();
    if CODE_WRITE_CALLS.iter().any(|m| lower.contains(m)) {
        return true;
    }
    lower.match_indices("open").any(|(i, m)| {
        let after = &lower[i.saturating_add(m.len())..];
        let args = after.trim_start_matches([' ', '(']);
        let segment = args.split([')', ';', '\n']).next().unwrap_or("");
        quoted_strings(segment).any(|q| {
            let q = q.trim();
            q.starts_with('>')
                || q.starts_with("+<")
                || (!q.is_empty()
                    && q.len() <= 4
                    && q.chars().all(|c| "rwaxbtu+".contains(c))
                    && q.chars().any(|c| "wax+".contains(c)))
        })
    })
}

/// The contents of the single- and double-quoted strings in `text`.
fn quoted_strings(text: &str) -> impl Iterator<Item = &str> {
    let mut rest = text;
    std::iter::from_fn(move || {
        let start = rest.find(['\'', '"'])?;
        let quote = rest[start..].chars().next()?;
        let body = &rest[start.saturating_add(1)..];
        let Some(end) = body.find(quote) else {
            rest = "";
            return None;
        };
        let found = &body[..end];
        rest = &body[end.saturating_add(1)..];
        Some(found)
    })
}

/// Whether the env-write rule denies a write to an env file at `tier`: Medium for a project
/// env file, Medium and High for any other env file.
fn denies(project: bool, tier: Tier) -> bool {
    tier == Tier::Medium || (!project && tier == Tier::High)
}

/// The verdict for a Write|Edit|MultiEdit|NotebookEdit `tool_input`; `None` is no opinion.
pub fn decide_file(
    tool_input: Option<&Value>,
    cwd: &Path,
    policy: &Policy,
    tier: Tier,
) -> Option<Verdict> {
    let _ = policy;
    let input = tool_input?.as_object()?;
    let file = ["file_path", "notebook_path"]
        .iter()
        .find_map(|k| input.get(*k).and_then(Value::as_str))?;
    if is_dotenv_keys_target(file, cwd) {
        return Some(Verdict::Deny(
            "safe-ai-skill: this is a dotenvx private-key file (`.env.keys`): key material, so agent writes, edits and removal are denied at every tier. Edit it yourself.".to_string(),
        ));
    }
    if !is_env_target(file, cwd) {
        return None;
    }
    if let Some(reason) = envread::key_material_reason(file, cwd) {
        return Some(Verdict::Deny(reason));
    }
    let label = Path::new(file)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".env".to_string());
    // At every tier: a redaction marker written into an env file replaces a real secret with
    // the marker (the model saw a pattern-redacted Read and copied it back).
    if writes_redaction_marker(input) {
        return Some(Verdict::Deny(format!(
            "safe-ai-skill: this write would put a redaction marker (`***REDACTED:…***` / `«redacted:…»`) into {label}, overwriting a real secret. Edit only the lines you need, or ask the user to set the value: `printf %s '<value>' | safe-ai-skill env set {label} KEY`."
        )));
    }
    let project = envread::is_project_env(file, cwd);
    if !denies(project, tier) {
        return None;
    }
    Some(Verdict::Deny(format!(
        "safe-ai-skill: tier {} denies agent writes to {} ({label}). Ask the user to edit it, or to set a value in their own terminal: `printf %s '<value>' | safe-ai-skill env set {label} KEY`. `safe-ai-skill env keys {label}` lists the keys.",
        tier.label(),
        what(project)
    )))
}

/// `project env files` or `env files outside the project's .env/.env.*` for a reason.
fn what(project: bool) -> &'static str {
    if project {
        "project env files"
    } else {
        "env files other than the project's .env/.env.*"
    }
}

/// The verdict for a Bash `command` that may run `safe-ai-skill env set|unset`; `None` is no
/// opinion.
pub fn decide_cli(command: &str, cwd: &Path, policy: &Policy, tier: Tier) -> Option<Verdict> {
    let _ = policy;
    if tier < Tier::Medium {
        return None;
    }
    let (action, file) = env_write_action(command, 0)?;
    let project = file
        .as_deref()
        .is_none_or(|f| envread::is_project_env(f, cwd));
    if !denies(project, tier) {
        return None;
    }
    Some(Verdict::Deny(format!(
        "safe-ai-skill: tier {} denies agent writes to {} (`safe-ai-skill env {action}`). Ask the user to run it in their own terminal (`printf %s '<value>' | safe-ai-skill env set FILE KEY`), or to edit the file. `safe-ai-skill env keys FILE` still works.",
        tier.label(),
        what(project)
    )))
}

/// The verdict for a Bash command that moves, removes, overwrites or edits in place the env file
/// `label` ([`envread::is_project_env`] says `project`): a write, by the tier.
pub fn bash_write(label: &str, project: bool, tier: Tier) -> Option<Verdict> {
    if !denies(project, tier) {
        return None;
    }
    Some(Verdict::Deny(format!(
        "safe-ai-skill: tier {} denies agent writes to {} ({label} would be moved, removed, overwritten or edited in place). Ask the user to do it in their own terminal. `safe-ai-skill env keys {label}` lists the keys.",
        tier.label(),
        what(project)
    )))
}

/// Whether the new text of a Write (`content`), Edit (`new_string`), MultiEdit
/// (`edits[].new_string`) or NotebookEdit (`new_source`) holds a redaction marker.
fn writes_redaction_marker(input: &serde_json::Map<String, Value>) -> bool {
    let marked = |v: Option<&Value>| {
        v.and_then(Value::as_str)
            .is_some_and(crate::redact::contains_marker)
    };
    marked(input.get("content"))
        || marked(input.get("new_string"))
        || marked(input.get("new_source"))
        || input
            .get("edits")
            .and_then(Value::as_array)
            .is_some_and(|edits| edits.iter().any(|e| marked(e.get("new_string"))))
}

/// Whether `file` (absolute, or relative to `cwd`), by its name or the file it resolves to, is
/// a dotenvx private-key file ([`envread::is_dotenv_keys_name`]).
fn is_dotenv_keys_target(file: &str, cwd: &Path) -> bool {
    let raw = expand(file, cwd);
    let mut candidates = vec![raw.clone()];
    if let Some(real) = resolve(&raw) {
        candidates.push(real);
    }
    candidates.iter().any(|p| {
        p.file_name()
            .is_some_and(|n| envread::is_dotenv_keys_name(&n.to_string_lossy()))
    })
}

/// Whether `file` (absolute, or relative to `cwd`) is an env-class file, by its name or, for an
/// existing path or symlink, by the file it resolves to. The Solana CLI config (env class for
/// reads) is not a write target here.
fn is_env_target(file: &str, cwd: &Path) -> bool {
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

/// `set` or `unset` (with the FILE operand, when given) when `command` runs
/// `safe-ai-skill env set|unset` in command position.
type Action = (&'static str, Option<String>);

/// See [`Action`].
fn env_write_action(command: &str, depth: usize) -> Option<Action> {
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
fn segment_action(tokens: &[String], depth: usize) -> Option<Action> {
    if depth > MAX_NESTING {
        return None;
    }
    let deeper = depth.saturating_add(1);
    let rest = skip_prefix(tokens);
    let (program, args) = rest.split_first()?;
    let name = base_name(program);
    if is_shell(&name) {
        let script = shell_script(args)?;
        return env_write_action(script, deeper);
    }
    match name.as_str() {
        "eval" => return env_write_action(&args.join(" "), deeper),
        "watch" => {
            return env_write_action(&skip_options(args, &["-n", "--interval"]).join(" "), deeper)
        }
        "script" => return script_action(args, deeper),
        "find" => return find_exec_action(args, deeper),
        "node" | "bun" | "deno" => return node_cli_action(args),
        _ => {}
    }
    if !is_engine_binary(&name) {
        return None;
    }
    env_action(args)
}

/// `env set|unset` (and its FILE) among the arguments of a safe-ai-skill invocation.
fn env_action(args: &[String]) -> Option<Action> {
    let mut positional = args.iter().filter(|a| !a.starts_with('-'));
    if positional.next().map(String::as_str) != Some("env") {
        return None;
    }
    let action = match positional.next().map(String::as_str) {
        Some("set") => "set",
        Some("unset") => "unset",
        _ => return None,
    };
    Some((action, positional.next().cloned()))
}

/// The engine binary: `safe-ai-skill`, or a per-platform build `safe-ai-skill-<os>-<arch>`.
fn is_engine_binary(name: &str) -> bool {
    name == "safe-ai-skill" || name.starts_with("safe-ai-skill-")
}

/// `node …/safe-ai-skill/…/cli.js env set …` (the npm launcher).
fn node_cli_action(args: &[String]) -> Option<Action> {
    let rest = skip_options(args, &[]);
    let (script, tail) = rest.split_first()?;
    let script = script.to_ascii_lowercase();
    if script.contains("safe-ai-skill") && script.ends_with(".js") {
        return env_action(tail);
    }
    None
}

/// `find … -exec|-execdir|-ok|-okdir CMD … ;|+`: each command run.
fn find_exec_action(args: &[String], depth: usize) -> Option<Action> {
    let mut rest = args;
    while let Some(i) = rest
        .iter()
        .position(|a| matches!(a.as_str(), "-exec" | "-execdir" | "-ok" | "-okdir"))
    {
        let after = rest.get(i.checked_add(1)?..)?;
        let end = after
            .iter()
            .position(|a| matches!(a.as_str(), ";" | "\\;" | "+"))
            .unwrap_or(after.len());
        let command = after.get(..end)?;
        if let Some(action) = segment_action(command, depth) {
            return Some(action);
        }
        rest = after.get(end..)?;
    }
    None
}

/// `script -c CMD [file]` (util-linux) or `script [-q…] FILE CMD …` (BSD).
fn script_action(args: &[String], depth: usize) -> Option<Action> {
    if let Some(i) = args.iter().position(|a| a == "-c" || a == "--command") {
        let command = args.get(i.checked_add(1)?)?;
        return env_write_action(command, depth);
    }
    let rest = skip_options(args, &["-t", "-T", "-F"]);
    let (_file, command) = rest.split_first()?;
    segment_action(command, depth)
}

/// `args` without leading options (and the values of those in `takes_value`).
fn skip_options<'a>(args: &'a [String], takes_value: &[&str]) -> &'a [String] {
    let mut rest = args;
    while let Some((opt, after)) = rest.split_first() {
        if opt == "--" {
            return after;
        }
        if !(opt.starts_with('-') && opt.len() > 1) {
            break;
        }
        rest = after;
        if takes_value.contains(&opt.as_str()) {
            rest = rest.split_first().map_or(rest, |(_, r)| r);
        }
    }
    rest
}

/// Shell keywords and grouping words that put the next word in command position.
const KEYWORDS: &[&str] = &[
    "{", "}", "!", "if", "then", "elif", "else", "fi", "while", "until", "do", "done", "case",
    "esac", "function",
];

/// `tokens` without leading assignments (`FOO=1`) and wrappers that run the rest of the line,
/// with their options.
fn skip_prefix(tokens: &[String]) -> &[String] {
    let mut rest = tokens;
    loop {
        let Some((first, tail)) = rest.split_first() else {
            return rest;
        };
        if is_assignment(first) || KEYWORDS.contains(&first.as_str()) {
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
    args.get(i.checked_add(1)?).map(String::as_str)
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

/// The last path component, lowercased, without `.exe`. A backslash is a Windows separator
/// unless dropping backslashes (shell escapes: `safe\\-ai\\-skill`) names the engine.
fn base_name(word: &str) -> String {
    let normal = |base: &str| {
        let base = base.to_ascii_lowercase();
        base.strip_suffix(".exe")
            .map(str::to_string)
            .unwrap_or(base)
    };
    let unescaped: String = word.chars().filter(|c| *c != '\\').collect();
    let unescaped = normal(unescaped.rsplit('/').next().unwrap_or_default());
    if is_engine_binary(&unescaped) {
        return unescaped;
    }
    normal(word.rsplit(['/', '\\']).next().unwrap_or(word))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action(cmd: &str) -> Option<&'static str> {
        env_write_action(cmd, 0).map(|(a, _)| a)
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
            (
                "unset CLAUDECODE; { safe-ai-skill env set .env K; }",
                Some("set"),
            ),
            (
                "if true; then safe-ai-skill env set .env K; fi",
                Some("set"),
            ),
            (
                "while true; do safe-ai-skill env unset .env K; done",
                Some("unset"),
            ),
            ("! safe-ai-skill env set .env K", Some("set")),
            (
                "~/.claude/plugins/x/bin/safe-ai-skill-darwin-arm64 env set .env K",
                Some("set"),
            ),
            ("safe\\-ai\\-skill env set .env K", Some("set")),
            (
                "C:\\tools\\safe-ai-skill.exe env unset .env K",
                Some("unset"),
            ),
            (
                "find . -name .env -exec safe-ai-skill env unset {} K \\;",
                Some("unset"),
            ),
            ("find . -execdir safe-ai-skill env set {} K +", Some("set")),
            ("watch -n 5 safe-ai-skill env set .env K", Some("set")),
            (
                "script -q /dev/null safe-ai-skill env set .env K",
                Some("set"),
            ),
            (
                "script -c 'safe-ai-skill env unset .env K' /dev/null",
                Some("unset"),
            ),
            (
                "node npm/safe-ai-skill/bin/cli.js env set .env K",
                Some("set"),
            ),
            ("node app.js env set .env K", None),
            ("find . -name .env -exec cat {} \\;", None),
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
