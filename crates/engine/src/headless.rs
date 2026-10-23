//! The headless rule (shared contract §3.3, D8 v2 spec §7), identical on the kit's side.
//!
//! Headless = any of: `SAFE_AI_SKILL_HEADLESS` or `KIT_FIREWALL_HEADLESS` = `1|true`; any of
//! `CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, `BUILDKITE`, `JENKINS_URL` set (non-empty) and not
//! `0|false`; `/dev/tty` cannot be opened for reading. Any signal turns it **on**; nothing turns
//! it off, because a repo's settings `env` can set every one of them (headless only tightens).
//!
//! When headless, [`apply`] turns every `ask` into a `deny` naming the interactive or grant
//! route: there is nobody to answer the dialog (under `claude -p` a hook `ask` is a denial
//! anyway). What still passes is a grant the user confirmed interactively beforehand, which
//! the relaxation layer has already turned into an `allow` (below High, grantable scopes only).
//! No env escape (`CONFIRM_MAINNET`, `CONFIRM_*`) is read, and `defer` is never emitted.
//!
//! The `/dev/tty` signal is wired but not consulted by the hooks yet ([`detect`] passes
//! `None`): processes Claude Code spawns were observed without a controlling terminal, so the
//! probe would make every interactive session headless. It is switched on once the live check
//! confirms what hook processes see.
//!
//! [`confirmation_refused`] is a separate, wider test used only where a pending relaxation is
//! announced or confirmed: besides the variables above, it walks the hook's process ancestry
//! (through the shells between Claude Code and the engine) to the Claude Code process that ran
//! the hook, and refuses when that process runs non-interactively (`-p`, `--print`) or was
//! itself started from another Claude Code session (an agent's nested `claude`). Neither can
//! be seen in the hook payload or in a variable Claude Code documents. It is best effort: a
//! process table it cannot read, or a Claude Code process it does not recognise (renamed, or
//! reached through a non-shell parent), reads as interactive.

use crate::io::Decision;

/// Explicit headless switches (`1` or `true`).
pub const SWITCH_VARS: [&str; 2] = ["SAFE_AI_SKILL_HEADLESS", "KIT_FIREWALL_HEADLESS"];

/// CI markers: set (non-empty) and not `0`/`false` means headless.
pub const CI_VARS: [&str; 5] = [
    "CI",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "BUILDKITE",
    "JENKINS_URL",
];

/// Appended to an `ask` reason when it becomes a headless `deny`.
pub const HEADLESS_SUFFIX: &str = "No interactive user can approve this (headless session): \
     approve it in an interactive session, confirm a grant there first where one applies, or \
     run it yourself.";

/// Whether the session is headless. `env` looks up a variable; `tty_readable` is the
/// `/dev/tty` probe (`None` when it is skipped).
pub fn is_headless(env: &dyn Fn(&str) -> Option<String>, tty_readable: Option<bool>) -> bool {
    let value = |k: &str| env(k).map(|v| v.trim().to_ascii_lowercase());
    let switched = SWITCH_VARS
        .iter()
        .any(|k| matches!(value(k).as_deref(), Some("1" | "true")));
    let ci = CI_VARS
        .iter()
        .any(|k| value(k).is_some_and(|v| !v.is_empty() && v != "0" && v != "false"));
    switched || ci || tty_readable == Some(false)
}

/// [`is_headless`] over the process environment (see the module docs on the `/dev/tty` probe).
pub fn detect() -> bool {
    is_headless(&|k| std::env::var(k).ok(), None)
}

/// Why a confirmation (or a code announcement) cannot happen in this session, if it can't:
/// a headless signal ([`detect`]), or the Claude Code process running this hook is
/// non-interactive or nested ([`ancestry_verdict`] over the live process table).
pub fn confirmation_refused() -> Option<&'static str> {
    if detect() {
        return Some("this is a headless session (CI or a headless switch is set)");
    }
    #[cfg(unix)]
    {
        let me = std::process::id();
        if let Some(table) = process_table() {
            return ancestry_verdict(me, &table);
        }
    }
    None
}

/// One process: its parent and its argument words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proc {
    pub ppid: u32,
    pub args: Vec<String>,
}

/// Shells (and `env`) that may sit between Claude Code and the engine: the hook command's
/// shell, the shim, its command substitution.
const HOOK_SHELLS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "busybox", "fish", "env",
];

/// Most ancestors walked.
const MAX_DEPTH: usize = 64;

/// The verdict for process `pid` in `table`: from its parent, skip hook shells to the first
/// other process; when that is Claude Code, refuse if it has `-p`/`--print` or another
/// Claude Code process above it. Anything else (a test harness, an unknown parent) is `None`.
pub fn ancestry_verdict(
    pid: u32,
    table: &std::collections::HashMap<u32, Proc>,
) -> Option<&'static str> {
    let mut cur = table.get(&pid)?.ppid;
    let mut hook_claude = None;
    for _ in 0..MAX_DEPTH {
        let proc = table.get(&cur)?;
        if is_claude(&proc.args) {
            hook_claude = Some(cur);
            break;
        }
        let base = program_base(proc.args.first().map(String::as_str).unwrap_or(""));
        if !HOOK_SHELLS.contains(&base.as_str()) {
            return None;
        }
        cur = proc.ppid;
    }
    let claude = table.get(&hook_claude?)?;
    if claude
        .args
        .iter()
        .skip(1)
        .any(|a| a == "-p" || a == "--print" || a.starts_with("--print="))
    {
        return Some("this Claude Code session runs non-interactively (`claude -p`)");
    }
    let mut up = claude.ppid;
    for _ in 0..MAX_DEPTH {
        if up <= 1 {
            break;
        }
        let Some(proc) = table.get(&up) else {
            break;
        };
        if is_claude(&proc.args) {
            return Some(
                "this Claude Code session was started from inside another Claude Code session",
            );
        }
        up = proc.ppid;
    }
    None
}

/// Whether argument words are a Claude Code process: program `claude` (any directory,
/// `.exe`), or a node/bun process running the `@anthropic-ai/claude-code` package.
fn is_claude(args: &[String]) -> bool {
    let Some(first) = args.first() else {
        return false;
    };
    let base = program_base(first);
    base == "claude"
        || args
            .iter()
            .take(3)
            .any(|a| a.to_ascii_lowercase().contains("@anthropic-ai/claude-code"))
}

fn program_base(word: &str) -> String {
    let base = word.rsplit(['/', '\\']).next().unwrap_or(word);
    let base = base.trim_start_matches('-').to_ascii_lowercase();
    base.strip_suffix(".exe")
        .map(str::to_string)
        .unwrap_or(base)
}

/// The process table: `/proc` on Linux, else one `ps` from a fixed system path.
#[cfg(unix)]
fn process_table() -> Option<std::collections::HashMap<u32, Proc>> {
    if std::path::Path::new("/proc/self/stat").exists() {
        return proc_table();
    }
    let ps = ["/bin/ps", "/usr/bin/ps"]
        .into_iter()
        .find(|p| std::path::Path::new(p).is_file())?;
    let out = std::process::Command::new(ps)
        .args(["-A", "-ww", "-o", "pid=", "-o", "ppid=", "-o", "args="])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| parse_ps(&String::from_utf8_lossy(&out.stdout)))
}

/// Parse `ps -o pid= -o ppid= -o args=` output.
pub fn parse_ps(text: &str) -> std::collections::HashMap<u32, Proc> {
    let mut table = std::collections::HashMap::new();
    for line in text.lines() {
        let mut words = line.split_whitespace();
        let (Some(pid), Some(ppid)) = (words.next(), words.next()) else {
            continue;
        };
        let (Ok(pid), Ok(ppid)) = (pid.parse::<u32>(), ppid.parse::<u32>()) else {
            continue;
        };
        table.insert(
            pid,
            Proc {
                ppid,
                args: words.map(str::to_string).collect(),
            },
        );
    }
    table
}

/// The ancestry of this process from `/proc` (only the chain up from here is read).
#[cfg(unix)]
fn proc_table() -> Option<std::collections::HashMap<u32, Proc>> {
    let mut table = std::collections::HashMap::new();
    let mut pid = std::process::id();
    for _ in 0..MAX_DEPTH {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let ppid = stat
            .rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().nth(1))
            .and_then(|p| p.parse::<u32>().ok())?;
        let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
        let args = cmdline
            .split(|b| *b == 0)
            .filter(|a| !a.is_empty())
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect();
        table.insert(pid, Proc { ppid, args });
        if ppid <= 1 {
            break;
        }
        pid = ppid;
    }
    Some(table)
}

/// Whether `/dev/tty` opens for reading; `None` where it does not exist.
pub fn tty_probe() -> Option<bool> {
    let path = std::path::Path::new("/dev/tty");
    if std::fs::symlink_metadata(path).is_err() {
        return None;
    }
    Some(std::fs::File::open(path).is_ok())
}

/// The headless post-processor: an `ask` becomes a `deny` (same reason plus
/// [`HEADLESS_SUFFIX`]); everything else passes unchanged.
pub fn apply(decision: Decision, headless: bool) -> Decision {
    match decision {
        Decision::Ask { reason } if headless => Decision::Deny {
            reason: format!("{reason} {HEADLESS_SUFFIX}"),
        },
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            pairs
                .iter()
                .find(|(key, _)| *key == k)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn any_signal_turns_it_on_and_nothing_turns_it_off() {
        assert!(!is_headless(&env(&[]), None));
        assert!(!is_headless(&env(&[]), Some(true)));
        assert!(is_headless(&env(&[]), Some(false)));
        for on in [
            ("CI", "true"),
            ("CI", "1"),
            ("GITHUB_ACTIONS", "true"),
            ("JENKINS_URL", "https://ci.example"),
            ("SAFE_AI_SKILL_HEADLESS", "1"),
            ("KIT_FIREWALL_HEADLESS", "TRUE"),
        ] {
            assert!(is_headless(&env(&[on]), None), "{on:?}");
        }
        for off in [
            ("CI", "0"),
            ("CI", "false"),
            ("CI", ""),
            ("SAFE_AI_SKILL_HEADLESS", "0"),
        ] {
            assert!(!is_headless(&env(&[off]), None), "{off:?}");
        }
        // An explicit 0 elsewhere never cancels a signal.
        assert!(is_headless(
            &env(&[
                ("CI", "true"),
                ("KIT_FIREWALL_HEADLESS", "0"),
                ("SAFE_AI_SKILL_HEADLESS", "false")
            ]),
            Some(true)
        ));
    }

    fn table(rows: &[(u32, u32, &str)]) -> std::collections::HashMap<u32, Proc> {
        parse_ps(
            &rows
                .iter()
                .map(|(p, pp, a)| format!("{p} {pp} {a}"))
                .collect::<Vec<_>>()
                .join("\n"),
        )
    }

    #[test]
    fn ancestry_finds_print_and_nested_sessions() {
        let hook = |claude: &str| {
            table(&[
                (1, 0, "/sbin/launchd"),
                (10, 1, "/bin/zsh -l"),
                (20, 10, claude),
                (30, 20, "/bin/sh -c /p/bin/safe-ai-skill prompt-guard"),
                (40, 30, "/bin/sh /p/bin/safe-ai-skill prompt-guard"),
                (41, 40, "/bin/sh /p/bin/safe-ai-skill prompt-guard"),
                (50, 41, "/p/bin/safe-ai-skill-darwin-arm64 prompt-guard"),
            ])
        };
        assert_eq!(ancestry_verdict(50, &hook("claude")), None);
        assert_eq!(
            ancestry_verdict(50, &hook("/opt/homebrew/bin/claude --resume")),
            None
        );
        for print in [
            "claude -p",
            "/usr/local/bin/claude --print hi",
            "node /n/lib/node_modules/@anthropic-ai/claude-code/cli.js -p x",
        ] {
            assert!(ancestry_verdict(50, &hook(print)).is_some(), "{print}");
        }
        // An agent's Bash tool starts a nested interactive session.
        let nested = table(&[
            (1, 0, "launchd"),
            (5, 1, "claude"),
            (6, 5, "/bin/zsh -c claude"),
            (7, 6, "claude"),
            (8, 7, "sh -c hook"),
            (9, 8, "safe-ai-skill prompt-guard"),
        ]);
        assert!(ancestry_verdict(9, &nested).unwrap().contains("another"));
        // A test harness parent (not a shell) stops the walk: an outer `claude -p` is not ours.
        let harness = table(&[
            (1, 0, "launchd"),
            (5, 1, "claude -p"),
            (6, 5, "cargo test"),
            (7, 6, "target/debug/deps/relaxation-abc"),
            (8, 7, "safe-ai-skill prompt-guard"),
        ]);
        assert_eq!(ancestry_verdict(8, &harness), None);
        assert_eq!(ancestry_verdict(99, &harness), None);
    }

    #[test]
    fn asks_become_denies_and_nothing_else_changes() {
        let ask = Decision::Ask {
            reason: "mainnet deploy".into(),
        };
        match apply(ask.clone(), true) {
            Decision::Deny { reason } => {
                assert!(reason.starts_with("mainnet deploy") && reason.contains("headless"))
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(apply(ask.clone(), false), ask);
        for d in [
            Decision::Allow,
            Decision::Defer,
            Decision::Deny { reason: "x".into() },
        ] {
            assert_eq!(apply(d.clone(), true), d);
        }
    }
}
