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
//! [`session_check`] is a separate, wider test used only where a pending relaxation is
//! announced or confirmed: besides the variables above, it walks the hook's process ancestry
//! (through the shells between Claude Code and the engine) to the Claude Code CLI that ran the
//! hook, and refuses when that process runs non-interactively (`-p`, `--print`) or was itself
//! started from another Claude Code CLI (an agent's nested `claude`). Neither can be seen in
//! the hook payload or in a variable Claude Code documents. When the ancestry cannot be
//! determined (no process table, as on native Windows; `ps` denied or too slow; a missing
//! parent; the depth cap) nothing is announced or confirmed either. Processes are recognised by their argument words, which a nested
//! session's launcher controls (`exec -a`): that residual is why `confirm` also binds each
//! request to one Claude Code session.

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

/// Whether this session may announce and confirm codes: refused on a headless signal
/// ([`detect`]) or when the Claude Code CLI running this hook is non-interactive or nested
/// ([`ancestry_verdict`]); [`SessionCheck::Unknown`] when the ancestry cannot be determined.
pub fn session_check() -> SessionCheck {
    if detect() {
        return SessionCheck::Refused(
            "this is a headless session (CI or a headless switch is set)".into(),
        );
    }
    let verdict = match process_table() {
        Ok(table) => ancestry_verdict(std::process::id(), &table),
        Err(why) => Ancestry::Unknown(why),
    };
    match verdict {
        Ancestry::Interactive => SessionCheck::Interactive,
        Ancestry::Refused(why) => SessionCheck::Refused(why.into()),
        Ancestry::Unknown(why) => SessionCheck::Unknown(format!(
            "could not determine whether this Claude Code session is interactive ({why})"
        )),
    }
}

/// [`session_check`]'s verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionCheck {
    /// Interactive, not nested.
    Interactive,
    /// Headless, non-interactive or nested: nothing is announced or confirmed.
    Refused(String),
    /// The ancestry could not be determined (no process table by design on native Windows, a
    /// denied or slow `ps`): refused like [`SessionCheck::Refused`], with the platform advice.
    /// The session id cannot stand in for the check: the agent can steer it.
    Unknown(String),
}

/// One process: its parent and its argument words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proc {
    pub ppid: u32,
    pub args: Vec<String>,
}

/// What the process ancestry says about the session running this hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ancestry {
    /// The hook's Claude Code CLI is interactive and not nested, or the hook was not started
    /// by a Claude Code CLI at all (a test harness, a script).
    Interactive,
    /// Non-interactive (`-p`) or nested.
    Refused(&'static str),
    /// The walk could not finish.
    Unknown(&'static str),
}

/// Shells (and `env`) that may sit between Claude Code and the engine: the hook command's
/// shell, the shim, its command substitution.
const HOOK_SHELLS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "busybox", "fish", "env",
];

/// Most ancestors walked; a deeper chain is undetermined.
const MAX_DEPTH: usize = 64;

/// Longest a `ps` run may take.
const PS_DEADLINE: std::time::Duration = std::time::Duration::from_millis(3000);

/// The verdict for process `pid` in `table`: from its parent, skip hook shells to the first
/// other process. A Claude Code CLI there is refused when it has `-p`/`--print` or another
/// Claude Code CLI above it; any other process (a test harness, a script) is interactive. A
/// missing entry or the depth cap is [`Ancestry::Unknown`].
///
/// Processes are recognised by their argument words, which the process that started them
/// chose: an agent that runs `exec -a bash claude -p …` is not seen (documented residual; the
/// session binding in `confirm` is the second, independent check).
pub fn ancestry_verdict(pid: u32, table: &std::collections::HashMap<u32, Proc>) -> Ancestry {
    const MISSING: Ancestry =
        Ancestry::Unknown("a parent process is missing from the process table");
    let Some(me) = table.get(&pid) else {
        return Ancestry::Unknown("this process is missing from the process table");
    };
    let mut cur = me.ppid;
    let mut hook_claude = None;
    for _ in 0..MAX_DEPTH {
        let Some(proc) = table.get(&cur) else {
            return MISSING;
        };
        if is_claude_cli(&proc.args) {
            hook_claude = Some(proc);
            break;
        }
        let base = program_base(proc.args.first().map(String::as_str).unwrap_or(""));
        if !HOOK_SHELLS.contains(&base.as_str()) {
            return Ancestry::Interactive;
        }
        cur = proc.ppid;
    }
    let Some(claude) = hook_claude else {
        return Ancestry::Unknown("the process chain is too deep");
    };
    if claude
        .args
        .iter()
        .skip(1)
        .any(|a| a == "-p" || a == "--print" || a.starts_with("--print="))
    {
        return Ancestry::Refused("this Claude Code session runs non-interactively (`claude -p`)");
    }
    let mut up = claude.ppid;
    for _ in 0..MAX_DEPTH {
        if up <= 1 {
            return Ancestry::Interactive;
        }
        let Some(proc) = table.get(&up) else {
            return MISSING;
        };
        if is_claude_cli(&proc.args) {
            return Ancestry::Refused(
                "this Claude Code session was started from inside another Claude Code session",
            );
        }
        up = proc.ppid;
    }
    Ancestry::Unknown("the process chain is too deep")
}

/// Whether argument words are a Claude Code CLI process: program word exactly `claude` (or
/// `claude.exe`) in any directory outside a macOS app bundle, or a node/bun process running
/// the `@anthropic-ai/claude-code` package. The Claude Desktop app
/// (`/Applications/Claude.app/Contents/MacOS/Claude`) and IDE hosts are not Claude Code CLIs,
/// so a session they start is not "nested" (assumed from their documented install paths, not
/// observed).
fn is_claude_cli(args: &[String]) -> bool {
    let Some(first) = args.first() else {
        return false;
    };
    let normalised = first.replace('\\', "/");
    let base = normalised.rsplit('/').next().unwrap_or(&normalised);
    let base = base.trim_start_matches('-');
    let in_app_bundle = normalised.contains(".app/Contents/");
    ((base == "claude" || base == "claude.exe") && !in_app_bundle)
        || args
            .iter()
            .take(3)
            .any(|a| a.contains("@anthropic-ai/claude-code"))
}

fn program_base(word: &str) -> String {
    let base = word.rsplit(['/', '\\']).next().unwrap_or(word);
    let base = base.trim_start_matches('-').to_ascii_lowercase();
    base.strip_suffix(".exe")
        .map(str::to_string)
        .unwrap_or(base)
}

/// The process table: `/proc` on Linux, else one `ps` from a fixed system path under
/// [`PS_DEADLINE`]. `Err` names why it could not be read.
fn process_table() -> Result<std::collections::HashMap<u32, Proc>, &'static str> {
    #[cfg(feature = "test-hooks")]
    if std::env::var_os("SAFE_AI_SKILL_TEST_NO_PROCESS_TABLE").is_some() {
        return Err("test: the process table is unavailable");
    }
    if !cfg!(unix) {
        return Err("no process table on this platform");
    }
    if std::path::Path::new("/proc/self/stat").exists() {
        return proc_table();
    }
    let ps = ["/bin/ps", "/usr/bin/ps"]
        .into_iter()
        .find(|p| std::path::Path::new(p).is_file())
        .ok_or("no ps")?;
    let mut child = std::process::Command::new(ps)
        .args(["-A", "-ww", "-o", "pid=", "-o", "ppid=", "-o", "args="])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|_| "ps could not be started")?;
    let mut stdout = child.stdout.take().ok_or("ps could not be read")?;
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut stdout, &mut buf).map(|_| buf)
    });
    let started = std::time::Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < PS_DEADLINE => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("ps did not finish in time");
            }
        }
    };
    if !status.success() {
        return Err("ps was denied or failed");
    }
    let out = reader
        .join()
        .ok()
        .and_then(Result::ok)
        .ok_or("ps output could not be read")?;
    let table = parse_ps(&String::from_utf8_lossy(&out));
    if table.is_empty() {
        return Err("ps output could not be parsed");
    }
    Ok(table)
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
fn proc_table() -> Result<std::collections::HashMap<u32, Proc>, &'static str> {
    let mut table = std::collections::HashMap::new();
    let mut pid = std::process::id();
    for _ in 0..MAX_DEPTH {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .map_err(|_| "/proc could not be read")?;
        let ppid = stat
            .rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().nth(1))
            .and_then(|p| p.parse::<u32>().ok())
            .ok_or("/proc could not be parsed")?;
        let cmdline =
            std::fs::read(format!("/proc/{pid}/cmdline")).map_err(|_| "/proc could not be read")?;
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
    Ok(table)
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
        let refused = |v: Ancestry| matches!(v, Ancestry::Refused(_));
        assert_eq!(ancestry_verdict(50, &hook("claude")), Ancestry::Interactive);
        assert_eq!(
            ancestry_verdict(50, &hook("/opt/homebrew/bin/claude --resume")),
            Ancestry::Interactive
        );
        for print in [
            "claude -p",
            "/usr/local/bin/claude --print hi",
            "node /n/lib/node_modules/@anthropic-ai/claude-code/cli.js -p x",
        ] {
            assert!(refused(ancestry_verdict(50, &hook(print))), "{print}");
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
        assert_eq!(
            ancestry_verdict(9, &nested),
            Ancestry::Refused(
                "this Claude Code session was started from inside another Claude Code session"
            )
        );
        // Children of an agent's Bash tool that take over or name a session are nested all
        // the same: `--resume <the user's id>`, `-c`, `--session-id <id>`, with or without -p.
        for child in [
            "claude --resume 7c5dcf5d-user-session",
            "claude -c",
            "claude --session-id 550e8400-e29b-41d4-a716-446655440000",
            "claude --resume 7c5dcf5d-user-session -p hi",
        ] {
            let t = table(&[
                (1, 0, "launchd"),
                (5, 1, "claude"),
                (6, 5, "/bin/bash -c ..."),
                (7, 6, child),
                (8, 7, "sh -c hook"),
                (9, 8, "safe-ai-skill prompt-guard"),
            ]);
            assert!(refused(ancestry_verdict(9, &t)), "{child}");
        }
        // The Claude Desktop app (or an IDE) hosting the CLI is not a Claude Code CLI.
        for host in [
            "/Applications/Claude.app/Contents/MacOS/Claude",
            "/Applications/Claude.app/Contents/MacOS/claude",
            "/Applications/Visual Studio Code.app/Contents/MacOS/Electron",
        ] {
            let desktop = table(&[
                (1, 0, "launchd"),
                (5, 1, host),
                (7, 5, "/Users/u/.local/bin/claude"),
                (8, 7, "sh -c hook"),
                (9, 8, "safe-ai-skill prompt-guard"),
            ]);
            assert_eq!(
                ancestry_verdict(9, &desktop),
                Ancestry::Interactive,
                "{host}"
            );
        }
        // A test harness parent (not a shell) stops the walk: an outer `claude -p` is not ours.
        let harness = table(&[
            (1, 0, "launchd"),
            (5, 1, "claude -p"),
            (6, 5, "cargo test"),
            (7, 6, "target/debug/deps/relaxation-abc"),
            (8, 7, "safe-ai-skill prompt-guard"),
        ]);
        assert_eq!(ancestry_verdict(8, &harness), Ancestry::Interactive);
    }

    #[test]
    fn an_undetermined_ancestry_is_unknown() {
        let unknown = |v: Ancestry| matches!(v, Ancestry::Unknown(_));
        let chain = table(&[(5, 1, "claude"), (8, 7, "sh -c hook"), (9, 8, "engine")]);
        // Our own pid missing, a parent missing (the shell's parent 7).
        assert!(unknown(ancestry_verdict(99, &chain)));
        assert!(unknown(ancestry_verdict(9, &chain)));
        // An empty table (ps output that parsed to nothing).
        assert!(unknown(ancestry_verdict(9, &table(&[]))));
        // A shell loop deeper than the cap.
        let rows: Vec<(u32, u32, &str)> = (2..200).map(|p| (p, p - 1, "sh")).collect();
        assert!(unknown(ancestry_verdict(199, &table(&rows))));
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
