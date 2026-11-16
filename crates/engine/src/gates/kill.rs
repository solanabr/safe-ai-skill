//! Process-kill guard: a signal sent to every process, or to a coding agent's own processes.
//!
//! Ported from the ai-kit `egress-guard` kill check, which holds at every tier. Killing one
//! process, or a worker by name (`pkill -f vitest`, `killall node`), is ordinary work and stays
//! silent; these are not:
//!
//! | What | Off | Relaxed | Medium | High |
//! |---|---|---|---|---|
//! | `kill` of PID -1 (`kill -9 -1`, `kill -KILL -1`, `kill -- -1`), `killall5` | deny | deny | deny | deny |
//! | `pkill` or `killall` of a coding agent (`claude`, `codex`, `opencode`, `orca`, any case), or `kill` of the PIDs `pgrep`/`pidof` find for one | deny | deny | deny | deny |
//! | `pkill` or `killall` that selects every process: a pattern that matches any name (`.`, `.*`, `''`), `pkill -v` (all but the match), or a user, group, session or terminal with no pattern (`pkill -u "$USER"`, `killall -u me`) | deny | deny | deny | deny |
//!
//! Signal 0, which only checks that a process exists, and the list options (`kill -l`) are not a
//! kill. Positions come from [`shell::parse`], so a commit message naming `pkill claude` is data.
//!
//! Known misses: a PID or pattern held in a variable or read from a file, a PID piped in
//! (`pgrep claude | xargs kill`), and a kill from a script file.

use std::path::Path;

use crate::context::shell::{self, base_name, SimpleCommand, Word};
use crate::gate::Verdict;
use crate::gates::bash::MAX_PARSE_BYTES;
use crate::policy::tier::Tier;
use crate::policy::Policy;

/// Coding agents whose processes a name pattern may not target (a substring, any case).
const AGENTS: &[&str] = &["claude", "codex", "opencode", "orca"];

/// `pkill` options that take a value (procps and BSD), short and long.
const PKILL_VALUE: &[&str] = &[
    "-g",
    "-G",
    "-s",
    "-t",
    "-u",
    "-U",
    "-P",
    "-F",
    "-O",
    "-r",
    "-j",
    "-M",
    "-N",
    "--signal",
    "--pgroup",
    "--group",
    "--session",
    "--terminal",
    "--euid",
    "--uid",
    "--parent",
    "--pidfile",
    "--older",
    "--runstates",
    "--ns",
    "--nslist",
    "--cgroup",
];

/// `pkill` selectors that, with no pattern, take in every process they cover.
const PKILL_BROAD: &[&str] = &[
    "-g",
    "-G",
    "-s",
    "-t",
    "-u",
    "-U",
    "-j",
    "--pgroup",
    "--group",
    "--session",
    "--terminal",
    "--euid",
    "--uid",
    "--ns",
    "--nslist",
    "--cgroup",
];

/// `killall` options that take a value (psmisc and BSD).
const KILLALL_VALUE: &[&str] = &[
    "-s",
    "-u",
    "-o",
    "-y",
    "-n",
    "-Z",
    "-t",
    "-c",
    "--signal",
    "--user",
    "--older-than",
    "--younger-than",
    "--ns",
    "--context",
];

/// Prefix programs that run the rest of their argv as a command (the parser strips the common
/// ones: `env`, `sudo`, `nice`, `timeout`, `xargs`, …).
const RUNNERS: &[&str] = &[
    "env",
    "sudo",
    "doas",
    "nice",
    "nohup",
    "time",
    "timeout",
    "stdbuf",
    "ionice",
    "chrt",
    "taskset",
    "numactl",
    "arch",
    "xargs",
    "setsid",
    "unbuffer",
    "chronic",
    "caffeinate",
    "command",
    "builtin",
    "exec",
    "watch",
    "flock",
    "chroot",
    "prlimit",
    "nsenter",
    "unshare",
    "runuser",
    "sg",
    "faketime",
    "firejail",
    "systemd-run",
    "strace",
    "ltrace",
    "rlwrap",
];

/// Runners whose first positional is not the command (`flock FILE cmd`, `chroot DIR cmd`).
const POSITIONAL_RUNNERS: &[&str] = &["chroot", "flock", "sg", "runuser", "timeout", "taskset"];

/// The programs this guard judges.
const KILLERS: &[&str] = &["kill", "pkill", "killall", "killall5"];

/// Decide a Bash `command` against the kill guard (see the module docs). `None` when it sends no
/// such signal. The verdict is the same at every tier; `cwd`, `policy` and `tier` are kept for
/// the gate signature.
pub fn decide(command: &str, _cwd: &Path, _policy: &Policy, _tier: Tier) -> Option<Verdict> {
    if command.len() > MAX_PARSE_BYTES || !may_concern(command) {
        return None;
    }
    let parsed = shell::parse(command);
    let why = parsed.commands.iter().find_map(|cmd| {
        if KILLERS.contains(&cmd.program().as_str()) {
            judge(cmd)
        } else {
            peel(&cmd.words).and_then(|inner| judge(&inner))
        }
    })?;
    Some(Verdict::Deny(format!(
        "safe-ai-skill kill guard: this {why}; that is denied at every tier, so signal one \
         process by its PID or a worker by its own name, or ask the user to run it themselves."
    )))
}

/// The byte prefilter: `kill` in any case, with quotes and backslashes inside the word skipped
/// (`ki"ll"`, `k\ill`), or ANSI-C quoting. Allocation-free.
pub fn may_concern(command: &str) -> bool {
    let b = command.as_bytes();
    if b.windows(2).any(|w| w == b"$'") {
        return true;
    }
    const NEEDLE: &[u8] = b"kill";
    let skip = |c: u8| matches!(c, b'\\' | b'\'' | b'"');
    'start: for i in 0..b.len() {
        if b[i].to_ascii_lowercase() != NEEDLE[0] {
            continue;
        }
        let mut j = i + 1;
        for &want in &NEEDLE[1..] {
            while j < b.len() && skip(b[j]) {
                j += 1;
            }
            if b.get(j).map(u8::to_ascii_lowercase) != Some(want) {
                continue 'start;
            }
            j += 1;
        }
        return true;
    }
    false
}

/// Why `cmd` (program `kill`, `pkill`, `killall` or `killall5`) is a broad kill, if it is.
fn judge(cmd: &SimpleCommand) -> Option<String> {
    let args = cmd.words.get(1..).unwrap_or_default();
    match cmd.program().as_str() {
        "kill" => kill_why(args),
        "pkill" => pkill_why(args),
        "killall" => killall_why(args),
        "killall5" => (!args.iter().any(|w| is_signal_zero(&w.text)))
            .then(|| "runs killall5, which signals every process outside its own session".into()),
        _ => None,
    }
}

/// `kill`: the first argument may name the signal (`-9`, `-KILL`, `-s KILL`, `-n 9`); every
/// argument after it is a PID, where -1 is every process the user may signal.
fn kill_why(args: &[Word]) -> Option<String> {
    let first = args.first().map(|w| w.text.as_str());
    let (signal, mut rest) = match first {
        Some("-l" | "-L" | "--list" | "--table") => return None,
        Some("-s" | "-n" | "--signal") => (
            args.get(1).map(|w| w.text.as_str()),
            args.get(2..).unwrap_or_default(),
        ),
        Some(t) if t.starts_with("--signal=") => (t.strip_prefix("--signal="), &args[1..]),
        Some(t) if t.starts_with('-') && t.len() > 1 && t != "--" => (Some(&t[1..]), &args[1..]),
        _ => (None, args),
    };
    if rest.first().is_some_and(|w| w.text == "--") {
        rest = &rest[1..];
    }
    if signal.is_some_and(|s| s == "0") {
        return None;
    }
    // A lone `kill -1` is read as PID -1 too, as the kit's guard reads it.
    if rest.iter().any(|w| w.text == "-1") || (rest.is_empty() && first == Some("-1")) {
        return Some("runs kill on PID -1, which signals every process the user owns".into());
    }
    rest.iter()
        .any(|w| w.dynamic && finds_agent(&w.text))
        .then(|| "runs kill on the PIDs pgrep or pidof finds for a coding agent".into())
}

/// `pkill`: why its selection is broad or names a coding agent, if it does.
fn pkill_why(args: &[Word]) -> Option<String> {
    let mut patterns: Vec<&str> = Vec::new();
    let mut broad_selector = false;
    let mut inverse = false;
    let mut i = 0;
    while let Some(w) = args.get(i) {
        let t = w.text.as_str();
        i += 1;
        if t == "--" {
            patterns.extend(args[i..].iter().map(|w| w.text.as_str()));
            break;
        }
        if !t.starts_with('-') || t.len() == 1 {
            patterns.push(t);
            continue;
        }
        let o = t.split_once('=').map_or(t, |(o, _)| o);
        if is_signal(&t[1..]) {
            if is_signal_zero(t) {
                return None;
            }
            continue;
        }
        if o == "--signal" {
            let value = match t.split_once('=') {
                Some((_, v)) => Some(v),
                None => {
                    i += 1;
                    args.get(i - 1).map(|w| w.text.as_str())
                }
            };
            if value == Some("0") {
                return None;
            }
            continue;
        }
        if matches!(o, "-v" | "--inverse") {
            inverse = true;
            continue;
        }
        if t.starts_with("--") {
            broad_selector |= PKILL_BROAD.contains(&o);
            if PKILL_VALUE.contains(&o) && !t.contains('=') {
                i += 1;
            }
            continue;
        }
        // A cluster of short flags (`-fx`, `-u0`, `-fu me`): a value letter takes the rest of the
        // word, or the next word.
        for (k, c) in t[1..].char_indices() {
            let flag = format!("-{c}");
            inverse |= c == 'v';
            broad_selector |= PKILL_BROAD.contains(&flag.as_str());
            if PKILL_VALUE.contains(&flag.as_str()) {
                if t[1..].len() == k + 1 {
                    i += 1;
                }
                break;
            }
        }
    }
    if inverse {
        return Some("runs pkill -v, which signals every process but the ones it matches".into());
    }
    broad_pattern("pkill", &patterns, broad_selector)
}

/// `killall`: why its selection is broad or names a coding agent, if it does.
fn killall_why(args: &[Word]) -> Option<String> {
    let mut names: Vec<&str> = Vec::new();
    let mut user = false;
    let mut regex = false;
    let mut i = 0;
    while let Some(w) = args.get(i) {
        let t = w.text.as_str();
        i += 1;
        if t == "--" {
            names.extend(args[i..].iter().map(|w| w.text.as_str()));
            break;
        }
        if !t.starts_with('-') || t.len() == 1 {
            names.push(t);
            continue;
        }
        let o = t.split_once('=').map_or(t, |(o, _)| o);
        match o {
            // Lists signals, or (BSD) only prints what it would do.
            "-l" | "--list" | "-d" => return None,
            "-r" | "--regexp" | "-m" => regex = true,
            "-u" | "--user" | "-t" => user = true,
            // BSD: only processes named NAME.
            "-c" => {
                names.extend(args.get(i).map(|w| w.text.as_str()));
                i += 1;
                continue;
            }
            "-s" | "--signal" => {
                let value = match t.split_once('=') {
                    Some((_, v)) => Some(v),
                    None => {
                        i += 1;
                        args.get(i - 1).map(|w| w.text.as_str())
                    }
                };
                if value == Some("0") {
                    return None;
                }
                continue;
            }
            _ if is_signal(&t[1..]) => {
                if is_signal_zero(t) {
                    return None;
                }
                continue;
            }
            _ => {}
        }
        if KILLALL_VALUE.contains(&o) && !t.contains('=') {
            i += 1;
        }
    }
    // A plain name matches only that program; a regular expression may match every one.
    let names: Vec<&str> = if regex {
        names
    } else {
        names.into_iter().filter(|n| !n.is_empty()).collect()
    };
    if !regex && names.iter().all(|n| !names_agent(n)) {
        return (names.is_empty() && user)
            .then(|| "runs killall on every process of a user or terminal".into());
    }
    broad_pattern("killall", &names, user)
}

/// Why a `pkill` or `killall` selection is broad, if it is: a pattern naming a coding agent, a
/// pattern that matches every name, or a whole user, group, session or terminal with no
/// pattern.
fn broad_pattern(program: &str, patterns: &[&str], broad_selector: bool) -> Option<String> {
    if let Some(agent) = patterns.iter().find_map(|p| {
        let lower = p.to_ascii_lowercase();
        AGENTS.iter().find(|a| lower.contains(*a))
    }) {
        return Some(format!(
            "runs {program} on {agent}, a coding agent's own processes"
        ));
    }
    if patterns.iter().any(|p| matches_everything(p)) {
        return Some(format!(
            "runs {program} with a pattern that matches every process"
        ));
    }
    (patterns.is_empty() && broad_selector)
        .then(|| format!("runs {program} on every process of a user, group, session or terminal"))
}

/// Whether a regular expression `pattern` matches any process name: what is left once anchors
/// and match-anything atoms (`.`, `.*`, `.+`) are taken out is empty.
fn matches_everything(pattern: &str) -> bool {
    let mut rest = pattern.replace(".*", "").replace(".+", "");
    rest.retain(|c| !matches!(c, '^' | '$' | '.' | '(' | ')'));
    rest.is_empty()
}

/// Whether a `killall` name (an exact program name) is a coding agent's.
fn names_agent(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    AGENTS.iter().any(|a| lower.contains(a))
}

/// Whether a dynamic `kill` argument finds a coding agent's PIDs (`$(pgrep -f claude)`).
fn finds_agent(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    (lower.contains("pgrep") || lower.contains("pidof")) && AGENTS.iter().any(|a| lower.contains(a))
}

/// Whether `spec` (an option without its dash) names a signal: a number, or an upper-case name
/// of two or more letters (`KILL`, `SIGTERM`); single letters are options (`-U`, `-G`).
fn is_signal(spec: &str) -> bool {
    !spec.is_empty()
        && (spec.chars().all(|c| c.is_ascii_digit())
            || (spec.len() >= 2
                && spec
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())))
}

/// Whether option `t` is signal 0, which only checks that a process exists.
fn is_signal_zero(t: &str) -> bool {
    t == "-0"
}

/// The kill command behind a chain of [`RUNNERS`], if `words` is one: every word before it is a
/// runner, an option, an option's value, a number or mask, an assignment or a runner's
/// positional operand.
fn peel(words: &[Word]) -> Option<SimpleCommand> {
    let first = base_name(&words.first()?.text);
    if !RUNNERS.contains(&first.as_str()) {
        return None;
    }
    let mut prev_runner = Some(first);
    let mut prev_option = false;
    for (i, w) in words.iter().enumerate().skip(1) {
        let t = w.text.as_str();
        let base = base_name(t);
        if KILLERS.contains(&base.as_str()) {
            return Some(SimpleCommand {
                words: words[i..].to_vec(),
                indirect: true,
                writes_file: false,
                canonical: false,
            });
        }
        let positional = prev_runner
            .as_deref()
            .is_some_and(|r| POSITIONAL_RUNNERS.contains(&r));
        let number = t.starts_with(|c: char| c.is_ascii_digit());
        let assignment = t.split_once('=').is_some_and(|(n, _)| {
            !n.is_empty() && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        });
        let runner = RUNNERS.contains(&base.as_str());
        if !(t.starts_with('-') || number || assignment || runner || prev_option || positional) {
            return None;
        }
        prev_option = t.starts_with('-') && !t.contains('=');
        prev_runner = runner.then_some(base);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(command: &str) -> &'static str {
        let tiers = [Tier::Off, Tier::Relaxed, Tier::Medium, Tier::High];
        let got = tiers.map(|t| decide(command, Path::new("."), &Policy::default(), t));
        assert!(got.windows(2).all(|w| w[0] == w[1]), "{command}: {got:?}");
        match &got[0] {
            Some(Verdict::Deny(_)) => "D",
            Some(_) => "?",
            None => "-",
        }
    }

    #[test]
    fn every_process_is_denied_at_every_tier() {
        for cmd in [
            "kill -9 -1",
            "kill -KILL -1",
            "kill -SIGKILL -1",
            "kill -s KILL -1",
            "kill -n 9 -1",
            "kill --signal=KILL -1",
            "kill -- -1",
            "kill -9 -- -1",
            "kill -1",
            "kill -TERM 1234 -1",
            "/bin/kill -9 -1",
            "sudo kill -9 -1",
            "command kill -9 -1",
            "taskset 0x1 kill -9 -1",
            "sh -c 'kill -9 -1'",
            "killall5 -9",
            "pkill -v node",
            "pkill -9 -fv vitest",
            "pkill -f .",
            "pkill -f '.*'",
            "pkill ''",
            "pkill -9 '^'",
            "pkill -u \"$USER\"",
            "pkill -U 501",
            "pkill -9 -u root",
            "pkill --euid me",
            "pkill -s 0",
            "pkill -t pts/1",
            "killall -u me",
            "killall -9 -u me",
            "killall -r '.*'",
            "killall -m .",
        ] {
            assert_eq!(v(cmd), "D", "{cmd}");
        }
    }

    #[test]
    fn coding_agents_are_denied_at_every_tier() {
        for cmd in [
            "pkill claude",
            "pkill -f claude",
            "pkill -9 -f 'node .*claude'",
            "pkill -f Claude",
            "pkill -ifx codex",
            "pkill -- -claude",
            "killall claude",
            "killall Claude",
            "killall -9 opencode",
            "killall -s KILL codex",
            "killall -c claude",
            "pkill -u me -f orca",
            "kill -9 $(pgrep -f claude)",
            "kill $(pidof codex)",
            "env -i pkill claude",
            "watch -n 5 'pkill claude'",
        ] {
            assert_eq!(v(cmd), "D", "{cmd}");
        }
    }

    #[test]
    fn ordinary_kills_and_mentions_are_silent() {
        for cmd in [
            "kill 1234",
            "kill -9 1234",
            "kill -1 1234",
            "kill -HUP 1234",
            "kill -9 -1234",
            "kill %1",
            "kill -l",
            "kill -0 -1",
            "kill -s 0 -1",
            "kill $(lsof -t -i :3000)",
            "kill -9 $(pgrep -f vitest)",
            "pkill node",
            "pkill -f vitest",
            "pkill -9 -f 'solana-test-validator'",
            "pkill -u me node",
            "pkill -P 1234",
            "pkill -F app.pid",
            "pkill -0 claude",
            "killall node",
            "killall -9 solana-test-validator",
            "killall -l",
            "pgrep -f claude",
            "pidof codex",
            "echo kill -9 -1",
            "git commit -m 'stop pkill claude in CI'",
            "grep -rn 'killall' docs",
            "cat > notes.md <<'EOF'\nkill -9 -1\nEOF",
            "skill check",
        ] {
            assert_eq!(v(cmd), "-", "{cmd}");
        }
    }

    #[test]
    fn reasons_name_what_was_matched() {
        let deny = |c: &str| match decide(c, Path::new("."), &Policy::default(), Tier::Relaxed) {
            Some(Verdict::Deny(r)) => r,
            other => panic!("{c}: {other:?}"),
        };
        assert!(deny("kill -9 -1").contains("PID -1"));
        assert!(deny("pkill -f claude").contains("pkill on claude"));
        let reason = deny("killall -u me");
        assert!(reason.ends_with("themselves."), "{reason}");
        assert_eq!(reason.matches(". ").count(), 0, "{reason}");
    }

    #[test]
    fn prefilter() {
        assert!(may_concern("kill -9 -1"));
        assert!(may_concern("p\"kill\" claude"));
        assert!(may_concern("KILLALL x"));
        assert!(!may_concern("cargo build --release"));
        assert!(!may_concern("ps aux"));
    }
}
