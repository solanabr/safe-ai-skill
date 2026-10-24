//! Codex-only pieces of the adapter: which `adapt codex` entries exist ([`route`]), the opt-in
//! PostToolUse redaction block ([`redact_block`]), and the interactive-session check
//! ([`interactive_reason`]).
//!
//! Contract (openai/codex `rust-v0.164.0`, `codex-rs/hooks/src`): PreToolUse honours only a
//! `deny` with a reason (`engine/output_parser.rs` `parse_pre_tool_use`); PostToolUse can
//! replace the model-visible result only by blocking it (`{"decision":"block","reason":…}`,
//! `events/post_tool_use.rs`, applied in `core/src/tools/registry.rs` as an error result);
//! `SessionStart` takes `systemMessage` and `hookSpecificOutput.additionalContext`
//! (`events/session_start.rs`). Every output object rejects unknown fields (`schema.rs`).

use std::path::Path;

use serde_json::Value;

use super::{tokenize, CodexTargets, Tok, PREFIXES};

/// The flag that turns on the redaction block (`adapt codex redact --block-with-redaction`).
pub const BLOCK_WITH_REDACTION: &str = "--block-with-redaction";

/// What one `adapt codex …` entry runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// A PreToolUse gate, by subcommand name.
    Gate(&'static str),
    /// `session-start`: the SessionStart sweep and tier report.
    SessionStart,
    /// `redact --block-with-redaction`: PostToolUse redaction as a block.
    RedactBlock,
}

/// The entry `adapt codex <name> [flags…]` names, if it is one.
pub fn route(name: &str, flags: &[String]) -> Option<Route> {
    let flags: Vec<&str> = flags.iter().map(String::as_str).collect();
    match (name, flags.as_slice()) {
        ("session-start", []) => Some(Route::SessionStart),
        ("redact", [BLOCK_WITH_REDACTION]) => Some(Route::RedactBlock),
        (gate, []) => super::CODEX_GATES
            .iter()
            .find(|g| **g == gate)
            .map(|g| Route::Gate(g)),
        _ => None,
    }
}

/// The usage line for `adapt codex`.
pub fn usage() -> String {
    format!(
        "safe-ai-skill: usage: safe-ai-skill adapt codex <{}|session-start|redact {BLOCK_WITH_REDACTION}>",
        super::CODEX_GATES.join("|")
    )
}

/// What `adapt codex session-start` checks, shown on every Codex session start.
pub const SESSION_SCOPE: &str = "safe-ai-skill (Codex): this report covers the tier and \
     safe-ai-skill's state only. Codex skills (`.agents/skills`, `$CODEX_HOME/skills`) and the \
     MCP servers in Codex's config.toml are not scanned; the Bash, apply_patch and MCP gates \
     still apply.";

/// Opening of the reason that carries a redacted result.
pub const REDACTED_PREFIX: &str = "safe-ai-skill withheld this tool result because it contained \
     secrets (opt-in redaction for Codex). The same output with the secrets replaced by \
     placeholders follows; use it as the command's output:";

/// The PostToolUse block for a result too large (or too malformed) to scan.
pub fn withheld() -> Value {
    serde_json::json!({
        "decision": "block",
        "reason": "safe-ai-skill withheld this tool result: it is too large to scan for secrets \
                   (opt-in redaction for Codex). Narrow the command's output and run it again.",
    })
}

/// The PostToolUse output for a redaction: a block whose reason is the redacted result (Codex
/// shows the model the reason in place of the result), or `None` when nothing was redacted.
pub fn redact_block(updated: Option<Value>) -> Option<Value> {
    let updated = updated?;
    let text = match &updated {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    Some(serde_json::json!({
        "decision": "block",
        "reason": format!("{REDACTED_PREFIX}\n\n{text}"),
    }))
}

/// Whether removing a bare `hooks.json` / `config.toml` (the command's working dir is unknown)
/// could reach a Codex hook config: some `hooks.json` exists in a Codex home or a `.codex/` dir
/// at or above `cwd`, or some `config.toml` there defines hooks (`[hooks…]`, `hooks.…`). Removing
/// a `config.toml` without hooks cannot turn a gate off; writing one still can, so only
/// removals are narrowed this way.
pub fn hook_config_could_be(name: &str, cwd: &Path, targets: &CodexTargets) -> bool {
    let mut candidates: Vec<std::path::PathBuf> =
        targets.codex_homes.iter().map(|h| h.join(name)).collect();
    candidates.extend(
        super::lexical(cwd)
            .ancestors()
            .map(|d| d.join(".codex").join(name)),
    );
    candidates.iter().any(|file| match name {
        "config.toml" => std::fs::read_to_string(file).is_ok_and(|t| defines_hooks(&t)),
        _ => file.exists(),
    })
}

/// Whether a Codex `config.toml` defines hooks.
fn defines_hooks(toml: &str) -> bool {
    toml.lines().map(str::trim).any(|l| {
        l.starts_with("[hooks")
            || l.starts_with("[[hooks")
            || l.starts_with("hooks.")
            || l.strip_prefix("hooks")
                .is_some_and(|rest| rest.trim_start().starts_with('='))
    })
}

/// Shells: with no `-c` script, no script file and no input from somewhere other than the
/// terminal, they read commands from a terminal the model can type into.
const SHELLS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "tcsh", "csh", "yash", "elvish",
    "nu", "pwsh", "xonsh",
];

/// Interpreters with a REPL: no `-c`/`-e` code, no `-m` module and no script means a prompt.
const REPLS: &[&str] = &[
    "python", "python2", "python3", "node", "nodejs", "ruby", "perl", "php", "lua", "luajit",
    "irb", "pry", "ghci", "julia", "tclsh", "wish", "R", "deno", "bun", "expect", "gdb", "lldb",
    "sqlplus", "ipython", "bpython", "ptpython", "jshell", "scala", "clojure", "clj", "erl", "iex",
    "racket", "guile", "sbcl", "ocaml", "utop", "swift", "kotlinc",
];

/// Database shells: interactive unless given a command or file.
const DB_SHELLS: &[&str] = &[
    "psql",
    "mysql",
    "mariadb",
    "sqlite3",
    "mongo",
    "mongosh",
    "redis-cli",
];

/// Terminal multiplexers: a session they start (or attach to) takes keystrokes from
/// `send-keys`/`stuff` and from `write_stdin`, which no gate reads as commands.
const MULTIPLEXERS: &[&str] = &["tmux", "screen", "byobu", "zellij", "dtach", "abduco"];

/// Read-only multiplexer subcommands.
const MULTIPLEXER_READS: &[&str] = &[
    "ls",
    "list-sessions",
    "list-windows",
    "list-panes",
    "list-clients",
    "list-commands",
    "list-keys",
    "has-session",
    "has",
    "show-options",
    "show",
    "-V",
    "-ls",
    "-list",
    "-v",
    "-version",
    "--version",
];

/// Paths that are the terminal (or this process's stdin, which is it).
const TTY_SOURCES: &[&str] = &[
    "/dev/tty",
    "/dev/stdin",
    "/dev/fd/0",
    "/proc/self/fd/0",
    "/dev/pts/0",
];

/// Commands that copy their stdin to their stdout when given no input file.
const PASS_THROUGH: &[&str] = &[
    "cat", "tac", "tee", "tr", "dd", "head", "tail", "grep", "egrep", "fgrep", "sed", "awk",
    "gawk", "mawk", "nawk", "cut", "stdbuf", "pv", "buffer", "mbuffer", "uniq", "nl",
];

/// Leading keywords of a compound command (`while read l; do …; done`).
const KEYWORDS: &[&str] = &[
    "while", "until", "if", "then", "do", "else", "elif", "!", "{", "}", "done", "fi",
];

/// Wrappers whose arguments are another command (on top of [`PREFIXES`]).
const WRAPPERS: &[&str] = &[
    "command",
    "stdbuf",
    "unbuffer",
    "timeout",
    "setsid",
    "chrt",
    "ionice",
    "taskset",
    "doas",
    "caffeinate",
    "systemd-inhibit",
    "rlwrap",
    "npx",
    "bunx",
    "pnpx",
    "winpty",
];

/// Why a Codex shell command may not run because it opens an interactive shell, REPL or any
/// other program that executes what is typed into it, or `None`. Codex's `write_stdin` feeds
/// such a session input without running any hook, so every gate would be skipped for it.
pub fn interactive_reason(command: &str) -> Option<String> {
    interactive_depth(command, 0)
}

/// Where a segment's stdin comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Input {
    /// The terminal (no redirection, or one from [`TTY_SOURCES`], or a pipe that only relays
    /// the terminal).
    Terminal,
    /// A file, here-document, here-string or a pipe from a command that produces its own data.
    Fed,
}

struct Segment<'a> {
    words: Vec<&'a str>,
    input: Input,
}

fn segments(toks: &[Tok]) -> Vec<Segment<'_>> {
    let mut out: Vec<Segment> = Vec::new();
    let mut words: Vec<&str> = Vec::new();
    let mut redirect: Option<Input> = None;
    let mut piped = false;
    let mut iter = toks.iter().peekable();
    loop {
        let tok = iter.next();
        match tok {
            Some(Tok::Word(w)) => {
                words.push(w);
                continue;
            }
            Some(Tok::In) => {
                let from = match iter.peek() {
                    Some(Tok::Word(w)) => {
                        let w = w.as_str();
                        iter.next();
                        w
                    }
                    _ => "",
                };
                redirect = Some(if TTY_SOURCES.contains(&from) {
                    Input::Terminal
                } else {
                    Input::Fed
                });
                continue;
            }
            Some(Tok::Out) => {
                // The redirection target is not an argument.
                if let Some(Tok::Word(_)) = iter.peek() {
                    iter.next();
                }
                continue;
            }
            Some(Tok::Break(_)) | None => {}
        }
        let input = match redirect.take() {
            Some(input) => input,
            None if piped => match out.last() {
                Some(prev) if prev.input == Input::Terminal && passes_through(&prev.words) => {
                    Input::Terminal
                }
                _ => Input::Fed,
            },
            None => Input::Terminal,
        };
        out.push(Segment {
            words: std::mem::take(&mut words),
            input,
        });
        piped = matches!(tok, Some(Tok::Break(true)));
        if tok.is_none() {
            return out;
        }
    }
}

fn interactive_depth(command: &str, depth: usize) -> Option<String> {
    if let Some(reason) = terminal_substitution(command) {
        return Some(reason);
    }
    let toks = tokenize(command);
    let segs = segments(&toks);
    if let Some(reason) = read_eval_loop(&segs) {
        return Some(reason);
    }
    segs.iter()
        .find_map(|s| interactive_segment(&s.words, s.input, depth))
}

/// A command or process substitution whose command reads the terminal (`"$(cat)"`, `<(cat)`,
/// `` `head -n1` ``): its output, which `write_stdin` supplies, becomes a command or script.
fn terminal_substitution(command: &str) -> Option<String> {
    let bytes = command.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let open = match (bytes[i], bytes.get(i + 1)) {
            (b'$' | b'<', Some(b'(')) => Some(i + 2),
            (b'`', _) => Some(i + 1),
            _ => None,
        };
        let Some(start) = open else {
            i += 1;
            continue;
        };
        let close = if bytes[i] == b'`' { '`' } else { ')' };
        let inner = command
            .get(start..)
            .and_then(|rest| rest.split(close).next())
            .unwrap_or("");
        let toks = tokenize(inner);
        let segs = segments(&toks);
        let reads_terminal = segs.first().is_some_and(|seg| {
            seg.input == Input::Terminal
                && program_index(&seg.words).0.is_some_and(|at| {
                    let program = base(seg.words[at]);
                    matches!(program, "read" | "line")
                        || (PASS_THROUGH.contains(&program) && passes_through(&seg.words))
                })
        });
        if reads_terminal {
            return deny_exec("a command substitution");
        }
        i = start;
    }
    None
}

/// The program name without a version suffix (`python3.12` → `python`, `lua5.4` → `lua`).
fn unversioned(program: &str) -> &str {
    let trimmed = program.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    if trimmed.is_empty() {
        program
    } else {
        trimmed
    }
}

fn base(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

fn is_assignment(word: &str) -> bool {
    word.contains('=') && !word.starts_with('=') && !word.starts_with('-')
}

/// Options of a wrapper that take a separate argument.
fn wrapper_option_takes_arg(wrapper: &str, opt: &str) -> bool {
    match wrapper {
        "sudo" | "doas" => matches!(
            opt,
            "-u" | "-g" | "-C" | "-D" | "-h" | "-p" | "-r" | "-t" | "-U" | "-T" | "-R"
        ),
        "env" => matches!(opt, "-u" | "-C" | "-S" | "--unset" | "--chdir"),
        "nice" => opt == "-n",
        "exec" => opt == "-a",
        "time" => matches!(opt, "-f" | "-o"),
        "stdbuf" => matches!(opt, "-i" | "-o" | "-e"),
        "timeout" => matches!(opt, "-s" | "-k" | "--signal" | "--kill-after"),
        "ionice" => matches!(opt, "-c" | "-n" | "-p"),
        "chrt" | "taskset" => false,
        _ => false,
    }
}

/// The program word's index after assignments, keywords and wrappers (with their options), and
/// whether a `sudo`/`doas` among them starts a login or interactive shell (`-i`, `-s`).
fn program_index(words: &[&str]) -> (Option<usize>, bool) {
    let mut i = 0;
    let mut shell_flag = false;
    while let Some(w) = words.get(i) {
        let b = base(w);
        if is_assignment(w) || KEYWORDS.contains(w) {
            i += 1;
            continue;
        }
        // Runners whose subcommand runs a command (`uv run python`, `mise exec node --`,
        // `npm exec -- tsx`).
        if let Some(sub) = words.get(i + 1) {
            let runs = match b {
                "uv" | "poetry" | "pipx" | "pdm" | "rye" | "hatch" | "pixi" => *sub == "run",
                "mise" | "rtx" => matches!(*sub, "exec" | "x"),
                "npm" | "pnpm" | "yarn" => *sub == "exec",
                _ => false,
            };
            if runs {
                i += 2;
                if let Some(dash) = words[i..].iter().position(|w| *w == "--") {
                    if matches!(b, "mise" | "rtx" | "npm" | "pnpm") {
                        i += dash + 1;
                    }
                }
                while words
                    .get(i)
                    .is_some_and(|w| w.starts_with('-') && *w != "--")
                {
                    i += 1;
                }
                if words.get(i) == Some(&"--") {
                    i += 1;
                }
                continue;
            }
        }
        if !(PREFIXES.contains(&b) || WRAPPERS.contains(&b)) {
            return (Some(i), shell_flag);
        }
        // `command -v bash` looks a name up; it runs nothing.
        if b == "command" && words.get(i + 1).is_some_and(|o| matches!(*o, "-v" | "-V")) {
            return (None, false);
        }
        i += 1;
        while let Some(opt) = words.get(i).filter(|o| o.starts_with('-') && **o != "-") {
            if matches!(b, "sudo" | "doas")
                && (matches!(*opt, "-i" | "-s" | "--login" | "--shell")
                    || (!opt.starts_with("--") && opt.len() > 2 && opt.contains(['i', 's'])))
            {
                shell_flag = true;
            }
            i += if wrapper_option_takes_arg(b, opt) {
                2
            } else {
                1
            };
        }
        if b == "timeout" && words.get(i).is_some() {
            // The duration.
            i += 1;
        }
    }
    (None, shell_flag)
}

/// Whether a segment copies its stdin to its stdout (`cat`, `tee`, `grep x`, a filter with no
/// input file).
fn passes_through(words: &[&str]) -> bool {
    let (Some(at), _) = program_index(words) else {
        return false;
    };
    let program = base(words[at]);
    if !PASS_THROUGH.contains(&program) {
        return false;
    }
    let args = &words[at + 1..];
    let operands: Vec<&str> = args
        .iter()
        .copied()
        .filter(|a| !a.starts_with('-') || *a == "-")
        .collect();
    let stdinish = |a: &&str| *a == "-" || TTY_SOURCES.contains(a);
    match program {
        "tee" | "tr" | "stdbuf" | "pv" | "buffer" | "mbuffer" => true,
        "dd" => !args.iter().any(|a| {
            a.strip_prefix("if=")
                .is_some_and(|f| !TTY_SOURCES.contains(&f))
        }),
        // The first operand is a pattern or program, the rest files.
        "grep" | "egrep" | "fgrep" | "sed" | "awk" | "gawk" | "mawk" | "nawk" => {
            let from_flag = args.iter().any(|a| matches!(*a, "-e" | "-f" | "--file"));
            let files = operands.iter().skip(usize::from(!from_flag));
            files.clone().all(stdinish) || files.count() == 0
        }
        _ => operands.iter().all(stdinish),
    }
}

fn deny(program: &str) -> Option<String> {
    Some(format!(
        "safe-ai-skill: `{program}` would start an interactive session; Codex feeds it input \
         through write_stdin without running any hook, so nothing typed into it would be \
         checked. Run it with the commands as arguments (`-c`, a script file), or yourself."
    ))
}

fn deny_exec(program: &str) -> Option<String> {
    Some(format!(
        "safe-ai-skill: `{program}` would run commands read from its input, which Codex's \
         write_stdin can feed without running any hook, so nothing sent to it would be checked. \
         Give it the commands or data as arguments or a file, or run it yourself."
    ))
}

/// A read loop that runs what it reads (`while read l; do eval "$l"; done`, `read c; $c`):
/// the reader takes the terminal, and the loop executes the text.
fn read_eval_loop(segs: &[Segment]) -> Option<String> {
    let reads = segs.iter().any(|s| {
        s.input == Input::Terminal
            && program_index(&s.words)
                .0
                .is_some_and(|i| matches!(s.words[i], "read" | "mapfile" | "readarray"))
    });
    if !reads {
        return None;
    }
    let runs = segs.iter().any(|s| {
        let Some(i) = program_index(&s.words).0 else {
            return false;
        };
        let program = s.words[i];
        let args = &s.words[i + 1..];
        let variable = |w: &&str| w.starts_with('$');
        matches!(program, "eval" | "source" | ".")
            || program.starts_with('$')
            || (SHELLS.contains(&base(program)) && args.iter().any(variable))
    });
    if runs {
        deny_exec("read")
    } else {
        None
    }
}

/// The code given to an interpreter with `-c`/`-e`/`--eval` (or a flag cluster ending in `e`,
/// as in `perl -ne`), and the index of the word after it.
fn inline_code<'a>(args: &[&'a str]) -> Option<(&'a str, usize)> {
    args.iter().enumerate().find_map(|(i, a)| {
        let cluster = a.starts_with('-') && !a.starts_with("--") && a.ends_with(['e', 'E', 'c']);
        let long = matches!(*a, "--eval" | "--exec" | "-p" | "--print");
        (cluster || long)
            .then(|| args.get(i + 1).map(|code| (*code, i + 2)))
            .flatten()
    })
}

/// Whether interpreter code (or a `-n`/`-p` loop) executes text it reads from stdin
/// (`perl -ne 'system $_'`, `python3 -c 'exec(sys.stdin.read())'`, `awk '{system($0)}'`).
fn executes_stdin(program: &str, args: &[&str]) -> bool {
    let lower = |s: &str| s.to_ascii_lowercase();
    match program {
        "perl" | "ruby" => {
            let looped = args.iter().any(|a| {
                a.starts_with('-')
                    && !a.starts_with("--")
                    && a.trim_start_matches('-').contains(['n', 'p'])
                    && a.trim_start_matches('-')
                        .chars()
                        .all(|c| c.is_ascii_alphabetic())
            });
            let Some((code, after)) = inline_code(args) else {
                return false;
            };
            let files = args
                .get(after..)
                .unwrap_or_default()
                .iter()
                .any(|a| !a.starts_with('-') && !TTY_SOURCES.contains(a));
            let reads = looped
                || ["stdin", "<>", "gets", "argf", "readline", "readlines"]
                    .iter()
                    .any(|k| lower(code).contains(k));
            let execs = [
                "system", "exec", "eval", "`", "qx", "spawn", "popen", "open(", "open ", "%x",
            ]
            .iter()
            .any(|k| code.contains(k));
            reads && execs && !files
        }
        p if p.starts_with("python") => inline_code(args).is_some_and(|(code, _)| {
            let code = lower(code);
            (code.contains("stdin") || code.contains("input("))
                && [
                    "exec(",
                    "eval(",
                    "system(",
                    "subprocess",
                    "popen",
                    "pty.spawn",
                    "os.exec",
                ]
                .iter()
                .any(|k| code.contains(k))
        }),
        "node" | "nodejs" | "deno" | "bun" => inline_code(args).is_some_and(|(code, _)| {
            (code.contains("stdin") || code.contains("readline"))
                && [
                    "eval(",
                    "child_process",
                    "execSync",
                    "spawn",
                    "Function(",
                    "vm.",
                ]
                .iter()
                .any(|k| code.contains(k))
        }),
        "awk" | "gawk" | "mawk" | "nawk" => {
            if args.iter().any(|a| matches!(*a, "-f" | "--file")) {
                return false;
            }
            let mut positional = args.iter().filter(|a| !a.starts_with('-'));
            let Some(program_text) = positional.next() else {
                return false;
            };
            let files = positional.any(|a| !a.contains('=') && !TTY_SOURCES.contains(a));
            let compact: String = program_text
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            let execs = compact.contains("system(")
                || compact.contains("|getline")
                || compact.contains("|&")
                || compact.contains("print|")
                || compact.contains("printf|");
            execs && !files
        }
        "sed" => {
            let mut positional = args.iter().filter(|a| !a.starts_with('-'));
            let script = args
                .iter()
                .position(|a| *a == "-e")
                .and_then(|i| args.get(i + 1))
                .or_else(|| positional.next());
            let Some(script) = script else {
                return false;
            };
            let has_files = positional.any(|a| !TTY_SOURCES.contains(a));
            let runs = script
                .split([';', '\n'])
                .any(|cmd| cmd.trim() == "e" || cmd.trim().starts_with("e "));
            runs && !has_files
        }
        _ => false,
    }
}

/// Where `ssh` (and `mosh`, `rsh`) put the remote command: `Some(true)` when one is given or
/// no shell is started (`-N`, `-W`, `-O`), `Some(false)` for a bare login.
fn ssh_has_command(args: &[&str]) -> bool {
    const WITH_ARG: &[&str] = &[
        "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o", "-p",
        "-Q", "-R", "-S", "-W", "-w", "-B", "-P",
    ];
    let mut i = 0;
    let mut host_seen = false;
    while let Some(a) = args.get(i) {
        if !host_seen && a.starts_with('-') {
            if matches!(*a, "-N" | "-W" | "-O" | "-V" | "-G" | "-Q")
                || (a.contains('N') && !a.starts_with("--"))
            {
                return true;
            }
            i += if WITH_ARG.contains(a) { 2 } else { 1 };
            continue;
        }
        if host_seen {
            return true;
        }
        host_seen = true;
        i += 1;
    }
    false
}

fn interactive_segment(words: &[&str], input: Input, depth: usize) -> Option<String> {
    // `env -S 'bash -i'` splits its argument into the command.
    if let Some(i) = words
        .iter()
        .position(|w| matches!(*w, "-S" | "--split-string"))
    {
        if words[..i].iter().any(|w| base(w) == "env") && depth < 2 {
            if let Some(split) = words.get(i + 1) {
                if let Some(reason) = interactive_depth(split, depth + 1) {
                    return Some(reason);
                }
            }
        }
    }
    let (at, sudo_shell) = program_index(words);
    let Some(at) = at else {
        return sudo_shell.then(|| deny("sudo")).flatten();
    };
    let program_word = words[at];
    let raw_program = base(program_word);
    let known = |p: &str| SHELLS.contains(&p) || REPLS.contains(&p) || DB_SHELLS.contains(&p);
    let program = if !known(raw_program) && known(unversioned(raw_program)) {
        unversioned(raw_program)
    } else {
        raw_program
    };
    let args: Vec<&str> = words[at + 1..].to_vec();
    // `busybox sh` runs the applet.
    if program == "busybox" && args.first().is_some_and(|a| !a.starts_with('-')) {
        return interactive_segment(&args, input, depth);
    }
    // `find … -exec bash \;` runs the command with find's terminal.
    if program == "find" {
        let mut rest = args.as_slice();
        while let Some(i) = rest
            .iter()
            .position(|a| matches!(*a, "-exec" | "-execdir" | "-ok" | "-okdir"))
        {
            let cmd: Vec<&str> = rest[i + 1..]
                .iter()
                .copied()
                .take_while(|a| *a != ";" && *a != "+")
                .collect();
            if let Some(reason) = interactive_segment(&cmd, input, depth) {
                return Some(reason);
            }
            rest = &rest[i + 1 + cmd.len()..];
        }
        return None;
    }
    if program == "socat"
        && args.iter().any(|a| {
            let up = a.to_ascii_uppercase();
            up.starts_with("EXEC:") || up.starts_with("SYSTEM:")
        })
    {
        return deny(program);
    }
    let flag = |pred: &dyn Fn(&str) -> bool| args.iter().any(|a| a.starts_with('-') && pred(a));
    let positionals: Vec<&str> = args
        .iter()
        .copied()
        .filter(|a| !a.starts_with('-') && !a.starts_with('+'))
        .collect();
    let terminal = input == Input::Terminal;
    let stdin_name = |a: &str| a == "-" || TTY_SOURCES.contains(&a);
    let forced = flag(&|a| a == "-i" || a == "--interactive");

    if SHELLS.contains(&program) {
        let script_at = args
            .iter()
            .position(|a| a.starts_with('-') && !a.starts_with("--") && a.contains('c'));
        if let Some(at) = script_at {
            if depth < 2 {
                if let Some(script) = args.get(at + 1) {
                    return interactive_depth(script, depth + 1);
                }
            }
            return None;
        }
        let from_stdin = flag(&|a| !a.starts_with("--") && a.contains('s'))
            || positionals.first().is_none_or(|s| stdin_name(s))
            || args.contains(&"-");
        return ((from_stdin && terminal) || forced)
            .then(|| deny(program))
            .flatten();
    }
    if executes_stdin(program, &args) && terminal {
        return deny_exec(program);
    }
    if REPLS.contains(&program) {
        if matches!(program, "deno" | "bun") {
            let first = positionals.first();
            return ((first.is_none() && terminal) || first == Some(&"repl"))
                .then(|| deny(program))
                .flatten();
        }
        let code = flag(&|a| {
            matches!(
                a,
                "-c" | "-e" | "-E" | "--eval" | "-m" | "-r" | "-p" | "--print" | "-f"
            ) || (program == "perl" || program == "ruby")
                && !a.starts_with("--")
                && a.ends_with('e')
        });
        let script_from_stdin = positionals.first().is_none_or(|s| stdin_name(s));
        return ((!code && script_from_stdin && terminal) || forced)
            .then(|| deny(program))
            .flatten();
    }
    if DB_SHELLS.contains(&program) {
        let command = flag(&|a| {
            matches!(a, "-c" | "-f" | "-e" | "--eval" | "--execute" | "--file")
                || a.starts_with("--command")
                || a.starts_with("--file=")
                || a.starts_with("--execute=")
        });
        let sql_arg = program == "sqlite3" && positionals.len() > 1;
        let redis_cmd = program == "redis-cli" && !positionals.is_empty();
        return (!command && !sql_arg && !redis_cmd && terminal)
            .then(|| deny(program))
            .flatten();
    }
    if MULTIPLEXERS.contains(&program) {
        let sub = args
            .iter()
            .find(|a| !a.starts_with('-') || MULTIPLEXER_READS.contains(a));
        let read_only = sub.is_some_and(|s| MULTIPLEXER_READS.contains(s));
        return (!read_only).then(|| deny(program)).flatten();
    }
    match program {
        // `script [opts] [file [command…]]` (BSD) or `script -c command [file]` (util-linux):
        // the command runs on a new terminal; without one, a shell does.
        "script" => {
            if let Some(i) = args.iter().position(|a| matches!(*a, "-c" | "--command")) {
                return match args.get(i + 1) {
                    Some(cmd) if depth < 2 => interactive_depth(cmd, depth + 1),
                    Some(_) => None,
                    None => deny(program),
                };
            }
            let mut i = 0;
            while args.get(i).is_some_and(|a| a.starts_with('-')) {
                i += if matches!(args[i], "-t" | "-F" | "-T" | "-B" | "-I" | "-O" | "-E") {
                    2
                } else {
                    1
                };
            }
            let command = args.get(i + 1..).unwrap_or_default();
            if command.is_empty() {
                return deny(program);
            }
            interactive_segment(command, Input::Terminal, depth)
        }
        "ssh" | "mosh" | "rsh" | "slogin" => {
            if program == "mosh" {
                return (!args.contains(&"--")).then(|| deny(program)).flatten();
            }
            (!ssh_has_command(&args)).then(|| deny(program)).flatten()
        }
        "telnet" | "rlogin" => deny(program),
        "su" | "runuser" => {
            let command =
                flag(&|a| a == "-c" || a.starts_with("--command") || a == "--session-command");
            (!command).then(|| deny(program)).flatten()
        }
        "chroot" | "nsenter" | "unshare" => {
            // `chroot dir` / `nsenter -t pid -a` / `unshare -r` with no command start a shell.
            let rest_after_dir = if program == "chroot" {
                positionals.len() > 1
            } else {
                !positionals.is_empty()
            };
            (!rest_after_dir).then(|| deny(program)).flatten()
        }
        "nix-shell" => {
            let command = args
                .iter()
                .position(|a| matches!(*a, "--run" | "--command"))
                .and_then(|i| args.get(i + 1));
            match command {
                Some(cmd) if depth < 2 => interactive_depth(cmd, depth + 1),
                Some(_) => None,
                None => deny(program),
            }
        }
        "nix" if matches!(positionals.first(), Some(&"develop" | &"shell")) => {
            let command = args.iter().any(|a| matches!(*a, "-c" | "--command"));
            (!command).then(|| deny(program)).flatten()
        }
        "docker" | "podman" if positionals.first() == Some(&"compose") => {
            // `compose exec` allocates a terminal unless told not to (`-T`, `-d`).
            let sub = positionals.get(1).copied().unwrap_or("");
            let no_tty = args
                .iter()
                .any(|a| matches!(*a, "-T" | "--no-TTY" | "--no-tty" | "-d" | "--detach"));
            (matches!(sub, "exec" | "run" | "attach") && !no_tty && terminal)
                .then(|| deny(program))
                .flatten()
        }
        "docker" | "podman" | "nerdctl" | "kubectl" | "oc" => {
            let sub = positionals.first().copied().unwrap_or("");
            let attaches = matches!(sub, "exec" | "run" | "attach" | "start" | "debug");
            let interactive = args.iter().any(|a| {
                matches!(*a, "--interactive" | "--stdin" | "--tty")
                    || (a.starts_with('-') && !a.starts_with("--") && a.contains('i'))
            });
            (attaches && interactive && (sub == "attach" || terminal))
                .then(|| deny(program))
                .flatten()
        }
        "systemd-run" | "machinectl" => {
            let shell = args
                .iter()
                .any(|a| matches!(*a, "-S" | "--shell" | "shell" | "login"));
            shell.then(|| deny(program)).flatten()
        }
        // `xargs` builds commands from its input: a shell, interpreter or `eval` it runs
        // executes what is typed into it.
        "xargs" if terminal => {
            let mut i = 0;
            while let Some(a) = args.get(i).filter(|a| a.starts_with('-')) {
                let takes = matches!(*a, "-I" | "-L" | "-n" | "-P" | "-s" | "-d" | "-E" | "-a");
                if *a == "-a" || a.starts_with("--arg-file") {
                    let file = args.get(i + 1).copied().unwrap_or("");
                    if !a.contains('=') && !TTY_SOURCES.contains(&file) {
                        return None;
                    }
                }
                i += if takes { 2 } else { 1 };
            }
            let runs = args
                .get(i)
                .map(|w| base(w))
                .is_some_and(|p| SHELLS.contains(&p) || REPLS.contains(&p) || p == "eval");
            runs.then(|| deny_exec(program)).flatten()
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interactive_sessions_are_recognized() {
        for c in [
            "bash",
            "sh -i",
            "zsh -l",
            "python3",
            "python3 -i script.py",
            "node",
            "irb",
            "psql -h db mydb",
            "sqlite3 my.db",
            "env FOO=1 bash",
            "cd x && python",
            "bash -c 'bash'",
            "deno",
            "bun repl",
        ] {
            assert!(interactive_reason(c).is_some(), "{c}");
        }
        for c in [
            "bash -c 'ls'",
            "bash script.sh",
            "sh -lc 'echo hi'",
            "python3 script.py",
            "python3 -c 'print(1)'",
            "python3 -m pytest",
            "echo ls | bash",
            "bash < script.sh",
            "python3 <<'EOF'\nprint(1)\nEOF",
            "node -e 'console.log(1)'",
            "psql -c 'select 1'",
            "sqlite3 my.db 'select 1'",
            "deno run x.ts",
            "cargo test",
            "ls > bash",
        ] {
            assert!(interactive_reason(c).is_none(), "{c}");
        }
    }

    #[test]
    fn other_shell_start_forms_are_recognized() {
        for c in [
            "cat | bash",
            "cat - | sh",
            "tee /tmp/log | bash",
            "cat | tee x | grep -v '^#' | bash",
            "bash /dev/stdin",
            "python3 /dev/stdin",
            "python3 -",
            "bash -s",
            "bash -s -- arg",
            "bash < /dev/tty",
            "sh 0</dev/stdin",
            "script -q /dev/null",
            "script",
            "script -c bash /dev/null",
            "script -q /dev/null zsh",
            "while read l; do eval \"$l\"; done",
            "while IFS= read -r l; do $l; done",
            "read cmd; eval $cmd",
            "while read l; do sh -c \"$l\"; done",
            "xargs -I{} sh -c {}",
            "xargs sh -c",
            "xargs -n1 bash -c",
            "perl -ne 'system $_'",
            "perl -lne 'system($_)'",
            "ruby -ne 'system $_'",
            "awk '{system($0)}'",
            "python3 -c 'import sys; exec(sys.stdin.read())'",
            "sed e",
            "tmux",
            "tmux new -s work",
            "tmux send-keys -t work 'rm -rf x' Enter",
            "screen",
            "screen -S x",
            "zellij",
            "ssh host",
            "ssh -p 2222 -i key user@host",
            "ssh -t host",
            "mosh host",
            "telnet host 23",
            "su",
            "su - root",
            "sudo -i",
            "sudo -s",
            "sudo -u root bash",
            "sudo su",
            "chroot /mnt",
            "docker exec -it web sh",
            "docker run -it ubuntu",
            "podman run --interactive img",
            "kubectl exec -it pod -- sh",
            "expect",
            "nice -n 5 bash",
            "timeout 60 bash",
            "exec -a x bash",
            "bash -c \"$(cat)\"",
            "eval \"$(cat)\"",
            "$(cat)",
            "bash <(cat)",
            "sh -c \"`head -n1`\"",
            "busybox sh",
            "python3.12",
            "ipython",
            "rlwrap bash",
            "socat - EXEC:bash,pty",
            "docker compose exec web sh",
            "nix-shell",
            "nix develop",
            "uv run python",
            "poetry run python",
            "npx node",
            "env -S 'bash -i'",
            "find . -exec bash \\;",
            "mise exec node -- node",
        ] {
            assert!(interactive_reason(c).is_some(), "{c}");
        }
        for c in [
            "echo ls | cat | bash",
            "cat script.sh | bash",
            "cat a b | sh",
            "printf 'ls\\n' | tee log | sh",
            "bash script.sh /dev/stdin",
            "bash -s < script.sh",
            "script -q /dev/null ls -la",
            "script -c 'cargo test' /dev/null",
            "while read l; do echo \"$l\"; done < list.txt",
            "while read l; do echo \"$l\"; done",
            "find . -name '*.rs' | xargs sh -c 'wc -l \"$@\"' _",
            "xargs -a list.txt sh -c 'echo $0'",
            "xargs rm",
            "perl -ne 'print if /x/' file.txt",
            "perl -ne 'system $_' cmds.txt",
            "perl -pi -e 's/a/b/' x",
            "awk '{print $1}'",
            "awk '{system($0)}' cmds.txt",
            "python3 -c 'import sys; print(sys.stdin.read())'",
            "sed -n p",
            "tmux ls",
            "tmux has-session -t x",
            "screen -ls",
            "ssh host uptime",
            "ssh -N -L 8080:localhost:80 host",
            "ssh -p 22 host 'ls -la'",
            "mosh host -- uptime",
            "su -c 'ls' root",
            "sudo -u root ls",
            "sudo ls",
            "chroot /mnt ls",
            "docker run --rm img cargo test",
            "docker ps",
            "kubectl get pods",
            "echo cmd | docker exec -i web sh",
            "timeout 60 cargo test",
            "nice -n 5 make",
            "echo \"$(cat file.txt)\"",
            "bash -c \"$(git rev-parse HEAD)\"",
            "busybox ls",
            "python3.12 script.py",
            "docker compose exec -T web sh -c 'ls'",
            "docker compose ps",
            "nix-shell --run 'cargo test'",
            "nix develop -c cargo build",
            "uv run pytest",
            "npx tsc",
            "find . -exec grep -l x {} +",
            "socat TCP:host:80 -",
        ] {
            assert!(interactive_reason(c).is_none(), "{c}");
        }
    }

    #[test]
    fn routes() {
        assert_eq!(route("gate-bash", &[]), Some(Route::Gate("gate-bash")));
        assert_eq!(route("session-start", &[]), Some(Route::SessionStart));
        assert_eq!(
            route("redact", &[BLOCK_WITH_REDACTION.to_string()]),
            Some(Route::RedactBlock)
        );
        assert_eq!(route("redact", &[]), None, "redaction is opt-in only");
        assert_eq!(route("gate-read", &[]), None);
        assert_eq!(route("gate-bash", &["x".to_string()]), None);
        assert_eq!(route("session-start", &["x".to_string()]), None);
    }

    #[test]
    fn redaction_blocks_with_the_redacted_text() {
        assert_eq!(redact_block(None), None);
        let v = redact_block(Some(Value::String("key=[REDACTED]".into()))).unwrap();
        assert_eq!(v["decision"], "block");
        let reason = v["reason"].as_str().unwrap();
        assert!(reason.starts_with(REDACTED_PREFIX) && reason.ends_with("key=[REDACTED]"));
        let obj = redact_block(Some(serde_json::json!({"a": "[REDACTED]"}))).unwrap();
        assert!(obj["reason"]
            .as_str()
            .unwrap()
            .ends_with(r#"{"a":"[REDACTED]"}"#));
        assert_eq!(
            v.as_object().unwrap().len(),
            2,
            "Codex rejects unknown fields"
        );
    }
}
