//! Shell command parsing for the Bash gate (spec D1.8).
//!
//! [`parse`] turns a Bash tool command into the simple commands it runs, the way a POSIX shell
//! would split it: on newline, `;`, `&`, `&&`, `||` and `|`, honoring quotes, escapes and
//! comments. Redirections are dropped (they never reach a program's argv). Each simple command
//! is stripped of what runs *it* rather than being it: `NAME=value` prefixes, reserved words
//! (`!`, `{`, `if`, `do`, …) and wrappers (`env`, `sudo`, `nohup`, `time`, `command`, `exec`,
//! `xargs`, …). The parser recurses into everything that runs code the command line spells
//! out: `$(…)`, backticks, `<(…)`, `(…)` subshells, `bash|sh|zsh -c '…'`, `eval`, here-strings
//! and here-documents fed to a shell, and `find -exec`-style launchers.
//!
//! It never evaluates anything. A word carrying an expansion is marked [`Word::dynamic`], and
//! one the shell may split into several words or globs ([`Word::splits`]) makes every argument
//! position after it unknowable. Shapes whose script is invisible on the command line (a
//! shell reading a pipe, `eval "$x"`, `python -c` naming `solana`) set [`Parsed::opaque`];
//! unbalanced quotes or substitutions set [`Parsed::unparseable`]. Pure: no I/O.

/// Deepest nesting of substitutions and `-c` scripts followed; deeper is unparseable.
const MAX_DEPTH: usize = 8;

/// The solana-family programs the Bash gate classifies.
pub const FAMILY: &[&str] = &["solana", "spl-token", "anchor"];

/// Shells whose `-c` script, here-string or here-document is parsed as a script.
const SHELLS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "yash", "fish", "busybox",
];

/// Interpreters whose `-c`/`-e` code runs programs the parser cannot see (a versioned name,
/// `python3.12`, counts as its base).
const INTERPRETERS: &[&str] = &[
    "python",
    "python2",
    "python3",
    "pypy",
    "pypy3",
    "node",
    "nodejs",
    "tsx",
    "ts-node",
    "perl",
    "ruby",
    "deno",
    "bun",
    "php",
    "lua",
    "luajit",
    "rscript",
    "julia",
    "tclsh",
    "osascript",
    "pwsh",
    "powershell",
];

/// Whether `program` (a base name, [`base_name`]) is one of [`INTERPRETERS`].
pub fn is_interpreter(program: &str) -> bool {
    INTERPRETERS
        .iter()
        .any(|i| program == *i || program.starts_with(&format!("{i}.")))
}

/// Project runners that run their command in an environment: `(name, subcommand)`, where an
/// empty subcommand means the name alone (`npx tsx`).
const RUNNERS: &[(&str, &str)] = &[
    ("uv", "run"),
    ("uvx", ""),
    ("poetry", "run"),
    ("pipenv", "run"),
    ("pdm", "run"),
    ("hatch", "run"),
    ("rye", "run"),
    ("conda", "run"),
    ("mamba", "run"),
    ("micromamba", "run"),
    ("npx", ""),
    ("bunx", ""),
    ("pnpx", ""),
    ("pnpm", "exec"),
    ("pnpm", "dlx"),
    ("yarn", "exec"),
    ("yarn", "dlx"),
    ("npm", "exec"),
];

/// Value-taking options of [`RUNNERS`].
const RUNNER_VALUE_FLAGS: &[&str] = &[
    "--with",
    "--python",
    "-p",
    "--project",
    "--directory",
    "-n",
    "--name",
    "--prefix",
    "--package",
    "--from",
    "-e",
    "--env",
];

/// The index of the interpreter a command runs: 0 for `python3 …`, the inner one behind a
/// project runner (`uv run python …`, `npx tsx …`, `conda run -n x python …`). `None` when it
/// runs none.
pub fn interpreter_at(words: &[Word]) -> Option<usize> {
    let first = base_name(&words.first()?.text);
    if is_interpreter(&first) {
        return Some(0);
    }
    let second = words.get(1).map(|w| w.text.as_str()).unwrap_or_default();
    let (_, sub) = RUNNERS
        .iter()
        .find(|(name, sub)| *name == first && (sub.is_empty() || *sub == second))?;
    let mut i = if sub.is_empty() { 1 } else { 2 };
    while let Some(word) = words.get(i) {
        let text = word.text.as_str();
        if text == "--" {
            i += 1;
            break;
        }
        if !text.starts_with('-') {
            break;
        }
        i += if RUNNER_VALUE_FLAGS.contains(&text) {
            2
        } else {
            1
        };
    }
    let inner = base_name(&words.get(i)?.text);
    is_interpreter(&inner).then_some(i)
}

/// Programs that run one of their later arguments as a command (`find … -exec solana …`).
const LAUNCHERS: &[&str] = &[
    "find",
    "watch",
    "parallel",
    "flock",
    "chroot",
    "ssh",
    "script",
    "unshare",
    "setpriv",
    "firejail",
    "systemd-run",
    "strace",
    "ltrace",
    "valgrind",
    "hyperfine",
    "entr",
    "npx",
    "pnpx",
    "bunx",
    "dbus-run-session",
    "taskset",
    "chrt",
    "prlimit",
    "runuser",
    "su",
    "doas",
    "busybox",
    "expect",
    "tmux",
    "screen",
    "nix-shell",
    "direnv",
    "mise",
    "asdf",
    "arch",
    "sandbox-exec",
    "pkexec",
    "sg",
    "fakeroot",
    "numactl",
    "chpst",
];

/// Value-moving or irreversible subcommand segments. A word is gated when one of its `.`- or
/// `-`-separated parts is one of these (`transfer`, `close-mint`, `set-upgrade-authority`,
/// `withdraw-from-vote-account`, `create-account`, `x.transfer`), or it holds `write-buffer`.
pub const GATED_SEGMENTS: &[&str] = &[
    "transfer",
    "deploy",
    "upgrade",
    "close",
    "authority",
    "authorize",
    "withdraw",
    "delegate",
    "stake",
    "mint",
    "burn",
    "approve",
    "revoke",
    "wrap",
    "unwrap",
    "erase",
    "create",
];

/// Whether `word` is a value-moving subcommand word (see [`GATED_SEGMENTS`]).
pub fn is_gated_word(word: &str) -> bool {
    let word = word.to_ascii_lowercase();
    word.contains("write-buffer")
        || word
            .split(['.', '-'])
            .any(|part| GATED_SEGMENTS.contains(&part))
}

/// Characters that continue a word for mention and gated-token matching.
fn is_mention_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')
}

/// Value-moving subcommands of the solana CLIs. An expansion run as a program followed by one
/// of these (`$X transfer …`) may be a family command.
pub const FAMILY_VERBS: &[&str] = &[
    "transfer",
    "program",
    "deploy",
    "upgrade",
    "close",
    "close-mint",
    "close-vote-account",
    "withdraw-stake",
    "withdraw-from-vote-account",
    "withdraw-from-nonce-account",
    "withdraw-withheld-tokens",
    "delegate-stake",
    "deactivate-stake",
    "split-stake",
    "merge-stake",
    "redelegate-stake",
    "create-stake-account",
    "create-stake-account-checked",
    "create-vote-account",
    "create-nonce-account",
    "create-token",
    "create-account",
    "stake-authorize",
    "stake-authorize-checked",
    "stake-set-lockup",
    "vote-authorize-voter",
    "vote-authorize-withdrawer",
    "authorize",
    "authorize-nonce-account",
    "mint",
    "burn",
    "approve",
    "revoke",
    "wrap",
    "unwrap",
    "idl",
    "migrate",
];

/// Programs whose arguments (or here-string) are the text they write: `echo 'solana …' > x.sh`.
const EMITTERS: &[&str] = &["echo", "printf", "print"];

/// Whether an expansion used as a program word could spell a solana-family program: it names
/// one (`$(printf %s ./solana)`), or a literal fragment of it is part of a family name
/// (`$(echo sol)ana`, `${S}olana`, `$SOLANA_BIN`).
pub fn could_spell_family(word: &str) -> bool {
    let lower = word.to_ascii_lowercase();
    mentions_family(&lower)
        || lower
            .split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|f| f.len() >= 3)
            .any(|f| {
                ["solana", "anchor", "spltoken"]
                    .iter()
                    .any(|n| n.contains(f))
            })
}

/// Whether `cmd` runs an expansion as its program that could be a solana-family program:
/// the program word could spell one (`$(echo sol)ana`, `${S}olana`), the command line assigns
/// a family name (`X=solana; $X …`, `for p in solana; do $p …`), or its first argument is a
/// value-moving solana verb with no flag or file before it (`$X transfer …`).
/// `$EDITOR close-notes.md`, `$PKG run deploy` and `$(npm bin)/hardhat deploy` are not.
pub fn dynamic_family_program(cmd: &SimpleCommand, parsed: &Parsed) -> bool {
    let Some(program) = cmd.words.first().filter(|w| w.dynamic) else {
        return false;
    };
    if program
        .text
        .rsplit_once('/')
        .is_some_and(|(_, last)| !last.is_empty() && !last.contains(['$', '`', ')', '}']))
    {
        // A literal last path segment fixes the program, and it is not a family one.
        return false;
    }
    let verb = cmd.words.get(1).is_some_and(|w| {
        !w.dynamic
            && !w.text.contains(['.', '/'])
            && FAMILY_VERBS.contains(&w.text.to_ascii_lowercase().as_str())
    });
    could_spell_family(&program.text) || parsed.assigns_family || verb
}

/// Whether the text a command writes is a script that runs a value-moving solana-family
/// command: parsed as shell, a family program in command position with a value-moving or
/// expanded word; else, as interpreter code, a quoted string that is such a script
/// (`os.system('solana transfer …')`) or a family program string beside a value-moving one
/// (`['solana', 'transfer', …]`). Prose naming a program (`anchor build failed`) is not.
fn script_runs_family(text: &str, depth: usize) -> bool {
    if text.trim().is_empty() {
        return false;
    }
    if depth >= MAX_DEPTH {
        return mentions_family(text);
    }
    let mut parsed = Parsed::default();
    parse_into(text, depth + 1, true, &mut parsed);
    let runs = parsed.opaque_mention
        || parsed.write_then_run
        || (parsed.unparseable && mentions_family(text) && quoted_segments(text).is_empty())
        || parsed.commands.iter().any(|c| {
            (c.is_family()
                && (c
                    .words
                    .iter()
                    .skip(1)
                    .any(|w| w.dynamic || is_gated_word(&w.text))
                    || unknown_cli_subcommand(c)))
                || dynamic_family_program(c, &parsed)
        });
    if runs {
        return true;
    }
    let segments = quoted_segments(text);
    segments.iter().any(|s| script_runs_family(s, depth + 1))
        || (segments
            .iter()
            .any(|s| FAMILY.contains(&base_name(s.trim()).as_str()))
            && segments.iter().any(|s| is_gated_word(s.trim())))
}

/// A `solana` / `spl-token` command in a written script whose subcommand is not a known
/// read-only one (`solana pay …`): the top-level gate asks on those, so a script running one
/// counts as running a gated command.
fn unknown_cli_subcommand(cmd: &SimpleCommand) -> bool {
    let program = cmd.program();
    let mut subs = cmd
        .words
        .iter()
        .skip(1)
        .map(|w| w.text.to_ascii_lowercase())
        .filter(|t| !t.starts_with('-'));
    let Some(sub) = subs.next() else {
        return false;
    };
    match program.as_str() {
        "solana" if sub.as_str() == "config" => subs.next().as_deref() != Some("get"),
        "solana" => !crate::gates::bash::is_solana_readonly(&sub),
        "spl-token" => !crate::gates::bash::is_spl_readonly(&sub),
        _ => false,
    }
}

/// The contents of the `'…'` and `"…"` strings in `text` (interpreter code).
fn quoted_segments(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(['\'', '"']) {
        let quote = rest[start..].chars().next().unwrap_or('"');
        let body = &rest[start + 1..];
        let Some(end) = body.find(quote) else {
            break;
        };
        out.push(&body[..end]);
        rest = &body[end + 1..];
    }
    out
}

/// The text an emitter writes (`echo`/`printf` arguments, a here-string), with `\n` read as a
/// newline. `None` for any other program: what it writes is its output, not its words.
fn emitted_text(program: &str, args: &[Word], herestrings: &[Word]) -> Option<String> {
    if program == "printf" {
        let args: Vec<&str> = args.iter().map(|w| w.text.as_str()).collect();
        return Some(printf_text(&args).replace("\\n", "\n"));
    }
    let words: Vec<&str> = if EMITTERS.contains(&program) {
        args.iter()
            .map(|w| w.text.as_str())
            .skip_while(|t| {
                t.len() > 1
                    && t.starts_with('-')
                    && t[1..].chars().all(|c| matches!(c, 'n' | 'e' | 'E' | 'r'))
            })
            .collect()
    } else if !herestrings.is_empty() && matches!(program, "cat" | "tee") {
        herestrings.iter().map(|w| w.text.as_str()).collect()
    } else {
        return None;
    };
    Some(words.join(" ").replace("\\n", "\n"))
}

/// What `printf FORMAT ARGS…` writes, best effort: each conversion (`%s`, `%b`, `%5d`, …)
/// takes the next argument verbatim, and the format repeats while arguments remain (as printf
/// does). A format it cannot follow (`%*d`, a trailing `%`): the format, then all its
/// arguments, on separate lines.
fn printf_text(args: &[&str]) -> String {
    let mut args = args;
    if args.first() == Some(&"-v") {
        args = args.get(2..).unwrap_or_default();
    }
    if args.first() == Some(&"--") {
        args = args.get(1..).unwrap_or_default();
    }
    let Some((format, rest)) = args.split_first() else {
        return String::new();
    };
    let format: Vec<char> = format.chars().collect();
    let mut values = rest.iter();
    let mut out = String::new();
    loop {
        let mut conversions = 0;
        let mut i = 0;
        while let Some(&c) = format.get(i) {
            i += 1;
            if c != '%' {
                out.push(c);
                continue;
            }
            if format.get(i) == Some(&'%') {
                i += 1;
                out.push('%');
                continue;
            }
            while let Some(&f) = format.get(i) {
                match f {
                    '-' | '+' | ' ' | '#' | '0'..='9' | '.' => {}
                    // A width or precision taken from the next argument.
                    '*' => {
                        values.next();
                    }
                    _ => break,
                }
                i += 1;
            }
            if !format.get(i).is_some_and(|c| c.is_ascii_alphabetic()) {
                let format: String = format.iter().collect();
                return format!("{format}\n{}", rest.join(" "));
            }
            i += 1;
            conversions += 1;
            out.push_str(values.next().copied().unwrap_or_default());
        }
        if conversions == 0 || values.len() == 0 {
            break;
        }
    }
    decode_escapes(&out)
}

/// The backslash escapes `printf` (format and `%b`) and `echo -e` decode: `\n`, `\t`, `\\`,
/// `\xHH` and octal `\NNN` / `\0NNN`, so `\x73olana` reads as `solana`. Others stay as written.
fn decode_escapes(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        i += 1;
        if c != '\\' || i >= chars.len() {
            out.push(c);
            continue;
        }
        let next = chars[i];
        let digits = |from: usize, max: usize, radix: u32| -> (u32, usize) {
            let mut value = 0u32;
            let mut n = 0;
            while n < max {
                match chars.get(from + n).and_then(|d| d.to_digit(radix)) {
                    Some(d) => value = value * radix + d,
                    None => break,
                }
                n += 1;
            }
            (value, n)
        };
        match next {
            'n' => {
                out.push('\n');
                i += 1;
            }
            't' => {
                out.push('\t');
                i += 1;
            }
            '\\' => {
                out.push('\\');
                i += 1;
            }
            'x' => {
                let (value, n) = digits(i + 1, 2, 16);
                match char::from_u32(value).filter(|_| n > 0) {
                    Some(ch) => {
                        out.push(ch);
                        i += 1 + n;
                    }
                    None => out.push('\\'),
                }
            }
            '0'..='7' => {
                // `\0NNN` (echo -e, %b) or `\NNN` (printf format).
                let start = if next == '0' { i + 1 } else { i };
                let (value, n) = digits(start, 3, 8);
                match char::from_u32(value) {
                    Some(ch) if n > 0 || next == '0' => {
                        out.push(ch);
                        i = start + n;
                    }
                    _ => out.push('\\'),
                }
            }
            _ => out.push('\\'),
        }
    }
    out
}

/// Whether a command's words make it `tee` writing a file (`tee x.sh`, not `tee` or
/// `tee /dev/null`).
fn tee_writes(program: &str, args: &[Word]) -> bool {
    program == "tee"
        && args
            .iter()
            .any(|w| !w.text.starts_with('-') && !is_harmless_target(&w.text))
}

/// Reserved words stripped from the head of a simple command.
const RESERVED: &[&str] = &[
    "!", "{", "}", "if", "then", "else", "elif", "fi", "do", "done", "while", "until", "case",
    "in", "esac", "select", "function",
];

/// Wrappers: `(name, value-taking short flags, value-taking long flags, positionals before
/// the command)`. Unknown flags of a wrapper are taken as boolean.
const WRAPPERS: &[(&str, &str, &[&str], usize)] = &[
    ("env", "uCSP", &["--unset", "--chdir", "--split-string"], 0),
    (
        "sudo",
        "ughpCDrtUTR",
        &[
            "--user",
            "--group",
            "--host",
            "--prompt",
            "--close-from",
            "--chdir",
            "--role",
            "--type",
            "--other-user",
            "--command-timeout",
        ],
        0,
    ),
    ("doas", "uC", &[], 0),
    ("nohup", "", &[], 0),
    ("nice", "n", &["--adjustment"], 0),
    ("time", "fo", &["--format", "--output"], 0),
    ("command", "", &[], 0),
    ("builtin", "", &[], 0),
    ("exec", "a", &[], 0),
    ("timeout", "sk", &["--signal", "--kill-after"], 1),
    ("stdbuf", "ioe", &["--input", "--output", "--error"], 0),
    (
        "xargs",
        "ILnPsdEa",
        &[
            "--arg-file",
            "--delimiter",
            "--max-args",
            "--max-procs",
            "--max-chars",
            "--replace",
            "--max-lines",
            "--eof",
        ],
        0,
    ),
    ("setsid", "", &[], 0),
    ("unbuffer", "", &[], 0),
    ("chronic", "", &[], 0),
    ("ionice", "cnp", &["--class", "--classdata", "--pid"], 0),
    ("caffeinate", "tw", &[], 0),
    ("coproc", "", &[], 0),
    // zsh precommand modifiers.
    ("noglob", "", &[], 0),
    ("nocorrect", "", &[], 0),
    ("repeat", "", &[], 1),
];

/// One shell word after quote removal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Word {
    /// The text; an expansion keeps its source spelling (`$X`, `$(…)`).
    pub text: String,
    /// Carries an expansion (`$X`, `${…}`, `$(…)`, backticks, `<(…)`): the runtime value is
    /// unknown.
    pub dynamic: bool,
    /// The shell may split or glob it into a different number of words (an unquoted
    /// expansion, `"$@"`, `*`, `?`, `[`, `{a,b}`).
    pub splits: bool,
    /// Spelled with quotes or escapes.
    pub quoted: bool,
}

/// One simple command: program word first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimpleCommand {
    /// The words, with assignments, reserved words and wrappers stripped.
    pub words: Vec<Word>,
    /// Reached in a way Claude Code's `if: Bash(solana *)` filter may not see: after a
    /// newline or `&`, inside a substitution, subshell or script, behind a wrapper, or through
    /// a quoted or path-qualified program word.
    pub indirect: bool,
    /// Redirects output to a file (other than `/dev/null` or a descriptor).
    pub writes_file: bool,
    /// A top-level command spelled exactly `solana …`, `spl-token …` or `anchor …` (unquoted,
    /// lowercase, nothing stripped): the shape Claude Code's `if` filters send to `gate-bash`.
    pub canonical: bool,
}

impl SimpleCommand {
    /// The program's base name, lowercased (`/usr/bin/Solana` → `solana`).
    pub fn program(&self) -> String {
        self.words
            .first()
            .map(|w| base_name(&w.text))
            .unwrap_or_default()
    }

    /// Whether the program is `solana`, `spl-token` or `anchor`.
    pub fn is_family(&self) -> bool {
        FAMILY.contains(&self.program().as_str())
    }
}

/// The parse of a whole command.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Parsed {
    /// Every simple command, in source order, recursion included.
    pub commands: Vec<SimpleCommand>,
    /// Quotes, substitutions or subshells do not balance, or nesting is too deep.
    pub unparseable: bool,
    /// Code runs whose text the command line does not spell out: a shell reading a pipe or a
    /// process substitution, `eval` of an expansion, interpreter code naming a solana-family
    /// program, a `source` of a process substitution.
    pub opaque: bool,
    /// Holds a command or process substitution.
    pub substitution: bool,
    /// Assigns a value naming a solana-family program (`X=solana`, `export X=…`, `for X in
    /// solana`): an expansion run as a program may be it.
    pub assigns_family: bool,
    /// Sets a variable the solana CLIs read their config through (`HOME`, `XDG_CONFIG_HOME`,
    /// `SOLANA_*`, `ANCHOR_*`), or sources a file that may.
    pub env_changed: bool,
    /// Changes directory (`cd`, `pushd`, `popd`, `env -C`) before a later command.
    pub cwd_changed: bool,
    /// An opaque input (see [`Parsed::opaque`]) whose text names a solana-family program: a
    /// solana command runs that the parser cannot read.
    pub opaque_mention: bool,
    /// Writes a file with emitted script text that runs a value-moving solana-family command
    /// (`echo 'solana transfer …' > x.sh`, `cat > x.sh <<EOF`, `printf 'solana …' | tee x.sh`).
    /// A command's output (`grep solana … > f`, `anchor build | tee log`) is not script text.
    pub writes_family_text: bool,
    /// After such a write, runs a file or standard input as code (`bash x.sh`, `cat x.sh |
    /// bash`, `sh < x.sh`, `python3 x.py`, `source x`, `./x`, `xargs … sh -c`).
    pub write_then_run: bool,
    /// The values of `NAME=value` prefix assignments, which [`SimpleCommand::words`] drops
    /// (`S=~/.ssh/id_ed25519; cat $S`): checked for credential paths.
    pub assigned_values: Vec<String>,
    /// Files whose contents a wrapper turns into the command's arguments (`xargs -a F`), which
    /// [`SimpleCommand::words`] drops: checked as reads.
    pub arg_files: Vec<String>,
    /// Interpreter code fed on standard input (`python3 - <<EOF`, `python3 <<< '…'`, `echo '…' |
    /// node`), which no word carries: checked for the files it names.
    pub stdin_code: Vec<String>,
    /// Input redirect targets (`< F`, `3< F`, `<> F`), which [`SimpleCommand::words`] drops:
    /// checked as reads.
    pub input_files: Vec<String>,
}

/// Record that a command runs a file or stdin as code: after a family write, that is a
/// solana command the gate cannot see.
fn executes(out: &mut Parsed) {
    out.write_then_run |= out.writes_family_text;
}

/// Mark `out` opaque because of code in `text` it cannot read.
fn opaque(out: &mut Parsed, text: &str) {
    out.opaque = true;
    out.opaque_mention |= mentions_family(text);
}

/// Parse `command` (see the module docs). Never panics.
pub fn parse(command: &str) -> Parsed {
    let mut out = Parsed::default();
    parse_into(command, 0, false, &mut out);
    out
}

/// Whether `text` names a solana-family program as code would: a word, or the last segment of
/// a path (`./solana`, `~/.local/…/bin/solana`, `/usr/bin/solana`), after removing quotes
/// (and, in a second reading, backslashes: `s\olana`), or holds ANSI-C quoting
/// (`$'\x73olana'`). `solana.exe` and `SOLANA` count; `solana-keygen`, `solana.so` and inner
/// path segments (`programs/anchor/x`) do not. Only text that runs is scanned: data
/// arguments of ordinary commands never are.
pub fn mentions_family(text: &str) -> bool {
    text.contains("$'") || readings(text).iter().any(|r| scan(r))
}

/// `text` lowercased with quotes removed: backslashes kept as separators (`C:\bin\solana`),
/// then also removed (`s\olana`).
fn readings(text: &str) -> [String; 2] {
    let unquoted: String = text
        .to_lowercase()
        .chars()
        .filter(|c| !matches!(c, '"' | '\''))
        .collect();
    let plain: String = unquoted.chars().filter(|&c| c != '\\').collect();
    [unquoted, plain]
}

/// Scan one reading for a program mention.
fn scan(text: &str) -> bool {
    // (word, counts as a program mention)
    let mut words: Vec<(&str, bool)> = Vec::new();
    let is_path_sep = |c: char| matches!(c, '/' | '\\');
    for token in text.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                ';' | '|'
                    | '&'
                    | '('
                    | ')'
                    | '<'
                    | '>'
                    | '='
                    | ','
                    | '['
                    | ']'
                    | '{'
                    | '}'
                    | '`'
                    | '$'
            )
    }) {
        // In a path, only the last segment can be the program (`./solana`, `~/…/bin/solana`,
        // `$HOME/…/solana`, `C:\bin\solana.exe`); `programs/anchor/x` names none.
        // An npm scope (`@coral-xyz/anchor`) names a package, never a program.
        let segments: Vec<&str> = token.split(is_path_sep).collect();
        let package = segments.iter().any(|s| s.starts_with('@'));
        let last = segments.len().saturating_sub(1);
        for (i, segment) in segments.iter().enumerate() {
            let program_position = i == last && !package;
            for word in segment.split(|c: char| !is_mention_char(c)) {
                if !word.is_empty() {
                    words.push((word, program_position));
                }
            }
        }
    }
    let is_mention = |w: &str| {
        let w = w.trim_end_matches('.');
        let w = w.strip_suffix(".exe").unwrap_or(w);
        FAMILY.contains(&w)
    };
    words
        .iter()
        .any(|&(word, program)| program && is_mention(word))
}

/// The base name of a program word, lowercased: path (`/` or `\`), a zsh `=` prefix and a
/// `.exe` suffix removed (`C:\bin\Solana.EXE` → `solana`).
pub fn base_name(word: &str) -> String {
    let name = word.rsplit(['/', '\\']).next().unwrap_or(word);
    let name = name.trim_start_matches('=').to_ascii_lowercase();
    match name.strip_suffix(".exe") {
        Some(stem) => stem.to_string(),
        None => name,
    }
}

/// Parse `script` into `out` at nesting `depth`; `indirect` marks every command found.
fn parse_into(script: &str, depth: usize, indirect: bool, out: &mut Parsed) {
    if depth > MAX_DEPTH {
        out.unparseable = true;
        return;
    }
    let mut lx = Lexer {
        chars: script.chars().collect(),
        i: 0,
        depth,
        line_writes: false,
        compound_seen: false,
        out,
    };
    lx.run(indirect);
}

/// A here-document waiting for its body.
struct Heredoc {
    delimiter: String,
    strip_tabs: bool,
    /// An unquoted delimiter: the body undergoes expansion (its substitutions run).
    expands: bool,
}

/// What a finished command reads from its standard input.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Reads {
    /// Nothing that runs as code.
    Data,
    /// An interpreter's code (`python3 -`).
    Interpreter,
    /// A shell script.
    Shell,
}

/// A simple command being collected.
#[derive(Default)]
struct Pending {
    words: Vec<Word>,
    herestrings: Vec<Word>,
    writes_file: bool,
    piped_in: bool,
    /// Follows `|` or `||`, which Claude Code's `if` filters are not known to split on.
    after_pipe: bool,
    /// The words of the earlier stages of its pipeline (what a shell reading the pipe runs).
    upstream: String,
    /// The text emitters upstream in its pipeline write to it (`printf '…' | tee x.sh`).
    upstream_emits: String,
}

struct Lexer<'p> {
    chars: Vec<char>,
    i: usize,
    depth: usize,
    /// A command on the current line writes a file (a here-document may be its content).
    line_writes: bool,
    /// A compound command (`for`, `case`, `while`, …) or a `case` pattern was seen at this
    /// level: later commands sit inside it, where the hook's `if` filters may not look.
    compound_seen: bool,
    out: &'p mut Parsed,
}

impl Lexer<'_> {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.i).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<char> {
        self.chars.get(self.i + offset).copied()
    }

    /// Lex the whole script.
    fn run(&mut self, indirect: bool) {
        let mut cmd = Pending::default();
        let mut heredocs: Vec<Heredoc> = Vec::new();
        // A newline or single `&` was seen at this level: later commands are indirect.
        let mut after_break = false;
        // What the current line's commands read from stdin (a here-document's consumer).
        let mut line_reads = Reads::Data;
        loop {
            self.skip_blanks();
            let Some(c) = self.peek() else {
                self.flush(&mut cmd, indirect || after_break, false);
                break;
            };
            match c {
                '#' if cmd_word_boundary(&self.chars, self.i) => self.skip_comment(),
                '\n' => {
                    self.i += 1;
                    line_reads =
                        line_reads.max(self.flush(&mut cmd, indirect || after_break, false));
                    for doc in heredocs.drain(..) {
                        let body = self.read_heredoc_body(&doc);
                        match line_reads {
                            Reads::Shell => parse_into(&body, self.depth + 1, true, self.out),
                            // Interpreter code the parser cannot read.
                            Reads::Interpreter => {
                                opaque(self.out, &body);
                                self.out.stdin_code.push(body);
                            }
                            Reads::Data => {
                                self.out.writes_family_text |=
                                    self.line_writes && script_runs_family(&body, self.depth);
                                if doc.expands {
                                    self.scan_expansions(&body);
                                }
                            }
                        }
                    }
                    line_reads = Reads::Data;
                    self.line_writes = false;
                    after_break = true;
                }
                ';' => {
                    self.i += 1;
                    if self.peek() == Some(';') {
                        self.i += 1;
                    }
                    line_reads =
                        line_reads.max(self.flush(&mut cmd, indirect || after_break, false));
                }
                '&' => match self.peek_at(1) {
                    Some('&') => {
                        self.i += 2;
                        line_reads =
                            line_reads.max(self.flush(&mut cmd, indirect || after_break, false));
                    }
                    Some('>') => {
                        self.i += 1;
                        self.redirection(&mut cmd, &mut heredocs);
                    }
                    _ => {
                        self.i += 1;
                        line_reads =
                            line_reads.max(self.flush(&mut cmd, indirect || after_break, false));
                        after_break = true;
                    }
                },
                '|' => {
                    self.i += 1;
                    let pipe = match self.peek() {
                        Some('|') => {
                            self.i += 1;
                            false
                        }
                        Some('&') => {
                            self.i += 1;
                            true
                        }
                        _ => true,
                    };
                    line_reads =
                        line_reads.max(self.flush(&mut cmd, indirect || after_break, pipe));
                    cmd.after_pipe = true;
                }
                '<' | '>' => self.redirection(&mut cmd, &mut heredocs),
                '(' if cmd.words.iter().all(|w| {
                    !w.quoted && (RESERVED.contains(&w.text.as_str()) || w.text == "time")
                }) =>
                {
                    self.i += 1;
                    if self.peek() == Some('(') {
                        // `(( … ))` arithmetic.
                        if self.matching_paren().is_none() {
                            self.out.unparseable = true;
                            return;
                        }
                        continue;
                    }
                    match self.matching_paren() {
                        Some(body) => parse_into(&body, self.depth + 1, true, self.out),
                        None => {
                            self.out.unparseable = true;
                            return;
                        }
                    }
                }
                ')' => {
                    // A `case` pattern or a stray paren ends the command.
                    self.i += 1;
                    self.compound_seen = true;
                    line_reads =
                        line_reads.max(self.flush(&mut cmd, indirect || after_break, false));
                }
                _ => {
                    let start = self.i;
                    let Some(word) = self.read_word() else {
                        self.out.unparseable = true;
                        return;
                    };
                    // `2>file`: an all-digit word glued to a redirection is a descriptor.
                    let glued = matches!(self.peek(), Some('<' | '>'))
                        && !word.quoted
                        && !word.text.is_empty()
                        && word.text.chars().all(|c| c.is_ascii_digit())
                        && self.i > start;
                    let lone_brace = word.text == "{" && !word.quoted && !word.splits;
                    if lone_brace && !cmd.words.is_empty() {
                        // `f() {`, `function f {`: the definition ends, its body begins.
                        line_reads =
                            line_reads.max(self.flush(&mut cmd, indirect || after_break, false));
                        cmd.words.push(word);
                    } else if !glued {
                        cmd.words.push(word);
                    }
                }
            }
        }
        if !heredocs.is_empty() {
            // Here-documents with no body line: bash runs them with an empty body.
            heredocs.clear();
        }
    }

    /// Finish the pending command, if any. Returns what it reads from stdin.
    fn flush(&mut self, cmd: &mut Pending, indirect: bool, pipe_next: bool) -> Reads {
        let pending = std::mem::take(cmd);
        cmd.piped_in = pipe_next;
        if pipe_next {
            let words: Vec<&str> = pending.words.iter().map(|w| w.text.as_str()).collect();
            cmd.upstream = format!("{} {}", pending.upstream, words.join(" "));
            cmd.upstream_emits = pipe_emits(&pending);
        }
        self.line_writes |= pending.writes_file || {
            // `tee x.sh <<EOF`: the here-document is the file's content.
            let skip = pending
                .words
                .iter()
                .take_while(|w| assignment_name(w).is_some())
                .count();
            match pending.words.get(skip..).unwrap_or_default() {
                [first, args @ ..] => tee_writes(&base_name(&first.text), args),
                [] => false,
            }
        };
        if pending.words.is_empty() {
            return Reads::Data;
        }
        let indirect = indirect || self.compound_seen;
        self.compound_seen |= pending.words.first().is_some_and(|w| {
            !w.quoted
                && matches!(
                    w.text.as_str(),
                    "for" | "select" | "while" | "until" | "if" | "case" | "function" | "repeat"
                )
        });
        finish_command(pending, indirect, self.depth, self.out)
    }

    /// Spaces, tabs and line continuations.
    fn skip_blanks(&mut self) {
        while let Some(c) = self.peek() {
            if c == ' ' || c == '\t' || c == '\r' {
                self.i += 1;
            } else if c == '\\' && self.peek_at(1) == Some('\n') {
                self.i += 2;
            } else {
                break;
            }
        }
    }

    fn skip_comment(&mut self) {
        while let Some(c) = self.peek() {
            if c == '\n' {
                break;
            }
            self.i += 1;
        }
    }

    /// Lex a redirection operator and its target at `self.i`.
    fn redirection(&mut self, cmd: &mut Pending, heredocs: &mut Vec<Heredoc>) {
        let first = self.peek().unwrap_or('>');
        self.i += 1;
        // Process substitution is an argument, not a redirection.
        if self.peek() == Some('(') {
            self.i += 1;
            match self.matching_paren() {
                Some(body) => {
                    self.out.substitution = true;
                    parse_into(&body, self.depth + 1, true, self.out);
                    cmd.words.push(Word {
                        text: format!("{first}({body})"),
                        dynamic: true,
                        ..Word::default()
                    });
                }
                None => self.out.unparseable = true,
            }
            return;
        }
        let mut heredoc = false;
        let mut herestring = false;
        let mut strip_tabs = false;
        let mut writes = first == '>';
        match (first, self.peek()) {
            ('<', Some('<')) => {
                self.i += 1;
                if self.peek() == Some('<') {
                    self.i += 1;
                    herestring = true;
                } else {
                    heredoc = true;
                    if self.peek() == Some('-') {
                        self.i += 1;
                        strip_tabs = true;
                    }
                }
            }
            ('<', Some('>')) => {
                self.i += 1;
                writes = true;
            }
            ('>', Some('>' | '|' | '&')) | ('<', Some('&')) => self.i += 1,
            _ => {}
        }
        self.skip_blanks();
        let target = match self.peek() {
            Some(c) if !is_metachar(c) => self.read_word(),
            _ => None,
        };
        let Some(target) = target else {
            self.out.unparseable = true;
            return;
        };
        if heredoc {
            heredocs.push(Heredoc {
                delimiter: target.text,
                strip_tabs,
                expands: !target.quoted,
            });
        } else if herestring {
            cmd.herestrings.push(target);
        } else {
            let descriptor = target.text == "-" || target.text.chars().all(|c| c.is_ascii_digit());
            if first == '<' && !descriptor {
                self.out.input_files.push(target.text.clone());
            }
            if writes && !is_harmless_target(&target.text) {
                cmd.writes_file = true;
            }
        }
    }

    /// Consume here-document body lines up to the delimiter line (or the end).
    fn read_heredoc_body(&mut self, doc: &Heredoc) -> String {
        let mut body = String::new();
        while self.i < self.chars.len() {
            let mut line = String::new();
            while let Some(c) = self.peek() {
                self.i += 1;
                if c == '\n' {
                    break;
                }
                line.push(c);
            }
            let check = if doc.strip_tabs {
                line.trim_start_matches('\t')
            } else {
                line.as_str()
            };
            if check == doc.delimiter {
                break;
            }
            body.push_str(&line);
            body.push('\n');
        }
        body
    }

    /// After an opening `(`: the text up to its matching `)`, which is consumed. Quotes,
    /// escapes, backticks and nested parens are skipped over. `None` when unbalanced.
    fn matching_paren(&mut self) -> Option<String> {
        let start = self.i;
        let mut depth = 1usize;
        while let Some(c) = self.peek() {
            match c {
                '\\' => self.i += 1,
                '\'' => {
                    self.i += 1;
                    while self.peek().is_some_and(|c| c != '\'') {
                        self.i += 1;
                    }
                    self.peek()?;
                }
                '"' => {
                    self.i += 1;
                    while let Some(c) = self.peek() {
                        if c == '\\' {
                            self.i += 1;
                        } else if c == '"' {
                            break;
                        }
                        self.i += 1;
                    }
                    self.peek()?;
                }
                '`' => {
                    self.i += 1;
                    while let Some(c) = self.peek() {
                        if c == '\\' {
                            self.i += 1;
                        } else if c == '`' {
                            break;
                        }
                        self.i += 1;
                    }
                    self.peek()?;
                }
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        let body: String = self.chars.get(start..self.i)?.iter().collect();
                        self.i += 1;
                        return Some(body);
                    }
                }
                _ => {}
            }
            self.i += 1;
        }
        None
    }

    /// After an opening backtick: the unescaped body up to the closing one, consumed.
    fn backtick_body(&mut self) -> Option<String> {
        let mut body = String::new();
        while let Some(c) = self.peek() {
            self.i += 1;
            match c {
                '`' => return Some(body),
                '\\' => {
                    let next = self.peek()?;
                    self.i += 1;
                    if !matches!(next, '`' | '\\' | '$') {
                        body.push('\\');
                    }
                    body.push(next);
                }
                _ => body.push(c),
            }
        }
        None
    }

    /// After an opening `{` of `${`: the body up to the matching `}`, consumed.
    fn brace_body(&mut self) -> Option<String> {
        let start = self.i;
        let mut depth = 1usize;
        while let Some(c) = self.peek() {
            match c {
                '\\' => self.i += 1,
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        let body: String = self.chars.get(start..self.i)?.iter().collect();
                        self.i += 1;
                        return Some(body);
                    }
                }
                _ => {}
            }
            self.i += 1;
        }
        None
    }

    /// Recurse into the substitutions of expandable text (a here-document body, a `${…}`).
    fn scan_expansions(&mut self, text: &str) {
        let mut inner = Lexer {
            chars: text.chars().collect(),
            i: 0,
            depth: self.depth,
            line_writes: false,
            compound_seen: false,
            out: &mut *self.out,
        };
        let mut sink = Word::default();
        while inner.peek().is_some() {
            if inner.dq_char(&mut sink, None).is_none() {
                inner.out.unparseable = true;
                return;
            }
        }
    }

    /// Read one word at `self.i`. `None` on an unterminated quote or substitution.
    fn read_word(&mut self) -> Option<Word> {
        let mut word = Word::default();
        while let Some(c) = self.peek() {
            match c {
                c if is_metachar(c) => {
                    // `f()`, `a=(1 2)`: a paren inside a command is part of its word.
                    if c == '(' {
                        self.i += 1;
                        let body = self.matching_paren()?;
                        word.text.push('(');
                        word.text.push_str(&body);
                        word.text.push(')');
                        if body.trim().is_empty() {
                            // `f()`: the definition's name ends here (`f(){` has its `{` next).
                            break;
                        }
                        continue;
                    }
                    break;
                }
                '\\' => {
                    self.i += 1;
                    match self.peek() {
                        Some('\n') => self.i += 1,
                        Some(next) => {
                            word.text.push(next);
                            word.quoted = true;
                            self.i += 1;
                        }
                        None => {}
                    }
                }
                '\'' => {
                    self.i += 1;
                    word.quoted = true;
                    loop {
                        let c = self.peek()?;
                        self.i += 1;
                        if c == '\'' {
                            break;
                        }
                        word.text.push(c);
                    }
                }
                '"' => {
                    self.i += 1;
                    word.quoted = true;
                    loop {
                        if self.peek()? == '"' {
                            self.i += 1;
                            break;
                        }
                        self.dq_char(&mut word, Some('"'))?;
                    }
                }
                '$' => self.dollar(&mut word, false)?,
                '`' => {
                    self.i += 1;
                    let body = self.backtick_body()?;
                    self.substitute(&body);
                    word.text.push('`');
                    word.text.push_str(&body);
                    word.text.push('`');
                    word.dynamic = true;
                    word.splits = true;
                }
                '*' | '?' | '[' => {
                    word.splits = true;
                    word.text.push(c);
                    self.i += 1;
                }
                '{' => {
                    // A lone `{` is a reserved word; inside a word it may brace-expand.
                    let lone = word.text.is_empty()
                        && self.peek_at(1).is_none_or(|n| is_metachar(n) || n == ' ');
                    if !lone {
                        word.splits = true;
                    }
                    word.text.push(c);
                    self.i += 1;
                }
                _ => {
                    word.text.push(c);
                    self.i += 1;
                }
            }
        }
        Some(word)
    }

    /// One unit of double-quoted (or expandable) text into `word`. `end` is the closing quote,
    /// if any. `None` on an unterminated construct.
    fn dq_char(&mut self, word: &mut Word, end: Option<char>) -> Option<()> {
        let c = self.peek()?;
        match c {
            '\\' => {
                self.i += 1;
                let next = self.peek()?;
                self.i += 1;
                if next == '\n' {
                    return Some(());
                }
                if !matches!(next, '$' | '`' | '\\') && Some(next) != end {
                    word.text.push('\\');
                }
                word.text.push(next);
            }
            '$' => self.dollar(word, true)?,
            '`' => {
                self.i += 1;
                let body = self.backtick_body()?;
                self.substitute(&body);
                word.text.push('`');
                word.text.push_str(&body);
                word.text.push('`');
                word.dynamic = true;
            }
            _ => {
                word.text.push(c);
                self.i += 1;
            }
        }
        Some(())
    }

    /// An expansion at `$` into `word`; `quoted` inside double quotes.
    fn dollar(&mut self, word: &mut Word, quoted: bool) -> Option<()> {
        self.i += 1;
        match self.peek() {
            Some('(') => {
                self.i += 1;
                if self.peek() == Some('(') {
                    // `$(( … ))` arithmetic: a number.
                    let body = self.matching_paren()?;
                    if self.peek() == Some(')') {
                        self.i += 1;
                    }
                    word.text.push_str(&format!("$({body})"));
                } else {
                    let body = self.matching_paren()?;
                    self.substitute(&body);
                    word.text.push_str(&format!("$({body})"));
                }
                word.dynamic = true;
                word.splits |= !quoted;
            }
            Some('{') => {
                self.i += 1;
                let body = self.brace_body()?;
                self.scan_expansions(&body);
                word.splits |= !quoted || body.starts_with('@') || body.contains("[@]");
                word.text.push_str(&format!("${{{body}}}"));
                word.dynamic = true;
            }
            Some('\'') if !quoted => {
                // ANSI-C quoting: decoded, so `$'\x73olana'` reads as `solana`.
                self.i += 1;
                word.quoted = true;
                word.text.push_str(&self.ansi_c_body()?);
            }
            Some('"') if !quoted => {
                // `$"…"` (locale translation) reads as `"…"`.
                word.quoted = true;
            }
            Some(c) if c.is_ascii_alphabetic() || c == '_' => {
                word.text.push('$');
                while let Some(c) = self
                    .peek()
                    .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                {
                    word.text.push(c);
                    self.i += 1;
                }
                word.dynamic = true;
                word.splits |= !quoted;
            }
            Some(c) if c.is_ascii_digit() || "@*#?$!-".contains(c) => {
                word.text.push('$');
                word.text.push(c);
                self.i += 1;
                word.dynamic = true;
                word.splits |= !quoted || c == '@';
            }
            _ => word.text.push('$'),
        }
        Some(())
    }

    /// After `$'`: the decoded body up to the closing quote, consumed.
    fn ansi_c_body(&mut self) -> Option<String> {
        let mut out = String::new();
        loop {
            let c = self.peek()?;
            self.i += 1;
            match c {
                '\'' => return Some(out),
                '\\' => {
                    let e = self.peek()?;
                    self.i += 1;
                    match e {
                        'n' => out.push('\n'),
                        't' => out.push('\t'),
                        'r' => out.push('\r'),
                        'a' => out.push('\u{7}'),
                        'b' => out.push('\u{8}'),
                        'e' | 'E' => out.push('\u{1b}'),
                        'f' => out.push('\u{c}'),
                        'v' => out.push('\u{b}'),
                        'x' => out.push(self.radix_char(16, 2)?),
                        'u' => out.push(self.radix_char(16, 4)?),
                        'U' => out.push(self.radix_char(16, 8)?),
                        '0'..='7' => {
                            self.i -= 1;
                            out.push(self.radix_char(8, 3)?);
                        }
                        other => out.push(other),
                    }
                }
                _ => out.push(c),
            }
        }
    }

    /// Up to `max` digits in `radix` as one char (`\x73`, `\163`).
    fn radix_char(&mut self, radix: u32, max: usize) -> Option<char> {
        let mut value: u32 = 0;
        let mut n = 0;
        while n < max {
            let Some(d) = self.peek().and_then(|c| c.to_digit(radix)) else {
                break;
            };
            value = value.checked_mul(radix)?.checked_add(d)?;
            self.i += 1;
            n += 1;
        }
        if n == 0 {
            return Some('\\');
        }
        Some(char::from_u32(value).unwrap_or('\u{fffd}'))
    }

    /// A command substitution body: its commands are parsed (indirect).
    fn substitute(&mut self, body: &str) {
        self.out.substitution = true;
        parse_into(body, self.depth + 1, true, self.out);
    }
}

/// Whether `c` ends an unquoted word.
fn is_metachar(c: char) -> bool {
    matches!(
        c,
        ' ' | '\t' | '\r' | '\n' | ';' | '&' | '|' | '<' | '>' | '(' | ')'
    )
}

/// Whether a `#` at `i` starts a comment (it begins a word).
fn cmd_word_boundary(chars: &[char], i: usize) -> bool {
    i == 0
        || chars
            .get(i.wrapping_sub(1))
            .is_some_and(|&c| is_metachar(c))
}

/// Redirection targets that write nothing: `/dev/null`, the std streams, descriptors.
fn is_harmless_target(target: &str) -> bool {
    matches!(target, "/dev/null" | "/dev/stdout" | "/dev/stderr" | "-")
        || (!target.is_empty() && target.chars().all(|c| c.is_ascii_digit()))
}

/// Whether `word` is a `NAME=value` / `NAME+=value` assignment.
fn assignment_name(word: &Word) -> Option<&str> {
    let (name, _) = word.text.split_once('=')?;
    let name = name.strip_suffix('+').unwrap_or(name);
    let mut chars = name.chars();
    let first = chars.next()?;
    let valid = (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    valid.then_some(name)
}

/// Whether assigning `name` changes where the solana CLIs find their config.
fn is_config_var(name: &str) -> bool {
    matches!(name, "HOME" | "XDG_CONFIG_HOME")
        || name.starts_with("SOLANA_")
        || name.starts_with("ANCHOR_")
}

/// The script text a pipeline stage hands the next one: an emitter's words or here-string, or
/// what a pass-through `tee`/`cat` received from its own upstream.
fn pipe_emits(pending: &Pending) -> String {
    let words: Vec<&Word> = pending
        .words
        .iter()
        .skip_while(|w| assignment_name(w).is_some())
        .collect();
    let Some(first) = words.first() else {
        return String::new();
    };
    let program = base_name(&first.text);
    let args: Vec<Word> = words.iter().skip(1).map(|w| (*w).clone()).collect();
    if let Some(text) = emitted_text(&program, &args, &pending.herestrings) {
        return text;
    }
    if matches!(program.as_str(), "tee" | "cat") && pending.piped_in {
        return pending.upstream_emits.clone();
    }
    String::new()
}

/// Strip, classify and record one simple command. Returns what it reads from its standard
/// input (so a here-document on its line is a script, interpreter code or data).
fn finish_command(pending: Pending, indirect: bool, depth: usize, out: &mut Parsed) -> Reads {
    let Pending {
        mut words,
        herestrings,
        writes_file,
        piped_in,
        after_pipe,
        upstream,
        upstream_emits,
    } = pending;
    let mut indirect = indirect || after_pipe;
    let canonical_head = words
        .first()
        .is_some_and(|w| !w.quoted && !w.dynamic && FAMILY.contains(&w.text.as_str()));

    loop {
        // Reserved words and `NAME=value` prefixes.
        let mut skip = 0;
        for word in &words {
            if !word.quoted && RESERVED.contains(&word.text.as_str()) {
                // Inside a group, function body, loop or conditional.
                indirect = true;
                skip += 1;
            } else if let Some(name) = assignment_name(word) {
                out.env_changed |= is_config_var(name);
                out.assigns_family |= mentions_family(&word.text[name.len()..]);
                if let Some((_, value)) = word.text.split_once('=') {
                    out.assigned_values.push(value.to_string());
                }
                skip += 1;
            } else {
                break;
            }
        }
        words.drain(..skip);
        let Some(first) = words.first() else {
            return Reads::Data;
        };
        let program = base_name(&first.text);
        if program == "command" && command_lookup(&words) {
            // `command -v solana` looks a program up; it runs nothing.
            return Reads::Data;
        }
        let Some(&(_, shorts, longs, positionals)) =
            WRAPPERS.iter().find(|(name, ..)| *name == program)
        else {
            break;
        };
        indirect = true;
        let skip = wrapper_len(&words, shorts, longs, positionals);
        if program == "env" {
            if let Some(split) = env_split_string(&words[..skip.min(words.len())]) {
                // `env -S 'solana …' …`: the string is split into the command's words.
                let rest: Vec<&str> = words.iter().skip(skip).map(|w| w.text.as_str()).collect();
                let script = format!("{split} {}", rest.join(" "));
                parse_into(&script, depth + 1, true, out);
                return Reads::Data;
            }
            out.cwd_changed |= words
                .iter()
                .take(skip)
                .any(|w| w.text.starts_with("-C") || w.text.starts_with("--chdir"));
        }
        let appends = program == "xargs";
        if appends {
            out.arg_files
                .extend(xargs_arg_files(&words[..skip.min(words.len())]));
        }
        words.drain(..skip.min(words.len()));
        if appends
            && words.first().is_some_and(|w| {
                let p = base_name(&w.text);
                SHELLS.contains(&p.as_str()) || is_interpreter(&p)
            })
        {
            // `xargs -a x.sh sh -c '{}'`: its input becomes code.
            executes(out);
            if piped_in && script_runs_family(&upstream_emits, depth) {
                out.opaque = true;
                out.opaque_mention = true;
            }
        }
        if appends && piped_in {
            // `echo .env | xargs cat`: the emitted words become arguments.
            words.extend(upstream_emits.split_whitespace().map(|t| Word {
                text: t.to_string(),
                ..Word::default()
            }));
        }
        if appends {
            // xargs appends arguments the command line does not show.
            words.push(Word {
                text: "$XARGS".to_string(),
                dynamic: true,
                splits: true,
                quoted: false,
            });
        }
        if words
            .first()
            .is_some_and(|w| w.dynamic && w.text == "$XARGS")
        {
            // `xargs` alone runs `echo`.
            return Reads::Data;
        }
    }

    let Some(first) = words.first() else {
        return Reads::Data;
    };
    let program = base_name(&first.text);
    if first.quoted || first.text != program {
        // A quoted, path-qualified, `=`-prefixed, `.exe` or non-lowercase program word.
        indirect = true;
    }
    let args = words.get(1..).unwrap_or_default();
    let mut reads = Reads::Data;
    if writes_file {
        if let Some(text) = emitted_text(&program, args, &herestrings) {
            out.writes_family_text |= script_runs_family(&text, depth);
        }
    }
    // `tee x.sh`, `dd of=x.sh`: they write what the pipe carries, script text only when an
    // emitter upstream wrote it.
    let writes_pipe = match program.as_str() {
        "tee" => tee_writes(&program, args),
        "dd" => args.iter().any(|w| w.text.starts_with("of=")),
        _ => false,
    };
    if writes_pipe && piped_in {
        out.writes_family_text |= script_runs_family(&upstream_emits, depth);
    }
    if writes_pipe && !herestrings.is_empty() {
        // `tee x.sh <<< 'solana …'`: the here-string is the file's content.
        if let Some(text) = emitted_text(&program, args, &herestrings) {
            out.writes_family_text |= script_runs_family(&text, depth);
        }
    }
    let family_program = FAMILY.contains(&program.as_str());
    if !family_program && (first.text.contains('/') || program.ends_with(".sh")) {
        // `./x`, `../x.sh`, `/tmp/x`: a file run as a program.
        executes(out);
    }

    // `uv run python …`, `npx tsx …`: the interpreter behind a project runner.
    let (program, args) = match interpreter_at(&words).and_then(|i| words.get(i..)) {
        Some([inner, rest @ ..]) if !std::ptr::eq(inner, first) => (base_name(&inner.text), rest),
        _ => (program, args),
    };
    match program.as_str() {
        "cd" | "pushd" | "popd" => out.cwd_changed = true,
        "export" | "declare" | "typeset" | "local" | "readonly" => {
            out.env_changed |= args.iter().filter_map(assignment_name).any(is_config_var);
            out.assigns_family |= args
                .iter()
                .filter_map(|w| w.text.split_once('=').map(|(_, v)| v))
                .any(mentions_family);
        }
        "for" | "select" => {
            let text: Vec<&str> = args.iter().map(|w| w.text.as_str()).collect();
            out.assigns_family |= mentions_family(&text.join(" "));
        }
        "source" | "." => {
            out.env_changed = true;
            executes(out);
            for word in args.iter().filter(|w| w.dynamic) {
                opaque(out, &word.text);
            }
        }
        "eval" => {
            if args.iter().any(|w| w.dynamic) {
                let text: Vec<&str> = args.iter().map(|w| w.text.as_str()).collect();
                opaque(out, &text.join(" "));
            } else {
                let script: Vec<&str> = args.iter().map(|w| w.text.as_str()).collect();
                parse_into(&script.join(" "), depth + 1, true, out);
            }
        }
        p if SHELLS.contains(&p) => {
            let args = if p == "busybox" {
                // `busybox sh -c …`
                match args.first().map(|w| base_name(&w.text)) {
                    Some(sh) if SHELLS.contains(&sh.as_str()) => args.get(1..).unwrap_or_default(),
                    _ => args,
                }
            } else {
                args
            };
            match shell_script(args) {
                ShellInput::Script(script) if script.dynamic => opaque(out, &script.text),
                ShellInput::Script(script) => parse_into(&script.text, depth + 1, true, out),
                ShellInput::File(file) if is_stdin_path(&file.text) => {
                    reads = Reads::Shell;
                    executes(out);
                    if piped_in {
                        opaque(out, &upstream);
                    }
                }
                ShellInput::File(file) => {
                    executes(out);
                    if file.dynamic {
                        opaque(out, &file.text);
                    }
                }
                ShellInput::Stdin => {
                    reads = Reads::Shell;
                    executes(out);
                    if piped_in {
                        opaque(out, &upstream);
                    }
                }
            }
            for here in &herestrings {
                if here.dynamic {
                    opaque(out, &here.text);
                } else {
                    parse_into(&here.text, depth + 1, true, out);
                }
            }
        }
        p if is_interpreter(p) => {
            // `deno run -`, `deno eval CODE`: the subcommand is not the script.
            let deno_eval = p == "deno" && args.first().is_some_and(|w| w.text == "eval");
            let args = match args.first() {
                Some(w) if p == "deno" && matches!(w.text.as_str(), "run" | "eval") => {
                    args.get(1..).unwrap_or_default()
                }
                _ => args,
            };
            let code_flag = |w: &Word| matches!(w.text.as_str(), "-c" | "-e" | "-E" | "--eval");
            let runs_code = deno_eval || args.iter().any(code_flag) || !herestrings.is_empty();
            let code: Vec<&str> = args
                .iter()
                .chain(herestrings.iter())
                .map(|w| w.text.as_str())
                .collect();
            // Code piped in is invisible; so is `-c`/`-e` code (it matters when it names a
            // solana-family program).
            if piped_in {
                opaque(out, &upstream);
                if !upstream_emits.is_empty() {
                    out.stdin_code.push(upstream_emits.clone());
                }
            }
            out.stdin_code
                .extend(herestrings.iter().map(|w| w.text.clone()));
            if runs_code {
                opaque(out, &code.join(" "));
            }
            if !deno_eval && !args.iter().any(code_flag) {
                // A script file or stdin: either way it runs code.
                executes(out);
                if interpreter_reads_stdin(args) {
                    reads = Reads::Interpreter;
                }
            }
        }
        p if LAUNCHERS.contains(&p) => launch(args, p, depth, out),
        _ => {}
    }

    let indirect = indirect || depth > 0;
    out.commands.push(SimpleCommand {
        words,
        indirect,
        writes_file,
        canonical: canonical_head && !indirect,
    });
    reads
}

/// Whether `command …` only looks a program up: `-v`/`-V` before the first non-option word.
fn command_lookup(words: &[Word]) -> bool {
    for word in words.iter().skip(1) {
        let text = word.text.as_str();
        if text == "--" || !text.starts_with('-') {
            return false;
        }
        if text.contains('v') || text.contains('V') {
            return true;
        }
    }
    false
}

/// Whether a script-file argument means standard input.
fn is_stdin_path(text: &str) -> bool {
    matches!(text, "-" | "/dev/stdin" | "/dev/fd/0" | "/proc/self/fd/0")
}

/// Whether an interpreter without `-c`/`-e` code reads its program from stdin: no script
/// argument, or `-` / `/dev/stdin`.
fn interpreter_reads_stdin(args: &[Word]) -> bool {
    match args
        .iter()
        .find(|w| !w.text.starts_with('-') || w.text == "-")
    {
        None => true,
        Some(word) => is_stdin_path(&word.text),
    }
}

/// What a shell invocation runs.
enum ShellInput<'w> {
    /// The `-c` script.
    Script(&'w Word),
    /// A script file (or process substitution).
    File(&'w Word),
    /// Its standard input.
    Stdin,
}

/// Find a shell's input among its arguments: `-c SCRIPT` (also in a cluster: `-lc`, `-ec`),
/// else the first non-option word, else stdin.
fn shell_script(args: &[Word]) -> ShellInput<'_> {
    let mut wants_script = false;
    let mut i = 0;
    while let Some(word) = args.get(i) {
        i += 1;
        let text = word.text.as_str();
        if text == "--" {
            break;
        }
        if text.starts_with('-') || text.starts_with('+') {
            if !text.starts_with("--") && text.contains('c') {
                wants_script = true;
            }
            if matches!(text, "-o" | "+o" | "-O" | "+O" | "--rcfile" | "--init-file") {
                i += 1;
            }
            continue;
        }
        return if wants_script {
            ShellInput::Script(word)
        } else {
            ShellInput::File(word)
        };
    }
    match args.get(i) {
        Some(word) if wants_script => ShellInput::Script(word),
        Some(word) => ShellInput::File(word),
        None => ShellInput::Stdin,
    }
}

/// The value of `env -S`/`--split-string`, if given.
fn env_split_string(words: &[Word]) -> Option<String> {
    let mut iter = words.iter().skip(1);
    while let Some(word) = iter.next() {
        let text = word.text.as_str();
        if let Some(v) = text.strip_prefix("--split-string=") {
            return Some(v.to_string());
        }
        if text == "-S" || text == "--split-string" {
            return iter.next().map(|w| w.text.clone());
        }
        if let Some(v) = text.strip_prefix("-S") {
            return Some(v.to_string());
        }
    }
    None
}

/// Whether `text` spells xargs's `--arg-file` as getopt accepts it: any prefix from `--arg`.
fn is_xargs_arg_file(text: &str) -> bool {
    text.len() >= "--arg".len() && "--arg-file".starts_with(text)
}

/// The `-a F`, `-aF`, `--arg-file F` and `--arg-file=F` values (long form abbreviated down to
/// `--arg`) among `xargs`'s own words.
fn xargs_arg_files(words: &[Word]) -> Vec<String> {
    let mut out = Vec::new();
    let mut iter = words.iter().skip(1).map(|w| w.text.as_str());
    while let Some(text) = iter.next() {
        if let Some((flag, value)) = text.split_once('=') {
            if is_xargs_arg_file(flag) {
                out.push(value.to_string());
            }
        } else if is_xargs_arg_file(text) {
            out.extend(iter.next().map(str::to_string));
        } else if let Some(cluster) = text.strip_prefix('-').filter(|c| !c.starts_with('-')) {
            // A short cluster: the first value-taking short consumes the rest or the next word.
            if let Some(pos) = cluster.find(|c| "ILnPsdEa".contains(c)) {
                let (_, rest) = cluster.split_at(pos);
                let mut chars = rest.chars();
                let short = chars.next();
                let value = match chars.as_str() {
                    "" => iter.next().unwrap_or_default(),
                    v => v,
                };
                if short == Some('a') && !value.is_empty() {
                    out.push(value.to_string());
                }
            }
        }
    }
    out
}

/// Words a wrapper takes before its command (its own name included).
fn wrapper_len(words: &[Word], shorts: &str, longs: &[&str], positionals: usize) -> usize {
    let mut i = 1;
    while let Some(word) = words.get(i) {
        let text = word.text.as_str();
        if text == "--" {
            i += 1;
            break;
        }
        if assignment_name(word).is_some() {
            // `env FOO=1 cmd`: left for the assignment pass.
            break;
        }
        if !text.starts_with('-') || text == "-" {
            break;
        }
        i += 1;
        if text.starts_with("--") {
            let xargs_file = longs.contains(&"--arg-file") && is_xargs_arg_file(text);
            if !text.contains('=') && (longs.contains(&text) || xargs_file) {
                i += 1;
            }
            continue;
        }
        // A short cluster: the first value-taking short consumes the rest or the next word.
        let cluster = text.get(1..).unwrap_or_default();
        if let Some(pos) = cluster.find(|c| shorts.contains(c)) {
            if pos + 1 == cluster.len() {
                i += 1;
            }
        }
    }
    i.saturating_add(positionals)
}

/// A launcher's command: from the first solana-family word on (to `;` or `+` for `find`).
fn launch(args: &[Word], program: &str, depth: usize, out: &mut Parsed) {
    if matches!(program, "su" | "runuser") {
        // `su -c 'cmd'`: a script.
        if let Some(pos) = args
            .iter()
            .position(|w| w.text == "-c" || w.text == "--command")
        {
            if let Some(script) = args.get(pos + 1) {
                if script.dynamic {
                    opaque(out, &script.text);
                } else {
                    parse_into(&script.text, depth + 1, true, out);
                }
            }
        }
        return;
    }
    if program == "ssh" {
        // The remote command is the words after the host, joined by the remote shell.
        let text: Vec<&str> = args.iter().map(|w| w.text.as_str()).collect();
        opaque(out, &text.join(" "));
        return;
    }
    // A literal argument holding a command line (`watch 'solana …'`, `tmux new 'solana …'`,
    // `nix-shell --run '…'`, `parallel ::: '…'`) is run by a shell: parse it as a script.
    for word in args {
        if word.text.contains([' ', '\t', '\n', ';']) {
            if word.dynamic {
                opaque(out, &word.text);
            } else {
                parse_into(&word.text, depth + 1, true, out);
            }
        }
    }
    let Some(start) = args
        .iter()
        .position(|w| FAMILY.contains(&base_name(&w.text).as_str()) || shell_word(w))
    else {
        return;
    };
    let mut words: Vec<Word> = args
        .iter()
        .skip(start)
        .take_while(|w| !(program == "find" && matches!(w.text.as_str(), ";" | "+")))
        .cloned()
        .collect();
    if words.first().is_some_and(shell_word) {
        let script = words
            .iter()
            .map(|w| shell_quote(&w.text))
            .collect::<Vec<_>>()
            .join(" ");
        parse_into(&script, depth + 1, true, out);
        return;
    }
    // Launchers substitute arguments (`{}`, `:::`): what follows is unknowable.
    words.push(Word {
        text: "$LAUNCHER".to_string(),
        dynamic: true,
        splits: true,
        quoted: false,
    });
    out.commands.push(SimpleCommand {
        words,
        indirect: true,
        writes_file: false,
        canonical: false,
    });
}

/// Whether `word` names a shell.
fn shell_word(word: &Word) -> bool {
    SHELLS.contains(&base_name(&word.text).as_str())
}

/// Single-quote `text` for re-parsing.
fn shell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The texts of each simple command.
    fn cmds(command: &str) -> Vec<Vec<String>> {
        parse(command)
            .commands
            .iter()
            .map(|c| c.words.iter().map(|w| w.text.clone()).collect())
            .collect()
    }

    fn family(command: &str) -> Vec<(Vec<String>, bool)> {
        parse(command)
            .commands
            .iter()
            .filter(|c| c.is_family())
            .map(|c| (c.words.iter().map(|w| w.text.clone()).collect(), c.indirect))
            .collect()
    }

    fn v(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    #[test]
    fn splits_on_every_separator() {
        assert_eq!(
            cmds("a 1; b 2 && c || d | e & f\ng |& h"),
            vec![
                v(&["a", "1"]),
                v(&["b", "2"]),
                v(&["c"]),
                v(&["d"]),
                v(&["e"]),
                v(&["f"]),
                v(&["g"]),
                v(&["h"]),
            ]
        );
    }

    #[test]
    fn separators_inside_quotes_do_not_split() {
        assert_eq!(
            cmds(r#"solana transfer --with-memo "a;b && c|d" X 1"#),
            vec![v(&[
                "solana",
                "transfer",
                "--with-memo",
                "a;b && c|d",
                "X",
                "1"
            ])]
        );
        assert_eq!(cmds("echo 'x\ny'"), vec![v(&["echo", "x\ny"])]);
    }

    #[test]
    fn empty_quoted_words_are_kept() {
        assert_eq!(cmds(r#"a "" ''"#), vec![v(&["a", "", ""])]);
    }

    #[test]
    fn quote_removal_concatenates() {
        assert_eq!(
            cmds(r#"sol"an"a s\pl-token 'anc'hor"#)[0],
            v(&["solana", "spl-token", "anchor"])
        );
        assert_eq!(cmds(r"$'\x73olana' x")[0], v(&["solana", "x"]));
    }

    #[test]
    fn prefixes_and_wrappers_are_stripped() {
        for command in [
            "FOO=1 solana transfer X 1",
            "env FOO=1 solana transfer X 1",
            "env -i -u HOME solana transfer X 1",
            "sudo -u root -E solana transfer X 1",
            "nohup solana transfer X 1",
            "time -p solana transfer X 1",
            "command solana transfer X 1",
            "exec -a name solana transfer X 1",
            "nice -n 5 timeout -s KILL 10 solana transfer X 1",
            "! solana transfer X 1",
            "if solana transfer X 1; then echo; fi",
        ] {
            let found = family(command);
            assert_eq!(found.len(), 1, "{command}: {found:?}");
            assert_eq!(
                found[0].0,
                v(&["solana", "transfer", "X", "1"]),
                "{command}"
            );
        }
        // An assignment prefix alone stays direct; a wrapper is indirect.
        assert!(!family("FOO=1 solana transfer X 1")[0].1);
        assert!(family("sudo solana transfer X 1")[0].1);
    }

    #[test]
    fn command_v_runs_nothing() {
        assert!(family("command -v solana").is_empty());
    }

    #[test]
    fn recursion_into_scripts_and_substitutions() {
        for command in [
            "bash -c 'solana transfer X 1'",
            "sh -lc \"solana transfer X 1\"",
            "zsh -c 'cd x && solana transfer X 1'",
            "echo $(solana transfer X 1)",
            "echo \"$(solana transfer X 1)\"",
            "echo `solana transfer X 1`",
            "cat <(solana transfer X 1)",
            "(cd x && solana transfer X 1)",
            "eval 'solana transfer X 1'",
            "echo hi\nsolana transfer X 1",
            "bash <<< 'solana transfer X 1'",
            "bash <<EOF\nsolana transfer X 1\nEOF",
            "f() { solana transfer X 1; }; f",
            "x=${Y:-$(solana transfer X 1)}",
            "busybox sh -c 'solana transfer X 1'",
            "su -c 'solana transfer X 1' root",
        ] {
            let found = family(command);
            assert!(
                found
                    .iter()
                    .any(|(w, indirect)| *w == v(&["solana", "transfer", "X", "1"]) && *indirect),
                "{command}: {found:?}"
            );
        }
    }

    #[test]
    fn launchers_run_their_solana_argument_with_unknown_args() {
        let found = family("find . -name '*.so' -exec solana program deploy {} \\;");
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].0[..3], v(&["solana", "program", "deploy"])[..]);
        let p = parse("cat list | xargs solana transfer");
        let cmd = p.commands.iter().find(|c| c.is_family()).unwrap();
        assert!(cmd.words.last().unwrap().splits);
    }

    #[test]
    fn opaque_shapes() {
        for command in [
            "echo 'solana transfer X 1' | bash",
            "eval \"$CMD\"",
            "bash <<< \"$S\"",
            "bash -c \"$S\"",
            "python3 -c \"import os; os.system('solana transfer X 1')\"",
            "source <(curl x)",
            "ssh host solana transfer X 1",
        ] {
            assert!(parse(command).opaque, "{command}");
        }
        for command in ["bash run.sh", "echo hi | grep h"] {
            assert!(!parse(command).opaque, "{command}");
        }
    }

    #[test]
    fn unbalanced_input_is_unparseable() {
        for command in [
            "echo \"solana",
            "echo 'solana",
            "echo $(solana",
            "echo `solana",
            "(solana transfer",
            "solana transfer X 1 >",
        ] {
            assert!(parse(command).unparseable, "{command}");
        }
        let deep = (0..12).fold("solana".to_string(), |s, _| {
            format!("bash -c {}", shell_quote(&s))
        });
        assert!(parse(&deep).unparseable);
    }

    #[test]
    fn redirections_are_dropped_and_file_writes_noted() {
        let p = parse("solana transfer X 1 2>&1 >/dev/null");
        assert_eq!(p.commands[0].words.len(), 4);
        assert!(!p.commands[0].writes_file);
        let p = parse("solana transfer X 1 > out.log");
        assert_eq!(p.commands[0].words.len(), 4);
        assert!(p.commands[0].writes_file);
        // `1>f` redirects: the `1` is a descriptor, not the amount.
        let p = parse("solana transfer X 1>f");
        assert_eq!(
            cmds("solana transfer X 1>f")[0],
            v(&["solana", "transfer", "X"])
        );
        assert!(p.commands[0].writes_file);
        assert_eq!(cmds("solana transfer X 1 &>/dev/null")[0].len(), 4);
    }

    #[test]
    fn expansions_are_marked() {
        let p = parse(r#"solana transfer $D "$Q" '$L' * {1,500} "$@""#);
        let w = &p.commands[0].words;
        assert!(w[2].dynamic && w[2].splits);
        assert!(w[3].dynamic && !w[3].splits);
        assert!(!w[4].dynamic && !w[4].splits);
        assert!(w[5].splits);
        assert!(w[6].splits);
        assert!(w[7].splits);
    }

    #[test]
    fn comments_are_skipped() {
        assert_eq!(
            cmds("solana balance # solana transfer X 1"),
            vec![v(&["solana", "balance"])]
        );
        assert_eq!(cmds("echo a#b"), vec![v(&["echo", "a#b"])]);
    }

    #[test]
    fn config_changes_are_noted() {
        assert!(parse("export HOME=/x; solana transfer X 1").env_changed);
        assert!(parse("HOME=/x solana transfer X 1").env_changed);
        assert!(parse("source .env && anchor deploy").env_changed);
        assert!(!parse("FOO=1 solana transfer X 1").env_changed);
        assert!(parse("cd other && anchor deploy").cwd_changed);
        assert!(parse("env -C other anchor deploy").cwd_changed);
    }

    #[test]
    fn command_v_only_before_the_program() {
        assert!(family("command -v solana").is_empty());
        assert!(family("command -pv solana").is_empty());
        assert_eq!(family("command solana transfer X 1 -v").len(), 1);
        assert_eq!(family("command -p solana -v").len(), 1);
    }

    #[test]
    fn function_brace_lexes_separately() {
        let found = family("f(){ solana \"$@\"; }; f transfer X 1");
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].0[0], "solana");
        assert!(found[0].1);
    }

    #[test]
    fn heredoc_to_stdin_paths_is_a_script() {
        for command in [
            "bash /dev/stdin <<EOF\nsolana transfer X 1\nEOF",
            "sh - <<EOF\nsolana transfer X 1\nEOF",
            "bash /dev/fd/0 <<EOF\nsolana transfer X 1\nEOF",
        ] {
            assert_eq!(family(command).len(), 1, "{command}");
        }
        assert!(parse("python3 - <<'EOF'\nprint(1)\nEOF").opaque);
        assert!(parse("node <<EOF\nx\nEOF").opaque);
        assert!(!parse("python3 run.py <<EOF\nx\nEOF").opaque);
    }

    #[test]
    fn base_name_normalizes_program_words() {
        assert_eq!(base_name("/usr/bin/solana"), "solana");
        assert_eq!(base_name(r"C:\bin\Solana.EXE"), "solana");
        assert_eq!(base_name("=solana"), "solana");
        assert_eq!(base_name("SPL-TOKEN"), "spl-token");
    }

    #[test]
    fn only_the_exact_lowercase_program_is_canonical() {
        let canon = |c: &str| {
            parse(c)
                .commands
                .iter()
                .map(|c| c.canonical)
                .collect::<Vec<_>>()
        };
        assert_eq!(canon("solana transfer X 1"), vec![true]);
        for command in [
            "SOLANA transfer X 1",
            "Solana transfer X 1",
            "solana.exe transfer X 1",
            "=solana transfer X 1",
            "/usr/bin/solana transfer X 1",
            "'solana' transfer X 1",
            "FOO=1 solana transfer X 1",
            "noglob solana transfer X 1",
        ] {
            assert_eq!(canon(command), vec![false], "{command}");
            // An assignment prefix alone stays direct for gate-bash; it is still not canonical.
            let prefixed = command.starts_with("FOO=");
            assert_eq!(parse(command).commands[0].indirect, !prefixed, "{command}");
        }
    }

    #[test]
    fn zsh_modifiers_and_new_launchers() {
        for command in [
            "noglob solana transfer X 1",
            "nocorrect solana transfer X 1",
            "repeat 3 solana transfer X 1",
            "arch -arm64 solana transfer X 1",
            "sandbox-exec -n x solana transfer X 1",
            "pkexec solana transfer X 1",
            "fakeroot solana transfer X 1",
            "chpst -u me solana transfer X 1",
            "watch -n 1 'solana transfer X 1'",
            "tmux new -d 'solana transfer X 1'",
            "nix-shell --run 'solana transfer X 1'",
            "case a in a) solana transfer X 1;; esac",
            "function f { solana transfer X 1; }",
        ] {
            assert!(!family(command).is_empty(), "{command}");
        }
    }

    #[test]
    fn mentions_use_word_boundaries_and_last_path_segments() {
        for text in [
            "x | /usr/bin/solana balance",
            "SOLANA.EXE balance",
            r"C:\bin\solana.exe balance",
            "./solana $X",
            "../bin/solana $A",
            "~/.local/share/solana/install/active_release/bin/solana $X",
            "$HOME/.local/share/solana/install/active_release/bin/solana $X",
            "os.system('./solana ' + a)",
        ] {
            assert!(mentions_family(text), "{text}");
        }
        for text in [
            "solana-keygen new",
            "cp target/deploy/solana_program.so x",
            "cargo add anchor-lang",
            "vim programs/anchor/tests/run.rs",
            "cat $HOME/.config/solana/cli/config.yml",
            "require('@coral-xyz/anchor')",
        ] {
            assert!(!mentions_family(text), "{text}");
        }
    }

    #[test]
    fn gated_words_match_on_segments() {
        for word in [
            "transfer",
            "withdraw-from-vote-account",
            "set-buffer-authority",
            "approve",
            "revoke",
            "wrap",
            "unwrap",
            "split-stake",
            "merge-stake",
            "deactivate-stake",
            "redelegate-stake",
            "close-vote-account",
            "create-account",
            "close-mint",
            "write-buffer",
            "x.transfer",
        ] {
            assert!(is_gated_word(word), "{word}");
        }
        for word in [
            "balance", "config", "test", "run", "build", "program", "get",
        ] {
            assert!(!is_gated_word(word), "{word}");
        }
    }

    #[test]
    fn executed_strings_naming_solana_are_opaque_mentions() {
        for command in [
            "bash -c \"solana $X\"",
            "eval \"$CMD solana\"",
            "printf 'solana %s' \"$A\" | sh",
            "python3 -c \"import os; os.system('solana ' + x)\"",
            "python3 - <<'EOF'\nimport os; os.system('solana transfer')\nEOF",
        ] {
            assert!(parse(command).opaque_mention, "{command}");
        }
        for command in [
            "eval \"$CMD\"",
            "python3 -c 'print(1)'",
            "echo hi | sh",
            "node -e \"require('@coral-xyz/anchor')\"",
        ] {
            assert!(!parse(command).opaque_mention, "{command}");
        }
    }

    #[test]
    fn scripts_written_then_run_are_noted() {
        for command in [
            "echo 'solana transfer -um X 1' > x.sh; bash x.sh",
            "cat > x.sh <<EOF\nsolana transfer X 1\nEOF\nchmod +x x.sh && ./x.sh",
            "echo 'solana transfer -um X 1' > x.sh; cat x.sh | bash",
            "echo 'solana transfer -um X 1' > x.sh; sh < x.sh",
            "printf 'solana transfer X 1' | tee x.sh >/dev/null; bash x.sh",
            "echo \"import os; os.system('solana transfer X 1')\" > x.py && python3 x.py",
            "echo './solana transfer X 1' > x; source x",
        ] {
            assert!(parse(command).write_then_run, "{command}");
        }
        assert!(!parse("echo 'solana balance' > notes.txt").write_then_run);
        // An unknown subcommand counts like at top level (where it asks); read-only ones don't.
        assert!(parse("echo 'solana pay D 1' > x.sh; bash x.sh").write_then_run);
        assert!(parse("echo 'spl-token frobnicate' > x.sh; bash x.sh").write_then_run);
        assert!(!parse("echo 'solana balance' > x.sh; bash x.sh").write_then_run);
        assert!(!parse("echo 'solana config get' > x.sh; bash x.sh").write_then_run);
        // The run must come after the write.
        assert!(!parse("bash x.sh; echo 'solana transfer' > x.sh").write_then_run);
    }

    #[test]
    fn only_emitted_scripts_count_as_written() {
        for command in [
            "echo 'solana transfer X 1' >> x.sh && zsh x.sh",
            "echo 'solana transfer X 1' > x.sh; chmod +x x.sh; x.sh",
            "echo 'solana transfer X 1' > x.sh; . ./x.sh",
            "cat <<< 'solana transfer X 1' > x.sh; bash x.sh",
            "printf 'cd a\\nsolana transfer X 1' > x.sh; bash x.sh",
            "printf 'solana transfer X 1' | tee a | tee x.sh; bash x.sh",
            "echo \"subprocess.run(['solana', 'transfer', 'X', '1'])\" > x.py; python3 x.py",
            "echo 'solana transfer X 1' > x.sh; xargs -a x.sh -I{} sh -c '{}'",
            "printf '\\x73olana transfer X 1' > x.sh; bash x.sh",
            "printf '%*s\\n' 0 'solana transfer X 1' > x.sh; bash x.sh",
        ] {
            assert!(parse(command).write_then_run, "{command}");
        }
        for command in [
            "anchor build 2>&1 | tee build.log && ./scripts/post-build.sh",
            "grep solana Cargo.toml > deps.txt && ./scripts/check.sh",
            "cargo tree | grep solana > tree.txt; python3 analyze.py tree.txt",
            "ls ~/.config/solana > out.txt; ./bin/report",
            "echo \"anchor build failed\" > notes.md; ./scripts/ci.sh",
            "echo 'see solana transfer docs' > notes.md; ./scripts/ci.sh",
        ] {
            assert!(!parse(command).write_then_run, "{command}");
        }
    }

    #[test]
    fn printf_formats_take_their_arguments() {
        assert_eq!(
            printf_text(&["%s", "solana transfer X 1"]),
            "solana transfer X 1"
        );
        assert_eq!(
            printf_text(&["%s ", "solana", "transfer", "X"]),
            "solana transfer X "
        );
        assert_eq!(
            printf_text(&["solana %s -um %5d", "transfer", "1"]),
            "solana transfer -um 1"
        );
        assert_eq!(printf_text(&["-v", "v", "--", "100%% %b", "x"]), "100% x");
        // `*` takes its width from the next argument.
        assert_eq!(
            printf_text(&["%*s\\n", "0", "solana transfer X 1"]),
            "solana transfer X 1\n"
        );
        assert_eq!(printf_text(&["%.3s", "solana"]), "solana");
        // Hex and octal escapes are decoded.
        assert_eq!(printf_text(&["\\x73olana transfer"]), "solana transfer");
        assert_eq!(printf_text(&["\\163olana"]), "solana");
        assert_eq!(printf_text(&["%b", "\\0163olana"]), "solana");
        assert_eq!(printf_text(&["plain", "ignored"]), "plain");
    }

    #[test]
    fn expansions_that_could_spell_a_family_program() {
        for word in [
            "$(echo sol)ana",
            "${S}olana",
            "$(printf %s ./solana)",
            "$SOLANA_BIN",
        ] {
            assert!(could_spell_family(word), "{word}");
        }
        for word in [
            "$EDITOR",
            "$CARGO",
            "\"$PYTHON\"",
            "${CC:-cc}",
            "$GIT",
            "$X",
        ] {
            assert!(!could_spell_family(word), "{word}");
        }
        assert!(parse("X=solana; $X $Y").assigns_family);
        assert!(parse("for p in solana; do $p transfer; done").assigns_family);
        assert!(!parse("X=1; $X $Y").assigns_family);
    }

    #[test]
    fn mentions_family_sees_through_quotes() {
        assert!(mentions_family("sol\"\"ana transfer"));
        assert!(mentions_family("S\\PL-token transfer"));
        assert!(mentions_family("$'\\x73olana'"));
        assert!(!mentions_family("ls -la"));
    }

    #[test]
    fn xargs_inputs_and_stdin_code_are_kept() {
        assert_eq!(parse("xargs -a .env echo").arg_files, [".env"]);
        assert_eq!(parse("xargs -0a.env echo").arg_files, [".env"]);
        assert_eq!(parse("xargs --arg-file=f -n 1 echo").arg_files, ["f"]);
        assert_eq!(parse("xargs -n 1 -a f echo").arg_files, ["f"]);
        assert!(parse("xargs -n 1 echo").arg_files.is_empty());
        let piped = parse("echo .env | xargs cat");
        let words: Vec<&str> = piped.commands[1]
            .words
            .iter()
            .map(|w| w.text.as_str())
            .collect();
        assert_eq!(words, ["cat", ".env", "$XARGS"]);
        assert_eq!(parse("python3 <<< 'open(1)'").stdin_code, ["open(1)"]);
        assert_eq!(parse("echo 'open(1)' | node").stdin_code, ["open(1)"]);
        assert_eq!(
            parse("python3 - <<'EOF'\nopen(1)\nEOF").stdin_code,
            ["open(1)\n"]
        );
        assert!(parse("cat <<< 'open(1)'").stdin_code.is_empty());
    }
}
