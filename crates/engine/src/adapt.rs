//! Hook adapters for clients other than Claude Code (experimental, issue #23).
//!
//! `safe-ai-skill adapt codex <gate>` runs one PreToolUse gate on a Codex CLI hook payload.
//! Codex sends Claude-shaped PreToolUse JSON (`tool_name` `Bash` with `tool_input.command`,
//! MCP tools as `mcp__<server>__<tool>`), so the gates read it unchanged. What differs:
//!
//! - **Output.** Codex PreToolUse honours only `deny`. An `ask` or a bare `allow` is an
//!   "unsupported" output that Codex logs and then runs the call anyway, so [`render`] turns
//!   every `ask` into a `deny` (adding [`CODEX_ASK_SUFFIX`]) and an `allow` into no output.
//! - **File edits.** Codex edits files through `apply_patch`: the tool (patch text in
//!   `tool_input.command`) or an `apply_patch` command in the shell, which Codex intercepts.
//!   [`patch_paths`] / [`patch_paths_in_command`] list the files a patch touches.
//! - **What guards the guard.** Nothing in Codex protects Claude Code's settings, the Codex
//!   hook config or the `safe-ai-skill` binary on `PATH`, so [`CodexTargets`] names them and
//!   [`patch_target_reason`] / [`bash_reason`] deny writes to them.
//! - **Unknown working dir.** Codex's `exec_command` may run in a `workdir` the payload does
//!   not carry, so a relative write naming a safe-ai-skill state file or a wallet is denied
//!   wherever it would land.
//!
//! The client is a process-wide setting chosen once by the `adapt` subcommand before the gate
//! runs; every emitter consults it through [`current`].

use std::collections::HashSet;
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

/// Whether this process answers Codex.
pub fn is_codex() -> bool {
    current() == Client::Codex
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

/// The most files one patch may touch under Codex; a bigger patch is denied unread.
pub const MAX_PATCH_PATHS: usize = 1000;

/// Translate a decision for `client`: under Codex an `ask` becomes a `deny` (same reason, minus
/// any "approve to proceed" tail, plus [`CODEX_ASK_SUFFIX`]) and an `allow` becomes no opinion,
/// since Codex runs the call on both.
pub fn render(decision: &Decision, client: Client) -> Decision {
    match (client, decision) {
        (Client::Codex, Decision::Ask { reason }) => {
            let base = reason
                .trim_end()
                .trim_end_matches("— approve to proceed")
                .trim_end_matches(|c: char| c.is_whitespace() || c == '.' || c == '—');
            Decision::Deny {
                reason: format!("{base}. {CODEX_ASK_SUFFIX}"),
            }
        }
        (Client::Codex, Decision::Allow) => Decision::Defer,
        _ => decision.clone(),
    }
}

/// The file paths an `apply_patch` patch adds, updates, deletes or moves to, in order, without
/// duplicates. Lines are matched after trimming, so an indented or CRLF patch still parses.
pub fn patch_paths(patch: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut paths = Vec::new();
    collect_patch_paths(patch, &mut seen, &mut paths);
    paths
}

/// [`patch_paths`] for a shell command that may run `apply_patch` (heredoc, quoted argument,
/// `$'…\n…'`, piped): the text is also read with `\n` escapes as newlines, and a path a closing
/// quote is glued to is listed with and without it.
pub fn patch_paths_in_command(command: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut paths = Vec::new();
    collect_patch_paths(command, &mut seen, &mut paths);
    if command.contains("\\n") {
        collect_patch_paths(&command.replace("\\n", "\n"), &mut seen, &mut paths);
    }
    paths
}

fn collect_patch_paths(text: &str, seen: &mut HashSet<String>, paths: &mut Vec<String>) {
    const MARKERS: [&str; 4] = [
        "*** Add File:",
        "*** Update File:",
        "*** Delete File:",
        "*** Move to:",
    ];
    for line in text.lines() {
        let line = line.trim().trim_start_matches(['\'', '"']);
        let Some(path) = MARKERS
            .iter()
            .find_map(|m| line.strip_prefix(m))
            .map(str::trim)
            .filter(|p| !p.is_empty())
        else {
            continue;
        };
        let unquoted = path.trim_end_matches(['\'', '"', ')', ';']).trim_end();
        for p in [path, unquoted] {
            if !p.is_empty() && seen.insert(p.to_string()) {
                paths.push(p.to_string());
            }
        }
    }
}

/// safe-ai-skill state file names (and the default wallet's) that a relative write is denied
/// on under Codex, where the command's working dir is unknown.
const RELATIVE_STATE_NAMES: &[&str] = &[
    "grants.json",
    "grants.lock",
    "mode.json",
    "tier.json",
    "tier.lock",
    "spend.json",
    "lockfile.json",
    "netcache.json",
    "audit.jsonl",
    "trust.json",
    "pending.json",
    "pending.lock",
    "sessions.json",
    "generations.json",
    "migrated.json",
    "id.json",
];

/// Names of the binaries a Codex hook runs.
const ENGINE_NAMES: [&str; 2] = ["safe-ai-skill", "safe-ai-skill-codex"];

/// Locations nothing in Codex protects, which a Codex session must not write.
#[derive(Debug, Clone, Default)]
pub struct CodexTargets {
    home: Option<PathBuf>,
    /// Codex config dirs: `<home>/.codex`, `$CODEX_HOME` (as given and canonical).
    codex_homes: Vec<PathBuf>,
    /// Claude Code config dirs: `<home>/.claude`, `$CLAUDE_CONFIG_DIR`.
    claude_dirs: Vec<PathBuf>,
    /// The engine and wrapper: this executable, its siblings by [`ENGINE_NAMES`], and each
    /// name found on `PATH` (as given and canonical).
    engines: Vec<PathBuf>,
}

impl CodexTargets {
    /// Read `HOME`, `CODEX_HOME`, `CLAUDE_CONFIG_DIR`, `PATH` and the current executable.
    pub fn from_env() -> Self {
        let var = |k: &str| {
            std::env::var_os(k)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        };
        let home = var("HOME").filter(|h| h.is_absolute());
        let mut t = CodexTargets {
            home: home.clone(),
            ..CodexTargets::default()
        };
        if let Some(h) = &home {
            t.push_codex_home(h.join(".codex"));
            t.push_claude_dir(h.join(".claude"));
        }
        if let Some(c) = var("CODEX_HOME").filter(|c| c.is_absolute()) {
            t.push_codex_home(c);
        }
        if let Some(c) = var("CLAUDE_CONFIG_DIR").filter(|c| c.is_absolute()) {
            t.push_claude_dir(c);
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                for name in ENGINE_NAMES {
                    t.push_engine(dir.join(name));
                }
            }
            t.push_engine(exe);
        }
        if let Some(path) = std::env::var_os("PATH") {
            for dir in std::env::split_paths(&path).filter(|d| d.is_absolute()) {
                for name in ENGINE_NAMES {
                    let candidate = dir.join(name);
                    if crate::localfs::exists(&candidate) {
                        t.push_engine(candidate);
                    }
                }
            }
        }
        t
    }

    /// The files the shell scan protects (with their ancestors): the engines; `hooks.json` and
    /// `config.toml` in each Codex home; the Claude settings in each Claude dir; and, where
    /// they exist, `.codex/` config and `.claude/` settings in `cwd` and every directory above.
    pub fn files(&self, cwd: &Path) -> Vec<PathBuf> {
        let mut files: Vec<PathBuf> = self.engines.clone();
        for home in &self.codex_homes {
            files.extend(["hooks.json", "config.toml"].map(|f| home.join(f)));
        }
        for dir in &self.claude_dirs {
            files.extend(["settings.json", "settings.local.json"].map(|f| dir.join(f)));
        }
        for dir in lexical(cwd).ancestors() {
            for rel in [
                ".codex/hooks.json",
                ".codex/config.toml",
                ".claude/settings.json",
                ".claude/settings.local.json",
            ] {
                let file = dir.join(rel);
                if crate::localfs::exists(&file) && !files.contains(&file) {
                    files.push(file);
                }
            }
        }
        files
    }

    fn push_codex_home(&mut self, dir: PathBuf) {
        push_spellings(&mut self.codex_homes, dir);
    }

    fn push_claude_dir(&mut self, dir: PathBuf) {
        push_spellings(&mut self.claude_dirs, dir);
    }

    fn push_engine(&mut self, file: PathBuf) {
        push_spellings(&mut self.engines, file);
    }
}

fn push_spellings(list: &mut Vec<PathBuf>, path: PathBuf) {
    let lexical = lexical(&path);
    let canonical = canonical_prefix(&lexical);
    for p in [lexical, canonical] {
        if !list.contains(&p) {
            list.push(p);
        }
    }
}

/// `path` resolved against `cwd` (`~/` expanded with `home`), lexically normalised.
fn absolute(path: &str, cwd: &Path, home: Option<&Path>) -> PathBuf {
    let expanded = match (path.strip_prefix("~/"), home) {
        (Some(rest), Some(home)) => home.join(rest),
        _ if path == "~" => home.map(Path::to_path_buf).unwrap_or_default(),
        _ => PathBuf::from(path),
    };
    let full = if expanded.is_absolute() {
        expanded
    } else {
        cwd.join(expanded)
    };
    lexical(&full)
}

/// Drop `.` and resolve `..` without touching the filesystem.
fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// `path` with its longest existing ancestor canonicalised (symlinks resolved), the rest
/// appended; `path` itself when nothing resolves.
fn canonical_prefix(path: &Path) -> PathBuf {
    let mut rest: Vec<&std::ffi::OsStr> = Vec::new();
    let mut cur = path;
    loop {
        if let Ok(canon) = crate::localfs::canonicalize(cur) {
            let mut out = canon;
            for part in rest.iter().rev() {
                out.push(part);
            }
            return out;
        }
        match (cur.parent(), cur.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name);
                cur = parent;
            }
            _ => return path.to_path_buf(),
        }
    }
}

fn lower_components(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_string_lossy().to_ascii_lowercase()),
            _ => None,
        })
        .collect()
}

fn same_path(a: &Path, b: &Path) -> bool {
    lower_components(a) == lower_components(b)
}

/// Why a Codex session may not write `target` (a patch path or a shell word), or `None`.
///
/// Denied: Codex hook config (`.codex/hooks.json|config.toml`, `$CODEX_HOME/…`, through
/// symlinks), Claude Code settings (`.claude/settings.json|settings.local.json`, the user's
/// and `$CLAUDE_CONFIG_DIR`'s), the `safe-ai-skill` binary and wrapper, and, for a relative
/// path, a safe-ai-skill state file or wallet name (the working dir may not be `cwd`).
pub fn patch_target_reason(target: &str, cwd: &Path, targets: &CodexTargets) -> Option<String> {
    let lexical = absolute(target, cwd, targets.home.as_deref());
    let canonical = canonical_prefix(&lexical);
    for full in [&lexical, &canonical] {
        let comps = lower_components(full);
        let (dir, file) = match comps.as_slice() {
            [.., dir, file] => (dir.as_str(), file.as_str()),
            _ => continue,
        };
        let parent = full.parent().unwrap_or(full);
        let codex_file = file == "hooks.json" || file == "config.toml";
        if codex_file
            && (dir == ".codex" || targets.codex_homes.iter().any(|h| same_path(h, parent)))
        {
            return Some(format!(
                "safe-ai-skill: `{target}` is Codex hook config, which runs safe-ai-skill's \
                 gates; edit it yourself, outside the agent."
            ));
        }
        let settings = file == "settings.json" || file == "settings.local.json";
        if settings
            && (dir == ".claude" || targets.claude_dirs.iter().any(|d| same_path(d, parent)))
        {
            return Some(format!(
                "safe-ai-skill: `{target}` is Claude Code settings; a Codex session may not \
                 change them. Edit it yourself, outside the agent."
            ));
        }
        if targets.engines.iter().any(|e| same_path(e, full)) {
            return Some(format!(
                "safe-ai-skill: `{target}` is the safe-ai-skill binary the Codex hooks run; \
                 replacing or deleting it would turn the gates off."
            ));
        }
    }
    let relative = !target.starts_with('/') && !target.starts_with('~');
    let name = target
        .rsplit('/')
        .next()
        .unwrap_or(target)
        .to_ascii_lowercase();
    if relative && RELATIVE_STATE_NAMES.contains(&name.as_str()) {
        return Some(format!(
            "safe-ai-skill: `{target}` names a safe-ai-skill state file or a wallet, and a \
             Codex command's working dir is not known to the hook; write it yourself."
        ));
    }
    None
}

/// Commands that only read their arguments.
const READ_ONLY: &[&str] = &[
    "cat",
    "less",
    "more",
    "head",
    "tail",
    "ls",
    "stat",
    "file",
    "wc",
    "grep",
    "rg",
    "jq",
    "diff",
    "cmp",
    "sha256sum",
    "shasum",
    "md5",
    "md5sum",
    "which",
    "type",
    "command",
    "readlink",
    "realpath",
    "test",
    "[",
    "echo",
    "printf",
    "true",
    "basename",
    "dirname",
];

/// Commands that write, move or remove their arguments.
const MUTATORS: &[&str] = &[
    "rm",
    "mv",
    "cp",
    "ln",
    "chmod",
    "chown",
    "truncate",
    "install",
    "unlink",
    "dd",
    "tee",
    "sed",
    "perl",
    "shred",
    "touch",
    "rsync",
    "patch",
    "apply_patch",
    "applypatch",
    "python",
    "python3",
    "node",
    "ruby",
    "curl",
    "wget",
];

/// Wrappers skipped when finding the command a segment runs.
const PREFIXES: &[&str] = &["sudo", "env", "exec", "nohup", "nice", "time", "builtin"];

#[derive(Debug, PartialEq)]
enum Tok {
    Word(String),
    /// A segment break (`;`, `|`, `&`, `(`, `)`, newline); `true` for a pipe (`|`, `|&`).
    Break(bool),
    /// An output redirection (`>`, `>>`, `>|`).
    Out,
    /// An input redirection, here-document or here-string (`<`, `<<`, `<<<`).
    In,
}

/// A rough shell tokenizer: quotes are removed (their content stays in the word), segment
/// breaks and output redirections are kept.
fn tokenize(command: &str) -> Vec<Tok> {
    let mut toks = Vec::new();
    let mut word = String::new();
    let mut quote: Option<char> = None;
    let flush = |word: &mut String, toks: &mut Vec<Tok>| {
        if !word.is_empty() {
            toks.push(Tok::Word(std::mem::take(word)));
        }
    };
    let mut chars = command.chars().peekable();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => word.push(c),
            (None, '\'' | '"') => quote = Some(c),
            (None, '\\') => {
                if let Some(next) = chars.next() {
                    word.push(next);
                }
            }
            (None, '|') => {
                flush(&mut word, &mut toks);
                let pipe = chars.peek() != Some(&'|');
                if !pipe {
                    chars.next();
                }
                toks.push(Tok::Break(pipe));
            }
            (None, ';' | '&' | '(' | ')' | '\n' | '`') => {
                flush(&mut word, &mut toks);
                toks.push(Tok::Break(false));
            }
            (None, '<') => {
                if word.chars().all(|d| d.is_ascii_digit()) {
                    word.clear();
                }
                flush(&mut word, &mut toks);
                while chars.peek() == Some(&'<') {
                    chars.next();
                }
                toks.push(Tok::In);
            }
            (None, '>') => {
                // `2>` / `&>` keep their fd prefix out of the next word.
                if word.chars().all(|d| d.is_ascii_digit()) {
                    word.clear();
                }
                flush(&mut word, &mut toks);
                while matches!(chars.peek(), Some('>' | '|')) {
                    chars.next();
                }
                toks.push(Tok::Out);
            }
            (None, c) if c.is_whitespace() => flush(&mut word, &mut toks),
            (None, c) => word.push(c),
        }
    }
    flush(&mut word, &mut toks);
    toks
}

/// Why a Codex shell command may not run, judged on what it writes: a [`patch_target_reason`]
/// target named as an output redirection, or as an argument of a command that is not
/// read-only (bare names only for [`MUTATORS`]), or the binary by name for a mutator.
///
/// Deletes, moves and overwrites of a protected file or a directory holding it, globs, `cd`,
/// `find -delete|-exec`, `chmod` and work-tree-rewriting `git` go through the wallet gate's
/// scanner ([`crate::gates::wallet::clobber_of`]) over [`CodexTargets::files`]. Literal paths
/// inside interpreter code (`python3 -c "os.remove('…')"`) are checked word by word.
pub fn bash_reason(command: &str, cwd: &Path, targets: &CodexTargets) -> Option<String> {
    if let Some(what) = crate::gates::wallet::clobber_of(command, cwd, &targets.files(cwd)) {
        return Some(format!(
            "safe-ai-skill: {what}, which the Codex hooks need (the safe-ai-skill binary or \
             wrapper, Codex hook config, or Claude Code settings); do it yourself, outside the \
             agent."
        ));
    }
    bash_reason_depth(command, cwd, targets, 0)
}

/// The path-like pieces of interpreter code: split on quotes, brackets, separators and
/// whitespace.
fn code_paths(code: &str) -> impl Iterator<Item = &str> {
    code.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                '\'' | '"' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';' | '=' | '`'
            )
    })
    .filter(|piece| path_like(piece))
}

/// Whether a word or code piece may be a path: it holds a separator (`\` too on Windows,
/// where code spells `C:\\…`) or starts with `~`.
fn path_like(piece: &str) -> bool {
    piece.contains('/') || piece.starts_with('~') || (cfg!(windows) && piece.contains('\\'))
}

fn bash_reason_depth(
    command: &str,
    cwd: &Path,
    targets: &CodexTargets,
    depth: usize,
) -> Option<String> {
    let toks = tokenize(command);
    let mut leader: Option<String> = None;
    let mut after_out = false;
    let mut after_code_flag = false;
    for tok in &toks {
        let word = match tok {
            Tok::Break(_) => {
                leader = None;
                after_out = false;
                continue;
            }
            Tok::Out => {
                after_out = true;
                continue;
            }
            Tok::In => continue,
            Tok::Word(w) => w,
        };
        let code = std::mem::replace(
            &mut after_code_flag,
            matches!(word.as_str(), "-c" | "-e" | "-E" | "--eval" | "-r"),
        );
        // A quoted script (`sh -c '…'`) is scanned as a command of its own, and literal paths
        // in interpreter code are checked whatever command they sit in.
        if code || word.contains(char::is_whitespace) {
            if depth < 2 {
                if let Some(reason) = bash_reason_depth(word, cwd, targets, depth + 1) {
                    return Some(reason);
                }
            }
            if let Some(reason) =
                code_paths(word).find_map(|p| patch_target_reason(p, cwd, targets))
            {
                return Some(reason);
            }
        }
        if depth > 0 && path_like(word) {
            if let Some(reason) = patch_target_reason(word, cwd, targets) {
                return Some(reason);
            }
        }
        if after_out {
            after_out = false;
            if let Some(reason) = patch_target_reason(word, cwd, targets) {
                return Some(reason);
            }
            continue;
        }
        let Some(cmd) = leader.as_deref() else {
            let base = word.rsplit('/').next().unwrap_or(word);
            let is_assignment = word.contains('=') && !word.starts_with('=');
            if !is_assignment && !PREFIXES.contains(&base) {
                leader = Some(base.to_string());
            }
            continue;
        };
        if word.starts_with('-') || word.starts_with('@') || READ_ONLY.contains(&cmd) {
            continue;
        }
        let mutator = MUTATORS.contains(&cmd);
        let path_like = word.contains('/') || word.starts_with('~');
        let name = word.rsplit('/').next().unwrap_or(word);
        if mutator && (name == "hooks.json" || name == "config.toml") && !path_like {
            return Some(format!(
                "safe-ai-skill: `{word}` may be Codex hook config (a Codex command's working dir \
                 is not known to the hook); change it yourself, outside the agent."
            ));
        }
        if mutator && ENGINE_NAMES.contains(&name) {
            return Some(format!(
                "safe-ai-skill: `{word}` names the safe-ai-skill binary the Codex hooks run; \
                 changing it would turn the gates off."
            ));
        }
        if path_like || mutator {
            if let Some(reason) = patch_target_reason(word, cwd, targets) {
                return Some(reason);
            }
        }
    }
    None
}

/// Shells: with no `-c` script, no script file and no redirected or piped input, they read
/// commands from a terminal the model can type into.
const SHELLS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "tcsh", "csh", "busybox",
];

/// Interpreters with a REPL: no `-c`/`-e` code, no `-m` module and no script means a prompt.
const REPLS: &[&str] = &[
    "python", "python2", "python3", "node", "nodejs", "ruby", "perl", "php", "lua", "luajit",
    "irb", "pry", "ghci", "julia", "tclsh", "R", "deno", "bun",
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

/// Why a Codex shell command may not run because it opens an interactive shell or REPL, or
/// `None`. Codex's `write_stdin` feeds such a session input without running any hook, so every
/// gate would be skipped for what is typed into it.
pub fn interactive_reason(command: &str) -> Option<String> {
    interactive_depth(command, 0)
}

fn interactive_depth(command: &str, depth: usize) -> Option<String> {
    let toks = tokenize(command);
    let mut segment: Vec<&str> = Vec::new();
    let mut piped = false;
    let mut input = false;
    let mut next_piped = false;
    let mut iter = toks.iter().peekable();
    loop {
        let tok = iter.next();
        match tok {
            Some(Tok::Word(w)) => {
                segment.push(w);
                continue;
            }
            Some(Tok::In) => {
                input = true;
                continue;
            }
            Some(Tok::Out) => {
                // The redirection target is not an argument.
                if let Some(Tok::Word(_)) = iter.peek() {
                    iter.next();
                }
                continue;
            }
            Some(Tok::Break(pipe)) => next_piped = *pipe,
            None => {}
        }
        if let Some(reason) = interactive_segment(&segment, piped, input, depth) {
            return Some(reason);
        }
        segment.clear();
        input = false;
        piped = next_piped;
        next_piped = false;
        tok?;
    }
}

fn interactive_segment(words: &[&str], piped: bool, input: bool, depth: usize) -> Option<String> {
    let mut rest = words.iter().copied().skip_while(|w| {
        let base = w.rsplit('/').next().unwrap_or(w);
        (w.contains('=') && !w.starts_with('=')) || PREFIXES.contains(&base)
    });
    let program_word = rest.next()?;
    let program = program_word.rsplit('/').next().unwrap_or(program_word);
    let args: Vec<&str> = rest.collect();
    let flag = |pred: &dyn Fn(&str) -> bool| args.iter().any(|a| a.starts_with('-') && pred(a));
    let positional = args.iter().any(|a| !a.starts_with('-'));
    let forced = flag(&|a| a == "-i" || a == "--interactive");
    let fed = piped || input;
    let deny = || {
        Some(format!(
            "safe-ai-skill: `{program}` would start an interactive session; Codex feeds it input \
             through write_stdin without running any hook, so nothing typed into it would be \
             checked. Run it with the commands as arguments (`-c`, a script file), or yourself."
        ))
    };
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
        return ((!positional && !fed) || forced).then(deny).flatten();
    }
    if REPLS.contains(&program) {
        if matches!(program, "deno" | "bun") {
            let first = args.iter().find(|a| !a.starts_with('-'));
            return (first.is_none() && !fed || first == Some(&"repl"))
                .then(deny)
                .flatten();
        }
        let code = flag(&|a| {
            matches!(
                a,
                "-c" | "-e" | "-E" | "--eval" | "-m" | "-r" | "-p" | "--print"
            )
        });
        return ((!code && !positional && !fed) || forced)
            .then(deny)
            .flatten();
    }
    if DB_SHELLS.contains(&program) {
        let command = flag(&|a| {
            matches!(a, "-c" | "-f" | "-e" | "--eval" | "--execute" | "--file")
                || a.starts_with("--command")
                || a.starts_with("--file=")
                || a.starts_with("--execute=")
        });
        let sql_arg =
            program == "sqlite3" && args.iter().filter(|a| !a.starts_with('-')).count() > 1;
        let redis_cmd = program == "redis-cli" && positional;
        return (!command && !sql_arg && !redis_cmd && !fed)
            .then(deny)
            .flatten();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn targets() -> CodexTargets {
        let mut t = CodexTargets {
            home: Some(PathBuf::from("/home/u")),
            ..CodexTargets::default()
        };
        t.push_codex_home(PathBuf::from("/home/u/.codex"));
        t.push_codex_home(PathBuf::from("/opt/cx"));
        t.push_claude_dir(PathBuf::from("/home/u/.claude"));
        t.push_engine(PathBuf::from("/home/u/.local/bin/safe-ai-skill"));
        t.push_engine(PathBuf::from("/home/u/.local/bin/safe-ai-skill-codex"));
        t
    }

    #[test]
    fn codex_ask_becomes_deny_and_allow_becomes_no_output() {
        let ask = Decision::Ask {
            reason: "MAINNET DEPLOY — approve to proceed".into(),
        };
        match render(&ask, Client::Codex) {
            Decision::Deny { reason } => {
                assert_eq!(reason, format!("MAINNET DEPLOY. {CODEX_ASK_SUFFIX}"));
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
    fn patch_paths_in_shell_commands() {
        let heredoc = "apply_patch <<'EOF'\n*** Begin Patch\n*** Add File: ~/.config/solana/id.json\n+[]\n*** End Patch\nEOF";
        assert_eq!(
            patch_paths_in_command(heredoc),
            ["~/.config/solana/id.json"]
        );
        let escaped =
            r"apply_patch $'*** Begin Patch\n*** Delete File: .codex/hooks.json\n*** End Patch'";
        assert!(patch_paths_in_command(escaped).contains(&".codex/hooks.json".to_string()));
        let quoted = "apply_patch \"*** Begin Patch\n*** Delete File: tier.json\"";
        assert!(patch_paths_in_command(quoted).contains(&"tier.json".to_string()));
    }

    #[test]
    fn protected_targets_are_recognized() {
        let cwd = Path::new("/w/proj");
        let t = targets();
        for p in [
            ".codex/hooks.json",
            ".codex/config.toml",
            "sub/../.codex/hooks.json",
            "/w/proj/.CODEX/Hooks.json",
            "~/.codex/hooks.json",
            "/opt/cx/hooks.json",
            ".claude/settings.json",
            ".claude/settings.local.json",
            "~/.claude/settings.json",
            "/home/u/.local/bin/safe-ai-skill",
            "~/.local/bin/safe-ai-skill-codex",
            "tier.json",
            "sub/grants.json",
            "id.json",
        ] {
            assert!(patch_target_reason(p, cwd, &t).is_some(), "{p}");
        }
        for p in [
            ".codex/notes.md",
            "codex/hooks.json",
            "hooks.json",
            "/",
            "src/settings.json",
            "/w/proj/tier.json.md",
            "bin/safe-ai-skill",
        ] {
            assert!(patch_target_reason(p, cwd, &t).is_none(), "{p}");
        }
    }

    #[test]
    fn bash_writes_to_protected_targets_are_denied() {
        let cwd = Path::new("/w/proj");
        let t = targets();
        for c in [
            "rm tier.json",
            "cd /data && rm -f grants.json",
            "echo {} > .codex/hooks.json",
            "cat x >> ~/.codex/config.toml",
            "cp evil ~/.local/bin/safe-ai-skill",
            "cd ~/.local/bin && rm safe-ai-skill",
            "sh -c 'rm -f ~/.codex/hooks.json'",
            "sudo mv a /opt/cx/hooks.json",
            "printf x | tee .claude/settings.local.json",
            "FOO=1 truncate -s0 id.json",
        ] {
            assert!(bash_reason(c, cwd, &t).is_some(), "{c}");
        }
        for c in [
            "cat .codex/hooks.json",
            "ls ~/.local/bin/safe-ai-skill",
            "which safe-ai-skill",
            "safe-ai-skill status",
            "git commit -m 'update safe-ai-skill docs'",
            "npx @stbr/safe-ai-skill add skill x",
            "grep tier.json README.md",
            "echo hello > out.txt",
            "cargo build",
        ] {
            assert!(bash_reason(c, cwd, &t).is_none(), "{c}");
        }
    }

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
    fn literal_paths_in_interpreter_code_are_checked() {
        let cwd = Path::new("/w/proj");
        let t = targets();
        for c in [
            "python3 -c \"import os;os.remove(os.path.expanduser('~/.local/bin/safe-ai-skill'))\"",
            "node -e \"require('fs').unlinkSync('/home/u/.codex/hooks.json')\"",
            "perl -e 'unlink(\"/home/u/.claude/settings.json\")'",
        ] {
            assert!(bash_reason(c, cwd, &t).is_some(), "{c}");
        }
        assert!(bash_reason("python3 -c 'print(1)'", cwd, &t).is_none());
    }

    #[test]
    fn symlinked_codex_home_is_resolved() {
        let base = std::env::temp_dir().join(format!("adapt-symlink-{}", std::process::id()));
        let real = base.join("real-codex");
        std::fs::create_dir_all(&real).unwrap();
        let link = base.join("cx");
        let _ = std::fs::remove_file(&link);
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let mut t = targets();
        t.push_codex_home(real.clone());
        #[cfg(unix)]
        assert!(patch_target_reason("cx/hooks.json", &base, &t).is_some());
        let _ = std::fs::remove_dir_all(&base);
    }
}
