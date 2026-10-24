//! Default-wallet destruction (D8 v2 spec §3.1; owned by F3): `solana-keygen new|recover` with
//! `--force/-f` and no `-o` (and no `--no-outfile`) or an outfile naming `~/.config/solana/id.json`
//! or the CLI config's `keypair_path`; Bash `rm|mv|cp|tee|dd of=|>` onto that file, and
//! `rm`/`mv` of a directory holding it; Write/Edit/NotebookEdit to it. Denied on every cluster
//! at every tier, headless or not; no grant, repo or env relaxes it.
//!
//! The keygen verbs come from the shared list's `irreversible any` rows
//! ([`crate::lists::irreversible`]). The protected files are `~/.config/solana/id.json` under
//! `$HOME` and under the account's passwd home (a repo-set `HOME` cannot move the real one out
//! of reach), and the `keypair_path` of `$HOME/.config/solana/cli/config.yml`. Paths compare
//! lexically (case-insensitively: macOS volumes usually are) and, when the file exists, by
//! its canonical path, so a symlink onto the wallet counts. An unquoted glob is matched
//! against the protected paths (and, for a delete or move, their ancestors). A relative path
//! is resolved against the payload cwd and every directory an earlier `cd`/`pushd` in the
//! command line names; after a directory change the gate cannot place, a relative name equal
//! to a protected file's (or, for a delete or move, an ancestor's) name counts.
//!
//! Call lines: `main::cmd_gate_bash` and `main::cmd_gate_bash_secrets` ([`decide_bash`]) and
//! `main::cmd_gate_tamper` ([`decide_file`]).

use std::io::Read;
use std::path::{Component, Path, PathBuf};

use serde_json::Value;

use crate::context::shell::{self, SimpleCommand, Word};
use crate::gate::Verdict;
use crate::gates::bash::glob_match;
use crate::lists::{self, VerbCluster};
use crate::policy::tier::Tier;
use crate::policy::Policy;

/// The default wallet, relative to a home dir.
const DEFAULT_WALLET: &str = ".config/solana/id.json";

/// The solana CLI config, relative to a home dir.
const CLI_CONFIG: &str = ".config/solana/cli/config.yml";

/// Largest CLI config read for its `keypair_path`.
const MAX_CONFIG_BYTES: u64 = 256 * 1024;

/// Programs that delete or move every path argument they name, a directory holding the wallet
/// included.
const DELETE_OR_MOVE: &[&str] = &["rm", "srm", "shred", "mv"];

/// Programs that overwrite or remove exactly the files they name.
const OVERWRITE: &[&str] = &["unlink", "truncate", "tee"];

/// Programs whose last path argument (or `-t DIR`) is a destination they overwrite.
const CLOBBER_DEST: &[&str] = &["cp", "install", "ln", "rsync", "ditto", "scp"];

/// Whether `program` (a base name) may delete, move or overwrite a file this gate protects.
pub(crate) fn is_file_clobber(program: &str) -> bool {
    program == "dd"
        || DELETE_OR_MOVE.contains(&program)
        || OVERWRITE.contains(&program)
        || CLOBBER_DEST.contains(&program)
}

/// The verdict for a Bash `command` run in `cwd`; `None` is no opinion.
pub fn decide_bash(command: &str, cwd: &Path, policy: &Policy, tier: Tier) -> Option<Verdict> {
    let _ = (policy, tier);
    decide_text(command, command, cwd, 0)
}

/// Deepest dynamic `eval`/`-c` script re-parsed for wallet shapes.
const MAX_SCRIPT_DEPTH: usize = 4;

/// [`decide_bash`] for `text` (the whole `command`, or a dynamic `eval`/`-c` script in it,
/// re-parsed with its expansions as dynamic words).
fn decide_text(command: &str, text: &str, cwd: &Path, depth: usize) -> Option<Verdict> {
    let wallet = Target {
        load: &Wallets::load,
        keygen: true,
        extended: false,
    };
    scan(text, cwd, depth, &wallet).map(|what| deny(what, command))
}

/// What [`scan`] protects and which commands it reads.
struct Target<'a> {
    /// The protected files (loaded only when the line may touch a file).
    load: &'a dyn Fn(&Homes) -> Wallets,
    /// Read `solana-keygen --force` (the default wallet's own destroyer).
    keygen: bool,
    /// Also read `chmod`/`chown`, `find -delete|-exec` and work-tree-rewriting `git`
    /// subcommands ([`extended_clobber`]).
    extended: bool,
}

/// What in `text` deletes, moves or overwrites one of `target`'s files (or a directory holding
/// one), if anything.
fn scan(text: &str, cwd: &Path, depth: usize, target: &Target) -> Option<String> {
    let parsed = shell::parse(text);
    let redirects = text.contains('>');
    let relevant = |c: &SimpleCommand| {
        let p = c.program();
        (target.keygen && p == "solana-keygen")
            || is_file_clobber(&p)
            || (target.extended && EXTENDED.contains(&p.as_str()))
    };
    let scripts: Vec<String> = parsed
        .commands
        .iter()
        .filter_map(crate::gates::bash::dynamic_script)
        .collect();
    if !redirects && scripts.is_empty() && !parsed.commands.iter().any(relevant) {
        return None;
    }
    let homes = Homes::from_env();
    let wallets = (target.load)(&homes);
    let keygen_rows = if target.keygen {
        keygen_rows()
    } else {
        Vec::new()
    };
    let mut dirs = Dirs::new(cwd, &parsed);
    for cmd in &parsed.commands {
        dirs.step(cmd, &homes);
        if !relevant(cmd) {
            continue;
        }
        if target.keygen {
            if let Some(reason) = keygen(cmd, &dirs, &homes, &wallets, &keygen_rows) {
                return Some(reason);
            }
        }
        if let Some(reason) = clobber(cmd, &dirs, &homes, &wallets) {
            return Some(reason);
        }
        if target.extended {
            if let Some(reason) = extended_clobber(cmd, &dirs, &homes, &wallets) {
                return Some(reason);
            }
        }
        if let Some(reason) = xargs_clobber(cmd, text, &dirs, &homes, &wallets) {
            return Some(reason);
        }
    }
    if redirects {
        if let Some(found) = redirect_target(text, &dirs, &homes, &wallets) {
            return Some(format!("a redirection overwrites {found}"));
        }
    }
    if depth >= MAX_SCRIPT_DEPTH {
        return None;
    }
    scripts
        .iter()
        .find_map(|script| scan(script, cwd, depth + 1, target))
}

/// Programs [`extended_clobber`] reads.
const EXTENDED: &[&str] = &["chmod", "chown", "chgrp", "chflags", "xattr", "find", "git"];

/// `git` subcommands that rewrite, remove or move work-tree files.
const GIT_REWRITES: &[&str] = &[
    "checkout", "restore", "clean", "rm", "mv", "stash", "reset", "switch",
];

/// [`scan`] with the files to protect given (the Codex adapter's self-protection: the
/// `safe-ai-skill` binary and wrapper, Codex hook config, Claude Code settings). On top of the
/// wallet gate's deletes, moves, overwrites, globs, ancestors and `cd` tracking it reads
/// `chmod`/`chown`, `find -delete|-exec` and work-tree-rewriting `git` subcommands.
pub fn clobber_of(command: &str, cwd: &Path, files: &[PathBuf]) -> Option<String> {
    let load = |_: &Homes| Wallets::from_files(files);
    let target = Target {
        load: &load,
        keygen: false,
        extended: true,
    };
    scan(command, cwd, 0, &target)
}

/// Why a `chmod`/`chown`, `find -delete|-exec` or work-tree-rewriting `git` command reaches a
/// protected file (or a directory holding one), if it does.
fn extended_clobber(
    cmd: &SimpleCommand,
    dirs: &Dirs,
    homes: &Homes,
    wallets: &Wallets,
) -> Option<String> {
    let program = cmd.program();
    let words: Vec<&Word> = cmd.words.iter().skip(1).collect();
    let hit = |w: &Word| match path_hit(&w.text, w.splits, dirs, homes, wallets, true) {
        Some(Hit::Wallet(t)) => Some(t),
        _ => None,
    };
    let operands = |from: &[&Word]| -> Vec<Word> {
        let mut out = Vec::new();
        let mut options = true;
        for w in from {
            if options && w.text == "--" {
                options = false;
                continue;
            }
            if options && w.text.starts_with('-') {
                continue;
            }
            out.push((*w).clone());
        }
        out
    };
    match program.as_str() {
        "find" => {
            let acts = ["-delete", "-exec", "-execdir", "-ok", "-okdir"];
            if !words.iter().any(|w| acts.contains(&w.text.as_str())) {
                return None;
            }
            let mut starts: Vec<Word> = words
                .iter()
                .take_while(|w| !w.text.starts_with(['-', '(', '!']))
                .map(|w| (*w).clone())
                .collect();
            if let (true, Some(first)) = (starts.is_empty(), cmd.words.first()) {
                let mut dot = first.clone();
                dot.text = ".".into();
                dot.dynamic = false;
                dot.splits = false;
                starts.push(dot);
            }
            starts
                .iter()
                .find_map(&hit)
                .map(|t| format!("`find` deletes or runs a command on {t}"))
        }
        "git" => {
            // Global options before the subcommand (`-C dir` moves where paths resolve).
            let mut i = 0;
            while let Some(w) = words.get(i) {
                match w.text.as_str() {
                    "-C" | "-c" | "--git-dir" | "--work-tree" => i += 2,
                    t if t.starts_with('-') => i += 1,
                    _ => break,
                }
            }
            let sub = words.get(i)?.text.clone();
            if !GIT_REWRITES.contains(&sub.as_str()) {
                return None;
            }
            let rest = &words[i + 1..];
            let paths = operands(rest);
            if let Some(t) = paths.iter().find_map(hit) {
                return Some(format!("`git {sub}` rewrites {t}"));
            }
            let untracked = sub == "clean"
                || (sub == "stash"
                    && rest.iter().any(|w| {
                        matches!(
                            w.text.as_str(),
                            "-u" | "--include-untracked" | "-a" | "--all"
                        )
                    }));
            if untracked && paths.is_empty() {
                // A path-less clean or untracked stash sweeps the whole tree: deny when a
                // protected file exists under a directory it may run in.
                return dirs
                    .known
                    .iter()
                    .find_map(|dir| wallets.existing_under(dir))
                    .map(|t| format!("`git {sub}` may remove {t}"));
            }
            None
        }
        _ => operands(&words)
            .iter()
            .find_map(hit)
            .map(|t| format!("`{program}` changes {t}")),
    }
}

/// The directories a relative path may resolve against, as the command line goes.
struct Dirs {
    /// The payload cwd and every directory a `cd`/`pushd` so far named (a subshell's `cd` may
    /// or may not still apply, so all are kept).
    known: Vec<PathBuf>,
    /// A directory change happened that the gate cannot place.
    unknown: bool,
}

impl Dirs {
    fn new(cwd: &Path, parsed: &shell::Parsed) -> Dirs {
        let has_cd = parsed
            .commands
            .iter()
            .any(|c| matches!(c.program().as_str(), "cd" | "pushd"));
        Dirs {
            known: vec![normalise(cwd)],
            // `env -C`, `popd` and the like change directory without a `cd` the gate reads.
            unknown: parsed.cwd_changed && !has_cd,
        }
    }

    /// Account for `cmd` if it changes directory.
    fn step(&mut self, cmd: &SimpleCommand, homes: &Homes) {
        match cmd.program().as_str() {
            "cd" | "pushd" => {}
            "popd" => {
                self.unknown = true;
                return;
            }
            _ => return,
        }
        let target = cmd
            .words
            .iter()
            .skip(1)
            .find(|w| !w.text.starts_with('-') || w.text == "-");
        let Some(target) = target else {
            match homes.expand_base() {
                Some(home) => self.known.push(normalise(home)),
                None => self.unknown = true,
            }
            return;
        };
        if target.text == "-" || target.dynamic || target.splits {
            self.unknown = true;
            return;
        }
        let next: Vec<PathBuf> = self
            .known
            .iter()
            .filter_map(|base| resolve(&target.text, base, homes))
            .collect();
        if next.is_empty() {
            self.unknown = true;
        }
        for dir in next {
            if !self.known.contains(&dir) {
                self.known.push(dir);
            }
        }
    }

    /// Every resolution of `raw` against the known directories.
    fn resolve_all(&self, raw: &str, homes: &Homes) -> Vec<PathBuf> {
        if is_absolute_word(raw) {
            return resolve(raw, Path::new("/"), homes).into_iter().collect();
        }
        self.known
            .iter()
            .filter_map(|base| resolve(raw, base, homes))
            .collect()
    }
}

/// Whether a path word does not depend on the cwd.
fn is_absolute_word(raw: &str) -> bool {
    raw.starts_with(['/', '~']) || raw.starts_with("$HOME") || raw.starts_with("${HOME}")
}

/// The verdict for a Write|Edit|MultiEdit|NotebookEdit `tool_input`; `None` is no opinion.
pub fn decide_file(
    tool_input: Option<&Value>,
    cwd: &Path,
    policy: &Policy,
    tier: Tier,
) -> Option<Verdict> {
    let _ = (policy, tier);
    let input = tool_input?;
    let raw = ["file_path", "notebook_path", "path"]
        .iter()
        .find_map(|k| input.get(k).and_then(Value::as_str))?;
    let homes = Homes::from_env();
    let wallets = Wallets::load(&homes);
    let path = resolve(raw, cwd, &homes)?;
    wallets.hit(&path).map(|target| {
        Verdict::Deny(format!(
            "Writing {target} would destroy the default Solana wallet (denied on \
             every cluster at every tier). Edit it yourself outside the agent if you intend to."
        ))
    })
}

fn deny(what: String, command: &str) -> Verdict {
    Verdict::Deny(format!(
        "Default-wallet destruction: {what} (denied on every cluster at every \
         tier). Run it yourself outside the agent if you intend it: `{}`",
        command.trim()
    ))
}

/// The home dirs whose `~/.config/solana/id.json` is protected.
struct Homes {
    /// `$HOME`, which `~` and `$HOME` expand to in the command.
    env: Option<PathBuf>,
    /// The passwd home (the account's real one).
    passwd: Option<PathBuf>,
}

impl Homes {
    fn from_env() -> Homes {
        Homes {
            env: std::env::var_os("HOME")
                .filter(|h| !h.is_empty())
                .map(PathBuf::from),
            passwd: crate::datadir::passwd_home(),
        }
    }

    /// The home `~` and `$HOME` expand to.
    fn expand_base(&self) -> Option<&Path> {
        self.env.as_deref().or(self.passwd.as_deref())
    }
}

/// The protected wallet files.
struct Wallets {
    /// (lexical, lowercased path; display form)
    paths: Vec<(String, String)>,
    /// Canonical forms of those that exist.
    canonical: Vec<PathBuf>,
}

impl Wallets {
    fn load(homes: &Homes) -> Wallets {
        let mut files: Vec<PathBuf> = [&homes.env, &homes.passwd]
            .iter()
            .filter_map(|h| h.as_ref().map(|h| h.join(DEFAULT_WALLET)))
            .collect();
        if let Some(home) = homes.expand_base() {
            if let Some(custom) = config_keypair_path(home) {
                if let Some(path) = resolve(&custom, home, homes) {
                    files.push(path);
                }
            }
        }
        let paths = files
            .iter()
            .map(|p| (key(p), p.display().to_string()))
            .collect();
        let canonical = files
            .iter()
            .filter_map(|p| crate::localfs::canonicalize(p).ok())
            .collect();
        Wallets { paths, canonical }
    }

    /// A set of given files (lexical keys plus the canonical forms of those that exist).
    fn from_files(files: &[PathBuf]) -> Wallets {
        Wallets {
            paths: files
                .iter()
                .map(|p| (key(p), p.display().to_string()))
                .collect(),
            canonical: files
                .iter()
                .filter_map(|p| crate::localfs::canonicalize(p).ok())
                .collect(),
        }
    }

    /// A protected file that exists below `dir`, if any.
    fn existing_under(&self, dir: &Path) -> Option<String> {
        let prefix = format!("{}/", key(dir));
        self.paths
            .iter()
            .find(|(p, shown)| p.starts_with(&prefix) && crate::localfs::exists(shown))
            .map(|(_, shown)| shown.clone())
    }

    /// The display form of the wallet `path` names, if it names one.
    fn hit(&self, path: &Path) -> Option<String> {
        let k = key(path);
        if let Some((_, shown)) = self.paths.iter().find(|(p, _)| *p == k) {
            return Some(shown.clone());
        }
        let real = crate::localfs::canonicalize(path).ok()?;
        self.canonical
            .contains(&real)
            .then(|| real.display().to_string())
    }

    /// The wallet `path` names or (with `ancestors`) holds below it, if any.
    fn hit_or_holds(&self, path: &Path, ancestors: bool) -> Option<String> {
        if let Some(t) = self.hit(path) {
            return Some(t);
        }
        if !ancestors {
            return None;
        }
        let k = key(path);
        let prefix = format!("{k}/");
        if let Some((_, shown)) = self.paths.iter().find(|(p, _)| p.starts_with(&prefix)) {
            return Some(format!("{shown} (inside {})", path.display()));
        }
        let real = crate::localfs::canonicalize(path).ok()?;
        self.canonical
            .iter()
            .find(|c| c.starts_with(&real) && **c != real)
            .map(|c| format!("{} (inside {})", c.display(), real.display()))
    }

    /// The wallet an unquoted glob `pattern` (resolved, lowercased key) matches, or (with
    /// `ancestors`) a directory holding it.
    fn glob_hit(&self, pattern: &str, ancestors: bool) -> Option<String> {
        self.paths.iter().find_map(|(p, shown)| {
            if glob_match(pattern, p) {
                return Some(shown.clone());
            }
            if !ancestors {
                return None;
            }
            let mut at = p.as_str();
            while let Some((parent, _)) = at.rsplit_once('/') {
                if glob_match(pattern, parent) || (parent.is_empty() && glob_match(pattern, "/")) {
                    return Some(format!("{shown} (inside `{pattern}`)"));
                }
                at = parent;
            }
            None
        })
    }

    /// Whether some wallet's file name (or, with `ancestors`, a directory name above it) is
    /// `name` (for relative paths after a directory change the gate cannot place).
    fn has_name(&self, name: &str, ancestors: bool) -> bool {
        let name = name.to_ascii_lowercase();
        self.paths.iter().any(|(p, _)| {
            let mut parts = p.rsplit('/');
            if parts.next() == Some(name.as_str()) {
                return true;
            }
            ancestors && parts.any(|part| part == name)
        })
    }

    /// The wallet a copy of `source` into directory `dir` would overwrite.
    fn hit_in_dir(&self, dir: &Path, source: &str) -> Option<String> {
        let name = Path::new(source).file_name()?;
        self.hit(&dir.join(name))
    }
}

/// A lexical comparison key: normalised, lowercased, `/`-separated.
fn key(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_ascii_lowercase()
}

/// `keypair_path` from `<home>/.config/solana/cli/config.yml`, when set.
fn config_keypair_path(home: &Path) -> Option<String> {
    let path = home.join(CLI_CONFIG);
    let meta = crate::localfs::metadata(&path).ok()?;
    if !meta.is_file() || meta.len() > MAX_CONFIG_BYTES {
        return None;
    }
    let mut text = String::new();
    std::fs::File::open(&path)
        .ok()?
        .take(MAX_CONFIG_BYTES)
        .read_to_string(&mut text)
        .ok()?;
    text.lines()
        .find_map(|l| l.trim().strip_prefix("keypair_path:"))
        .map(|v| v.trim().trim_matches(|c| c == '"' || c == '\'').to_string())
        .filter(|v| !v.is_empty())
}

/// Resolve a path word: `~`, `$HOME`, `${HOME}` expanded, relative to `cwd`, lexically
/// normalised. `None` when it holds any other expansion.
fn resolve(raw: &str, cwd: &Path, homes: &Homes) -> Option<PathBuf> {
    let raw = raw.trim();
    let home_rel = ["~/", "$HOME/", "${HOME}/"]
        .iter()
        .find_map(|p| raw.strip_prefix(p));
    let joined = if let Some(rest) = home_rel {
        if rest.contains(['$', '`']) {
            return None;
        }
        homes.expand_base()?.join(rest)
    } else if matches!(raw, "~" | "$HOME" | "${HOME}") {
        homes.expand_base()?.to_path_buf()
    } else if raw.contains(['$', '`']) || raw.starts_with('~') || raw.is_empty() {
        return None;
    } else if Path::new(raw).is_absolute() {
        PathBuf::from(raw)
    } else {
        cwd.join(raw)
    };
    Some(normalise(&joined))
}

/// Remove `.` and fold `..` without touching the file system.
fn normalise(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// `(verb, force flags)` from the list's `irreversible any` keygen rows.
fn keygen_rows() -> Vec<(String, String)> {
    let Ok(rows) = lists::irreversible() else {
        // Fail closed: the 1.1.0-era shapes.
        return [
            ("new", "--force"),
            ("new", "-f"),
            ("recover", "--force"),
            ("recover", "-f"),
        ]
        .iter()
        .map(|(v, f)| (v.to_string(), f.to_string()))
        .collect();
    };
    rows.iter()
        .filter(|v| v.cluster == VerbCluster::Any)
        .filter(|v| v.argv.first().is_some_and(|p| p == "solana-keygen"))
        .filter_map(|v| {
            let verb = v.argv.get(1)?.clone();
            let flag = v
                .argv
                .iter()
                .find_map(|t| t.strip_prefix('[').and_then(|t| t.strip_suffix(']')))?;
            Some((verb, flag.to_string()))
        })
        .collect()
}

/// The parsed flags of a `solana-keygen` command.
struct KeygenArgs<'a> {
    verb: Option<&'a str>,
    flags: Vec<String>,
    /// The `-o/--outfile` value, when given (`Some("")` when it is missing).
    outfile: Option<&'a Word>,
    outfile_flag: bool,
}

fn keygen_args(words: &[Word]) -> KeygenArgs<'_> {
    let mut args = KeygenArgs {
        verb: None,
        flags: Vec::new(),
        outfile: None,
        outfile_flag: false,
    };
    let mut i = 1;
    while let Some(word) = words.get(i) {
        i += 1;
        let text = word.text.as_str();
        if let Some(value) = text.strip_prefix("--outfile=") {
            args.outfile_flag = true;
            if !value.is_empty() {
                args.outfile = Some(word);
                args.flags.push("--outfile".into());
            }
            continue;
        }
        if text == "--outfile" {
            args.outfile_flag = true;
            args.outfile = words.get(i);
            i += 1;
            continue;
        }
        if text.starts_with("--") {
            args.flags
                .push(text.split('=').next().unwrap_or(text).to_string());
            continue;
        }
        if let Some(cluster) = text.strip_prefix('-').filter(|c| !c.is_empty()) {
            // A short cluster: `-f`, `-fo x`, `-sf`; `o` takes the rest or the next word.
            for (at, c) in cluster.char_indices() {
                if c == 'o' {
                    args.outfile_flag = true;
                    let rest = &cluster[at + 1..];
                    if rest.is_empty() {
                        args.outfile = words.get(i);
                        i += 1;
                    } else {
                        args.outfile = Some(word);
                    }
                    break;
                }
                args.flags.push(format!("-{c}"));
            }
            continue;
        }
        if args.verb.is_none() {
            args.verb = Some(text);
        }
    }
    args
}

/// The outfile path a `-o` word names (`-ofile`, `--outfile=file`, or the word itself).
fn outfile_text(word: &Word) -> &str {
    let t = word.text.as_str();
    if let Some(v) = t.strip_prefix("--outfile=") {
        return v;
    }
    if t.starts_with('-') && !t.starts_with("--") {
        if let Some(at) = t.find('o') {
            return &t[at + 1..];
        }
    }
    t
}

/// Why a `solana-keygen` command destroys the default wallet, if it does.
fn keygen(
    cmd: &SimpleCommand,
    dirs: &Dirs,
    homes: &Homes,
    wallets: &Wallets,
    rows: &[(String, String)],
) -> Option<String> {
    if cmd.program() != "solana-keygen" {
        return None;
    }
    let args = keygen_args(&cmd.words);
    let verb = args.verb?.to_ascii_lowercase();
    let forced = rows
        .iter()
        .any(|(v, flag)| *v == verb && args.flags.iter().any(|f| f == flag));
    if !forced || args.flags.iter().any(|f| f == "--no-outfile") {
        return None;
    }
    let Some(word) = args.outfile else {
        return (!args.outfile_flag).then(|| {
            format!(
                "`solana-keygen {verb}` with --force and no outfile overwrites the default wallet"
            )
        });
    };
    let text = outfile_text(word);
    match path_hit(text, word.splits, dirs, homes, wallets, false) {
        Some(Hit::Wallet(target)) => Some(format!(
            "`solana-keygen {verb} --force` overwrites {target}"
        )),
        Some(Hit::Unresolved) => Some(format!(
            "`solana-keygen {verb} --force` writes `{text}`, which may be the default wallet"
        )),
        None => None,
    }
}

/// What a path word names.
enum Hit {
    /// A protected wallet (display form).
    Wallet(String),
    /// A word the gate cannot resolve (an expansion).
    Unresolved,
}

/// Whether path word `raw` names a protected wallet (or, with `ancestors`, a directory holding
/// one): every resolution against the known directories, an unquoted glob matched, and after
/// an unplaceable directory change a relative name equal to a protected one.
fn path_hit(
    raw: &str,
    globs: bool,
    dirs: &Dirs,
    homes: &Homes,
    wallets: &Wallets,
    ancestors: bool,
) -> Option<Hit> {
    let resolved = dirs.resolve_all(raw, homes);
    if resolved.is_empty() {
        // An expansion: a delete or move under a directory holding the wallet may reach it
        // (`rm -rf ~/.config/$X`).
        if ancestors {
            if let Some((prefix, _)) = raw.split_once('$').and_then(|(p, _)| p.rsplit_once('/')) {
                let base = if prefix.is_empty() { "/" } else { prefix };
                for dir in dirs.resolve_all(base, homes) {
                    if let Some(t) = wallets.hit_or_holds(&dir, true) {
                        return Some(Hit::Wallet(format!("{t} (`{raw}` may name it)")));
                    }
                }
            }
        }
        return Some(Hit::Unresolved);
    }
    let globbed = globs && raw.contains(['*', '?', '[']);
    for path in &resolved {
        let found = if globbed {
            wallets.glob_hit(&key(path), ancestors)
        } else {
            wallets.hit_or_holds(path, ancestors)
        };
        if let Some(t) = found {
            return Some(Hit::Wallet(t));
        }
    }
    if dirs.unknown && !is_absolute_word(raw) {
        let name = resolved
            .first()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("");
        if globbed || wallets.has_name(name, ancestors) {
            return Some(Hit::Wallet(format!("`{raw}` (after a directory change)")));
        }
    }
    None
}

/// Why a file command deletes, moves or overwrites a wallet, if it does.
fn clobber(cmd: &SimpleCommand, dirs: &Dirs, homes: &Homes, wallets: &Wallets) -> Option<String> {
    let program = cmd.program();
    let words: Vec<&Word> = cmd.words.iter().skip(1).collect();
    // An unresolvable operand of a file command is not assumed to be the wallet.
    let hit = |w: &Word, ancestors: bool| match path_hit(
        &w.text, w.splits, dirs, homes, wallets, ancestors,
    ) {
        Some(Hit::Wallet(t)) => Some(t),
        _ => None,
    };
    if program == "dd" {
        return words
            .iter()
            .filter_map(|w| {
                w.text.strip_prefix("of=").map(|rest| Word {
                    text: rest.to_string(),
                    ..(*w).clone()
                })
            })
            .find_map(|w| hit(&w, false))
            .map(|t| format!("`dd` writes {t}"));
    }
    let paths: Vec<&Word> = words
        .iter()
        .copied()
        .filter(|w| !w.text.starts_with('-') || w.text == "-")
        .collect();
    if DELETE_OR_MOVE.contains(&program.as_str()) {
        // `mv`'s destination overwrites; every other operand of these is deleted or moved away.
        let found = if program == "mv" {
            paths.split_last().and_then(|(dest, sources)| {
                hit(dest, false).or_else(|| sources.iter().find_map(|w| hit(w, true)))
            })
        } else {
            paths.iter().find_map(|w| hit(w, true))
        };
        return found.map(|t| format!("`{program}` removes or overwrites {t}"));
    }
    if OVERWRITE.contains(&program.as_str()) {
        return paths
            .iter()
            .find_map(|w| hit(w, false))
            .map(|t| format!("`{program}` removes or overwrites {t}"));
    }
    if CLOBBER_DEST.contains(&program.as_str()) {
        let texts: Vec<&str> = words.iter().map(|w| w.text.as_str()).collect();
        let target_dir = texts
            .iter()
            .position(|a| *a == "-t" || *a == "--target-directory")
            .and_then(|i| words.get(i + 1))
            .copied()
            .or_else(|| {
                words
                    .iter()
                    .copied()
                    .find(|w| w.text.starts_with("--target-directory="))
            });
        let owned_dir;
        let (dest, sources): (&Word, Vec<&Word>) = match target_dir {
            Some(dir) => {
                owned_dir = Word {
                    text: dir
                        .text
                        .strip_prefix("--target-directory=")
                        .unwrap_or(&dir.text)
                        .to_string(),
                    ..dir.clone()
                };
                let sources = paths
                    .iter()
                    .copied()
                    .filter(|p| p.text != dir.text)
                    .collect();
                (&owned_dir, sources)
            }
            None => {
                let (last, rest) = paths.split_last()?;
                (*last, rest.to_vec())
            }
        };
        if let Some(t) = hit(dest, false) {
            return Some(format!("`{program}` overwrites {t}"));
        }
        return dirs
            .resolve_all(&dest.text, homes)
            .iter()
            .find_map(|dir| {
                sources
                    .iter()
                    .find_map(|s| wallets.hit_in_dir(dir, &s.text))
            })
            .map(|t| format!("`{program}` overwrites {t}"));
    }
    None
}

/// A file-clobbering program fed its operands by `xargs` (the parser's `$XARGS` word): when
/// any word of the line resolves to a protected wallet (or, for a delete or move, a directory
/// holding one), it may be among them (`echo ~/.config/solana/id.json | xargs rm`).
fn xargs_clobber(
    cmd: &SimpleCommand,
    text: &str,
    dirs: &Dirs,
    homes: &Homes,
    wallets: &Wallets,
) -> Option<String> {
    let program = cmd.program();
    if !cmd.words.iter().any(|w| w.dynamic && w.text == "$XARGS") {
        return None;
    }
    let ancestors = DELETE_OR_MOVE.contains(&program.as_str());
    crate::context::tokenize(text).iter().find_map(|token| {
        let raw = token.trim_matches(|c| matches!(c, ';' | '|' | '&' | '(' | ')'));
        if raw.is_empty() || raw.starts_with('-') {
            return None;
        }
        match path_hit(raw, false, dirs, homes, wallets, ancestors) {
            Some(Hit::Wallet(t)) => Some(format!("`xargs {program}` may receive {t}")),
            _ => None,
        }
    })
}

/// The wallet a `>`/`>>`/`>|`/`&>` redirection in `command` writes, if any. The parser drops
/// redirections, so the raw text is scanned (nested `-c` scripts included).
fn redirect_target(command: &str, dirs: &Dirs, homes: &Homes, wallets: &Wallets) -> Option<String> {
    let chars: Vec<char> = command.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] != '>' {
            i += 1;
            continue;
        }
        i += 1;
        while i < chars.len() && matches!(chars[i], '>' | '|') {
            i += 1;
        }
        // `>&2` duplicates a descriptor; `>& file` writes the file.
        let ampersand = chars.get(i) == Some(&'&');
        if ampersand {
            i += 1;
        }
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
        let mut word = String::new();
        let mut quoted = false;
        while i < chars.len() {
            let c = chars[i];
            if c.is_whitespace() || matches!(c, ';' | '|' | '&' | ')' | '<' | '>') {
                break;
            }
            if matches!(c, '"' | '\'' | '\\') {
                quoted = true;
            } else {
                word.push(c);
            }
            i += 1;
        }
        if word.is_empty() || (ampersand && word.chars().all(|c| c.is_ascii_digit() || c == '-')) {
            continue;
        }
        if let Some(Hit::Wallet(target)) = path_hit(&word, !quoted, dirs, homes, wallets, false) {
            return Some(target);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn homes(home: &str) -> Homes {
        Homes {
            env: Some(PathBuf::from(home)),
            passwd: None,
        }
    }

    #[test]
    fn resolve_expands_home_and_normalises() {
        let h = homes("/h");
        let cwd = Path::new("/p");
        assert_eq!(
            resolve("~/.config/solana/id.json", cwd, &h),
            Some(PathBuf::from("/h/.config/solana/id.json"))
        );
        assert_eq!(
            resolve("${HOME}/a/../.config/./solana/id.json", cwd, &h),
            Some(PathBuf::from("/h/.config/solana/id.json"))
        );
        assert_eq!(resolve("k.json", cwd, &h), Some(PathBuf::from("/p/k.json")));
        assert_eq!(resolve("$X/id.json", cwd, &h), None);
    }

    #[test]
    fn keygen_args_read_short_clusters_and_outfiles() {
        let parsed = shell::parse("solana-keygen new -fo out.json");
        let args = keygen_args(&parsed.commands[0].words);
        assert_eq!(args.verb, Some("new"));
        assert!(args.flags.iter().any(|f| f == "-f"));
        assert_eq!(args.outfile.map(outfile_text), Some("out.json"));
        let parsed = shell::parse("solana-keygen new --outfile=x.json --force");
        let args = keygen_args(&parsed.commands[0].words);
        assert_eq!(args.outfile.map(outfile_text), Some("x.json"));
        assert!(args.flags.iter().any(|f| f == "--force"));
    }

    #[test]
    fn keygen_rows_come_from_the_shared_list() {
        let rows = keygen_rows();
        for want in [
            ("new", "--force"),
            ("new", "-f"),
            ("recover", "--force"),
            ("recover", "-f"),
        ] {
            assert!(
                rows.iter().any(|(v, f)| v == want.0 && f == want.1),
                "{want:?} in {rows:?}"
            );
        }
    }

    #[test]
    fn redirections_onto_the_wallet_are_found() {
        let h = homes("/h");
        let w = Wallets {
            paths: vec![(
                "/h/.config/solana/id.json".into(),
                "/h/.config/solana/id.json".into(),
            )],
            canonical: Vec::new(),
        };
        let cwd = Dirs {
            known: vec![PathBuf::from("/p")],
            unknown: false,
        };
        let cwd = &cwd;
        assert!(redirect_target("echo [] > ~/.config/solana/id.json", cwd, &h, &w).is_some());
        assert!(
            redirect_target("echo x >>\"$HOME/.config/solana/id.json\"", cwd, &h, &w).is_some()
        );
        assert!(
            redirect_target("bash -c 'cat k >| ~/.config/solana/id.json'", cwd, &h, &w).is_some()
        );
        assert!(redirect_target("echo x >& ~/.config/solana/id.json", cwd, &h, &w).is_some());
        assert!(redirect_target("echo x > ~/.config/solana/*.json", cwd, &h, &w).is_some());
        assert!(redirect_target("echo x > out.json 2>&1", cwd, &h, &w).is_none());
        assert!(redirect_target("echo x >&2", cwd, &h, &w).is_none());
    }
}
