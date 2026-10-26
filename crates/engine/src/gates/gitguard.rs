//! Git and gh guard: the ai-kit egress-guard git/gh gates and their static deny rules, ported.
//!
//! Tier matrix (ai-kit `egress-guard.sh`, `egress-guard.awk`, `firewall.sh` `DENY_*`). `Off`
//! acts as `Relaxed` (its asks and denies hold); headless turns every ask into a deny upstream.
//!
//! | Item | What | Relaxed | Medium | High |
//! |---|---|---|---|---|
//! | E5 | force push (`--force*`, `-f` clusters, `+refspec`, not `--dry-run`), `gh pr merge` | – | ask | deny |
//! | E6 | `rebase` (not `--abort/--continue/…`), `filter-branch/-repo`, `commit --amend`, `stash drop/clear`, `branch/tag -d`, `branch -D/-f` | – | – | ask |
//! | E8 | `clean` (not `-n`/`--dry-run`), `restore` (not `--staged` alone), `checkout --`, `reset --ha*`, `reflog expire/delete/drop`, `prune`, `gc --prune*`, `push --mirror` | deny | deny | deny |
//! | E10 | `git --config-env`, `git --exec-path=<dir>`, `GIT_CONFIG_COUNT/KEY_n/VALUE_n`, `GIT_CONFIG_PARAMETERS`, `GIT_EXEC_PATH` | deny | deny | deny |
//! | E11 | `GIT_SSH_COMMAND`, `GIT_SSH`, `GIT_PROXY_COMMAND`, `GIT_EXTERNAL_DIFF`, `GIT_ASKPASS` (+ `GIT_TEMPLATE_DIR`) | – | – | ask |
//! | E12 | `--receive-pack`/`--exec` on push, `--upload-pack` on pull/fetch/clone/ls-remote (+ `clone -u`, `archive --exec`) | deny | deny | deny |
//! | E13 | `gh secret set`, `gh variable set`, `gh api` writes to secrets/variables | deny | deny | deny |
//! | E14 | `gh api` writes to workflow dispatches, deployments, environments | ask | deny | deny |
//! | E15 | `gh api` (any) | – | deny | deny |
//! | E15 | `gh repo delete`, `gh issue delete`, `gh alias`, `gh api -X DELETE repos/O/R` | deny | deny | deny |
//! | E7 | `git config` / `git -c` keys that run a program, `config --edit` ([`decide_git_config_risk`]) | ask | deny | deny |
//!
//! Positions are read from [`shell::parse`], so a commit message or an issue body naming any of
//! these is data. Strings git itself runs as shell code (`git submodule foreach CMD`, `git
//! rebase --exec CMD`) are judged as commands too, and exposed by [`inner_commands`] so other
//! Bash gates can judge them. Unlike the kit, every spelling is decided the same way: a git-level
//! option in front of a subcommand, a wrapper or a quoted word is not a different command.
//!
//! Known misses: a subcommand or endpoint held in a variable (`G=git; $G clean`, `gh api
//! "$EP"`), text the shell assembles at run time, git run from a script file, and environment
//! assignments inside a here-document or a double-quoted substitution.

use std::path::Path;

use crate::context::shell::{self, base_name, SimpleCommand, Word};
use crate::gate::Verdict;
use crate::gates::bash::MAX_PARSE_BYTES;
use crate::policy::tier::Tier;
use crate::policy::Policy;

/// Deepest nesting of code strings (`foreach`, `--exec`, `sh -c`) followed.
const MAX_DEPTH: usize = 4;

/// Shells whose `-c` code the environment scan reads.
const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "yash"];

/// What a scan found.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Finding {
    Deny(String),
    Ask(String),
}

/// Which checks a scan runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Every gate in this module, the config-key gate included.
    All,
    /// Only [`decide_git_config_risk`]'s.
    ConfigOnly,
}

/// Decide a Bash `command` against the git and gh gates (see the module docs). `None` when no
/// gate has an opinion. `cwd` and `policy` are unused today and kept for the gate signature.
pub fn decide(command: &str, _cwd: &Path, _policy: &Policy, tier: Tier) -> Option<Verdict> {
    if command.len() > MAX_PARSE_BYTES || !may_concern(command) {
        return None;
    }
    let mut out = Vec::new();
    scan(command, effective(tier), 0, Mode::All, &mut out);
    verdict(out)
}

/// E7 alignment: a `git config` write (or a one-shot `git -c key=value`) of a key that makes git
/// run a program is denied from Medium up and asked at Relaxed and Off. Keys: the kit's
/// `GITEXEC` set (`alias.*`, `core.pager`, `core.editor`, `core.hooksPath`, `sequence.editor`,
/// `credential.helper`, `diff.external`, any value, plus `git config --edit` and a
/// `--rename-section` onto one of their sections), the viewer and browser commands `git help`
/// runs (`man.viewer`, `man.<tool>.cmd|path`, `web.browser`, `browser.<tool>.cmd|path`), and the
/// tamper gate's wider set (fsmonitor, sshCommand, gpg programs, filter and merge drivers,
/// include paths, …).
pub fn decide_git_config_risk(command: &str, tier: Tier) -> Option<Verdict> {
    if command.len() > MAX_PARSE_BYTES || !may_concern(command) {
        return None;
    }
    let mut out = Vec::new();
    scan(command, effective(tier), 0, Mode::ConfigOnly, &mut out);
    verdict(out)
}

/// H6: the code strings git runs as shell commands — `git submodule foreach CMD ARG…` (CMD and
/// its arguments) and each `git rebase --exec CODE` / `-x CODE` — in source order, nested ones
/// included. Feed each back through the Bash gates as a command of its own.
pub fn inner_commands(command: &str) -> Vec<String> {
    let mut out = Vec::new();
    if command.len() <= MAX_PARSE_BYTES && may_concern(command) {
        collect_inner(command, 0, &mut out);
    }
    out
}

fn collect_inner(text: &str, depth: usize, out: &mut Vec<String>) {
    if depth >= MAX_DEPTH {
        return;
    }
    for cmd in &shell::parse(text).commands {
        for code in git_code_strings(cmd) {
            out.push(code.clone());
            collect_inner(&code, depth + 1, out);
        }
    }
}

/// `Off` keeps every ask and deny of `Relaxed`.
fn effective(tier: Tier) -> Tier {
    tier.max(Tier::Relaxed)
}

/// The strongest finding: the first deny, else the first ask.
fn verdict(out: Vec<Finding>) -> Option<Verdict> {
    let mut ask = None;
    for f in out {
        match f {
            Finding::Deny(r) => return Some(Verdict::Deny(r)),
            Finding::Ask(r) => {
                ask.get_or_insert(r);
            }
        }
    }
    ask.map(Verdict::Ask)
}

/// The byte prefilter: `git` in any case (which also covers every `GIT_*` name), a `gh` word,
/// a backslash (`g\it`) or ANSI-C quoting. Allocation-free.
pub fn may_concern(command: &str) -> bool {
    let b = command.as_bytes();
    if b.windows(2).any(|w| w == b"$'") || b.contains(&b'\\') {
        return true;
    }
    let lower = |i: usize| b.get(i).map(u8::to_ascii_lowercase);
    for i in 0..b.len() {
        match lower(i) {
            Some(b'g') => {}
            _ => continue,
        }
        if lower(i + 1) == Some(b'i') && lower(i + 2) == Some(b't') {
            return true;
        }
        // `gh` as a word: `gh api`, `/usr/bin/gh pr`, `"gh" secret`.
        if lower(i + 1) == Some(b'h') {
            let before = i == 0 || !b[i - 1].is_ascii_alphanumeric();
            let after = b
                .get(i + 2)
                .is_none_or(|c| !c.is_ascii_alphanumeric() && *c != b'-');
            if before && after {
                return true;
            }
        }
    }
    false
}

/// Scan `text` (the command, or a code string inside it) into `out`.
fn scan(text: &str, tier: Tier, depth: usize, mode: Mode, out: &mut Vec<Finding>) {
    if depth > MAX_DEPTH {
        return;
    }
    if mode == Mode::All {
        env_scan(text, tier, 0, out);
    }
    let parsed = shell::parse(text);
    // git or gh behind a prefix program the parser does not strip (`arch -x86_64 git …`,
    // `taskset 0x1 git …`), read from the parsed words and from the raw statements, since a
    // wrapper option the parser misreads can swallow the program word itself.
    let mut peeled: Vec<SimpleCommand> = Vec::new();
    for cmd in &parsed.commands {
        if !matches!(cmd.program().as_str(), "git" | "gh") {
            peeled.extend(peel(&cmd.words));
        }
    }
    let (stmts, _) = env_statements(text);
    for st in &stmts {
        let words: Vec<Word> = st
            .iter()
            .skip_while(|w| w.assignment().is_some())
            .map(|w| Word {
                text: w.text.clone(),
                quoted: w.quoted_at.is_some(),
                ..Word::default()
            })
            .collect();
        if words
            .first()
            .is_some_and(|w| RUNNERS.contains(&base_name(&w.text).as_str()))
        {
            peeled.extend(peel(&words));
        }
    }
    for cmd in parsed.commands.iter().chain(&peeled) {
        judge(cmd, tier, depth, mode, out);
    }
}

/// Judge one simple command whose program may be git or gh.
fn judge(cmd: &SimpleCommand, tier: Tier, depth: usize, mode: Mode, out: &mut Vec<Finding>) {
    match cmd.program().as_str() {
        "git" => {
            let Some(walk) = git_walk(&cmd.words) else {
                return;
            };
            if mode == Mode::All {
                git_findings(&walk, tier, out);
            }
            if let Some(why) = config_risk(&walk) {
                out.push(if tier >= Tier::Medium {
                    Finding::Deny(format!(
                        "safe-ai-skill git guard: this {why}; the {} tier denies it, so ask the user to \
                         set the key themselves.",
                        tier.label()
                    ))
                } else {
                    Finding::Ask(format!(
                        "safe-ai-skill git guard: this {why}; confirm the key and the program \
                         before approving."
                    ))
                });
            }
        }
        "gh" if mode == Mode::All => gh_findings(cmd, tier, out),
        _ => {}
    }
    for code in git_code_strings(cmd) {
        scan(&code, tier, depth + 1, mode, out);
    }
}

/// Prefix programs that run the rest of their argv as a command.
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
    "noglob",
    "nocorrect",
    "watch",
    "flock",
    "chroot",
    "prlimit",
    "cpulimit",
    "trickle",
    "nsenter",
    "unshare",
    "runuser",
    "pkexec",
    "sg",
    "faketime",
    "firejail",
    "systemd-run",
    "proxychains",
    "proxychains4",
    "torsocks",
    "tsocks",
    "strace",
    "ltrace",
    "valgrind",
    "catchsegv",
    "rlwrap",
    "xvfb-run",
    "dbus-run-session",
    "ssh-agent",
];

/// Prefix programs whose first positional is not the command (`chroot DIR cmd`, `flock FILE cmd`).
const POSITIONAL_RUNNERS: &[&str] = &["chroot", "flock", "sg", "runuser", "timeout", "taskset"];

/// The git or gh command a chain of [`RUNNERS`] runs, if `words` is one: every word before it
/// is a runner, an option, an option's value, a number or mask (`5`, `0x1`), an assignment or a
/// runner's positional operand. `None` when a word in between is another program.
fn peel(words: &[Word]) -> Option<SimpleCommand> {
    let first = base_name(&words.first()?.text);
    let leftover = |t: &str| t.starts_with('-') || is_number(t);
    if !RUNNERS.contains(&first.as_str()) && !leftover(&words[0].text) {
        return None;
    }
    let mut prev_runner = Some(first);
    let mut prev_option = false;
    for (i, w) in words.iter().enumerate().skip(1) {
        let t = w.text.as_str();
        let base = base_name(t);
        if matches!(base.as_str(), "git" | "gh") {
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
        let assignment = t.split_once('=').is_some_and(|(n, _)| {
            !n.is_empty() && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        });
        let runner = RUNNERS.contains(&base.as_str());
        if !(t.starts_with('-')
            || is_number(t)
            || assignment
            || runner
            || prev_option
            || positional)
        {
            return None;
        }
        prev_option = t.starts_with('-') && !t.contains('=');
        prev_runner = runner.then_some(base);
    }
    None
}

/// A count, priority, duration or CPU mask: `5`, `0x1`, `1.5s`, `0-3,7`.
fn is_number(t: &str) -> bool {
    t.starts_with(|c: char| c.is_ascii_digit())
        && t.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ',' | '-' | ':'))
}

// ---- git ---------------------------------------------------------------------------------

/// A git invocation after its git-level options.
struct GitWalk<'a> {
    /// The subcommand, if one runs.
    sub: Option<&'a str>,
    /// The words after the subcommand.
    rest: &'a [Word],
    /// `--config-env` among the git-level options.
    config_env: bool,
    /// The `--exec-path=<dir>` option, if given.
    exec_path: Option<&'a str>,
    /// `-c key=value` values among the git-level options.
    dash_c: Vec<&'a str>,
}

/// A git-level option that takes the next word (`lib-tokenize.awk` `kit_git_optarg`).
fn git_optarg(o: &str) -> bool {
    matches!(
        o,
        "-C" | "-c"
            | "--git-dir"
            | "--work-tree"
            | "--namespace"
            | "--attr-source"
            | "--super-prefix"
            | "--config-env"
            | "--shallow-file"
    )
}

/// Walk git's own options (`words[0]` is `git`). `None` for no words.
fn git_walk(words: &[Word]) -> Option<GitWalk<'_>> {
    let mut walk = GitWalk {
        sub: None,
        rest: &[],
        config_env: false,
        exec_path: None,
        dash_c: Vec::new(),
    };
    let mut i = 1;
    while let Some(w) = words.get(i) {
        let t = w.text.as_str();
        if !t.starts_with('-') || t == "-" || t == "--" {
            break;
        }
        let o = t.split_once('=').map_or(t, |(o, _)| o);
        if t.starts_with("--exec-path=") {
            walk.exec_path.get_or_insert(t);
        }
        if o == "--config-env" {
            walk.config_env = true;
        }
        // git prints and exits on these: no subcommand runs.
        if matches!(
            o,
            "-h" | "--help"
                | "-v"
                | "--version"
                | "--html-path"
                | "--man-path"
                | "--info-path"
                | "--list-cmds"
        ) || t == "--exec-path"
        {
            return Some(walk);
        }
        if o == "-c" {
            if let Some(v) = words.get(i + 1) {
                walk.dash_c.push(v.text.as_str());
            }
        }
        if git_optarg(o) && !t.contains('=') {
            i += 1;
        }
        i += 1;
    }
    if let Some(w) = words.get(i) {
        walk.sub = Some(w.text.as_str());
        walk.rest = &words[i + 1..];
    }
    Some(walk)
}

fn deny_every_tier(what: &str, fix: &str) -> Finding {
    Finding::Deny(format!(
        "safe-ai-skill git guard: this {what}, which is denied at every tier; {fix}."
    ))
}

/// The ladder for remote rewrites (E5): silent at Relaxed, ask at Medium, deny at High.
fn remote_ladder(what: &str, tier: Tier, out: &mut Vec<Finding>) {
    match tier {
        Tier::High => out.push(Finding::Deny(format!(
            "safe-ai-skill git guard: this {what}; the high tier denies it, so ask the user to \
             run it or lower the tier."
        ))),
        Tier::Medium => out.push(Finding::Ask(format!(
            "safe-ai-skill git guard: this {what}; confirm the branch and the remote before \
             approving."
        ))),
        _ => {}
    }
}

/// E6: a recoverable history rewrite, asked at High only.
fn rewrite_ask(what: &str, tier: Tier, out: &mut Vec<Finding>) {
    if tier == Tier::High {
        out.push(Finding::Ask(format!(
            "safe-ai-skill git guard: this {what}, which rewrites local history (recoverable from \
             the reflog); the high tier asks first, so confirm it is intended before approving."
        )));
    }
}

fn texts(words: &[Word]) -> impl Iterator<Item = &str> {
    words.iter().map(|w| w.text.as_str())
}

/// The options of a git subcommand, up to `--` (after it, every word is a path).
fn options(words: &[Word]) -> impl Iterator<Item = &str> {
    texts(words)
        .take_while(|t| *t != "--")
        .filter(|t| t.starts_with('-'))
}

/// `git clean -n` / `--dry-run` (alone or in a cluster such as `-nd`) only lists.
fn clean_dry_run(rest: &[Word]) -> bool {
    options(rest).any(|t| t == "--dry-run" || (!t.starts_with("--") && t[1..].contains('n')))
}

/// `git restore --staged` / `-S` without `--worktree` / `-W` only unstages: the working tree
/// is untouched. `-s` takes a value, so the rest of its cluster is that value.
fn restore_index_only(rest: &[Word]) -> bool {
    let (mut staged, mut worktree) = (false, false);
    for t in options(rest) {
        match t {
            "--staged" => staged = true,
            "--worktree" => worktree = true,
            _ if t.starts_with("--") => {}
            _ => {
                for c in t[1..].chars() {
                    match c {
                        'S' => staged = true,
                        'W' => worktree = true,
                        's' => break,
                        _ => {}
                    }
                }
            }
        }
    }
    staged && !worktree
}

/// Whether `t` is `full` or an abbreviation of it git accepts (at least `min` bytes).
fn abbrev(t: &str, full: &str, min: usize) -> bool {
    t.len() >= min && full.starts_with(t)
}

/// Whether a short-option cluster (`-qf`) holds `flag` before an option in `valued`, whose
/// value is the rest of the cluster.
fn cluster_has(t: &str, flag: char, valued: &str) -> bool {
    if t.starts_with("--") || !t.starts_with('-') {
        return false;
    }
    for c in t[1..].chars() {
        if c == flag {
            return true;
        }
        if valued.contains(c) {
            return false;
        }
    }
    false
}

/// `git checkout` forms that overwrite the working tree: a `--` path separator anywhere, a
/// `.` pathspec, or `-f` / `--force`. `git checkout <branch>` and `-b <name>` do not.
fn checkout_discards(rest: &[Word]) -> bool {
    texts(rest).any(|t| t == "--" || t == ".")
        || options(rest).any(|t| abbrev(t, "--force", 5) || cluster_has(t, 'f', "bB"))
}

/// `git switch -f` / `--force` / `--discard-changes`.
fn forced_switch(rest: &[Word]) -> bool {
    options(rest).any(|t| {
        abbrev(t, "--force", 5) || abbrev(t, "--discard-changes", 4) || cluster_has(t, 'f', "cC")
    })
}

fn git_findings(walk: &GitWalk<'_>, tier: Tier, out: &mut Vec<Finding>) {
    const FIX_RUN: &str = "if the user wants it, they run it themselves";
    if walk.config_env {
        out.push(deny_every_tier(
            "sets git config through --config-env, where a key such as core.fsmonitor or alias.* \
             names a program git runs",
            "if the user needs the value set, they run the command themselves",
        ));
    }
    if let Some(p) = walk.exec_path {
        out.push(deny_every_tier(
            &format!("runs git with {p}, so git runs the helpers it finds in that directory"),
            FIX_RUN,
        ));
    }
    let Some(sub) = walk.sub else { return };
    let rest = walk.rest;
    let first = rest.first().map(|w| w.text.as_str());
    let any = |pred: &dyn Fn(&str) -> bool| texts(rest).any(pred);
    match sub {
        // E8: uncommitted work and the reflog record are in no reflog.
        "clean" if !clean_dry_run(rest) => out.push(deny_every_tier(
            "runs git clean, deleting untracked files",
            FIX_RUN,
        )),
        "restore" if !restore_index_only(rest) => out.push(deny_every_tier(
            "runs git restore, overwriting the working tree",
            FIX_RUN,
        )),
        "checkout" if checkout_discards(rest) => out.push(deny_every_tier(
            "runs git checkout over a path or with --force, discarding uncommitted changes",
            FIX_RUN,
        )),
        "switch" if forced_switch(rest) => out.push(deny_every_tier(
            "runs git switch --force or --discard-changes, discarding uncommitted changes",
            FIX_RUN,
        )),
        "reset" if any(&|t| t.starts_with("--ha")) => out.push(deny_every_tier(
            "runs git reset --hard, discarding uncommitted changes",
            FIX_RUN,
        )),
        "reset" if any(&|t| abbrev(t, "--merge", 4) || abbrev(t, "--keep", 3)) => {
            out.push(deny_every_tier(
                "runs git reset --merge or --keep, which overwrites working-tree files",
                FIX_RUN,
            ))
        }
        "prune" => out.push(deny_every_tier(
            "runs git prune, deleting the unreachable objects a dropped stash or branch is \
             recovered from",
            FIX_RUN,
        )),
        "gc" if any(&|t| t.starts_with("--prune")) => out.push(deny_every_tier(
            "runs git gc --prune, deleting the unreachable objects a dropped stash or branch is \
             recovered from",
            FIX_RUN,
        )),
        "reflog" if matches!(first, Some("expire" | "delete" | "drop")) => {
            out.push(deny_every_tier(
                "removes reflog entries, which is what makes dropped history unrecoverable",
                FIX_RUN,
            ))
        }
        "push" => push_findings(rest, tier, out),
        "pull" | "fetch" | "ls-remote" | "clone" => {
            let clone = sub == "clone";
            if any(&|t| t.starts_with("--upload-pack") || (clone && t.starts_with("-u"))) {
                out.push(deny_every_tier(
                    &format!("names a program for git to run as the far end of a {sub}"),
                    FIX_RUN,
                ));
            }
        }
        "archive" if any(&|t| t.starts_with("--exec")) => out.push(deny_every_tier(
            "names a program for git to run as the far end of an archive",
            FIX_RUN,
        )),
        // E6, High only.
        "rebase" => {
            let finishing = any(&|t| {
                matches!(
                    t,
                    "--abort" | "--continue" | "--skip" | "--quit" | "--edit-todo"
                ) || t == "--show-current-patch"
            });
            if !finishing {
                rewrite_ask("runs git rebase", tier, out);
            }
        }
        "filter-branch" | "filter-repo" => rewrite_ask(&format!("runs git {sub}"), tier, out),
        "commit" if any(&|t| t == "--amend") => rewrite_ask("amends a commit", tier, out),
        "stash" if matches!(first, Some("drop" | "clear")) => {
            rewrite_ask("drops stashed changes", tier, out)
        }
        "branch" | "tag" => {
            let delete = any(&|t| t == "-d" || t == "--delete" || t.starts_with("--delete="));
            let force = sub == "branch"
                && any(&|t| {
                    t == "--force"
                        || (t.starts_with('-')
                            && !t.starts_with("--")
                            && t[1..].contains(['D', 'f']))
                });
            if delete || force {
                rewrite_ask(&format!("deletes or force-moves a {sub}"), tier, out);
            }
        }
        _ => {}
    }
}

/// `git push`: mirror and transport overrides deny; a force push or a remote branch deletion
/// ladders (E5).
fn push_findings(rest: &[Word], tier: Tier, out: &mut Vec<Finding>) {
    let mut forced = false;
    let mut deleted = false;
    let mut dry_run = false;
    for t in texts(rest) {
        if t.starts_with("--mirror") {
            out.push(deny_every_tier(
                "runs git push --mirror, overwriting every ref on the remote",
                "if the user wants it, they run it themselves",
            ));
        }
        if t.starts_with("--receive-pack") || t.starts_with("--exec") {
            out.push(deny_every_tier(
                "names a program for git to run as the far end of a push",
                "if the user wants it, they run it themselves",
            ));
        }
        match t {
            "-n" | "--dry-run" => dry_run = true,
            _ if t == "--force"
                || t.starts_with("--force=")
                || t.starts_with("--force-with-lease")
                || t.starts_with("--force-if-includes") =>
            {
                forced = true
            }
            _ if t.starts_with('+') && t.len() > 1 => forced = true,
            _ if t.starts_with(':') && t.len() > 1 => deleted = true,
            _ if abbrev(t, "--delete", 4) => deleted = true,
            _ if t.starts_with("--") => {}
            _ if t.starts_with('-') => {
                forced |= cluster_has(t, 'f', "o");
                deleted |= cluster_has(t, 'd', "o");
            }
            _ => {}
        }
    }
    if dry_run {
        return;
    }
    if forced {
        remote_ladder(
            "force-pushes, which discards commits on the remote branch",
            tier,
            out,
        );
    } else if deleted {
        remote_ladder(
            "deletes a branch or tag on the remote, which discards its commits there",
            tier,
            out,
        );
    }
}

/// H6: the shell code strings a git command runs (see [`inner_commands`]).
fn git_code_strings(cmd: &SimpleCommand) -> Vec<String> {
    if cmd.program() != "git" {
        return Vec::new();
    }
    let Some(walk) = git_walk(&cmd.words) else {
        return Vec::new();
    };
    let rest = walk.rest;
    match walk.sub {
        Some("submodule") => {
            let mut i = 0;
            while rest.get(i).is_some_and(|w| w.text.starts_with('-')) {
                i += 1;
            }
            if rest.get(i).map(|w| w.text.as_str()) != Some("foreach") {
                return Vec::new();
            }
            i += 1;
            while let Some(w) = rest.get(i) {
                if !w.text.starts_with('-') {
                    break;
                }
                i += 1;
                if w.text == "--" {
                    break;
                }
            }
            let Some((code, args)) = rest.get(i..).and_then(<[Word]>::split_first) else {
                return Vec::new();
            };
            // git runs `sh -c 'CMD "$@"' CMD ARG…`: CMD is code, each ARG one word.
            let mut s = code.text.clone();
            for a in args {
                s.push(' ');
                s.push_str(&shell_quote(&a.text));
            }
            vec![s]
        }
        Some("rebase") => {
            let mut out = Vec::new();
            let mut i = 0;
            while let Some(w) = rest.get(i) {
                let t = w.text.as_str();
                if t == "--" {
                    break;
                }
                let next = rest.get(i + 1).map(|w| w.text.clone());
                let value = if let Some((o, v)) = t.split_once('=') {
                    matches!(o, "--exec" | "--exe" | "--ex").then(|| v.to_string())
                } else if matches!(t, "--exec" | "--exe" | "--ex") {
                    i += 1;
                    next
                } else if let Some(cluster) = t.strip_prefix('-').filter(|c| !c.starts_with('-')) {
                    match cluster.find('x') {
                        Some(x) if cluster[..x].chars().all(|c| "iqvnfkmr".contains(c)) => {
                            if x + 1 == cluster.len() {
                                i += 1;
                                next
                            } else {
                                Some(cluster[x + 1..].to_string())
                            }
                        }
                        _ => None,
                    }
                } else {
                    None
                };
                out.extend(value);
                i += 1;
            }
            out
        }
        _ => Vec::new(),
    }
}

fn shell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

// ---- git config keys (E7) ------------------------------------------------------------------

/// Why a git invocation's config write or `-c` makes git run a program, if it does.
fn config_risk(walk: &GitWalk<'_>) -> Option<String> {
    for kv in &walk.dash_c {
        if let Some((key, value)) = kv.split_once('=') {
            if exec_key(key, value) {
                return Some(format!(
                    "runs git with -c {}, a key that names a program git runs",
                    key.to_ascii_lowercase()
                ));
            }
        }
    }
    if walk.sub != Some("config") {
        return None;
    }
    const SILENT: &[&str] = &[
        "--get",
        "--get-all",
        "--get-regexp",
        "--get-urlmatch",
        "--get-color",
        "--get-colorbool",
        "--list",
        "-l",
        "--unset",
        "--unset-all",
        "--remove-section",
    ];
    const VALUED: &[&str] = &[
        "-f",
        "--file",
        "--blob",
        "--type",
        "--default",
        "--value",
        "--comment",
    ];
    #[derive(PartialEq)]
    enum M {
        Plain,
        Write,
        Edit,
        Rename,
    }
    let mut mode = M::Plain;
    let mut ops: Vec<&str> = Vec::new();
    let mut i = 0;
    while let Some(w) = walk.rest.get(i) {
        let t = w.text.as_str();
        i += 1;
        if t.starts_with('-') && t != "-" {
            let o = t.split_once('=').map_or(t, |(o, _)| o);
            if SILENT.contains(&o) {
                return None;
            }
            match o {
                "--edit" | "-e" => mode = M::Edit,
                "--add" | "--replace-all" if mode == M::Plain => mode = M::Write,
                "--rename-section" if mode == M::Plain => mode = M::Rename,
                _ if VALUED.contains(&o) && !t.contains('=') => i += 1,
                _ => {}
            }
            continue;
        }
        ops.push(t);
    }
    let mut j = 0;
    if mode == M::Plain {
        match ops.first().copied() {
            Some("set") => (mode, j) = (M::Write, 1),
            Some("edit") => mode = M::Edit,
            Some("rename-section") => (mode, j) = (M::Rename, 1),
            Some("get" | "list" | "unset" | "unset-all" | "remove-section") => return None,
            _ => {}
        }
    }
    match mode {
        M::Edit => Some("runs git config --edit, which opens an editor on the git config".into()),
        M::Rename => {
            let to = ops.get(j + 1)?;
            let section = to.split('.').next().unwrap_or("").to_ascii_lowercase();
            EXEC_SECTIONS.contains(&section.as_str()).then(|| {
                format!("renames a git config section onto {to}, where its keys would run programs")
            })
        }
        M::Plain | M::Write => {
            let key = ops.get(j)?;
            let value = match ops.get(j + 1) {
                Some(v) => *v,
                // The bare form with no value is a read.
                None if mode == M::Plain => return None,
                None => "",
            };
            exec_key(key, value).then(|| {
                format!(
                    "writes git config {}, a key that names a program git runs",
                    key.to_ascii_lowercase()
                )
            })
        }
    }
}

/// The sections of the kit's `GITEXEC` keys, for `--rename-section`.
const EXEC_SECTIONS: &[&str] = &["alias", "core", "sequence", "credential", "diff"];

/// Whether git key `key` set to `value` names a program git runs: the kit's `GITEXEC` set (any
/// value) or the tamper gate's set.
fn exec_key(key: &str, value: &str) -> bool {
    let k = key.to_ascii_lowercase();
    let first = k.split('.').next().unwrap_or("");
    let last = k.rsplit('.').next().unwrap_or("");
    let tool_key = matches!(
        (first, last),
        ("core", "pager" | "editor") | ("sequence", "editor")
    ) || first == "pager";
    if tool_key && crate::gates::tamper::is_known_editor_or_pager(value) {
        return false;
    }
    let kit = k.contains('.')
        && (first == "alias"
            || matches!(
                (first, last),
                ("core", "pager" | "editor" | "hookspath")
                    | ("sequence", "editor")
                    | ("credential", "helper")
                    | ("diff", "external")
                    | ("man", "viewer" | "cmd" | "path")
                    | ("web", "browser")
                    | ("browser", "cmd" | "path")
            ));
    kit || crate::gates::tamper::risky_git_key(&k, value)
}

// ---- gh ----------------------------------------------------------------------------------

fn gh_deny(what: &str, fix: &str) -> Finding {
    Finding::Deny(format!(
        "safe-ai-skill gh guard: this {what}, which is denied at every tier; {fix}."
    ))
}

fn gh_findings(cmd: &SimpleCommand, tier: Tier, out: &mut Vec<Finding>) {
    let words = &cmd.words;
    let sub = words.get(1).map(|w| w.text.as_str());
    let verb = words.get(2).map(|w| w.text.as_str());
    match (sub, verb) {
        (Some("alias"), _) => out.push(gh_deny(
            "defines or runs a gh alias, which expands inside gh where no gate sees it",
            "the user manages gh aliases themselves",
        )),
        (Some(s @ ("secret" | "variable")), Some("set")) => out.push(gh_deny(
            &format!("stores a CI {s} that every later workflow run reads"),
            "if the user wants the value set, they set it themselves",
        )),
        (Some(s @ ("repo" | "issue")), Some("delete")) => out.push(gh_deny(
            &format!("deletes a GitHub {s}, which GitHub cannot undo"),
            "if the user wants it deleted, they delete it themselves",
        )),
        (Some("pr"), Some("merge")) => remote_ladder(
            "merges a pull request, landing the branch and closing the PR for everyone",
            tier,
            out,
        ),
        (Some("api"), _) => gh_api(&words[2..], tier, out),
        _ => {}
    }
}

/// A `gh api` option that takes a value.
fn gha_operand(o: &str) -> bool {
    matches!(
        o,
        "-X" | "--method"
            | "-f"
            | "--raw-field"
            | "-F"
            | "--field"
            | "--input"
            | "-H"
            | "--header"
            | "-p"
            | "--preview"
            | "-q"
            | "--jq"
            | "-t"
            | "--template"
            | "--cache"
            | "--hostname"
    )
}

#[derive(Debug, PartialEq, Eq)]
enum ApiClass {
    Secret,
    Action,
    RepoDelete,
}

fn gh_api(args: &[Word], tier: Tier, out: &mut Vec<Finding>) {
    let mut method: Option<String> = None;
    let mut body = false;
    let mut endpoints: Vec<&str> = Vec::new();
    let mut i = 0;
    while let Some(w) = args.get(i) {
        let t = w.text.as_str();
        i += 1;
        if let Some(long) = t.strip_prefix("--") {
            let (o, inline) = match long.split_once('=') {
                Some((o, v)) => (o, Some(v)),
                None => (long, None),
            };
            let o = format!("--{o}");
            if !gha_operand(&o) {
                continue;
            }
            let v = match inline {
                Some(v) => v.to_string(),
                None => {
                    i += 1;
                    args.get(i - 1).map(|w| w.text.clone()).unwrap_or_default()
                }
            };
            match o.as_str() {
                "--method" => method = Some(v),
                "--field" | "--raw-field" | "--input" => body = true,
                _ => {}
            }
            continue;
        }
        if t.len() > 1 && t.starts_with('-') {
            for (j, ch) in t[1..].char_indices() {
                if !gha_operand(&format!("-{ch}")) {
                    continue;
                }
                let attached = &t[1 + j + ch.len_utf8()..];
                let v = match attached.strip_prefix('=').unwrap_or(attached) {
                    "" => {
                        i += 1;
                        args.get(i - 1).map(|w| w.text.clone()).unwrap_or_default()
                    }
                    v => v.to_string(),
                };
                match ch {
                    'X' => method = Some(v),
                    'f' | 'F' => body = true,
                    _ => {}
                }
                break;
            }
            continue;
        }
        endpoints.push(t);
    }
    let method = method
        .unwrap_or_else(|| if body { "POST" } else { "GET" }.to_string())
        .to_ascii_uppercase();
    // A method the hook cannot read counts as a write.
    let unknown = method.contains('$') || method.contains('`');
    let write = unknown || matches!(method.as_str(), "PUT" | "POST" | "PATCH");
    let delete = unknown || method == "DELETE";
    let class = endpoints.iter().find_map(|ep| {
        let c = api_class(ep)?;
        let applies = match c {
            ApiClass::RepoDelete => delete,
            _ => write,
        };
        applies.then_some((c, *ep))
    });
    match class {
        Some((ApiClass::Secret, ep)) => out.push(gh_deny(
            &format!(
                "writes a secret or variable through gh api ({method} {ep}), which is what gh \
                 secret set and gh variable set do"
            ),
            "if the user wants the value set, they set it themselves",
        )),
        Some((ApiClass::RepoDelete, ep)) => out.push(gh_deny(
            &format!(
                "deletes a repository through gh api ({method} {ep}), which GitHub cannot undo"
            ),
            "if the user wants it deleted, they delete it themselves",
        )),
        Some((ApiClass::Action, ep)) if tier < Tier::Medium => out.push(Finding::Ask(format!(
            "safe-ai-skill gh guard: this dispatches a workflow, creates a deployment or changes \
             an environment through gh api ({method} {ep}); confirm the repository, the workflow \
             or environment and the ref before approving."
        ))),
        _ => {}
    }
    if tier >= Tier::Medium {
        out.push(Finding::Deny(format!(
            "safe-ai-skill gh guard: the {} tier denies gh api, the raw escape hatch around every \
             narrower gh rule; use gh pr, gh issue, gh run or gh repo view, or lower the tier.",
            tier.label()
        )));
    }
}

/// Classify a `gh api` endpoint by its path past the owner and repository.
fn api_class(endpoint: &str) -> Option<ApiClass> {
    let mut p = endpoint.to_ascii_lowercase();
    if let Some(at) = p.find("://") {
        let after = &p[at + 3..];
        p = after
            .find('/')
            .map_or(String::new(), |s| after[s..].to_string());
    }
    if let Some(q) = p.find(['?', '#']) {
        p.truncate(q);
    }
    let p = p.trim_start_matches('/');
    let p = p.strip_prefix("api/v3/").unwrap_or(p);
    let seg: Vec<&str> = p.split('/').filter(|s| !s.is_empty()).collect();
    let (start, alt) = match seg.first().copied() {
        Some("repos") => {
            let expanded = seg.get(1).is_some_and(|s| s.contains('$'))
                || seg.get(2).is_some_and(|s| s.contains('$'));
            // `repos/O/R` exactly is the repository itself.
            if seg.len() == 3 || (expanded && seg.len() == 2) {
                return Some(ApiClass::RepoDelete);
            }
            (3, expanded.then_some(2))
        }
        Some("repositories" | "orgs") => (2, None),
        Some("user") => (1, None),
        _ => return None,
    };
    rest_class(&seg, start).or_else(|| alt.and_then(|a| rest_class(&seg, a)))
}

fn rest_class(seg: &[&str], s: usize) -> Option<ApiClass> {
    let at = |k: usize| seg.get(s + k).copied().unwrap_or("");
    let (a, b, c, d) = (at(0), at(1), at(2), at(3));
    if matches!(a, "actions" | "dependabot" | "codespaces") && matches!(b, "secrets" | "variables")
    {
        return Some(ApiClass::Secret);
    }
    if a == "environments" && matches!(c, "secrets" | "variables") {
        return Some(ApiClass::Secret);
    }
    if matches!(a, "dispatches" | "deployments" | "environments")
        || (a == "actions" && b == "workflows" && d == "dispatches")
        || (a == "pages" && b == "deployments")
    {
        return Some(ApiClass::Action);
    }
    None
}

// ---- git configuration through the environment (E10, E11) --------------------------------

/// `-c` by another name: denied at every tier.
fn env_hard(name: &str) -> bool {
    let numbered = |p: &str| {
        name.strip_prefix(p)
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
    };
    matches!(
        name,
        "GIT_CONFIG_COUNT" | "GIT_CONFIG_PARAMETERS" | "GIT_EXEC_PATH"
    ) || numbered("GIT_CONFIG_KEY_")
        || numbered("GIT_CONFIG_VALUE_")
}

/// Names a program git runs, but is ordinary work below High: asked at High.
fn env_soft(name: &str) -> bool {
    matches!(
        name,
        "GIT_SSH_COMMAND"
            | "GIT_SSH"
            | "GIT_PROXY_COMMAND"
            | "GIT_EXTERNAL_DIFF"
            | "GIT_ASKPASS"
            | "GIT_TEMPLATE_DIR"
    )
}

/// One word of the environment scan: its text with quotes removed, and the byte offset in that
/// text where quoting first began (an assignment's name must be unquoted).
struct EnvWord {
    text: String,
    quoted_at: Option<usize>,
}

impl EnvWord {
    fn assignment(&self) -> Option<&str> {
        let eq = self.text.find('=')?;
        if self.quoted_at.is_some_and(|q| q < eq) {
            return None;
        }
        let name = &self.text[..eq];
        let name = name.strip_suffix('+').unwrap_or(name);
        let mut chars = name.chars();
        let first = chars.next()?;
        ((first.is_ascii_alphabetic() || first == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_'))
        .then_some(name)
    }
}

/// Split `text` into statements of words, the way a shell would at the top level (quotes,
/// escapes, comments and here-document bodies honored). The text of `$(…)` and backtick
/// substitutions is returned separately for its own scan.
fn env_statements(text: &str) -> (Vec<Vec<EnvWord>>, Vec<String>) {
    let chars: Vec<char> = text.chars().collect();
    let mut stmts: Vec<Vec<EnvWord>> = vec![Vec::new()];
    let mut nested = Vec::new();
    let mut cur = String::new();
    let mut quoted_at: Option<usize> = None;
    let mut in_word = false;
    let mut heredocs: Vec<(String, bool)> = Vec::new();
    let mut i = 0;
    macro_rules! end_word {
        () => {
            if in_word {
                if let Some(s) = stmts.last_mut() {
                    s.push(EnvWord {
                        text: std::mem::take(&mut cur),
                        quoted_at: quoted_at.take(),
                    });
                }
                in_word = false;
            }
        };
    }
    while i < chars.len() {
        let c = chars[i];
        match c {
            ' ' | '\t' | '\r' => {
                end_word!();
                i += 1;
            }
            '\n' | ';' | '&' | '|' | '(' | ')' => {
                end_word!();
                stmts.push(Vec::new());
                i += 1;
                if c == '\n' {
                    // Skip here-document bodies.
                    for (delim, dash) in std::mem::take(&mut heredocs) {
                        loop {
                            let start = i;
                            while i < chars.len() && chars[i] != '\n' {
                                i += 1;
                            }
                            let line: String = chars[start..i].iter().collect();
                            i = (i + 1).min(chars.len());
                            let line = if dash {
                                line.trim_start_matches('\t')
                            } else {
                                &line
                            };
                            if line == delim || i >= chars.len() {
                                break;
                            }
                        }
                    }
                }
            }
            '#' if !in_word => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '\\' => {
                if chars.get(i + 1) == Some(&'\n') {
                    i += 2;
                    continue;
                }
                quoted_at.get_or_insert(cur.len());
                if let Some(&n) = chars.get(i + 1) {
                    cur.push(n);
                }
                in_word = true;
                i += 2;
            }
            '\'' => {
                quoted_at.get_or_insert(cur.len());
                in_word = true;
                i += 1;
                while i < chars.len() && chars[i] != '\'' {
                    cur.push(chars[i]);
                    i += 1;
                }
                i += 1;
            }
            '"' => {
                quoted_at.get_or_insert(cur.len());
                in_word = true;
                i += 1;
                while i < chars.len() && chars[i] != '"' {
                    if chars[i] == '\\' && i + 1 < chars.len() {
                        i += 1;
                    }
                    cur.push(chars[i]);
                    i += 1;
                }
                i += 1;
            }
            '$' if chars.get(i + 1) == Some(&'\'') => {
                quoted_at.get_or_insert(cur.len());
                in_word = true;
                i += 2;
                while i < chars.len() && chars[i] != '\'' {
                    if chars[i] == '\\' && i + 1 < chars.len() {
                        cur.push(chars[i]);
                        i += 1;
                    }
                    cur.push(chars[i]);
                    i += 1;
                }
                i += 1;
            }
            '`' | '$' if c == '`' || chars.get(i + 1) == Some(&'(') => {
                // A substitution stays inside its word; its text is scanned on its own.
                let tick = c == '`';
                let start = if tick { i + 1 } else { i + 2 };
                let mut j = start;
                let mut depth = 1usize;
                while j < chars.len() {
                    match chars[j] {
                        '`' if tick => break,
                        '(' if !tick => depth += 1,
                        ')' if !tick => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    j += 1;
                }
                nested.push(chars[start..j.min(chars.len())].iter().collect());
                cur.push('$');
                in_word = true;
                i = j + 1;
            }
            '<' if chars.get(i + 1) == Some(&'<') && chars.get(i + 2) != Some(&'<') => {
                end_word!();
                i += 2;
                let dash = chars.get(i) == Some(&'-');
                if dash {
                    i += 1;
                }
                while matches!(chars.get(i), Some(' ' | '\t')) {
                    i += 1;
                }
                let mut delim = String::new();
                while let Some(&d) = chars.get(i) {
                    if d.is_whitespace() || matches!(d, ';' | '&' | '|' | '(' | ')' | '<' | '>') {
                        break;
                    }
                    if !matches!(d, '\'' | '"' | '\\') {
                        delim.push(d);
                    }
                    i += 1;
                }
                if !delim.is_empty() {
                    heredocs.push((delim, dash));
                }
            }
            _ => {
                cur.push(c);
                in_word = true;
                i += 1;
            }
        }
    }
    if in_word {
        if let Some(s) = stmts.last_mut() {
            s.push(EnvWord {
                text: cur,
                quoted_at,
            });
        }
    }
    (stmts, nested)
}

/// Reserved words that may stand before a command (`lib-tokenize.awk` `kit_reserved`).
fn reserved(word: &str) -> bool {
    matches!(
        word,
        "!" | "{"
            | "}"
            | "if"
            | "then"
            | "else"
            | "elif"
            | "fi"
            | "do"
            | "done"
            | "while"
            | "until"
            | "time"
    )
}

/// A wrapper option of `env`, `sudo` or `doas` that takes the next word.
fn wrapper_optarg(program: &str, o: &str) -> bool {
    match program {
        "env" => matches!(
            o,
            "-u" | "--unset" | "-C" | "--chdir" | "-S" | "--split-string"
        ),
        "sudo" => matches!(
            o,
            "-u" | "-g"
                | "-C"
                | "-D"
                | "-h"
                | "-p"
                | "-r"
                | "-t"
                | "-U"
                | "-T"
                | "--user"
                | "--group"
        ),
        "doas" => matches!(o, "-u" | "-C"),
        _ => false,
    }
}

/// E10/E11: git configuration set through the environment, in front of a command, after
/// `export` and its kin, or among the assignments `env`, `sudo` and `doas` take; and in the
/// code of `sh -c`, `eval` and substitutions.
fn env_scan(text: &str, tier: Tier, depth: usize, out: &mut Vec<Finding>) {
    if depth > MAX_DEPTH || !text.contains("GIT_") {
        return;
    }
    let (stmts, nested) = env_statements(text);
    let mut names: Vec<String> = Vec::new();
    let mut codes: Vec<String> = nested;
    for st in &stmts {
        let mut i = 0;
        while let Some(w) = st.get(i) {
            if let Some(n) = w.assignment() {
                names.push(n.to_string());
            } else if !(w.quoted_at.is_none() && reserved(&w.text)) {
                break;
            }
            i += 1;
        }
        let Some(c) = st.get(i) else { continue };
        let program = base_name(&c.text);
        i += 1;
        match program.as_str() {
            "export" | "declare" | "typeset" | "local" | "readonly" => {
                names.extend(
                    st[i..]
                        .iter()
                        .filter_map(|w| w.assignment().map(String::from)),
                );
            }
            "env" | "sudo" | "doas" => {
                while let Some(w) = st.get(i) {
                    if w.text.starts_with('-') {
                        i += if wrapper_optarg(&program, &w.text) {
                            2
                        } else {
                            1
                        };
                        continue;
                    }
                    match w.assignment() {
                        Some(n) => names.push(n.to_string()),
                        None => break,
                    }
                    i += 1;
                }
            }
            "eval" => {
                let code: Vec<&str> = st[i..].iter().map(|w| w.text.as_str()).collect();
                codes.push(code.join(" "));
            }
            p if SHELLS.contains(&p) => {
                let mut c_flag = false;
                while let Some(w) = st.get(i) {
                    let t = w.text.as_str();
                    if t == "-o" || t == "+o" {
                        i += 2;
                        continue;
                    }
                    if t.starts_with('-') || t.starts_with('+') {
                        c_flag |= t.len() > 1 && !t.starts_with("--") && t[1..].contains('c');
                        i += 1;
                        continue;
                    }
                    if c_flag {
                        codes.push(w.text.clone());
                    }
                    break;
                }
            }
            _ => {}
        }
    }
    if let Some(n) = names.iter().find(|n| env_hard(n)) {
        let what = if n == "GIT_EXEC_PATH" {
            "sets GIT_EXEC_PATH, which is git --exec-path= by another name".to_string()
        } else {
            format!("sets {n}, which is git -c by another name and can make any git command run a program")
        };
        out.push(deny_every_tier(
            &what,
            "if the user needs it set, they set it themselves",
        ));
    } else if tier == Tier::High {
        if let Some(n) = names.iter().find(|n| env_soft(n)) {
            out.push(Finding::Ask(format!(
                "safe-ai-skill git guard: this sets {n}, which names a program git runs; the \
                 high tier asks, so confirm the program before approving."
            )));
        }
    }
    for code in codes {
        env_scan(&code, tier, depth + 1, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(cmd: &str, tier: Tier) -> &'static str {
        match decide(cmd, Path::new("."), &Policy::default(), tier) {
            Some(Verdict::Deny(_)) => "D",
            Some(Verdict::Ask(_)) => "A",
            _ => "-",
        }
    }

    fn row(cmd: &str, want: [&str; 4]) {
        let got: Vec<&str> = Tier::ALL.iter().map(|&t| d(cmd, t)).collect();
        assert_eq!(got, want, "{cmd}");
    }

    #[test]
    fn usability_floor_is_silent_at_every_tier_but_gh_api() {
        for cmd in [
            "git push origin main",
            "git push -u origin feat/x",
            "git push --follow-tags",
            "git commit -m 'git clean -fdx; gh secret set X'",
            "git pull --rebase=false",
            "git status && git diff",
            "gh pr create --fill",
            "gh pr view 12",
            "gh run view 99 --log",
            "git log --oneline -5",
            "git reset HEAD file",
            "git branch --sort=-date",
            "git config --get core.pager",
            "git checkout main",
            "echo gh api repos/o/r/actions/secrets/X -X PUT",
        ] {
            row(cmd, ["-", "-", "-", "-"]);
        }
    }

    #[test]
    fn force_push_and_merge_ladder() {
        for cmd in [
            "git push --force",
            "git push -f origin main",
            "git push -uf origin main",
            "git push origin +main",
            "git push --force-with-lease",
            "git -P push --force",
            "nice git push \\\n --force",
            "gh pr merge 3 --squash",
        ] {
            row(cmd, ["-", "-", "A", "D"]);
        }
        row("git push --force --dry-run", ["-", "-", "-", "-"]);
    }

    #[test]
    fn recoverable_rewrites_ask_at_high() {
        for cmd in [
            "git rebase -i HEAD~3",
            "git commit --amend --no-edit",
            "git stash drop",
            "git branch -D old",
            "git branch -Df old",
            "git tag -d v1",
            "git filter-repo --path x",
        ] {
            row(cmd, ["-", "-", "-", "A"]);
        }
        row("git rebase --continue", ["-", "-", "-", "-"]);
    }

    #[test]
    fn unrecoverable_git_denies_everywhere() {
        for cmd in [
            "git clean -fdx",
            "git clean",
            "git --no-pager clean -fd",
            "git -C . restore .",
            "git checkout -- .",
            "git reset --ha HEAD",
            "git reflog expire --all",
            "git prune",
            "git gc --prune=now",
            "git push --mirror",
            "git fetch --upload-pack=/tmp/x.sh .",
            "git push --receive-pack=/tmp/x origin",
            "git clone -u /tmp/x.sh repo",
            "git --config-env=core.fsmonitor=X status",
            "git --exec-path=/tmp ls-remote https://x",
            "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.pager GIT_CONFIG_VALUE_0=x git log",
            "export GIT_CONFIG_PARAMETERS=\"'core.pager=x'\"; git log",
            "env -u X GIT_EXEC_PATH=/tmp git status",
            "sh -c 'GIT_CONFIG_COUNT=1 git log'",
            "git submodule foreach 'git clean -fdx'",
            "git rebase -x 'git reset --hard' main",
            "gh secret set TOKEN < t",
            "gh variable set X --body y",
            "gh repo delete o/r --yes",
            "gh issue delete 4",
            "gh alias set co 'pr checkout'",
            "gh api -X PUT repos/o/r/actions/secrets/T -f encrypted_value=x",
            "gh api --method DELETE /repos/o/r",
        ] {
            row(cmd, ["D", "D", "D", "D"]);
        }
        row("git gc --no-prune", ["-", "-", "-", "-"]);
        row("git reflog show", ["-", "-", "-", "-"]);
        row("git --exec-path", ["-", "-", "-", "-"]);
    }

    #[test]
    fn env_program_vars_ask_at_high_and_heredocs_are_data() {
        row("GIT_SSH_COMMAND='ssh -i k' git fetch", ["-", "-", "-", "A"]);
        row(
            "cat > n.md <<'EOF'\nGIT_CONFIG_COUNT=1\nEOF",
            ["-", "-", "-", "-"],
        );
        row("echo 'GIT_EXEC_PATH=/tmp'", ["-", "-", "-", "-"]);
    }

    #[test]
    fn gh_api_actions_ask_then_deny_and_any_api_denies_from_medium() {
        row(
            "gh api repos/o/r/actions/workflows/1/dispatches -f ref=main",
            ["A", "A", "D", "D"],
        );
        row("gh api repos/o/r/pulls", ["-", "-", "D", "D"]);
        row(
            "gh api repos/o/r/issues/1/comments -f body=hi",
            ["-", "-", "D", "D"],
        );
        row("gh api repos/o/r", ["-", "-", "D", "D"]);
    }

    #[test]
    fn config_risk_denies_from_medium() {
        let v = |c: &str, t: Tier| decide_git_config_risk(c, t).map(|v| v.label());
        for cmd in [
            "git config core.hooksPath .h",
            "git config --global alias.co checkout",
            "git config set core.pager /tmp/p",
            "git config --edit",
            "git -c core.fsmonitor=/tmp/x status",
            "git config --rename-section foo core",
        ] {
            assert_eq!(v(cmd, Tier::Relaxed), Some("ask"), "{cmd}");
            assert_eq!(v(cmd, Tier::Medium), Some("deny"), "{cmd}");
            assert_eq!(d(cmd, Tier::High), "D", "{cmd}");
        }
        for cmd in [
            "git config core.pager",
            "git config set core.pager less",
            "git -c core.editor=true rebase --continue",
            "git config user.name x",
            "git config -l",
        ] {
            assert_eq!(v(cmd, Tier::High), None, "{cmd}");
        }
    }

    #[test]
    fn inner_commands_are_returned() {
        assert_eq!(
            inner_commands("git submodule foreach --recursive 'git push --force'"),
            vec!["git push --force".to_string()]
        );
        assert_eq!(
            inner_commands("git rebase --exec 'make test' -x\"npm publish\" --exec=ls main"),
            vec!["make test", "npm publish", "ls"]
        );
        assert_eq!(
            inner_commands("git submodule foreach echo a b"),
            vec!["echo 'a' 'b'".to_string()]
        );
        assert!(inner_commands("git rebase -i main").is_empty());
    }

    #[test]
    fn prefilter() {
        assert!(!may_concern("cargo build --release"));
        assert!(!may_concern("echo high"));
        assert!(may_concern("GIT_SSH=x make"));
        assert!(may_concern("/usr/bin/gh api x"));
        assert!(may_concern("command gh"));
    }
}
