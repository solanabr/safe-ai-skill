//! Enforcement of blocked skill packs without moving them (spec D2.6).
//!
//! - `Skill` (PreToolUse) and a typed `/name` (`UserPromptExpansion`, or a raw `/name` in
//!   `UserPromptSubmit`): the name is mapped to every swept pack providing it (its directory
//!   name or a `SKILL.md` name), each is re-hashed and re-graded on the spot (a mid-session
//!   edit is drift), and the call is denied when any of them is blocked. A typed `/name`
//!   never reaches the Skill tool, so both prompt-time events are needed.
//! - Read: denied when the file resolves inside a blocked pack. Grep/Glob: denied when the
//!   search root lies inside a blocked pack or contains one.
//! - Verifying a skill's packs is bounded by [`SKILL_BUDGET`]; an overrun denies, and the
//!   Skill hook is wired `onFailure: block`, so a crash or timeout never fails open.
//! - Bash (best effort): every word of every command segment is resolved against the hook
//!   `cwd`, following each `cd`/`pushd` in order and expanding globs; denied when one lands
//!   inside a blocked pack, or when a command runs with its working dir inside one.
//!
//! The read and Bash checks only consult the stored state (no hashing), so they stay cheap.

use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::Value;

use super::state::{self, PackStatus, State};
use super::{expand_home, grading, project_root, swept_packs, Env, Scanner, USER_SKILLS_DIR};
use crate::datadir::DataDir;
use crate::gate::Verdict;
use crate::policy::Policy;

/// Time the Skill and slash gates may spend re-hashing packs before denying.
const SKILL_BUDGET: Duration = Duration::from_secs(5);
/// Bytes of an unreadable prompt payload searched for a slash command.
const RAW_HEAD_BYTES: usize = 64 * 1024;
/// Glob matches examined per word.
const MAX_GLOB_MATCHES: usize = 512;
/// Words examined per command.
const MAX_WORDS: usize = 4096;

/// A blocked pack as the gates see it.
struct BlockedPack {
    /// Canonical paths whose contents are denied (the pack, and where `on_block: move` put it).
    roots: Vec<PathBuf>,
    /// Shown in the denial.
    shown: String,
    /// Why it is blocked.
    why: &'static str,
}

/// Every blocked pack in `st`.
fn blocked_packs(st: &State) -> Vec<BlockedPack> {
    st.packs
        .iter()
        .filter(|(_, e)| e.state == PackStatus::Blocked)
        .map(|(key, e)| {
            let mut roots = vec![state::path_of(key)];
            roots.extend(e.quarantined_to.iter().map(PathBuf::from));
            BlockedPack {
                roots,
                shown: key.clone(),
                why: why_label(e.reason),
            }
        })
        .collect()
}

fn why_label(reason: Option<state::Reason>) -> &'static str {
    match reason {
        Some(state::Reason::Drift) => "its content changed since it was pinned",
        Some(state::Reason::LockMismatch) => "it does not match the project's packs.lock",
        Some(state::Reason::Combo) => "a combination rule fired",
        _ => "it is blocked",
    }
}

fn denial(subject: &str, shown: &str, why: &str) -> Verdict {
    Verdict::Deny(format!(
        "safe-ai-skill: {subject} the skill pack {shown}, which is blocked ({why}). The user \
         must review it and run `safe-ai-skill verify approve {shown}` in a terminal, then \
         confirm it."
    ))
}

/// The directories a hook's packs are looked up under: the hook `cwd`, its repository root,
/// and `CLAUDE_PROJECT_DIR`.
fn project_dirs(cwd: &Path) -> Vec<PathBuf> {
    let mut dirs = vec![cwd.to_path_buf(), project_root(cwd)];
    if let Some(p) = std::env::var_os("CLAUDE_PROJECT_DIR").filter(|p| !p.is_empty()) {
        dirs.push(PathBuf::from(p));
    }
    let mut out: Vec<PathBuf> = Vec::new();
    for d in dirs {
        let c = d.canonicalize().unwrap_or(d);
        if !out.contains(&c) {
            out.push(c);
        }
    }
    out
}

/// The names a `Skill` / slash invocation may refer to: `x`, and `y` for a namespaced `x:y`.
fn skill_candidates(skill: &str) -> Vec<String> {
    let name = skill.trim().trim_start_matches('/');
    if name.is_empty() {
        return Vec::new();
    }
    let mut out = vec![name.to_string()];
    if let Some((_, local)) = name.rsplit_once(':') {
        if !local.is_empty() {
            out.push(local.to_string());
        }
    }
    out
}

/// PreToolUse `Skill` / slash enforcement: deny when any pack providing `skill` is blocked
/// after re-hashing it (TOCTOU).
pub fn skill_verdict(dir: &DataDir, cwd: &Path, policy: &Policy, skill: &str) -> Verdict {
    skill_verdict_in(
        dir,
        cwd,
        &expand_home(USER_SKILLS_DIR),
        policy,
        skill,
        grading::scan_pack,
        SKILL_BUDGET,
    )
}

/// [`skill_verdict`] with an explicit user skills dir, scanner and time budget.
pub(super) fn skill_verdict_in(
    dir: &DataDir,
    cwd: &Path,
    user_skills: &Path,
    policy: &Policy,
    skill: &str,
    scanner: Scanner,
    budget: Duration,
) -> Verdict {
    let wanted = skill_candidates(skill);
    if wanted.is_empty() {
        return Verdict::NoOpinion;
    }
    let is_wanted = |n: &str| wanted.iter().any(|w| w.eq_ignore_ascii_case(n));
    let deadline = Instant::now() + budget;
    let mut st = state::load(dir).state;
    let mut seen: Vec<String> = Vec::new();
    let mut blocked: Option<(String, &'static str)> = None;
    // Blocked packs whose names may be incomplete (unparseable frontmatter).
    let mut unsure_blocked: Option<String> = None;
    for project in project_dirs(cwd) {
        let env = Env::new(dir, &project, user_skills, scanner);
        for pack in swept_packs(&project, user_skills, policy, &env.v1) {
            if Instant::now() >= deadline {
                return over_budget(skill);
            }
            let key = state::key_of(&pack.canonical);
            if seen.contains(&key) {
                continue;
            }
            // Current names (a mid-session rename counts) united with the recorded ones.
            let current = state::skill_names_checked(&pack.canonical);
            let stored = st.packs.get(&key);
            let provides = is_wanted(&pack.name)
                || current.names.iter().any(|n| is_wanted(n))
                || stored.is_some_and(|e| e.names.iter().any(|n| is_wanted(n)));
            if !provides {
                if current.unparseable
                    && stored.is_some_and(|e| e.state == PackStatus::Blocked)
                    && unsure_blocked.is_none()
                {
                    unsure_blocked = Some(pack.display.clone());
                }
                continue;
            }
            seen.push(key.clone());
            let Some(ev) = super::evaluate(&mut st, &pack, &env, Some(deadline)) else {
                return over_budget(skill);
            };
            if let Some(e) = st.packs.get(&ev.key) {
                if e.state == PackStatus::Blocked && blocked.is_none() {
                    blocked = Some((pack.display.clone(), why_label(e.reason)));
                }
            }
        }
    }
    if !seen.is_empty() {
        let _ = state::store(dir, &st);
    }
    match (blocked, unsure_blocked) {
        (Some((shown, why)), _) => denial(&format!("skill `{skill}` comes from"), &shown, why),
        (None, Some(shown)) if seen.is_empty() => denial(
            &format!("skill `{skill}` matches no verified pack, and it may come from"),
            &shown,
            "its SKILL.md frontmatter does not parse, so its skill names are unknown",
        ),
        _ => Verdict::NoOpinion,
    }
}

/// The denial when verifying a skill's packs overran [`SKILL_BUDGET`].
fn over_budget(skill: &str) -> Verdict {
    Verdict::Deny(format!(
        "safe-ai-skill: the packs providing skill `{skill}` could not be verified within {} s; \
         the call is denied. Run `safe-ai-skill verify session` to inspect them.",
        SKILL_BUDGET.as_secs()
    ))
}

/// The raw head of an unreadable prompt-time payload: the slash command it names, if any.
///
/// `Some(Some(name))` when a `command_name` or a prompt starting with `/` is found,
/// `Some(None)` when the payload may be a slash command whose name cannot be read, and `None`
/// when it is plainly not one.
pub fn slash_name_from_raw(raw: &[u8]) -> Option<Option<String>> {
    let head = String::from_utf8_lossy(&raw[..raw.len().min(RAW_HEAD_BYTES)]);
    // The string value of `key`, up to its closing quote or the end of what was read.
    let value_of = |key: &str| -> Option<String> {
        let at = head.find(key)? + key.len();
        let rest = head[at..].trim_start().strip_prefix(':')?.trim_start();
        let rest = rest.strip_prefix('"')?;
        Some(rest.split('"').next().unwrap_or("").to_string())
    };
    if let Some(name) = value_of("\"command_name\"") {
        let name = name.trim();
        return Some((!name.is_empty()).then(|| name.to_string()));
    }
    match value_of("\"prompt\"") {
        Some(prompt) => {
            let rest = prompt.trim_start().strip_prefix('/')?;
            Some(rest.split_whitespace().next().map(String::from))
        }
        None => Some(None),
    }
}

/// Block reason for a prompt-time payload the engine could not parse: block a slash command
/// whose skill is blocked, and one whose name cannot be read while any pack in scope is blocked.
pub fn unreadable_prompt_verdict(
    dir: &DataDir,
    cwd: &Path,
    policy: &Policy,
    raw: &[u8],
) -> Option<String> {
    let reason = |v: Verdict| match v {
        Verdict::Deny(r) | Verdict::Ask(r) => Some(r),
        _ => None,
    };
    match slash_name_from_raw(raw)? {
        Some(name) => reason(skill_verdict(dir, cwd, policy, &name)),
        None => {
            let st = state::load(dir).state;
            let scope = project_dirs(cwd);
            let blocked = blocked_packs(&st).into_iter().find(|b| {
                b.roots
                    .iter()
                    .any(|r| scope.iter().any(|p| r.starts_with(p)))
            })?;
            Some(format!(
                "safe-ai-skill: this prompt could not be read, and the skill pack {} is \
                 blocked ({}); retry with a shorter prompt.",
                blocked.shown, blocked.why
            ))
        }
    }
}

/// The skill a prompt-time hook payload invokes: `command_name` of a `UserPromptExpansion`
/// slash command, or the first word of a `UserPromptSubmit` prompt that starts with `/`.
pub fn slash_skill_name(payload: &Value) -> Option<String> {
    match payload.get("hook_event_name").and_then(Value::as_str)? {
        "UserPromptExpansion" => {
            if payload.get("expansion_type").and_then(Value::as_str) != Some("slash_command") {
                return None;
            }
            let name = payload.get("command_name").and_then(Value::as_str)?;
            (!name.trim().is_empty()).then(|| name.trim().to_string())
        }
        "UserPromptSubmit" => {
            let prompt = payload.get("prompt").and_then(Value::as_str)?.trim_start();
            let rest = prompt.strip_prefix('/')?;
            let name = rest.split_whitespace().next()?;
            (!name.is_empty()).then(|| name.to_string())
        }
        _ => None,
    }
}

/// Read/Grep/Glob enforcement: deny a Read whose file resolves inside a blocked pack, and a
/// Grep or Glob whose search root (`path`, else the hook `cwd`, narrowed by the literal prefix
/// of a Glob `pattern` or a Grep `glob`) lies inside a blocked pack or contains one.
pub fn read_verdict(dir: &DataDir, tool_name: &str, tool_input: &Value, cwd: &Path) -> Verdict {
    let st = state::load(dir).state;
    let blocked = blocked_packs(&st);
    if blocked.is_empty() {
        return Verdict::NoOpinion;
    }
    let field = |k: &str| tool_input.get(k).and_then(Value::as_str);
    for target in ["file_path", "notebook_path"]
        .iter()
        .filter_map(|k| field(k))
        .map(|p| absolute(cwd, p))
    {
        if let Some(b) = inside_blocked(&target, &blocked) {
            return denial(&format!("{} is inside", target.display()), &b.shown, b.why);
        }
    }
    let search = match tool_name {
        "Glob" => Some(field("pattern")),
        "Grep" => Some(field("glob").filter(|g| g.contains('/'))),
        "Read" | "NotebookRead" => None,
        // Anything else that names a path is checked like a search.
        _ => field("path").map(|_| None),
    };
    let Some(narrow) = search else {
        return Verdict::NoOpinion;
    };
    let mut root = field("path")
        .map(|p| absolute(cwd, p))
        .unwrap_or_else(|| cwd.to_path_buf());
    if let Some(pattern) = narrow.filter(|p| !p.starts_with(['!', '*'])) {
        let literal: Vec<&str> = pattern
            .split('/')
            .take_while(|c| !c.contains(['*', '?', '[', '{']))
            .collect();
        if !literal.is_empty() {
            root = absolute(&root, &literal.join("/"));
        }
    }
    if let Some(b) = inside_blocked(&root, &blocked).or_else(|| contains_blocked(&root, &blocked)) {
        return denial(
            &format!("this search of {} reaches", root.display()),
            &b.shown,
            b.why,
        );
    }
    Verdict::NoOpinion
}

/// The blocked pack that lies inside the directory `root`.
fn contains_blocked<'a>(root: &Path, blocked: &'a [BlockedPack]) -> Option<&'a BlockedPack> {
    let mut forms = vec![lenient_canonical(root)];
    if let Ok(real) = root.canonicalize() {
        forms.push(real);
    }
    blocked.iter().find(|b| {
        b.roots
            .iter()
            .any(|r| forms.iter().any(|f| r.starts_with(f)))
    })
}

/// Bash enforcement (best effort): deny when a word of the command resolves inside a blocked
/// pack, or a command runs with its working dir inside one.
pub fn bash_verdict(dir: &DataDir, command: &str, cwd: &Path) -> Verdict {
    let st = state::load(dir).state;
    let blocked = blocked_packs(&st);
    if blocked.is_empty() {
        return Verdict::NoOpinion;
    }
    let home = super::home_dir();
    let mut wd = cwd.to_path_buf();
    let mut words_seen = 0usize;
    for segment in segments(command) {
        // A quoted inner command (`sh -c 'cd x; …'`) is split at its `;` by [`segments`], so
        // its words may hold spaces: each piece counts as a word of its own.
        let words: Vec<String> = crate::context::tokenize(&segment)
            .iter()
            .flat_map(|w| w.split_whitespace().map(String::from).collect::<Vec<_>>())
            .map(|w| clean_word(&w))
            .filter(|w| !w.is_empty())
            .collect();
        if words.is_empty() {
            continue;
        }
        if let Some(b) = inside_blocked(&wd, &blocked) {
            return denial("this command runs inside", &b.shown, b.why);
        }
        let mut i = 0;
        while i < words.len() {
            let word = &words[i];
            i += 1;
            words_seen += 1;
            if words_seen > MAX_WORDS {
                return Verdict::NoOpinion;
            }
            if matches!(word.as_str(), "cd" | "pushd") {
                // Options (`-P`, `-L`, `--`, …) come before the target; `-` alone is one.
                while words.get(i).is_some_and(|w| w.starts_with('-') && w != "-") {
                    i += 1;
                }
                let target = words.get(i).map(String::as_str);
                wd = match target {
                    None => home.clone().unwrap_or(wd),
                    Some("-") => wd,
                    Some(t) => expand(&wd, t, home.as_deref())
                        .into_iter()
                        .next()
                        .unwrap_or_else(|| absolute(&wd, t)),
                };
                i += 1;
                if let Some(b) = inside_blocked(&wd, &blocked) {
                    return denial("this command enters", &b.shown, b.why);
                }
                continue;
            }
            // `--opt=path` and `VAR=path` carry the path after the `=`.
            let candidate = match word.split_once('=') {
                Some((lhs, rhs)) if lhs.starts_with('-') || is_var_name(lhs) => rhs,
                _ => word.as_str(),
            };
            for path in expand(&wd, candidate, home.as_deref()) {
                if let Some(b) = inside_blocked(&path, &blocked) {
                    return denial(
                        &format!("this command touches {}, inside", path.display()),
                        &b.shown,
                        b.why,
                    );
                }
            }
        }
    }
    Verdict::NoOpinion
}

/// A shell word with grouping and quoting characters removed (`$`, `{`, `}` are kept, so
/// `$HOME` and `${HOME}` still expand) and a leading redirection operator dropped.
fn clean_word(word: &str) -> String {
    let w: String = word
        .chars()
        .filter(|c| !matches!(c, '(' | ')' | '`' | '\'' | '"'))
        .collect();
    let ops = w
        .trim_start_matches(|c: char| c.is_ascii_digit() || c == '&')
        .trim_start_matches(['<', '>']);
    // Only a real redirection (`<f`, `>f`, `2>f`, `&>f`) loses its prefix.
    if ops.len()
        < w.trim_start_matches(|c: char| c.is_ascii_digit() || c == '&')
            .len()
    {
        ops.to_string()
    } else {
        w
    }
}

/// Command segments, split on newlines, `;`, `&`, `|` (so `&&` and `||` too), anywhere: a
/// quoted `sh -c 'cd x; sh y'` is split as well, which can only add candidate paths.
fn segments(command: &str) -> Vec<String> {
    command
        .split(['\n', ';', '&', '|'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

fn is_var_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !s.starts_with(|c: char| c.is_ascii_digit())
}

/// The paths `word` may name from `wd`: `~`/`$HOME` expanded, globs expanded (capped).
fn expand(wd: &Path, word: &str, home: Option<&Path>) -> Vec<PathBuf> {
    let word = match home {
        Some(h) => {
            if word == "~" || word == "$HOME" || word == "${HOME}" {
                h.to_string_lossy().into_owned()
            } else if let Some(rest) = word
                .strip_prefix("~/")
                .or_else(|| word.strip_prefix("$HOME/"))
                .or_else(|| word.strip_prefix("${HOME}/"))
            {
                h.join(rest).to_string_lossy().into_owned()
            } else {
                word.to_string()
            }
        }
        None => word.to_string(),
    };
    let path = absolute(wd, &word);
    if !word.contains(['*', '?', '[']) {
        return vec![path];
    }
    match glob::glob(&path.to_string_lossy()) {
        Ok(paths) => paths.flatten().take(MAX_GLOB_MATCHES).collect(),
        Err(_) => vec![path],
    }
}

/// `p` resolved against `base` when relative.
fn absolute(base: &Path, p: &str) -> PathBuf {
    let path = Path::new(p);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

/// The blocked pack `path` lies inside, judged both by the real path (symlinks resolved) and by
/// the lexically normalized path resolved through its deepest existing ancestor.
fn inside_blocked<'a>(path: &Path, blocked: &'a [BlockedPack]) -> Option<&'a BlockedPack> {
    let mut forms = vec![lenient_canonical(path)];
    if let Ok(real) = path.canonicalize() {
        forms.push(real);
    }
    blocked.iter().find(|b| {
        forms
            .iter()
            .any(|f| b.roots.iter().any(|r| f.starts_with(r)))
    })
}

/// `..` and `.` removed without touching the filesystem.
fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// [`lexical`] `path`, with its deepest existing ancestor canonicalized.
fn lenient_canonical(path: &Path) -> PathBuf {
    let path = lexical(path);
    let mut existing = path.clone();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if let Ok(mut c) = existing.canonicalize() {
            for t in tail.iter().rev() {
                c.push(t);
            }
            return c;
        }
        match (existing.file_name(), existing.parent()) {
            (Some(name), Some(parent)) => {
                tail.push(name.to_os_string());
                existing = parent.to_path_buf();
            }
            _ => return path,
        }
    }
}
