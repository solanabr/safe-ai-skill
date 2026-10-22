//! Enforcement of blocked skill packs without moving them (spec D2.6).
//!
//! - `Skill` (PreToolUse) and a typed `/name` (`UserPromptExpansion`, or a raw `/name` in
//!   `UserPromptSubmit`): the name is mapped to every swept pack providing it (its directory
//!   name or a `SKILL.md` name), each is re-hashed and re-graded on the spot (a mid-session
//!   edit is drift), and the call is denied when any of them is blocked. A typed `/name`
//!   never reaches the Skill tool, so both prompt-time events are needed.
//! - Read/Grep/Glob: denied when a target path resolves inside a blocked pack.
//! - Bash (best effort): every word of every command segment is resolved against the hook
//!   `cwd`, following each `cd`/`pushd` in order and expanding globs; denied when one lands
//!   inside a blocked pack, or when a command runs with its working dir inside one.
//!
//! The read and Bash checks only consult the stored state (no hashing), so they stay cheap.

use std::path::{Component, Path, PathBuf};

use serde_json::Value;

use super::state::{self, PackStatus, State};
use super::{expand_home, grading, project_root, swept_packs, Env, Scanner, USER_SKILLS_DIR};
use crate::datadir::DataDir;
use crate::gate::Verdict;
use crate::policy::Policy;

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
    )
}

/// [`skill_verdict`] with an explicit user skills dir and scanner.
pub(super) fn skill_verdict_in(
    dir: &DataDir,
    cwd: &Path,
    user_skills: &Path,
    policy: &Policy,
    skill: &str,
    scanner: Scanner,
) -> Verdict {
    let wanted = skill_candidates(skill);
    if wanted.is_empty() {
        return Verdict::NoOpinion;
    }
    let is_wanted = |n: &str| wanted.iter().any(|w| w.eq_ignore_ascii_case(n));
    let mut st = state::load(dir).state;
    let mut seen: Vec<String> = Vec::new();
    let mut blocked: Option<(String, &'static str)> = None;
    for project in project_dirs(cwd) {
        let env = Env::new(dir, &project, user_skills, scanner);
        for pack in swept_packs(&project, user_skills, policy, &env.v1) {
            let key = state::key_of(&pack.canonical);
            if seen.contains(&key) {
                continue;
            }
            let provides = is_wanted(&pack.name)
                || match st.packs.get(&key) {
                    Some(e) => e.names.iter().any(|n| is_wanted(n)),
                    None => state::skill_names(&pack.canonical)
                        .iter()
                        .any(|n| is_wanted(n)),
                };
            if !provides {
                continue;
            }
            seen.push(key.clone());
            let ev = super::evaluate(&mut st, &pack, &env);
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
    match blocked {
        Some((shown, why)) => denial(&format!("skill `{skill}` comes from"), &shown, why),
        None => Verdict::NoOpinion,
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

/// Read/Grep/Glob enforcement: deny when a target path resolves inside a blocked pack.
pub fn read_verdict(dir: &DataDir, tool_input: &Value, cwd: &Path) -> Verdict {
    let st = state::load(dir).state;
    let blocked = blocked_packs(&st);
    if blocked.is_empty() {
        return Verdict::NoOpinion;
    }
    let field = |k: &str| tool_input.get(k).and_then(Value::as_str);
    let base = field("path")
        .map(|p| absolute(cwd, p))
        .unwrap_or_else(|| cwd.to_path_buf());
    let mut targets: Vec<PathBuf> = ["file_path", "notebook_path", "path"]
        .iter()
        .filter_map(|k| field(k))
        .map(|p| absolute(cwd, p))
        .collect();
    if let Some(pattern) = field("pattern") {
        // A Glob pattern's literal prefix (up to the first glob character).
        let literal: Vec<&str> = pattern
            .split('/')
            .take_while(|c| !c.contains(['*', '?', '[', '{']))
            .collect();
        if !literal.is_empty() {
            targets.push(absolute(&base, &literal.join("/")));
        }
    }
    for target in &targets {
        if let Some(b) = inside_blocked(target, &blocked) {
            return denial(&format!("{} is inside", target.display()), &b.shown, b.why);
        }
    }
    Verdict::NoOpinion
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
            .map(|w| {
                w.trim_matches(|c| matches!(c, '(' | ')' | '{' | '}' | '`' | '$' | '\'' | '"'))
                    .to_string()
            })
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
