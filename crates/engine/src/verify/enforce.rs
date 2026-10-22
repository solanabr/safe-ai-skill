//! Enforcement of blocked skill packs without moving them (spec D2.6).
//!
//! - `Skill` (PreToolUse) and a typed `/name` (`UserPromptExpansion`, or a raw `/name` in
//!   `UserPromptSubmit`): the name is mapped to every swept pack providing it (its directory
//!   name or a `SKILL.md` name); a pack whose stat fingerprint changed since it was verified is
//!   re-hashed and re-graded on the spot (a mid-session edit is drift), and the call is denied
//!   when any of them is blocked or was never fully scanned. A typed `/name` never reaches the
//!   Skill tool, so both prompt-time events are needed.
//! - Read: denied when the file resolves inside a blocked pack. Grep/Glob: denied when the
//!   search root lies inside a blocked pack or contains one. A pack the sweep could not fully
//!   scan in its budget counts as blocked here.
//! - Verifying a skill's packs is bounded by [`SKILL_BUDGET`]; an overrun denies the names the
//!   unverified packs may provide, and the Skill hook is wired `onFailure: block`, so a crash
//!   or timeout never fails open.
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

/// Every pack in `st` whose paths the gates deny: blocked packs, and packs left unreviewed
/// because they were not fully scanned (a pack unreviewed only for a first-seen HIGH finding is
/// a warning, not denied).
fn blocked_packs(st: &State) -> Vec<BlockedPack> {
    st.packs
        .iter()
        .filter(|(_, e)| e.state == PackStatus::Blocked || e.unscanned())
        .map(|(key, e)| {
            let mut roots = vec![state::path_of(key)];
            roots.extend(e.quarantined_to.iter().map(PathBuf::from));
            BlockedPack {
                roots,
                shown: key.clone(),
                why: if e.state == PackStatus::Blocked {
                    why_label(e.reason)
                } else {
                    "it could not be fully scanned within the time budget; `safe-ai-skill verify \
                     check <dir>` scans it"
                },
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

/// The names a `Skill` / slash invocation may refer to. A plugin-namespaced `plugin:skill` is a
/// plugin's skill, which no project or user pack provides, so it is never matched by its local
/// part.
fn skill_candidates(skill: &str) -> Vec<String> {
    let name = skill.trim().trim_start_matches('/');
    if name.is_empty() {
        return Vec::new();
    }
    vec![name.to_string()]
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
        grading::scan_pack_until,
        Limits::default(),
    )
}

/// [`skill_verdict`] with an explicit user skills dir, scanner and time budget.
///
/// Per pack in scope, the stat fingerprint is taken first (cheap, bounded by the budget):
/// - it matches the one recorded when the pack was last hashed and scanned (trusted data dir):
///   the stored verdict and names stand, with no content hash, so a pack too large to hash in
///   the budget costs only its stat walk;
/// - otherwise (changed, never verified, or left unscanned) the pack's names are walked and,
///   when it may provide the name, it is hashed and re-graded on the spot. Running out of
///   budget then denies the names that pack may provide (drift until the next sweep).
///
/// A pack the stat walk itself cannot cover in time denies only the names it may provide (its
/// directory name and recorded names), never every name. When no pack resolves the name and a
/// pack in scope has names that may be incomplete (an escaping link, unparseable frontmatter,
/// a name walk out of budget), the name is denied, unless it is plugin-namespaced
/// (`plugin:skill`), which a project pack cannot provide.
pub(super) fn skill_verdict_in(
    dir: &DataDir,
    cwd: &Path,
    user_skills: &Path,
    policy: &Policy,
    skill: &str,
    scanner: Scanner,
    limits: Limits,
) -> Verdict {
    let wanted = skill_candidates(skill);
    if wanted.is_empty() {
        return Verdict::NoOpinion;
    }
    let is_wanted = |n: &str| wanted.iter().any(|w| w.eq_ignore_ascii_case(n));
    let plugin = skill.contains(':');
    let deadline = Instant::now() + limits.budget;
    let mut st = state::load(dir).state;
    let mut seen: Vec<String> = Vec::new();
    let mut evaluated = false;
    let mut blocked: Option<(String, &'static str)> = None;
    // A pack whose names may be incomplete (escaping link, unparseable frontmatter, a walk out
    // of budget): it may provide a name no pack resolves.
    let mut unsure: Option<String> = None;
    // A pack that may provide the name but could not be verified in time (or was left
    // unscanned by the sweep).
    let mut unverified: Option<String> = None;
    let projects = project_dirs(cwd);
    let envs: Vec<Env> = projects
        .iter()
        .map(|p| Env::new(dir, p, user_skills, scanner))
        .collect();
    let mut queue: Vec<(&Env, super::Pack)> = Vec::new();
    for (project, env) in projects.iter().zip(&envs) {
        for pack in swept_packs(project, user_skills, policy, &env.v1) {
            queue.push((env, pack));
        }
    }
    // Packs that may provide the name are verified first, so the budget goes to them.
    queue.sort_by_key(|(_, pack)| {
        !(is_wanted(&pack.name)
            || st
                .packs
                .get(&state::key_of(&pack.canonical))
                .is_some_and(|e| e.names.iter().any(|n| is_wanted(n))))
    });
    for (env, pack) in queue {
        // A deny is settled: the packs that may provide the name came first.
        if blocked.is_some() || unverified.is_some() {
            break;
        }
        let key = state::key_of(&pack.canonical);
        if seen.contains(&key) {
            continue;
        }
        let stored = st.packs.get(&key);
        let recorded =
            is_wanted(&pack.name) || stored.is_some_and(|e| e.names.iter().any(|n| is_wanted(n)));
        let fingerprint = if Instant::now() >= deadline {
            None
        } else {
            state::stat_fingerprint_until(&pack.canonical, Some(deadline))
        };
        let Some(fingerprint) = fingerprint else {
            if recorded {
                unverified.get_or_insert_with(|| pack.display.clone());
            } else if stored.is_none_or(|e| e.names_incomplete || e.unscanned()) {
                // Its names are unknown or incomplete: it may provide the name. A slower stat
                // walk must never make the gate more permissive.
                unsure.get_or_insert_with(|| pack.display.clone());
            }
            continue;
        };
        let same = stored.filter(|e| !e.fingerprint.is_empty() && e.fingerprint == fingerprint);
        // Unchanged since it was verified: the stored verdict stands (trusted data dir, unix).
        if let Some(e) = same.filter(|_| dir.trusted && state::FINGERPRINT_TRUSTED) {
            if let Some(name) = e.escaping.iter().find(|n| is_wanted(n)) {
                return escaping_denial(skill, name, &pack.display);
            }
            if !recorded {
                if !e.approved && (e.names_incomplete || e.escapes()) {
                    unsure.get_or_insert_with(|| pack.display.clone());
                }
                continue;
            }
            seen.push(key.clone());
            // A packs.lock committed since the content was scanned can only tighten.
            let lock_mismatch = env
                .lock_pins
                .get(&key)
                .is_some_and(|pin| *pin != e.last_scanned_hash);
            if e.state == PackStatus::Blocked {
                blocked.get_or_insert_with(|| (pack.display.clone(), why_label(e.reason)));
            } else if lock_mismatch {
                blocked.get_or_insert_with(|| {
                    (
                        pack.display.clone(),
                        why_label(Some(state::Reason::LockMismatch)),
                    )
                });
            } else if e.unscanned() {
                unverified.get_or_insert_with(|| pack.display.clone());
            }
            continue;
        }
        // In an untrusted data dir an unchanged pack's names are reused (approved, or
        // complete and contained), but it is still hashed and re-graded below.
        let current = match same.filter(|e| (e.approved || !e.names_incomplete) && !e.escapes()) {
            Some(e) => state::SkillNames {
                names: e.names.clone(),
                ..state::SkillNames::default()
            },
            None => state::skill_names_bounded(&pack.canonical, Some(deadline), limits.name_cap),
        };
        // A skill dir (or its SKILL.md) linking outside the pack is never verified.
        if let Some(name) = current.escaping.iter().find(|n| is_wanted(n)) {
            return escaping_denial(skill, name, &pack.display);
        }
        let provides = recorded || current.names.iter().any(|n| is_wanted(n));
        if current.over_budget {
            let slot = if provides {
                &mut unverified
            } else {
                &mut unsure
            };
            slot.get_or_insert_with(|| pack.display.clone());
            continue;
        }
        if !provides {
            if current.unparseable || !current.escaping.is_empty() {
                unsure.get_or_insert_with(|| pack.display.clone());
            }
            continue;
        }
        // Only a pack that may provide the name is hashed in full (TOCTOU).
        let Some(hash) = state::tree_hash_until(&pack.canonical, Some(deadline)) else {
            unverified.get_or_insert_with(|| pack.display.clone());
            continue;
        };
        seen.push(key.clone());
        let input = super::EvalInput {
            deadline: Some(deadline),
            names: Some(current),
            hash: Some(hash),
            fingerprint: Some(fingerprint),
            hash_on_trust: false,
            soft_deadline: None,
        };
        let Some(ev) = super::evaluate(&mut st, &pack, env, input) else {
            unverified.get_or_insert_with(|| pack.display.clone());
            continue;
        };
        evaluated = true;
        if let Some(e) = st.packs.get(&ev.key) {
            if e.state == PackStatus::Blocked {
                blocked.get_or_insert_with(|| (pack.display.clone(), why_label(e.reason)));
            } else if e.unscanned() {
                unverified.get_or_insert_with(|| pack.display.clone());
            }
        }
    }
    if evaluated {
        let _ = state::store(dir, &st);
    }
    if let Some((shown, why)) = blocked {
        return denial(&format!("skill `{skill}` comes from"), &shown, why);
    }
    if let Some(shown) = unverified {
        return over_budget_pack(skill, &shown);
    }
    if seen.is_empty() && !plugin {
        if let Some(shown) = unsure {
            return denial(
                &format!("skill `{skill}` matches no verified pack, and it may come from"),
                &shown,
                "a SKILL.md links outside the pack, its frontmatter does not parse, or it is \
                 too large to list its skills, so its skill names are unknown",
            );
        }
    }
    Verdict::NoOpinion
}

/// The denial for a skill reached through a link leaving its pack.
fn escaping_denial(skill: &str, name: &str, shown: &str) -> Verdict {
    Verdict::Deny(format!(
        "safe-ai-skill: skill `{skill}` resolves through `{name}` in the skill pack {shown}, \
         which links outside the pack, so its content was never verified."
    ))
}

/// What the Skill and slash gates may spend.
#[derive(Debug, Clone, Copy)]
pub(super) struct Limits {
    /// Time for re-hashing and walking every pack in scope.
    pub budget: Duration,
    /// Name-walk work units per pack.
    pub name_cap: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            budget: SKILL_BUDGET,
            name_cap: state::MAX_NAME_WALK_ENTRIES,
        }
    }
}

/// The denial for a skill an over-budget pack may provide.
fn over_budget_pack(skill: &str, shown: &str) -> Verdict {
    Verdict::Deny(format!(
        "safe-ai-skill: skill `{skill}` may come from the skill pack {shown}, which could not be \
         verified within {} s (too large or too slow to list its skills); review it and run \
         `safe-ai-skill verify approve {shown}`.",
        SKILL_BUDGET.as_secs()
    ))
}

/// The raw head of an unreadable prompt-time payload: the slash command it names, if any.
///
/// `Some(Some(name))` when a `command_name` or a prompt starting with `/` is found,
/// `Some(None)` when the payload may be a slash command whose name cannot be read, and `None`
/// when it is plainly not one.
pub fn slash_name_from_raw(raw: &[u8]) -> Option<Option<String>> {
    if let Some(name) = raw_string(raw, "command_name") {
        let name = name.trim();
        return Some((!name.is_empty()).then(|| name.to_string()));
    }
    // An expansion is a slash command whose name lies past what was read.
    if raw_string(raw, "hook_event_name").as_deref() == Some("UserPromptExpansion") {
        return Some(None);
    }
    match raw_string(raw, "prompt") {
        Some(prompt) => {
            let rest = prompt.trim_start().strip_prefix('/')?;
            Some(rest.split_whitespace().next().map(String::from))
        }
        None => Some(None),
    }
}

/// The `cwd` an unparseable hook payload carries, read from its head.
pub fn raw_cwd(raw: &[u8]) -> Option<PathBuf> {
    raw_string(raw, "cwd")
        .filter(|c| !c.is_empty() && !c.contains('\\'))
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

/// The string value of JSON key `key` in the first [`RAW_HEAD_BYTES`] of `raw`, up to its
/// closing quote or the end of what was read.
fn raw_string(raw: &[u8], key: &str) -> Option<String> {
    let head = String::from_utf8_lossy(&raw[..raw.len().min(RAW_HEAD_BYTES)]);
    let quoted = format!("\"{key}\"");
    let at = head.find(&quoted)? + quoted.len();
    let rest = head[at..].trim_start().strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    Some(rest.split('"').next().unwrap_or("").to_string())
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
            let mut scope = project_dirs(cwd);
            // User-level packs load in every project.
            let user = expand_home(USER_SKILLS_DIR);
            scope.push(user.canonicalize().unwrap_or(user));
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
