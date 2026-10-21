//! Project overlay ratchet (D1.10).
//!
//! `.safe-ai-skill/policy.yaml` is repo-controlled, so it may only tighten the base policy,
//! field by field. Each refused change becomes an `ignored_overrides` note. Notes name the
//! field and echo only trusted values (base policy, known words, numbers): they reach the
//! model at SessionStart, so repo text never goes in them.

use std::cmp::Ordering;
use std::fmt::Display;
use std::path::{Component, Path};

use serde_yaml::Value as Yaml;

use super::{merge_yaml, Policy, PROFILE_ENV};

/// A project's policy overlay, relative to the project root.
pub(super) const PROJECT_POLICY: &str = ".safe-ai-skill/policy.yaml";

/// Known profiles from loosest to strictest. [`PROFILE_ENV`] may only move right.
const PROFILE_STRICTNESS: [&str; 4] = ["off", "autopilot", "strict", "paranoid"];

/// The skill scan dirs, and the note for project dirs that leave the project.
const SCAN_DIRS: &str = "supply_chain.verify_skills_dirs";
pub(super) const SCAN_DIRS_OUTSIDE: &str =
    "supply_chain.verify_skills_dirs: dirs outside the project ignored";

/// Fold a project's overlay `text` into `policy` (parsed from `base`), keeping only what
/// tightens it.
pub(super) fn apply_project_overlay(policy: &mut Policy, base: &Yaml, text: &str) {
    let mut overlay = match serde_yaml::from_str::<Yaml>(text) {
        Ok(Yaml::Mapping(map)) => map,
        Ok(Yaml::Null) => return, // empty or comments only
        parsed => {
            let why = if parsed.is_ok() {
                "not a YAML mapping"
            } else {
                "not valid YAML"
            };
            policy
                .ignored_overrides
                .push(format!("{PROJECT_POLICY}: {why}; ignored"));
            return;
        }
    };

    // Profile selection belongs to the user, never to the repo.
    for key in ["active_profile", "profiles"] {
        if let Some(asked) = overlay.remove(key) {
            let current = base.get(key).cloned().unwrap_or(Yaml::Null);
            if merge_yaml(current.clone(), asked) != current {
                policy.ignored_overrides.push(format!(
                    "{key}: a project may not select or define profiles"
                ));
            }
        }
    }

    match serde_yaml::from_value::<Policy>(merge_yaml(base.clone(), Yaml::Mapping(overlay))) {
        Ok(asked) => {
            let notes = ratchet(policy, &asked);
            policy.ignored_overrides.extend(notes);
        }
        Err(_) => {
            // An ill-typed overlay fails closed, as before, but only where that tightens.
            // The notes compare against the fail-closed stand-in, not the repo: drop them.
            let _ = ratchet(policy, &Policy::fail_closed());
            policy.ignored_overrides.push(format!(
                "{PROJECT_POLICY}: a value has the wrong type; failing closed (spend caps 0)"
            ));
        }
    }
}

/// Tighten `policy` with every field of `asked` (the base deep-merged with the overlay)
/// that tightens it. Returns a note per refused change. Profiles are handled by the caller.
fn ratchet(policy: &mut Policy, asked: &Policy) -> Vec<String> {
    let mut notes = Vec::new();
    let n = &mut notes;

    keep_mainnet_default(
        "network.default",
        &mut policy.network.default,
        &asked.network.default,
        n,
    );
    keep_stricter(
        "network.mainnet",
        &mut policy.network.mainnet,
        &asked.network.mainnet,
        n,
    );

    let (spend, caps) = (&mut policy.spend, &mut policy.project_caps);
    for (path, cap, project, wanted) in [
        (
            "spend.per_tx_sol_max",
            &mut spend.per_tx_sol_max,
            &mut caps.per_tx_sol_max,
            asked.spend.per_tx_sol_max,
        ),
        (
            "spend.hard_tx_sol_max",
            &mut spend.hard_tx_sol_max,
            &mut caps.hard_tx_sol_max,
            asked.spend.hard_tx_sol_max,
        ),
        (
            "spend.daily_sol_max",
            &mut spend.daily_sol_max,
            &mut caps.daily_sol_max,
            asked.spend.daily_sol_max,
        ),
    ] {
        if keep_min(path, cap, wanted, n) {
            *project = Some(wanted);
        }
    }

    keep_union("gates", &mut policy.gates, &asked.gates, n);
    keep_union(
        "hard_guards",
        &mut policy.hard_guards,
        &asked.hard_guards,
        n,
    );
    keep_pattern(
        "mcp.sensitive_name_pattern",
        &mut policy.mcp.sensitive_name_pattern,
        &asked.mcp.sensitive_name_pattern,
        n,
    );

    let swap = &mut policy.swap;
    keep_on("swap.rugcheck", &mut swap.rugcheck, asked.swap.rugcheck, n);
    keep_min(
        "swap.rugcheck_max_score",
        &mut swap.rugcheck_max_score,
        asked.swap.rugcheck_max_score,
        n,
    );
    // A timed-out rugcheck asks where a bad score denies, so a shorter timeout turns denies
    // into asks, and a longer one risks the hook timing out (no opinion): no safe direction.
    keep_fixed(
        "swap.rugcheck_timeout_ms",
        &swap.rugcheck_timeout_ms,
        &asked.swap.rugcheck_timeout_ms,
        n,
    );
    keep_subset(
        "swap.trusted_mints",
        &mut swap.trusted_mints,
        &asked.swap.trusted_mints,
        n,
    );

    keep_union(
        "secrets.deny_read_globs",
        &mut policy.secrets.deny_read_globs,
        &asked.secrets.deny_read_globs,
        n,
    );
    keep_subset(
        "secrets.allow_read_globs",
        &mut policy.secrets.allow_read_globs,
        &asked.secrets.allow_read_globs,
        n,
    );

    keep_on(
        "redact.enabled",
        &mut policy.redact.enabled,
        asked.redact.enabled,
        n,
    );
    keep_on(
        "audit.enabled",
        &mut policy.audit.enabled,
        asked.audit.enabled,
        n,
    );
    // Catalog classes match first-wins and short-circuit the MCP gate, so even an added
    // keyword can turn a rugcheck `deny` into an `ask`: the catalog is not overridable.
    keep_fixed("catalog", &policy.catalog, &asked.catalog, n);

    let chain = &mut policy.supply_chain;
    let asked_chain = &asked.supply_chain;
    let added_dirs = keep_scan_dirs(
        &mut chain.verify_skills_dirs,
        &asked_chain.verify_skills_dirs,
        n,
    );
    keep_on(
        "supply_chain.flag_unpinned_mcp",
        &mut chain.flag_unpinned_mcp,
        asked_chain.flag_unpinned_mcp,
        n,
    );
    keep_on(
        "supply_chain.flag_telemetry_curl",
        &mut chain.flag_telemetry_curl,
        asked_chain.flag_telemetry_curl,
        n,
    );
    keep_fixed(
        "supply_chain.verify_ext_submodules",
        &chain.verify_ext_submodules,
        &asked_chain.verify_ext_submodules,
        n,
    );
    keep_fixed(
        "supply_chain.ext_dir",
        &chain.ext_dir,
        &asked_chain.ext_dir,
        n,
    );
    keep_stricter(
        "supply_chain.exec_install_scripts",
        &mut chain.exec_install_scripts,
        &asked_chain.exec_install_scripts,
        n,
    );
    policy.project_scan_dirs = added_dirs;

    notes
}

/// Lower `current` to `asked` when that tightens it; returns whether it moved.
fn keep_min<T: PartialOrd + Copy + Display>(
    path: &str,
    current: &mut T,
    asked: T,
    notes: &mut Vec<String>,
) -> bool {
    match asked.partial_cmp(current) {
        Some(Ordering::Less) => {
            *current = asked;
            true
        }
        Some(Ordering::Equal) => false,
        _ => {
            notes.push(format!(
                "{path}: kept at {current} (a project may only lower it)"
            ));
            false
        }
    }
}

/// Turn `current` on when asked; refuse turning it off.
fn keep_on(path: &str, current: &mut bool, asked: bool, notes: &mut Vec<String>) {
    if asked {
        *current = true;
    } else if *current {
        notes.push(format!("{path}: kept on (a project may not turn it off)"));
    }
}

/// Rank of a decision word, `allow` < `ask` < `deny`; `None` for any other word.
fn decision_rank(word: &str) -> Option<u8> {
    match word {
        "allow" => Some(0),
        "ask" => Some(1),
        "deny" => Some(2),
        _ => None,
    }
}

/// Move the decision `current` toward `deny` when asked; refuse any other change.
fn keep_stricter(path: &str, current: &mut String, asked: &str, notes: &mut Vec<String>) {
    if asked == current {
        return;
    }
    // Gates read an unknown word as `ask`.
    let rank = decision_rank(current).unwrap_or(1);
    match decision_rank(asked).map(|r| r.cmp(&rank)) {
        Some(Ordering::Greater) => *current = asked.to_string(),
        Some(Ordering::Equal) => {}
        _ => notes.push(format!(
            "{path}: kept at {current} (a project may only move it toward deny)"
        )),
    }
}

/// Keep every entry of `current` and add the asked ones (deny-lists: more is tighter).
fn keep_union(path: &str, current: &mut Vec<String>, asked: &[String], notes: &mut Vec<String>) {
    note_dropped(path, current, asked, notes);
    for entry in asked {
        if !current.contains(entry) {
            current.push(entry.clone());
        }
    }
}

/// Keep only the entries of `current` that `asked` also lists (allow-lists: fewer is
/// tighter).
fn keep_subset(path: &str, current: &mut Vec<String>, asked: &[String], notes: &mut Vec<String>) {
    if asked.iter().any(|e| !current.contains(e)) {
        notes.push(format!(
            "{path}: additions ignored (a project may only remove entries)"
        ));
    }
    current.retain(|e| asked.contains(e));
}

/// [`keep_union`] for skill scan dirs, except an added dir must stay inside the project:
/// sweeping `~`, `/`, `..` or the project root itself would treat unrelated dirs as packs.
/// The project's order comes first, since `verify approve` restores into the first dir.
/// Returns the added dirs; [`Policy::load_with_mode`] re-checks them on disk.
fn keep_scan_dirs(
    current: &mut Vec<String>,
    asked: &[String],
    notes: &mut Vec<String>,
) -> Vec<String> {
    note_dropped(SCAN_DIRS, current, asked, notes);
    let mut dirs: Vec<String> = Vec::new();
    let mut added = Vec::new();
    let mut outside = false;
    for dir in asked {
        if dirs.contains(dir) {
            continue;
        }
        if current.contains(dir) {
            dirs.push(dir.clone());
        } else if is_inside_project(dir) {
            dirs.push(dir.clone());
            added.push(dir.clone());
        } else {
            outside = true;
        }
    }
    for dir in current.iter() {
        if !dirs.contains(dir) {
            dirs.push(dir.clone());
        }
    }
    *current = dirs;
    if outside {
        notes.push(SCAN_DIRS_OUTSIDE.to_string());
    }
    added
}

/// Note the entries of `current` that `asked` leaves out; they stay.
fn note_dropped(path: &str, current: &[String], asked: &[String], notes: &mut Vec<String>) {
    let dropped: Vec<String> = current
        .iter()
        .filter(|e| !asked.contains(e))
        .map(|e| format!("`{e}`"))
        .collect();
    if !dropped.is_empty() {
        notes.push(format!(
            "{path}: kept {} (a project may only add entries)",
            dropped.join(", ")
        ));
    }
}

/// Whether `dir` is, as text, a relative path below the project root. Symlinks are checked
/// on disk by [`Policy::load_with_mode`].
fn is_inside_project(dir: &str) -> bool {
    let components = || Path::new(dir).components();
    !dir.starts_with('~')
        && components().all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
        && components().any(|c| matches!(c, Component::Normal(_)))
}

/// Move the assumed network only to mainnet: assuming mainnet asks more, never less.
fn keep_mainnet_default(path: &str, current: &mut String, asked: &str, notes: &mut Vec<String>) {
    if asked == current {
        return;
    }
    if matches!(asked, "mainnet" | "mainnet-beta") {
        *current = asked.to_string();
    } else {
        notes.push(format!(
            "{path}: kept at {current} (a project may only change it to mainnet)"
        ));
    }
}

/// [`keep_union`] over the alternatives of an `a|b|c` name pattern.
fn keep_pattern(path: &str, current: &mut String, asked: &str, notes: &mut Vec<String>) {
    if asked == current {
        return;
    }
    let alternatives = |pattern: &str| -> Vec<String> {
        pattern
            .split('|')
            .map(str::trim)
            .filter(|a| !a.is_empty())
            .map(str::to_string)
            .collect()
    };
    let mut merged = alternatives(current);
    keep_union(path, &mut merged, &alternatives(asked), notes);
    *current = merged.join("|");
}

/// A field with no tighter direction: a project may not change it.
fn keep_fixed<T: PartialEq>(path: &str, current: &T, asked: &T, notes: &mut Vec<String>) {
    if asked != current {
        notes.push(format!("{path}: a project may not change it"));
    }
}

/// Pick the active profile: the user's `persisted` choice replaces `base`, then `env` (which
/// a repo's `.claude/settings.json` can set) may only select a stricter profile. Returns the
/// profile and a note when `env` was refused.
pub(super) fn resolve_profile(
    base: &str,
    persisted: Option<&str>,
    env: Option<&str>,
) -> (String, Option<String>) {
    let current = persisted
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .unwrap_or(base);
    let env = match env.map(str::trim).filter(|e| !e.is_empty()) {
        Some(e) => e,
        None => return (current.to_string(), None),
    };
    let rank = |profile: &str| PROFILE_STRICTNESS.iter().position(|p| *p == profile);
    match (rank(current), rank(env)) {
        (Some(floor), Some(asked)) if asked >= floor => (env.to_string(), None),
        _ if env == current => (current.to_string(), None),
        _ => (
            current.to_string(),
            Some(format!(
                "{PROFILE_ENV}: kept profile `{current}` (it may only select a stricter one)"
            )),
        ),
    }
}
