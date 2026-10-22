//! Key material and home credential stores by path (D8 v2 spec §4; owned by F1).
//!
//! **F0 stub:** reproduces 1.1.0 behaviour. [`is_credential`] adds nothing yet (the 1.1.0
//! classes live in [`crate::gates::secretpath`]); [`grep_root`] and [`grep_exclusions`] are
//! the 1.1.0 directory-Grep rules moved here unchanged. F1 fills them from
//! [`crate::lists::credentials`] (every class denied at every tier; `!` exceptions readable).
//!
//! Call lines (shared files; F1 edits only this file):
//! - `secretpath::classify_with_homes` → [`is_credential`] (Read, file Grep, MCP path args,
//!   Bash readers and sinks all classify through it);
//! - `read::decide_grep` → [`grep_root`] and, through `read::grep_exclusion`,
//!   [`grep_exclusions`].

use std::path::{Path, PathBuf};

use crate::gate::Verdict;
use crate::gates::secretpath;

/// Appended to a directory Grep's `glob`: env-class names, key files and the hard-deny trees
/// (1.1.0 list). Template and schema files fall under `.env.*` too, so a directory Grep never
/// searches `.env.example` or `.env.schema` (read them directly); re-including them would turn
/// the glob list into a whitelist.
const GREP_EXCLUDED: &[&str] = &[
    "**/.env",
    "**/.env.*",
    "**/*.env",
    "**/.envrc",
    "**/.dev.vars",
    "**/.dev.vars.*",
    "**/.varlock-frozen-env",
    "**/*-keypair.json",
    "**/id.json",
    "**/*.pem",
    "**/*.key",
    "**/.ssh/id_*",
    "**/.config/solana/**",
    "**/.superstack/**",
    "**/.config/varlock/**",
    "**/.varlock/**",
    "**/.claude/projects/**",
];

/// Whether `path` (normalised: absolute, `/` separators, lowercased where the platform folds
/// case) is a credential store entry that is not a readable exception. Stub: `false`.
pub fn is_credential(path: &Path) -> bool {
    let _ = path;
    false
}

/// The verdict for a directory Grep rooted at `target` (as given) / `real` (canonical), before
/// any exclusion is appended; `None` lets the search proceed with [`grep_exclusions`].
/// Stub (1.1.0): deny inside a hard-deny tree, or over a directory containing one.
pub fn grep_root(target: &Path, real: &Path, homes: &[String]) -> Option<Verdict> {
    let in_hard_tree = [target, real]
        .iter()
        .any(|p| secretpath::is_hard_tree(&p.to_string_lossy(), homes));
    if in_hard_tree {
        return Some(hard_deny("search inside a key directory"));
    }
    // Grep passes `--hidden`: a search from $HOME, ~/.config or any ancestor reaches ~/.ssh and
    // ~/.config/solana, and name exclusions cannot cover every key file name there.
    if [target, real].iter().any(|p| contains_hard_tree(p, homes)) {
        return Some(hard_deny(
            "search over a directory that contains ~/.ssh or ~/.config/solana; pass a project path",
        ));
    }
    None
}

/// The exclusion globs for a directory Grep rooted at `dir`. Stub: the 1.1.0 list.
pub fn grep_exclusions(dir: &Path) -> Vec<String> {
    let _ = dir;
    GREP_EXCLUDED.iter().map(|g| g.to_string()).collect()
}

fn hard_deny(what: &str) -> Verdict {
    Verdict::Deny(format!(
        "Protected secret file blocked ({what}): reading credential material is denied."
    ))
}

/// Whether `dir` is an ancestor of (or equal to) a home hard-deny tree.
fn contains_hard_tree(dir: &Path, homes: &[String]) -> bool {
    let dir = PathBuf::from(secretpath::normalize(&dir.to_string_lossy(), None));
    homes.iter().any(|home| {
        let home = secretpath::normalize(home, None);
        [
            ".ssh",
            ".config/solana",
            ".superstack",
            ".config/varlock",
            ".varlock",
        ]
        .iter()
        .any(|tree| Path::new(&home).join(tree).starts_with(&dir))
    }) || std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|x| !x.is_empty())
        .is_some_and(|x| {
            Path::new(&secretpath::normalize(&x, None))
                .join("varlock")
                .starts_with(&dir)
        })
}
