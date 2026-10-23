//! Cargo: `Cargo.toml` build scripts, proc-macros, git and registry dependencies, redirects
//! and a missing `Cargo.lock`; `Cargo.lock` sources; `.cargo/config.toml` exec and source keys.

use std::collections::BTreeMap;
use std::path::Path;

use super::super::{Ctx, FileOut, Severity};
use super::toml::{entries, inline_get, unquote, Entry};
use super::{is_commit, PackFiles, MAX_LOCATED};

/// Sources a `Cargo.lock` entry may come from without a finding.
const CRATES_IO: &[&str] = &[
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
];

/// The dependency table an entry belongs to, and the crate name when the table is a
/// `[dependencies.<name>]` sub-table.
fn dep_table(table: &str) -> Option<Option<&str>> {
    const KINDS: &[&str] = &["dependencies", "dev-dependencies", "build-dependencies"];
    for kind in KINDS {
        if table == *kind || table.ends_with(&format!(".{kind}")) {
            return Some(None);
        }
        let prefix = format!("{kind}.");
        if let Some(name) = table.strip_prefix(&prefix) {
            return Some(Some(name));
        }
        let nested = format!(".{kind}.");
        if let Some(p) = table.find(&nested) {
            return Some(Some(&table[p + nested.len()..]));
        }
    }
    None
}

/// What one dependency declares.
#[derive(Default)]
struct Dep {
    line: u32,
    git: bool,
    rev: bool,
    registry: bool,
}

/// `Cargo.toml`.
pub(super) fn manifest(rel: &Path, text: &str, pack: &PackFiles<'_>, out: &mut FileOut) {
    let all = entries(text);
    let mut package_line: Option<u32> = None;
    let mut build: Option<(u32, bool)> = None;
    let mut deps: BTreeMap<String, Dep> = BTreeMap::new();
    let mut first_dep_line: Option<u32> = None;
    let mut dep_header: Option<u32> = None;
    for e in &all {
        if e.header {
            dep_header = (dep_table(e.table()) == Some(None)).then_some(e.line);
            if e.table() == "package" {
                package_line = Some(e.line);
            }
            if e.table().starts_with("patch.") || e.table() == "patch" || e.table() == "replace" {
                out.emit(
                    "dep_nonregistry_source",
                    Severity::Warn,
                    Some(e.line),
                    Ctx::Meta,
                );
            }
            if let Some(Some(name)) = dep_table(e.table()) {
                let d = deps.entry(unquote(name).to_string()).or_default();
                d.line = e.line;
                first_dep_line.get_or_insert(e.line);
            }
            continue;
        }
        if e.table() == "package" && e.key == "build" {
            build = Some((e.line, e.value.trim() != "false"));
        }
        if e.table() == "lib"
            && (e.key == "proc-macro" || e.key == "proc_macro")
            && e.value == "true"
        {
            out.emit("dep_build_script", Severity::Warn, Some(e.line), Ctx::Meta);
        }
        match dep_table(e.table()) {
            Some(None) => {
                first_dep_line.get_or_insert(dep_header.unwrap_or(e.line));
                let name = e.key.split('.').next().unwrap_or(&e.key).to_string();
                let d = deps.entry(name).or_default();
                d.line = e.line;
                read_dep_value(d, e);
            }
            Some(Some(name)) => {
                let d = deps.entry(unquote(name).to_string()).or_default();
                match e.key.as_str() {
                    "git" => d.git = true,
                    "rev" => d.rev = is_commit(unquote(&e.value)),
                    "registry" | "registry-index" => d.registry = true,
                    _ => {}
                }
            }
            None => {}
        }
    }
    let mut floating = 0;
    let mut elsewhere = 0;
    for d in deps.values() {
        if d.git && !d.rev && floating < MAX_LOCATED {
            floating += 1;
            out.emit(
                "dep_floating_source",
                Severity::Warn,
                Some(d.line),
                Ctx::Meta,
            );
        } else if (d.git || d.registry) && elsewhere < MAX_LOCATED {
            elsewhere += 1;
            out.emit(
                "dep_nonregistry_source",
                Severity::Warn,
                Some(d.line),
                Ctx::Meta,
            );
        }
    }
    if let Some(package) = package_line {
        let script = match build {
            Some((line, true)) => Some(line),
            Some((_, false)) => None,
            None => pack.sibling(rel, "build.rs").then_some(package),
        };
        if let Some(line) = script {
            out.emit("dep_build_script", Severity::Warn, Some(line), Ctx::Meta);
        }
    }
    if let Some(line) = first_dep_line {
        if !pack.has_up(rel, &["Cargo.lock"]) {
            out.emit(
                "dep_lockfile_missing",
                Severity::Warn,
                Some(line),
                Ctx::Meta,
            );
        }
    }
}

/// One `name = …` line of a dependency table: a version string, an inline table, or a dotted
/// key (`name.git = "…"`).
fn read_dep_value(d: &mut Dep, e: &Entry) {
    match e.key.split_once('.') {
        Some((_, "git")) => d.git = true,
        Some((_, "rev")) => d.rev = is_commit(unquote(&e.value)),
        Some((_, "registry")) => d.registry = true,
        Some(_) => {}
        None => {
            if inline_get(&e.value, "git").is_some() {
                d.git = true;
            }
            if inline_get(&e.value, "rev").is_some_and(is_commit) {
                d.rev = true;
            }
            if inline_get(&e.value, "registry").is_some()
                || inline_get(&e.value, "registry-index").is_some()
            {
                d.registry = true;
            }
        }
    }
}

/// `Cargo.lock`: `[[package]]` sources other than crates.io (git, other registries).
pub(super) fn lock(text: &str, out: &mut FileOut) {
    let mut elsewhere = 0;
    for e in entries(text) {
        if e.header || e.table() != "package" || e.key != "source" {
            continue;
        }
        let source = unquote(&e.value);
        if !CRATES_IO.contains(&source) && elsewhere < MAX_LOCATED {
            elsewhere += 1;
            out.emit(
                "dep_nonregistry_source",
                Severity::Warn,
                Some(e.line),
                Ctx::Meta,
            );
        }
    }
}

/// `.cargo/config.toml`: keys that run another program in cargo's place or redirect sources.
pub(super) fn config(text: &str, out: &mut FileOut) {
    const EXEC_KEYS: &[&str] = &[
        "rustc-wrapper",
        "rustc-workspace-wrapper",
        "rustc",
        "rustdoc",
        "linker",
        "runner",
        "replace-with",
    ];
    let mut hits = 0;
    for e in entries(text) {
        let flagged = if e.header {
            e.table() == "alias"
        } else {
            let last = e.key.rsplit('.').next().unwrap_or(&e.key);
            EXEC_KEYS.contains(&last) || e.table() == "alias" || e.key.starts_with("alias.")
        };
        if flagged {
            out.emit("dep_pm_config", Severity::Warn, Some(e.line), Ctx::Meta);
            hits += 1;
            if hits >= MAX_LOCATED {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::{grade, Grade};
    use super::super::tests::{pack, rules_at};

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn build_rs_beside_a_package_is_a_build_script_unless_disabled() {
        let m = "[package]\nname = \"x\"\n";
        let r = pack(&[("Cargo.toml", m), ("build.rs", "fn main() {}\n")]);
        assert_eq!(
            rules_at(&r, "dep_build_script"),
            vec![("Cargo.toml".into(), Some(1))]
        );
        assert_eq!(grade(&r), Grade::Warn);
        let r = pack(&[
            ("Cargo.toml", "[package]\nname = \"x\"\nbuild = false\n"),
            ("build.rs", "fn main() {}\n"),
        ]);
        assert!(rules_at(&r, "dep_build_script").is_empty(), "{r:?}");
        let r = pack(&[("Cargo.toml", "[package]\nbuild = \"gen/b.rs\"\n")]);
        assert_eq!(
            rules_at(&r, "dep_build_script"),
            vec![("Cargo.toml".into(), Some(2))]
        );
        // A stray build.rs with no package next to it runs nothing.
        let r = pack(&[("build.rs", "fn main() {}\n")]);
        assert!(rules_at(&r, "dep_build_script").is_empty(), "{r:?}");
    }

    #[test]
    fn proc_macro_lib_is_a_build_script() {
        let r = pack(&[
            (
                "Cargo.toml",
                "[package]\nname = \"m\"\n[lib]\nproc-macro = true\n",
            ),
            ("Cargo.lock", ""),
        ]);
        assert_eq!(
            rules_at(&r, "dep_build_script"),
            vec![("Cargo.toml".into(), Some(4))]
        );
    }

    #[test]
    fn git_deps_without_a_rev_float_and_registries_and_patches_redirect() {
        let m = format!(
            "[package]\nname = \"x\"\n[dependencies]\nserde = \"1\"\na = {{ git = \"https://g.invalid/a\" }}\nb = {{ git = \"https://g.invalid/b\", rev = \"{SHA}\" }}\nc = {{ version = \"1\", registry = \"corp\" }}\nd.git = \"https://g.invalid/d\"\n[dependencies.e]\ngit = \"https://g.invalid/e\"\nbranch = \"main\"\n[patch.crates-io]\nserde = {{ path = \"../serde\" }}\n"
        );
        let r = pack(&[("Cargo.toml", &m), ("Cargo.lock", "")]);
        let mut floating = rules_at(&r, "dep_floating_source");
        floating.sort();
        assert_eq!(
            floating,
            vec![
                ("Cargo.toml".into(), Some(5)),
                ("Cargo.toml".into(), Some(8)),
                ("Cargo.toml".into(), Some(9))
            ]
        );
        let mut elsewhere = rules_at(&r, "dep_nonregistry_source");
        elsewhere.sort();
        assert_eq!(
            elsewhere,
            vec![
                ("Cargo.toml".into(), Some(6)),
                ("Cargo.toml".into(), Some(7)),
                ("Cargo.toml".into(), Some(12))
            ]
        );
        assert!(rules_at(&r, "dep_lockfile_missing").is_empty());
    }

    #[test]
    fn a_missing_cargo_lock_is_flagged_and_a_workspace_lock_counts() {
        let m = "[package]\nname = \"x\"\n\n[dependencies]\nserde = \"1\"\n";
        let r = pack(&[("Cargo.toml", m)]);
        assert_eq!(
            rules_at(&r, "dep_lockfile_missing"),
            vec![("Cargo.toml".into(), Some(4))]
        );
        let r = pack(&[("crates/x/Cargo.toml", m), ("Cargo.lock", "")]);
        assert!(rules_at(&r, "dep_lockfile_missing").is_empty());
        let r = pack(&[("Cargo.toml", "[package]\nname = \"x\"\n")]);
        assert!(rules_at(&r, "dep_lockfile_missing").is_empty());
    }

    #[test]
    fn cargo_lock_git_and_foreign_registry_sources() {
        let lock = "version = 3\n\n[[package]]\nname = \"serde\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"g\"\nsource = \"git+https://github.com/o/g?rev=abc#abc\"\n\n[[package]]\nname = \"c\"\nsource = \"sparse+https://corp.invalid/index/\"\n\n[[package]]\nname = \"local\"\n";
        let r = pack(&[("Cargo.lock", lock)]);
        assert_eq!(
            rules_at(&r, "dep_nonregistry_source"),
            vec![
                ("Cargo.lock".into(), Some(9)),
                ("Cargo.lock".into(), Some(13))
            ]
        );
    }

    #[test]
    fn cargo_config_exec_and_source_keys() {
        let cfg = "[build]\njobs = 4\nrustc-wrapper = \"/tmp/w\"\n[target.x86_64-unknown-linux-gnu]\nlinker = \"cc\"\nrunner = \"./run.sh\"\n[alias]\nb = \"build\"\n[source.crates-io]\nreplace-with = \"vendored\"\n[net]\nretry = 2\n";
        let r = pack(&[(".cargo/config.toml", cfg)]);
        let lines: Vec<Option<u32>> = rules_at(&r, "dep_pm_config")
            .into_iter()
            .map(|(_, l)| l)
            .collect();
        assert_eq!(lines, vec![Some(3), Some(5), Some(6), Some(7), Some(8)]);
        let r = pack(&[(".cargo/config.toml", "[net]\nretry = 2\n")]);
        assert!(rules_at(&r, "dep_pm_config").is_empty());
    }
}
