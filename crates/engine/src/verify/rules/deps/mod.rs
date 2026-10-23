//! Dependency manifests, lockfiles and launch specs (issue #11, spec D7.2).
//!
//! A pack is pinned by its content, but what it causes a package manager to fetch and run is a
//! second trust decision. This family reads the dependency files a pack ships and reports, from
//! the files alone:
//!
//! * build- and install-time code: a crate's `build.rs` or proc-macro, `binding.gyp`, a
//!   `setup.py` that does more than declare metadata, an in-tree PEP 517 backend, npm lockfile
//!   entries with `hasInstallScript` (pnpm `requiresBuild`), Yarn `exec:` packages;
//! * where dependencies come from: lockfile entries resolved from git, a tarball URL or a
//!   registry other than the default one, manifest dependencies on git refs without a commit,
//!   unpinned `requirements.txt` lines, `[patch]`/`replace` redirects;
//! * a manifest that declares dependencies with no lockfile beside it (or in a parent dir of the
//!   pack, for workspaces), so the resolved set is whatever the registry serves that day;
//! * package-manager config that changes what runs or where packages come from
//!   (`.cargo/config.toml` wrappers, linkers, runners, aliases and source replacement, `.npmrc`,
//!   `.yarnrc.yml`, `pip.conf`);
//! * MCP server configs the pack ships whose launch command floats ([`launch`]).
//!
//! Everything here is a heuristic, so nothing is above WARN: the pack is reported, never denied
//! on these alone. Offline and static: no network, no package manager is run, nothing under
//! `node_modules/` is analysed, symlinks are never followed (only regular files reach here), and
//! each file is read once, capped at [`MAX_DEP_BYTES`]; at most [`MAX_DEP_FILES`] files per
//! pack are analysed. A file over the cap, or a lockfile that does not parse, is
//! `dep_unanalysed` (WARN). The transitive graph is not resolved and nothing is fetched to look
//! at it: a lockfile is read for what it records, not for what its packages contain.

mod cargo;
mod golang;
pub mod launch;
mod npm;
mod python;
mod toml;

use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

use super::{Ctx, FileOut, RuleInfo, Severity};

/// Bytes read from one dependency file. A larger file is `dep_unanalysed`.
pub const MAX_DEP_BYTES: u64 = 8 * 1024 * 1024;
/// Dependency files analysed per pack; the rest are `dep_unanalysed`.
pub const MAX_DEP_FILES: usize = 512;
/// Entries walked in one lockfile (package-lock v1 nests them; the walk is iterative).
const MAX_LOCK_ENTRIES: usize = 200_000;
/// Findings per rule per file that get a line number looked up (the store keeps five anyway).
const MAX_LOCATED: usize = 5;

pub(in crate::verify::rules) const RULES: &[RuleInfo] = &[
    RuleInfo { id: "dep_manifest", code: Severity::Info, summary: "dependency manifest or lockfile (inventoried into the dependency pin)" },
    RuleInfo { id: "dep_build_script", code: Severity::Warn, summary: "build-time code a package manager runs on build or install (build.rs, proc-macro, binding.gyp, active setup.py, in-tree build backend)" },
    RuleInfo { id: "dep_install_script", code: Severity::Warn, summary: "lockfile dependency with an install script (npm hasInstallScript, pnpm requiresBuild, Yarn exec:)" },
    RuleInfo { id: "dep_install_scripts_unknown", code: Severity::Info, summary: "lockfile format that does not record install scripts (Yarn, pnpm 9, npm v1)" },
    RuleInfo { id: "dep_lockfile_missing", code: Severity::Warn, summary: "manifest declares dependencies with no lockfile beside it (resolved set floats)" },
    RuleInfo { id: "dep_nonregistry_source", code: Severity::Warn, summary: "dependency resolved from git, a tarball URL, a non-default registry or a redirect ([patch], replace)" },
    RuleInfo { id: "dep_floating_source", code: Severity::Warn, summary: "git dependency without a pinned commit (branch, tag or default HEAD)" },
    RuleInfo { id: "dep_unpinned", code: Severity::Warn, summary: "requirements line without an exact == pin" },
    RuleInfo { id: "dep_pm_config", code: Severity::Warn, summary: "package-manager config that changes what runs or where packages come from" },
    RuleInfo { id: "dep_unanalysed", code: Severity::Warn, summary: "dependency file over the size cap, unparseable, or past the per-pack file cap (not analysed)" },
    RuleInfo { id: "mcp_unpinned_launch", code: Severity::Warn, summary: "shipped MCP server config whose launch command floats (no version, @latest, a range, a git ref without a commit, docker :latest)" },
];

/// What a dependency file is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    NpmManifest,
    NpmLock,
    PnpmLock,
    YarnLock,
    CargoManifest,
    CargoLock,
    CargoConfig,
    Requirements,
    Pyproject,
    SetupPy,
    PyLock,
    GoMod,
    BindingGyp,
    PmConfig,
    McpConfig,
    /// Recorded in the dependency pin, not read (`bun.lockb`, `go.sum`, `build.rs` …).
    Inventory,
}

impl Kind {
    /// A manifest or lockfile (inventoried as `dep_manifest`).
    fn is_manifest(self) -> bool {
        !matches!(
            self,
            Kind::PmConfig | Kind::McpConfig | Kind::BindingGyp | Kind::CargoConfig
        )
    }
}

/// The kind of the pack-relative file `rel`, when it is part of the dependency set. Anything
/// under a `node_modules/` directory is not (it is installed output, not what the pack asks for).
pub fn kind_of(rel: &Path) -> Option<Kind> {
    if rel.components().any(|c| c.as_os_str() == "node_modules") {
        return None;
    }
    let name = rel.file_name()?.to_str()?.to_ascii_lowercase();
    let parent = rel
        .parent()
        .and_then(Path::file_name)
        .and_then(|n| n.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    let kind = match name.as_str() {
        "package.json" => Kind::NpmManifest,
        "package-lock.json" | "npm-shrinkwrap.json" => Kind::NpmLock,
        "pnpm-lock.yaml" => Kind::PnpmLock,
        "yarn.lock" => Kind::YarnLock,
        "cargo.toml" => Kind::CargoManifest,
        "cargo.lock" => Kind::CargoLock,
        "config" | "config.toml" if parent == ".cargo" => Kind::CargoConfig,
        "pyproject.toml" => Kind::Pyproject,
        "setup.py" => Kind::SetupPy,
        "poetry.lock" | "uv.lock" => Kind::PyLock,
        "go.mod" => Kind::GoMod,
        "binding.gyp" => Kind::BindingGyp,
        ".npmrc" | ".yarnrc" | ".yarnrc.yml" | "pip.conf" | "pip.ini" | ".pypirc" => Kind::PmConfig,
        ".mcp.json" | "mcp.json" | "plugin.json" | "claude_desktop_config.json" => Kind::McpConfig,
        "bun.lock" | "bun.lockb" | "deno.lock" | "go.sum" | "build.rs" | "setup.cfg"
        | "pipfile" | "pipfile.lock" | "pdm.lock" | "pylock.toml" | "requirements.lock" => {
            Kind::Inventory
        }
        n if is_requirements(n, &parent) => Kind::Requirements,
        _ => return None,
    };
    Some(kind)
}

/// `requirements*.txt` / `constraints*.txt` (and `.in`), or any `.txt` in a `requirements/` dir.
fn is_requirements(name: &str, parent: &str) -> bool {
    let txt = name.ends_with(".txt") || name.ends_with(".in");
    txt && (name.starts_with("requirements")
        || name.starts_with("constraints")
        || parent == "requirements")
}

/// The pack's file set, for "is there a lockfile here or above" questions.
pub(crate) struct PackFiles<'a> {
    files: &'a HashSet<PathBuf>,
}

impl PackFiles<'_> {
    /// A file named one of `names` sits in `rel`'s directory or any parent dir inside the pack.
    pub(crate) fn has_up(&self, rel: &Path, names: &[&str]) -> bool {
        let dir = rel.parent().unwrap_or(Path::new(""));
        dir.ancestors()
            .any(|anc| names.iter().any(|n| self.files.contains(&anc.join(n))))
    }

    /// A file named `name` sits next to `rel`.
    pub(crate) fn sibling(&self, rel: &Path, name: &str) -> bool {
        let dir = rel.parent().unwrap_or(Path::new(""));
        self.files.contains(&dir.join(name))
    }
}

/// Analyse every dependency file among `files` (pack-relative, under `base`), appending one
/// [`FileOut`] per file to `outs`. Returns the file the scan stopped at when `deadline` passed
/// (the caller reports the pack as cut short), `None` when it finished.
pub(in crate::verify::rules) fn scan(
    base: &Path,
    files: &HashSet<PathBuf>,
    cap: u64,
    deadline: Option<Instant>,
    outs: &mut Vec<FileOut>,
) -> Option<PathBuf> {
    let mut found: Vec<(&PathBuf, Kind)> = files
        .iter()
        .filter_map(|p| kind_of(p).map(|k| (p, k)))
        .collect();
    found.sort();
    let pack = PackFiles { files };
    let limit = cap.min(MAX_DEP_BYTES);
    for (i, (rel, kind)) in found.into_iter().enumerate() {
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Some(rel.clone());
        }
        let mut out = FileOut::new(rel);
        if i >= MAX_DEP_FILES {
            out.emit("dep_unanalysed", Severity::Warn, None, Ctx::Meta);
            outs.push(out);
            break;
        }
        if kind.is_manifest() {
            out.emit("dep_manifest", Severity::Info, None, Ctx::Meta);
        }
        if kind != Kind::Inventory {
            match read_capped(&base.join(rel), limit) {
                Some(text) => analyse(kind, rel, &text, &pack, &mut out),
                None => out.emit("dep_unanalysed", Severity::Warn, None, Ctx::Meta),
            }
        }
        outs.push(out);
    }
    None
}

fn analyse(kind: Kind, rel: &Path, text: &str, pack: &PackFiles<'_>, out: &mut FileOut) {
    match kind {
        Kind::NpmManifest => npm::manifest(rel, text, pack, out),
        Kind::NpmLock => npm::package_lock(text, out),
        Kind::PnpmLock => npm::pnpm_lock(text, out),
        Kind::YarnLock => npm::yarn_lock(text, out),
        Kind::BindingGyp => out.emit("dep_build_script", Severity::Warn, None, Ctx::Meta),
        Kind::CargoManifest => cargo::manifest(rel, text, pack, out),
        Kind::CargoLock => cargo::lock(text, out),
        Kind::CargoConfig => cargo::config(text, out),
        Kind::Requirements => python::requirements(text, out),
        Kind::Pyproject => python::pyproject(rel, text, pack, out),
        Kind::SetupPy => python::setup_py(text, out),
        Kind::PyLock => python::lock(text, out),
        Kind::GoMod => golang::go_mod(rel, text, pack, out),
        Kind::PmConfig => pm_config(text, out),
        Kind::McpConfig => launch::scan_config(text, out),
        Kind::Inventory => {}
    }
}

/// Open `path` for reading only if it is a regular file reached without following a symlink:
/// `O_NOFOLLOW` refuses a link swapped in after the walk, `O_NONBLOCK` keeps a FIFO from
/// hanging `open()`, and the `fstat` check refuses FIFOs, sockets and devices.
pub(crate) fn open_regular(path: &Path) -> Option<std::fs::File> {
    let meta = path.symlink_metadata().ok()?;
    if !meta.is_file() {
        return None;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = opts.open(path).ok()?;
    file.metadata().ok()?.is_file().then_some(file)
}

/// `path` as text, BOM dropped, or `None` when it is not a regular file (see
/// [`open_regular`]), unreadable, or longer than `limit` bytes.
pub(crate) fn read_capped(path: &Path, limit: u64) -> Option<String> {
    let file = open_regular(path)?;
    let mut buf = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut buf)
        .ok()?;
    if buf.len() as u64 > limit {
        return None;
    }
    let body = buf.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&buf);
    Some(String::from_utf8_lossy(body).into_owned())
}

/// 1-based line of byte offset `at` in `text`.
pub(crate) fn line_at(text: &str, at: usize) -> u32 {
    let end = at.min(text.len());
    let newlines = text.as_bytes()[..end]
        .iter()
        .filter(|&&b| b == b'\n')
        .count();
    super::line_no(newlines)
}

/// 1-based line of the first JSON key `"key"` (followed by `:`), when it can be found verbatim.
pub(crate) fn json_key_line(text: &str, key: &str) -> Option<u32> {
    let needle = format!("\"{key}\"");
    text.match_indices(&needle)
        .find(|(p, _)| text[p + needle.len()..].trim_start().starts_with(':'))
        .map(|(p, _)| line_at(text, p))
}

/// Emit `rule` (WARN, meta) for each of `keys`, locating the first [`MAX_LOCATED`] with `locate`.
pub(crate) fn emit_located<F>(out: &mut FileOut, rule: &'static str, keys: &[String], locate: F)
where
    F: Fn(&str) -> Option<u32>,
{
    for key in keys.iter().take(MAX_LOCATED) {
        out.emit(rule, Severity::Warn, locate(key), Ctx::Meta);
    }
}

/// True when `s` is a full git commit id (40 or 64 hex digits).
pub(crate) fn is_commit(s: &str) -> bool {
    matches!(s.len(), 40 | 64) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// True when the host of the URL in `url` is one of `hosts` (or a subdomain of one).
pub(crate) fn url_host_in(url: &str, hosts: &[&str]) -> bool {
    let lower = url.to_ascii_lowercase();
    let Some((_, host)) = super::context::next_url_host(&lower, 0) else {
        return false;
    };
    hosts.iter().any(|h| {
        host.strip_suffix(h)
            .is_some_and(|rest| rest.is_empty() || rest.ends_with('.'))
    })
}

/// Keys of package-manager config files that change what runs or where packages come from.
const PM_CONFIG_KEYS: &[&str] = &[
    "registry",
    "script-shell",
    "node-options",
    "git",
    "yarnpath",
    "plugins",
    "npmregistryserver",
    "npmscopes",
    "unsafeHttpWhitelist",
    "index-url",
    "extra-index-url",
    "find-links",
    "trusted-host",
    "index",
    "repository",
];

/// `.npmrc`, `.yarnrc(.yml)`, `pip.conf`, `.pypirc`: a key from [`PM_CONFIG_KEYS`] (or any
/// `…registry` / `@scope:registry` key) is `dep_pm_config`.
fn pm_config(text: &str, out: &mut FileOut) {
    let mut hits = 0;
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(['#', ';', '[']) {
            continue;
        }
        // `.npmrc` / `pip.conf` are `key = value` (`@scope:registry=` included); YAML is `key:`.
        let sep = if line.contains('=') { '=' } else { ':' };
        let key = line
            .split(sep)
            .next()
            .unwrap_or("")
            .trim()
            .trim_matches('"')
            .to_ascii_lowercase();
        let listed = PM_CONFIG_KEYS.iter().any(|k| key == k.to_ascii_lowercase());
        if listed || key.ends_with("registry") || key.ends_with(":registry") {
            out.emit(
                "dep_pm_config",
                Severity::Warn,
                Some(super::line_no(i)),
                Ctx::Meta,
            );
            hits += 1;
            if hits >= MAX_LOCATED {
                return;
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::testkit::*;
    use super::super::{grade, Grade, PackReport, Severity};
    use super::*;

    pub(crate) fn rules_at(r: &PackReport, rule: &str) -> Vec<(String, Option<u32>)> {
        r.findings
            .iter()
            .filter(|f| f.rule == rule)
            .map(|f| (f.path.to_string_lossy().replace('\\', "/"), f.line))
            .collect()
    }

    pub(crate) fn pack(files: &[(&str, &str)]) -> PackReport {
        let p = TempPack::new("deps");
        for (rel, body) in files {
            p.file(rel, body);
        }
        p.scan()
    }

    #[test]
    fn every_deps_rule_is_described_and_never_above_warn() {
        for r in RULES {
            assert!(!super::super::describe(r.id).is_empty(), "{}", r.id);
            assert!(r.code <= Severity::Warn, "{}", r.id);
        }
        let sources = [
            include_str!("mod.rs"),
            include_str!("npm.rs"),
            include_str!("cargo.rs"),
            include_str!("python.rs"),
            include_str!("golang.rs"),
            include_str!("launch.rs"),
        ];
        let mut seen = 0;
        for src in sources {
            for (p, _) in src
                .match_indices("\"dep_")
                .chain(src.match_indices("\"mcp_"))
            {
                let id = src[p + 1..].split('"').next().unwrap_or("");
                let word = id.bytes().all(|b| b.is_ascii_lowercase() || b == b'_');
                if word && !id.ends_with('_') {
                    seen += 1;
                    assert!(!super::super::describe(id).is_empty(), "undescribed {id}");
                }
            }
        }
        assert!(seen > 20, "{seen}");
    }

    #[test]
    fn kinds_by_name_and_node_modules_is_skipped() {
        assert_eq!(
            kind_of(Path::new("a/package.json")),
            Some(Kind::NpmManifest)
        );
        assert_eq!(kind_of(Path::new("Cargo.lock")), Some(Kind::CargoLock));
        assert_eq!(
            kind_of(Path::new(".cargo/config.toml")),
            Some(Kind::CargoConfig)
        );
        assert_eq!(kind_of(Path::new("config.toml")), None);
        assert_eq!(
            kind_of(Path::new("requirements-dev.txt")),
            Some(Kind::Requirements)
        );
        assert_eq!(
            kind_of(Path::new("requirements/base.txt")),
            Some(Kind::Requirements)
        );
        assert_eq!(kind_of(Path::new("notes.txt")), None);
        assert_eq!(kind_of(Path::new("node_modules/x/package.json")), None);
        assert_eq!(
            kind_of(Path::new(".claude-plugin/plugin.json")),
            Some(Kind::McpConfig)
        );
    }

    #[test]
    fn inventory_is_info_only_and_grades_clean() {
        let r = pack(&[
            ("SKILL.md", "# x\n"),
            ("go.sum", "x v1 h1:abc\n"),
            ("bun.lockb", "\0\0"),
        ]);
        assert_eq!(rules_at(&r, "dep_manifest").len(), 2, "{r:?}");
        assert_eq!(grade(&r), Grade::Clean, "{r:?}");
    }

    #[test]
    fn pm_config_keys_are_flagged_and_harmless_ones_are_not() {
        let r = pack(&[
            (
                ".npmrc",
                "save-exact=true\nregistry=https://npm.evil.invalid/\n",
            ),
            (
                ".yarnrc.yml",
                "nodeLinker: node-modules\nyarnPath: .yarn/releases/x.cjs\n",
            ),
            (
                "pip.conf",
                "[global]\nindex-url = https://pypi.evil.invalid/simple\n",
            ),
        ]);
        let hits = rules_at(&r, "dep_pm_config");
        assert!(hits.contains(&(".npmrc".into(), Some(2))), "{hits:?}");
        assert!(hits.contains(&(".yarnrc.yml".into(), Some(2))), "{hits:?}");
        assert!(hits.contains(&("pip.conf".into(), Some(2))), "{hits:?}");
        assert_eq!(hits.len(), 3, "{hits:?}");
        assert_eq!(grade(&r), Grade::Warn);
    }

    #[test]
    fn oversize_dependency_file_is_unanalysed_not_read() {
        let p = TempPack::new("deps-big");
        p.file("SKILL.md", "# x\n");
        p.file("package-lock.json", &" ".repeat(64));
        let r = super::super::scan_pack_capped(&p.root, 16);
        assert_eq!(rules_at(&r, "dep_unanalysed").len(), 1, "{r:?}");
    }

    #[test]
    fn the_per_pack_file_cap_is_reported_once() {
        let p = TempPack::new("deps-many");
        for i in 0..(MAX_DEP_FILES + 3) {
            p.file(&format!("d{i:04}/go.sum"), "");
        }
        let r = p.scan();
        assert_eq!(rules_at(&r, "dep_unanalysed").len(), 1);
        assert_eq!(rules_at(&r, "dep_manifest").len(), MAX_DEP_FILES);
    }

    #[cfg(unix)]
    #[test]
    fn fifos_and_links_named_like_dependency_files_are_never_opened() {
        let p = TempPack::new("deps-fifo");
        p.file("SKILL.md", "# x\n");
        crate::statefile::tests::mkfifo(&p.root.join("Cargo.lock"));
        crate::statefile::tests::mkfifo(&p.root.join("package.json"));
        p.symlink("Cargo.toml", "SKILL.md");
        assert!(read_capped(&p.root.join("Cargo.lock"), MAX_DEP_BYTES).is_none());
        assert!(read_capped(&p.root.join("Cargo.toml"), MAX_DEP_BYTES).is_none());
        let started = Instant::now();
        let r = p.scan();
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        assert!(grade(&r) <= Grade::Warn, "{r:?}");
    }

    #[test]
    fn a_passed_deadline_cuts_the_dependency_pass_as_a_budget_finding() {
        let p = TempPack::new("deps-late");
        p.file("package.json", "{}");
        let past = Instant::now();
        let mut outs = Vec::new();
        let files: HashSet<PathBuf> = [PathBuf::from("package.json")].into_iter().collect();
        let cut = scan(&p.root, &files, MAX_DEP_BYTES, Some(past), &mut outs);
        assert_eq!(cut, Some(PathBuf::from("package.json")));
        assert!(outs.is_empty());
    }
}
