//! Python: `requirements*.txt` pins and sources, `pyproject.toml` dependencies and in-tree
//! build backends, an active `setup.py`, and `poetry.lock` / `uv.lock` sources.

use std::path::Path;

use super::super::{line_no, Ctx, FileOut, Severity};
use super::toml::{entries, inline_get, unquote};
use super::{is_commit, url_host_in, PackFiles, MAX_LOCATED};

/// Indexes that need no finding.
const PYPI: &[&str] = &["pypi.org", "pypi.python.org", "files.pythonhosted.org"];
/// Lockfiles that pin a Python project's resolved set.
const LOCKS: &[&str] = &[
    "uv.lock",
    "poetry.lock",
    "pdm.lock",
    "pylock.toml",
    "Pipfile.lock",
    "requirements.lock",
];
/// `setup.py` content that does more than declare metadata: it runs at `pip install` from
/// source, so these make it build-time code worth a look.
const ACTIVE_SETUP: &[&str] = &[
    "cmdclass",
    "ext_modules",
    "build_ext",
    "subprocess",
    "os.system",
    "os.popen",
    "check_call",
    "check_output",
    "urllib",
    "urlopen",
    "requests.",
    "http.client",
    "socket",
    "exec(",
    "eval(",
    "compile(",
    "__import__",
    "ctypes",
    "base64",
];

/// Where one requirement points.
#[derive(Debug, PartialEq, Eq)]
enum Req {
    /// `name==1.2.3` (or `===`).
    Pinned,
    /// A range, a bare name, or `==1.*`.
    Unpinned,
    /// A local path (nothing fetched).
    Local,
    /// A URL, or a VCS ref pinned to a commit.
    Remote,
    /// A VCS ref with no commit.
    Floating,
}

/// Classify a PEP 508 requirement (or a pip VCS / URL line).
fn classify(req: &str) -> Req {
    let r = req.trim();
    let lower = r.to_ascii_lowercase();
    if ["git+", "hg+", "svn+", "bzr+"]
        .iter()
        .any(|v| lower.contains(v))
    {
        // `git+https://host/repo@<rev>#egg=x`: the rev follows the last `@` of the URL path.
        let url = lower.split('#').next().unwrap_or("");
        let after_scheme = url.split("://").nth(1).unwrap_or(url);
        let rev = after_scheme
            .rsplit_once('@')
            .map(|(head, rev)| (head.contains('/'), rev))
            .filter(|(path, _)| *path)
            .map(|(_, rev)| rev);
        return if rev.is_some_and(is_commit) {
            Req::Remote
        } else {
            Req::Floating
        };
    }
    if lower.contains("://") {
        return Req::Remote;
    }
    if r.starts_with(['.', '/', '~']) || lower.starts_with("file:") {
        return Req::Local;
    }
    let spec = r.split(';').next().unwrap_or(r);
    if spec.contains("===") {
        return Req::Pinned;
    }
    match spec.split_once("==") {
        Some((_, v)) if !v.trim().is_empty() && !v.trim().ends_with('*') && !v.contains(',') => {
            Req::Pinned
        }
        _ => Req::Unpinned,
    }
}

/// `requirements*.txt`: unpinned lines, VCS refs without a commit, URLs, and index options
/// pointing off PyPI.
pub(super) fn requirements(text: &str, out: &mut FileOut) {
    let (mut unpinned, mut floating, mut elsewhere) = (0, 0, 0);
    let mut joined = String::new();
    let mut start = 0usize;
    for (i, raw) in text.lines().enumerate() {
        if joined.is_empty() {
            start = i;
        }
        // A `\` at the end continues the requirement on the next line.
        if let Some(head) = raw.strip_suffix('\\') {
            if joined.len() < 64 * 1024 {
                joined.push_str(head);
                joined.push(' ');
            }
            continue;
        }
        joined.push_str(raw);
        let logical = std::mem::take(&mut joined);
        let line = Some(line_no(start));
        let body = match logical.find(" #") {
            Some(p) => &logical[..p],
            None => &logical,
        };
        let t = body.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let (opt, value) = match t.split_once(|c: char| c == '=' || c.is_whitespace()) {
            Some((o, v)) if t.starts_with('-') => (o, v.trim()),
            _ if t.starts_with('-') => (t, ""),
            _ => ("", t),
        };
        let class = match opt {
            "" => classify(value),
            "-i" | "--index-url" | "--extra-index-url" | "-f" | "--find-links" => {
                if url_host_in(value, PYPI) || !value.contains("://") {
                    continue;
                }
                Req::Remote
            }
            "--trusted-host" => Req::Remote,
            "-e" | "--editable" => match classify(value) {
                Req::Pinned | Req::Unpinned => Req::Local,
                other => other,
            },
            _ => continue,
        };
        let (rule, count) = match class {
            Req::Unpinned => ("dep_unpinned", &mut unpinned),
            Req::Floating => ("dep_floating_source", &mut floating),
            Req::Remote => ("dep_nonregistry_source", &mut elsewhere),
            Req::Pinned | Req::Local => continue,
        };
        if *count < MAX_LOCATED {
            *count += 1;
            out.emit(rule, Severity::Warn, line, Ctx::Meta);
        }
    }
}

/// The strings of a TOML array value (`["a", 'b']`), unquoted.
fn array_items(value: &str) -> Vec<&str> {
    let body = value.trim().trim_start_matches('[').trim_end_matches(']');
    let mut items = Vec::new();
    let mut rest = body;
    while let Some(start) = rest.find(['"', '\'']) {
        let q = rest[start..].chars().next().unwrap_or('"');
        let after = &rest[start + 1..];
        let Some(end) = after.find(q) else { break };
        items.push(&after[..end]);
        rest = &after[end + 1..];
    }
    items
}

/// `pyproject.toml`: declared dependencies with no lockfile, VCS / URL requirements, Poetry git
/// tables, and an in-tree build backend (`backend-path`).
pub(super) fn pyproject(rel: &Path, text: &str, pack: &PackFiles<'_>, out: &mut FileOut) {
    let mut first_dep: Option<u32> = None;
    let (mut floating, mut elsewhere) = (0, 0);
    let mut flag = |rule: &'static str, line: u32, out: &mut FileOut| {
        let count = if rule == "dep_floating_source" {
            &mut floating
        } else {
            &mut elsewhere
        };
        if *count < MAX_LOCATED {
            *count += 1;
            out.emit(rule, Severity::Warn, Some(line), Ctx::Meta);
        }
    };
    for e in entries(text) {
        if e.header {
            continue;
        }
        if e.table() == "build-system" && e.key == "backend-path" {
            out.emit("dep_build_script", Severity::Warn, Some(e.line), Ctx::Meta);
            continue;
        }
        let pep621 = (e.table() == "project"
            && (e.key == "dependencies" || e.key == "optional-dependencies"))
            || e.table() == "project.optional-dependencies"
            || e.table() == "dependency-groups"
            || (e.table() == "tool.uv" && e.key == "dev-dependencies");
        let poetry = e.table() == "tool.poetry.dependencies"
            || e.table() == "tool.poetry.dev-dependencies"
            || (e.table().starts_with("tool.poetry.group.")
                && e.table().ends_with(".dependencies"));
        if pep621 {
            let items = array_items(&e.value);
            if !items.is_empty() {
                first_dep.get_or_insert(e.line);
            }
            for item in items {
                match classify(item) {
                    Req::Floating => flag("dep_floating_source", e.line, out),
                    Req::Remote => flag("dep_nonregistry_source", e.line, out),
                    _ => {}
                }
            }
        } else if poetry && e.key != "python" {
            first_dep.get_or_insert(e.line);
            if inline_get(&e.value, "git").is_some() {
                if inline_get(&e.value, "rev").is_some_and(is_commit) {
                    flag("dep_nonregistry_source", e.line, out);
                } else {
                    flag("dep_floating_source", e.line, out);
                }
            } else if inline_get(&e.value, "url").is_some()
                || inline_get(&e.value, "source").is_some()
            {
                flag("dep_nonregistry_source", e.line, out);
            }
        }
    }
    if let Some(line) = first_dep {
        if !pack.has_up(rel, LOCKS) {
            out.emit(
                "dep_lockfile_missing",
                Severity::Warn,
                Some(line),
                Ctx::Meta,
            );
        }
    }
}

/// `setup.py` that runs more than a metadata `setup()` call (see [`ACTIVE_SETUP`]).
pub(super) fn setup_py(text: &str, out: &mut FileOut) {
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim_start();
        if line.starts_with('#') {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if ACTIVE_SETUP.iter().any(|t| lower.contains(t)) {
            out.emit(
                "dep_build_script",
                Severity::Warn,
                Some(line_no(i)),
                Ctx::Meta,
            );
            return;
        }
    }
}

/// `poetry.lock` / `uv.lock`: packages sourced from git, a URL, or an index other than PyPI.
pub(super) fn lock(text: &str, out: &mut FileOut) {
    let mut elsewhere = 0;
    for e in entries(text) {
        if e.header {
            continue;
        }
        let off_pypi = match (e.table(), e.key.as_str()) {
            // poetry.lock `[package.source] type = "git" | "url" | "legacy"` (a custom index).
            ("package.source", "type") => {
                matches!(unquote(&e.value), "git" | "url" | "legacy")
            }
            // uv.lock `source = { registry = "…" }`, `{ git = "…" }`, `{ url = "…" }`.
            ("package", "source") => {
                inline_get(&e.value, "git").is_some()
                    || inline_get(&e.value, "url").is_some()
                    || inline_get(&e.value, "registry").is_some_and(|r| !url_host_in(r, PYPI))
            }
            _ => false,
        };
        if off_pypi && elsewhere < MAX_LOCATED {
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

#[cfg(test)]
mod tests {
    use super::super::tests::{pack, rules_at};
    use super::*;

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn requirement_classes() {
        assert_eq!(classify("requests==2.31.0"), Req::Pinned);
        assert_eq!(classify("x===1"), Req::Pinned);
        assert_eq!(classify("requests>=2"), Req::Unpinned);
        assert_eq!(classify("requests==2.*"), Req::Unpinned);
        assert_eq!(classify("requests"), Req::Unpinned);
        assert_eq!(classify("x==1; python_version<'3.9'"), Req::Pinned);
        assert_eq!(
            classify("git+https://g.invalid/o/r.git@main#egg=r"),
            Req::Floating
        );
        assert_eq!(classify("git+https://g.invalid/o/r.git"), Req::Floating);
        assert_eq!(
            classify(&format!("r @ git+https://g.invalid/o/r.git@{SHA}")),
            Req::Remote
        );
        assert_eq!(classify("git+ssh://git@g.invalid/o/r.git"), Req::Floating);
        assert_eq!(classify("x @ https://f.invalid/x-1.whl"), Req::Remote);
        assert_eq!(classify("./local"), Req::Local);
    }

    #[test]
    fn requirements_lines_and_options() {
        let body = "# deps\nrequests==2.31.0\nflask>=2  # web\n-r other.txt\n--index-url https://pypi.evil.invalid/simple\n--extra-index-url=https://pypi.org/simple\n-e .\n-e git+https://g.invalid/o/r.git#egg=r\nnumpy==1.26.0 \\\n    --hash=sha256:abc\ntorch\n";
        let r = pack(&[("requirements.txt", body)]);
        assert_eq!(
            rules_at(&r, "dep_unpinned"),
            vec![
                ("requirements.txt".into(), Some(3)),
                ("requirements.txt".into(), Some(11))
            ]
        );
        assert_eq!(
            rules_at(&r, "dep_nonregistry_source"),
            vec![("requirements.txt".into(), Some(5))]
        );
        assert_eq!(
            rules_at(&r, "dep_floating_source"),
            vec![("requirements.txt".into(), Some(8))]
        );
    }

    #[test]
    fn pyproject_deps_without_a_lock_and_git_sources() {
        let body = "[build-system]\nrequires = [\"setuptools\"]\nbackend-path = [\".\"]\n[project]\nname = \"x\"\ndependencies = [\n  \"httpx>=0.27\",\n  \"r @ git+https://g.invalid/o/r.git@main\",\n]\n[tool.poetry.dependencies]\npython = \"^3.11\"\ng = { git = \"https://g.invalid/g.git\", branch = \"dev\" }\n";
        let r = pack(&[("pyproject.toml", body)]);
        assert_eq!(
            rules_at(&r, "dep_build_script"),
            vec![("pyproject.toml".into(), Some(3))]
        );
        assert_eq!(
            rules_at(&r, "dep_floating_source"),
            vec![
                ("pyproject.toml".into(), Some(6)),
                ("pyproject.toml".into(), Some(12))
            ]
        );
        assert_eq!(
            rules_at(&r, "dep_lockfile_missing"),
            vec![("pyproject.toml".into(), Some(6))]
        );
        let r = pack(&[("pyproject.toml", body), ("uv.lock", "version = 1\n")]);
        assert!(rules_at(&r, "dep_lockfile_missing").is_empty());
        let r = pack(&[(
            "pyproject.toml",
            "[project]\nname = \"x\"\ndependencies = []\n",
        )]);
        assert!(rules_at(&r, "dep_lockfile_missing").is_empty());
    }

    #[test]
    fn setup_py_only_when_it_runs_something() {
        let plain = "from setuptools import setup\nsetup(name=\"x\", install_requires=[\"a\"])\n";
        assert!(rules_at(&pack(&[("setup.py", plain)]), "dep_build_script").is_empty());
        let active = "import subprocess\nfrom setuptools import setup\nsubprocess.call(['sh', 'x'])\nsetup()\n";
        assert_eq!(
            rules_at(&pack(&[("setup.py", active)]), "dep_build_script"),
            vec![("setup.py".into(), Some(1))]
        );
    }

    #[test]
    fn poetry_and_uv_lock_sources() {
        let poetry = "[[package]]\nname = \"a\"\n\n[[package]]\nname = \"g\"\n[package.source]\ntype = \"git\"\nurl = \"https://g.invalid/g.git\"\n";
        assert_eq!(
            rules_at(&pack(&[("poetry.lock", poetry)]), "dep_nonregistry_source"),
            vec![("poetry.lock".into(), Some(7))]
        );
        let uv = "[[package]]\nname = \"a\"\nsource = { registry = \"https://pypi.org/simple\" }\n[[package]]\nname = \"b\"\nsource = { registry = \"https://corp.invalid/simple\" }\n[[package]]\nname = \"c\"\nsource = { git = \"https://g.invalid/c?rev=x#x\" }\n[[package]]\nname = \"d\"\nsource = { editable = \".\" }\n";
        assert_eq!(
            rules_at(&pack(&[("uv.lock", uv)]), "dep_nonregistry_source"),
            vec![("uv.lock".into(), Some(6)), ("uv.lock".into(), Some(9))]
        );
    }
}
