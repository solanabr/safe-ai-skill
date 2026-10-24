//! npm, pnpm and Yarn: `package.json` dependency specs and lockfile entries.
//!
//! The pack's own `package.json` lifecycle scripts are the `lifecycle` family's; this file
//! looks at what the manifest pulls in and what the lockfile recorded about it.

use std::path::Path;

use serde_json::Value;

use super::super::{line_no, Ctx, FileOut, Severity};
use super::{emit_located, is_commit, json_key_line, url_host_in, PackFiles, MAX_LOCK_ENTRIES};

/// Lockfiles that pin an npm dependency tree.
const LOCKS: &[&str] = &[
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
    "bun.lockb",
];
/// Fields whose entries `npm install` in the package installs.
const DEP_FIELDS: &[&str] = &["dependencies", "devDependencies", "optionalDependencies"];
/// Registries a lockfile may resolve to without a finding.
pub(super) const NPM_REGISTRIES: &[&str] = &[
    "registry.npmjs.org",
    "registry.npmjs.com",
    "registry.yarnpkg.com",
];

/// Where a `package.json` dependency spec comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Spec {
    /// A registry version or range (the lockfile pins it).
    Registry,
    /// A path, `file:`, `link:`, `workspace:` or `portal:` (nothing fetched).
    Local,
    /// A tarball URL, or a git ref pinned to a commit.
    Remote,
    /// A git ref with no commit: whatever the branch or default HEAD is at install time.
    GitFloating,
}

/// Classify one dependency spec (the value of a `dependencies` entry).
pub(super) fn classify(spec: &str) -> Spec {
    let s = spec.trim();
    let lower = s.to_ascii_lowercase();
    let local = ["file:", "link:", "workspace:", "portal:"];
    if local.iter().any(|p| lower.starts_with(p)) || s.starts_with(['.', '/', '~']) {
        return Spec::Local;
    }
    if lower.starts_with("npm:") {
        return Spec::Registry;
    }
    let git_prefix = [
        "git+",
        "git://",
        "git@",
        "github:",
        "gitlab:",
        "bitbucket:",
        "gist:",
    ];
    // `owner/repo` (optionally `#ref`): a GitHub shorthand. Ranges never contain `/`.
    let shorthand = !s.starts_with('@')
        && !s.contains(':')
        && !s.contains(char::is_whitespace)
        && s.split('#')
            .next()
            .is_some_and(|r| r.matches('/').count() == 1)
        && s.chars().next().is_some_and(|c| c.is_ascii_alphanumeric());
    if git_prefix.iter().any(|p| lower.starts_with(p)) || shorthand {
        let commit = s.rsplit_once('#').is_some_and(|(_, r)| is_commit(r));
        return if commit {
            Spec::Remote
        } else {
            Spec::GitFloating
        };
    }
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return Spec::Remote;
    }
    Spec::Registry
}

/// `package.json`: git and URL dependency specs, a missing lockfile, `gypfile: true`.
pub(super) fn manifest(rel: &Path, text: &str, pack: &PackFiles<'_>, out: &mut FileOut) {
    // A manifest that does not parse is the lifecycle family's `manifest_unparsed`.
    let Ok(json) = serde_json::from_str::<Value>(text) else {
        return;
    };
    let mut floating = Vec::new();
    let mut remote = Vec::new();
    let mut first_field: Option<&str> = None;
    for field in DEP_FIELDS {
        let Some(map) = json.get(field).and_then(Value::as_object) else {
            continue;
        };
        if !map.is_empty() && first_field.is_none() {
            first_field = Some(field);
        }
        for (name, spec) in map {
            match spec.as_str().map(classify) {
                Some(Spec::GitFloating) => floating.push(name.clone()),
                Some(Spec::Remote) => remote.push(name.clone()),
                _ => {}
            }
        }
    }
    let locate = |key: &str| json_key_line(text, key);
    emit_located(out, "dep_floating_source", &floating, locate);
    emit_located(out, "dep_nonregistry_source", &remote, locate);
    if let Some(field) = first_field {
        if !pack.has_up(rel, LOCKS) {
            out.emit(
                "dep_lockfile_missing",
                Severity::Warn,
                json_key_line(text, field),
                Ctx::Meta,
            );
        }
    }
    if json.get("gypfile").and_then(Value::as_bool) == Some(true) {
        out.emit(
            "dep_build_script",
            Severity::Warn,
            json_key_line(text, "gypfile"),
            Ctx::Meta,
        );
    }
}

/// True when a lockfile `resolved` URL is not the default registry (git, tarball, mirror).
fn resolved_elsewhere(resolved: &str) -> bool {
    let lower = resolved.trim().to_ascii_lowercase();
    if lower.is_empty() || lower.starts_with("file:") || lower.starts_with("link:") {
        return false;
    }
    !(lower.starts_with("https://") && url_host_in(&lower, NPM_REGISTRIES))
}

/// `package-lock.json` / `npm-shrinkwrap.json`: entries with `hasInstallScript`, entries
/// resolved off the default registry. A v1 lockfile does not record install scripts.
pub(super) fn package_lock(text: &str, out: &mut FileOut) {
    let Ok(json) = serde_json::from_str::<Value>(text) else {
        out.emit("dep_unanalysed", Severity::Warn, None, Ctx::Meta);
        return;
    };
    let mut scripts = Vec::new();
    let mut elsewhere = Vec::new();
    if let Some(packages) = json.get("packages").and_then(Value::as_object) {
        for (key, entry) in packages.iter().take(MAX_LOCK_ENTRIES) {
            if key.is_empty() || entry.get("link").and_then(Value::as_bool) == Some(true) {
                continue;
            }
            if entry.get("hasInstallScript").and_then(Value::as_bool) == Some(true) {
                scripts.push(key.clone());
            }
            if entry
                .get("resolved")
                .and_then(Value::as_str)
                .is_some_and(resolved_elsewhere)
            {
                elsewhere.push(key.clone());
            }
        }
    } else if let Some(deps) = json.get("dependencies").and_then(Value::as_object) {
        // lockfileVersion 1: nested `dependencies`, walked iteratively.
        let mut stack: Vec<(&String, &Value)> = deps.iter().collect();
        let mut walked = 0usize;
        while let Some((name, entry)) = stack.pop() {
            walked += 1;
            if walked > MAX_LOCK_ENTRIES {
                break;
            }
            if entry
                .get("resolved")
                .and_then(Value::as_str)
                .is_some_and(resolved_elsewhere)
            {
                elsewhere.push(name.clone());
            }
            if let Some(nested) = entry.get("dependencies").and_then(Value::as_object) {
                stack.extend(nested.iter());
            }
        }
        out.emit(
            "dep_install_scripts_unknown",
            Severity::Info,
            None,
            Ctx::Meta,
        );
    }
    let locate = |key: &str| json_key_line(text, key);
    emit_located(out, "dep_install_script", &scripts, locate);
    emit_located(out, "dep_nonregistry_source", &elsewhere, locate);
}

/// `pnpm-lock.yaml`, line by line: `requiresBuild: true` (pnpm ≤ 8), tarball resolutions off
/// the registry, git resolutions. pnpm 9 no longer records install scripts.
pub(super) fn pnpm_lock(text: &str, out: &mut FileOut) {
    let mut records_builds = false;
    let (mut scripts, mut elsewhere) = (0, 0);
    for (i, raw) in text.lines().enumerate() {
        let t = raw.trim();
        if t.starts_with("requiresBuild:") {
            records_builds = true;
            if t.ends_with("true") && scripts < super::MAX_LOCATED {
                scripts += 1;
                out.emit(
                    "dep_install_script",
                    Severity::Warn,
                    Some(line_no(i)),
                    Ctx::Meta,
                );
            }
        }
        let git = t == "type: git" || t.contains("type: git,") || t.contains("repo:");
        let tarball = t
            .split("tarball:")
            .nth(1)
            .map(|u| {
                u.trim()
                    .trim_matches(|c| matches!(c, '}' | '"' | '\'' | ',' | ' '))
            })
            .is_some_and(|u| !u.is_empty() && resolved_elsewhere(u));
        if (git || tarball) && elsewhere < super::MAX_LOCATED {
            elsewhere += 1;
            out.emit(
                "dep_nonregistry_source",
                Severity::Warn,
                Some(line_no(i)),
                Ctx::Meta,
            );
        }
    }
    if !records_builds {
        out.emit(
            "dep_install_scripts_unknown",
            Severity::Info,
            None,
            Ctx::Meta,
        );
    }
}

/// `yarn.lock` (classic and Berry): resolutions off the npm registry; Berry `exec:` packages
/// (built by running a script). Neither format records install scripts.
pub(super) fn yarn_lock(text: &str, out: &mut FileOut) {
    let local = ["@workspace:", "@file:", "@link:", "@portal:", "@patch:"];
    let (mut elsewhere, mut exec) = (0, 0);
    for (i, raw) in text.lines().enumerate() {
        let t = raw.trim();
        let off_registry = if let Some(url) = t.strip_prefix("resolved ") {
            resolved_elsewhere(url.trim().trim_matches('"'))
        } else if let Some(res) = t.strip_prefix("resolution:") {
            let res = res.trim().trim_matches('"');
            if res.contains("@exec:") {
                if exec < super::MAX_LOCATED {
                    exec += 1;
                    out.emit(
                        "dep_install_script",
                        Severity::Warn,
                        Some(line_no(i)),
                        Ctx::Meta,
                    );
                }
                false
            } else {
                !res.contains("@npm:") && !local.iter().any(|l| res.contains(l))
            }
        } else {
            false
        };
        if off_registry && elsewhere < super::MAX_LOCATED {
            elsewhere += 1;
            out.emit(
                "dep_nonregistry_source",
                Severity::Warn,
                Some(line_no(i)),
                Ctx::Meta,
            );
        }
    }
    out.emit(
        "dep_install_scripts_unknown",
        Severity::Info,
        None,
        Ctx::Meta,
    );
}

#[cfg(test)]
mod tests {
    use super::super::super::{grade, Grade};
    use super::super::tests::{pack, rules_at};
    use super::*;

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn spec_classes() {
        assert_eq!(classify("^1.2.3"), Spec::Registry);
        assert_eq!(classify("npm:other@1"), Spec::Registry);
        assert_eq!(classify("file:../x"), Spec::Local);
        assert_eq!(classify("workspace:*"), Spec::Local);
        assert_eq!(classify("github:a/b"), Spec::GitFloating);
        assert_eq!(classify("a/b#main"), Spec::GitFloating);
        assert_eq!(classify("git+https://g.invalid/a/b.git"), Spec::GitFloating);
        assert_eq!(classify(&format!("a/b#{SHA}")), Spec::Remote);
        assert_eq!(classify("https://x.invalid/p.tgz"), Spec::Remote);
        assert_eq!(classify("1.0.0 - 2.0.0"), Spec::Registry);
    }

    #[test]
    fn manifest_flags_git_url_specs_and_a_missing_lockfile() {
        let body = format!(
            "{{\n  \"dependencies\": {{\n    \"a\": \"^1\",\n    \"b\": \"github:o/b\",\n    \"c\": \"o/c#{SHA}\",\n    \"d\": \"https://x.invalid/d.tgz\"\n  }}\n}}\n"
        );
        let r = pack(&[("package.json", &body)]);
        assert_eq!(
            rules_at(&r, "dep_floating_source"),
            vec![("package.json".into(), Some(4))]
        );
        let remote = rules_at(&r, "dep_nonregistry_source");
        assert_eq!(remote.len(), 2, "{remote:?}");
        assert_eq!(
            rules_at(&r, "dep_lockfile_missing"),
            vec![("package.json".into(), Some(2))]
        );
        assert_eq!(grade(&r), Grade::Warn);
    }

    #[test]
    fn a_lockfile_beside_or_above_the_manifest_counts() {
        let m = "{\"dependencies\": {\"a\": \"1.0.0\"}}";
        let r = pack(&[
            ("package.json", m),
            ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n"),
        ]);
        assert!(rules_at(&r, "dep_lockfile_missing").is_empty(), "{r:?}");
        let r = pack(&[("pkgs/a/package.json", m), ("package-lock.json", "{}")]);
        assert!(rules_at(&r, "dep_lockfile_missing").is_empty(), "{r:?}");
        let r = pack(&[("package.json", "{\"name\": \"x\", \"devDependencies\": {}}")]);
        assert!(rules_at(&r, "dep_lockfile_missing").is_empty(), "{r:?}");
    }

    #[test]
    fn gypfile_and_binding_gyp_are_build_scripts() {
        let r = pack(&[
            ("package.json", "{\n\"gypfile\": true\n}"),
            ("binding.gyp", "{}"),
        ]);
        let b = rules_at(&r, "dep_build_script");
        assert!(b.contains(&("package.json".into(), Some(2))), "{b:?}");
        assert!(b.contains(&("binding.gyp".into(), None)), "{b:?}");
    }

    #[test]
    fn package_lock_v3_install_scripts_and_off_registry_resolutions() {
        let body = "{\n  \"lockfileVersion\": 3,\n  \"packages\": {\n    \"\": {\"name\": \"root\"},\n    \"node_modules/esbuild\": {\n      \"resolved\": \"https://registry.npmjs.org/esbuild/-/esbuild-0.20.0.tgz\",\n      \"hasInstallScript\": true\n    },\n    \"node_modules/evil\": {\n      \"resolved\": \"https://evil.invalid/evil-1.0.0.tgz\"\n    },\n    \"node_modules/gitdep\": {\n      \"resolved\": \"git+ssh://git@github.com/o/r.git#0123456789abcdef0123456789abcdef01234567\"\n    },\n    \"node_modules/local\": {\"resolved\": \"file:../local\", \"link\": true}\n  }\n}\n";
        let r = pack(&[("package-lock.json", body)]);
        assert_eq!(
            rules_at(&r, "dep_install_script"),
            vec![("package-lock.json".into(), Some(5))]
        );
        assert_eq!(
            rules_at(&r, "dep_nonregistry_source"),
            vec![
                ("package-lock.json".into(), Some(9)),
                ("package-lock.json".into(), Some(12))
            ]
        );
        assert!(rules_at(&r, "dep_install_scripts_unknown").is_empty());
    }

    #[test]
    fn package_lock_v1_is_walked_and_install_scripts_are_unknown() {
        let body = "{\"lockfileVersion\": 1, \"dependencies\": {\"a\": {\"version\": \"1\", \"resolved\": \"https://registry.npmjs.org/a/-/a-1.tgz\", \"dependencies\": {\"b\": {\"resolved\": \"https://mirror.invalid/b.tgz\"}}}}}";
        let r = pack(&[("package-lock.json", body)]);
        assert_eq!(rules_at(&r, "dep_nonregistry_source").len(), 1, "{r:?}");
        assert_eq!(rules_at(&r, "dep_install_scripts_unknown").len(), 1);
    }

    #[test]
    fn unparseable_or_hostile_lockfiles_are_unanalysed_without_panicking() {
        let deep = "[".repeat(10_000) + &"]".repeat(10_000);
        for body in ["{", "not json", deep.as_str(), "{\"packages\": 7}"] {
            let r = pack(&[("package-lock.json", body)]);
            assert!(grade(&r) <= Grade::Warn, "{r:?}");
        }
        let r = pack(&[("package-lock.json", deep.as_str())]);
        assert_eq!(rules_at(&r, "dep_unanalysed").len(), 1);
    }

    #[test]
    fn pnpm_lock_build_flags_tarballs_and_git() {
        let body = "lockfileVersion: '6.0'\npackages:\n  /esbuild@0.20.0:\n    resolution: {integrity: sha512-x}\n    requiresBuild: true\n  /left-pad@1.0.0:\n    resolution: {integrity: sha512-y}\n    requiresBuild: false\n  /evil@1.0.0:\n    resolution: {tarball: https://evil.invalid/evil.tgz}\n  /g@1.0.0:\n    resolution: {commit: abc, repo: https://github.com/o/g, type: git}\n";
        let r = pack(&[("pnpm-lock.yaml", body)]);
        assert_eq!(
            rules_at(&r, "dep_install_script"),
            vec![("pnpm-lock.yaml".into(), Some(5))]
        );
        assert_eq!(
            rules_at(&r, "dep_nonregistry_source"),
            vec![
                ("pnpm-lock.yaml".into(), Some(10)),
                ("pnpm-lock.yaml".into(), Some(12))
            ]
        );
        assert!(rules_at(&r, "dep_install_scripts_unknown").is_empty());
        let r = pack(&[("pnpm-lock.yaml", "lockfileVersion: '9.0'\n")]);
        assert_eq!(rules_at(&r, "dep_install_scripts_unknown").len(), 1);
    }

    #[test]
    fn yarn_classic_and_berry_resolutions() {
        let classic = "a@^1:\n  version \"1.0.0\"\n  resolved \"https://registry.yarnpkg.com/a/-/a-1.0.0.tgz#abc\"\nb@^1:\n  resolved \"https://evil.invalid/b.tgz\"\n";
        let r = pack(&[("yarn.lock", classic)]);
        assert_eq!(
            rules_at(&r, "dep_nonregistry_source"),
            vec![("yarn.lock".into(), Some(5))]
        );
        assert_eq!(rules_at(&r, "dep_install_scripts_unknown").len(), 1);
        let berry = "\"a@npm:^1\":\n  resolution: \"a@npm:1.0.0\"\n\"w@workspace:.\":\n  resolution: \"w@workspace:.\"\n\"g@https://github.com/o/g.git\":\n  resolution: \"g@https://github.com/o/g.git#commit=abc\"\n\"x@exec:./gen.js\":\n  resolution: \"x@exec:./gen.js#./gen.js::hash=1\"\n";
        let r = pack(&[("yarn.lock", berry)]);
        assert_eq!(
            rules_at(&r, "dep_nonregistry_source"),
            vec![("yarn.lock".into(), Some(6))]
        );
        assert_eq!(
            rules_at(&r, "dep_install_script"),
            vec![("yarn.lock".into(), Some(8))]
        );
    }

    #[test]
    fn findings_per_rule_are_capped_in_a_huge_lockfile() {
        let mut body = String::from("{\"packages\": {");
        for i in 0..20_000 {
            body.push_str(&format!(
                "\"node_modules/p{i}\": {{\"hasInstallScript\": true, \"resolved\": \"https://m.invalid/p{i}.tgz\"}},"
            ));
        }
        body.push_str("\"node_modules/z\": {}}}");
        let r = pack(&[("package-lock.json", &body)]);
        assert_eq!(rules_at(&r, "dep_install_script").len(), 5);
        assert_eq!(rules_at(&r, "dep_nonregistry_source").len(), 5);
    }
}
