//! Provenance pinning: resolve a source to an immutable reference.
//!
//! [`classify_source`] reads the source's structure, never a substring:
//! * **Local** paths (`.`, `..`, `~`, `~/x`, `./x`, `../x`, `/x`, `C:\x`) are directories,
//!   never packages.
//! * **GitHub**: a URL whose host is exactly `github.com` / `www.github.com` (`https://`,
//!   `http://`, `git+https://`, `git://`, `ssh://`, `git@github.com:owner/repo`), or the
//!   `owner/repo` / `github:owner/repo` shorthand with an optional `#ref` / `@ref`. A moving ref
//!   (a branch, a tag, the default branch) is a MEDIUM "unpinned ref" finding; a 40-hex commit
//!   SHA is immutable. Resolving a ref to its current SHA needs the GitHub API: isolated in
//!   [`github_resolve_sha`].
//! * **npm** packages (`pkg`, `@scope/pkg`, `npm:pkg`, an npmjs.com package URL) require an exact
//!   version (a range / `@latest` is a finding); a Levenshtein-near match to a popular package
//!   name is a HIGH typosquat finding. The registry lookup (the exact version a dist-tag serves)
//!   is isolated in [`npm_fetch`].
//! * **Other** sources (GitLab and other git hosts, tarball and remote MCP URLs, anything
//!   unparseable) are a MEDIUM `unrecognised_source` finding: nothing about them is checked.
//!
//! The pure logic (URL parsing, ref classification, typosquat distance, version pinning) is
//! fully unit-tested with fixtures; the network functions are thin, optional, and in tests talk
//! to a loopback server only.

use super::{Finding, Report, Severity};

/// Popular Solana / MCP package names used as the typosquat reference set.
const POPULAR_PACKAGES: &[&str] = &[
    "helius-mcp",
    "@solana/web3.js",
    "@solana/kit",
    "@coral-xyz/anchor",
    "@solana/spl-token",
    "@metaplex-foundation/umi",
    "@solana-developers/helpers",
    "solana-agent-kit",
    "@modelcontextprotocol/sdk",
    "rugcheck",
    "jupiter-ag",
];

/// npm registry base URL.
const NPM_REGISTRY: &str = "https://registry.npmjs.org";

/// GitHub REST API base URL.
const GITHUB_API: &str = "https://api.github.com";

/// Test-only override of [`NPM_REGISTRY`], read only in `test-hooks` builds.
pub const TEST_NPM_REGISTRY_ENV: &str = "SAFE_AI_SKILL_TEST_NPM_REGISTRY";

/// Test-only override of [`GITHUB_API`], read only in `test-hooks` builds.
pub const TEST_GITHUB_API_ENV: &str = "SAFE_AI_SKILL_TEST_GITHUB_API";

/// Kind of source resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    /// A GitHub repository URL or `owner/repo` shorthand.
    GitHub,
    /// An npm package spec.
    Npm,
    /// A local path: a directory, never a package.
    Local,
    /// Anything not recognized.
    Other,
}

/// The immutable identity resolved from a source (best-effort, network-free).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Resolved {
    /// Source kind label (`"github"`/`"npm"`/`"local"`/`"other"`).
    pub kind: String,
    /// GitHub `owner` or npm scope, when applicable.
    pub owner: String,
    /// GitHub repo or npm package name.
    pub name: String,
    /// The requested ref / version (branch, tag, SHA, or semver).
    pub reference: String,
    /// True when [`reference`](Self::reference) is already immutable (commit SHA / exact ver).
    pub immutable: bool,
    /// The exact version / full commit SHA graded: [`reference`](Self::reference) when it is
    /// immutable, else what an online lookup ([`pin_npm`], [`pin_github`]) resolved it to;
    /// empty when nothing is pinned.
    pub pin: String,
    /// GitHub: the directory inside the repository (`…/tree/<ref>/<path>`, `owner/repo/<path>`).
    pub subpath: String,
    /// GitHub: the skill the skills CLI's `owner/repo@<skill>` form selects.
    pub skill: String,
    /// GitHub: the source is an SSH form (`git@github.com:…`, `ssh://`).
    pub ssh: bool,
}

impl Resolved {
    /// A local directory: nothing to resolve.
    pub fn local(path: &str) -> Self {
        Resolved {
            kind: "local".into(),
            reference: path.to_string(),
            ..Default::default()
        }
    }
}

/// Resolve `source` to an immutable ref and flag provenance risks (network-free).
///
/// Dispatches on the source shape, parses the identity, and emits findings. Returns only the
/// [`Report`]; callers that also want the resolved identity use [`resolve_with_identity`].
pub fn resolve(source: &str) -> Report {
    resolve_with_identity(source).1
}

/// Like [`resolve`], but also returns the parsed [`Resolved`] identity.
pub fn resolve_with_identity(source: &str) -> (Resolved, Report) {
    let mut report = Report::default();
    let kind = classify_source(source);
    let resolved = match kind {
        SourceKind::GitHub => resolve_github(source, &mut report),
        SourceKind::Npm => resolve_npm(source, &mut report),
        SourceKind::Local => Resolved::local(source),
        SourceKind::Other => {
            report.findings.push(Finding::new(
                Severity::Medium,
                "unrecognised_source",
                format!(
                    "safe-ai-skill could not check `{}`: it is not a GitHub repository, an npm \
                     package or a local directory, so nothing about it was verified",
                    source.trim()
                ),
            ));
            Resolved {
                kind: "other".into(),
                reference: source.to_string(),
                ..Default::default()
            }
        }
    };
    (resolved, report)
}

/// Classify a source string into a [`SourceKind`] by its structure.
pub fn classify_source(source: &str) -> SourceKind {
    let s = source.trim();
    if is_local_path(s) {
        return SourceKind::Local;
    }
    if github_path(s.split('#').next().unwrap_or(s)).is_some() || parse_github_source(s).is_some() {
        return SourceKind::GitHub;
    }
    if npm_spec(s).is_some() {
        return SourceKind::Npm;
    }
    SourceKind::Other
}

/// True for a local path: `.`, `..`, `~`, `~/…`, `./…`, `../…`, an absolute path, or a
/// Windows drive / UNC / `.\` path.
pub fn is_local_path(source: &str) -> bool {
    let s = source.trim();
    let b = s.as_bytes();
    matches!(s, "." | ".." | "~")
        || ["~/", "./", "../", "/", ".\\", "..\\", "\\\\"]
            .iter()
            .any(|p| s.starts_with(p))
        || (b.len() >= 3
            && b[0].is_ascii_alphabetic()
            && b[1] == b':'
            && matches!(b[2], b'\\' | b'/'))
}

/// True when `source` is an `http://` / `https://` URL with a host.
pub fn is_http_url(source: &str) -> bool {
    url_host(source.trim()).is_some()
}

/// The lowercased host of an `http(s)://` URL (userinfo and port dropped).
pub fn url_host(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    if !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https") {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = host.split(':').next().unwrap_or("").to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

// ---------------------------------------------------------------------------------------
// GitHub
// ---------------------------------------------------------------------------------------

/// A parsed GitHub source.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GitHubSource {
    /// Repository owner.
    pub owner: String,
    /// Repository name (no `.git`).
    pub repo: String,
    /// The requested ref; empty for the default branch.
    pub reference: String,
    /// The directory inside the repository; empty for its root.
    pub subpath: String,
    /// The skill the skills CLI's `owner/repo@<skill>` form selects; usually empty.
    pub skill: String,
    /// An SSH form (`git@github.com:…`, `ssh://`, `git+ssh://`).
    pub ssh: bool,
}

/// Parse a GitHub URL into `(owner, repo, ref)`. `ref` is empty when absent.
///
/// See [`parse_github_source`] for the accepted forms.
pub fn parse_github(url: &str) -> Option<(String, String, String)> {
    parse_github_source(url).map(|g| (g.owner, g.repo, g.reference))
}

/// Parse a GitHub source, or `None` when it is not one.
///
/// URLs whose host is exactly `github.com` / `www.github.com` (`https`, `http`, `git+https`,
/// `git`, `ssh`, `git+ssh`, schemeless `github.com/…`, scp-style `git@github.com:owner/repo`)
/// with an optional `.git`, `tree/<ref>[/<path>]`, `commit/<sha>`, `blob/<ref>/…` or `#<ref>`;
/// and the `owner/repo[/<path>]` / `github:owner/repo` shorthand with an optional `#<ref>`, or
/// `@<ref>` where `<ref>` is a version tag or a full commit SHA (anything else after `@` names a
/// skill, as in the skills CLI). Owner, repo and ref must be well-formed GitHub names.
pub fn parse_github_source(source: &str) -> Option<GitHubSource> {
    let s = source.trim();
    let (base, fragment) = match s.split_once('#') {
        Some((b, f)) => (b, Some(f)),
        None => (s, None),
    };
    if let Some(f) = fragment {
        if !is_ref_name(f) {
            return None;
        }
    }
    let mut parsed = match github_path(base) {
        Some((path, ssh)) => parse_github_url_path(path, ssh)?,
        None => parse_github_shorthand(base.strip_prefix("github:").unwrap_or(base))?,
    };
    if let Some(f) = fragment {
        parsed.reference = f.to_string();
    }
    Some(parsed)
}

/// The path after the host when `s` is a URL (or the scp-style `git@github.com:…`) whose host
/// is exactly `github.com` / `www.github.com`, and whether it is an SSH form. `None` for any
/// other host or scheme, so `https://evil.example/github.com/…` is not GitHub.
fn github_path(s: &str) -> Option<(&str, bool)> {
    if let Some(rest) = s.strip_prefix("git@github.com:") {
        return Some((rest, true));
    }
    let (scheme, rest) = match s.split_once("://") {
        Some((scheme, rest)) => (Some(scheme.to_ascii_lowercase()), rest),
        None => (None, s),
    };
    let ssh = match scheme.as_deref() {
        Some("https" | "http" | "git+https" | "git+http" | "git") | None => false,
        Some("ssh" | "git+ssh") => true,
        Some(_) => return None,
    };
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let host = match authority.rsplit_once('@') {
        // `github.com/…` with no scheme takes no userinfo.
        Some(_) if scheme.is_none() => return None,
        Some((_, host)) => host,
        None => authority,
    };
    let host = host.to_ascii_lowercase();
    (host == "github.com" || host == "www.github.com").then_some((path, ssh))
}

/// `owner/repo[.git][/tree/<ref>[/<path>] | /commit/<sha> | /blob/<ref>/…][?query]`.
fn parse_github_url_path(path: &str, ssh: bool) -> Option<GitHubSource> {
    let path = path.split('?').next().unwrap_or(path);
    let mut parts = path.split('/').filter(|p| !p.is_empty());
    let owner = parts.next()?;
    let repo = parts.next()?;
    let repo = repo.strip_suffix(".git").unwrap_or(repo);
    if !is_owner_name(owner) || !is_repo_name(repo) {
        return None;
    }
    let rest: Vec<&str> = parts.collect();
    let (reference, subpath) = match rest.as_slice() {
        ["tree", r, sub @ ..] => (r.to_string(), sub.join("/")),
        ["commit" | "blob", r, ..] => (r.to_string(), String::new()),
        _ => (String::new(), String::new()),
    };
    if (!reference.is_empty() && !is_ref_name(&reference)) || !is_subpath(&subpath) {
        return None;
    }
    Some(GitHubSource {
        owner: owner.to_string(),
        repo: repo.to_string(),
        reference,
        subpath,
        skill: String::new(),
        ssh,
    })
}

/// `owner/repo[/<path>]`, then an optional `@<tag | sha | skill>` straight after `owner/repo`.
fn parse_github_shorthand(s: &str) -> Option<GitHubSource> {
    if s.contains(':') || s.contains('\\') {
        return None;
    }
    let (path, at) = match s.split_once('@') {
        Some((p, a)) => (p, Some(a)),
        None => (s, None),
    };
    let mut parts = path.split('/');
    let owner = parts.next()?;
    let repo = parts.next()?;
    let subpath: Vec<&str> = parts.collect();
    if !is_owner_name(owner) || !is_repo_name(repo) {
        return None;
    }
    let subpath = subpath.join("/");
    if !is_subpath(&subpath) || (at.is_some() && !subpath.is_empty()) {
        return None;
    }
    let (reference, skill) = match at {
        Some(a) if is_commit_sha(a) || is_version_tag(a) => (a.to_string(), String::new()),
        Some(a) if is_plain_name(a) => (String::new(), a.to_string()),
        Some(_) => return None,
        None => (String::new(), String::new()),
    };
    Some(GitHubSource {
        owner: owner.to_string(),
        repo: repo.to_string(),
        reference,
        subpath,
        skill,
        ssh: false,
    })
}

/// A GitHub owner: 1-39 of `[A-Za-z0-9_-]`, not starting with `-`.
fn is_owner_name(s: &str) -> bool {
    (1..=39).contains(&s.len())
        && !s.starts_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A GitHub repository name: 1-100 of `[A-Za-z0-9._-]`, not `.`/`..`, not starting with `-`.
fn is_repo_name(s: &str) -> bool {
    (1..=100).contains(&s.len()) && s != "." && s != ".." && is_plain_name(s)
}

/// `[A-Za-z0-9._-]+`, not starting with `-` (a flag) or `.`/`..` alone.
fn is_plain_name(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('-')
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A git ref name safe to pass on: `[A-Za-z0-9._/+-]`, no `..`, not starting with `-` or `/`.
fn is_ref_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && !s.starts_with(['-', '/'])
        && !s.contains("..")
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'+' | b'-'))
}

/// Empty, or `/`-separated [`is_plain_name`] segments (no `.`/`..` segment).
fn is_subpath(s: &str) -> bool {
    s.is_empty() || s.split('/').all(is_plain_name)
}

/// A version tag the skills CLI treats as a ref after `@`: `v1.2`, `1.2.3`, `1.2.3-rc.1+b`.
fn is_version_tag(s: &str) -> bool {
    let core = s.strip_prefix('v').unwrap_or(s);
    let (core, suffix) = match core.find(['-', '+']) {
        Some(i) => (&core[..i], &core[i..]),
        None => (core, ""),
    };
    let numeric: Vec<&str> = core.split('.').collect();
    numeric.len() >= 2
        && numeric
            .iter()
            .all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        && suffix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))
}

/// True if `r` is a moving ref (branch / `HEAD`) rather than an immutable one.
pub fn is_moving_ref(r: &str) -> bool {
    let r = r.trim();
    if r.is_empty() {
        return true; // no ref given → defaults to the default branch → moving
    }
    matches!(
        r.to_lowercase().as_str(),
        "main" | "master" | "head" | "develop" | "dev"
    ) || !is_commit_sha(r)
}

/// True if `r` looks like a full 40-char hex commit SHA.
pub fn is_commit_sha(r: &str) -> bool {
    r.len() == 40 && r.bytes().all(|b| b.is_ascii_hexdigit())
}

fn resolve_github(source: &str, report: &mut Report) -> Resolved {
    let Some(parsed) = parse_github_source(source) else {
        report.findings.push(Finding::new(
            Severity::Medium,
            "unparseable_source",
            "could not parse a GitHub owner/repo from the source URL",
        ));
        return Resolved {
            kind: "github".into(),
            reference: source.to_string(),
            ..Default::default()
        };
    };

    let immutable = is_commit_sha(&parsed.reference);
    if !immutable {
        report.findings.push(Finding::new(
            Severity::Medium,
            "unpinned_ref",
            format!(
                "GitHub ref `{}` is moving; pin to a commit SHA for immutability",
                shown_ref(&parsed.reference)
            ),
        ));
    }

    Resolved {
        kind: "github".into(),
        owner: parsed.owner,
        name: parsed.repo,
        pin: if immutable {
            parsed.reference.clone()
        } else {
            String::new()
        },
        reference: parsed.reference,
        immutable,
        subpath: parsed.subpath,
        skill: parsed.skill,
        ssh: parsed.ssh,
    }
}

/// A GitHub ref as findings name it (`default branch` when none was given).
pub fn shown_ref(reference: &str) -> String {
    if reference.is_empty() {
        "default branch".to_string()
    } else {
        reference.to_string()
    }
}

/// Online: pin a GitHub source's moving ref to the commit it names now ([`github_resolve_sha`]),
/// recorded in [`Resolved::pin`]. True when pinned; a no-op for any other source.
pub fn pin_github(resolved: &mut Resolved) -> bool {
    if resolved.kind != "github" || resolved.immutable || resolved.owner.is_empty() {
        return false;
    }
    match github_resolve_sha(&resolved.owner, &resolved.name, &resolved.reference) {
        Some(sha) => {
            resolved.pin = sha;
            true
        }
        None => false,
    }
}

// ---------------------------------------------------------------------------------------
// npm
// ---------------------------------------------------------------------------------------

/// Parse an npm spec into `(name, version)`. `version` is empty when absent.
///
/// Handles `pkg`, `[email protected]`, `@scope/pkg`, `@scope/[email protected]`, and an `npm:` prefix.
pub fn parse_npm(spec: &str) -> (String, String) {
    let s = spec.trim().strip_prefix("npm:").unwrap_or(spec.trim());
    if let Some(rest) = s.strip_prefix('@') {
        // Scoped: the version `@` is the one *after* the scope separator.
        match rest.split_once('@') {
            Some((np, ver)) => (format!("@{np}"), ver.to_string()),
            None => (format!("@{rest}"), String::new()),
        }
    } else {
        match s.split_once('@') {
            Some((np, ver)) => (np.to_string(), ver.to_string()),
            None => (s.to_string(), String::new()),
        }
    }
}

/// A well-formed npm `(name, version)` from `source`, or `None` when it is not an npm spec.
///
/// [`parse_npm`]'s forms, plus an `https://www.npmjs.com/package/<name>[/v/<version>]` URL;
/// the name must be a valid npm name (`[A-Za-z0-9._-]`, optionally `@scope/`), the version
/// (when present) a version, tag or range.
pub fn npm_spec(source: &str) -> Option<(String, String)> {
    let s = source.trim();
    let (name, version) = match npmjs_package_path(s) {
        Some(path) => match path.split_once("/v/") {
            Some((name, version)) => (name.to_string(), version.to_string()),
            None => (path.trim_end_matches('/').to_string(), String::new()),
        },
        None if s.contains("://") => return None,
        None => parse_npm(s),
    };
    let valid_name = match name.strip_prefix('@') {
        Some(scoped) => scoped
            .split_once('/')
            .is_some_and(|(scope, pkg)| is_npm_name_part(scope) && is_npm_name_part(pkg)),
        None => is_npm_name_part(&name),
    };
    let valid_version = version.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'.' | b'+' | b'-' | b'_' | b'^' | b'~' | b'<' | b'>' | b'=' | b'*' | b'|' | b' '
            )
    });
    (valid_name && valid_version).then_some((name, version))
}

/// The `<name>[/v/<version>]` path of an npmjs.com package page URL.
fn npmjs_package_path(s: &str) -> Option<&str> {
    let host = url_host(s)?;
    if host != "npmjs.com" && host != "www.npmjs.com" {
        return None;
    }
    let (_, rest) = s.split_once("://")?;
    let path = rest.split_once('/').map_or("", |(_, p)| p);
    let path = path.split(['?', '#']).next().unwrap_or(path);
    path.strip_prefix("package/")
}

/// One part of an npm name (the scope, or the name): `[A-Za-z0-9._-]`, at most 214 bytes, not
/// starting with `.`, `_` or `-`.
fn is_npm_name_part(s: &str) -> bool {
    (1..=214).contains(&s.len())
        && !s.starts_with(['.', '_', '-'])
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// True if `version` is an exact pin (a concrete `major.minor.patch` semver, optionally with a
/// pre-release / build suffix), not a range, a partial version (`1`, `1.2`), a tag or `latest`.
pub fn is_exact_version(version: &str) -> bool {
    let v = version.trim();
    let core = v.strip_prefix('v').unwrap_or(v);
    let (core, suffix) = match core.find(['-', '+']) {
        Some(i) => (&core[..i], Some(&core[i + 1..])),
        None => (core, None),
    };
    let numeric: Vec<&str> = core.split('.').collect();
    numeric.len() == 3
        && numeric
            .iter()
            .all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        && suffix.is_none_or(|s| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))
        })
}

/// True if `version` names an npm dist-tag (`latest`, `next`, …) or nothing: what the registry
/// can resolve to one exact version. A range (`^1`, `1.x`, `>=2`) is not one.
pub fn is_dist_tag(version: &str) -> bool {
    let v = version.trim();
    v.is_empty()
        || (v.starts_with(|c: char| c.is_ascii_alphabetic())
            && !v.eq_ignore_ascii_case("x")
            && v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')))
}

fn resolve_npm(source: &str, report: &mut Report) -> Resolved {
    let (name, version) = npm_spec(source).unwrap_or_else(|| parse_npm(source));

    // Typosquat check against popular packages.
    if let Some((target, dist)) = nearest_popular(&name) {
        if (1..=2).contains(&dist) {
            report.findings.push(Finding::new(
                Severity::High,
                "typosquat",
                format!("`{name}` is within edit-distance {dist} of popular package `{target}`"),
            ));
        }
    }

    let immutable = is_exact_version(&version);
    if !immutable {
        report.findings.push(Finding::new(
            Severity::Medium,
            "unpinned_version",
            format!(
                "npm version `{}` is not an exact pin (use `name@x.y.z`)",
                shown_version(&version)
            ),
        ));
    }

    // Owner = scope for scoped packages.
    let owner = name
        .strip_prefix('@')
        .and_then(|s| s.split_once('/'))
        .map(|(scope, _)| format!("@{scope}"))
        .unwrap_or_default();

    Resolved {
        kind: "npm".into(),
        owner,
        name,
        pin: if immutable {
            version.clone()
        } else {
            String::new()
        },
        reference: version,
        immutable,
        ..Default::default()
    }
}

/// An npm version as findings name it (`unspecified` when none was given).
pub fn shown_version(version: &str) -> String {
    if version.is_empty() {
        "unspecified".to_string()
    } else {
        version.to_string()
    }
}

/// Online: pin an npm source's dist-tag (or missing version) to the exact version the registry
/// serves now ([`npm_fetch`]), recorded in [`Resolved::pin`]. True when pinned; a no-op for a
/// range, an exact version or any other source.
pub fn pin_npm(resolved: &mut Resolved) -> bool {
    if resolved.kind != "npm" || resolved.immutable || !is_dist_tag(&resolved.reference) {
        return false;
    }
    match npm_fetch(&resolved.name, &resolved.reference) {
        Some(version) => {
            resolved.pin = version;
            true
        }
        None => false,
    }
}

/// Find the nearest popular package by Levenshtein distance. Exact match → distance 0.
pub fn nearest_popular(name: &str) -> Option<(&'static str, usize)> {
    let mut best: Option<(&'static str, usize)> = None;
    for &pkg in POPULAR_PACKAGES {
        if pkg == name {
            return Some((pkg, 0));
        }
        let d = levenshtein(name, pkg);
        if best.map(|(_, bd)| d < bd).unwrap_or(true) {
            best = Some((pkg, d));
        }
    }
    best
}

/// Classic Levenshtein edit distance.
pub fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let n = b.len();
    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr: Vec<usize> = vec![0; n + 1];
    for (i, ca) in a.iter().enumerate() {
        curr[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            curr[j + 1] = (prev[j + 1] + 1).min(curr[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[n]
}

// ---------------------------------------------------------------------------------------
// Network (isolated — never exercised by unit tests)
// ---------------------------------------------------------------------------------------

/// Resolve a GitHub `owner/repo` ref to its current commit SHA via the GitHub API.
///
/// Isolated and optional: on any network error returns `None` (caller treats the ref as
/// unresolved rather than failing). Unit tests drive [`github_resolve_sha_at`] against a
/// loopback server only.
pub fn github_resolve_sha(owner: &str, repo: &str, reference: &str) -> Option<String> {
    github_resolve_sha_at(
        &base_url(GITHUB_API, TEST_GITHUB_API_ENV),
        owner,
        repo,
        reference,
    )
}

/// [`github_resolve_sha`] against the API at `base`.
pub fn github_resolve_sha_at(
    base: &str,
    owner: &str,
    repo: &str,
    reference: &str,
) -> Option<String> {
    let r = if reference.is_empty() {
        "HEAD"
    } else {
        reference
    };
    let url = format!(
        "{base}/repos/{}/{}/commits/{}",
        percent_encode(owner),
        percent_encode(repo),
        percent_encode(r)
    );
    let resp = ureq::agent()
        .get(&url)
        .timeout(std::time::Duration::from_secs(4))
        .set("User-Agent", "safe-ai-skill")
        .set("Accept", "application/vnd.github.sha")
        .call()
        .ok()?;
    let sha = resp.into_string().ok()?;
    let sha = sha.trim().to_ascii_lowercase();
    if is_commit_sha(&sha) {
        Some(sha)
    } else {
        None
    }
}

/// The exact version npm package `name` serves for dist-tag `tag` (`latest` when empty).
///
/// Isolated and optional: `None` on any network/parse error, or when the reply is not for
/// `name` or names no exact version. Unit tests drive [`npm_fetch_at`] against a loopback
/// server only; [`parse_npm_version`] parses a fixture body.
pub fn npm_fetch(name: &str, tag: &str) -> Option<String> {
    npm_fetch_at(&base_url(NPM_REGISTRY, TEST_NPM_REGISTRY_ENV), name, tag)
}

/// [`npm_fetch`] against the registry at `base`.
pub fn npm_fetch_at(base: &str, name: &str, tag: &str) -> Option<String> {
    let tag = if tag.is_empty() { "latest" } else { tag };
    let url = format!(
        "{base}/{}/{}",
        name.replacen('/', "%2F", 1),
        percent_encode(tag)
    );
    let resp = ureq::agent()
        .get(&url)
        .timeout(std::time::Duration::from_secs(4))
        .set("User-Agent", "safe-ai-skill")
        .call()
        .ok()?;
    let body = resp.into_string().ok()?;
    parse_npm_version(&body, name)
}

/// The exact `version` of an npm registry version document for package `name`. Pure.
pub fn parse_npm_version(body: &str, name: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    if value.get("name").and_then(|n| n.as_str()) != Some(name) {
        return None;
    }
    let version = value.get("version").and_then(|v| v.as_str())?;
    is_exact_version(version).then(|| version.to_string())
}

/// `default`, or in a `test-hooks` build the URL in env `var` when it is set.
fn base_url(default: &str, var: &str) -> String {
    #[cfg(feature = "test-hooks")]
    if let Ok(url) = std::env::var(var) {
        return url.trim_end_matches('/').to_string();
    }
    #[cfg(not(feature = "test-hooks"))]
    let _ = var;
    default.to_string()
}

/// Percent-encode everything but RFC 3986 unreserved characters (one URL path segment).
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Parse `dist.shasum` out of an npm registry response body. Pure — unit-testable.
pub fn parse_npm_shasum(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    value
        .get("dist")
        .and_then(|d| d.get("shasum"))
        .and_then(|s| s.as_str())
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(report: &Report) -> Vec<String> {
        report.findings.iter().map(|f| f.kind.clone()).collect()
    }

    /// Join a package name and version with `@`. Built at runtime so the literal
    /// `name@version` form never appears in source (avoids fixture mangling).
    fn pin(name: &str, version: &str) -> String {
        format!("{name}{}{version}", '@')
    }

    #[test]
    fn classify_sources() {
        assert_eq!(
            classify_source("https://github.com/a/b"),
            SourceKind::GitHub
        );
        assert_eq!(classify_source("@solana/web3.js"), SourceKind::Npm);
        assert_eq!(classify_source("helius-mcp"), SourceKind::Npm);
        assert_eq!(
            classify_source(&format!("npm:{}", pin("helius-mcp", "1.0.0"))),
            SourceKind::Npm
        );
    }

    #[test]
    fn github_is_classified_by_host_not_substring() {
        let sha = "a".repeat(40);
        let scp = format!("git{}github.com:owner/repo.git", '@');
        let ssh = format!("ssh://git{}github.com/owner/repo.git", '@');
        for s in [
            "https://github.com/owner/repo",
            "http://github.com/owner/repo",
            "git+https://github.com/owner/repo.git",
            "git://github.com/owner/repo.git",
            "https://www.github.com/owner/repo",
            "HTTPS://GitHub.com/owner/repo",
            "github.com/owner/repo",
            scp.as_str(),
            ssh.as_str(),
        ] {
            assert_eq!(classify_source(s), SourceKind::GitHub, "{s}");
        }
        let at_userinfo = format!("https://github.com{}evil.example/a/b", '@');
        for s in [
            format!("https://evil.example/github.com/a/b/commit/{sha}"),
            format!("https://github.com.evil.example/a/b/commit/{sha}"),
            at_userinfo,
            "https://evilgithub.com/a/b".to_string(),
            "https://gist.github.com/a/b".to_string(),
            "https://raw.githubusercontent.com/a/b/main/x".to_string(),
            "ftp://github.com/a/b".to_string(),
        ] {
            assert_eq!(classify_source(&s), SourceKind::Other, "{s}");
        }
    }

    #[test]
    fn a_spoofed_github_host_is_unrecognised_and_holds() {
        let sha = "a".repeat(40);
        let report = resolve(&format!("https://evil.example/github.com/a/b/commit/{sha}"));
        assert_eq!(kinds(&report), vec!["unrecognised_source".to_string()]);
        assert_eq!(report.max_severity(), Some(Severity::Medium));
    }

    #[test]
    fn shorthand_is_github() {
        let sha = "b".repeat(40);
        for s in [
            "owner/repo".to_string(),
            "github:owner/repo".to_string(),
            "owner/repo#main".to_string(),
            "github:owner/repo#v1.0.0".to_string(),
            pin("owner/repo", "v1.2.3"),
            pin("owner/repo", &sha),
            pin("owner/repo", "my-skill"),
            "owner/repo/skills/x".to_string(),
        ] {
            assert_eq!(classify_source(&s), SourceKind::GitHub, "{s}");
        }
        let (resolved, report) = resolve_with_identity(&pin("owner/repo", &sha));
        assert!(
            resolved.immutable && report.findings.is_empty(),
            "{report:?}"
        );
        assert_eq!(
            (resolved.owner.as_str(), resolved.pin.as_str()),
            ("owner", sha.as_str())
        );
        // Not owner/repo: a bad owner, a dot-led name, an option-like name.
        for s in [".claude/skills", "-x/y", "a b/c", "owner/repo/../x"] {
            assert_ne!(classify_source(s), SourceKind::GitHub, "{s}");
        }
    }

    #[test]
    fn github_source_parts() {
        let g = parse_github_source("https://github.com/o/r/tree/main/skills/x?tab=1").unwrap();
        assert_eq!(
            (
                g.owner.as_str(),
                g.repo.as_str(),
                g.reference.as_str(),
                g.subpath.as_str()
            ),
            ("o", "r", "main", "skills/x")
        );
        let g = parse_github_source("o/r/skills/x#dev").unwrap();
        assert_eq!(
            (g.reference.as_str(), g.subpath.as_str()),
            ("dev", "skills/x")
        );
        let g = parse_github_source(&pin("o/r", "my-skill")).unwrap();
        assert_eq!((g.reference.as_str(), g.skill.as_str()), ("", "my-skill"));
        let g = parse_github_source(&pin("o/r", "v2.1.0")).unwrap();
        assert_eq!((g.reference.as_str(), g.skill.as_str()), ("v2.1.0", ""));
        let g = parse_github_source(&format!("git{}github.com:o/r.git", '@')).unwrap();
        assert!(g.ssh && g.repo == "r");
        // A ref or path a shell or git would read as something else is not a GitHub source.
        assert_eq!(parse_github_source("o/r#$(id)"), None);
        assert_eq!(parse_github_source("https://github.com/o/r/tree/-x"), None);
        assert_eq!(
            parse_github_source("https://github.com/o/r/tree/main/../x"),
            None
        );
        // An unparseable github.com URL is still GitHub, and holds.
        let report = resolve("https://github.com/only-owner");
        assert_eq!(kinds(&report), vec!["unparseable_source".to_string()]);
    }

    #[test]
    fn local_paths_are_never_npm() {
        for s in [
            ".", "..", "~", "~/x", "./x", "../x", "/abs/x", "C:\\x", "C:/x", ".\\x",
        ] {
            assert_eq!(classify_source(s), SourceKind::Local, "{s}");
            let (resolved, report) = resolve_with_identity(s);
            assert_eq!(resolved.kind, "local", "{s}");
            assert!(report.findings.is_empty(), "{s}: {report:?}");
        }
    }

    #[test]
    fn other_sources_are_unrecognised_and_hold() {
        let scp = format!("git{}gitlab.com:o/r.git", '@');
        for s in [
            "https://gitlab.com/org/repo",
            scp.as_str(),
            "https://example.com/skill.tgz",
            "https://mcp.example.com/mcp",
            "gitlab:o/r",
            "file:./x",
            "foo bar",
            "",
        ] {
            assert_eq!(classify_source(s), SourceKind::Other, "{s}");
            let report = resolve(s);
            assert_eq!(
                kinds(&report),
                vec!["unrecognised_source".to_string()],
                "{s}"
            );
            assert_eq!(report.max_severity(), Some(Severity::Medium), "{s}");
            assert!(report.findings[0].detail.contains("could not check"), "{s}");
        }
    }

    #[test]
    fn npm_specs() {
        assert_eq!(
            npm_spec("https://www.npmjs.com/package/x402-proxy"),
            Some(("x402-proxy".into(), "".into()))
        );
        assert_eq!(
            npm_spec("https://www.npmjs.com/package/@scope/pkg/v/1.2.3"),
            Some(("@scope/pkg".into(), "1.2.3".into()))
        );
        assert_eq!(
            npm_spec(&pin("left-pad", "^1.0.0")),
            Some(("left-pad".into(), "^1.0.0".into()))
        );
        for s in [
            "Foo Bar",
            &pin("pkg", "1.0.0;id"),
            "@scope",
            "@/x",
            ".hidden",
            "https://npmjs.org.evil/package/x",
        ] {
            assert_eq!(npm_spec(s), None, "{s}");
        }
    }

    #[test]
    fn dist_tags_and_ranges() {
        for v in ["", "latest", "next", "beta-2"] {
            assert!(is_dist_tag(v), "{v}");
        }
        for v in ["1", "1.x", "^1.0.0", ">=2", "x", "*", "1.2.3"] {
            assert!(!is_dist_tag(v), "{v}");
        }
    }

    #[test]
    fn parse_npm_version_fixture() {
        let body = r#"{"name":"left-pad","version":"1.3.0","dist":{"shasum":"x"}}"#;
        assert_eq!(parse_npm_version(body, "left-pad"), Some("1.3.0".into()));
        assert_eq!(parse_npm_version(body, "right-pad"), None);
        assert_eq!(
            parse_npm_version(r#"{"name":"a","version":"^1"}"#, "a"),
            None
        );
        assert_eq!(parse_npm_version("not json", "a"), None);
    }

    #[test]
    fn npm_fetch_against_a_loopback_registry() {
        let base = crate::verify::testnet::serve(|method, path, _| match (method, path) {
            ("GET", "/left-pad/latest") => (200, r#"{"name":"left-pad","version":"1.3.0"}"#.into()),
            ("GET", "/@scope%2Fpkg/next") => (
                200,
                r#"{"name":"@scope/pkg","version":"2.0.0-rc.1"}"#.into(),
            ),
            ("GET", "/garbage/latest") => (200, "<html>".into()),
            _ => (404, r#""version not found""#.into()),
        });
        assert_eq!(npm_fetch_at(&base, "left-pad", ""), Some("1.3.0".into()));
        assert_eq!(
            npm_fetch_at(&base, "@scope/pkg", "next"),
            Some("2.0.0-rc.1".into())
        );
        assert_eq!(npm_fetch_at(&base, "nope", "latest"), None);
        assert_eq!(npm_fetch_at(&base, "garbage", "latest"), None);
        assert_eq!(
            npm_fetch_at(&crate::verify::testnet::closed(), "left-pad", ""),
            None
        );
    }

    #[test]
    fn github_resolve_against_a_loopback_api() {
        let sha = "c".repeat(40);
        let reply = sha.clone();
        let base = crate::verify::testnet::serve(move |_, path, _| match path {
            "/repos/o/r/commits/HEAD" | "/repos/o/r/commits/feature%2Fx" => (200, reply.clone()),
            "/repos/o/r/commits/junk" => (200, "not a sha".into()),
            _ => (422, r#"{"message":"No commit found"}"#.into()),
        });
        assert_eq!(
            github_resolve_sha_at(&base, "o", "r", ""),
            Some(sha.clone())
        );
        assert_eq!(
            github_resolve_sha_at(&base, "o", "r", "feature/x"),
            Some(sha)
        );
        assert_eq!(github_resolve_sha_at(&base, "o", "r", "junk"), None);
        assert_eq!(github_resolve_sha_at(&base, "o", "r", "gone"), None);
        assert_eq!(
            github_resolve_sha_at(&crate::verify::testnet::closed(), "o", "r", ""),
            None
        );
    }

    #[test]
    fn parse_github_variants() {
        assert_eq!(
            parse_github("https://github.com/solana-labs/web3.js"),
            Some(("solana-labs".into(), "web3.js".into(), "".into()))
        );
        assert_eq!(
            parse_github("https://github.com/owner/repo/tree/feature-x"),
            Some(("owner".into(), "repo".into(), "feature-x".into()))
        );
        assert_eq!(
            parse_github("https://github.com/owner/repo#v1.0.0"),
            Some(("owner".into(), "repo".into(), "v1.0.0".into()))
        );
        let ssh = format!("git{}github.com:owner/repo.git", '@');
        assert_eq!(
            parse_github(&ssh),
            Some(("owner".into(), "repo".into(), "".into()))
        );
    }

    #[test]
    fn github_main_is_unpinned() {
        let report = resolve("https://github.com/owner/repo/tree/main");
        assert!(kinds(&report).contains(&"unpinned_ref".to_string()));
        assert_eq!(report.max_severity(), Some(Severity::Medium));
    }

    #[test]
    fn github_no_ref_is_unpinned() {
        let report = resolve("https://github.com/owner/repo");
        assert!(kinds(&report).contains(&"unpinned_ref".to_string()));
    }

    #[test]
    fn github_pinned_sha_is_ok() {
        let sha = "a".repeat(40);
        let (resolved, report) =
            resolve_with_identity(&format!("https://github.com/owner/repo/commit/{sha}"));
        assert!(resolved.immutable);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn parse_npm_variants() {
        assert_eq!(parse_npm("helius-mcp"), ("helius-mcp".into(), "".into()));
        assert_eq!(
            parse_npm(&pin("helius-mcp", "1.2.3")),
            ("helius-mcp".into(), "1.2.3".into())
        );
        assert_eq!(
            parse_npm("@solana/web3.js"),
            ("@solana/web3.js".into(), "".into())
        );
        assert_eq!(
            parse_npm(&pin("@solana/web3.js", "2.0.0")),
            ("@solana/web3.js".into(), "2.0.0".into())
        );
    }

    #[test]
    fn npm_latest_is_flagged() {
        let report = resolve(&pin("helius-mcp", "latest"));
        assert!(kinds(&report).contains(&"unpinned_version".to_string()));
    }

    #[test]
    fn npm_exact_version_is_ok() {
        let (resolved, _report) = resolve_with_identity(&pin("helius-mcp", "1.2.3"));
        // Exact version → immutable. (helius-mcp is itself a popular pkg → distance 0, no squat.)
        assert!(resolved.immutable);
    }

    #[test]
    fn exact_version_classifier() {
        assert!(is_exact_version("1.2.3"));
        assert!(is_exact_version("v2.0.0"));
        assert!(is_exact_version("1.2.3-rc.1+build.5"));
        assert!(!is_exact_version("1"));
        assert!(!is_exact_version("1.2"));
        assert!(!is_exact_version("1.2.3-"));
        assert!(!is_exact_version("1.2.3 || 2.0.0"));
        assert!(!is_exact_version("1.2.x"));
        assert!(!is_exact_version("^1.0.0"));
        assert!(!is_exact_version("~1.0.0"));
        assert!(!is_exact_version("latest"));
        assert!(!is_exact_version("*"));
        assert!(!is_exact_version(""));
    }

    #[test]
    fn typosquat_is_high() {
        // `heliusmcp` (drop hyphen) and `helius-mpc` (transpose) are near `helius-mcp`.
        let r1 = resolve(&pin("heliusmcp", "1.0.0"));
        assert!(kinds(&r1).contains(&"typosquat".to_string()));
        assert_eq!(r1.max_severity(), Some(Severity::High));

        let r2 = resolve(&pin("helius-mpc", "1.0.0"));
        assert!(kinds(&r2).contains(&"typosquat".to_string()));
    }

    #[test]
    fn exact_popular_is_not_typosquat() {
        let report = resolve(&pin("helius-mcp", "1.0.0"));
        assert!(!kinds(&report).contains(&"typosquat".to_string()));
    }

    #[test]
    fn levenshtein_basic() {
        assert_eq!(levenshtein("kitten", "sitting"), 3);
        assert_eq!(levenshtein("abc", "abc"), 0);
        assert_eq!(levenshtein("helius-mcp", "heliusmcp"), 1);
    }

    #[test]
    fn parse_npm_shasum_fixture() {
        let body = r#"{"name":"x","version":"1.0.0","dist":{"shasum":"deadbeefcafe","integrity":"sha512-..."}}"#;
        assert_eq!(parse_npm_shasum(body), Some("deadbeefcafe".to_string()));
        assert_eq!(parse_npm_shasum("{}"), None);
    }
}
