//! Provenance pinning: resolve a source to an immutable reference.
//!
//! Two source kinds are understood:
//! * **GitHub** URLs → parse `owner/repo/ref`; a moving ref (`main`/`master`/`HEAD`) is a
//!   MEDIUM "unpinned ref" finding, a 40-hex commit SHA is treated as immutable. Resolving a
//!   branch to its current SHA needs the GitHub API — isolated in [`github_resolve_sha`] and
//!   never exercised by unit tests.
//! * **npm** packages → require an exact version (a range / `@latest` is a finding); a
//!   Levenshtein-near match to a popular package name is a HIGH typosquat finding. The
//!   registry lookup (`dist.shasum`, download counts) is isolated in [`npm_fetch`].
//!
//! The pure logic (URL parsing, ref classification, typosquat distance, version pinning) is
//! fully unit-tested with fixtures; the network functions are thin and optional.

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

/// Kind of source resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    /// A GitHub repository URL.
    GitHub,
    /// An npm package spec.
    Npm,
    /// Anything not recognized.
    Other,
}

/// The immutable identity resolved from a source (best-effort, network-free).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Resolved {
    /// Source kind label (`"github"`/`"npm"`/`"other"`).
    pub kind: String,
    /// GitHub `owner` or npm scope, when applicable.
    pub owner: String,
    /// GitHub repo or npm package name.
    pub name: String,
    /// The requested ref / version (branch, tag, SHA, or semver).
    pub reference: String,
    /// True when [`reference`](Self::reference) is already immutable (commit SHA / exact ver).
    pub immutable: bool,
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
        SourceKind::Other => Resolved {
            kind: "other".into(),
            reference: source.to_string(),
            ..Default::default()
        },
    };
    (resolved, report)
}

/// Classify a source string into a [`SourceKind`].
pub fn classify_source(source: &str) -> SourceKind {
    let s = source.trim();
    if s.contains("github.com") || s.starts_with("git@github.com") {
        return SourceKind::GitHub;
    }
    // npm: scoped (`@scope/pkg`), `npm:pkg`, or a bare package@version with no slashes/dots.
    if s.starts_with("npm:") || s.starts_with('@') {
        return SourceKind::Npm;
    }
    if !s.contains("://") && !s.contains('/') {
        // bare token like `helius-mcp` or `[email protected]`
        return SourceKind::Npm;
    }
    SourceKind::Other
}

// ---------------------------------------------------------------------------------------
// GitHub
// ---------------------------------------------------------------------------------------

/// Parse a GitHub URL into `(owner, repo, ref)`. `ref` is empty when absent.
///
/// Handles `https://github.com/owner/repo`, `.../tree/<ref>`, `.../commit/<sha>`,
/// `...#<ref>`, trailing `.git`, and `git@github.com:owner/repo.git`.
pub fn parse_github(url: &str) -> Option<(String, String, String)> {
    let s = url.trim();

    // Split off a `#ref` fragment first.
    let (base, frag_ref) = match s.split_once('#') {
        Some((b, r)) => (b, Some(r.to_string())),
        None => (s, None),
    };

    // Normalize to the `owner/repo[/...]` path portion.
    let path = if let Some(rest) = base.strip_prefix("git@github.com:") {
        rest.to_string()
    } else if let Some(idx) = base.find("github.com/") {
        base[idx + "github.com/".len()..].to_string()
    } else {
        return None;
    };

    let mut parts = path.split('/').filter(|p| !p.is_empty());
    let owner = parts.next()?.to_string();
    let repo_raw = parts.next()?;
    let repo = repo_raw.trim_end_matches(".git").to_string();

    // Remaining path may encode the ref via `tree/<ref>` or `commit/<sha>`.
    let rest: Vec<&str> = parts.collect();
    let path_ref = match rest.first().copied() {
        Some("tree") | Some("commit") | Some("blob") => rest.get(1).map(|s| s.to_string()),
        _ => None,
    };

    let reference = frag_ref.or(path_ref).unwrap_or_default();
    Some((owner, repo, reference))
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
    let (owner, name, reference) = match parse_github(source) {
        Some(t) => t,
        None => {
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
        }
    };

    let immutable = is_commit_sha(&reference);
    if !immutable {
        let shown = if reference.is_empty() {
            "default branch".to_string()
        } else {
            reference.clone()
        };
        report.findings.push(Finding::new(
            Severity::Medium,
            "unpinned_ref",
            format!("GitHub ref `{shown}` is moving; pin to a commit SHA for immutability"),
        ));
    }

    Resolved {
        kind: "github".into(),
        owner,
        name,
        reference,
        immutable,
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

/// True if `version` is an exact pin (a concrete semver), not a range/tag/`latest`.
pub fn is_exact_version(version: &str) -> bool {
    let v = version.trim();
    if v.is_empty() || v.eq_ignore_ascii_case("latest") {
        return false;
    }
    // Reject range operators / wildcards.
    if v.starts_with(['^', '~', '>', '<', '=', '*']) || v.contains('*') || v.contains(" - ") {
        return false;
    }
    // Require a leading digit (major).
    let core = v.trim_start_matches('v');
    core.chars()
        .next()
        .map(|c| c.is_ascii_digit())
        .unwrap_or(false)
}

fn resolve_npm(source: &str, report: &mut Report) -> Resolved {
    let (name, version) = parse_npm(source);

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
        let shown = if version.is_empty() {
            "unspecified".to_string()
        } else {
            version.clone()
        };
        report.findings.push(Finding::new(
            Severity::Medium,
            "unpinned_version",
            format!("npm version `{shown}` is not an exact pin (use `name@x.y.z`)"),
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
        reference: version,
        immutable,
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
/// unresolved rather than failing). NEVER called from unit tests.
pub fn github_resolve_sha(owner: &str, repo: &str, reference: &str) -> Option<String> {
    let r = if reference.is_empty() {
        "HEAD"
    } else {
        reference
    };
    let url = format!("https://api.github.com/repos/{owner}/{repo}/commits/{r}");
    let resp = ureq::agent()
        .get(&url)
        .timeout(std::time::Duration::from_secs(4))
        .set("User-Agent", "safe-ai-skill")
        .set("Accept", "application/vnd.github.sha")
        .call()
        .ok()?;
    let sha = resp.into_string().ok()?;
    let sha = sha.trim().to_string();
    if is_commit_sha(&sha) {
        Some(sha)
    } else {
        None
    }
}

/// Fetch the npm registry metadata for `name@version` (`dist.shasum`, etc.).
///
/// Isolated and optional: returns `None` on any network/parse error. NEVER called from
/// unit tests. Use [`parse_npm_shasum`] to test the parsing against a fixture body.
pub fn npm_fetch(name: &str, version: &str) -> Option<String> {
    let v = if version.is_empty() {
        "latest"
    } else {
        version
    };
    let url = format!("https://registry.npmjs.org/{name}/{v}");
    let resp = ureq::agent()
        .get(&url)
        .timeout(std::time::Duration::from_secs(4))
        .set("User-Agent", "safe-ai-skill")
        .call()
        .ok()?;
    let body = resp.into_string().ok()?;
    parse_npm_shasum(&body)
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
