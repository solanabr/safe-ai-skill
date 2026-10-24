//! The shared list files (shared contract §1), embedded at build time.
//!
//! `policy/shared/{credentials,exfil-hosts,onchain-verbs}.list` and `MANIFEST` are compiled in
//! with `include_str!` (a test pins them byte-for-byte to the repo files). [`lists`] parses
//! them once and checks every MANIFEST count and sha256; any failure makes the lists
//! [`ListsUnavailable`], and the gates that depend on them answer a hard-guard `ask` (fail
//! closed) instead of deciding on partial data.
//!
//! Formats (one record per line, whitespace-separated columns, `#` comments, blank lines and
//! `[section]` headers ignored):
//! - `credentials.list`: `class os sb glob`, the glob being the rest of the line; a leading
//!   `!` marks a readable exception;
//! - `exfil-hosts.list`: `tier host` (the tier where the host starts to apply);
//! - `onchain-verbs.list`: `class cluster argv…`.

use std::sync::OnceLock;

use sha2::{Digest, Sha256};

use crate::policy::tier::Tier;

/// `policy/shared/credentials.list`.
pub const CREDENTIALS_LIST: &str = include_str!("../../../policy/shared/credentials.list");
/// `policy/shared/exfil-hosts.list`.
pub const EXFIL_HOSTS_LIST: &str = include_str!("../../../policy/shared/exfil-hosts.list");
/// `policy/shared/onchain-verbs.list`.
pub const ONCHAIN_VERBS_LIST: &str = include_str!("../../../policy/shared/onchain-verbs.list");
/// `policy/shared/MANIFEST`.
pub const MANIFEST: &str = include_str!("../../../policy/shared/MANIFEST");

/// The lists could not be used; callers that depend on them ask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListsUnavailable(pub String);

impl std::fmt::Display for ListsUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "safe-ai-skill shared lists unavailable: {}", self.0)
    }
}

/// `credentials.list` classes (contract §1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredClass {
    /// Signing keys and key-equivalent files.
    KeyMaterial,
    /// Registry and host tokens.
    HostToken,
    /// Keychains and password managers.
    Vault,
    /// Browser profile stores.
    BrowserStore,
    /// Wallet extension stores.
    WalletExt,
}

/// The OS an entry belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    /// Every OS (case rule of the host).
    Any,
    /// macOS (case-insensitive).
    Macos,
    /// Linux (case-sensitive).
    Linux,
    /// Windows (case-insensitive).
    Windows,
}

/// The lowest kit tier whose sandbox `denyRead` carries an entry. Hook consumers ignore it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbTier {
    /// From Relaxed.
    Relaxed,
    /// From Medium.
    Medium,
    /// High only.
    High,
    /// Never sandbox-denied (subprocesses must read it).
    Never,
}

/// One `credentials.list` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    /// Class.
    pub class: CredClass,
    /// OS.
    pub os: Os,
    /// Sandbox tier.
    pub sb: SbTier,
    /// The glob (contract §1.3 dialect).
    pub glob: String,
    /// A readable exception (`!` line).
    pub exception: bool,
    /// The `[section]` it sits in (provenance), `""` before any header.
    pub section: String,
}

/// One `exfil-hosts.list` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExfilHost {
    /// The lowest tier where it applies.
    pub tier: Tier,
    /// Lowercase host; `*.x` = any subdomain of `x`.
    pub host: String,
}

/// `onchain-verbs.list` classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerbClass {
    /// Class U.
    Irreversible,
    /// Class C.
    Recoverable,
}

/// Whether the decision depends on the cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerbCluster {
    /// Decided whatever the cluster.
    Any,
    /// Decided by the resolved cluster.
    Net,
}

/// One `onchain-verbs.list` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verb {
    /// Class.
    pub class: VerbClass,
    /// Cluster dependence.
    pub cluster: VerbCluster,
    /// Tokens from the program name: literals, `*`, `[--flag]`.
    pub argv: Vec<String>,
}

/// All parsed lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lists {
    /// MANIFEST `contract` version.
    pub contract: String,
    /// Hex sha256 of the MANIFEST bytes.
    pub manifest_sha256: String,
    /// `credentials.list`.
    pub credentials: Vec<Credential>,
    /// `exfil-hosts.list`.
    pub exfil_hosts: Vec<ExfilHost>,
    /// `onchain-verbs.list`.
    pub verbs: Vec<Verb>,
}

/// The embedded lists, parsed and checked once.
pub fn lists() -> Result<&'static Lists, ListsUnavailable> {
    static PARSED: OnceLock<Result<Lists, String>> = OnceLock::new();
    PARSED
        .get_or_init(|| {
            parse_all(
                CREDENTIALS_LIST,
                EXFIL_HOSTS_LIST,
                ONCHAIN_VERBS_LIST,
                MANIFEST,
            )
        })
        .as_ref()
        .map_err(|e| ListsUnavailable(e.clone()))
}

/// Every `credentials.list` record (exceptions included, marked).
pub fn credentials() -> Result<&'static [Credential], ListsUnavailable> {
    lists().map(|l| l.credentials.as_slice())
}

/// The exfil hosts that apply at `tier` (cumulative; none at Off).
pub fn exfil_hosts(tier: Tier) -> Result<Vec<&'static str>, ListsUnavailable> {
    Ok(lists()?
        .exfil_hosts
        .iter()
        .filter(|h| tier != Tier::Off && h.tier <= tier)
        .map(|h| h.host.as_str())
        .collect())
}

/// The Class U rows.
pub fn irreversible() -> Result<Vec<&'static Verb>, ListsUnavailable> {
    verbs_of(VerbClass::Irreversible)
}

/// The Class C rows.
pub fn recoverable() -> Result<Vec<&'static Verb>, ListsUnavailable> {
    verbs_of(VerbClass::Recoverable)
}

fn verbs_of(class: VerbClass) -> Result<Vec<&'static Verb>, ListsUnavailable> {
    Ok(lists()?.verbs.iter().filter(|v| v.class == class).collect())
}

/// Parse all three files and check them against `manifest`.
pub fn parse_all(
    credentials: &str,
    exfil_hosts: &str,
    onchain_verbs: &str,
    manifest: &str,
) -> Result<Lists, String> {
    let creds = parse_credentials(credentials)?;
    let hosts = parse_exfil_hosts(exfil_hosts)?;
    let verbs = parse_onchain_verbs(onchain_verbs)?;
    let mut lines = manifest.lines();
    let contract = lines
        .next()
        .and_then(|l| l.strip_prefix("contract "))
        .map(str::trim)
        .filter(|v| v.split('.').count() == 3)
        .ok_or("MANIFEST: line 1 must be `contract X.Y.Z`")?
        .to_string();
    let entries: Vec<(&str, &str)> = lines
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let mut cols = l.split_whitespace();
            (cols.next().unwrap_or(""), l)
        })
        .collect();
    for (name, text, count) in [
        ("credentials.list", credentials, creds.len()),
        ("exfil-hosts.list", exfil_hosts, hosts.len()),
        ("onchain-verbs.list", onchain_verbs, verbs.len()),
    ] {
        let want = format!("{name} {count} sha256:{}", sha256_hex(text.as_bytes()));
        match entries.iter().find(|(n, _)| *n == name) {
            Some((_, line)) if line.trim() == want => {}
            Some(_) => return Err(format!("MANIFEST does not match {name}")),
            None => return Err(format!("MANIFEST has no entry for {name}")),
        }
    }
    Ok(Lists {
        contract,
        manifest_sha256: sha256_hex(manifest.as_bytes()),
        credentials: creds,
        exfil_hosts: hosts,
        verbs,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Record lines with their 1-based line numbers and the section they sit in.
fn records(text: &str) -> impl Iterator<Item = (usize, &str, String)> {
    let mut section = String::new();
    text.lines().enumerate().filter_map(move |(i, line)| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.to_string();
            return None;
        }
        Some((i + 1, line, section.clone()))
    })
}

/// Parse `credentials.list`.
pub fn parse_credentials(text: &str) -> Result<Vec<Credential>, String> {
    records(text)
        .map(|(n, line, section)| {
            let bad = |what: &str| format!("credentials.list:{n}: {what}");
            let (exception, line) = match line.strip_prefix('!') {
                Some(rest) => (true, rest),
                None => (false, line),
            };
            let (head, glob) = split_head(line, 3);
            let mut cols = head.into_iter();
            let class = match cols.next() {
                Some("key_material") => CredClass::KeyMaterial,
                Some("host_token") => CredClass::HostToken,
                Some("vault") => CredClass::Vault,
                Some("browser_store") => CredClass::BrowserStore,
                Some("wallet_ext") => CredClass::WalletExt,
                _ => return Err(bad("unknown class")),
            };
            let os = match cols.next() {
                Some("any") => Os::Any,
                Some("macos") => Os::Macos,
                Some("linux") => Os::Linux,
                Some("windows") => Os::Windows,
                _ => return Err(bad("unknown os")),
            };
            let sb = match cols.next() {
                Some("relaxed") => SbTier::Relaxed,
                Some("medium") => SbTier::Medium,
                Some("high") => SbTier::High,
                Some("never") => SbTier::Never,
                _ => return Err(bad("unknown sb tier")),
            };
            let glob = glob.to_string();
            if glob.is_empty() {
                return Err(bad("missing glob"));
            }
            let rest = glob.replace("${CLAUDE_CONFIG_DIR:-~/.claude}", "");
            if rest.contains(['{', '}', '[', ']', '$']) {
                return Err(bad("braces, character classes or variables in the glob"));
            }
            Ok(Credential {
                class,
                os,
                sb,
                glob,
                exception,
                section,
            })
        })
        .collect()
}

/// The first `n` whitespace-separated columns of `line` and the trimmed rest.
fn split_head(line: &str, n: usize) -> (Vec<&str>, &str) {
    let mut rest = line.trim_start();
    let mut head = Vec::with_capacity(n);
    for _ in 0..n {
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let (col, tail) = rest.split_at(end);
        if !col.is_empty() {
            head.push(col);
        }
        rest = tail.trim_start();
    }
    (head, rest.trim_end())
}

/// Parse `exfil-hosts.list`.
pub fn parse_exfil_hosts(text: &str) -> Result<Vec<ExfilHost>, String> {
    records(text)
        .map(|(n, line, _)| {
            let bad = |what: &str| format!("exfil-hosts.list:{n}: {what}");
            let cols: Vec<&str> = line.split_whitespace().collect();
            let [tier, host] = cols.as_slice() else {
                return Err(bad("expected `tier host`"));
            };
            let tier = match *tier {
                "relaxed" => Tier::Relaxed,
                "medium" => Tier::Medium,
                "high" => Tier::High,
                _ => return Err(bad("unknown tier")),
            };
            let bare = host.strip_prefix("*.").unwrap_or(host);
            let valid = !bare.is_empty()
                && !bare.ends_with('.')
                && bare.contains('.')
                && bare
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-');
            if !valid {
                return Err(bad(
                    "host must be lowercase, no scheme, port or trailing dot",
                ));
            }
            Ok(ExfilHost {
                tier,
                host: host.to_string(),
            })
        })
        .collect()
}

/// Parse `onchain-verbs.list`.
pub fn parse_onchain_verbs(text: &str) -> Result<Vec<Verb>, String> {
    records(text)
        .map(|(n, line, _)| {
            let bad = |what: &str| format!("onchain-verbs.list:{n}: {what}");
            let cols: Vec<&str> = line.split_whitespace().collect();
            let class = match cols.first() {
                Some(&"irreversible") => VerbClass::Irreversible,
                Some(&"recoverable") => VerbClass::Recoverable,
                _ => return Err(bad("unknown class")),
            };
            let cluster = match cols.get(1) {
                Some(&"any") => VerbCluster::Any,
                Some(&"net") => VerbCluster::Net,
                _ => return Err(bad("unknown cluster")),
            };
            let argv: Vec<String> = cols.iter().skip(2).map(|t| t.to_string()).collect();
            if argv.len() < 2 {
                return Err(bad("expected a program and a verb"));
            }
            Ok(Verb {
                class,
                cluster,
                argv,
            })
        })
        .collect()
}
