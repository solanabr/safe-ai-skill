//! Execution context: network resolution and well-known directories.
//!
//! [`resolve_network`] implements the precedence: explicit cluster flags in the command
//! ([`network_from_flags`]), then `ANCHOR_PROVIDER_URL`, then `<cwd>/Anchor.toml` `[provider]
//! cluster`, then a cached `solana config get` (60s TTL). It never panics — any failure
//! yields [`Network::Unknown`].

pub mod shell;

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Resolved Solana cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// mainnet-beta.
    Mainnet,
    /// devnet.
    Devnet,
    /// testnet.
    Testnet,
    /// localhost validator.
    Localnet,
    /// Could not be determined.
    Unknown,
}

impl Network {
    /// Stable lowercase label.
    pub fn label(&self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Devnet => "devnet",
            Network::Testnet => "testnet",
            Network::Localnet => "localnet",
            Network::Unknown => "unknown",
        }
    }
}

/// Per-invocation execution context.
#[derive(Debug, Clone)]
pub struct Context {
    /// Resolved network for the action.
    pub network: Network,
    /// The plugin data dir ([`plugin_data_dir`]) — where state lives.
    pub plugin_data: PathBuf,
    /// Project root for the session.
    pub project_dir: PathBuf,
}

impl Context {
    /// Build a context from a resolved command and the session cwd.
    pub fn build(command: &str, cwd: &Path) -> Context {
        Context {
            network: resolve_network(command, cwd),
            plugin_data: plugin_data_dir(),
            project_dir: project_dir(cwd),
        }
    }
}

/// Resolve the network for `command` in `cwd`.
///
/// Precedence: explicit flags in the command ([`network_from_flags`], which may itself be
/// [`Network::Unknown`]) → `ANCHOR_PROVIDER_URL` env → `Anchor.toml` `[provider] cluster` →
/// cached `solana config get` (60s TTL). Returns [`Network::Unknown`] when nothing resolves.
/// Never panics.
pub fn resolve_network(command: &str, cwd: &Path) -> Network {
    if let Some(net) = network_from_flags(command) {
        return net;
    }
    if let Ok(url) = std::env::var("ANCHOR_PROVIDER_URL") {
        let net = classify_url(&url);
        if net != Network::Unknown {
            return net;
        }
    }
    if let Some(net) = network_from_anchor_toml(cwd) {
        return net;
    }
    network_from_solana_config().unwrap_or(Network::Unknown)
}

/// Map an RPC URL or cluster moniker to a [`Network`].
fn classify_url(raw: &str) -> Network {
    let s = raw
        .trim()
        .trim_matches(|c| c == '"' || c == '\'')
        .to_lowercase();
    // Cluster monikers.
    match s.as_str() {
        "m" | "mainnet" | "mainnet-beta" => return Network::Mainnet,
        "d" | "devnet" => return Network::Devnet,
        "t" | "testnet" => return Network::Testnet,
        "l" | "localnet" | "localhost" => return Network::Localnet,
        _ => {}
    }
    // Mainnet first: a URL naming mainnet anywhere is mainnet, whatever else it mentions
    // (`…mainnet…/?x=localhost`). Helius mainnet RPCs and mainnet-beta endpoints land here.
    if s.contains("mainnet") {
        return Network::Mainnet;
    }
    if s.contains("127.0.0.1") || s.contains("localhost") || s.contains("localnet") {
        return Network::Localnet;
    }
    if s.contains("devnet") {
        return Network::Devnet;
    }
    if s.contains("testnet") {
        return Network::Testnet;
    }
    Network::Unknown
}

/// Long flags of the `solana` / `spl-token` / `anchor` CLIs that take a value. Without an
/// attached `=value`, the next word is the flag's value, never a positional argument.
const VALUE_FLAGS: &[&str] = &[
    // Global options.
    "--url",
    "--config",
    "--keypair",
    "--commitment",
    "--ws",
    "--output",
    "--rpc-timeout",
    "--confirm-timeout",
    "--fee-payer",
    "--program-id",
    "--with-compute-unit-price",
    "--with-compute-unit-limit",
    "--cluster",
    "--provider.cluster",
    "--provider.wallet",
    // Transaction options.
    "--with-memo",
    "--from",
    "--nonce",
    "--nonce-authority",
    "--blockhash",
    "--signer",
    "--derived-address-seed",
    "--derived-address-program-id",
    // `spl-token transfer`.
    "--owner",
    "--mint-decimals",
    "--expected-fee",
    "--multisig-signer",
    "--transfer-hook-account",
    // `anchor deploy` / `anchor program deploy`.
    "--program-name",
    "--program-keypair",
];

/// Long boolean flags of the same CLIs.
const BOOL_FLAGS: &[&str] = &[
    // Global flags.
    "--help",
    "--version",
    "--verbose",
    "--no-address-labels",
    "--skip-preflight",
    "--skip-seed-phrase-validation",
    "--use-quic",
    "--use-tpu-client",
    "--use-udp",
    "--program-2022",
    "--use-unchecked-instruction",
    // Transfer flags.
    "--no-wait",
    "--allow-unfunded-recipient",
    "--allow-empty-recipient",
    "--fund-recipient",
    "--allow-non-system-account-recipient",
    "--no-recipient-is-ata-owner",
    "--recipient-is-ata-owner",
    "--confidential",
    "--sign-only",
    "--dump-transaction-message",
    // Irreversible-action flags.
    "--final",
    "--disable",
];

/// Short flags that take a value, with the long flag each stands for (`-p` differs by CLI).
const VALUE_SHORTS: &[(char, &str)] = &[
    ('u', "--url"),
    ('k', "--keypair"),
    ('C', "--config"),
    ('p', "-p"),
];

/// Short boolean flags (`-v`, `-h`, `-V`). They may precede a value-taking short in one
/// cluster (`-vum`).
const BOOL_SHORTS: &[char] = &['v', 'h', 'V'];

/// Long flags whose value is an RPC URL or cluster moniker (`-u` is the short form).
const URL_FLAGS: &[&str] = &["--url", "--cluster", "--provider.cluster"];

/// The cluster `command` names explicitly, or `None` when it names none: the riskiest of what
/// each segment's [`Argv::network`] says.
pub fn network_from_flags(command: &str) -> Option<Network> {
    split_segments(command)
        .into_iter()
        .filter_map(|segment| Argv::parse(&tokenize(segment)).network())
        .reduce(riskier)
}

/// One command segment's arguments (after the program word) split into flags and positional
/// words. This is the single flag model: network resolution and the Bash gate both read it, so
/// a word is never a flag value to one and a flag to the other.
pub struct Argv<'a> {
    /// Positional words, without flags, flag values and fd duplications (`2>&1`).
    pub positionals: Vec<&'a str>,
    /// Index into `positionals` from which positions are uncertain: a flag of unknown arity was
    /// followed by a word that may be its value.
    pub uncertain_from: Option<usize>,
    /// Flags as `(long name, value)`; shorts appear under their long name.
    flags: Vec<(&'a str, Option<&'a str>)>,
    /// A value-taking flag was followed by a `-`-word or by nothing. A CLI may read that word
    /// as the flag's value or as a flag of its own, so the cluster it names is uncertain.
    ambiguous_value: bool,
}

/// How one word relates to the words around it.
enum Kind<'a> {
    /// A positional word.
    Positional,
    /// A flag with its value attached (`--url=m`, `-um`).
    Attached(&'a str, &'a str),
    /// A boolean flag, or a cluster of boolean shorts.
    Bool(&'a str),
    /// A flag whose value is the next word.
    TakesValue(&'a str),
    /// A flag of unknown arity.
    Unknown(&'a str),
}

impl<'a> Argv<'a> {
    /// Split a tokenized segment (`tokens[0]` is the program word).
    pub fn parse(tokens: &'a [String]) -> Argv<'a> {
        let words: Vec<&'a str> = tokens
            .iter()
            .skip(1)
            .map(String::as_str)
            .filter(|word| !is_fd_duplication(word))
            .collect();
        Argv::parse_words(&words)
    }

    fn parse_words(words: &[&'a str]) -> Argv<'a> {
        let mut argv = Argv {
            positionals: Vec::new(),
            uncertain_from: None,
            flags: Vec::new(),
            ambiguous_value: false,
        };
        let mut i = 0;
        while let Some(&word) = words.get(i) {
            i += 1;
            if word == "--" {
                // Positional from here. Anchor hands these words to `solana program deploy`, so
                // their flags (`-- --final`) count as well.
                let rest = words.get(i..).unwrap_or_default();
                argv.positionals.extend_from_slice(rest);
                let passed_on = Argv::parse_words(rest);
                argv.flags.extend(passed_on.flags);
                argv.ambiguous_value |= passed_on.ambiguous_value;
                break;
            }
            let next = words.get(i).copied();
            match kind(word) {
                Kind::Positional => argv.positionals.push(word),
                Kind::Attached(name, value) => argv.flags.push((name, Some(value))),
                Kind::Bool(name) => argv.flags.push((name, None)),
                Kind::TakesValue(name) => match next {
                    Some(value) if !is_flag_like(value) => {
                        argv.flags.push((name, Some(value)));
                        i += 1;
                    }
                    // The following word stays a flag in its own right.
                    _ => {
                        argv.flags.push((name, None));
                        argv.ambiguous_value = true;
                    }
                },
                Kind::Unknown(name) => {
                    argv.flags.push((name, None));
                    let word_follows = next.is_some_and(|w| !is_flag_like(w));
                    if word_follows && argv.uncertain_from.is_none() {
                        argv.uncertain_from = Some(argv.positionals.len());
                    }
                }
            }
        }
        argv
    }

    /// Whether flag `name` (a long name such as `--final`) is present, with or without a value.
    pub fn has_flag(&self, name: &str) -> bool {
        self.flags.iter().any(|&(flag, _)| flag == name)
    }

    /// The cluster these arguments name, or `None` when they name none.
    ///
    /// A URL flag (`--url`, `-u`, `--cluster`, Anchor's `--provider.cluster`) whose value names
    /// no recognizable cluster is [`Network::Unknown`]: an explicit target never falls back to
    /// the config. So is `-C/--config <file>` without a URL flag (the file is not read), and so
    /// is an ambiguous flag value. Several flags fold to the riskiest (mainnet, then unknown).
    pub fn network(&self) -> Option<Network> {
        let mut named: Option<Network> = None;
        let mut config_file = false;
        for &(name, value) in &self.flags {
            if URL_FLAGS.contains(&name) {
                let net = value.map_or(Network::Unknown, classify_url);
                named = Some(named.map_or(net, |prev| riskier(prev, net)));
            } else if name == "--config" {
                config_file = true;
            }
        }
        let net = named.or_else(|| config_file.then_some(Network::Unknown));
        if self.ambiguous_value {
            return Some(net.map_or(Network::Unknown, |n| riskier(n, Network::Unknown)));
        }
        net
    }
}

/// Classify one word against the flag tables.
fn kind(word: &str) -> Kind<'_> {
    if !is_flag_like(word) {
        return Kind::Positional;
    }
    if word.starts_with("--") {
        return if let Some((name, value)) = word.split_once('=') {
            Kind::Attached(name, value)
        } else if VALUE_FLAGS.contains(&word) {
            Kind::TakesValue(word)
        } else if BOOL_FLAGS.contains(&word) {
            Kind::Bool(word)
        } else {
            Kind::Unknown(word)
        };
    }
    // A short cluster: boolean shorts, then at most one value-taking short whose value is the
    // rest of the word (`-um`, `-u=m`) or the next word (`-u`, `-vu`).
    let cluster = word.trim_start_matches('-');
    let rest = cluster.trim_start_matches(|c| BOOL_SHORTS.contains(&c));
    let Some(first) = rest.chars().next() else {
        return Kind::Bool(word);
    };
    match VALUE_SHORTS.iter().find(|&&(short, _)| short == first) {
        Some(&(_, long)) => {
            let value = rest.get(first.len_utf8()..).unwrap_or_default();
            let value = value.strip_prefix('=').unwrap_or(value);
            if value.is_empty() {
                Kind::TakesValue(long)
            } else {
                Kind::Attached(long, value)
            }
        }
        None => Kind::Unknown(word),
    }
}

/// Whether `word` reads as a flag (`-x`, `--x`); a lone `-` is a value (stdin).
fn is_flag_like(word: &str) -> bool {
    word.starts_with('-') && word != "-"
}

/// Whether `word` is a file-descriptor duplication such as `2>&1`, `>&2` or `1>&-`: the shell
/// strips it before the CLI sees its argv, and it touches no file. File redirections
/// (`> out.log`) stay as words, so a transfer carrying one never reads as clean.
fn is_fd_duplication(word: &str) -> bool {
    let op = word.trim_start_matches(|c: char| c.is_ascii_digit());
    op.strip_prefix(">&")
        .or_else(|| op.strip_prefix("<&"))
        .is_some_and(|fd| !fd.is_empty() && fd.chars().all(|c| c.is_ascii_digit() || c == '-'))
}

/// Split a command on top-level `&&`, `||`, `;`, `|` separators into segments.
pub fn split_segments(command: &str) -> Vec<&str> {
    let mut segments = Vec::new();
    let bytes = command.as_bytes();
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        let two = bytes.get(i..i + 2);
        if matches!(two, Some(b"&&")) || matches!(two, Some(b"||")) {
            segments.push(command[start..i].trim());
            i += 2;
            start = i;
            continue;
        }
        let c = bytes[i];
        if c == b';' || c == b'|' {
            segments.push(command[start..i].trim());
            i += 1;
            start = i;
            continue;
        }
        i += 1;
    }
    segments.push(command[start..].trim());
    segments.into_iter().filter(|s| !s.is_empty()).collect()
}

/// The riskier of two networks for gating: mainnet, then unknown, then any identified other.
fn riskier(a: Network, b: Network) -> Network {
    let rank = |n: Network| match n {
        Network::Mainnet => 2,
        Network::Unknown => 1,
        Network::Devnet | Network::Testnet | Network::Localnet => 0,
    };
    if rank(b) > rank(a) {
        b
    } else {
        a
    }
}

/// Split `text` into words on whitespace, honoring single and double quotes (quotes removed).
pub fn tokenize(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;

    for c in text.chars() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                } else {
                    current.push(c);
                }
            }
            None => match c {
                '\'' | '"' => quote = Some(c),
                c if c.is_whitespace() => {
                    if !current.is_empty() {
                        tokens.push(std::mem::take(&mut current));
                    }
                }
                _ => current.push(c),
            },
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// Parse `[provider] cluster = "..."` from `<cwd>/Anchor.toml`.
fn network_from_anchor_toml(cwd: &Path) -> Option<Network> {
    let text = std::fs::read_to_string(cwd.join("Anchor.toml")).ok()?;
    let mut in_provider = false;
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.starts_with('[') {
            in_provider = line.starts_with("[provider]");
            continue;
        }
        if in_provider {
            if let Some(rest) = line.strip_prefix("cluster") {
                let value = rest.trim_start_matches(|c: char| c == '=' || c.is_whitespace());
                let net = classify_url(value);
                if net != Network::Unknown {
                    return Some(net);
                }
            }
        }
    }
    None
}

/// Read the cached `solana config get` RPC URL, refreshing it (60s TTL) by shelling out.
///
/// Cache file: `${CLAUDE_PLUGIN_DATA}/netcache.json` as `{"url":..,"ts":..}`. A missing
/// `solana` binary or any error → `None`.
fn network_from_solana_config() -> Option<Network> {
    let cache_path = plugin_data_dir().join("netcache.json");
    let now = now_secs();

    if let Some(url) = read_fresh_cache(&cache_path, now) {
        let net = classify_url(&url);
        if net != Network::Unknown {
            return Some(net);
        }
    }

    let url = solana_config_rpc_url()?;
    write_cache(&cache_path, &url, now);
    let net = classify_url(&url);
    if net == Network::Unknown {
        None
    } else {
        Some(net)
    }
}

/// Return the cached URL if the cache is fresh (within 60s), else `None`.
fn read_fresh_cache(path: &Path, now: u64) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    let ts = value.get("ts").and_then(serde_json::Value::as_u64)?;
    if now.saturating_sub(ts) > 60 {
        return None;
    }
    value
        .get("url")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

/// Best-effort cache write (errors ignored).
fn write_cache(path: &Path, url: &str, ts: u64) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let body = serde_json::json!({ "url": url, "ts": ts });
    if let Ok(s) = serde_json::to_string(&body) {
        let _ = std::fs::write(path, s);
    }
}

/// Run `solana config get` and extract the RPC URL line. `None` on any failure.
fn solana_config_rpc_url() -> Option<String> {
    let output = std::process::Command::new("solana")
        .arg("config")
        .arg("get")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("RPC URL:") {
            return Some(rest.trim().to_string());
        }
    }
    None
}

/// The plugin data dir path, resolved by [`crate::datadir::data_dir`] exactly as the hooks
/// resolve it (never a `./.safe-ai-skill` fallback).
///
/// Kept for the call sites that only need a path. When nothing resolves it returns the
/// [`crate::datadir::unresolved`] sentinel: reads under it find nothing and writes fail.
pub fn plugin_data_dir() -> PathBuf {
    crate::datadir::data_dir()
        .unwrap_or_else(|_| crate::datadir::unresolved())
        .path
}

/// Project root for a session. Currently the cwd itself (reserved for a future git-root walk).
pub fn project_dir(cwd: &Path) -> PathBuf {
    cwd.to_path_buf()
}

/// Current time in epoch seconds (0 on clock error; never panics).
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn classify_url_mappings() {
        assert_eq!(
            classify_url("https://api.mainnet-beta.solana.com"),
            Network::Mainnet
        );
        assert_eq!(
            classify_url("https://mainnet.helius-rpc.com/?api-key=x"),
            Network::Mainnet
        );
        assert_eq!(
            classify_url("https://api.devnet.solana.com"),
            Network::Devnet
        );
        assert_eq!(
            classify_url("https://api.testnet.solana.com"),
            Network::Testnet
        );
        assert_eq!(classify_url("http://127.0.0.1:8899"), Network::Localnet);
        assert_eq!(classify_url("http://localhost:8899"), Network::Localnet);
        assert_eq!(classify_url("garbage"), Network::Unknown);
    }

    #[test]
    fn classify_monikers() {
        assert_eq!(classify_url("mainnet-beta"), Network::Mainnet);
        assert_eq!(classify_url("m"), Network::Mainnet);
        assert_eq!(classify_url("devnet"), Network::Devnet);
        assert_eq!(classify_url("d"), Network::Devnet);
        assert_eq!(classify_url("t"), Network::Testnet);
        assert_eq!(classify_url("l"), Network::Localnet);
    }

    #[test]
    fn flags_space_and_equals_forms() {
        assert_eq!(
            network_from_flags("solana program deploy --url https://api.mainnet-beta.solana.com"),
            Some(Network::Mainnet)
        );
        assert_eq!(
            network_from_flags("anchor deploy --cluster=devnet"),
            Some(Network::Devnet)
        );
        assert_eq!(
            network_from_flags("solana balance -u localhost"),
            Some(Network::Localnet)
        );
        assert_eq!(network_from_flags("solana balance"), None);
    }

    #[test]
    fn flags_provider_cluster_form() {
        // Anchor's native --provider.cluster space form must be gated, not bypassed.
        assert_eq!(
            network_from_flags("anchor deploy --provider.cluster mainnet"),
            Some(Network::Mainnet)
        );
        assert_eq!(
            network_from_flags("anchor deploy --provider.cluster=mainnet-beta"),
            Some(Network::Mainnet)
        );
        assert_eq!(
            network_from_flags("anchor deploy --provider.cluster devnet"),
            Some(Network::Devnet)
        );
        assert_eq!(
            network_from_flags(
                "anchor deploy --provider.cluster https://api.mainnet-beta.solana.com"
            ),
            Some(Network::Mainnet)
        );
        assert_eq!(
            network_from_flags("anchor deploy --provider.cluster=devnet"),
            Some(Network::Devnet)
        );
    }

    #[test]
    fn flags_attached_short_forms() {
        assert_eq!(
            network_from_flags("solana transfer -um D 1"),
            Some(Network::Mainnet)
        );
        assert_eq!(
            network_from_flags("solana transfer -ud D 1"),
            Some(Network::Devnet)
        );
        assert_eq!(
            network_from_flags("solana transfer -u=m D 1"),
            Some(Network::Mainnet)
        );
        assert_eq!(
            network_from_flags("solana transfer --url=m D 1"),
            Some(Network::Mainnet)
        );
        // Boolean shorts may precede `u` in a cluster.
        assert_eq!(
            network_from_flags("solana -vum transfer D 1"),
            Some(Network::Mainnet)
        );
        assert_eq!(
            network_from_flags("solana -uhttp://127.0.0.1:8899 balance"),
            Some(Network::Localnet)
        );
        // `-k` takes a value, so `-ku` is a keypair path, not a URL flag.
        assert_eq!(network_from_flags("solana -ku balance"), None);
    }

    #[test]
    fn explicit_unrecognized_url_is_unknown() {
        assert_eq!(
            network_from_flags("solana transfer D 1 --url https://rpc.example.com"),
            Some(Network::Unknown)
        );
        assert_eq!(
            network_from_flags("solana transfer D 1 -u"),
            Some(Network::Unknown)
        );
    }

    #[test]
    fn config_file_without_url_is_unknown() {
        assert_eq!(
            network_from_flags("solana transfer -C ./c.yml D 1"),
            Some(Network::Unknown)
        );
        assert_eq!(
            network_from_flags("solana transfer --config=./c.yml D 1"),
            Some(Network::Unknown)
        );
        // An explicit URL overrides the config file's.
        assert_eq!(
            network_from_flags("solana transfer -C ./c.yml -ud D 1"),
            Some(Network::Devnet)
        );
    }

    #[test]
    fn several_flags_fold_to_the_riskiest() {
        assert_eq!(
            network_from_flags("solana transfer -ud -um D 1"),
            Some(Network::Mainnet)
        );
        assert_eq!(
            network_from_flags("solana transfer -ud --url https://rpc.example.com D 1"),
            Some(Network::Unknown)
        );
    }

    #[test]
    fn quoted_text_is_not_a_flag() {
        assert_eq!(
            network_from_flags("solana transfer --with-memo \"pay -ud\" D 1"),
            None
        );
    }

    #[test]
    fn flag_values_are_not_cluster_flags() {
        // A `-`-word after a value-taking flag may be that flag's value: unknown at best.
        assert_eq!(
            network_from_flags("solana transfer --with-memo -ud D 1"),
            Some(Network::Unknown)
        );
        assert_eq!(
            network_from_flags("solana transfer --with-memo --url=d D 1"),
            Some(Network::Unknown)
        );
        assert_eq!(
            network_from_flags("solana transfer --fee-payer -um D 1"),
            Some(Network::Mainnet)
        );
        // An attached value is only a value.
        assert_eq!(
            network_from_flags("solana transfer --with-memo=-ud D 1"),
            None
        );
        // Anchor passes the words after `--` to `solana program deploy`.
        assert_eq!(
            network_from_flags("anchor deploy -- --url m"),
            Some(Network::Mainnet)
        );
    }

    #[test]
    fn url_naming_mainnet_wins_over_other_hints() {
        assert_eq!(
            classify_url("https://mainnet.helius-rpc.com/?x=localhost"),
            Network::Mainnet
        );
        assert_eq!(
            classify_url("https://mainnet.example.com/devnet"),
            Network::Mainnet
        );
    }

    #[test]
    fn explicit_unknown_url_does_not_fall_back() {
        let dir =
            std::env::temp_dir().join(format!("safe_ai_skill_explicit_{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("Anchor.toml"),
            "[provider]\ncluster = \"devnet\"\n",
        )
        .unwrap();
        let net = resolve_network("solana transfer D 1 --url https://rpc.example.com", &dir);
        assert_eq!(net, Network::Unknown);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn anchor_toml_provider_cluster() {
        let dir = std::env::temp_dir().join(format!("safe_ai_skill_anchor_{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("Anchor.toml"),
            "[provider]\ncluster = \"devnet\"\nwallet = \"~/.config/solana/id.json\"\n",
        )
        .unwrap();
        assert_eq!(network_from_anchor_toml(&dir), Some(Network::Devnet));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn precedence_flag_beats_anchor_toml() {
        let dir = std::env::temp_dir().join(format!("safe_ai_skill_prec_{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("Anchor.toml"),
            "[provider]\ncluster = \"devnet\"\n",
        )
        .unwrap();
        // explicit mainnet flag must win over Anchor.toml devnet
        let net = resolve_network(
            "anchor deploy --provider.cluster ignored --url https://api.mainnet-beta.solana.com",
            &dir,
        );
        assert_eq!(net, Network::Mainnet);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_on_garbage() {
        let dir = std::env::temp_dir().join(format!("safe_ai_skill_unk_{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        // No flags, no Anchor.toml; solana config may or may not exist — accept either a
        // real network or Unknown, but the call must not panic.
        let _ = resolve_network("echo hi", &dir);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn plugin_data_dir_honors_env() {
        // Save/restore to avoid cross-test interference.
        let prev = std::env::var("CLAUDE_PLUGIN_DATA").ok();
        std::env::set_var("CLAUDE_PLUGIN_DATA", "/tmp/safe-ai-skill-data");
        assert_eq!(plugin_data_dir(), PathBuf::from("/tmp/safe-ai-skill-data"));
        match prev {
            Some(v) => std::env::set_var("CLAUDE_PLUGIN_DATA", v),
            None => std::env::remove_var("CLAUDE_PLUGIN_DATA"),
        }
    }
}
