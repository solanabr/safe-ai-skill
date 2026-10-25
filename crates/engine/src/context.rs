//! Execution context: network resolution and well-known directories.
//!
//! A command's cluster comes from its own flags first ([`explicit_network`]: `-u/--url`,
//! attached `-um`, `--url=m`, monikers, `-C/--config <file>` read for its `json_rpc_url`).
//! Without one, `solana` and `spl-token` use the CLI config ([`cli_network`]: `solana config
//! get`, bounded at 2 s, cached 60 s in an authenticated state file), and `anchor` uses
//! `Anchor.toml` `[provider] cluster` ([`anchor_network`]), falling back to the CLI config. An
//! `ANCHOR_PROVIDER_URL` in the hook environment may only make an anchor command riskier.
//! Nothing here panics: any failure yields [`Network::Unknown`].

pub mod shell;

use std::cell::OnceCell;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::datadir::{self, DataDir};
use crate::statefile::{self, Loaded};

/// How long `solana config get` may run before the CLI network counts as unknown (D1.3).
pub const SOLANA_CONFIG_TIMEOUT: Duration = Duration::from_secs(2);

/// How long a cached `solana config get` URL stays fresh, in seconds.
const NETCACHE_TTL_SECS: u64 = 60;

/// State file holding the cached CLI URL.
const NETCACHE_FILE: &str = "netcache.json";

/// Largest `-C` config file or `Anchor.toml` read.
const MAX_CONFIG_BYTES: u64 = 256 * 1024;

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
    /// The cluster a `solana`/`spl-token` command naming none runs on (the CLI config).
    pub network: Network,
    /// The cluster an `anchor` command naming none runs on (`Anchor.toml`, else the CLI
    /// config).
    pub anchor_network: Network,
    /// The plugin data dir ([`plugin_data_dir`]) — where state lives.
    pub plugin_data: PathBuf,
    /// Project root for the session (the hook `cwd`): relative `-C` paths resolve here.
    pub project_dir: PathBuf,
}

impl Context {
    /// Build a context for `command` in the session `cwd`.
    ///
    /// The defaults are resolved only when some solana-family command in `command` names no
    /// cluster of its own, so a command that needs none never runs `solana config get`.
    pub fn build(command: &str, cwd: &Path) -> Context {
        let parsed = shell::parse(command);
        let cli = OnceCell::new();
        let cli_net = || *cli.get_or_init(|| cli_network(cwd));
        let needs_default = |anchor: bool| {
            parsed.commands.iter().any(|c| {
                c.is_family()
                    && (c.program() == "anchor") == anchor
                    && explicit_network(&Argv::from_shell(&c.words), Some(cwd)).is_none()
            })
        };
        let network = if needs_default(false) {
            cli_net()
        } else {
            Network::Unknown
        };
        let anchor_network = if needs_default(true) {
            anchor_network(cwd, cli_net)
        } else {
            Network::Unknown
        };
        Context {
            network,
            anchor_network,
            plugin_data: plugin_data_dir(),
            project_dir: project_dir(cwd),
        }
    }
}

/// Resolve the network of the first solana-family command in `command`, run in `cwd`: its
/// own flags ([`explicit_network`]), else [`anchor_network`] for `anchor` and
/// [`cli_network`] for the rest. [`Network::Unknown`] when nothing resolves.
pub fn resolve_network(command: &str, cwd: &Path) -> Network {
    let parsed = shell::parse(command);
    let Some(cmd) = parsed.commands.iter().find(|c| c.is_family()) else {
        return Network::Unknown;
    };
    if let Some(net) = explicit_network(&Argv::from_shell(&cmd.words), Some(cwd)) {
        return net;
    }
    if cmd.program() == "anchor" {
        anchor_network(cwd, || cli_network(cwd))
    } else {
        cli_network(cwd)
    }
}

/// The cluster an `anchor` command naming none targets: the nearest `Anchor.toml` (cwd, then
/// its ancestors, as anchor discovers it) `[provider] cluster`, else `cli`. A cluster value
/// that names no recognizable cluster is [`Network::Unknown`]. `ANCHOR_PROVIDER_URL`, when
/// set, can only make the result riskier: the hook environment may be repo-controlled.
pub fn anchor_network(cwd: &Path, cli: impl FnOnce() -> Network) -> Network {
    let base = network_from_anchor_toml(cwd).unwrap_or_else(cli);
    match std::env::var("ANCHOR_PROVIDER_URL") {
        Ok(url) if !url.trim().is_empty() => riskier(base, classify_url(&url)),
        _ => base,
    }
}

/// The CLI config's cluster: `solana config get`, bounded at [`SOLANA_CONFIG_TIMEOUT`] (a
/// timeout, a missing binary or any failure is [`Network::Unknown`]), cached for 60 s in the
/// authenticated `netcache.json` of a trusted data dir.
pub fn cli_network(cwd: &Path) -> Network {
    let dir = datadir::data_dir_with_cwd(Some(cwd))
        .ok()
        .filter(|d| d.trusted);
    let now = now_secs();
    let fingerprint = cli_config_fingerprint();
    if let Some(dir) = &dir {
        if let Some(url) = read_fresh_cache(dir, now, &fingerprint) {
            return classify_url(&url);
        }
    }
    let Some(url) = solana_config_rpc_url(SOLANA_CONFIG_TIMEOUT) else {
        return Network::Unknown;
    };
    if let Some(dir) = &dir {
        let cache = NetCache {
            url: url.clone(),
            ts: now,
            config: fingerprint,
        };
        // Best-effort: a cache that cannot be written is re-resolved next time.
        let _ = statefile::store(dir, NETCACHE_FILE, &cache);
    }
    classify_url(&url)
}

/// Map an RPC URL or cluster moniker to a [`Network`].
///
/// Anything naming mainnet is mainnet (the riskier reading is always safe). Otherwise only
/// exact hosts count: `api.devnet.solana.com`/`devnet.helius-rpc.com` (devnet),
/// `api.testnet.solana.com` (testnet), and `localhost`, `127.0.0.1`, `[::1]` or `0.0.0.0`
/// with nothing after the host but a port (localnet). `devnet.attacker.example` is unknown,
/// and so is a host without an `http(s)://` / `ws(s)://` scheme (`devnet.helius-rpc.com`):
/// the CLIs do not take it as that endpoint, so it identifies nothing.
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
    // An expansion's value is unknown, whatever else its spelling says.
    if s.contains('$') || s.contains('`') {
        return Network::Unknown;
    }
    let rest = match s.split_once("://") {
        Some(("http" | "https" | "ws" | "wss", rest)) => rest,
        _ => return Network::Unknown,
    };
    // WHATWG (the `url` crate the CLIs connect through) ends the authority at `\` too for these
    // schemes: `https://evil.example\@api.devnet.solana.com` is the host `evil.example`.
    let end = rest.find(['/', '\\', '?', '#']).unwrap_or(rest.len());
    let (authority, after) = rest.split_at(end);
    // Anything a URL parser could strip, decode or read differently identifies nothing.
    if !authority
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '@' | '[' | ']'))
    {
        return Network::Unknown;
    }
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    let host = if host_port.starts_with('[') {
        host_port.find(']').map_or(host_port, |i| &host_port[..=i])
    } else {
        host_port.split(':').next().unwrap_or(host_port)
    };
    match host {
        "localhost" | "127.0.0.1" | "[::1]" | "0.0.0.0" if after.is_empty() || after == "/" => {
            Network::Localnet
        }
        "api.devnet.solana.com" | "devnet.helius-rpc.com" => Network::Devnet,
        "api.testnet.solana.com" => Network::Testnet,
        _ => Network::Unknown,
    }
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
    // `solana program close` (Class U): a program's confirmation, and every buffer.
    "--bypass-warning",
    "--buffers",
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
/// each simple command's [`Argv::network`] says. Config files are not read.
pub fn network_from_flags(command: &str) -> Option<Network> {
    shell::parse(command)
        .commands
        .iter()
        .filter_map(|cmd| Argv::from_shell(&cmd.words).network())
        .reduce(riskier)
}

/// The cluster one command's arguments name, reading a `-C/--config` file for its
/// `json_rpc_url` (a relative path resolves against `base`; with no `base` it is unknown).
///
/// An explicit URL flag beats the config file, as in the CLI. A config file that cannot be
/// read, names no `json_rpc_url`, or is spelled with an expansion is [`Network::Unknown`]: an
/// explicit target never falls back to the default config. `None` when nothing is named.
pub fn explicit_network(argv: &Argv, base: Option<&Path>) -> Option<Network> {
    let named = argv.url_network();
    let net = match (named, argv.config_file()) {
        (Some(net), _) => Some(net),
        (None, Some(file)) => Some(config_file_network(file, base)),
        (None, None) if argv.config_flag_without_value() => Some(Network::Unknown),
        (None, None) => None,
    };
    if argv.ambiguous_value {
        return Some(net.map_or(Network::Unknown, |n| riskier(n, Network::Unknown)));
    }
    net
}

/// The cluster of a solana CLI config file's `json_rpc_url`, or [`Network::Unknown`].
fn config_file_network(file: &str, base: Option<&Path>) -> Network {
    if file.contains(['$', '`', '*', '?', '[']) || file.is_empty() {
        return Network::Unknown;
    }
    let path = if let Some(rest) = file.strip_prefix("~/") {
        match std::env::var_os("HOME") {
            Some(home) => PathBuf::from(home).join(rest),
            None => return Network::Unknown,
        }
    } else if Path::new(file).is_absolute() {
        PathBuf::from(file)
    } else {
        match base {
            Some(base) => base.join(file),
            None => return Network::Unknown,
        }
    };
    let Some(text) = read_small_file(&path) else {
        return Network::Unknown;
    };
    config_text_network(&text)
}

/// The cluster a CLI config file's text names: its one top-level `json_rpc_url`.
///
/// The CLI reads the file as YAML, so a line scan alone can be fooled (a `json_rpc_url:` line
/// inside a block scalar or a nested map). The file must parse as one YAML mapping whose
/// `json_rpc_url` is a string, and exactly one unindented line may spell that key, with the
/// same plain or quoted value. Anything else (duplicate, flow, anchor or alias syntax, a
/// second document, a parse error) is [`Network::Unknown`].
fn config_text_network(text: &str) -> Network {
    let mut top_level = text
        .lines()
        .filter_map(|line| line.strip_prefix("json_rpc_url:"));
    let (Some(spelled), None) = (top_level.next(), top_level.next()) else {
        return Network::Unknown;
    };
    let spelled = spelled.trim();
    let Ok(serde_yaml::Value::Mapping(map)) = serde_yaml::from_str::<serde_yaml::Value>(text)
    else {
        return Network::Unknown;
    };
    let Some(serde_yaml::Value::String(parsed)) = map.get("json_rpc_url") else {
        return Network::Unknown;
    };
    let unquoted = spelled
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .or_else(|| {
            spelled
                .strip_prefix('\'')
                .and_then(|v| v.strip_suffix('\''))
        })
        .unwrap_or(spelled);
    if unquoted != parsed {
        return Network::Unknown;
    }
    classify_url(parsed)
}

/// Read a regular file of at most [`MAX_CONFIG_BYTES`]; `None` otherwise (a FIFO or device
/// is never opened).
fn read_small_file(path: &Path) -> Option<String> {
    let meta = crate::localfs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_CONFIG_BYTES {
        return None;
    }
    let mut text = String::new();
    std::fs::File::open(path)
        .ok()?
        .take(MAX_CONFIG_BYTES)
        .read_to_string(&mut text)
        .ok()?;
    Some(text)
}

/// One command's arguments (after the program word) split into flags and positional words.
/// This is the single flag model: network resolution and the Bash gate both read it, so a
/// word is never a flag value to one and a flag to the other.
pub struct Argv<'a> {
    /// Positional words, without flags, flag values and fd duplications (`2>&1`).
    pub positionals: Vec<&'a str>,
    /// Index into `positionals` from which positions are uncertain: a flag of unknown arity was
    /// followed by a word that may be its value, or a word the shell may split or glob came
    /// first.
    pub uncertain_from: Option<usize>,
    /// Flags as `(long name, value)`; shorts appear under their long name.
    flags: Vec<(&'a str, Option<&'a str>)>,
    /// A value-taking flag was followed by a `-`-word or by nothing, an unknown long flag was
    /// followed by a `-`-word, or a word may split into flags. The cluster named is uncertain.
    ambiguous_value: bool,
}

/// Whether the shell may turn one word into a different number of words.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Splits {
    /// It stays one word.
    No,
    /// Only through an unquoted glob or brace character (`*`, `?`, `[`, `{`): no expansion.
    Glob,
    /// Through an expansion (`$X`, `$(…)`, `"$@"`): its text is unknown.
    Yes,
}

impl Splits {
    /// Whether this word, the value of flag `name`, is a URL whose glob leaves its cluster as
    /// spelled ([`inert_url_glob`]).
    fn inert_as_url(self, name: &str, value: &str) -> bool {
        self == Splits::Glob && URL_FLAGS.contains(&name) && inert_url_glob(value)
    }
}

/// Whether an RPC URL spelled with an unquoted glob (`https://api.mainnet-beta.solana.com/?x`)
/// names the same cluster whatever the shell does with the glob. True only when the scheme and
/// host (`http(s)://` or `ws(s)://`, up to the first `/`) hold no glob, brace or expansion
/// character and there is no brace or expansion anywhere: then every glob character sits in a
/// later path component, so the shell leaves the word as written (no match), fails the
/// command (zsh `nomatch`, bash `failglob`), or yields words that all start with that same
/// `scheme://host/`. The CLI reads the first as its URL and rejects the rest as extra
/// positionals: none can be an amount, a subcommand or a pubkey.
fn inert_url_glob(value: &str) -> bool {
    const SPECIAL: [char; 6] = ['*', '?', '[', '{', '$', '`'];
    let Some((scheme, rest)) = value.split_once("://") else {
        return false;
    };
    if !matches!(
        scheme.to_ascii_lowercase().as_str(),
        "http" | "https" | "ws" | "wss"
    ) {
        return false;
    }
    let Some(slash) = rest.find('/') else {
        return false;
    };
    let (authority, _) = rest.split_at(slash);
    !authority.contains(SPECIAL) && !value.contains(['{', '$', '`'])
}

/// How one word relates to the words around it.
enum Kind<'a> {
    /// A positional word.
    Positional,
    /// A flag with its value attached (`--url=m`, `-um`, `-u=`).
    Attached(&'a str, &'a str),
    /// A boolean flag, or a cluster of boolean shorts.
    Bool(&'a str),
    /// A flag whose value is the next word.
    TakesValue(&'a str),
    /// A flag of unknown arity.
    Unknown(&'a str),
}

impl<'a> Argv<'a> {
    /// Split a tokenized command (`tokens[0]` is the program word).
    pub fn parse(tokens: &'a [String]) -> Argv<'a> {
        let words: Vec<(&'a str, Splits)> = tokens
            .iter()
            .skip(1)
            .map(|t| (t.as_str(), Splits::No))
            .filter(|(word, _)| !is_fd_duplication(word))
            .collect();
        Argv::parse_words(&words)
    }

    /// Split a parsed shell command (`words[0]` is the program word). A word the shell may
    /// split or glob ([`shell::Word::splits`]) makes every position from it on uncertain,
    /// except a URL flag's value whose glob cannot change its cluster ([`inert_url_glob`]).
    pub fn from_shell(words: &'a [shell::Word]) -> Argv<'a> {
        let words: Vec<(&'a str, Splits)> = words
            .iter()
            .skip(1)
            .map(|w| {
                let splits = match (w.splits, w.dynamic) {
                    (false, _) => Splits::No,
                    (true, false) => Splits::Glob,
                    (true, true) => Splits::Yes,
                };
                (w.text.as_str(), splits)
            })
            .collect();
        Argv::parse_words(&words)
    }

    fn parse_words(words: &[(&'a str, Splits)]) -> Argv<'a> {
        let mut argv = Argv {
            positionals: Vec::new(),
            uncertain_from: None,
            flags: Vec::new(),
            ambiguous_value: false,
        };
        let mut i = 0;
        while let Some(&(word, splits)) = words.get(i) {
            i += 1;
            let inert = match kind(word) {
                Kind::Attached(name, value) => splits.inert_as_url(name, value),
                _ => false,
            };
            if splits != Splits::No && !inert {
                // Its words, flags included, are unknowable: so is everything after it.
                argv.ambiguous_value = true;
                argv.mark_uncertain();
            }
            if word == "--" {
                // Positional from here. Anchor hands these words to `solana program deploy`, so
                // their flags (`-- --final`) count as well.
                let rest = words.get(i..).unwrap_or_default();
                argv.positionals.extend(rest.iter().map(|&(w, _)| w));
                let passed_on = Argv::parse_words(rest);
                argv.flags.extend(passed_on.flags);
                argv.ambiguous_value |= passed_on.ambiguous_value;
                break;
            }
            let next = words.get(i).map(|&(w, _)| w);
            match kind(word) {
                Kind::Positional => argv.positionals.push(word),
                Kind::Attached(name, value) => argv.flags.push((name, Some(value))),
                Kind::Bool(name) => argv.flags.push((name, None)),
                Kind::TakesValue(name) => match next {
                    Some(value) if !is_flag_like(value) => {
                        argv.flags.push((name, Some(value)));
                        i += 1;
                        let value_splits = words.get(i - 1).map_or(Splits::No, |&(_, s)| s);
                        if value_splits != Splits::No && !value_splits.inert_as_url(name, value) {
                            argv.ambiguous_value = true;
                            argv.mark_uncertain();
                        }
                    }
                    // The following word stays a flag in its own right.
                    _ => {
                        argv.flags.push((name, None));
                        argv.ambiguous_value = true;
                    }
                },
                Kind::Unknown(name) => {
                    argv.flags.push((name, None));
                    match next {
                        Some(w) if !is_flag_like(w) => argv.mark_uncertain(),
                        // `--mystery -ud`: `-ud` may be the mystery flag's value.
                        Some(_) => argv.ambiguous_value = true,
                        None => {}
                    }
                }
            }
        }
        argv
    }

    /// Positions from the current one on are uncertain.
    fn mark_uncertain(&mut self) {
        if self.uncertain_from.is_none() {
            self.uncertain_from = Some(self.positionals.len());
        }
    }

    /// Whether flag `name` (a long name such as `--final`) is present, with or without a value.
    pub fn has_flag(&self, name: &str) -> bool {
        self.flags.iter().any(|&(flag, _)| flag == name)
    }

    /// The cluster these arguments name, or `None` when they name none.
    ///
    /// A URL flag (`--url`, `-u`, `--cluster`, Anchor's `--provider.cluster`) whose value names
    /// no recognizable cluster is [`Network::Unknown`]: an explicit target never falls back to
    /// the config. So is `-C/--config <file>` without a URL flag (the file is not read here;
    /// [`explicit_network`] reads it), and so is an ambiguous flag value. Several flags fold to
    /// the riskiest (mainnet, then unknown).
    pub fn network(&self) -> Option<Network> {
        let net = self
            .url_network()
            .or_else(|| self.has_flag("--config").then_some(Network::Unknown));
        if self.ambiguous_value {
            return Some(net.map_or(Network::Unknown, |n| riskier(n, Network::Unknown)));
        }
        net
    }

    /// The riskiest cluster the URL flags name, or `None` without one.
    fn url_network(&self) -> Option<Network> {
        self.flags
            .iter()
            .filter(|(name, _)| URL_FLAGS.contains(name))
            .map(|&(_, value)| value.map_or(Network::Unknown, classify_url))
            .reduce(riskier)
    }

    /// The last `-C/--config` value.
    fn config_file(&self) -> Option<&'a str> {
        self.flags
            .iter()
            .rev()
            .find(|(name, _)| *name == "--config")
            .and_then(|&(_, value)| value)
    }

    /// Whether `-C/--config` appears with no value.
    fn config_flag_without_value(&self) -> bool {
        self.flags
            .iter()
            .any(|&(name, value)| name == "--config" && value.is_none())
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
    // rest of the word (`-um`, `-u=m`, `-u=`) or the next word (`-u`, `-vu`).
    let cluster = word.trim_start_matches('-');
    let rest = cluster.trim_start_matches(|c| BOOL_SHORTS.contains(&c));
    let Some(first) = rest.chars().next() else {
        return Kind::Bool(word);
    };
    match VALUE_SHORTS.iter().find(|&&(short, _)| short == first) {
        Some(&(_, long)) => {
            let value = rest.get(first.len_utf8()..).unwrap_or_default();
            match value.strip_prefix('=') {
                // `-u=` is an empty attached value, never "take the next word".
                Some(attached) => Kind::Attached(long, attached),
                None if value.is_empty() => Kind::TakesValue(long),
                None => Kind::Attached(long, value),
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
/// strips it before the CLI sees its argv.
fn is_fd_duplication(word: &str) -> bool {
    let op = word.trim_start_matches(|c: char| c.is_ascii_digit());
    op.strip_prefix(">&")
        .or_else(|| op.strip_prefix("<&"))
        .is_some_and(|fd| !fd.is_empty() && fd.chars().all(|c| c.is_ascii_digit() || c == '-'))
}

/// The riskier of two networks for gating: mainnet, then unknown, then any identified other.
pub fn riskier(a: Network, b: Network) -> Network {
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

/// Split `text` into words like [`shell::parse`] does for one simple command, without
/// stripping anything: quotes removed, empty quoted words (`""`) kept.
pub fn tokenize(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut started = false;
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
                '\'' | '"' => {
                    quote = Some(c);
                    started = true;
                }
                c if c.is_whitespace() => {
                    if started {
                        tokens.push(std::mem::take(&mut current));
                        started = false;
                    }
                }
                _ => {
                    current.push(c);
                    started = true;
                }
            },
        }
    }
    if started {
        tokens.push(current);
    }
    tokens
}

/// The nearest `Anchor.toml` (cwd, then ancestors; the first that exists wins) provider
/// cluster: `Some` of its cluster ([`Network::Unknown`] when unrecognized, when the file cannot
/// be read or is oversized, or when it mentions `cluster` in a form this parser does not
/// understand), `None` when there is no file or it sets no cluster.
fn network_from_anchor_toml(cwd: &Path) -> Option<Network> {
    let path = cwd
        .ancestors()
        .map(|dir| dir.join("Anchor.toml"))
        .find(|p| crate::localfs::symlink_metadata(p).is_ok())?;
    let Some(text) = read_small_file(&path) else {
        return Some(Network::Unknown);
    };
    anchor_toml_cluster(&text)
}

/// The provider cluster of `Anchor.toml` text, in any of the forms `[provider] cluster = …`,
/// top-level `provider.cluster = …` or `provider = { cluster = … }`. Several fold to the
/// riskiest.
fn anchor_toml_cluster(text: &str) -> Option<Network> {
    let unquote = |v: &str| {
        v.trim()
            .trim_matches(|c| c == '"' || c == '\'')
            .trim()
            .to_string()
    };
    let mut section = String::new();
    let mut found: Option<Network> = None;
    let mut add = |value: &str| {
        let net = classify_url(&unquote(value));
        found = Some(found.map_or(net, |prev| riskier(prev, net)));
    };
    for raw_line in text.lines() {
        let line = strip_toml_comment(raw_line).trim();
        if let Some(header) = line.strip_prefix('[') {
            section = header
                .trim_end_matches(']')
                .trim()
                .trim_matches('"')
                .to_string();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key: String = key
            .chars()
            .filter(|c| !matches!(c, '"' | '\'' | ' ' | '\t'))
            .collect();
        match (section.as_str(), key.as_str()) {
            ("provider", "cluster") | ("", "provider.cluster") => add(value),
            ("", "provider") => {
                // Inline table: `provider = { cluster = "…", wallet = "…" }`.
                let inner = value.trim().trim_start_matches('{').trim_end_matches('}');
                for pair in inner.split(',') {
                    if let Some((k, v)) = pair.split_once('=') {
                        if k.trim().trim_matches(|c| c == '"' || c == '\'') == "cluster" {
                            add(v);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    found.or_else(|| text.contains("cluster").then_some(Network::Unknown))
}

/// `line` without a `#` comment (a `#` inside quotes is kept).
fn strip_toml_comment(line: &str) -> &str {
    let mut quote: Option<char> = None;
    for (i, c) in line.char_indices() {
        match (quote, c) {
            (None, '"' | '\'') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            (None, '#') => return &line[..i],
            _ => {}
        }
    }
    line
}

/// The cached `solana config get` URL.
#[derive(Debug, Default, Serialize, Deserialize)]
struct NetCache {
    /// The RPC URL.
    url: String,
    /// When it was read (epoch seconds).
    ts: u64,
    /// [`cli_config_fingerprint`] when it was read: a config change invalidates it.
    config: String,
}

/// The cached URL if the authenticated cache is fresh: written at most 60 s ago, never in
/// the future, and for the current CLI config file. A forged or edited cache is ignored.
fn read_fresh_cache(dir: &DataDir, now: u64, fingerprint: &str) -> Option<String> {
    let Loaded::Valid(cache) = statefile::load::<NetCache>(dir, NETCACHE_FILE) else {
        return None;
    };
    let age = now.checked_sub(cache.ts)?;
    (age <= NETCACHE_TTL_SECS && cache.config == fingerprint).then_some(cache.url)
}

/// Size and mtime of the default solana CLI config (`~/.config/solana/cli/config.yml`), so
/// `solana config set` invalidates the cache at once.
fn cli_config_fingerprint() -> String {
    let Some(home) = std::env::var_os("HOME") else {
        return "no-home".to_string();
    };
    let path = PathBuf::from(home).join(".config/solana/cli/config.yml");
    match crate::localfs::metadata(&path) {
        Ok(meta) => {
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_nanos());
            format!("{}:{mtime}", meta.len())
        }
        Err(_) => "absent".to_string(),
    }
}

/// Run `solana config get` for at most `timeout` and extract the RPC URL line. `None` on a
/// timeout (the child is killed) or any failure. Its output is read on a helper thread, so a
/// grandchild holding the pipe open cannot stall the gate.
fn solana_config_rpc_url(timeout: Duration) -> Option<String> {
    let deadline = Instant::now() + timeout;
    let mut child = Command::new("solana")
        .args(["config", "get"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let stdout = child.stdout.take()?;
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.take(64 * 1024).read_to_end(&mut buf);
        let _ = tx.send(buf);
    });
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    };
    if !status.success() {
        return None;
    }
    let buf = rx
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .ok()?;
    let text = String::from_utf8_lossy(&buf);
    text.lines()
        .find_map(|line| line.trim().strip_prefix("RPC URL:"))
        .map(|rest| rest.trim().to_string())
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

/// The plugin data dir for a CLI command run from the user's terminal: resolved by
/// [`crate::datadir::data_dir`] like the hooks (`CLAUDE_PLUGIN_DATA`, else the install dir under
/// `$CLAUDE_CONFIG_DIR` / `~/.claude` `plugins/data`). Never the cwd or `~/.safe-ai-skill`; the
/// error says to set `CLAUDE_PLUGIN_DATA`.
pub fn resolve_plugin_data_dir() -> Result<PathBuf, String> {
    crate::datadir::data_dir()
        .map(|d| d.path)
        .map_err(|e| format!("safe-ai-skill: {e}"))
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

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "safe_ai_skill_ctx_{tag}_{}_{}",
            std::process::id(),
            now_secs()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn netcache_from_the_future_or_forged_is_ignored() {
        let path = temp_dir("netcache");
        let dir = DataDir {
            path: path.clone(),
            trusted: true,
        };
        let now = 1_000_000;
        let store = |ts: u64, config: &str| {
            let cache = NetCache {
                url: "https://api.devnet.solana.com".into(),
                ts,
                config: config.into(),
            };
            statefile::store(&dir, NETCACHE_FILE, &cache).unwrap();
        };
        store(now - 10, "fp");
        assert_eq!(
            read_fresh_cache(&dir, now, "fp").as_deref(),
            Some("https://api.devnet.solana.com")
        );
        // Stale, written for another config, or stamped in the future.
        store(now - 61, "fp");
        assert_eq!(read_fresh_cache(&dir, now, "fp"), None);
        store(now - 10, "fp");
        assert_eq!(read_fresh_cache(&dir, now, "other"), None);
        store(u64::MAX, "fp");
        assert_eq!(read_fresh_cache(&dir, now, "fp"), None);
        // A hand-written (unauthenticated) cache is tampered: ignored.
        fs::write(
            path.join(NETCACHE_FILE),
            format!(r#"{{"url":"https://api.devnet.solana.com","ts":{now},"config":"fp"}}"#),
        )
        .unwrap();
        assert_eq!(read_fresh_cache(&dir, now, "fp"), None);
        let _ = fs::remove_dir_all(&path);
    }

    #[test]
    fn empty_attached_url_is_unknown_not_the_next_word() {
        assert_eq!(
            network_from_flags("solana transfer -u= d D 1"),
            Some(Network::Unknown)
        );
        assert_eq!(
            network_from_flags("solana transfer --url= d D 1"),
            Some(Network::Unknown)
        );
    }

    #[test]
    fn unknown_long_flag_before_a_dash_word_is_ambiguous() {
        assert_eq!(
            network_from_flags("solana transfer --mystery -ud D 1"),
            Some(Network::Unknown)
        );
    }

    #[test]
    fn tokenize_keeps_empty_quoted_words() {
        assert_eq!(tokenize(r#"a "" '' b"#), vec!["a", "", "", "b"]);
        assert_eq!(tokenize("a  b "), vec!["a", "b"]);
    }

    #[test]
    fn config_file_json_rpc_url_is_read() {
        let dir = temp_dir("cfgread");
        fs::write(
            dir.join("c.yml"),
            "json_rpc_url: 'https://api.mainnet-beta.solana.com'\n",
        )
        .unwrap();
        let words = shell::parse("solana transfer -C c.yml D 1").commands[0]
            .words
            .clone();
        let argv = Argv::from_shell(&words);
        assert_eq!(explicit_network(&argv, Some(&dir)), Some(Network::Mainnet));
        // Without a base, a relative path is unknown; a URL flag beats the file.
        assert_eq!(explicit_network(&argv, None), Some(Network::Unknown));
        let words = shell::parse("solana transfer -C c.yml -ud D 1").commands[0]
            .words
            .clone();
        assert_eq!(
            explicit_network(&Argv::from_shell(&words), Some(&dir)),
            Some(Network::Devnet)
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn anchor_toml_is_found_upward_and_unrecognized_cluster_is_unknown() {
        let dir = temp_dir("anchorup");
        fs::write(
            dir.join("Anchor.toml"),
            "[provider]\ncluster = \"Localnet\" # local\n",
        )
        .unwrap();
        let sub = dir.join("programs/p");
        fs::create_dir_all(&sub).unwrap();
        assert_eq!(network_from_anchor_toml(&sub), Some(Network::Localnet));
        fs::write(
            dir.join("Anchor.toml"),
            "[provider]\ncluster = \"https://rpc.example.com\"\n",
        )
        .unwrap();
        assert_eq!(network_from_anchor_toml(&sub), Some(Network::Unknown));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_schemeless_host_identifies_nothing() {
        for raw in [
            "devnet.helius-rpc.com",
            "api.devnet.solana.com",
            "api.testnet.solana.com",
            "127.0.0.1:8899",
            "localhost:8899",
            "ftp://api.devnet.solana.com",
            "//api.devnet.solana.com",
        ] {
            assert_eq!(classify_url(raw), Network::Unknown, "{raw}");
        }
        // Naming mainnet is still mainnet, scheme or not (the riskier reading).
        assert_eq!(classify_url("mainnet.helius-rpc.com"), Network::Mainnet);
        assert_eq!(
            network_from_flags("solana transfer X 1 -u devnet.helius-rpc.com"),
            Some(Network::Unknown)
        );
        assert_eq!(
            network_from_flags("solana transfer X 1 -u https://devnet.helius-rpc.com"),
            Some(Network::Devnet)
        );
        assert_eq!(classify_url("wss://api.devnet.solana.com"), Network::Devnet);
        assert_eq!(classify_url("http://localhost:8899"), Network::Localnet);
    }

    #[test]
    fn classify_url_matches_hosts_exactly() {
        for url in [
            "https://devnet.attacker.example",
            "https://api.devnet.solana.com.attacker.example",
            "https://api.devnet.solana.com@evil.example",
            "http://localhost.attacker.example:8899",
            "http://127.0.0.1:8899/proxy",
            "https://rpc.example.com/devnet",
        ] {
            assert_eq!(classify_url(url), Network::Unknown, "{url}");
        }
        assert_eq!(classify_url("http://[::1]:8899"), Network::Localnet);
        assert_eq!(classify_url("http://0.0.0.0:8899/"), Network::Localnet);
        assert_eq!(
            classify_url("https://devnet.helius-rpc.com/?api-key=x"),
            Network::Devnet
        );
        assert_eq!(
            classify_url("https://user@api.testnet.solana.com"),
            Network::Testnet
        );
    }

    #[test]
    fn anchor_toml_cluster_forms() {
        assert_eq!(
            anchor_toml_cluster("provider = { cluster = \"Devnet\", wallet = \"k\" }\n"),
            Some(Network::Devnet)
        );
        assert_eq!(
            anchor_toml_cluster("provider.cluster = 'localnet'\n"),
            Some(Network::Localnet)
        );
        assert_eq!(
            anchor_toml_cluster("[provider]\ncluster = \"devnet\"\n[x]\ncluster = \"m\"\n"),
            Some(Network::Devnet)
        );
        // Two provider clusters fold to the riskier.
        assert_eq!(
            anchor_toml_cluster(
                "provider.cluster = \"devnet\"\n[provider]\ncluster = \"mainnet\"\n"
            ),
            Some(Network::Mainnet)
        );
        // Mentions a cluster in a form the parser does not read: unknown, not a fallback.
        assert_eq!(
            anchor_toml_cluster("[\"provider\".x]\ncluster = \"devnet\"\n"),
            Some(Network::Unknown)
        );
        assert_eq!(anchor_toml_cluster("[provider]\nwallet = \"k\"\n"), None);
    }

    #[test]
    fn nearest_anchor_toml_wins_and_unreadable_is_unknown() {
        let dir = temp_dir("anchornear");
        fs::write(
            dir.join("Anchor.toml"),
            "[provider]\ncluster = \"devnet\"\n",
        )
        .unwrap();
        let sub = dir.join("sub");
        fs::create_dir_all(&sub).unwrap();
        // The nearer file sets no cluster: no fallback to the parent's.
        fs::write(sub.join("Anchor.toml"), "[workspace]\n").unwrap();
        assert_eq!(network_from_anchor_toml(&sub), None);
        // Oversized: unknown.
        fs::write(
            sub.join("Anchor.toml"),
            "#".repeat(MAX_CONFIG_BYTES as usize + 1),
        )
        .unwrap();
        assert_eq!(network_from_anchor_toml(&sub), Some(Network::Unknown));
        // A directory named Anchor.toml cannot be read: unknown.
        fs::remove_file(sub.join("Anchor.toml")).unwrap();
        fs::create_dir_all(sub.join("Anchor.toml")).unwrap();
        assert_eq!(network_from_anchor_toml(&sub), Some(Network::Unknown));
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

    #[test]
    fn bypass_warning_is_boolean_and_leaves_the_cluster_flag_alone() {
        let tokens = tokenize("solana program close P --bypass-warning -ud");
        let argv = Argv::parse(&tokens);
        assert!(argv.has_flag("--bypass-warning"));
        assert_eq!(argv.network(), Some(Network::Devnet));
        assert_eq!(argv.positionals, vec!["program", "close", "P"]);
        assert_eq!(argv.uncertain_from, None);
    }
}
