//! Execution context: network resolution and well-known directories.
//!
//! [`resolve_network`] implements the precedence: explicit `-u`/`--url`/`--cluster` flag
//! in the command, then `ANCHOR_PROVIDER_URL`, then `<cwd>/Anchor.toml` `[provider]
//! cluster`, then a cached `solana config get` (60s TTL). It never panics — any failure
//! yields [`Network::Unknown`].

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
    /// `${CLAUDE_PLUGIN_DATA}` (or `~/.safe-solana-ai`) — where state lives.
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
/// Precedence: explicit flag in the command → `ANCHOR_PROVIDER_URL` env → `Anchor.toml`
/// `[provider] cluster` → cached `solana config get` (60s TTL). Returns
/// [`Network::Unknown`] when nothing resolves. Never panics.
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
    if s.contains("127.0.0.1") || s.contains("localhost") || s.contains("localnet") {
        return Network::Localnet;
    }
    if s.contains("devnet") {
        return Network::Devnet;
    }
    if s.contains("testnet") {
        return Network::Testnet;
    }
    // Mainnet last, and only if not already a dev/test endpoint. Helius mainnet RPCs and
    // generic mainnet-beta endpoints land here.
    if s.contains("mainnet") || s.contains("mainnet-beta") {
        return Network::Mainnet;
    }
    Network::Unknown
}

/// Extract a network from an explicit `-u <x>`, `--url <x>`, or `--cluster <x>` flag.
fn network_from_flags(command: &str) -> Option<Network> {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    let mut i = 0;
    while i < tokens.len() {
        let tok = tokens[i];
        // --url=value / --cluster=value / -u=value forms.
        if let Some(val) = tok
            .strip_prefix("--url=")
            .or_else(|| tok.strip_prefix("--cluster="))
            .or_else(|| tok.strip_prefix("-u="))
        {
            let net = classify_url(val);
            if net != Network::Unknown {
                return Some(net);
            }
        }
        // -u value / --url value / --cluster value forms.
        if (tok == "-u" || tok == "--url" || tok == "--cluster") && i + 1 < tokens.len() {
            let net = classify_url(tokens[i + 1]);
            if net != Network::Unknown {
                return Some(net);
            }
        }
        i += 1;
    }
    None
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

/// `${CLAUDE_PLUGIN_DATA}` if set, else `~/.safe-solana-ai`, else `./.safe-solana-ai`.
pub fn plugin_data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("CLAUDE_PLUGIN_DATA") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            return PathBuf::from(home).join(".safe-solana-ai");
        }
    }
    PathBuf::from(".safe-solana-ai")
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
    fn anchor_toml_provider_cluster() {
        let dir = std::env::temp_dir().join(format!("ssai_anchor_{}", std::process::id()));
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
        let dir = std::env::temp_dir().join(format!("ssai_prec_{}", std::process::id()));
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
        let dir = std::env::temp_dir().join(format!("ssai_unk_{}", std::process::id()));
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
        std::env::set_var("CLAUDE_PLUGIN_DATA", "/tmp/ssai-data");
        assert_eq!(plugin_data_dir(), PathBuf::from("/tmp/ssai-data"));
        match prev {
            Some(v) => std::env::set_var("CLAUDE_PLUGIN_DATA", v),
            None => std::env::remove_var("CLAUDE_PLUGIN_DATA"),
        }
    }
}
