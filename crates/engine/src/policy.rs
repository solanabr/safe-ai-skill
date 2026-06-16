//! Policy loading, deep-merge, profiles, and fail-closed behavior.
//!
//! The base policy mirrors `default.policy.yaml` and is embedded as
//! [`DEFAULT_POLICY_YAML`] so the crate compiles standalone. [`Policy::load`] merges a
//! project override over the default and FAILS CLOSED on any unrecoverable parse error.
//!
//! The relaxation layer is configured here: [`Policy::active_profile`] selects a
//! [`ProfileOverlay`] (`strict`/`autopilot`/`paranoid`/`off`) applied by
//! [`Policy::effective`]. [`Policy::hard_guards`] lists scopes that NO profile or grant
//! may relax.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;
use serde_yaml::Value as Yaml;

/// Embedded default policy. Mirrors `plugins/safe-ai-skill/policy/default.policy.yaml`.
pub const DEFAULT_POLICY_YAML: &str = r#"
version: 1
active_profile: strict
network:
  default: devnet
  mainnet: ask
spend:
  per_tx_sol_max: 1.0
  hard_tx_sol_max: 10.0
  daily_sol_max: 5.0
gates:
  - mainnet_deploy
  - program_upgrade
  - set_authority
  - account_close
hard_guards:
  - mainnet_deploy
  - set_authority
  - account_close
  - secret_read
mcp:
  sensitive_name_pattern: "transfer|sign|swap|send|withdraw|burn|pay|upgrade|stake|delegate|mint|bridge|lend|borrow"
swap:
  rugcheck: true
  rugcheck_max_score: 40
  rugcheck_timeout_ms: 3000
  trusted_mints:
    - "So11111111111111111111111111111111111111112"
    - "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
secrets:
  deny_read_globs:
    - "**/*-keypair.json"
    - "**/id.json"
    - "**/.env"
    - "**/.env.*"
    - "**/*.pem"
    - "~/.config/solana/**"
    - "~/.superstack/config.json"
  allow_read_globs:
    - "**/.env.example"
redact:
  enabled: true
audit:
  enabled: true
catalog:
  registry_path: ".claude/skills/skill-registry.json"
  high_risk_classes:
    - kind: wallet_signing
      decision: ask
      keywords:
        - "wallet signing"
        - "sign/submit"
        - signing
      ids:
        - phantom-mcp
    - kind: key_custody
      decision: ask
      keywords:
        - "key custody"
        - "key-custody"
        - "bip-39"
        - "bip39"
      ids:
        - x402-proxy-mcp
    - kind: installer_script
      decision: ask
      keywords:
        - "curl | bash"
        - "curl|bash"
        - "| sh"
        - "wget"
      ids: []
supply_chain:
  verify_skills_dirs:
    - "~/.claude/skills"
    - ".claude/skills"
  flag_unpinned_mcp: true
  flag_telemetry_curl: true
  verify_ext_submodules: true
  ext_dir: ".claude/skills/ext"
  exec_install_scripts: ask
profiles:
  strict: {}
  autopilot:
    relax_transfer: true
    relax_swap: true
    per_tx_sol_max: 2.0
  paranoid:
    ask_all: true
  off:
    disabled: true
"#;

/// Environment variable that overrides [`Policy::active_profile`].
pub const PROFILE_ENV: &str = "SAFE_AI_SKILL_PROFILE";

fn default_version() -> u32 {
    1
}
fn default_profile() -> String {
    "strict".to_string()
}

/// Top-level policy.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Policy {
    /// Schema version.
    #[serde(default = "default_version")]
    pub version: u32,
    /// Currently active profile name (overridable via env / `mode.json`).
    #[serde(default = "default_profile")]
    pub active_profile: String,
    /// Network gating policy.
    pub network: NetworkPolicy,
    /// Spend caps.
    pub spend: SpendPolicy,
    /// Always-ask gate names.
    pub gates: Vec<String>,
    /// Scopes that may never be relaxed by any profile or grant.
    pub hard_guards: Vec<String>,
    /// MCP gating policy.
    pub mcp: McpPolicy,
    /// Swap / rugcheck policy.
    pub swap: SwapPolicy,
    /// Secret-read globs.
    pub secrets: SecretsPolicy,
    /// Output redaction toggle.
    pub redact: TogglePolicy,
    /// Audit logging toggle.
    pub audit: TogglePolicy,
    /// Opt-in skill-registry catalog gating settings.
    pub catalog: CatalogPolicy,
    /// Supply-chain verification settings.
    pub supply_chain: SupplyChainPolicy,
    /// Named profile overlays.
    pub profiles: BTreeMap<String, ProfileOverlay>,
}

/// Network gating policy.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct NetworkPolicy {
    /// Assumed network when none can be resolved.
    pub default: String,
    /// Decision applied to any mainnet-touching action (`ask`/`deny`/`allow`).
    pub mainnet: String,
}

/// Spend caps in SOL.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SpendPolicy {
    /// Per-transaction soft cap; above → ask.
    pub per_tx_sol_max: f64,
    /// Per-transaction hard cap; above → deny.
    pub hard_tx_sol_max: f64,
    /// Daily cumulative cap; above → ask/deny.
    pub daily_sol_max: f64,
}

/// MCP gating policy.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct McpPolicy {
    /// Regex-like alternation of sensitive tool-name substrings.
    pub sensitive_name_pattern: String,
}

/// Swap / rugcheck policy.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SwapPolicy {
    /// Whether to query rugcheck before allowing swaps.
    pub rugcheck: bool,
    /// Deny swaps for mints scoring above this value.
    pub rugcheck_max_score: u32,
    /// Rugcheck request timeout (ms); on timeout → ask.
    pub rugcheck_timeout_ms: u64,
    /// Mints exempt from rugcheck.
    pub trusted_mints: Vec<String>,
}

/// Secret-read glob policy.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SecretsPolicy {
    /// Globs whose reads are denied.
    pub deny_read_globs: Vec<String>,
    /// Globs explicitly allowed even if they match a deny glob.
    pub allow_read_globs: Vec<String>,
}

/// A boolean feature toggle.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TogglePolicy {
    /// Whether the feature is enabled.
    pub enabled: bool,
}

/// Supply-chain verification settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SupplyChainPolicy {
    /// Directories scanned for installed skills.
    pub verify_skills_dirs: Vec<String>,
    /// Flag `@latest` / unpinned MCP entries.
    ///
    /// With the kit's MCPs deliberately kept at `@latest`, unpinned detection is
    /// INFORMATIONAL/LOW (a session note + opt-in pin offer), not a blocking warning.
    pub flag_unpinned_mcp: bool,
    /// Flag the solana-new Convex telemetry curl preamble.
    pub flag_telemetry_curl: bool,
    /// Verify each `ext/<name>` git submodule as an individual unit (vs. one `ext/` blob).
    #[serde(default = "default_true")]
    pub verify_ext_submodules: bool,
    /// Directory (relative to a skills root or project) holding the `ext/` submodules.
    #[serde(default = "default_ext_dir")]
    pub ext_dir: String,
    /// Runtime gate for `curl … | sh/bash` installer execution: `allow` | `ask` | `deny`.
    #[serde(default = "default_exec_install_scripts")]
    pub exec_install_scripts: String,
}

/// Opt-in skill-registry catalog gating.
///
/// The catalog is the kit's `skill-registry.json` (every entry `default_installed:false`).
/// safe-ai-skill parses it to (a) audit installed-vs-registry and (b) force `ask`/`deny` on entries
/// matching a [`HighRiskClass`] (e.g. `phantom-mcp` wallet signing, `x402-proxy-mcp` BIP-39
/// key custody, `curl … | bash` installer scripts).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CatalogPolicy {
    /// Path (relative to the project) of the opt-in registry catalog.
    pub registry_path: String,
    /// Risk classes that force a non-default decision on a matching catalog entry.
    pub high_risk_classes: Vec<HighRiskClass>,
}

/// One high-risk catalog classification rule.
///
/// A catalog entry is classified into this class when its id is in [`HighRiskClass::ids`]
/// OR any of [`HighRiskClass::keywords`] appears (case-insensitively) in the entry's
/// safety/description/tag text. A match forces [`HighRiskClass::decision`] (`ask`/`deny`).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct HighRiskClass {
    /// Machine-stable class label (e.g. `wallet_signing`, `key_custody`, `installer_script`).
    pub kind: String,
    /// Forced decision when an entry matches this class (`ask` | `deny`).
    pub decision: String,
    /// Case-insensitive substrings that classify an entry into this class.
    pub keywords: Vec<String>,
    /// Exact registry entry ids that always belong to this class.
    pub ids: Vec<String>,
}

fn default_true() -> bool {
    true
}
fn default_ext_dir() -> String {
    ".claude/skills/ext".to_string()
}
fn default_exec_install_scripts() -> String {
    "ask".to_string()
}

/// A profile overlay applied onto the base policy by [`Policy::effective`].
///
/// All fields are optional; only the set fields override the base.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ProfileOverlay {
    /// When `true`, transfers within caps become `Allow` instead of `Ask`.
    pub relax_transfer: bool,
    /// When `true`, swaps within caps become `Allow` instead of `Ask`.
    pub relax_swap: bool,
    /// When `true`, every soft-gated action becomes `Ask` (paranoid).
    pub ask_all: bool,
    /// When `true`, soft gates are disabled (off).
    pub disabled: bool,
    /// Optional per-transaction cap override for this profile.
    pub per_tx_sol_max: Option<f64>,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        NetworkPolicy {
            default: "devnet".into(),
            mainnet: "ask".into(),
        }
    }
}

impl Default for SpendPolicy {
    fn default() -> Self {
        SpendPolicy {
            per_tx_sol_max: 1.0,
            hard_tx_sol_max: 10.0,
            daily_sol_max: 5.0,
        }
    }
}

impl Default for McpPolicy {
    fn default() -> Self {
        McpPolicy {
            sensitive_name_pattern:
                "transfer|sign|swap|send|withdraw|burn|pay|upgrade|stake|delegate|mint|bridge|lend|borrow"
                    .into(),
        }
    }
}

impl Default for SwapPolicy {
    fn default() -> Self {
        SwapPolicy {
            rugcheck: true,
            rugcheck_max_score: 40,
            rugcheck_timeout_ms: 3000,
            trusted_mints: Vec::new(),
        }
    }
}

impl Default for SecretsPolicy {
    fn default() -> Self {
        SecretsPolicy {
            deny_read_globs: vec![
                "**/*-keypair.json".into(),
                "**/id.json".into(),
                "**/.env".into(),
                "**/.env.*".into(),
                "**/*.pem".into(),
                "~/.config/solana/**".into(),
                "~/.superstack/config.json".into(),
            ],
            allow_read_globs: vec!["**/.env.example".into()],
        }
    }
}

impl Default for TogglePolicy {
    fn default() -> Self {
        TogglePolicy { enabled: true }
    }
}

impl Default for SupplyChainPolicy {
    fn default() -> Self {
        SupplyChainPolicy {
            verify_skills_dirs: vec!["~/.claude/skills".into(), ".claude/skills".into()],
            flag_unpinned_mcp: true,
            flag_telemetry_curl: true,
            verify_ext_submodules: true,
            ext_dir: default_ext_dir(),
            exec_install_scripts: default_exec_install_scripts(),
        }
    }
}

impl Default for CatalogPolicy {
    fn default() -> Self {
        CatalogPolicy {
            registry_path: ".claude/skills/skill-registry.json".into(),
            high_risk_classes: default_high_risk_classes(),
        }
    }
}

impl Default for HighRiskClass {
    fn default() -> Self {
        HighRiskClass {
            kind: String::new(),
            decision: "ask".into(),
            keywords: Vec::new(),
            ids: Vec::new(),
        }
    }
}

/// The built-in high-risk class rules, mirroring the embedded policy.
fn default_high_risk_classes() -> Vec<HighRiskClass> {
    vec![
        HighRiskClass {
            kind: "wallet_signing".into(),
            decision: "ask".into(),
            keywords: vec![
                "wallet signing".into(),
                "sign/submit".into(),
                "signing".into(),
            ],
            ids: vec!["phantom-mcp".into()],
        },
        HighRiskClass {
            kind: "key_custody".into(),
            decision: "ask".into(),
            keywords: vec![
                "key custody".into(),
                "key-custody".into(),
                "bip-39".into(),
                "bip39".into(),
            ],
            ids: vec!["x402-proxy-mcp".into()],
        },
        HighRiskClass {
            kind: "installer_script".into(),
            decision: "ask".into(),
            keywords: vec![
                "curl | bash".into(),
                "curl|bash".into(),
                "| sh".into(),
                "wget".into(),
            ],
            ids: Vec::new(),
        },
    ]
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            version: 1,
            active_profile: "strict".into(),
            network: NetworkPolicy::default(),
            spend: SpendPolicy::default(),
            gates: vec![
                "mainnet_deploy".into(),
                "program_upgrade".into(),
                "set_authority".into(),
                "account_close".into(),
            ],
            hard_guards: vec![
                "mainnet_deploy".into(),
                "set_authority".into(),
                "account_close".into(),
                "secret_read".into(),
            ],
            mcp: McpPolicy::default(),
            swap: SwapPolicy::default(),
            secrets: SecretsPolicy::default(),
            redact: TogglePolicy::default(),
            audit: TogglePolicy::default(),
            catalog: CatalogPolicy::default(),
            supply_chain: SupplyChainPolicy::default(),
            profiles: default_profiles(),
        }
    }
}

fn default_profiles() -> BTreeMap<String, ProfileOverlay> {
    let mut m = BTreeMap::new();
    m.insert("strict".to_string(), ProfileOverlay::default());
    m.insert(
        "autopilot".to_string(),
        ProfileOverlay {
            relax_transfer: true,
            relax_swap: true,
            per_tx_sol_max: Some(2.0),
            ..ProfileOverlay::default()
        },
    );
    m.insert(
        "paranoid".to_string(),
        ProfileOverlay {
            ask_all: true,
            ..ProfileOverlay::default()
        },
    );
    m.insert(
        "off".to_string(),
        ProfileOverlay {
            disabled: true,
            ..ProfileOverlay::default()
        },
    );
    m
}

impl Policy {
    /// Load the effective base policy for a project.
    ///
    /// Order: parse `${CLAUDE_PLUGIN_ROOT}/policy/default.policy.yaml` if present, else the
    /// embedded [`DEFAULT_POLICY_YAML`]; then deep-merge `<cwd>/.safe-ai-skill/policy.yaml`
    /// over it. Any unrecoverable parse error → [`Policy::fail_closed`] (every soft gate
    /// becomes `ask`). The `active_profile` is then overridden by the [`PROFILE_ENV`] env var
    /// if set.
    ///
    /// Note: this returns the *base* policy. Call [`Policy::effective`] to apply the active
    /// profile overlay before gating.
    pub fn load(cwd: &Path) -> Policy {
        let base_src = plugin_default_src().unwrap_or_else(|| DEFAULT_POLICY_YAML.to_string());
        let mut base: Yaml = match serde_yaml::from_str(&base_src) {
            Ok(y) => y,
            Err(_) => return Policy::fail_closed(),
        };

        let override_path = cwd.join(".safe-ai-skill").join("policy.yaml");
        if let Ok(text) = std::fs::read_to_string(&override_path) {
            if let Ok(overlay) = serde_yaml::from_str::<Yaml>(&text) {
                base = merge_yaml(base, overlay);
            }
            // A malformed override is ignored: the base policy still applies.
        }

        let mut policy: Policy = match serde_yaml::from_value(base) {
            Ok(p) => p,
            Err(_) => return Policy::fail_closed(),
        };

        if let Ok(profile) = std::env::var(PROFILE_ENV) {
            if !profile.trim().is_empty() {
                policy.active_profile = profile;
            }
        }
        policy
    }

    /// A conservative policy used when configuration cannot be trusted.
    ///
    /// Every soft-gated action resolves to `ask`: caps are tiny, mainnet is `ask`, and all
    /// hard guards are present. Profiles cannot relax it because the active profile is
    /// `strict` (an empty overlay).
    pub fn fail_closed() -> Policy {
        Policy {
            version: 1,
            active_profile: "strict".into(),
            network: NetworkPolicy {
                default: "devnet".into(),
                mainnet: "ask".into(),
            },
            spend: SpendPolicy {
                per_tx_sol_max: 0.0,
                hard_tx_sol_max: 0.0,
                daily_sol_max: 0.0,
            },
            gates: vec![
                "mainnet_deploy".into(),
                "program_upgrade".into(),
                "set_authority".into(),
                "account_close".into(),
            ],
            hard_guards: vec![
                "mainnet_deploy".into(),
                "set_authority".into(),
                "account_close".into(),
                "secret_read".into(),
            ],
            mcp: McpPolicy::default(),
            swap: SwapPolicy::default(),
            secrets: SecretsPolicy::default(),
            redact: TogglePolicy { enabled: true },
            audit: TogglePolicy { enabled: true },
            catalog: CatalogPolicy::default(),
            supply_chain: SupplyChainPolicy::default(),
            profiles: {
                let mut m = BTreeMap::new();
                m.insert("strict".to_string(), ProfileOverlay::default());
                m
            },
        }
    }

    /// Whether this policy is the conservative fail-closed baseline (all caps zero).
    pub fn is_fail_closed(&self) -> bool {
        self.spend.per_tx_sol_max == 0.0
            && self.spend.hard_tx_sol_max == 0.0
            && self.spend.daily_sol_max == 0.0
    }

    /// Whether `scope_label` is a hard guard that may never be relaxed.
    pub fn is_hard_guard(&self, scope_label: &str) -> bool {
        self.hard_guards.iter().any(|g| g == scope_label)
    }

    /// Apply the active profile overlay onto this base policy, producing the policy that
    /// gates should evaluate against.
    ///
    /// `strict` (or an unknown profile name) is a no-op. `autopilot` may raise
    /// `per_tx_sol_max`. `paranoid`/`off` set advisory flags consumed by the relaxation
    /// layer and gates. Hard guards are unaffected.
    pub fn effective(&self) -> Policy {
        let mut out = self.clone();
        let overlay = match self.profiles.get(&self.active_profile) {
            Some(o) => o.clone(),
            None => return out, // unknown profile → strict
        };
        if let Some(cap) = overlay.per_tx_sol_max {
            out.spend.per_tx_sol_max = cap;
        }
        out
    }

    /// The active profile overlay (empty/default when unknown).
    pub fn active_overlay(&self) -> ProfileOverlay {
        self.profiles
            .get(&self.active_profile)
            .cloned()
            .unwrap_or_default()
    }
}

/// Read the plugin's on-disk default policy if `${CLAUDE_PLUGIN_ROOT}` points at one.
fn plugin_default_src() -> Option<String> {
    let root = std::env::var("CLAUDE_PLUGIN_ROOT").ok()?;
    let path = Path::new(&root).join("policy").join("default.policy.yaml");
    std::fs::read_to_string(path).ok()
}

/// Recursively overlay `overlay` onto `base`. Mappings merge key-by-key; any other node
/// in `overlay` replaces the corresponding `base` node.
fn merge_yaml(base: Yaml, overlay: Yaml) -> Yaml {
    match (base, overlay) {
        (Yaml::Mapping(mut base_map), Yaml::Mapping(overlay_map)) => {
            for (k, v) in overlay_map {
                let merged = match base_map.remove(&k) {
                    Some(existing) => merge_yaml(existing, v),
                    None => v,
                };
                base_map.insert(k, merged);
            }
            Yaml::Mapping(base_map)
        }
        (_, overlay) => overlay,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Parse the on-disk plugin policy YAML, asserting it exists and is well-formed.
    fn ondisk_policy() -> Policy {
        // The on-disk file lives at <repo>/plugins/safe-ai-skill/policy/default.policy.yaml,
        // i.e. three levels up from this crate's manifest dir (crates/engine).
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../plugins/safe-ai-skill/policy/default.policy.yaml");
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("on-disk policy missing at {}: {e}", path.display()));
        serde_yaml::from_str(&text).expect("on-disk policy must parse")
    }

    #[test]
    fn ondisk_policy_equivalent_to_embedded() {
        // The on-disk default.policy.yaml MUST be the full schema and parse to the same Policy
        // as the embedded DEFAULT_POLICY_YAML const (the "keep equivalent" invariant).
        let disk = ondisk_policy();
        let embedded: Policy = serde_yaml::from_str(DEFAULT_POLICY_YAML).unwrap();

        assert_eq!(disk.version, embedded.version);
        assert_eq!(disk.active_profile, embedded.active_profile);
        assert_eq!(disk.network.default, embedded.network.default);
        assert_eq!(disk.network.mainnet, embedded.network.mainnet);
        assert_eq!(disk.spend.per_tx_sol_max, embedded.spend.per_tx_sol_max);
        assert_eq!(disk.spend.hard_tx_sol_max, embedded.spend.hard_tx_sol_max);
        assert_eq!(disk.spend.daily_sol_max, embedded.spend.daily_sol_max);
        assert_eq!(disk.gates, embedded.gates);
        assert_eq!(disk.hard_guards, embedded.hard_guards);
        assert_eq!(
            disk.mcp.sensitive_name_pattern,
            embedded.mcp.sensitive_name_pattern
        );
        assert_eq!(disk.swap.trusted_mints, embedded.swap.trusted_mints);
        assert_eq!(
            disk.secrets.deny_read_globs,
            embedded.secrets.deny_read_globs
        );
        assert_eq!(
            disk.secrets.allow_read_globs,
            embedded.secrets.allow_read_globs
        );
        assert_eq!(disk.redact.enabled, embedded.redact.enabled);
        assert_eq!(disk.audit.enabled, embedded.audit.enabled);
        // Catalog parity.
        assert_eq!(disk.catalog.registry_path, embedded.catalog.registry_path);
        assert_eq!(
            disk.catalog.high_risk_classes.len(),
            embedded.catalog.high_risk_classes.len()
        );
        for (a, b) in disk
            .catalog
            .high_risk_classes
            .iter()
            .zip(&embedded.catalog.high_risk_classes)
        {
            assert_eq!(a.kind, b.kind);
            assert_eq!(a.decision, b.decision);
            assert_eq!(a.keywords, b.keywords);
            assert_eq!(a.ids, b.ids);
        }
        // Supply-chain parity (incl. the new ext fields).
        assert_eq!(
            disk.supply_chain.verify_skills_dirs,
            embedded.supply_chain.verify_skills_dirs
        );
        assert_eq!(
            disk.supply_chain.flag_unpinned_mcp,
            embedded.supply_chain.flag_unpinned_mcp
        );
        assert_eq!(
            disk.supply_chain.flag_telemetry_curl,
            embedded.supply_chain.flag_telemetry_curl
        );
        assert_eq!(
            disk.supply_chain.verify_ext_submodules,
            embedded.supply_chain.verify_ext_submodules
        );
        assert_eq!(disk.supply_chain.ext_dir, embedded.supply_chain.ext_dir);
        assert_eq!(
            disk.supply_chain.exec_install_scripts,
            embedded.supply_chain.exec_install_scripts
        );
        // Profiles parity.
        assert_eq!(
            disk.profiles.keys().collect::<Vec<_>>(),
            embedded.profiles.keys().collect::<Vec<_>>()
        );
        assert_eq!(disk.effective().spend.per_tx_sol_max, 1.0);
    }

    #[test]
    fn embedded_default_parses() {
        let p: Policy = serde_yaml::from_str(DEFAULT_POLICY_YAML).unwrap();
        assert_eq!(p.version, 1);
        assert_eq!(p.active_profile, "strict");
        assert_eq!(p.network.mainnet, "ask");
        assert_eq!(p.spend.per_tx_sol_max, 1.0);
        assert_eq!(p.spend.hard_tx_sol_max, 10.0);
        assert!(p.redact.enabled);
        assert!(p.audit.enabled);
        assert!(p.hard_guards.contains(&"secret_read".to_string()));
        assert!(p.profiles.contains_key("autopilot"));
    }

    #[test]
    fn defaults_match_embedded() {
        let d = Policy::default();
        let p: Policy = serde_yaml::from_str(DEFAULT_POLICY_YAML).unwrap();
        assert_eq!(d.spend.per_tx_sol_max, p.spend.per_tx_sol_max);
        assert_eq!(d.mcp.sensitive_name_pattern, p.mcp.sensitive_name_pattern);
        assert_eq!(d.hard_guards, p.hard_guards);
        assert_eq!(
            d.supply_chain.verify_ext_submodules,
            p.supply_chain.verify_ext_submodules
        );
        assert_eq!(d.supply_chain.ext_dir, p.supply_chain.ext_dir);
        assert_eq!(
            d.supply_chain.exec_install_scripts,
            p.supply_chain.exec_install_scripts
        );
        assert_eq!(d.catalog.registry_path, p.catalog.registry_path);
        assert_eq!(
            d.catalog.high_risk_classes.len(),
            p.catalog.high_risk_classes.len()
        );
    }

    #[test]
    fn embedded_has_expanded_mcp_verbs_catalog_and_ext() {
        let p: Policy = serde_yaml::from_str(DEFAULT_POLICY_YAML).unwrap();
        // Expanded value-moving verb list (G4).
        for verb in ["stake", "delegate", "mint", "bridge", "lend", "borrow"] {
            assert!(
                p.mcp.sensitive_name_pattern.contains(verb),
                "missing verb `{verb}`"
            );
        }
        // Catalog high-risk classes present and keyed.
        let kinds: Vec<&str> = p
            .catalog
            .high_risk_classes
            .iter()
            .map(|c| c.kind.as_str())
            .collect();
        assert!(kinds.contains(&"wallet_signing"));
        assert!(kinds.contains(&"key_custody"));
        assert!(kinds.contains(&"installer_script"));
        // ext submodule verification defaults.
        assert!(p.supply_chain.verify_ext_submodules);
        assert_eq!(p.supply_chain.ext_dir, ".claude/skills/ext");
        assert_eq!(p.supply_chain.exec_install_scripts, "ask");
    }

    #[test]
    fn older_policy_without_new_fields_still_parses() {
        // A pre-expansion override (no catalog / no ext fields) must parse via serde defaults.
        let legacy = "version: 1\nsupply_chain:\n  flag_unpinned_mcp: true\n";
        let p: Policy = serde_yaml::from_str(legacy).unwrap();
        assert!(p.supply_chain.verify_ext_submodules); // serde default
        assert_eq!(p.supply_chain.exec_install_scripts, "ask");
        assert_eq!(
            p.catalog.registry_path,
            ".claude/skills/skill-registry.json"
        );
    }

    #[test]
    fn merge_override_changes_only_set_fields() {
        let base: Yaml = serde_yaml::from_str(DEFAULT_POLICY_YAML).unwrap();
        let overlay: Yaml = serde_yaml::from_str("spend:\n  per_tx_sol_max: 0.25\n").unwrap();
        let merged = merge_yaml(base, overlay);
        let p: Policy = serde_yaml::from_value(merged).unwrap();
        assert_eq!(p.spend.per_tx_sol_max, 0.25);
        // untouched field keeps default
        assert_eq!(p.spend.hard_tx_sol_max, 10.0);
        assert_eq!(p.network.mainnet, "ask");
    }

    #[test]
    fn load_merges_project_override() {
        let dir = std::env::temp_dir().join(format!("safe_ai_skill_pol_{}", std::process::id()));
        let cfg = dir.join(".safe-ai-skill");
        fs::create_dir_all(&cfg).unwrap();
        fs::write(cfg.join("policy.yaml"), "spend:\n  per_tx_sol_max: 0.1\n").unwrap();
        let p = Policy::load(&dir);
        assert_eq!(p.spend.per_tx_sol_max, 0.1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fail_closed_is_conservative() {
        let p = Policy::fail_closed();
        assert!(p.is_fail_closed());
        assert_eq!(p.network.mainnet, "ask");
        assert_eq!(p.active_profile, "strict");
        assert!(p.is_hard_guard("secret_read"));
    }

    #[test]
    fn effective_autopilot_raises_cap() {
        let mut p: Policy = serde_yaml::from_str(DEFAULT_POLICY_YAML).unwrap();
        p.active_profile = "autopilot".into();
        let eff = p.effective();
        assert_eq!(eff.spend.per_tx_sol_max, 2.0);
        assert!(eff.active_overlay().relax_transfer);
    }

    #[test]
    fn effective_strict_is_noop() {
        let p: Policy = serde_yaml::from_str(DEFAULT_POLICY_YAML).unwrap();
        let eff = p.effective();
        assert_eq!(eff.spend.per_tx_sol_max, p.spend.per_tx_sol_max);
    }

    #[test]
    fn unknown_profile_falls_back_to_base() {
        let mut p: Policy = serde_yaml::from_str(DEFAULT_POLICY_YAML).unwrap();
        p.active_profile = "does-not-exist".into();
        let eff = p.effective();
        assert_eq!(eff.spend.per_tx_sol_max, 1.0);
    }
}
