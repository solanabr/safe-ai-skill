//! Policy loading, project ratchet, tiers, and fail-closed behavior.
//!
//! The base policy mirrors `default.policy.yaml` and is embedded as
//! [`DEFAULT_POLICY_YAML`] so the crate compiles standalone. [`Policy::load`] ratchets a
//! project override over the default — it may only tighten it, see [`ratchet`] — and FAILS
//! CLOSED on any unrecoverable parse error.
//!
//! The strictness the user picked is a [`tier::Tier`] (D8 v2): [`load_runtime`] resolves it
//! ([`tier::resolve`]) together with the sandbox state and the headless rule into
//! [`Policy::runtime`], which gates read. The base policy names the base tier (`tier`, or the
//! legacy `active_profile` alias); a project's `tier`/`active_profile` and `secrets.env_read`
//! are raise-only hints recorded here for the resolver. Hard guards are set by the gates
//! themselves ([`crate::gate::GateMeta::hard_guard`]); no tier, grant or policy relaxes them.
//! The removed knobs (`profiles` with `ask_all` and the autopilot cap, `gates`,
//! `hard_guards`) are ignored where an old policy still has them, and listed in
//! [`Policy::ignored_overrides`].

use std::path::Path;

use serde::Deserialize;
use serde_yaml::Value as Yaml;

mod ratchet;
pub mod tier;

use ratchet::{apply_project_overlay, is_user_skills, PROJECT_POLICY, SCAN_DIRS_OUTSIDE};
use tier::{EnvRead, RawHint, Tier, TierContext, PROFILE_ENV, TIER_ENV};

use crate::datadir::DataDir;
use crate::sandbox::SandboxState;

/// Embedded default policy. Mirrors `plugins/safe-ai-skill/policy/default.policy.yaml`.
pub const DEFAULT_POLICY_YAML: &str = r#"
version: 1
tier: relaxed
network:
  default: devnet
  mainnet: ask
spend:
  per_tx_sol_max: 1.0
  hard_tx_sol_max: 10.0
  daily_sol_max: 5.0
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
  env_read: tier
  deny_read_globs:
    - "**/*-keypair.json"
    - "~/.superstack/config.json"
  key_material_extra_globs: []
  exfil_hosts_extra: []
  allow_read_globs:
    - "**/.env.example"
    - "**/.env.sample"
    - "**/.env.template"
    - "**/.env.dist"
    - "**/.env.schema"
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
    - ".claude/skills"
  flag_unpinned_mcp: true
  flag_telemetry_curl: true
  verify_ext_submodules: true
  ext_dir: ".claude/skills/ext"
  exec_install_scripts: ask
  on_block: deny
"#;

fn default_version() -> u32 {
    1
}

/// Top-level policy.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default)]
pub struct Policy {
    /// Schema version.
    #[serde(default = "default_version")]
    pub version: u32,
    /// Network gating policy.
    pub network: NetworkPolicy,
    /// Spend caps.
    pub spend: SpendPolicy,
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
    /// Overrides that would have loosened the policy and were refused (project overlay
    /// fields) and removed settings. Listed by [`Policy::ignored_notice`] at SessionStart.
    #[serde(skip)]
    pub ignored_overrides: Vec<String>,
    /// The base policy's tier (`tier`, else the legacy `active_profile` alias).
    #[serde(skip)]
    pub base_tier: Tier,
    /// The project overlay's `tier` / `active_profile` values: raise-only hints.
    #[serde(skip)]
    pub repo_tier_hints: Vec<RawHint>,
    /// The project overlay's own `secrets.env_read`, when it names a known word (it may only
    /// tighten the user's choice).
    #[serde(skip)]
    pub repo_env_read: Option<EnvRead>,
    /// The resolved tier, `env_read`, sandbox state and headless flag ([`load_runtime`]); the
    /// default (Relaxed, deny, sandbox unknown, interactive) until then.
    #[serde(skip)]
    pub runtime: TierContext,
    /// Scan dirs the project overlay added, confined on disk by [`Policy::load`].
    #[serde(skip)]
    project_scan_dirs: Vec<String>,
}

/// Network gating policy.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default)]
pub struct NetworkPolicy {
    /// Assumed network when none can be resolved.
    pub default: String,
    /// Decision applied to any mainnet-touching action (`ask`/`deny`/`allow`).
    pub mainnet: String,
}

/// Spend caps in SOL.
#[derive(Debug, Clone, PartialEq, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default)]
pub struct McpPolicy {
    /// Regex-like alternation of sensitive tool-name substrings.
    pub sensitive_name_pattern: String,
}

/// Swap / rugcheck policy.
#[derive(Debug, Clone, PartialEq, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default)]
pub struct SecretsPolicy {
    /// Raw reads of project env files (`.env`, `.env.*` inside the project): `tier` (default:
    /// open at Off/Relaxed/Medium, denied at High) or `deny` (denied at every tier). The user
    /// sets it with `safe-ai-skill tier --env-read` ([`tier::EnvRead`]); a project may only
    /// tighten it. Other env files and hard-deny classes (keypairs, private keys, the Solana
    /// config tree) are never affected.
    pub env_read: String,
    /// Extra globs whose reads are denied, on top of the built-in classes
    /// (`gates::secretpath`).
    pub deny_read_globs: Vec<String>,
    /// Extra key-material globs, added to the shared `credentials.list` (union only).
    pub key_material_extra_globs: Vec<String>,
    /// Extra exfil hosts, added to the shared `exfil-hosts.list` at every tier above Off
    /// (union only: nothing removes a listed host).
    pub exfil_hosts_extra: Vec<String>,
    /// Globs readable even though they match a deny glob or the env class (never a hard-deny
    /// class). Templates and `.env.schema` are readable only while listed here.
    pub allow_read_globs: Vec<String>,
}

/// A boolean feature toggle.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default)]
pub struct TogglePolicy {
    /// Whether the feature is enabled.
    pub enabled: bool,
}

/// Supply-chain verification settings.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default)]
pub struct SupplyChainPolicy {
    /// Directories scanned for installed skills.
    pub verify_skills_dirs: Vec<String>,
    /// Flag `@latest` / unpinned MCP entries.
    ///
    /// With the kit's MCPs deliberately kept at `@latest`, unpinned detection is
    /// INFORMATIONAL/LOW (a session note + opt-in pin offer), not a blocking warning.
    pub flag_unpinned_mcp: bool,
    /// Flag the outbound telemetry curl preamble (POST to an external host).
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
    /// What a blocked skill pack gets: `deny` (enforced in place by the gates, the default) or
    /// `move` (also moved into `${DATA}/quarantine/`, origin recorded, never overwriting).
    #[serde(default = "default_on_block")]
    pub on_block: String,
}

/// Opt-in skill-registry catalog gating.
///
/// The catalog is the kit's `skill-registry.json` (every entry `default_installed:false`).
/// safe-ai-skill parses it to (a) audit installed-vs-registry and (b) force `ask`/`deny` on entries
/// matching a [`HighRiskClass`] (e.g. `phantom-mcp` wallet signing, `x402-proxy-mcp` BIP-39
/// key custody, `curl … | bash` installer scripts).
#[derive(Debug, Clone, PartialEq, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Deserialize)]
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

fn default_on_block() -> String {
    "deny".to_string()
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
            env_read: "tier".into(),
            deny_read_globs: vec![
                "**/*-keypair.json".into(),
                "~/.superstack/config.json".into(),
            ],
            key_material_extra_globs: Vec::new(),
            exfil_hosts_extra: Vec::new(),
            allow_read_globs: vec![
                "**/.env.example".into(),
                "**/.env.sample".into(),
                "**/.env.template".into(),
                "**/.env.dist".into(),
                "**/.env.schema".into(),
            ],
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
            verify_skills_dirs: vec![".claude/skills".into()],
            flag_unpinned_mcp: true,
            flag_telemetry_curl: true,
            verify_ext_submodules: true,
            ext_dir: default_ext_dir(),
            exec_install_scripts: default_exec_install_scripts(),
            on_block: default_on_block(),
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
            network: NetworkPolicy::default(),
            spend: SpendPolicy::default(),
            mcp: McpPolicy::default(),
            swap: SwapPolicy::default(),
            secrets: SecretsPolicy::default(),
            redact: TogglePolicy::default(),
            audit: TogglePolicy::default(),
            catalog: CatalogPolicy::default(),
            supply_chain: SupplyChainPolicy::default(),
            ignored_overrides: Vec::new(),
            base_tier: Tier::Relaxed,
            repo_tier_hints: Vec::new(),
            repo_env_read: None,
            runtime: TierContext::default(),
            project_scan_dirs: Vec::new(),
        }
    }
}

/// Load the policy for a session rooted at `cwd` and resolve its runtime tier context: the
/// tier and `env_read` ([`tier::resolve`], against the project root of `cwd`), with `sandbox`
/// and `headless` as given. Returns the policy (with [`Policy::runtime`] set) and the
/// resolution, whose notes SessionStart and `status` print.
pub fn load_runtime(
    cwd: &Path,
    dir: &DataDir,
    env: &dyn Fn(&str) -> Option<String>,
    sandbox: SandboxState,
    headless: bool,
) -> (Policy, tier::Resolution) {
    let mut policy = Policy::load(cwd);
    let root = tier::project_root(cwd);
    let resolution = tier::resolve(&root, dir, &policy, env);
    policy.runtime = TierContext {
        tier: resolution.tier,
        source: resolution.source,
        env_read: resolution.env_read,
        sandbox,
        headless,
    };
    (policy, resolution)
}

/// The base policy alone (the plugin's default policy file, else the embedded one), with no
/// project overlay.
pub fn base() -> Policy {
    let src = plugin_default_src().unwrap_or_else(|| DEFAULT_POLICY_YAML.to_string());
    Policy::from_sources(&src, None)
}

impl Policy {
    /// Load the base policy for a project.
    ///
    /// Order: parse `${CLAUDE_PLUGIN_ROOT}/policy/default.policy.yaml` if present, else the
    /// embedded [`DEFAULT_POLICY_YAML`]; then ratchet `<cwd>/.safe-ai-skill/policy.yaml` over
    /// it, which may only tighten it. An unparsable base → [`Policy::fail_closed`] (every
    /// soft gate becomes `ask`). Scan dirs the project added are kept only when they resolve,
    /// on disk, to a directory strictly inside `cwd`. The tier is resolved separately
    /// ([`load_runtime`]).
    pub fn load(cwd: &Path) -> Policy {
        let base_src = plugin_default_src().unwrap_or_else(|| DEFAULT_POLICY_YAML.to_string());
        let project_src =
            std::fs::read_to_string(cwd.join(".safe-ai-skill").join("policy.yaml")).ok();
        let mut policy = Policy::from_sources(&base_src, project_src.as_deref());
        let home = std::env::var_os("HOME").filter(|h| !h.is_empty());
        policy.confine_project_dirs(cwd, home.as_deref().map(Path::new));
        policy
    }

    /// Re-check the scan dirs the project overlay added against the filesystem. The ratchet
    /// checks the text only, so a committed symlink (`up -> ..`) would pass it and sweep
    /// whatever it points at. Each dir becomes its canonical path when it is a directory
    /// strictly inside the canonical `root`, so the sweep scans exactly what was checked;
    /// otherwise it is dropped (and noted when it resolves outside). The one opt-in outside the
    /// project, `~/.claude/skills`, is kept as the canonical `<home>/.claude/skills`.
    fn confine_project_dirs(&mut self, root: &Path, home: Option<&Path>) {
        let added = std::mem::take(&mut self.project_scan_dirs);
        if added.is_empty() {
            return;
        }
        let canonical_root = std::fs::canonicalize(root).ok();
        let mut outside = false;
        for dir in added {
            let (resolved, within) = if is_user_skills(&dir) {
                let resolved =
                    home.and_then(|h| std::fs::canonicalize(h.join(".claude/skills")).ok());
                let within = resolved.is_some();
                (resolved, within)
            } else {
                let resolved = std::fs::canonicalize(root.join(&dir)).ok();
                let within = match (&canonical_root, &resolved) {
                    (Some(r), Some(path)) => path != r && path.starts_with(r),
                    _ => false,
                };
                (resolved, within)
            };
            // A dir that does not resolve has nothing to sweep: drop it quietly.
            outside |= resolved.is_some() && !within;
            let keep = resolved
                .filter(|path| within && path.is_dir())
                .and_then(|path| path.to_str().map(str::to_string));
            let dirs = &mut self.supply_chain.verify_skills_dirs;
            if let Some(slot) = dirs.iter().position(|d| *d == dir) {
                match keep {
                    Some(path) => dirs[slot] = path,
                    None => {
                        dirs.remove(slot);
                    }
                }
            }
        }
        let note = SCAN_DIRS_OUTSIDE.to_string();
        if outside && !self.ignored_overrides.contains(&note) {
            self.ignored_overrides.push(note);
        }
    }

    /// Build a policy from its sources without touching the environment or the filesystem.
    ///
    /// `base_src` is the trusted default policy YAML; `project_src` a project's overlay, which
    /// may only tighten it. Every refused override is noted in [`Policy::ignored_overrides`].
    /// Scan dirs the project adds get only the text check here: confining them on disk
    /// (symlinks) happens in [`Policy::load`] alone.
    pub fn from_sources(base_src: &str, project_src: Option<&str>) -> Policy {
        let base: Yaml = match serde_yaml::from_str(base_src) {
            Ok(y) => y,
            Err(_) => return Policy::fail_closed(),
        };
        let mut policy: Policy = match serde_yaml::from_value(base.clone()) {
            Ok(p) => p,
            Err(_) => return Policy::fail_closed(),
        };

        policy.ignored_overrides.extend(removed_settings(&base));
        policy.base_tier = base_tier(&base, &mut policy.ignored_overrides);
        pin_base_env_read(&mut policy);

        if let Some(text) = project_src {
            apply_project_overlay(&mut policy, &base, text);
        }
        policy
    }

    /// A conservative policy used when configuration cannot be trusted.
    ///
    /// Every soft-gated action resolves to `ask`: caps are tiny, mainnet is `ask`, raw project
    /// env reads are denied (`env_read: deny`), and all hard guards are present.
    pub fn fail_closed() -> Policy {
        Policy {
            version: 1,
            network: NetworkPolicy {
                default: "devnet".into(),
                mainnet: "ask".into(),
            },
            spend: SpendPolicy {
                per_tx_sol_max: 0.0,
                hard_tx_sol_max: 0.0,
                daily_sol_max: 0.0,
            },
            mcp: McpPolicy::default(),
            swap: SwapPolicy::default(),
            secrets: SecretsPolicy {
                env_read: "deny".into(),
                ..SecretsPolicy::default()
            },
            redact: TogglePolicy { enabled: true },
            audit: TogglePolicy { enabled: true },
            catalog: CatalogPolicy::default(),
            supply_chain: SupplyChainPolicy::default(),
            ignored_overrides: Vec::new(),
            base_tier: Tier::Relaxed,
            repo_tier_hints: Vec::new(),
            repo_env_read: None,
            runtime: TierContext::default(),
            project_scan_dirs: Vec::new(),
        }
    }

    /// Whether this policy is the conservative fail-closed baseline (all caps zero).
    pub fn is_fail_closed(&self) -> bool {
        self.spend.per_tx_sol_max == 0.0
            && self.spend.hard_tx_sol_max == 0.0
            && self.spend.daily_sol_max == 0.0
    }

    /// The effective tier ([`Policy::runtime`]).
    pub fn tier(&self) -> Tier {
        self.runtime.tier
    }

    /// The SessionStart notice listing [`Policy::ignored_overrides`]; `None` when there are
    /// none.
    pub fn ignored_notice(&self) -> Option<String> {
        if self.ignored_overrides.is_empty() {
            return None;
        }
        Some(format!(
            "safe-ai-skill did not apply these policy settings ({PROJECT_POLICY}, \
             {TIER_ENV} and {PROFILE_ENV} may only tighten; removed settings are ignored):\n - {}",
            self.ignored_overrides.join("\n - ")
        ))
    }
}

/// The base policy's tier: `tier`, else the legacy `active_profile` (an alias), else
/// `relaxed`. A value that names no tier is noted and `relaxed` applies.
fn base_tier(base: &Yaml, notes: &mut Vec<String>) -> Tier {
    for key in ["tier", "active_profile"] {
        if let Some(value) = base.get(key) {
            return match value.as_str().and_then(Tier::parse) {
                Some(t) if t < Tier::Relaxed => {
                    notes.push(format!(
                        "{key}: the plugin default policy may not go below relaxed (lowering is \
                         `safe-ai-skill tier`, confirmed by you); relaxed applies"
                    ));
                    Tier::Relaxed
                }
                Some(t) => t,
                None => {
                    notes.push(format!(
                        "{key}: not a tier name in the base policy; relaxed applies"
                    ));
                    Tier::Relaxed
                }
            };
        }
    }
    Tier::Relaxed
}

/// The plugin default policy's `secrets.env_read` must be a known word (`tier`, the default, or
/// the tightening `deny`). Anything else (the retired `ask` included) is ignored with a note and
/// `tier` applies.
fn pin_base_env_read(policy: &mut Policy) {
    if EnvRead::parse(&policy.secrets.env_read).is_none() {
        policy.ignored_overrides.push(
            "secrets.env_read: the plugin default policy may only say tier or deny; tier applies"
                .to_string(),
        );
        policy.secrets.env_read = "tier".to_string();
    }
}

/// Removed settings still present in the base policy `base`, one note each. They are
/// ignored; the policy still loads.
fn removed_settings(base: &Yaml) -> Vec<String> {
    let mut notes: Vec<String> = REMOVED_TOP_LEVEL
        .iter()
        .filter(|key| base.get(**key).is_some())
        .map(|key| format!("{key}: removed in 1.1.0; ignored"))
        .collect();
    if base.get("profiles").is_some() {
        notes.push(PROFILES_REMOVED.to_string());
    }
    notes
}

/// Top-level policy keys removed in 1.1.0 (never read before either).
pub(crate) const REMOVED_TOP_LEVEL: [&str; 2] = ["gates", "hard_guards"];

/// The note for a `profiles:` block (with `ask_all` and the autopilot cap).
pub(crate) const PROFILES_REMOVED: &str = "profiles: removed in 1.1.0 (tiers replace \
     profiles: `safe-ai-skill tier`; to turn the hooks off use SAFE_AI_SKILL_DISABLE); ignored";

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
        assert_eq!(disk.network.default, embedded.network.default);
        assert_eq!(disk.network.mainnet, embedded.network.mainnet);
        assert_eq!(disk.spend.per_tx_sol_max, embedded.spend.per_tx_sol_max);
        assert_eq!(disk.spend.hard_tx_sol_max, embedded.spend.hard_tx_sol_max);
        assert_eq!(disk.spend.daily_sol_max, embedded.spend.daily_sol_max);
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
        assert_eq!(disk.secrets.env_read, embedded.secrets.env_read);
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
        assert_eq!(disk.supply_chain.on_block, embedded.supply_chain.on_block);
        assert_eq!(
            disk.secrets.key_material_extra_globs,
            embedded.secrets.key_material_extra_globs
        );
        assert_eq!(
            disk.secrets.exfil_hosts_extra,
            embedded.secrets.exfil_hosts_extra
        );
        // Base tier parity, through the loader (the field is not deserialized).
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../plugins/safe-ai-skill/policy/default.policy.yaml");
        let text = fs::read_to_string(path).unwrap();
        let from_disk = Policy::from_sources(&text, None);
        assert_eq!(from_disk.base_tier, Tier::Relaxed);
        assert!(
            from_disk.ignored_overrides.is_empty(),
            "{:?}",
            from_disk.ignored_overrides
        );
    }

    #[test]
    fn embedded_default_parses() {
        let p: Policy = serde_yaml::from_str(DEFAULT_POLICY_YAML).unwrap();
        assert_eq!(p.version, 1);
        assert_eq!(p.network.mainnet, "ask");
        assert_eq!(p.spend.per_tx_sol_max, 1.0);
        assert_eq!(p.spend.hard_tx_sol_max, 10.0);
        assert!(p.redact.enabled);
        assert!(p.audit.enabled);
        assert_eq!(
            Policy::from_sources(DEFAULT_POLICY_YAML, None).base_tier,
            Tier::Relaxed
        );
    }

    #[test]
    fn defaults_match_embedded() {
        let d = Policy::default();
        let p: Policy = serde_yaml::from_str(DEFAULT_POLICY_YAML).unwrap();
        assert_eq!(d.spend.per_tx_sol_max, p.spend.per_tx_sol_max);
        assert_eq!(d.mcp.sensitive_name_pattern, p.mcp.sensitive_name_pattern);
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
        assert_eq!(p.tier(), Tier::Relaxed);
    }

    #[test]
    fn the_shipped_policy_has_no_removed_settings() {
        let p = Policy::from_sources(DEFAULT_POLICY_YAML, None);
        assert!(p.ignored_overrides.is_empty(), "{:?}", p.ignored_overrides);
    }

    #[test]
    fn removed_settings_in_an_old_policy_are_listed_not_fatal() {
        let old = format!(
            "{DEFAULT_POLICY_YAML}gates: [mainnet_deploy]\nhard_guards: [secret_read]\n\
             profiles:\n  autopilot:\n    per_tx_sol_max: 2.0\n  paranoid:\n    ask_all: true\n"
        );
        let p = Policy::from_sources(&old, None);
        assert!(!p.is_fail_closed());
        assert_eq!(p.spend.per_tx_sol_max, 1.0);
        for note in ["gates:", "hard_guards:", "profiles:"] {
            assert!(
                p.ignored_overrides.iter().any(|n| n.starts_with(note)),
                "{note}: {:?}",
                p.ignored_overrides
            );
        }
    }

    #[test]
    fn the_base_tier_reads_tier_then_the_legacy_profile_alias() {
        let with = |line: &str| {
            Policy::from_sources(&DEFAULT_POLICY_YAML.replace("tier: relaxed", line), None)
        };
        assert_eq!(with("tier: high").base_tier, Tier::High);
        assert_eq!(with("active_profile: paranoid").base_tier, Tier::High);
        assert_eq!(with("active_profile: strict").base_tier, Tier::Relaxed);
        let off = with("tier: off");
        assert_eq!(off.base_tier, Tier::Relaxed);
        assert!(off.ignored_overrides.iter().any(|n| n.starts_with("tier:")));
        let env = Policy::from_sources(
            &DEFAULT_POLICY_YAML.replace("env_read: tier", "env_read: ask"),
            None,
        );
        assert_eq!(env.secrets.env_read, "tier");
        assert!(env
            .ignored_overrides
            .iter()
            .any(|n| n.starts_with("secrets.env_read")));
        let deny = Policy::from_sources(
            &DEFAULT_POLICY_YAML.replace("env_read: tier", "env_read: deny"),
            None,
        );
        assert_eq!(deny.secrets.env_read, "deny");
        let bad = with("tier: turbo");
        assert_eq!(bad.base_tier, Tier::Relaxed);
        assert!(bad.ignored_overrides.iter().any(|n| n.starts_with("tier:")));
    }
}
