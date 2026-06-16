//! Opt-in skill-registry catalog parsing and high-risk classification.
//!
//! The kit ships `.claude/skills/skill-registry.json`: an opt-in catalog whose entries are
//! all `default_installed:false`. ssai parses it to (a) audit installed-vs-registry and
//! (b) force `ask`/`deny` on entries matching a [`crate::policy::HighRiskClass`] (e.g.
//! `phantom-mcp` wallet signing, `x402-proxy-mcp` BIP-39 key custody, `curl … | bash`
//! installer scripts).
//!
//! # Round-2 ownership
//! **Agent A** fills the stub bodies (parse + classify + load) and the `#[cfg(test)]` tests.
//! The public signatures below are FROZEN — consume them, do not change them. The on-disk
//! registry shape is `{ "version": …, "updated": …, "entries": [ … ] }` where each entry
//! carries `id`, `name`, `type`, `domain`, `description`, `source`, `install`, `license`,
//! `maintainer`, `signal`, `default_installed`, `safety`, `tags`. The fields kept on
//! [`RegistryEntry`] are the subset ssai gates on; unknown fields are tolerated.

use std::path::Path;

use serde::Deserialize;

use crate::error::{Error, Result};
use crate::policy::{HighRiskClass, Policy};

/// One catalog entry, projected to the fields ssai gates on.
///
/// `risk_class` is NOT a field of the on-disk JSON — it is the class ssai *derives* by
/// classifying the entry against [`crate::policy::CatalogPolicy::high_risk_classes`] (see
/// [`Registry::high_risk`]). It is `None` until classified.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RegistryEntry {
    /// Stable catalog id (e.g. `phantom-mcp`). The registry's `id` field.
    #[serde(default)]
    pub id: String,
    /// Human-readable title. The registry's `name` field.
    #[serde(default)]
    pub title: String,
    /// Where the entry installs from (the registry's `source` URL).
    #[serde(default)]
    pub source: String,
    /// Entry kind: `skill` | `mcp` | `plugin` | `template-repo` | `aggregator` (`type`).
    #[serde(default, rename = "type")]
    pub category: String,
    /// Whether the kit installs this entry by default (always `false` for the opt-in catalog).
    #[serde(default)]
    pub default_installed: bool,
    /// Free-text safety note (the registry's `safety` field); the primary classification input.
    #[serde(default)]
    pub safety: Option<String>,
    /// Free-text description; a secondary classification input.
    #[serde(default)]
    pub description: Option<String>,
    /// Catalog tags; a secondary classification input.
    #[serde(default)]
    pub tags: Vec<String>,
    /// The derived high-risk class label, populated by [`Registry::high_risk`]. NOT on disk.
    #[serde(skip)]
    pub risk_class: Option<String>,
}

/// A parsed registry catalog.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Registry {
    /// Catalog entries.
    #[serde(default)]
    pub entries: Vec<RegistryEntry>,
}

/// Raw on-disk catalog entry, deserialized straight from JSON before projection.
///
/// The public [`RegistryEntry`] keeps only the subset ssai gates on. This private mirror
/// captures the on-disk field names (`name`, `type`) so they can be mapped onto the
/// public struct (`title`, `category`). Unknown fields are silently dropped.
#[derive(Debug, Default, Deserialize)]
struct RawEntry {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    source: String,
    #[serde(default)]
    default_installed: bool,
    #[serde(default)]
    safety: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
}

impl From<RawEntry> for RegistryEntry {
    fn from(raw: RawEntry) -> Self {
        RegistryEntry {
            id: raw.id,
            title: raw.name,
            source: raw.source,
            category: raw.kind,
            default_installed: raw.default_installed,
            safety: raw.safety,
            description: raw.description,
            tags: raw.tags,
            risk_class: None,
        }
    }
}

/// Raw on-disk catalog document.
///
/// The kit ships `{ "version", "updated", "entries": [ … ] }`. Older or hand-rolled
/// catalogs may use `skills` for the entry list; both are accepted, and a bare top-level
/// array is handled separately in [`parse`]. Every field defaults so a partial document
/// still parses.
#[derive(Debug, Default, Deserialize)]
struct RawCatalog {
    #[serde(default)]
    entries: Vec<RawEntry>,
    #[serde(default)]
    skills: Vec<RawEntry>,
}

/// Parse a `skill-registry.json` body into a [`Registry`].
///
/// Accepts either the canonical object form (`{ "version", "updated", "entries": [ … ] }`,
/// or `skills` as an alias for `entries`) or a bare top-level array of entries. On-disk
/// field names are mapped onto the public struct (`name`→`title`, `type`→`category`) and
/// unknown/missing fields are tolerated so the parser degrades gracefully across catalog
/// versions.
///
/// # Errors
/// Returns [`Error::Parse`] on malformed JSON — this never panics on bad input.
pub fn parse(json: &str) -> Result<Registry> {
    // An empty/whitespace body is a well-formed empty catalog, not an error.
    if json.trim().is_empty() {
        return Ok(Registry::default());
    }

    // First try the canonical object form. If the document is a bare array, retry as a Vec.
    let raw_entries = match serde_json::from_str::<RawCatalog>(json) {
        Ok(catalog) => {
            if catalog.entries.is_empty() {
                catalog.skills
            } else {
                catalog.entries
            }
        }
        Err(object_err) => serde_json::from_str::<Vec<RawEntry>>(json)
            .map_err(|array_err| Error::Parse(format!("{object_err}; {array_err}")))?,
    };

    Ok(Registry {
        entries: raw_entries.into_iter().map(RegistryEntry::from).collect(),
    })
}

impl RegistryEntry {
    /// Whether the entry is opt-in (i.e. NOT installed by the kit by default).
    ///
    /// The opt-in catalog is entirely `default_installed:false`, so this is `true` for every
    /// genuine catalog entry; it lets `ssai add`/`registry verify` distinguish deliberate
    /// installs from defaults without re-reading the raw `default_installed` flag.
    pub fn is_opt_in(&self) -> bool {
        !self.default_installed
    }

    /// Lowercased haystack of every field [`Registry::high_risk`] classifies against.
    ///
    /// Concatenates `safety`, `description`, `title`, `category`, and `tags` so a single
    /// case-insensitive substring scan covers all classification inputs.
    fn classification_text(&self) -> String {
        let mut haystack = String::new();
        for field in [
            self.safety.as_deref().unwrap_or_default(),
            self.description.as_deref().unwrap_or_default(),
            self.title.as_str(),
            self.category.as_str(),
        ] {
            haystack.push_str(field);
            haystack.push(' ');
        }
        for tag in &self.tags {
            haystack.push_str(tag);
            haystack.push(' ');
        }
        haystack.to_lowercase()
    }
}

impl Registry {
    /// Load and parse the registry catalog at `path`.
    ///
    /// A missing file is treated as an empty catalog (`Ok(Registry::default())`) so session
    /// and verify flows degrade gracefully when the opt-in catalog is absent. Any other read
    /// failure surfaces as [`Error::Io`]; malformed contents surface as [`Error::Parse`].
    pub fn load(path: &Path) -> Result<Registry> {
        match std::fs::read_to_string(path) {
            Ok(body) => parse(&body),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Registry::default()),
            Err(err) => Err(Error::Io(err)),
        }
    }

    /// Find an entry by its exact catalog `id`.
    ///
    /// Returns the first matching entry, or `None` if no entry carries that id.
    pub fn entry_by_id(&self, id: &str) -> Option<&RegistryEntry> {
        self.entries.iter().find(|entry| entry.id == id)
    }

    /// Classify `entry` against `policy.catalog.high_risk_classes`.
    ///
    /// Returns the matching class `kind` (e.g. `"wallet_signing"`) when the entry's id is in a
    /// class's `ids` list OR any of its `keywords` appears (case-insensitively) in the entry's
    /// `safety` / `description` / `title` / `category` / `tags` text; otherwise `None`. The
    /// first matching class in policy order wins, so policies should order classes from highest
    /// to lowest severity.
    pub fn high_risk(entry: &RegistryEntry, policy: &Policy) -> Option<String> {
        let haystack = entry.classification_text();
        for class in &policy.catalog.high_risk_classes {
            if class.ids.iter().any(|id| id == &entry.id) {
                return Some(class.kind.clone());
            }
            if class
                .keywords
                .iter()
                .any(|keyword| !keyword.is_empty() && haystack.contains(&keyword.to_lowercase()))
            {
                return Some(class.kind.clone());
            }
        }
        None
    }

    /// Look up the forced policy decision (`"ask"` | `"deny"`) for a high-risk class `kind`.
    ///
    /// `kind` is the value returned by [`Registry::high_risk`]. Returns `None` if no class in
    /// the policy declares that kind, so callers can fall back to their natural decision.
    pub fn decision_for_kind<'p>(policy: &'p Policy, kind: &str) -> Option<&'p str> {
        policy
            .catalog
            .high_risk_classes
            .iter()
            .find(|class| class.kind == kind)
            .map(|class: &HighRiskClass| class.decision.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A representative subset of the real `.claude/skills/skill-registry.json` from
    /// solanabr/solana-ai-kit: the canonical object form plus the two load-bearing high-risk
    /// reals (`phantom-mcp`, `x402-proxy-mcp`) and two ordinary clean skills (one of which,
    /// `anthropic-skills`, carries a benign "curl references …" note that must NOT match the
    /// `installer_script` keywords).
    const FIXTURE: &str = r#"{
  "version": "1.0",
  "updated": "2026-06-15",
  "entries": [
    {
      "id": "anthropic-skills",
      "name": "Anthropic Skills",
      "type": "skill",
      "domain": "productivity",
      "description": "Anthropic's official skill collection.",
      "source": "https://github.com/anthropics/skills",
      "default_installed": false,
      "safety": "clean (curl references are Claude-API doc examples, not installers); doc set is source-available",
      "tags": ["official"]
    },
    {
      "id": "ux-writing-skill",
      "name": "UX Writing Skill",
      "type": "skill",
      "domain": "ux-writing",
      "description": "Systematic UX microcopy.",
      "source": "https://github.com/content-designer/ux-writing-skill",
      "default_installed": false,
      "safety": "clean (one build-skill.sh builder, not runtime)",
      "tags": ["ux-writing", "microcopy"]
    },
    {
      "id": "x402-proxy-mcp",
      "name": "x402 Proxy MCP",
      "type": "mcp",
      "domain": "solana-infra",
      "description": "Agent-payments proxy MCP (x402).",
      "source": "https://www.npmjs.com/package/x402-proxy",
      "default_installed": false,
      "safety": "caution: BIP-39 key custody for agent payments — isolate keys, explicit opt-in only, never a default",
      "tags": ["x402", "payments", "mcp", "key-custody", "solana"]
    },
    {
      "id": "phantom-mcp",
      "name": "Phantom MCP",
      "type": "mcp",
      "domain": "solana-infra",
      "description": "Phantom wallet MCP — can sign/submit transactions.",
      "source": "https://www.npmjs.com/package/@phantom/mcp-server",
      "default_installed": false,
      "safety": "caution: wallet signing — can sign/submit transactions; explicit user consent only, never a default (key-custody risk)",
      "tags": ["phantom", "wallet", "signing", "mcp", "solana"]
    }
  ]
}"#;

    fn policy() -> Policy {
        // fail_closed() carries the built-in CatalogPolicy::default() high_risk_classes.
        Policy::fail_closed()
    }

    #[test]
    fn parse_real_catalog_subset_counts_and_maps_fields() {
        let registry = parse(FIXTURE).unwrap();
        assert_eq!(registry.entries.len(), 4);

        // name → title, type → category mapping.
        let phantom = registry.entry_by_id("phantom-mcp").unwrap();
        assert_eq!(phantom.title, "Phantom MCP");
        assert_eq!(phantom.category, "mcp");
        assert!(phantom
            .safety
            .as_deref()
            .unwrap()
            .contains("wallet signing"));

        let x402 = registry.entry_by_id("x402-proxy-mcp").unwrap();
        assert_eq!(x402.title, "x402 Proxy MCP");
        assert!(x402.tags.iter().any(|t| t == "key-custody"));
    }

    #[test]
    fn parse_tolerates_unknown_and_missing_fields() {
        let json = r#"{
            "version": 9,
            "wat": "an unknown top-level field",
            "entries": [
                { "id": "minimal", "extra": "ignored" }
            ]
        }"#;
        let registry = parse(json).unwrap();
        assert_eq!(registry.entries.len(), 1);
        let entry = &registry.entries[0];
        assert_eq!(entry.id, "minimal");
        assert_eq!(entry.title, "");
        assert!(entry.safety.is_none());
        assert!(entry.tags.is_empty());
    }

    #[test]
    fn parse_accepts_bare_top_level_array() {
        let json = r#"[ { "id": "a", "name": "A", "type": "skill" } ]"#;
        let registry = parse(json).unwrap();
        assert_eq!(registry.entries.len(), 1);
        assert_eq!(registry.entries[0].title, "A");
    }

    #[test]
    fn parse_accepts_skills_key_alias() {
        let json = r#"{ "skills": [ { "id": "b", "name": "B" } ] }"#;
        let registry = parse(json).unwrap();
        assert_eq!(registry.entries.len(), 1);
        assert_eq!(registry.entries[0].id, "b");
    }

    #[test]
    fn parse_empty_body_is_empty_catalog() {
        assert!(parse("").unwrap().entries.is_empty());
        assert!(parse("   \n").unwrap().entries.is_empty());
    }

    #[test]
    fn parse_malformed_json_is_err_not_panic() {
        assert!(matches!(parse("{ not json"), Err(Error::Parse(_))));
        assert!(matches!(parse("{ \"entries\": "), Err(Error::Parse(_))));
    }

    #[test]
    fn load_missing_file_is_empty_catalog() {
        let path = Path::new("/nonexistent/safe-solana-ai/skill-registry.json");
        let registry = Registry::load(path).unwrap();
        assert!(registry.entries.is_empty());
    }

    #[test]
    fn load_reads_and_parses_a_real_file() {
        let dir = std::env::temp_dir().join("ssai_registry_load_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("skill-registry.json");
        std::fs::write(&path, FIXTURE).unwrap();

        let registry = Registry::load(&path).unwrap();
        assert_eq!(registry.entries.len(), 4);
        assert!(registry.entry_by_id("phantom-mcp").is_some());

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn high_risk_matches_phantom_by_id() {
        let policy = policy();
        let registry = parse(FIXTURE).unwrap();
        let phantom = registry.entry_by_id("phantom-mcp").unwrap();
        assert_eq!(
            Registry::high_risk(phantom, &policy),
            Some("wallet_signing".to_string())
        );
    }

    #[test]
    fn high_risk_matches_x402_by_id() {
        let policy = policy();
        let registry = parse(FIXTURE).unwrap();
        let x402 = registry.entry_by_id("x402-proxy-mcp").unwrap();
        assert_eq!(
            Registry::high_risk(x402, &policy),
            Some("key_custody".to_string())
        );
    }

    #[test]
    fn high_risk_matches_by_keyword_when_id_absent() {
        let policy = policy();

        // No id match (renamed), but the "wallet signing" / "signing" keyword still classifies.
        let wallet = RegistryEntry {
            id: "some-other-wallet-mcp".into(),
            title: "Some Wallet".into(),
            category: "mcp".into(),
            safety: Some("can do wallet signing of transactions".into()),
            ..Default::default()
        };
        assert_eq!(
            Registry::high_risk(&wallet, &policy),
            Some("wallet_signing".to_string())
        );

        // No id match, but "bip-39" keyword (case-insensitive, here in description) classifies.
        let custody = RegistryEntry {
            id: "unknown-payments-mcp".into(),
            description: Some("Holds a BIP-39 seed phrase for agent payments".into()),
            ..Default::default()
        };
        assert_eq!(
            Registry::high_risk(&custody, &policy),
            Some("key_custody".to_string())
        );

        // installer_script class has no ids; keyword "curl | bash" classifies.
        let installer = RegistryEntry {
            id: "sketchy-installer".into(),
            safety: Some("runs curl | bash from its postinstall step".into()),
            ..Default::default()
        };
        assert_eq!(
            Registry::high_risk(&installer, &policy),
            Some("installer_script".to_string())
        );
    }

    #[test]
    fn high_risk_none_for_ordinary_entries() {
        let policy = policy();
        let registry = parse(FIXTURE).unwrap();

        let ux = registry.entry_by_id("ux-writing-skill").unwrap();
        assert_eq!(Registry::high_risk(ux, &policy), None);

        // anthropic-skills mentions "curl references" but must NOT match installer_script,
        // whose keywords are the precise "curl | bash" / "| sh" / "wget" forms.
        let anthropic = registry.entry_by_id("anthropic-skills").unwrap();
        assert_eq!(Registry::high_risk(anthropic, &policy), None);
    }

    #[test]
    fn is_opt_in_reflects_default_installed() {
        let opt_in = RegistryEntry {
            default_installed: false,
            ..Default::default()
        };
        assert!(opt_in.is_opt_in());

        let bundled = RegistryEntry {
            default_installed: true,
            ..Default::default()
        };
        assert!(!bundled.is_opt_in());
    }

    #[test]
    fn decision_for_kind_resolves_forced_decision() {
        let policy = policy();
        assert_eq!(
            Registry::decision_for_kind(&policy, "wallet_signing"),
            Some("ask")
        );
        assert_eq!(
            Registry::decision_for_kind(&policy, "key_custody"),
            Some("ask")
        );
        assert_eq!(Registry::decision_for_kind(&policy, "no_such_kind"), None);
    }
}
