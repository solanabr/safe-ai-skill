//! Tiers (D8 v2, firewall split spec §1): the strictness the user picked, as an input.
//!
//! `off < relaxed < medium < high`; `relaxed` is the default. **Off is not DISABLE**: every
//! deny row of spec §2 holds at Off, and `SAFE_AI_SKILL_DISABLE=1` stays the only no-guards
//! switch. The old profile names are input aliases (`strict`/`autopilot` → relaxed,
//! `paranoid` → high).
//!
//! ## Resolution ([`resolve`], spec §1.2), per hook, for the project root of the payload cwd
//!
//! 1. `base`: the plugin default policy's `tier` (`relaxed`).
//! 2. `user`: the authenticated `tier.json` in a trusted data dir ([`crate::tierstate`]):
//!    `projects[root]`, else `global`, else `base`. The only channel that can select a tier
//!    below the floors or below `base`, and only through a whole-prompt nonce confirmation.
//! 3. Raise-only hints: the kit's `.claude/security.json` (max of `tier`, `declared.tier`,
//!    `enforced.tier`), the repo `.safe-ai-skill/policy.yaml` `tier` (or legacy
//!    `active_profile`), and the env `SAFE_AI_SKILL_TIER` / `SAFE_AI_SKILL_PROFILE`.
//!    `effective = max(user, hints…)`; a hint below the user value is ignored with a note.
//!
//! `env_read` resolves the same way: the user value from `tier.json` (loosened back to `tier`
//! only through a confirmation), else the base policy's; a repo value may only tighten it.
//!
//! Notes reach the model at SessionStart, so they echo only known words, never file text.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::datadir::DataDir;
use crate::sandbox::SandboxState;
use crate::tierstate::{self, UserStatus};

/// Env var naming a tier; it may only raise the effective tier.
pub const TIER_ENV: &str = "SAFE_AI_SKILL_TIER";

/// Legacy env var naming a profile; read as a tier alias, raise-only like [`TIER_ENV`].
pub const PROFILE_ENV: &str = "SAFE_AI_SKILL_PROFILE";

/// The ai-kit's tier file, relative to the project root.
pub const KIT_SECURITY: &str = ".claude/security.json";

/// Largest kit `security.json` read; a bigger one is ignored with a note.
pub const MAX_KIT_SECURITY_BYTES: u64 = 256 * 1024;

/// Firewall strictness, ordered `Off < Relaxed < Medium < High`.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// Every deny row still holds; asks and grants as at Relaxed; no exfil host list.
    Off,
    /// The default.
    #[default]
    Relaxed,
    /// Relaxed plus project env write denies.
    Medium,
    /// A repo you distrust: never `allow`, Class C denied, HIGH packs denied until trusted,
    /// project env reads denied.
    High,
}

impl Tier {
    /// Every tier, loosest first.
    pub const ALL: [Tier; 4] = [Tier::Off, Tier::Relaxed, Tier::Medium, Tier::High];

    /// The canonical lowercase name.
    pub fn label(self) -> &'static str {
        match self {
            Tier::Off => "off",
            Tier::Relaxed => "relaxed",
            Tier::Medium => "medium",
            Tier::High => "high",
        }
    }

    /// Parse a tier name or a legacy profile alias (`strict`/`autopilot` → relaxed,
    /// `paranoid` → high). Surrounding whitespace and ASCII case are ignored; anything else is
    /// `None`.
    pub fn parse(word: &str) -> Option<Tier> {
        match word.trim().to_ascii_lowercase().as_str() {
            "off" => Some(Tier::Off),
            "relaxed" | "strict" | "autopilot" => Some(Tier::Relaxed),
            "medium" => Some(Tier::Medium),
            "high" | "paranoid" => Some(Tier::High),
            _ => None,
        }
    }

    /// Whether `word` is a legacy profile name rather than a tier name.
    pub fn is_alias(word: &str) -> bool {
        matches!(
            word.trim().to_ascii_lowercase().as_str(),
            "strict" | "autopilot" | "paranoid"
        )
    }

    /// The label shown at SessionStart and in `status`: `relaxed (hooks only)` when the Claude
    /// Code sandbox is not on (spec §1.4).
    pub fn display(self, sandbox: SandboxState) -> String {
        if sandbox == SandboxState::On {
            self.label().to_string()
        } else {
            format!("{} (hooks only)", self.label())
        }
    }
}

/// Where the effective tier came from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TierSource {
    /// The plugin default policy.
    #[default]
    Base,
    /// `tier.json` `global`.
    UserGlobal,
    /// `tier.json` `projects[root]`.
    UserProject,
    /// The kit's `.claude/security.json` (raise-only).
    KitSecurityJson,
    /// The repo's `.safe-ai-skill/policy.yaml` (raise-only).
    RepoPolicy,
    /// `SAFE_AI_SKILL_TIER` / `SAFE_AI_SKILL_PROFILE` (raise-only).
    Env,
    /// `tier.json` was deleted after a tier was set: High until the user sets one again.
    StateDeleted,
    /// `tier.json` failed authentication: High until the user sets a tier again.
    StateTampered,
}

impl TierSource {
    /// A short human label.
    pub fn label(self) -> &'static str {
        match self {
            TierSource::Base => "default",
            TierSource::UserGlobal => "your setting",
            TierSource::UserProject => "your project setting",
            TierSource::KitSecurityJson => "kit .claude/security.json",
            TierSource::RepoPolicy => "repo .safe-ai-skill/policy.yaml",
            TierSource::Env => "env",
            TierSource::StateDeleted => "tier.json deleted",
            TierSource::StateTampered => "tier.json failed authentication",
        }
    }
}

/// Raw reads of project env files (`secrets.env_read`), ordered by looseness: `Deny < Tier`.
///
/// `tier` (the default) lets the tier decide: open at Off, Relaxed and Medium, denied at High.
/// `deny` is a tightening the user (or a repo) may choose: denied at every tier. The 1.1.0
/// loosening values `ask` and the sandbox-conditioned `tier` were retired in 1.2.0; a stored
/// `ask` reads as `tier` and is removed at the next SessionStart ([`crate::migrate`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EnvRead {
    /// Raw reads denied at every tier; served by `safe-ai-skill env`.
    Deny,
    /// Raw reads follow the tier (the default).
    #[default]
    Tier,
}

impl<'de> Deserialize<'de> for EnvRead {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let word = String::deserialize(d)?;
        EnvRead::parse(&word)
            .or_else(|| EnvRead::is_retired(&word).then_some(EnvRead::Tier))
            .ok_or_else(|| serde::de::Error::custom("expected deny|tier"))
    }
}

impl EnvRead {
    /// The policy word.
    pub fn label(self) -> &'static str {
        match self {
            EnvRead::Deny => "deny",
            EnvRead::Tier => "tier",
        }
    }

    /// Parse a policy word (`deny|tier`, ASCII case and whitespace ignored).
    pub fn parse(word: &str) -> Option<EnvRead> {
        match word.trim().to_ascii_lowercase().as_str() {
            "deny" => Some(EnvRead::Deny),
            "tier" => Some(EnvRead::Tier),
            _ => None,
        }
    }

    /// Whether `word` is the retired 1.1.0 value `ask` (stored values still load, as `tier`).
    pub fn is_retired(word: &str) -> bool {
        word.trim().eq_ignore_ascii_case("ask")
    }
}

/// A raise-only tier hint as read from a file field: `tier` is `None` when the value is not a
/// tier name (the note then says so without echoing it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawHint {
    /// The field that held it (`tier`, `active_profile`, …).
    pub field: &'static str,
    /// The parsed tier.
    pub tier: Option<Tier>,
}

/// What gates see of the tier: carried by the effective [`crate::policy::Policy`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TierContext {
    /// The effective tier.
    pub tier: Tier,
    /// Where it came from.
    pub source: TierSource,
    /// The effective `env_read`.
    pub env_read: EnvRead,
    /// Declared Claude Code sandbox state for the project.
    pub sandbox: SandboxState,
    /// Whether the session is headless (contract §3.3).
    pub headless: bool,
}

/// The outcome of [`resolve`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    /// The effective tier.
    pub tier: Tier,
    /// Where it came from.
    pub source: TierSource,
    /// The user-scope value (or the base when there is none).
    pub user: Tier,
    /// Where the user-scope value came from (`Base` when there is none).
    pub user_source: TierSource,
    /// The effective `env_read`.
    pub env_read: EnvRead,
    /// Ignored hints and state warnings, one line each.
    pub notes: Vec<String>,
}

/// The project root for a payload `cwd`: the nearest ancestor of its canonical path holding a
/// `.git` entry (the git toplevel), else the canonical `cwd`. No git is run.
pub fn project_root(cwd: &Path) -> PathBuf {
    let base = std::fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    base.ancestors()
        .find(|dir| std::fs::symlink_metadata(dir.join(".git")).is_ok())
        .map(Path::to_path_buf)
        .unwrap_or(base)
}

/// The inputs of [`resolve_from`], gathered from files and the environment by [`resolve`].
#[derive(Debug, Clone)]
pub struct Inputs {
    /// The plugin default policy's tier.
    pub base: Tier,
    /// The plugin default policy's `env_read` (after the repo ratchet).
    pub base_env_read: EnvRead,
    /// The user-scope choice from `tier.json`.
    pub user: tierstate::UserChoice,
    /// The kit `security.json` hints, or `Err(note)` when it could not be used.
    pub kit: Result<Vec<RawHint>, String>,
    /// The repo `policy.yaml` hints.
    pub repo: Vec<RawHint>,
    /// The repo's own `secrets.env_read`, when it sets a known word (raise-only).
    pub repo_env_read: Option<EnvRead>,
    /// The env hints.
    pub env: Vec<RawHint>,
}

/// Resolve the effective tier and `env_read` for the project at `root` (spec §1.2).
///
/// `base`, `base_env_read`, the repo hints and the repo `env_read` come from the loaded
/// policy (`policy`); `env` looks up an environment variable.
pub fn resolve(
    root: &Path,
    dir: &DataDir,
    policy: &crate::policy::Policy,
    env: &dyn Fn(&str) -> Option<String>,
) -> Resolution {
    resolve_from(Inputs {
        base: policy.base_tier,
        base_env_read: EnvRead::parse(&policy.secrets.env_read).unwrap_or_default(),
        user: tierstate::user_choice(dir, root),
        kit: kit_hints(root),
        repo: policy.repo_tier_hints.clone(),
        repo_env_read: policy.repo_env_read,
        env: env_hints(env),
    })
}

impl Default for Inputs {
    fn default() -> Self {
        Inputs {
            base: Tier::Relaxed,
            base_env_read: EnvRead::Tier,
            user: tierstate::UserChoice::default(),
            kit: Ok(Vec::new()),
            repo: Vec::new(),
            repo_env_read: None,
            env: Vec::new(),
        }
    }
}

/// [`resolve`] over gathered inputs (pure).
pub fn resolve_from(inputs: Inputs) -> Resolution {
    let mut notes = Vec::new();
    match inputs.user.status {
        UserStatus::Tampered => notes.push(
            "tier.json failed authentication (MAC mismatch, rolled back, or the state key is \
             missing); tier high applies until you choose a tier again with \
             `safe-ai-skill tier <off|relaxed|medium|high>`"
                .to_string(),
        ),
        UserStatus::Untrusted => notes.push(
            "user tier ignored: data dir untrusted (tier.json is not under \
             ~/.claude/plugins/data, or that dir is inside the project)"
                .to_string(),
        ),
        UserStatus::Deleted => notes.push(
            "tier.json was deleted after a tier was set; tier high applies until you choose a \
             tier again with `safe-ai-skill tier <off|relaxed|medium|high>`"
                .to_string(),
        ),
        UserStatus::Valid | UserStatus::Missing => {}
    }
    let (user, user_source) = inputs.user.tier.unwrap_or((inputs.base, TierSource::Base));

    let mut hints: Vec<(TierSource, &'static str, Tier)> = Vec::new();
    let mut collect = |source: TierSource, list: &[RawHint], notes: &mut Vec<String>| {
        for h in list {
            match h.tier {
                Some(t) => hints.push((source, h.field, t)),
                None => notes.push(format!(
                    "{} `{}` is not a tier name; ignored",
                    source.label(),
                    h.field
                )),
            }
        }
    };
    match &inputs.kit {
        Ok(list) => collect(TierSource::KitSecurityJson, list, &mut notes),
        Err(note) => notes.push(note.clone()),
    }
    collect(TierSource::RepoPolicy, &inputs.repo, &mut notes);
    collect(TierSource::Env, &inputs.env, &mut notes);

    let (mut tier, mut source) = (user, user_source);
    for &(hint_source, _, t) in &hints {
        if t > tier {
            tier = t;
            source = hint_source;
        }
    }
    for &(hint_source, field, t) in &hints {
        if t < user {
            notes.push(format!(
                "{} `{field}: {}` ignored: it is below {} ({}); repo, kit and env settings may \
                 only raise the tier",
                hint_source.label(),
                t.label(),
                user.label(),
                user_source.label()
            ));
        }
    }
    if tier > user && user_source != TierSource::Base {
        notes.push(format!(
            "tier {} applies: {} sets a floor above {} ({}); change the floor to go lower",
            tier.label(),
            source.label(),
            user.label(),
            user_source.label()
        ));
    }

    let mut env_read = inputs.user.env_read.unwrap_or(inputs.base_env_read);
    if let Some(repo) = inputs.repo_env_read {
        env_read = env_read.min(repo);
    }

    Resolution {
        tier,
        source,
        user,
        user_source,
        env_read,
        notes,
    }
}

/// The env hints: [`TIER_ENV`] and [`PROFILE_ENV`], when set and non-blank.
pub fn env_hints(env: &dyn Fn(&str) -> Option<String>) -> Vec<RawHint> {
    [(TIER_ENV, TIER_ENV), (PROFILE_ENV, PROFILE_ENV)]
        .into_iter()
        .filter_map(|(var, field)| {
            let value = env(var)?;
            let value = value.trim();
            (!value.is_empty()).then(|| RawHint {
                field,
                tier: Tier::parse(value),
            })
        })
        .collect()
}

/// The kit `security.json` hints (`tier`, `declared.tier`, `enforced.tier`), or the note for
/// a file that exists but cannot be used. A missing file is `Ok(empty)`.
pub fn kit_hints(root: &Path) -> Result<Vec<RawHint>, String> {
    let path = root.join(KIT_SECURITY);
    let Ok(meta) = std::fs::metadata(&path) else {
        return Ok(Vec::new());
    };
    let unusable = || {
        format!(
            "{} is not a regular JSON file of at most 256 KiB; ignored",
            TierSource::KitSecurityJson.label()
        )
    };
    if !meta.is_file() {
        return Err(unusable());
    }
    let text = read_bounded(&path, MAX_KIT_SECURITY_BYTES).ok_or_else(unusable)?;
    kit_hints_from(&text).ok_or_else(unusable)
}

/// The UTF-8 text of `path` when it is at most `max` bytes, read with a bound (the file may
/// grow after a size check); `None` otherwise.
pub(crate) fn read_bounded(path: &Path, max: u64) -> Option<String> {
    use std::io::Read;
    let file = std::fs::File::open(path).ok()?;
    let mut text = String::new();
    file.take(max.saturating_add(1))
        .read_to_string(&mut text)
        .ok()?;
    (u64::try_from(text.len()).ok()? <= max).then_some(text)
}

/// The hints in a kit `security.json` body; `None` when it is not a JSON object.
pub fn kit_hints_from(text: &str) -> Option<Vec<RawHint>> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let obj = value.as_object()?;
    let fields: [(&'static str, Option<&serde_json::Value>); 3] = [
        ("tier", obj.get("tier")),
        (
            "declared.tier",
            obj.get("declared").and_then(|d| d.get("tier")),
        ),
        (
            "enforced.tier",
            obj.get("enforced").and_then(|e| e.get("tier")),
        ),
    ];
    Some(
        fields
            .into_iter()
            .filter_map(|(field, v)| {
                let v = v.filter(|v| !v.is_null())?;
                Some(RawHint {
                    field,
                    tier: v.as_str().and_then(Tier::parse),
                })
            })
            .collect(),
    )
}

/// The shipped per-gate table (Off / Relaxed / Medium / High), the single source the README
/// tier table is checked against (`tests/readme_tier_table.rs`). The exfil host-list tripwire
/// is deferred (#19) and has no row.
pub const GATE_TABLE: &[(&str, [&str; 4])] = &[
    (
        "Key material + home credential stores, path or command-form read",
        ["deny", "deny", "deny", "deny"],
    ),
    (
        "Key material to a network-capable command",
        ["deny", "deny", "deny", "deny"],
    ),
    (
        "Project .env / .env.* raw read (Read, Grep, Bash readers, MCP code), default env_read: tier",
        ["n/o", "n/o", "n/o", "deny"],
    ),
    (
        "Project .env / .env.* raw read, user-scope env_read: deny",
        ["deny", "deny", "deny", "deny"],
    ),
    (
        "Other env files raw read (.envrc, *.env, .dev.vars, Solana CLI config, env files outside the project)",
        ["deny", "deny", "deny", "deny"],
    ),
    (
        "varlock value printers",
        ["= raw read", "= raw read", "= raw read", "= raw read"],
    ),
    (
        ".env.schema, templates (content guard applies)",
        ["n/o", "n/o", "n/o", "n/o"],
    ),
    (
        "Write/Edit/MultiEdit, Bash write or agent env set|unset to project .env / .env.*",
        ["n/o", "n/o", "deny", "n/o"],
    ),
    (
        "Write/Edit/MultiEdit or Bash write to other env files",
        ["n/o", "n/o", "deny", "deny"],
    ),
    ("env keys", ["n/o", "n/o", "n/o", "n/o"]),
    ("Pattern redaction", ["on", "on", "on", "on"]),
    (
        "Value scrub, except the Read response of a raw env read the tier permits",
        ["on", "on", "on", "on"],
    ),
    (
        "Class U, mainnet, Unknown, or any cluster not positively identified as localnet/devnet",
        ["deny", "deny", "deny", "deny"],
    ),
    (
        "Class U, positively identified localnet/devnet",
        ["ask", "ask", "ask", "ask"],
    ),
    (
        "Default-wallet destruction",
        ["deny", "deny", "deny", "deny"],
    ),
    (
        "Class C on mainnet or Unknown",
        ["ask", "ask", "ask", "deny"],
    ),
    (
        "Class C on mainnet or Unknown with a live confirmed grant covering it",
        ["allow", "allow", "allow", "deny"],
    ),
    (
        "Class C on identified test cluster: deploy/upgrade",
        ["n/o", "n/o", "n/o", "n/o"],
    ),
    (
        "Class C on identified test cluster: transfer within spend caps",
        ["allow", "allow", "allow", "n/o"],
    ),
    (
        "Class C on identified test cluster: authority change",
        ["ask", "ask", "ask", "ask"],
    ),
    (
        "Unparseable/opaque/dynamic Solana-family command",
        ["ask", "ask", "ask", "deny"],
    ),
    (
        "MCP value-moving or signing tool",
        ["ask", "ask", "ask", "deny"],
    ),
    (
        "Project env file and a network command in one command line",
        ["deny", "deny", "deny", "deny"],
    ),
    (
        "Inline curl/wget POST body to a known Solana RPC host",
        ["n/o", "n/o", "n/o", "ask"],
    ),
    (
        "Inline curl/wget POST body to any other non-localhost host; any file-body upload",
        ["ask", "ask", "ask", "ask"],
    ),
    (
        "Supply chain: combo, drift, lock_mismatch, unscanned",
        ["report", "deny in place", "deny in place", "deny in place"],
    ),
    (
        "Supply chain: HIGH heuristic (unreviewed)",
        ["report", "report", "report", "deny in place"],
    ),
    (
        "Tamper tripwire, authenticated state, prompt guard",
        ["on", "on", "on", "on"],
    ),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tierstate::UserChoice;

    fn hint(field: &'static str, tier: Option<Tier>) -> RawHint {
        RawHint { field, tier }
    }

    fn inputs() -> Inputs {
        Inputs::default()
    }

    #[test]
    fn order_names_and_aliases() {
        assert!(Tier::Off < Tier::Relaxed && Tier::Relaxed < Tier::Medium);
        assert!(Tier::Medium < Tier::High);
        assert_eq!(Tier::default(), Tier::Relaxed);
        for (word, tier) in [
            ("off", Tier::Off),
            ("relaxed", Tier::Relaxed),
            ("medium", Tier::Medium),
            ("high", Tier::High),
            ("strict", Tier::Relaxed),
            ("autopilot", Tier::Relaxed),
            ("paranoid", Tier::High),
            (" HIGH ", Tier::High),
        ] {
            assert_eq!(Tier::parse(word), Some(tier), "{word}");
        }
        for bad in ["", "disable", "low", "max", "of f"] {
            assert_eq!(Tier::parse(bad), None, "{bad:?}");
        }
        assert!(Tier::is_alias("paranoid") && !Tier::is_alias("high"));
        assert_eq!(serde_json::to_string(&Tier::Medium).unwrap(), "\"medium\"");
        assert!(serde_json::from_str::<Tier>("\"paranoid\"").is_err());
    }

    #[test]
    fn env_read_is_ordered_by_looseness() {
        assert!(EnvRead::Deny < EnvRead::Tier);
        assert_eq!(EnvRead::default(), EnvRead::Tier);
        assert_eq!(EnvRead::parse("TIER"), Some(EnvRead::Tier));
        assert_eq!(EnvRead::parse("allow"), None);
        assert_eq!(EnvRead::parse("ask"), None);
    }

    #[test]
    fn a_stored_retired_ask_loads_as_tier() {
        let e: EnvRead = serde_json::from_str("\"ask\"").unwrap();
        assert_eq!(e, EnvRead::Tier);
        assert_eq!(serde_json::to_string(&e).unwrap(), "\"tier\"");
        assert!(serde_json::from_str::<EnvRead>("\"allow\"").is_err());
    }

    #[test]
    fn hooks_only_label_when_the_sandbox_is_not_on() {
        assert_eq!(Tier::Relaxed.display(SandboxState::On), "relaxed");
        assert_eq!(
            Tier::Relaxed.display(SandboxState::Off),
            "relaxed (hooks only)"
        );
        assert_eq!(
            Tier::High.display(SandboxState::Unknown),
            "high (hooks only)"
        );
    }

    #[test]
    fn hints_only_raise_and_lowerings_are_noted() {
        let mut i = inputs();
        i.kit = Ok(vec![hint("tier", Some(Tier::Off))]);
        i.env = vec![hint(TIER_ENV, Some(Tier::Medium))];
        let r = resolve_from(i);
        assert_eq!((r.tier, r.source), (Tier::Medium, TierSource::Env));
        assert!(
            r.notes
                .iter()
                .any(|n| n.contains("kit") && n.contains("off")),
            "{:?}",
            r.notes
        );
        assert!(
            !r.notes.iter().any(|n| n.contains("env `")),
            "{:?}",
            r.notes
        );
    }

    #[test]
    fn a_floor_above_the_users_choice_wins_and_is_named() {
        let mut i = inputs();
        i.user = UserChoice {
            tier: Some((Tier::Off, TierSource::UserProject)),
            env_read: None,
            status: UserStatus::Valid,
        };
        i.kit = Ok(vec![hint("tier", Some(Tier::High))]);
        let r = resolve_from(i);
        assert_eq!(
            (r.tier, r.source),
            (Tier::High, TierSource::KitSecurityJson)
        );
        assert_eq!(r.user, Tier::Off);
        assert!(
            r.notes
                .iter()
                .any(|n| n.contains("floor") && n.contains("kit")),
            "{:?}",
            r.notes
        );
    }

    #[test]
    fn unknown_hint_words_are_noted_without_echo() {
        let mut i = inputs();
        i.repo = vec![hint("tier", None)];
        let r = resolve_from(i);
        assert_eq!(r.tier, Tier::Relaxed);
        assert_eq!(r.notes.len(), 1);
        assert!(r.notes[0].contains("not a tier name"));
    }

    #[test]
    fn env_read_user_value_then_repo_may_only_tighten() {
        let mut i = inputs();
        assert_eq!(resolve_from(i.clone()).env_read, EnvRead::Tier);
        i.user.env_read = Some(EnvRead::Deny);
        assert_eq!(resolve_from(i.clone()).env_read, EnvRead::Deny);
        i.user.env_read = Some(EnvRead::Tier);
        i.repo_env_read = Some(EnvRead::Deny);
        assert_eq!(resolve_from(i.clone()).env_read, EnvRead::Deny);
        i.repo_env_read = Some(EnvRead::Tier);
        i.user.env_read = Some(EnvRead::Deny);
        assert_eq!(resolve_from(i).env_read, EnvRead::Deny);
    }

    #[test]
    fn kit_security_json_takes_the_max_of_its_three_fields() {
        let hints = kit_hints_from(
            r#"{"tier":"relaxed","declared":{"tier":"high"},"enforced":{"tier":"medium"}}"#,
        )
        .unwrap();
        assert_eq!(hints.len(), 3);
        let mut i = inputs();
        i.kit = Ok(hints);
        assert_eq!(resolve_from(i).tier, Tier::High);
        assert!(kit_hints_from("[1,2]").is_none());
        assert!(kit_hints_from("{").is_none());
        assert_eq!(kit_hints_from(r#"{"tier":7}"#).unwrap()[0].tier, None);
    }

    #[test]
    fn project_root_is_the_git_toplevel() {
        let base = std::env::temp_dir().join(format!("tier_root_{}", std::process::id()));
        let sub = base.join("a").join("b");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::create_dir_all(base.join(".git")).unwrap();
        assert_eq!(project_root(&sub), std::fs::canonicalize(&base).unwrap());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn the_gate_table_has_four_tiers_per_row() {
        assert!(GATE_TABLE.len() >= 20);
        assert!(GATE_TABLE
            .iter()
            .all(|(row, cells)| !row.is_empty() && cells.len() == 4));
    }
}
