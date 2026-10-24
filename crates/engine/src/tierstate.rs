//! The user-scope tier file `${DATA}/tier.json` (D8 v2 spec §1.2-§1.3, contract §3.1).
//!
//! One authenticated [`crate::statefile`] envelope whose body is
//! `{v: 1, global?: {tier, env_read?}, projects: {<root>: {tier, env_read?}}}`, keyed by the
//! canonical git toplevel ([`crate::policy::tier::project_root`]). Its only writer is
//! `safe-ai-skill tier` (the deprecated `mode` is an alias): raising the tier or tightening
//! `env_read` to `deny` applies at once ([`plan`] → [`Plan::Immediate`]); lowering, or loosening
//! `env_read` back to `tier` (`deny < tier`), is parked as a [`crate::confirm::PendingKind::Tier`]
//! entry and applied by [`apply`] only after the user's whole-prompt confirmation.
//!
//! Gates read it through [`user_choice`]: nothing unless the file authenticates and the data
//! dir is trusted, so a forged, replayed or misplaced file selects nothing (the base tier).

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::datadir::DataDir;
use crate::error::{EngineError, Error};
use crate::policy::tier::{EnvRead, Tier, TierSource};
use crate::statefile::{self, FileLock, Loaded};

/// State file holding the user's tier choices.
pub const TIER_FILE: &str = "tier.json";

/// The base tier changes are planned against: fixed at compile time (spec §1.2 `base =
/// relaxed`), never read from a policy file an environment variable can point elsewhere.
pub const BASE: Tier = Tier::Relaxed;

/// Lock guarding the read-modify-write of [`TIER_FILE`].
pub const LOCK_FILE: &str = "tier.lock";

fn one() -> u32 {
    1
}

/// The `tier.json` body.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TierFile {
    /// Body format version.
    #[serde(default = "one")]
    pub v: u32,
    /// The choice for every project without its own entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub global: Option<Entry>,
    /// Per-project choices, keyed by canonical project root.
    #[serde(default)]
    pub projects: BTreeMap<String, Entry>,
}

impl Default for TierFile {
    fn default() -> Self {
        TierFile {
            v: 1,
            global: None,
            projects: BTreeMap::new(),
        }
    }
}

/// One choice.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    /// The tier.
    pub tier: Tier,
    /// Raw project env reads, when chosen (`deny`; a retired 1.1.0 `ask` loads as `tier`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_read: Option<EnvRead>,
    /// When it was set (epoch seconds; informational).
    #[serde(default)]
    pub set_at: u64,
}

/// Whether `tier.json` can be used.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum UserStatus {
    /// It authenticates in a trusted data dir.
    Valid,
    /// There is none.
    #[default]
    Missing,
    /// It failed authentication (bad MAC or envelope, rolled-back generation, missing state
    /// key) in a trusted data dir. Tier High applies until the user sets a tier again.
    Tampered,
    /// It exists, but the data dir is not trusted.
    Untrusted,
    /// It is missing although it was stored before ([`statefile::was_stored`]): deleted.
    /// Tier High applies until the user sets a tier again.
    Deleted,
}

/// The user-scope choice for one project.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserChoice {
    /// The tier and whether it came from the project entry or `global`.
    pub tier: Option<(Tier, TierSource)>,
    /// `env_read` from the project entry, else `global`.
    pub env_read: Option<EnvRead>,
    /// Whether the file could be used.
    pub status: UserStatus,
}

/// The key of a project root in [`TierFile::projects`].
pub fn root_key(root: &Path) -> String {
    root.to_string_lossy().into_owned()
}

/// Load and authenticate `tier.json`.
pub fn load(dir: &DataDir) -> Loaded<TierFile> {
    statefile::load(dir, TIER_FILE)
}

/// The usable file: `Some` only when it authenticates in a trusted data dir.
fn usable(dir: &DataDir) -> (Option<TierFile>, UserStatus) {
    match load(dir) {
        Loaded::Valid(f) if dir.trusted => (Some(f), UserStatus::Valid),
        Loaded::Valid(_) => (None, UserStatus::Untrusted),
        Loaded::Tampered if !dir.trusted => (None, UserStatus::Untrusted),
        Loaded::Tampered => (None, UserStatus::Tampered),
        Loaded::Missing if deleted(dir) => (None, UserStatus::Deleted),
        Loaded::Missing => (None, UserStatus::Missing),
    }
}

/// Whether `tier.json` is missing from a trusted data dir although it was stored before.
pub fn deleted(dir: &DataDir) -> bool {
    dir.trusted && matches!(load(dir), Loaded::Missing) && statefile::was_stored(dir, TIER_FILE)
}

/// The tier a deleted or tampered `tier.json` fails closed to.
const FAIL_CLOSED_TIER: Tier = Tier::High;

/// Whether `tier.json` in a trusted data dir was deleted or fails authentication, so tier
/// High applies until the user sets a tier again.
pub fn fails_closed(dir: &DataDir) -> bool {
    dir.trusted && (matches!(load(dir), Loaded::Tampered) || deleted(dir))
}

/// The user-scope choice for the project at `root`: `projects[root]`, else `global`.
pub fn user_choice(dir: &DataDir, root: &Path) -> UserChoice {
    let (file, status) = usable(dir);
    let fail_closed = match status {
        UserStatus::Deleted => Some(TierSource::StateDeleted),
        UserStatus::Tampered => Some(TierSource::StateTampered),
        _ => None,
    };
    if let Some(source) = fail_closed {
        return UserChoice {
            tier: Some((FAIL_CLOSED_TIER.max(BASE), source)),
            env_read: None,
            status,
        };
    }
    let Some(file) = file else {
        return UserChoice {
            status,
            ..UserChoice::default()
        };
    };
    let project = file.projects.get(&root_key(root));
    let tier = project
        .map(|e| (e.tier, TierSource::UserProject))
        .or_else(|| {
            file.global
                .as_ref()
                .map(|e| (e.tier, TierSource::UserGlobal))
        });
    let env_read = project
        .and_then(|e| e.env_read)
        .or_else(|| file.global.as_ref().and_then(|e| e.env_read));
    UserChoice {
        tier,
        env_read,
        status,
    }
}

/// A requested change (`safe-ai-skill tier …`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// `Some(root key)` for `--project`, `None` for the global entry.
    pub project: Option<String>,
    /// The new tier, if one was named.
    pub tier: Option<Tier>,
    /// The new `env_read`, if `--env-read` was given.
    pub env_read: Option<EnvRead>,
    /// `--clear`: remove the entry.
    pub clear: bool,
}

/// What a [`Change`] needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plan {
    /// It changes nothing.
    NoChange,
    /// It only raises or tightens: apply at once.
    Immediate,
    /// It lowers the tier or loosens `env_read`: park it for confirmation.
    NeedsConfirm,
}

/// The `(tier, env_read)` in force for the change's scope before and after it, against
/// [`BASE`] and the stored file whenever it authenticates, trusted or not (so a lowering from a
/// stored value always needs a confirmation; a file that fails authentication counts as absent).
fn before_after(dir: &DataDir, change: &Change) -> ((Tier, EnvRead), (Tier, EnvRead)) {
    let file = match load(dir) {
        Loaded::Valid(f) => f,
        _ => TierFile::default(),
    };
    let global = file.global.as_ref();
    // A deleted or tampered file counts as tier High: lowering from it needs a confirmation.
    let floor = if fails_closed(dir) {
        FAIL_CLOSED_TIER.max(BASE)
    } else {
        BASE
    };
    let global_tier = global.map_or(floor, |e| e.tier);
    let global_env = global.and_then(|e| e.env_read).unwrap_or_default();
    let (current, fallback) = match &change.project {
        Some(key) => {
            let entry = file.projects.get(key);
            let current = (
                entry.map_or(global_tier, |e| e.tier),
                entry.and_then(|e| e.env_read).unwrap_or(global_env),
            );
            (current, (global_tier, global_env))
        }
        None => ((global_tier, global_env), (BASE, EnvRead::Tier)),
    };
    let after = if change.clear {
        fallback
    } else {
        (
            change.tier.unwrap_or(current.0),
            change.env_read.unwrap_or(current.1),
        )
    };
    (current, after)
}

/// Whether `change` applies at once, needs a confirmation, or changes nothing. Clearing an
/// entry above [`BASE`] or with a loosened `env_read` always needs a confirmation.
pub fn plan(dir: &DataDir, change: &Change) -> Plan {
    let (before, after) = before_after(dir, change);
    if (change.clear && clears_a_raise(dir, change)) || after.0 < before.0 || after.1 > before.1 {
        Plan::NeedsConfirm
    } else if after == before && !change.clear && !fails_closed(dir) {
        Plan::NoChange
    } else {
        Plan::Immediate
    }
}

/// Whether the entry `change` clears holds a tier above [`BASE`] or `env_read: deny` (both
/// tighten, so clearing them loosens).
fn clears_a_raise(dir: &DataDir, change: &Change) -> bool {
    let Loaded::Valid(file) = load(dir) else {
        return false;
    };
    let entry = match &change.project {
        Some(key) => file.projects.get(key),
        None => file.global.as_ref(),
    };
    entry.is_some_and(|e| e.tier > BASE || e.env_read == Some(EnvRead::Deny))
}

/// Write `change` into `tier.json`. The caller decided it may apply ([`plan`], or a confirmed
/// pending entry). A file that fails authentication is replaced.
pub fn apply(dir: &DataDir, change: &Change, now: u64) -> Result<(), EngineError> {
    statefile::create_dir_private(&dir.path)?;
    let _lock = FileLock::acquire(&dir.path, LOCK_FILE)?;
    let (_, after) = before_after(dir, change);
    let mut file = match load(dir) {
        Loaded::Valid(f) => f,
        _ => TierFile::default(),
    };
    let slot = match &change.project {
        Some(key) => file.projects.remove(key),
        None => file.global.take(),
    };
    let entry = if change.clear {
        None
    } else {
        Some(Entry {
            tier: after.0,
            env_read: change
                .env_read
                .or_else(|| slot.as_ref().and_then(|e| e.env_read)),
            set_at: now,
        })
    };
    match (&change.project, entry) {
        (Some(key), Some(e)) => {
            file.projects.insert(key.clone(), e);
        }
        (None, Some(e)) => file.global = Some(e),
        (_, None) => {}
    }
    statefile::store(dir, TIER_FILE, &file)
}

/// Whether the stored `tier.json` names the retired 1.1.0 `env_read: ask` anywhere.
fn names_retired_env_read(dir: &DataDir) -> bool {
    let Loaded::Valid(raw) = statefile::load::<Value>(dir, TIER_FILE) else {
        return false;
    };
    let retired = |entry: &Value| {
        entry
            .get("env_read")
            .and_then(Value::as_str)
            .is_some_and(EnvRead::is_retired)
    };
    raw.get("global").is_some_and(retired)
        || raw
            .get("projects")
            .and_then(Value::as_object)
            .is_some_and(|m| m.values().any(retired))
}

/// Rewrite a `tier.json` that names the retired `env_read: ask` (it loads as `tier`, the
/// default, and is stored as `tier`). Nothing else changes. Returns whether it rewrote the
/// file; only an authenticated file in a trusted data dir is touched.
pub fn rewrite_retired_env_read(dir: &DataDir) -> Result<bool, EngineError> {
    if dir.is_unresolved() || !dir.trusted || !names_retired_env_read(dir) {
        return Ok(false);
    }
    let _lock = FileLock::acquire(&dir.path, LOCK_FILE)?;
    let Loaded::Valid(file) = load(dir) else {
        return Ok(false);
    };
    statefile::store(dir, TIER_FILE, &file)?;
    Ok(true)
}

/// A one-line description of `change` for the pending summary and the confirmation echo.
pub fn summary(change: &Change) -> String {
    let scope = match &change.project {
        Some(root) => format!("project {root}"),
        None => "all projects".to_string(),
    };
    if change.clear {
        return format!("clear the tier setting for {scope}");
    }
    let mut parts = Vec::new();
    if let Some(t) = change.tier {
        parts.push(format!("tier {}", t.label()));
    }
    if let Some(e) = change.env_read {
        parts.push(format!("env_read {}", e.label()));
    }
    format!("{} for {scope}", parts.join(", "))
}

/// The pending-entry payload for `change`.
pub fn to_payload(change: &Change) -> Value {
    json!({
        "project": change.project,
        "tier": change.tier.map(Tier::label),
        "env_read": change.env_read.map(EnvRead::label),
        "clear": change.clear,
    })
}

/// Re-validate a confirmed pending payload.
pub fn from_payload(payload: &Value) -> Result<Change, String> {
    let invalid = || "the pending tier change is invalid".to_string();
    let word = |key: &str| -> Result<Option<String>, String> {
        match payload.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(_) => Err(invalid()),
        }
    };
    let project = word("project")?;
    if project
        .as_deref()
        .is_some_and(|p| p.is_empty() || !Path::new(p).is_absolute())
    {
        return Err(invalid());
    }
    let tier = match word("tier")? {
        Some(t) => Some(serde_json::from_value::<Tier>(json!(t)).map_err(|_| invalid())?),
        None => None,
    };
    let env_read = match word("env_read")? {
        Some(e) => Some(serde_json::from_value::<EnvRead>(json!(e)).map_err(|_| invalid())?),
        None => None,
    };
    let clear = payload
        .get("clear")
        .and_then(Value::as_bool)
        .ok_or_else(invalid)?;
    if !clear && tier.is_none() && env_read.is_none() {
        return Err(invalid());
    }
    Ok(Change {
        project,
        tier,
        env_read,
        clear,
    })
}

/// The error for a tier word outside the known names (the word is not echoed).
pub fn unknown_tier() -> EngineError {
    Error::Other(
        "unknown tier; expected off|relaxed|medium|high (aliases: strict, autopilot, paranoid)"
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grants::tests::tmp_data;

    fn global(tier: Option<Tier>, env_read: Option<EnvRead>) -> Change {
        Change {
            project: None,
            tier,
            env_read,
            clear: false,
        }
    }

    /// An absolute project root on this platform (payloads refuse relative ones).
    fn root() -> String {
        if cfg!(windows) {
            r"C:\work\proj"
        } else {
            "/work/proj"
        }
        .to_string()
    }

    #[test]
    fn a_deleted_tier_file_fails_closed_to_high_until_a_tier_is_set() {
        let dir = tmp_data("tierstate_deleted");
        apply(&dir, &global(Some(Tier::Off), None), 1).unwrap();
        std::fs::remove_file(dir.path.join(TIER_FILE)).unwrap();
        let c = user_choice(&dir, Path::new("/x"));
        assert_eq!(c.status, UserStatus::Deleted);
        assert_eq!(c.tier, Some((Tier::High, TierSource::StateDeleted)));
        // Setting a tier again: High re-creates the file at once, lowering needs a confirm.
        assert_eq!(
            plan(&dir, &global(Some(Tier::Relaxed), None)),
            Plan::NeedsConfirm
        );
        assert_eq!(plan(&dir, &global(Some(Tier::High), None)), Plan::Immediate);
        apply(&dir, &global(Some(Tier::High), None), 2).unwrap();
        let c = user_choice(&dir, Path::new("/x"));
        assert_eq!(
            (c.status, c.tier),
            (
                UserStatus::Valid,
                Some((Tier::High, TierSource::UserGlobal))
            )
        );
        // No index although the key exists: deleted as well.
        std::fs::remove_file(dir.path.join(TIER_FILE)).unwrap();
        std::fs::remove_file(dir.path.join(statefile::GEN_INDEX)).unwrap();
        assert_eq!(
            user_choice(&dir, Path::new("/x")).status,
            UserStatus::Deleted
        );
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn a_tier_file_never_stored_is_missing_not_deleted() {
        let dir = tmp_data("tierstate_never");
        assert_eq!(
            user_choice(&dir, Path::new("/x")).status,
            UserStatus::Missing
        );
        // Other state (a grant file) exists: tier.json was still never stored.
        crate::grants::save(&dir, &crate::grants::Grants::default()).unwrap();
        assert_eq!(
            user_choice(&dir, Path::new("/x")).status,
            UserStatus::Missing
        );
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn raising_is_immediate_and_lowering_needs_confirmation() {
        let dir = tmp_data("tierstate_plan");
        assert_eq!(plan(&dir, &global(Some(Tier::High), None)), Plan::Immediate);
        assert_eq!(
            plan(&dir, &global(Some(Tier::Off), None)),
            Plan::NeedsConfirm
        );
        assert_eq!(
            plan(&dir, &global(Some(Tier::Relaxed), None)),
            Plan::NoChange
        );
        assert_eq!(
            plan(&dir, &global(None, Some(EnvRead::Deny))),
            Plan::Immediate
        );
        assert_eq!(
            plan(&dir, &global(None, Some(EnvRead::Tier))),
            Plan::NoChange
        );
        apply(&dir, &global(None, Some(EnvRead::Deny)), 1).unwrap();
        assert_eq!(
            plan(&dir, &global(None, Some(EnvRead::Tier))),
            Plan::NeedsConfirm
        );
        let clear_deny = Change {
            clear: true,
            ..global(None, None)
        };
        assert_eq!(plan(&dir, &clear_deny), Plan::NeedsConfirm);
        apply(&dir, &global(Some(Tier::High), Some(EnvRead::Tier)), 1).unwrap();
        assert_eq!(
            plan(&dir, &global(Some(Tier::Medium), None)),
            Plan::NeedsConfirm
        );
        let clear = Change {
            clear: true,
            ..global(None, None)
        };
        assert_eq!(plan(&dir, &clear), Plan::NeedsConfirm);
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn project_entries_beat_global_and_siblings_get_global() {
        let dir = tmp_data("tierstate_project");
        apply(&dir, &global(Some(Tier::Medium), None), 1).unwrap();
        let project = Change {
            project: Some(root()),
            tier: Some(Tier::High),
            env_read: Some(EnvRead::Deny),
            clear: false,
        };
        apply(&dir, &project, 2).unwrap();
        let c = user_choice(&dir, Path::new(&root()));
        assert_eq!(c.tier, Some((Tier::High, TierSource::UserProject)));
        assert_eq!(c.env_read, Some(EnvRead::Deny));
        let s = user_choice(&dir, Path::new("/work/sibling"));
        assert_eq!(s.tier, Some((Tier::Medium, TierSource::UserGlobal)));
        assert_eq!(s.env_read, None);
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn env_read_only_change_keeps_the_scope_tier() {
        let dir = tmp_data("tierstate_envonly");
        apply(&dir, &global(Some(Tier::Medium), None), 1).unwrap();
        apply(&dir, &global(None, Some(EnvRead::Deny)), 2).unwrap();
        let c = user_choice(&dir, Path::new("/x"));
        assert_eq!(c.tier, Some((Tier::Medium, TierSource::UserGlobal)));
        assert_eq!(c.env_read, Some(EnvRead::Deny));
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn a_retired_ask_is_rewritten_as_tier_once() {
        let dir = tmp_data("tierstate_retired");
        let file = TierFile {
            global: Some(Entry {
                tier: Tier::Medium,
                env_read: None,
                set_at: 1,
            }),
            ..TierFile::default()
        };
        let legacy = json!({
            "v": 1,
            "global": {"tier": "medium", "env_read": "ask", "set_at": 1},
            "projects": {"/p": {"tier": "high", "env_read": "deny", "set_at": 1}},
        });
        statefile::store(&dir, TIER_FILE, &legacy).unwrap();
        let c = user_choice(&dir, Path::new("/x"));
        assert_eq!(c.env_read, Some(EnvRead::Tier));
        assert!(rewrite_retired_env_read(&dir).unwrap());
        assert!(!rewrite_retired_env_read(&dir).unwrap());
        let Loaded::Valid(raw) = statefile::load::<Value>(&dir, TIER_FILE) else {
            panic!("tier.json must stay authenticated");
        };
        assert_eq!(raw["global"]["env_read"], "tier");
        assert_eq!(raw["global"]["tier"], "medium");
        assert_eq!(raw["projects"]["/p"]["env_read"], "deny");
        statefile::store(&dir, TIER_FILE, &file).unwrap();
        assert!(!rewrite_retired_env_read(&dir).unwrap());
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn a_forged_file_fails_closed_to_high_and_an_untrusted_one_selects_nothing() {
        let mut dir = tmp_data("tierstate_forged");
        std::fs::create_dir_all(&dir.path).unwrap();
        std::fs::write(
            dir.path.join(TIER_FILE),
            r#"{"v":1,"global":{"tier":"off"},"projects":{}}"#,
        )
        .unwrap();
        let c = user_choice(&dir, Path::new("/x"));
        assert_eq!(
            (c.tier, c.status),
            (
                Some((Tier::High, TierSource::StateTampered)),
                UserStatus::Tampered
            )
        );
        let _ = std::fs::remove_file(dir.path.join(TIER_FILE));
        apply(&dir, &global(Some(Tier::Off), None), 1).unwrap();
        dir.trusted = false;
        let c = user_choice(&dir, Path::new("/x"));
        assert_eq!((c.tier, c.status), (None, UserStatus::Untrusted));
        let _ = std::fs::remove_dir_all(&dir.path);
    }

    #[test]
    fn payload_round_trip_and_revalidation() {
        let change = Change {
            project: Some(root()),
            tier: Some(Tier::Off),
            env_read: Some(EnvRead::Tier),
            clear: false,
        };
        assert_eq!(from_payload(&to_payload(&change)).unwrap(), change);
        for bad in [
            json!({"project": null, "tier": "disabled", "env_read": null, "clear": false}),
            json!({"project": "relative/dir", "tier": "off", "env_read": null, "clear": false}),
            json!({"project": null, "tier": null, "env_read": null, "clear": false}),
            json!({"project": null, "tier": "off", "env_read": "allow", "clear": false}),
            json!({"tier": "off"}),
        ] {
            assert!(from_payload(&bad).is_err(), "{bad}");
        }
        assert!(summary(&change).contains("tier off"));
    }
}
