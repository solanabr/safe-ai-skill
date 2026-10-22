//! User-scope pack trust (spec D2.8): `${DATA}/trust.json`, keyed by content hash.
//!
//! `{"<tree_hash>": {"acked_rules": [...], "confirmed_via": "prompt-nonce", "at": <unix>}}`.
//! An entry is written only by [`super::apply_confirmed`], i.e. after the user typed the
//! confirmation nonce of a `verify trust` or `verify approve` request (spec D4.1). Keying by
//! hash means a worktree, a fresh clone or a move of the same content needs no re-trust.
//!
//! Trust is honoured only when the data dir is trusted ([`DataDir::trusted`]: under the
//! plugin data root and outside the project). It covers a pack when the pack's content hash
//! has an entry whose `acked_rules` include every combo and HIGH rule the pack trips now, so a
//! scanner upgrade that finds something new is not silently covered.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::datadir::DataDir;
use crate::error::EngineError;
use crate::statefile::{self, Loaded};

/// The trust file name.
pub const TRUST_FILE: &str = "trust.json";
/// [`TrustEntry::confirmed_via`] of every entry this engine writes.
pub const CONFIRMED_VIA: &str = "prompt-nonce";

/// One trusted content hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustEntry {
    /// The combo and HIGH rules the user acknowledged for this content.
    #[serde(default)]
    pub acked_rules: Vec<String>,
    /// How it was confirmed (always [`CONFIRMED_VIA`]).
    pub confirmed_via: String,
    /// Unix seconds of the confirmation.
    pub at: u64,
    /// Where the pack was when trusted (display only; trust is not bound to it).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path_hint: String,
}

/// Trusted hashes.
pub type TrustStore = BTreeMap<String, TrustEntry>;

/// The trust entries this engine may honour: empty when the data dir is untrusted, or when
/// `trust.json` is missing or fails authentication.
pub fn load_honoured(dir: &DataDir) -> TrustStore {
    if !dir.trusted {
        return TrustStore::new();
    }
    match statefile::load::<TrustStore>(dir, TRUST_FILE) {
        Loaded::Valid(store) => store,
        Loaded::Missing | Loaded::Tampered => TrustStore::new(),
    }
}

/// True when `store` trusts content `hash` for every rule in `flagged`.
pub fn covers(store: &TrustStore, hash: &str, flagged: &[String]) -> bool {
    store
        .get(hash)
        .is_some_and(|e| flagged.iter().all(|r| e.acked_rules.contains(r)))
}

/// Record trust in content `hash`. Refused when the data dir is untrusted (it would never be
/// honoured). A tampered `trust.json` is replaced.
pub fn add(
    dir: &DataDir,
    hash: &str,
    acked_rules: &[String],
    path_hint: &str,
    now: u64,
) -> Result<(), EngineError> {
    if !dir.trusted {
        return Err(crate::error::Error::Other(
            "the plugin data dir is not trusted (it is inside the project or outside the \
             Claude Code plugin data root), so trust would be ignored"
                .to_string(),
        ));
    }
    let mut store = match statefile::load::<TrustStore>(dir, TRUST_FILE) {
        Loaded::Valid(s) => s,
        Loaded::Missing | Loaded::Tampered => TrustStore::new(),
    };
    let mut acked = acked_rules.to_vec();
    acked.sort();
    acked.dedup();
    store.insert(
        hash.to_string(),
        TrustEntry {
            acked_rules: acked,
            confirmed_via: CONFIRMED_VIA.to_string(),
            at: now,
            path_hint: path_hint.to_string(),
        },
    );
    statefile::store(dir, TRUST_FILE, &store)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(trusted: bool) -> DataDir {
        let path = std::env::temp_dir().join(format!(
            "ssai-trust-{trusted}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        DataDir { path, trusted }
    }

    #[test]
    fn trust_covers_only_acked_rules_of_that_hash() {
        let d = dir(true);
        add(&d, "h1", &["padding_sink".into()], "/p", 1).unwrap();
        let store = load_honoured(&d);
        assert!(covers(&store, "h1", &["padding_sink".into()]));
        assert!(covers(&store, "h1", &[]));
        assert!(!covers(&store, "h1", &["bang_cmd".into()]));
        assert!(!covers(&store, "h2", &[]));
    }

    #[test]
    fn untrusted_data_dir_neither_writes_nor_honours_trust() {
        let d = dir(false);
        assert!(add(&d, "h1", &[], "/p", 1).is_err());
        // Even a validly MAC'd file there is ignored.
        statefile::store(
            &d,
            TRUST_FILE,
            &TrustStore::from([(
                "h1".to_string(),
                TrustEntry {
                    acked_rules: vec![],
                    confirmed_via: CONFIRMED_VIA.into(),
                    at: 1,
                    path_hint: String::new(),
                },
            )]),
        )
        .unwrap();
        assert!(load_honoured(&d).is_empty());
        let trusted = DataDir {
            path: d.path.clone(),
            trusted: true,
        };
        assert_eq!(load_honoured(&trusted).len(), 1);
    }

    #[test]
    fn hand_written_trust_file_is_ignored() {
        let d = dir(true);
        add(&d, "h0", &[], "", 1).unwrap();
        std::fs::write(
            d.path.join(TRUST_FILE),
            r#"{"h1":{"acked_rules":[],"confirmed_via":"prompt-nonce","at":1}}"#,
        )
        .unwrap();
        assert!(load_honoured(&d).is_empty());
    }
}
