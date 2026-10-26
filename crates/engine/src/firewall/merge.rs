//! Merge a generated [`Block`] into a settings document, touching only safe-ai-skill's entries.
//!
//! The ownership model is the kit's `enforced.ruleIds` subtraction (firewall.sh l.5–31,
//! l.2383–2433): an apply removes exactly the entries the last apply recorded writing, and
//! only those some tier can emit, then appends the newly generated block after everything else.
//! An entry the user wrote is never removed, and when it equals a generated one the block skips
//! it and does not record it, so it stays the user's through every later tier change.
//!
//! Scalars follow the same rule: one is written only where the key is absent, only ever as
//! `true`, and removed only when the record says this writer set it and it still holds `true`.
//! A key the user set — including `sandbox.enabled: false` — is left as it is and reported.

use std::collections::BTreeMap;

use super::json::Json;
use super::rules::{Block, LISTS, SCALARS};

/// The containers this writer may create, deepest first (the cleanup order).
const CONTAINERS: &[&str] = &[
    "sandbox.filesystem",
    "sandbox.network",
    "sandbox",
    "permissions",
];

/// What a merge produced.
#[derive(Debug, Clone, PartialEq)]
pub struct Merged {
    /// The new document.
    pub doc: Json,
    /// The entries this apply wrote, per list.
    pub rule_ids: BTreeMap<String, Vec<String>>,
    /// The scalars this writer owns after the apply.
    pub scalars: Vec<String>,
    /// One line per changed setting.
    pub changes: Vec<String>,
    /// Settings the user holds that differ from the block (left untouched).
    pub user_held: Vec<String>,
}

/// The ownership record of the previous apply, as far as a merge needs it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Owned<'a> {
    /// Recorded list entries, per list.
    pub rule_ids: Option<&'a BTreeMap<String, Vec<String>>>,
    /// Recorded scalars.
    pub scalars: &'a [String],
}

/// Merge `block` into `doc`. `emittable(path)` lists every entry some tier can write into that
/// list (a recorded entry outside it is the user's and is kept). `doc` must be an object.
pub fn merge(
    doc: &Json,
    block: &Block,
    owned: &Owned<'_>,
    emittable: &dyn Fn(&str) -> Vec<String>,
) -> Merged {
    let mut out = doc.clone();
    let mut rule_ids = BTreeMap::new();
    let mut changes = Vec::new();
    let mut user_held = Vec::new();

    for path in LISTS {
        let generated = block.list(path);
        let current = out.at(path);
        if current.is_some_and(|v| !matches!(v, Json::Arr(_))) {
            user_held.push(format!("{path} is not a list; left as it is"));
            continue;
        }
        let before: Vec<Json> = match current {
            Some(Json::Arr(items)) => items.clone(),
            _ => Vec::new(),
        };
        let recorded: &[String] = owned
            .rule_ids
            .and_then(|m| m.get(*path))
            .map_or(&[], Vec::as_slice);
        let may_emit = if recorded.is_empty() {
            Vec::new()
        } else {
            emittable(path)
        };
        let removable =
            |e: &str| recorded.iter().any(|r| r == e) && may_emit.iter().any(|m| m == e);
        let kept: Vec<Json> = before
            .iter()
            .filter(|v| !matches!(v, Json::Str(s) if removable(s)))
            .cloned()
            .collect();
        let kept_strings: Vec<&str> = kept
            .iter()
            .filter_map(|v| match v {
                Json::Str(s) => Some(s.as_str()),
                _ => None,
            })
            .collect();
        let added: Vec<String> = generated
            .iter()
            .filter(|g| !kept_strings.contains(&g.as_str()))
            .cloned()
            .collect();
        let mut after = kept.clone();
        after.extend(added.iter().cloned().map(Json::Str));

        let removed = before.len().saturating_sub(kept.len());
        let net_added = added
            .iter()
            .filter(|a| !before.iter().any(|b| matches!(b, Json::Str(s) if s == *a)))
            .count();
        if after != before {
            if after.is_empty() {
                remove_path(&mut out, path);
            } else if !set_path(&mut out, path, Json::Arr(after)) {
                user_held.push(format!("{path}: a parent setting is not an object; left"));
                continue;
            }
            changes.push(format!("{path}: +{net_added} / -{removed}"));
        }
        if !added.is_empty() {
            rule_ids.insert((*path).to_string(), added);
        }
    }

    let mut scalars = Vec::new();
    for path in SCALARS {
        let want = block.scalars.contains(path);
        let ours = owned.scalars.iter().any(|s| s == path);
        match out.at(path).cloned() {
            Some(Json::Bool(true)) if ours => {
                if want {
                    scalars.push((*path).to_string());
                } else {
                    remove_path(&mut out, path);
                    changes.push(format!("{path}: removed"));
                }
            }
            Some(v) => {
                if want && v != Json::Bool(true) {
                    user_held.push(format!(
                        "{path} is set to {} in this file by you; left as it is",
                        describe(&v)
                    ));
                }
            }
            None if want => {
                if set_path(&mut out, path, Json::Bool(true)) {
                    scalars.push((*path).to_string());
                    changes.push(format!("{path}: true"));
                } else {
                    user_held.push(format!("{path}: a parent setting is not an object; left"));
                }
            }
            None => {}
        }
    }

    for c in CONTAINERS {
        let was_empty = doc.at(c).is_some_and(Json::is_empty_obj);
        if out.at(c).is_some_and(Json::is_empty_obj) && !was_empty {
            remove_path(&mut out, c);
        }
    }

    Merged {
        doc: out,
        rule_ids,
        scalars,
        changes,
        user_held,
    }
}

fn describe(v: &Json) -> String {
    match v {
        Json::Bool(b) => b.to_string(),
        Json::Null => "null".to_string(),
        Json::Num(n) => n.clone(),
        Json::Str(_) => "a string".to_string(),
        Json::Arr(_) => "a list".to_string(),
        Json::Obj(_) => "an object".to_string(),
    }
}

/// Set a dotted path, creating missing objects. `false` when a parent is not an object.
fn set_path(doc: &mut Json, path: &str, value: Json) -> bool {
    let mut parts: Vec<&str> = path.split('.').collect();
    let Some(last) = parts.pop() else {
        return false;
    };
    let mut node = doc;
    for part in parts {
        if node.get(part).is_none() {
            node.set(part, Json::Obj(Vec::new()));
        }
        match node.get_mut(part) {
            Some(child @ Json::Obj(_)) => node = child,
            _ => return false,
        }
    }
    if !matches!(node, Json::Obj(_)) {
        return false;
    }
    node.set(last, value);
    true
}

fn remove_path(doc: &mut Json, path: &str) {
    let mut parts: Vec<&str> = path.split('.').collect();
    let Some(last) = parts.pop() else {
        return;
    };
    let mut node = doc;
    for part in parts {
        match node.get_mut(part) {
            Some(child) => node = child,
            None => return,
        }
    }
    node.remove(last);
}

#[cfg(test)]
mod tests {
    use super::super::json::{parse, to_text};
    use super::super::rules::{plan, MachineInputs};
    use super::*;
    use crate::policy::tier::Tier;

    fn emit(path: &str) -> Vec<String> {
        super::super::rules::emittable(path, &["webhook.site"], &MachineInputs::default())
    }

    fn run(doc: &Json, tier: Tier, owned: &Owned<'_>) -> Merged {
        let block = plan(tier, &["webhook.site"], &MachineInputs::default());
        merge(doc, &block, owned, &emit)
    }

    #[test]
    fn user_rules_survive_and_block_appends() {
        let doc = parse(
            r#"{"permissions":{"deny":["Read(./secret)"],"allow":["Bash(ls)"]},"model":"x"}"#,
        )
        .unwrap();
        let m = run(&doc, Tier::High, &Owned::default());
        assert_eq!(
            m.doc.at("permissions.deny").unwrap().strings(),
            ["Read(./secret)", "Bash(bash -c *)"]
        );
        assert_eq!(
            m.doc.at("permissions.allow").unwrap().strings(),
            ["Bash(ls)"]
        );
        assert_eq!(m.doc.at("sandbox.enabled"), Some(&Json::Bool(true)));
        let keys: Vec<&str> = match &m.doc {
            Json::Obj(e) => e.iter().map(|(k, _)| k.as_str()).collect(),
            _ => vec![],
        };
        assert_eq!(keys, ["permissions", "model", "sandbox"]);
    }

    #[test]
    fn round_trip_to_off_restores_the_original() {
        let text = "{\n  \"permissions\": {\n    \"deny\": [\n      \"Read(./x)\"\n    ]\n  }\n}\n";
        let doc = parse(text).unwrap();
        let m = run(&doc, Tier::High, &Owned::default());
        let owned = Owned {
            rule_ids: Some(&m.rule_ids),
            scalars: &m.scalars,
        };
        let back = run(&m.doc, Tier::Off, &owned);
        assert_eq!(to_text(&back.doc), text);
    }

    #[test]
    fn identical_user_rule_stays_the_users() {
        let doc = parse(r#"{"permissions":{"deny":["Bash(bash -c *)"]}}"#).unwrap();
        let m = run(&doc, Tier::Medium, &Owned::default());
        assert!(!m.rule_ids.contains_key("permissions.deny"));
        let owned = Owned {
            rule_ids: Some(&m.rule_ids),
            scalars: &m.scalars,
        };
        let r = run(&m.doc, Tier::Relaxed, &owned);
        assert_eq!(
            r.doc.at("permissions.deny").unwrap().strings(),
            ["Bash(bash -c *)"]
        );
    }

    #[test]
    fn never_writes_false_and_keeps_user_false() {
        let doc = parse(r#"{"sandbox":{"enabled":false}}"#).unwrap();
        let m = run(&doc, Tier::High, &Owned::default());
        assert_eq!(m.doc.at("sandbox.enabled"), Some(&Json::Bool(false)));
        assert!(m.user_held.iter().any(|n| n.contains("sandbox.enabled")));
        assert!(!m.scalars.contains(&"sandbox.enabled".to_string()));
    }

    #[test]
    fn forged_record_cannot_remove_a_user_rule() {
        let doc = parse(r#"{"permissions":{"deny":["Read(./mine)"]}}"#).unwrap();
        let mut ids = BTreeMap::new();
        ids.insert(
            "permissions.deny".to_string(),
            vec!["Read(./mine)".to_string()],
        );
        let owned = Owned {
            rule_ids: Some(&ids),
            scalars: &[],
        };
        let m = run(&doc, Tier::Off, &owned);
        assert_eq!(
            m.doc.at("permissions.deny").unwrap().strings(),
            ["Read(./mine)"]
        );
    }
}
