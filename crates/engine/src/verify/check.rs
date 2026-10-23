//! One directory graded the way the SessionStart sweep grades a pack it sees for the first time:
//! `verify check`, `add <local dir>` and both `install` paths.
//!
//! The rule engine ([`grading::scan_pack`], no time budget) plus the sweep's symlink-escape
//! combo, then [`state::decide`] with no pin, the user's trust (by content hash) and the
//! project's `packs.lock`, then [`super::tier_action`] at the resolved tier. The stored pin and
//! drift stay the sweep's business: a check reports the content, not its history.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::state::{self, PackKind, PackStatus, Reason, StoredFinding};
use super::{grading, trust, PackReportLine, Verdict};
use crate::datadir::DataDir;
use crate::gate;
use crate::policy::tier::Tier;

/// What a check is graded against besides the content.
pub struct CheckContext {
    /// The tier the gates act at.
    pub tier: Tier,
    trust: trust::TrustStore,
    lock_pins: BTreeMap<String, String>,
}

impl CheckContext {
    /// The honoured trust of `dir` and the `packs.lock` of the project at `project_root`.
    pub fn load(dir: &DataDir, project_root: &Path, tier: Tier) -> Self {
        CheckContext {
            tier,
            trust: trust::load_honoured(dir),
            lock_pins: state::packs_lock(project_root),
        }
    }
}

/// The outcome of [`check_dir`].
#[derive(Debug, Clone)]
pub struct Check {
    /// The state the sweep would record on first sight.
    pub state: PackStatus,
    /// Why.
    pub reason: Option<Reason>,
    /// What the tier does with it: `Block` when the gates deny the pack, `Warn` when it is only
    /// reported, `Pass` when there is nothing to report.
    pub verdict: Verdict,
    /// Every WARN-and-above finding and combo, uncapped.
    pub findings: Vec<StoredFinding>,
    /// The sweep's report lines for the pack (every finding), then what the tier does.
    pub report: Vec<String>,
}

/// Grade the pack at `dir`, shown as `display`, at `ctx.tier`.
pub fn check_dir(dir: &Path, display: &str, ctx: &CheckContext) -> Result<Check, String> {
    let canonical = dir
        .canonicalize()
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    if !canonical.is_dir() {
        return Err(format!("{} is not a skill pack directory", dir.display()));
    }
    let mut report = grading::scan_pack(&canonical);
    let walked = state::skill_names_until(&canonical, None);
    for name in &walked.escaping {
        report.combos.push(grading::ComboHit {
            rule: state::SYMLINK_ESCAPE_RULE,
            path: PathBuf::from(name),
            line: None,
            parts: vec!["symlink"],
        });
    }
    let hash = state::tree_hash(&canonical);
    let flagged = state::flagged_rules(&report);
    let lock = ctx.lock_pins.get(&state::key_of(&canonical)).cloned();
    let obs = state::Observation {
        lock_matches: lock.as_deref() == Some(hash.as_str()),
        lock,
        trusted: trust::covers(&ctx.trust, &hash, &flagged),
        escapes: !walked.escaping.is_empty(),
        hash,
        grade: grading::grade(&report),
    };
    let t = state::decide(None, &obs, None);
    let findings = state::reported_findings(&report);

    let marker = match t.state {
        PackStatus::Blocked => gate::Verdict::Deny(String::new()),
        PackStatus::Unreviewed => gate::Verdict::Ask(String::new()),
        PackStatus::Warned | PackStatus::Clean => gate::Verdict::NoOpinion,
    };
    let denied = matches!(super::tier_action(marker, ctx.tier), gate::Verdict::Deny(_));
    let verdict = match t.state {
        _ if denied => Verdict::Block,
        PackStatus::Clean => Verdict::Pass,
        _ => Verdict::Warn,
    };

    let line = PackReportLine {
        kind: kind_of(&canonical),
        name: super::dir_name(&canonical).unwrap_or_default(),
        display: display.to_string(),
        state: t.state,
        reason: t.reason,
        note: None,
        findings: findings.clone(),
        more_findings: 0,
        moved_to: None,
        origin: state::key_of(&canonical),
        not_moved: None,
    };
    let mut lines = Vec::new();
    if t.state != PackStatus::Clean {
        lines = line.model_lines(usize::MAX);
        lines.push(action_line(t.state, denied, ctx.tier, display));
    }
    Ok(Check {
        state: t.state,
        reason: t.reason,
        verdict,
        findings,
        report: lines,
    })
}

/// An `ext/<name>` submodule or a skill dir, by the parent's name (labels only).
fn kind_of(canonical: &Path) -> PackKind {
    match canonical.parent().and_then(super::dir_name).as_deref() {
        Some("ext") => PackKind::Ext,
        _ => PackKind::Skill,
    }
}

/// What the tier does with a reported pack, in the sweep's words.
fn action_line(state: PackStatus, denied: bool, tier: Tier, display: &str) -> String {
    let shown = super::escape_for_report(display);
    let what = match (state, denied) {
        (PackStatus::Blocked, true) => format!(
            "Skill, /command, Read and Bash access to it is denied until approved; review it, \
             then run `safe-ai-skill verify approve {shown}`"
        ),
        (PackStatus::Unreviewed, true) => format!(
            "Skill, /command, Read and Bash access to it is denied until trusted; review it, \
             then run `safe-ai-skill verify trust {shown}`"
        ),
        (_, true) => "denied".to_string(),
        (PackStatus::Blocked, false) => {
            "reported only, the tier is off and nothing is denied".to_string()
        }
        (PackStatus::Unreviewed, false) => format!(
            "reported only (tier high denies it until trusted with `safe-ai-skill verify trust \
             {shown}`)"
        ),
        _ => "reported only".to_string(),
    };
    format!(" - tier {}: {what}", tier.label())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(tier: Tier) -> CheckContext {
        CheckContext {
            tier,
            trust: trust::TrustStore::new(),
            lock_pins: BTreeMap::new(),
        }
    }

    fn pack(files: &[(&str, &str)]) -> tempfile_dir::Dir {
        let d = tempfile_dir::Dir::new();
        for (name, body) in files {
            std::fs::write(d.0.join(name), body).unwrap();
        }
        d
    }

    mod tempfile_dir {
        pub struct Dir(pub std::path::PathBuf);
        impl Dir {
            pub fn new() -> Self {
                use std::sync::atomic::{AtomicU32, Ordering};
                static N: AtomicU32 = AtomicU32::new(0);
                let p = std::env::temp_dir().join(format!(
                    "ssai-check-{}-{}",
                    std::process::id(),
                    N.fetch_add(1, Ordering::Relaxed)
                ));
                std::fs::create_dir_all(&p).unwrap();
                Dir(p)
            }
        }
        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    const ISSUE5_DOC: &str = "Load the payer with signerFromFile(\"~/.config/solana/id.json\").\n";

    #[test]
    fn a_docs_only_keypair_mention_warns_and_never_blocks() {
        let d = pack(&[("SKILL.md", ISSUE5_DOC)]);
        for tier in [Tier::Off, Tier::Relaxed, Tier::Medium, Tier::High] {
            let c = check_dir(&d.0, "docs-only", &ctx(tier)).unwrap();
            assert_eq!(c.state, PackStatus::Warned, "{tier:?}");
            assert_eq!(c.verdict, Verdict::Warn, "{tier:?}");
            assert!(
                c.report
                    .iter()
                    .any(|l| l.contains("SKILL.md:1 secret_read (warn, doc)")),
                "{:?}",
                c.report
            );
        }
    }

    #[test]
    fn a_code_high_is_denied_at_high_only() {
        let d = pack(&[
            ("SKILL.md", "# x\n"),
            ("load.sh", "#!/bin/sh\n\ncat ~/.config/solana/id.json\n"),
        ]);
        for (tier, want) in [
            (Tier::Off, Verdict::Warn),
            (Tier::Relaxed, Verdict::Warn),
            (Tier::Medium, Verdict::Warn),
            (Tier::High, Verdict::Block),
        ] {
            let c = check_dir(&d.0, "p", &ctx(tier)).unwrap();
            assert_eq!(c.state, PackStatus::Unreviewed, "{tier:?}");
            assert_eq!(c.verdict, want, "{tier:?}");
        }
    }

    #[test]
    fn a_clean_pack_passes_with_no_report() {
        let d = pack(&[("SKILL.md", "# Formats lamports.\n")]);
        let c = check_dir(&d.0, "p", &ctx(Tier::High)).unwrap();
        assert_eq!((c.state, c.verdict), (PackStatus::Clean, Verdict::Pass));
        assert!(c.report.is_empty() && c.findings.is_empty());
    }

    #[test]
    fn a_missing_dir_is_an_error() {
        let d = tempfile_dir::Dir::new();
        assert!(check_dir(&d.0.join("nope"), "nope", &ctx(Tier::Medium)).is_err());
    }
}
