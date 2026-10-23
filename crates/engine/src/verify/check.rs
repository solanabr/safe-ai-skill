//! One directory graded the way the SessionStart sweep grades a pack it sees for the first time:
//! `verify check`, `add <local dir>` and both `install` paths.
//!
//! The rule engine ([`grading::scan_pack`], no time budget) plus the sweep's symlink-escape
//! combo and its unscanned marker (a name walk past its entry cap), then [`state::decide`] with
//! no pin, the user's trust (by content hash) and the project's `packs.lock`, then
//! [`super::tier_action`] at the resolved tier. The pack's own git history ([`history::scan`])
//! is graded with the content here, never in the sweep. The stored pin and drift stay the
//! sweep's business.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::state::{self, PackKind, PackStatus, Reason, StoredFinding};
use super::{grading, history, trust, PackReportLine, Verdict};
use crate::datadir::DataDir;
use crate::gate;
use crate::policy::tier::Tier;

/// What a check is graded against besides the content.
pub struct CheckContext {
    /// The tier the gates act at.
    pub tier: Tier,
    /// The check is for `add` / `install` (the pack is not swept yet), not `verify check`.
    installing: bool,
    trust: trust::TrustStore,
    lock_pins: BTreeMap<String, String>,
}

impl CheckContext {
    /// The honoured trust of `dir` and the `packs.lock` of the project at `project_root`.
    pub fn load(dir: &DataDir, project_root: &Path, tier: Tier) -> Self {
        CheckContext {
            tier,
            installing: false,
            trust: trust::load_honoured(dir),
            lock_pins: state::packs_lock(project_root),
        }
    }

    /// The same context, worded for `add` / `install`.
    pub fn for_install(mut self) -> Self {
        self.installing = true;
        self
    }

    /// The project's `packs.lock` pins the pack at `dir` (so editing it breaks the pin).
    pub fn lock_pinned(&self, dir: &Path) -> bool {
        dir.canonicalize()
            .is_ok_and(|c| self.lock_pins.contains_key(&state::key_of(&c)))
    }
}

/// The outcome of [`check_dir`].
#[derive(Debug, Clone)]
pub struct Check {
    /// The state the sweep would record on first sight.
    pub state: PackStatus,
    /// Why.
    pub reason: Option<Reason>,
    /// Not fully scanned (its name walk ran past the entry cap): denied like a blocked pack.
    pub unscanned: bool,
    /// What the tier does with it: `Block` when the gates deny the pack, `Warn` when it is only
    /// reported, `Pass` when there is nothing to report.
    pub verdict: Verdict,
    /// Every finding and combo, INFO included, uncapped.
    pub findings: Vec<StoredFinding>,
    /// The sweep's report lines for the pack (every finding), then what the tier does.
    pub report: Vec<String>,
}

/// Grade the pack at `dir`, shown as `display`, at `ctx.tier`, its git history included.
pub fn check_dir(dir: &Path, display: &str, ctx: &CheckContext) -> Result<Check, String> {
    check_dir_with(dir, display, ctx, &history::scan(dir))
}

/// [`check_dir`] with the history scan already made (`install` grades a directory twice, before
/// and after neutralizing telemetry, and reads its history once).
pub fn check_dir_with(
    dir: &Path,
    display: &str,
    ctx: &CheckContext,
    history: &history::HistoryReport,
) -> Result<Check, String> {
    let canonical = dir
        .canonicalize()
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    if !canonical.is_dir() {
        return Err(format!("{} is not a skill pack directory", dir.display()));
    }
    let mut report = grading::scan_pack(&canonical);
    merge_history(&mut report, history);
    let walked = state::skill_names_until(&canonical, None);
    let unscanned = walked.over_budget;
    if unscanned {
        report.findings.push(grading::Finding {
            rule: state::SCAN_BUDGET_RULE,
            sev: grading::Severity::High,
            path: PathBuf::new(),
            line: None,
            ctx: grading::Ctx::Meta,
        });
    }
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
    let mut t = state::decide(None, &obs, None);
    // The sweep records an unscanned pack `unreviewed` whatever it trusts, and denies it like a
    // blocked one.
    if unscanned && t.state < PackStatus::Unreviewed {
        t.state = PackStatus::Unreviewed;
        t.reason = Some(Reason::Heuristic);
    }
    let findings = state::reported_findings(&report, true);

    let marker = match t.state {
        PackStatus::Blocked => gate::Verdict::Deny(String::new()),
        PackStatus::Unreviewed if unscanned => gate::Verdict::Deny(String::new()),
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
        note: note(unscanned, history),
        findings: findings.clone(),
        more_findings: 0,
        moved_to: None,
        origin: state::key_of(&canonical),
        not_moved: None,
    };
    let mut lines = Vec::new();
    if t.state != PackStatus::Clean || !findings.is_empty() {
        lines = line.model_lines(usize::MAX);
    }
    if t.state != PackStatus::Clean {
        lines.push(action_line(&Action {
            state: t.state,
            reason: t.reason,
            unscanned,
            denied,
            tier: ctx.tier,
            installing: ctx.installing,
            display,
        }));
    }
    Ok(Check {
        state: t.state,
        reason: t.reason,
        unscanned,
        verdict,
        findings,
        report: lines,
    })
}

/// Add the history findings to the checkout's report. `docs_commit_code` is report-only (INFO
/// here: listed, never holding an install); `docs_commit_sink` is the blocking combo.
fn merge_history(report: &mut grading::PackReport, history: &history::HistoryReport) {
    report
        .findings
        .extend(history.report.findings.iter().cloned().map(|mut f| {
            if f.rule == "docs_commit_code" {
                f.sev = grading::Severity::Info;
            }
            f
        }));
    report.combos.extend(history.report.combos.iter().cloned());
    report.capped.extend(history.report.capped.iter().cloned());
}

/// The report note: an over-budget name walk, and why part of the git history went unscanned.
fn note(unscanned: bool, history: &history::HistoryReport) -> Option<String> {
    let mut parts = Vec::new();
    if unscanned {
        parts.push(format!(
            "not fully scanned: more than {} entries to walk",
            state::MAX_NAME_WALK_ENTRIES
        ));
    }
    if !history.unscanned.is_empty() {
        parts.push(format!(
            "git history not fully scanned: {}",
            history.unscanned.join("; ")
        ));
    }
    (!parts.is_empty()).then(|| parts.join("; "))
}

/// An `ext/<name>` submodule or a skill dir, by the parent's name (labels only).
fn kind_of(canonical: &Path) -> PackKind {
    match canonical.parent().and_then(super::dir_name).as_deref() {
        Some("ext") => PackKind::Ext,
        _ => PackKind::Skill,
    }
}

/// What [`action_line`] words.
struct Action<'a> {
    state: PackStatus,
    reason: Option<Reason>,
    unscanned: bool,
    denied: bool,
    tier: Tier,
    installing: bool,
    display: &'a str,
}

/// What the tier does with a reported pack, in the sweep's words.
fn action_line(a: &Action) -> String {
    let shown = super::escape_for_report(a.display);
    let gates = if a.installing {
        "once swept, the gates would deny Skill, /command, Read and Bash access to it"
    } else {
        "Skill, /command, Read and Bash access to it is denied"
    };
    let what = match (a.state, a.denied) {
        // Approval never clears a combination rule.
        (PackStatus::Blocked, true) if a.reason == Some(Reason::Combo) => format!(
            "{gates}: a combination rule fires, which neither approval nor trust clears; fix or \
             remove the pack"
        ),
        (PackStatus::Blocked, true) => format!(
            "{gates} until approved; review it, then run `safe-ai-skill verify approve {shown}`"
        ),
        (PackStatus::Unreviewed, true) if a.unscanned => {
            format!("{gates} until a sweep scans it in full, which a pack this large never fits")
        }
        (PackStatus::Unreviewed, true) => format!(
            "{gates} until trusted; review it, then run `safe-ai-skill verify trust {shown}`"
        ),
        (_, true) => gates.to_string(),
        (PackStatus::Blocked, false) => {
            "reported only, the tier is off and nothing is denied".to_string()
        }
        (PackStatus::Unreviewed, false) => format!(
            "reported only (tier high denies it until trusted with `safe-ai-skill verify trust \
             {shown}`)"
        ),
        _ => "reported only".to_string(),
    };
    format!(" - tier {}: {what}", a.tier.label())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(tier: Tier) -> CheckContext {
        CheckContext {
            tier,
            installing: false,
            trust: trust::TrustStore::new(),
            lock_pins: BTreeMap::new(),
        }
    }

    struct Dir(PathBuf);

    impl Dir {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU32, Ordering};
            static N: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "ssai-check-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&p).unwrap();
            Dir(p.canonicalize().unwrap())
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn pack(files: &[(&str, &str)]) -> Dir {
        let d = Dir::new();
        for (name, body) in files {
            std::fs::write(d.0.join(name), body).unwrap();
        }
        d
    }

    const ISSUE5_DOC: &str = "Load the payer with signerFromFile(\"~/.config/solana/id.json\").\n";
    const KEYPAIR_SCRIPT: &str = "#!/bin/sh\n\ncat ~/.config/solana/id.json\n";
    const ALL: [Tier; 4] = [Tier::Off, Tier::Relaxed, Tier::Medium, Tier::High];

    #[test]
    fn a_docs_only_keypair_mention_warns_and_never_blocks() {
        let d = pack(&[("SKILL.md", ISSUE5_DOC)]);
        for tier in ALL {
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
        let d = pack(&[("SKILL.md", "# x\n"), ("load.sh", KEYPAIR_SCRIPT)]);
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
    fn info_findings_are_listed_and_change_nothing() {
        let d = pack(&[
            ("SKILL.md", "# x\n"),
            (
                ".mcp.json",
                r#"{"mcpServers":{"h":{"command":"npx","args":["-y","h-mcp@1.2.3"]}}}"#,
            ),
        ]);
        let c = check_dir(&d.0, "p", &ctx(Tier::High)).unwrap();
        assert_eq!((c.state, c.verdict), (PackStatus::Clean, Verdict::Pass));
        assert!(
            c.findings.iter().any(|f| f.sev == state::StoredSev::Info),
            "{:?}",
            c.findings
        );
        assert!(c.report[0].starts_with(" - INFO skill"), "{:?}", c.report);
        assert!(
            c.report.iter().any(|l| l.contains("(info, ")),
            "{:?}",
            c.report
        );
    }

    #[test]
    fn a_walk_past_the_entry_cap_is_unscanned_and_denied_like_a_block() {
        let d = pack(&[("SKILL.md", "# x\n")]);
        for i in 0..8 {
            std::fs::create_dir_all(d.0.join(format!("d{i}"))).unwrap();
        }
        state::NAME_CAP.with(|c| c.set(4));
        let checks: Vec<Check> = ALL
            .iter()
            .map(|t| check_dir(&d.0, "p", &ctx(*t)).unwrap())
            .collect();
        state::NAME_CAP.with(|c| c.set(state::MAX_NAME_WALK_ENTRIES));
        for (tier, c) in ALL.iter().zip(&checks) {
            assert!(c.unscanned, "{tier:?}");
            assert_eq!(c.state, PackStatus::Unreviewed, "{tier:?}");
            let want = if *tier == Tier::Off {
                Verdict::Warn
            } else {
                Verdict::Block
            };
            assert_eq!(c.verdict, want, "{tier:?}");
            assert!(
                c.findings.iter().any(|f| f.rule == state::SCAN_BUDGET_RULE),
                "{:?}",
                c.findings
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_out_of_the_pack_is_a_combo_block() {
        let outside = pack(&[("SKILL.md", "---\nname: other\n---\n")]);
        let d = pack(&[("SKILL.md", "# x\n")]);
        std::os::unix::fs::symlink(&outside.0, d.0.join("sub")).unwrap();
        let c = check_dir(&d.0, "p", &ctx(Tier::Relaxed)).unwrap();
        assert_eq!(
            (c.state, c.reason),
            (PackStatus::Blocked, Some(Reason::Combo))
        );
        assert_eq!(c.verdict, Verdict::Block);
        assert!(
            c.report.iter().any(|l| l.contains("fix or remove")),
            "{:?}",
            c.report
        );
        assert!(!c.report.iter().any(|l| l.contains("verify approve")));
    }

    #[test]
    fn trust_clears_a_high_and_packs_lock_pins_the_content() {
        let d = pack(&[("SKILL.md", "# x\n"), ("load.sh", KEYPAIR_SCRIPT)]);
        let hash = state::tree_hash(&d.0);
        let mut trusted = ctx(Tier::High);
        trusted.trust.insert(
            hash.clone(),
            trust::TrustEntry {
                acked_rules: vec!["secret_read".to_string()],
                confirmed_via: trust::CONFIRMED_VIA.to_string(),
                at: 0,
                path_hint: String::new(),
            },
        );
        let c = check_dir(&d.0, "p", &trusted).unwrap();
        assert_eq!((c.state, c.verdict), (PackStatus::Clean, Verdict::Pass));

        // A matching lock entry keeps a HIGH a warning, even at High.
        let mut locked = ctx(Tier::High);
        locked.lock_pins.insert(state::key_of(&d.0), hash);
        assert!(locked.lock_pinned(&d.0));
        let c = check_dir(&d.0, "p", &locked).unwrap();
        assert_eq!((c.state, c.verdict), (PackStatus::Warned, Verdict::Warn));

        // A mismatching one blocks, with approval as the way out.
        let mut stale = ctx(Tier::Relaxed);
        stale.lock_pins.insert(state::key_of(&d.0), "0".repeat(64));
        let c = check_dir(&d.0, "p", &stale).unwrap();
        assert_eq!(
            (c.state, c.reason, c.verdict),
            (
                PackStatus::Blocked,
                Some(Reason::LockMismatch),
                Verdict::Block
            )
        );
        assert!(
            c.report.iter().any(|l| l.contains("verify approve p")),
            "{:?}",
            c.report
        );
    }

    #[test]
    fn install_wording_says_would_be_denied() {
        let d = pack(&[("SKILL.md", "# x\n"), ("load.sh", KEYPAIR_SCRIPT)]);
        let c = check_dir(&d.0, "p", &ctx(Tier::High).for_install()).unwrap();
        assert!(
            c.report.iter().any(|l| l.contains("the gates would deny")),
            "{:?}",
            c.report
        );
    }

    #[test]
    fn a_missing_dir_or_a_file_is_an_error() {
        let d = pack(&[("f.md", "x")]);
        assert!(check_dir(&d.0.join("nope"), "nope", &ctx(Tier::Medium)).is_err());
        assert!(check_dir(&d.0.join("f.md"), "f.md", &ctx(Tier::Medium)).is_err());
    }

    #[test]
    fn history_findings_are_graded_with_the_content() {
        let d = pack(&[("SKILL.md", "# x\n")]);
        let finding = |rule: &'static str| grading::Finding {
            rule,
            sev: grading::Severity::Warn,
            path: PathBuf::from("git:abc:x.ts"),
            line: None,
            ctx: grading::Ctx::Code,
        };
        let mut h = history::HistoryReport::default();
        h.report.findings.push(finding("docs_commit_code"));
        let c = check_dir_with(&d.0, "p", &ctx(Tier::High), &h).unwrap();
        // Report-only: listed, never moves the pack off clean.
        assert_eq!(c.state, PackStatus::Clean);
        assert_eq!(c.verdict, Verdict::Pass);
        assert!(c.findings.iter().any(|f| f.rule == "docs_commit_code"));

        h.report.findings.push(finding("history_unscanned"));
        h.unscanned.push("time budget spent".into());
        let c = check_dir_with(&d.0, "p", &ctx(Tier::High), &h).unwrap();
        assert_eq!(c.state, PackStatus::Warned);
        assert!(
            c.report.iter().any(|l| l.contains("time budget spent")),
            "{:?}",
            c.report
        );

        h.report.combos.push(grading::ComboHit {
            rule: "docs_commit_sink",
            path: PathBuf::from("git:abc:x.ts"),
            line: None,
            parts: vec!["docs_commit_code", "padding_sink"],
        });
        let c = check_dir_with(&d.0, "p", &ctx(Tier::Medium), &h).unwrap();
        assert_eq!(c.state, PackStatus::Blocked);
        assert_eq!(c.verdict, Verdict::Block);
    }
}
