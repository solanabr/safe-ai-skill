//! v1 compatibility view of the rule engine ([`super::rules`]).
//!
//! The orchestrator still consumes a flat [`Report`] (severity, kind, detail). This module keeps
//! that signature on top of [`rules::scan_pack`] until the verify state machine switches to
//! [`rules::scan_pack`] + [`rules::grade`] (spec D2.4 grading lives there, not here).
//!
//! Mapping, chosen so v1 callers and tests keep their meaning:
//! * a combo → `High`;
//! * a `High` finding → `High`; a documentation finding capped from a code-`High` rule also →
//!   `High` (v1 never told docs from code — the grader is where the doc cap bites);
//! * any other `Warn` → `Medium`; `Info` → `Low`, except `unpinned_npx`, which v1 graded
//!   `Medium` and keeps.
//!
//! [`scan_within`] reports a scan cut by its time budget as `complete: false` instead of a
//! finding: the SessionStart sweep keeps such a pack unreviewed (never pinned), and only what
//! was found before the cut can quarantine it.
//!
//! Detectors ported from v1 keep their v1 kind (`install_hook`, `eval`, `base64_exec`,
//! `unicode_obfuscation`, `broad_permissions`, and `telemetry_post` for any outbound POST); new
//! detectors use their rule id. Every finding's `detail` ends with its pack-relative `path:line`.

use std::path::Path;

use super::rules::{self, Ctx};
use super::{Finding, Report, Severity};

/// Scan `path` — a skill/MCP directory or a single file — through the rule engine.
///
/// Pure and hermetic: no network, no command execution, no panics.
pub fn scan(path: &Path) -> Report {
    legacy_report(&rules::scan_pack(path))
}

/// A [`scan_within`] result.
pub struct BudgetedScan {
    /// Findings of what was scanned (the budget marker is reported as `complete` instead).
    pub report: Report,
    /// False when the time budget cut the scan short: the pack is unreviewed.
    pub complete: bool,
}

/// [`scan`] under a wall-clock budget shared across a sweep (SessionStart).
pub fn scan_within(path: &Path, budget: &rules::ScanBudget) -> BudgetedScan {
    scan_until(path, budget.pack_deadline())
}

/// [`scan`] that stops at `deadline` (`None`: unbounded).
pub fn scan_until(path: &Path, deadline: Option<std::time::Instant>) -> BudgetedScan {
    let mut pack = rules::scan_pack_until(path, deadline);
    let before = pack.findings.len();
    pack.findings.retain(|f| f.rule != "scan_budget_exceeded");
    BudgetedScan {
        complete: pack.findings.len() == before,
        report: legacy_report(&pack),
    }
}

fn legacy_report(pack: &rules::PackReport) -> Report {
    let mut report = Report::default();
    for f in &pack.findings {
        report.findings.push(legacy(
            legacy_severity(f),
            legacy_kind(f.rule),
            rules::describe(f.rule),
            &f.path,
            f.line,
        ));
    }
    for c in &pack.combos {
        report.findings.push(legacy(
            Severity::High,
            c.rule,
            rules::describe(c.rule),
            &c.path,
            c.line,
        ));
    }
    report
}

/// One v1 finding located at `path:line`.
fn legacy(sev: Severity, kind: &str, summary: &str, path: &Path, line: Option<u32>) -> Finding {
    let location = match line {
        Some(l) => format!("{}:{l}", path.display()),
        None => path.display().to_string(),
    };
    let mut finding = Finding::new(sev, kind, format!("{summary} ({location})"));
    finding.path = path.to_string_lossy().replace('\\', "/");
    finding.line = line.and_then(|l| usize::try_from(l).ok()).unwrap_or(0);
    finding
}

/// v1 severity of a rule finding (see the module docs).
fn legacy_severity(f: &rules::Finding) -> Severity {
    match f.sev {
        rules::Severity::High => Severity::High,
        rules::Severity::Warn
            if f.ctx == Ctx::Doc && rules::code_severity(f.rule) == Some(rules::Severity::High) =>
        {
            Severity::High
        }
        rules::Severity::Warn => Severity::Medium,
        rules::Severity::Info if f.rule == "unpinned_npx" => Severity::Medium,
        rules::Severity::Info => Severity::Low,
    }
}

/// v1 kind for detectors that existed in v1; the rule id otherwise.
fn legacy_kind(rule: &'static str) -> &'static str {
    match rule {
        "lifecycle_script" => "install_hook",
        "network_post" => "telemetry_post",
        "eval" | "shell_eval" => "eval",
        "exec_decode" => "base64_exec",
        "unicode_bidi" | "unicode_invisible" | "unicode_tag" => "unicode_obfuscation",
        "broad_tools" => "broad_permissions",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::Duration;

    fn tempdir(tag: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!(
            "safe-ai-skill-heur-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&base).unwrap();
        base
    }

    fn scan_text(name: &str, text: &str) -> Report {
        let dir = tempdir("text");
        fs::write(dir.join(name), text).unwrap();
        let report = scan(&dir.join(name));
        fs::remove_dir_all(&dir).ok();
        report
    }

    fn kinds(report: &Report) -> Vec<String> {
        report.findings.iter().map(|f| f.kind.clone()).collect()
    }

    #[test]
    fn doc_telemetry_keeps_v1_high_with_its_location() {
        let dir = tempdir("telemetry");
        let skill = dir.join("my-skill");
        fs::create_dir_all(&skill).unwrap();
        fs::write(
            skill.join("SKILL.md"),
            "# My Skill\n```bash\ncurl -s -X POST \"$CONVEX/api/mutation\" -d '{}'\n```\n",
        )
        .unwrap();

        let report = scan(&skill);
        let f = report
            .findings
            .iter()
            .find(|f| f.kind == "telemetry_post")
            .expect("telemetry_post");
        assert_eq!(f.severity, Severity::High);
        assert!(f.detail.ends_with("(SKILL.md:3)"), "{}", f.detail);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn clean_skill_is_empty_or_low() {
        let report = scan_text(
            "SKILL.md",
            "# Clean Skill\nThis skill formats Solana addresses. No network access.\n",
        );
        let max = report.max_severity();
        assert!(max.is_none() || max == Some(Severity::Low), "got {max:?}");
    }

    #[test]
    fn ported_detectors_keep_v1_kinds() {
        let cases = [
            (
                "package.json",
                "{ \"name\": \"x\", \"scripts\": { \"postinstall\": \"node s.js\" } }",
                "install_hook",
            ),
            ("run.sh", "#!/bin/sh\neval \"$(cat payload)\"\n", "eval"),
            (
                "run.sh",
                "#!/bin/sh\necho Zm9v | base64 -d | sh\n",
                "base64_exec",
            ),
            (
                "SKILL.md",
                "# Skill\nzero\u{200B}width\n",
                "unicode_obfuscation",
            ),
            (
                "SKILL.md",
                "# Skill\nallowed-tools: Bash(*)\n",
                "broad_permissions",
            ),
        ];
        for (name, text, kind) in cases {
            let report = scan_text(name, text);
            assert!(
                kinds(&report).contains(&kind.to_string()),
                "{kind}: {report:?}"
            );
        }
    }

    #[test]
    fn combos_map_to_high_and_warn_to_medium() {
        let dir = tempdir("combo");
        let pack = dir.join("p");
        fs::create_dir_all(&pack).unwrap();
        fs::write(
            pack.join("watch.js"),
            format!("x();{}eval(atob(s))\n", " ".repeat(300)),
        )
        .unwrap();
        fs::write(
            pack.join("SKILL.md"),
            "---\nname: p\ndescription: Docs at https://docs.example.invalid for details.\n---\n",
        )
        .unwrap();
        let report = scan(&pack);
        let combo = report
            .findings
            .iter()
            .find(|f| f.kind == "padding_sink")
            .expect("padding_sink");
        assert_eq!(combo.severity, Severity::High);
        let url = report
            .findings
            .iter()
            .find(|f| f.kind == "description_url")
            .expect("description_url");
        assert_eq!(url.severity, Severity::Medium);
        assert_eq!(super::super::verdict(&report), super::super::Verdict::Block);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_budget_cut_is_reported_as_incomplete_not_as_a_finding() {
        let dir = tempdir("budget");
        fs::write(dir.join("README.md"), "# plain\n").unwrap();
        let none = rules::ScanBudget::new(Duration::ZERO, Duration::from_secs(60));
        let scan = scan_within(&dir, &none);
        assert!(!scan.complete);
        assert!(
            scan.report.findings.is_empty(),
            "{:?}",
            scan.report.findings
        );
        let ample = rules::ScanBudget::new(Duration::from_secs(60), Duration::from_secs(60));
        assert!(scan_within(&dir, &ample).complete);
        // The marker itself maps to High wherever a v1 report carries it.
        let marker = rules::Finding {
            rule: "scan_budget_exceeded",
            sev: rules::Severity::High,
            path: dir.clone(),
            line: None,
            ctx: Ctx::Meta,
        };
        assert_eq!(legacy_severity(&marker), Severity::High);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn info_maps_to_low_but_unpinned_npx_stays_medium() {
        let report = scan_text(
            "setup.sh",
            "#!/bin/sh\nnpx -y some-mcp-server\nchmod +x run.sh\n",
        );
        let f = report
            .findings
            .iter()
            .find(|f| f.kind == "unpinned_npx")
            .expect("unpinned_npx");
        assert_eq!(f.severity, Severity::Medium);
        let report = scan_text("README.md", "# R\n\nhttps://example.invalid/docs\n");
        assert!(
            report.findings.iter().all(|f| f.severity <= Severity::Low),
            "{:?}",
            report.findings
        );
    }
}
