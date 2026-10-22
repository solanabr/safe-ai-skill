//! The grading boundary between the pack scanner and the verify state machine (spec D2.4).
//!
//! The types below mirror `verify::rules` from the detector workstream field for field:
//! [`PackReport`] `{findings, combos}`, [`Finding`] `{rule, sev, path, line, ctx}`, [`ComboHit`],
//! [`Severity`], [`Ctx`] and [`Grade`], with [`scan_pack`] and [`grade`] of the same signatures.
//! Until that scanner lands, [`scan_pack`] adapts the line heuristics in [`super::heuristics`]
//! (which know no combinations, so they never grade [`Grade::Block`]). When `verify::rules` is
//! merged this whole module becomes
//! `pub use super::rules::{grade, scan_pack, ComboHit, Ctx, Finding, Grade, PackReport, Severity};`
//! and nothing else changes: the state machine only reads the fields mirrored here.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Severity of one finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Inventory only; never changes the grade.
    Info,
    /// Worth a look; the ceiling for anything found in documentation.
    Warn,
    /// A code/meta signal of risky behaviour: the pack is `unreviewed` until a person looks.
    High,
}

/// Where a finding was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ctx {
    /// Executable source.
    Code,
    /// Documentation.
    Doc,
    /// Pack structure.
    Meta,
}

/// One rule hit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// Stable rule id.
    pub rule: &'static str,
    /// Severity, already capped at WARN when `ctx` is [`Ctx::Doc`].
    pub sev: Severity,
    /// Path relative to the pack root.
    pub path: PathBuf,
    /// 1-based line, when the finding is line-addressable.
    pub line: Option<u32>,
    /// Context the finding was made in.
    pub ctx: Ctx,
}

impl Finding {
    /// Severity after the doc cap.
    pub fn effective_sev(&self) -> Severity {
        if self.ctx == Ctx::Doc {
            self.sev.min(Severity::Warn)
        } else {
            self.sev
        }
    }
}

/// A combination rule hit: the only source of [`Grade::Block`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ComboHit {
    /// Stable combo id.
    pub rule: &'static str,
    /// Pack-relative path of the anchoring file.
    pub path: PathBuf,
    /// 1-based line of the anchor, when line-addressable.
    pub line: Option<u32>,
    /// Ids of the signals that combined into this hit.
    pub parts: Vec<&'static str>,
}

/// Everything one pack scan produced.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PackReport {
    /// Per-file findings, in walk order.
    pub findings: Vec<Finding>,
    /// Pack-level combination hits.
    pub combos: Vec<ComboHit>,
}

/// Pack-level verdict (spec D2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Grade {
    /// Nothing above INFO.
    Clean,
    /// Warnings only.
    Warn,
    /// At least one code/meta HIGH.
    High,
    /// A combination rule fired.
    Block,
}

/// Grade a pack report: any combo → `Block`; else the worst effective severity.
pub fn grade(report: &PackReport) -> Grade {
    if !report.combos.is_empty() {
        return Grade::Block;
    }
    match report.findings.iter().map(Finding::effective_sev).max() {
        Some(Severity::High) => Grade::High,
        Some(Severity::Warn) => Grade::Warn,
        _ => Grade::Clean,
    }
}

/// Scan one pack (a directory, or a single file) with the line heuristics.
pub fn scan_pack(root: &Path) -> PackReport {
    let findings = super::heuristics::scan(root)
        .findings
        .into_iter()
        .map(|f| {
            let ctx = if is_doc(&f.path) { Ctx::Doc } else { Ctx::Code };
            let sev = match f.severity {
                super::Severity::High => Severity::High,
                super::Severity::Medium => Severity::Warn,
                super::Severity::Low => Severity::Info,
            };
            let sev = if ctx == Ctx::Doc {
                sev.min(Severity::Warn)
            } else {
                sev
            };
            Finding {
                rule: rule_id(&f.kind),
                sev,
                path: PathBuf::from(&f.path),
                line: u32::try_from(f.line).ok().filter(|l| *l > 0),
                ctx,
            }
        })
        .collect();
    PackReport {
        findings,
        combos: symlink_escapes(root),
    }
}

/// A `symlink_escape` combo for every symlink in the pack whose target, resolved lexically
/// against the link's dir, leaves the pack (as WS-D2's `symlink_escape` rule does). Links are
/// never followed.
fn symlink_escapes(root: &Path) -> Vec<ComboHit> {
    let mut hits = Vec::new();
    let walker = walkdir::WalkDir::new(root)
        .follow_links(false)
        .min_depth(1)
        .into_iter()
        .filter_entry(|e| !(e.depth() == 1 && e.file_name() == ".git"));
    for entry in walker.flatten() {
        if !entry.path_is_symlink() {
            continue;
        }
        let Ok(target) = std::fs::read_link(entry.path()) else {
            continue;
        };
        let base = entry.path().parent().unwrap_or(root);
        let resolved = lexical(&base.join(&target));
        if !resolved.starts_with(lexical(root)) {
            hits.push(ComboHit {
                rule: "symlink_escape",
                path: entry
                    .path()
                    .strip_prefix(root)
                    .unwrap_or(entry.path())
                    .to_path_buf(),
                line: None,
                parts: vec!["symlink"],
            });
        }
    }
    hits
}

/// `path` with `.` and `..` removed without touching the filesystem.
fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// Markdown and plain-text files are documentation.
fn is_doc(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [".md", ".mdx", ".markdown", ".txt", ".rst"]
        .iter()
        .any(|ext| lower.ends_with(ext))
}

/// The static id of a heuristic kind.
fn rule_id(kind: &str) -> &'static str {
    const KNOWN: &[&str] = &[
        "broad_permissions",
        "download_and_run",
        "embedded_secret_key",
        "eval",
        "hidden_instruction",
        "install_hook",
        "prompt_injection",
        "secret_read",
        "telemetry_post",
        "todo_secret",
        "unicode_obfuscation",
        "unpinned_npx",
    ];
    KNOWN
        .iter()
        .copied()
        .find(|k| *k == kind)
        .unwrap_or("heuristic")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(sev: Severity, ctx: Ctx) -> Finding {
        Finding {
            rule: "x",
            sev,
            path: PathBuf::from("a"),
            line: Some(1),
            ctx,
        }
    }

    #[test]
    fn docs_are_capped_at_warn() {
        let report = PackReport {
            findings: vec![finding(Severity::High, Ctx::Doc)],
            combos: vec![],
        };
        assert_eq!(grade(&report), Grade::Warn);
    }

    #[test]
    fn a_code_high_grades_high_and_a_combo_blocks() {
        let mut report = PackReport {
            findings: vec![finding(Severity::High, Ctx::Code)],
            combos: vec![],
        };
        assert_eq!(grade(&report), Grade::High);
        report.combos.push(ComboHit {
            rule: "padding_sink",
            path: PathBuf::from("a"),
            line: None,
            parts: vec![],
        });
        assert_eq!(grade(&report), Grade::Block);
        assert_eq!(grade(&PackReport::default()), Grade::Clean);
    }

    #[test]
    fn adapter_classifies_markdown_as_doc_and_scripts_as_code() {
        let dir = std::env::temp_dir().join(format!("ssai-grading-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("SKILL.md"), "cat ~/.config/solana/id.json\n").unwrap();
        std::fs::write(dir.join("run.sh"), "cat ~/.config/solana/id.json\n").unwrap();
        let report = scan_pack(&dir);
        let md = report
            .findings
            .iter()
            .find(|f| f.path == Path::new("SKILL.md"))
            .unwrap();
        let sh = report
            .findings
            .iter()
            .find(|f| f.path == Path::new("run.sh"))
            .unwrap();
        assert_eq!(
            (md.ctx, md.sev, md.rule),
            (Ctx::Doc, Severity::Warn, "secret_read")
        );
        assert_eq!(
            (sh.ctx, sh.sev, sh.line),
            (Ctx::Code, Severity::High, Some(1))
        );
        assert_eq!(grade(&report), Grade::High);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
