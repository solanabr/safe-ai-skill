//! The rules over one in-memory file: a blob read from a pack's git history (#10).
//!
//! Same rules, caps and line-local combos as a file on disk. Combos that need other files of
//! the pack (a `!`cmd`` running a pack script, a `.pyc` beside its `.py`, SKILL.md references)
//! see only this blob.

use std::path::Path;
use std::time::Instant;

use super::binary_magic::{self, Content};
use super::context::{self, FileClass};
use super::{
    combo, scan_body, scan_name, FileBody, FileOut, PackFacts, PackReport, RuleCount,
    MAX_HITS_PER_RULE, MAX_SCAN_BYTES, SNIFF_BYTES,
};

/// A [`scan_blob`] result.
pub struct BlobScan {
    pub report: PackReport,
    /// The deadline cut the scan short.
    pub expired: bool,
}

/// Scan `bytes` as the file `rel` (with the exec bit when `executable`), stopping at `deadline`.
pub fn scan_blob(
    rel: &Path,
    bytes: &[u8],
    executable: bool,
    deadline: Option<Instant>,
) -> BlobScan {
    let mut facts = PackFacts::default();
    facts.files.insert(rel.to_path_buf());
    let mut out = FileOut::new(rel);
    out.deadline = deadline;
    let settings = scan_name(rel, executable, &mut out);
    let cap = usize::try_from(MAX_SCAN_BYTES).unwrap_or(usize::MAX);
    let head = &bytes[..bytes.len().min(SNIFF_BYTES as usize)];
    let content = binary_magic::scan(rel, head, &mut out, &mut facts);
    if content != Content::Binary {
        let body = FileBody {
            buf: &bytes[..bytes.len().min(cap)],
            content,
            size: bytes.len() as u64,
            cap: MAX_SCAN_BYTES,
            executable,
            settings,
        };
        scan_body(rel, &body, &mut out, &mut facts);
    }
    out.signals.seal();
    let expired = out.expired;
    let outs = [out];
    let combos = combo::evaluate(&outs, &facts);
    let [out] = outs;
    let capped = out
        .hits
        .iter()
        .filter(|&&(_, n)| n > MAX_HITS_PER_RULE)
        .map(|&(rule, hits)| RuleCount {
            rule,
            path: out.path.clone(),
            hits,
        })
        .collect();
    BlobScan {
        report: PackReport {
            findings: out.findings,
            combos,
            capped,
        },
        expired,
    }
}

/// True when a file at `rel` is executable source by its name or exec bit (no shebang check).
pub fn is_code_path(rel: &Path, executable: bool) -> bool {
    matches!(context::classify(rel, "", executable), FileClass::Code(_))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::rules::{grade, scan_pack, Grade};

    #[test]
    fn a_blob_grades_like_the_same_file_on_disk() {
        let src = format!(
            "export const x = 1;{}eval(atob('{}'))\n",
            " ".repeat(500),
            "QUJD".repeat(40)
        );
        let blob = scan_blob(Path::new("src/watch.js"), src.as_bytes(), false, None);
        assert_eq!(grade(&blob.report), Grade::Block);
        assert!(!blob.expired);

        let dir = std::env::temp_dir().join(format!("blob-eq-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/watch.js"), &src).unwrap();
        let disk = scan_pack(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(disk.findings, blob.report.findings);
        assert_eq!(disk.combos, blob.report.combos);
    }

    #[test]
    fn code_paths_by_name_and_mode() {
        assert!(is_code_path(Path::new("a/b.ts"), false));
        assert!(is_code_path(Path::new("run"), true));
        assert!(!is_code_path(Path::new("README.md"), true));
        assert!(!is_code_path(Path::new("notes"), false));
    }
}
