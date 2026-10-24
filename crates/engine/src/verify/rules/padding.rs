//! Padding detectors (spec D2.4/D2.5): horizontal whitespace runs and vertical blank-line runs
//! that push a payload out of view, plus long-line inventory with the printable-ratio split
//! between base64 data (INFO) and encoded text (WARN).

use super::context::{self, Document, FileClass, Role};
use super::{line_no, Ctx, FileOut, Severity, Signal};

/// Whitespace run that pushes the rest of a line out of view (spec D2.4).
const HORIZONTAL_RUN: usize = 100;
/// Blank lines that push what follows out of view (spec D2.4).
const VERTICAL_RUN: usize = 50;
/// Lines longer than this are inventoried (issue #10: ~500).
const LONG_LINE: usize = 500;
/// Base64 run inside a long line worth decoding.
const LONG_B64_RUN: usize = 256;
/// Decoded printable ratio at or above which a run is encoded text, not data. Spec D2.5 puts
/// data below ~0.4; random bytes sit near 0.38, so text is only claimed well above that.
const TEXT_RATIO: f64 = 0.75;

pub(super) fn scan(doc: &Document<'_>, out: &mut FileOut) {
    // Data files (JSON, YAML, terminal captures …) pad for alignment and are never run or read
    // as instructions: padding is checked in code, Markdown and metadata only.
    if doc.class == FileClass::Doc {
        return;
    }
    let mut blank_start: Option<usize> = None;
    for i in 0..doc.len() {
        let line = doc.line(i);
        let blank = if line.is_ascii() {
            line.bytes().all(|b| b == b' ' || b == b'\t')
        } else {
            line.chars().all(is_blank)
        };
        if blank {
            blank_start.get_or_insert(i);
            continue;
        }
        if let Some(start) = blank_start.take() {
            if i - start >= VERTICAL_RUN {
                let ctx = doc.ctx(start);
                out.emit(
                    "padding_vertical",
                    Severity::High,
                    Some(line_no(start)),
                    ctx,
                );
                out.signal(Signal::PadV(line_no(i)), ctx);
            }
        }
        let ctx = doc.ctx(i);
        // A Markdown table pads cells for alignment, and renders them anyway.
        let table_row = doc.role(i) == Role::Prose && line.trim_start().starts_with('|');
        if !table_row && line.len() > HORIZONTAL_RUN && longest_blank_run(line) >= HORIZONTAL_RUN {
            out.emit("padding_horizontal", Severity::High, Some(line_no(i)), ctx);
            out.signal(Signal::PadH(line_no(i)), ctx);
        }
        if ctx == Ctx::Code && line.len() > LONG_LINE {
            if encoded_text(line) {
                out.emit("encoded_blob", Severity::Warn, Some(line_no(i)), ctx);
            } else {
                out.emit("long_line", Severity::Info, Some(line_no(i)), ctx);
            }
        }
    }
}

/// Space, tab, Unicode space separators (Zs) and the fillers that render blank.
fn is_blank(c: char) -> bool {
    matches!(
        c,
        ' ' | '\t' | '\u{00A0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200A}'
                | '\u{202F}'
                | '\u{205F}'
                | '\u{3000}'
                | '\u{115F}'
                | '\u{1160}'
                | '\u{2800}'
                | '\u{3164}'
                | '\u{FFA0}'
    )
}

/// Longest blank run followed by visible text on the same line.
fn longest_blank_run(line: &str) -> usize {
    let mut best = 0;
    let mut run = 0;
    if line.is_ascii() {
        for b in line.bytes() {
            if b == b' ' || b == b'\t' {
                run += 1;
            } else {
                best = best.max(run);
                run = 0;
            }
        }
        return best;
    }
    for c in line.chars() {
        if is_blank(c) {
            run += 1;
        } else {
            best = best.max(run);
            run = 0;
        }
    }
    best
}

/// True when the line's longest base64 run decodes to text (embedded encoded code or config).
fn encoded_text(line: &str) -> bool {
    let b = line.as_bytes();
    let (mut best_start, mut best_len, mut start) = (0, 0, 0);
    for (i, &c) in b.iter().enumerate() {
        if !context::is_b64_byte(c) {
            if i - start > best_len {
                best_start = start;
                best_len = i - start;
            }
            start = i + 1;
        }
    }
    if b.len() - start > best_len {
        best_start = start;
        best_len = b.len() - start;
    }
    if best_len < LONG_B64_RUN {
        return false;
    }
    let run = &line[best_start..best_start + best_len];
    if context::is_hex(run.trim_end_matches('=')) {
        return false;
    }
    context::b64_decode(run.as_bytes())
        .is_some_and(|bytes| context::printable_ratio(&bytes) >= TEXT_RATIO)
}

#[cfg(test)]
mod tests {
    use super::super::testkit::*;
    use super::super::{grade, Ctx, Grade, Severity};

    #[test]
    fn horizontal_run_in_code_is_high() {
        let line = format!("}});{}doSomething()", " ".repeat(120));
        let r = scan_one("src/watch.js", &format!("const a = 1;\n{line}\n"));
        let f = hits(&r, "padding_horizontal");
        assert_eq!(f.len(), 1, "{r:?}");
        assert_eq!(
            (f[0].sev, f[0].ctx, f[0].line),
            (Severity::High, Ctx::Code, Some(2))
        );
    }

    #[test]
    fn unicode_space_and_tab_runs_count() {
        let em = "\u{2003}".repeat(60);
        let tabs = "\t".repeat(40);
        let r = scan_one("a.py", &format!("x = 1{em}{tabs}y = 2\n"));
        assert!(has(&r, "padding_horizontal"), "{r:?}");
    }

    #[test]
    fn short_runs_and_trailing_whitespace_are_ignored() {
        let r = scan_one(
            "a.js",
            &format!("a(){}b()\nc();{}\n", " ".repeat(99), " ".repeat(300)),
        );
        assert!(!has(&r, "padding_horizontal"), "{r:?}");
    }

    #[test]
    fn markdown_padding_is_capped_at_warn() {
        let r = scan_one(
            "SKILL.md",
            &format!("# S\nSee{}hidden text\n", " ".repeat(150)),
        );
        let f = hits(&r, "padding_horizontal");
        assert_eq!(f.len(), 1, "{r:?}");
        assert_eq!(f[0].sev, Severity::Warn);
        assert_eq!(grade(&r), Grade::Warn);
    }

    #[test]
    fn table_rows_and_data_files_are_not_padding() {
        let row = format!("| Category        | Description{}|\n", " ".repeat(120));
        let r = scan_one("README.md", &format!("# T\n\n{row}"));
        assert!(!has(&r, "padding_horizontal"), "{r:?}");
        let cast = format!("[8.0, \"o\", \"x{}y\"]\n", " ".repeat(200));
        assert!(!has(&scan_one("demo.cast", &cast), "padding_horizontal"));
        assert!(!has(&scan_one("data.json", &cast), "padding_horizontal"));
    }

    #[test]
    fn vertical_run_in_code_is_high_at_run_start() {
        let body = format!("import os\n{}print(1)\n", "\n".repeat(60));
        let r = scan_one("s.py", &body);
        let f = hits(&r, "padding_vertical");
        assert_eq!(f.len(), 1, "{r:?}");
        assert_eq!((f[0].sev, f[0].line), (Severity::High, Some(2)));
    }

    #[test]
    fn short_vertical_runs_and_eof_runs_are_ignored() {
        let r = scan_one(
            "s.py",
            &format!("a = 1\n{}b = 2\n{}", "\n".repeat(49), "\n".repeat(80)),
        );
        assert!(!has(&r, "padding_vertical"), "{r:?}");
    }

    #[test]
    fn long_line_is_info_once_per_file() {
        let line = format!("var x=[{}];", "1,".repeat(400));
        let r = scan_one("min.js", &format!("{line}\n{line}\n"));
        let f = hits(&r, "long_line");
        assert_eq!(f.len(), 1, "{r:?}");
        assert_eq!(f[0].sev, Severity::Info);
        assert_eq!(grade(&r), Grade::Clean);
    }

    #[test]
    fn long_base64_of_binary_is_data_but_of_text_is_encoded_blob() {
        let binary: Vec<u8> = (0..600u32).map(|i| (i * 7 % 251) as u8).collect();
        let data = format!("const d = \"{}\";", b64(&binary));
        let r = scan_one("data.js", &data);
        assert!(has(&r, "long_line") && !has(&r, "encoded_blob"), "{r:?}");

        let text = "console.log('inert fixture text, nothing runs here');".repeat(12);
        let enc = format!("const t = \"{}\";", b64(text.as_bytes()));
        let r = scan_one("enc.js", &enc);
        let f = hits(&r, "encoded_blob");
        assert_eq!(f.len(), 1, "{r:?}");
        assert_eq!(f[0].sev, Severity::Warn);
    }

    /// Minimal base64 encoder for fixtures.
    fn b64(bytes: &[u8]) -> String {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::new();
        for c in bytes.chunks(3) {
            let n = (u32::from(c[0]) << 16)
                | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
                | u32::from(*c.get(2).unwrap_or(&0));
            for k in 0..4 {
                if k <= c.len() {
                    s.push(A[((n >> (18 - 6 * k)) & 63) as usize] as char);
                } else {
                    s.push('=');
                }
            }
        }
        s
    }
}
