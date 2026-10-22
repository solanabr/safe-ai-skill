//! Evasion regressions for the rule engine: every shape from the WS-D2 review probe
//! (`examples/evade.rs`) with the verdict it must get.

mod common;

use common::TempDir;
use safe_ai_skill::verify::rules::{self, Grade, PackReport};

fn b64(s: &str) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = s.as_bytes();
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for k in 0..4 {
            if k <= c.len() {
                out.push(A[((n >> (18 - 6 * k)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Inert base64 payload (decodes to a `console.log`).
fn payload() -> String {
    b64(&"console.log('inert fixture: nothing to see');".repeat(3))
}

/// Lay out a pack from `(path, bytes)` files and unix symlinks, then scan it.
fn scan(files: &[(&str, Vec<u8>)], links: &[(&str, &str)]) -> PackReport {
    let tmp = TempDir::new("evasion");
    for (rel, body) in files {
        let p = tmp.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, body).unwrap();
    }
    #[cfg(unix)]
    for (rel, target) in links {
        let p = tmp.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(target, &p).unwrap();
    }
    #[cfg(not(unix))]
    let _ = links;
    rules::scan_pack(tmp.path())
}

fn text(rel: &str, body: String) -> (&str, Vec<u8>) {
    (rel, body.into_bytes())
}

#[track_caller]
fn assert_blocks(r: &PackReport, combo: &str) {
    assert_eq!(rules::grade(r), Grade::Block, "{r:?}");
    assert!(
        r.combos.iter().any(|c| c.rule == combo),
        "missing {combo}: {r:?}"
    );
}

// ---------------------------------------------------------------------------------------
// Lexer: interpolations are code, regex literals and line breaks do not hide code.
// ---------------------------------------------------------------------------------------

#[test]
fn baseline_eval_over_base64_blocks() {
    let r = scan(
        &[text("w.js", format!("eval(atob('{}'))\n", payload()))],
        &[],
    );
    assert_blocks(&r, "exec_b64_literal");
}

#[test]
fn js_template_interpolation_is_code() {
    let r = scan(
        &[text(
            "w.js",
            format!("const r = `${{eval(atob('{}'))}}`;\n", payload()),
        )],
        &[],
    );
    assert_blocks(&r, "exec_b64_literal");
}

#[test]
fn python_fstring_interpolation_is_code() {
    let body = format!(
        "import base64\nr = f\"{{exec(base64.b64decode('{}'))}}\"\n",
        payload()
    );
    assert_blocks(&scan(&[text("w.py", body)], &[]), "exec_b64_literal");
}

#[test]
fn regex_literal_quote_does_not_open_a_string() {
    let body = format!("/'/; eval(atob('{}'))\n", payload());
    assert_blocks(&scan(&[text("w.js", body)], &[]), "exec_b64_literal");
}

#[test]
fn star_led_line_outside_a_block_comment_is_code() {
    let body = format!("const y = 2\n*eval(atob('{}'))\n", payload());
    assert_blocks(&scan(&[text("w.js", body)], &[]), "exec_b64_literal");
}

#[test]
fn lone_carriage_return_ends_a_comment() {
    let js = format!("// note\reval(atob('{}'))\n", payload());
    assert_blocks(&scan(&[text("w.js", js)], &[]), "exec_b64_literal");
    let py = format!(
        "import base64\n# note\rexec(base64.b64decode('{}'))\n",
        payload()
    );
    assert_blocks(&scan(&[text("w.py", py)], &[]), "exec_b64_literal");
}

#[test]
fn unicode_line_separator_ends_a_comment() {
    let js = format!("// note\u{2028}eval(atob('{}'))\n", payload());
    assert_blocks(&scan(&[text("w.js", js)], &[]), "exec_b64_literal");
}

#[test]
fn padding_with_a_sink_in_a_template_blocks() {
    let pad = " ".repeat(200);
    assert_blocks(
        &scan(&[text("w.js", format!("x();{pad}eval(atob(s))\n"))], &[]),
        "padding_sink",
    );
    assert_blocks(
        &scan(
            &[text("w.js", format!("x();{pad}`${{eval(atob(s))}}`\n"))],
            &[],
        ),
        "padding_sink",
    );
}

#[test]
fn a_real_base64_payload_beside_a_quoted_sink_still_blocks() {
    let body = format!("const s = \"eval(atob('{}'))\";\n", payload());
    assert_blocks(&scan(&[text("w.js", body)], &[]), "exec_b64_literal");
}
