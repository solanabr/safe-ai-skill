//! Scan-budget regressions: every performance probe from the WS-D2 round-2 review (`evade2.rs`
//! perf cases and `perf2.rs`). Each crafted file must come back within the pack budget (plus
//! slack for reading and splitting the file), and a pack cut short must never grade clean.
//!
//! Release builds use the review's full 16 MiB bodies; debug builds use 256 KiB so the default
//! `cargo test` stays fast. Runs are serialised: several 16 MiB bodies at once would cost GBs.

mod common;

use std::sync::Mutex;
use std::time::{Duration, Instant};

use common::TempDir;
use safe_ai_skill::verify::rules::{self, Grade, ScanBudget, PACK_BUDGET};

/// Body size: the review's 16 MiB in release builds.
const SIZE: usize = if cfg!(debug_assertions) {
    256 * 1024
} else {
    16 * 1024 * 1024 - 64
};
/// Reading, decoding and splitting a 16 MiB file is not interruptible.
const SLACK: Duration = Duration::from_secs(3);

static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn within_budget(name: &str, rel: &str, body: String) {
    let _turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = TempDir::new("perf");
    let path = tmp.join(rel);
    std::fs::write(&path, body).unwrap();
    let budget = ScanBudget::new(PACK_BUDGET, PACK_BUDGET);
    let started = Instant::now();
    let r = rules::scan_pack_within(tmp.path(), &budget);
    let took = started.elapsed();
    let cut = r.findings.iter().any(|f| f.rule == "scan_budget_exceeded");
    eprintln!(
        "{name:24} {took:>10.1?} cut={cut} grade={:?}",
        rules::grade(&r)
    );
    assert!(took < PACK_BUDGET + SLACK, "{name}: {took:?}");
    if cut {
        assert!(rules::grade(&r) >= Grade::High, "{name}: {r:?}");
    }
}

macro_rules! shapes {
    ($($name:ident: $rel:expr => $body:expr;)*) => {
        $(
            #[test]
            fn $name() {
                within_budget(stringify!($name), $rel, $body);
            }
        )*
    };
}

fn fill(unit: &str) -> String {
    unit.repeat(SIZE / unit.len())
}

fn led(lead: &str, unit: &str) -> String {
    let mut s = String::from(lead);
    s.push_str(&unit.repeat(SIZE / unit.len()));
    s
}

shapes! {
    // evade2.rs perf cases
    dollar_brace_js: "a.js" => fill("${");
    backtick_dollar_brace: "a.js" => led("`", "${`");
    block_open_js: "a.js" => fill("/*");
    slash_js: "a.js" => fill("/");
    slash_space_js: "a.js" => fill("x / ");
    regex_open_lines: "a.js" => fill("=/\n");
    regex_open_oneline: "a.js" => fill("(/");
    quote_js: "a.js" => fill("'");
    fbrace_py: "a.py" => led("f'", "{f'");
    triple_py: "a.py" => fill("f\"\"\"{");
    shell_dollar_paren: "a.sh" => led("\"", "$(\"");
    open_paren_js: "a.js" => fill("(");
    md_backticks: "a.md" => fill("`");
    md_fences: "a.md" => fill("```\n");
    pkg_json_strings: "package.json" => led("{", "\"a\":\"\\u");
    semicolons_eval: "a.js" => fill("eval(x);");
    long_line_a: "a.js" => fill("a");
    b64_long: "a.js" => {
        let mut s = String::from("eval(atob('");
        s.push_str(&"QUFB".repeat(SIZE / 4 - 8));
        s.push_str("'))");
        s
    };
    // perf2.rs
    semicolons_x: "a.js" => fill("x(y);");
    newline_eval: "a.js" => fill("eval(x)\n");
    sh_semicolon_curl: "a.sh" => fill("curl x;");
    md_eval: "a.md" => fill("eval(x); ");
    tpl_multiline: "a.js" => fill("`${\n0}`;\n");
}
