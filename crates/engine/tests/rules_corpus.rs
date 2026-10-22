//! Acceptance corpus for the rule engine (spec D2.10).
//!
//! * `shapes/` — re-synthesised malicious shapes (Trail of Bits ×4, the #10 stealer, the scanner
//!   research demo, harness bypass, bang exfil) must BLOCK; Google's `exec(base64.b64decode(…))`
//!   must stay in the warning tier. Each shape is a directory of inert data files plus a
//!   `shape.json` naming what the test materialises in a temp copy (binary magic, symlinks, exec
//!   bits, and template dirs renamed to names the repo ignores, e.g. `dot-claude` → `.claude`).
//! * `aikit.manifest.tsv` — the ai-kit packs at a pinned commit. Opt-in only
//!   (`SAFE_AI_SKILL_CORPUS=1`): the corpus is fetched (or read from `SAFE_AI_SKILL_CORPUS_DIR`),
//!   every pack SHA is checked, and the run asserts 0 BLOCK, at most 14 HIGH, and each pack's
//!   expected grade. Release builds also assert the scan stays under 5 s (the faster of two
//!   passes, so a cold page cache does not count against it).

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use common::TempDir;
use safe_ai_skill::verify::rules::{self, Grade, PackReport};
use serde_json::Value;

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/corpus")
}

fn grade_name(g: Grade) -> &'static str {
    match g {
        Grade::Clean => "clean",
        Grade::Warn => "warn",
        Grade::High => "high",
        Grade::Block => "block",
    }
}

/// Copy `src` into `dst`, skipping `shape.json`.
fn copy_tree(src: &Path, dst: &Path) {
    for entry in walkdir::WalkDir::new(src).into_iter().flatten() {
        let rel = entry.path().strip_prefix(src).unwrap();
        if rel.as_os_str().is_empty() || rel == Path::new("shape.json") {
            continue;
        }
        let to = dst.join(rel);
        if entry.file_type().is_dir() {
            std::fs::create_dir_all(&to).unwrap();
        } else {
            std::fs::create_dir_all(to.parent().unwrap()).unwrap();
            std::fs::copy(entry.path(), &to).unwrap();
        }
    }
}

/// Inert bytes with the requested magic.
fn magic_bytes(kind: &str, body: &str) -> Vec<u8> {
    let mut b: Vec<u8> = match kind {
        "zip" => b"PK\x03\x04\x0a\x00\x00\x00\x00\x00".to_vec(),
        "pyc" => {
            b"\xa7\x0d\x0d\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe3\x00".to_vec()
        }
        "elf-x86_64" => {
            let mut e = vec![0u8; 64];
            e[..4].copy_from_slice(b"\x7fELF");
            e[4] = 2;
            e[5] = 1;
            e[18..20].copy_from_slice(&62u16.to_le_bytes());
            e
        }
        other => panic!("unknown magic {other}"),
    };
    b.extend_from_slice(body.as_bytes());
    b.push(0);
    b
}

/// Lay a shape out in `dst` and apply its `shape.json` materialisation.
fn materialise(shape_dir: &Path, spec: &Value, dst: &Path) {
    copy_tree(shape_dir, dst);
    for pair in spec["rename"].as_array().into_iter().flatten() {
        let from = dst.join(pair[0].as_str().unwrap());
        let to = dst.join(pair[1].as_str().unwrap());
        std::fs::rename(from, to).unwrap();
    }
    for bin in spec["binaries"].as_array().into_iter().flatten() {
        let path = dst.join(bin["path"].as_str().unwrap());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let bytes = magic_bytes(
            bin["magic"].as_str().unwrap(),
            bin["body"].as_str().unwrap_or(""),
        );
        std::fs::write(path, bytes).unwrap();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for link in spec["symlinks"].as_array().into_iter().flatten() {
            let path = dst.join(link[0].as_str().unwrap());
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(link[1].as_str().unwrap(), path).unwrap();
        }
        for rel in spec["exec"].as_array().into_iter().flatten() {
            let path = dst.join(rel.as_str().unwrap());
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
}

fn scan_shape(name: &str) -> (Value, PackReport) {
    let shape_dir = corpus_dir().join("shapes").join(name);
    let spec: Value =
        serde_json::from_str(&std::fs::read_to_string(shape_dir.join("shape.json")).unwrap())
            .unwrap();
    let tmp = TempDir::new("shape");
    let pack = tmp.join(name);
    materialise(&shape_dir, &spec, &pack);
    let report = rules::scan_pack(&pack);
    (spec, report)
}

fn shape_names() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(corpus_dir().join("shapes"))
        .unwrap()
        .flatten()
        .filter(|e| e.path().join("shape.json").is_file())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn every_shape_grades_as_declared() {
    let names = shape_names();
    assert!(names.len() >= 9, "shape fixtures missing: {names:?}");
    let mut failures = Vec::new();
    for name in &names {
        let (spec, report) = scan_shape(name);
        let got = grade_name(rules::grade(&report));
        let want = spec["expect"].as_str().unwrap();
        if got != want {
            failures.push(format!("{name}: graded {got}, expected {want}: {report:?}"));
            continue;
        }
        for c in spec["combos"].as_array().into_iter().flatten() {
            let c = c.as_str().unwrap();
            if !report.combos.iter().any(|h| h.rule == c) {
                failures.push(format!("{name}: missing combo {c}: {:?}", report.combos));
            }
        }
        for f in spec["findings"].as_array().into_iter().flatten() {
            let rule = f["rule"].as_str().unwrap();
            let path = PathBuf::from(f["path"].as_str().unwrap());
            let line = f["line"].as_u64().map(|l| l as u32);
            if !report
                .findings
                .iter()
                .any(|x| x.rule == rule && x.path == path && x.line == line)
            {
                failures.push(format!("{name}: missing {rule} at {path:?}:{line:?}"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn malicious_shapes_block_and_google_stays_in_the_warning_tier() {
    for name in [
        "tob-csv-summarizer",
        "tob-context-loader",
        "tob-simple-formatter",
        "tob-dev-env-setup",
        "issue10-stealer",
    ] {
        let (_, report) = scan_shape(name);
        assert_eq!(rules::grade(&report), Grade::Block, "{name}: {report:?}");
    }
    let (_, google) = scan_shape("google-exec-b64");
    assert!(google.combos.is_empty(), "{google:?}");
    assert!(rules::grade(&google) < Grade::Block);
    assert!(rules::grade(&google) >= Grade::Warn);
}

// ---------------------------------------------------------------------------------------
// ai-kit corpus (opt-in).
// ---------------------------------------------------------------------------------------

struct Manifest {
    repo: String,
    commit: String,
    packs_dir: String,
    rows: Vec<(String, String, String)>,
}

fn manifest() -> Manifest {
    let text = std::fs::read_to_string(corpus_dir().join("aikit.manifest.tsv")).unwrap();
    let mut m = Manifest {
        repo: String::new(),
        commit: String::new(),
        packs_dir: String::new(),
        rows: Vec::new(),
    };
    for line in text.lines() {
        let cols: Vec<&str> = line.split('\t').collect();
        match cols.as_slice() {
            ["# repo", v] => m.repo = v.to_string(),
            ["# commit", v] => m.commit = v.to_string(),
            ["# packs", v] => m.packs_dir = v.to_string(),
            [pack, sha, expected, _] if *pack != "pack" && !pack.starts_with('#') => {
                m.rows
                    .push((pack.to_string(), sha.to_string(), expected.to_string()))
            }
            _ => {}
        }
    }
    m
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .expect("git");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// The ai-kit checkout: `SAFE_AI_SKILL_CORPUS_DIR`, or a clone at the pinned commit under
/// `target/corpus/` (fetched once, then reused).
fn corpus_root(m: &Manifest) -> PathBuf {
    if let Some(dir) = std::env::var_os("SAFE_AI_SKILL_CORPUS_DIR") {
        return PathBuf::from(dir);
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target/corpus")
        .join(format!("ai-kit-{}", &m.commit[..12]));
    if !root.join(&m.packs_dir).is_dir() {
        std::fs::create_dir_all(root.parent().unwrap()).unwrap();
        let status = Command::new("git")
            .args(["clone", "--filter=blob:none", &m.repo])
            .arg(&root)
            .status()
            .expect("git clone");
        assert!(status.success(), "clone of {} failed", m.repo);
        git(&root, &["checkout", "--quiet", &m.commit]);
        let mut args = vec!["submodule", "update", "--init", "--"];
        let paths: Vec<String> = m
            .rows
            .iter()
            .map(|(p, _, _)| format!("{}/{p}", m.packs_dir))
            .collect();
        args.extend(paths.iter().map(String::as_str));
        git(&root, &args);
    }
    root
}

#[test]
fn aikit_corpus_acceptance() {
    if std::env::var("SAFE_AI_SKILL_CORPUS").as_deref() != Ok("1") {
        eprintln!("aikit_corpus_acceptance: skipped (set SAFE_AI_SKILL_CORPUS=1 to run)");
        return;
    }
    let m = manifest();
    assert_eq!(m.rows.len(), 46, "manifest rows");
    let root = corpus_root(&m);
    // SAFE_AI_SKILL_CORPUS_VERBOSE=1 lists every combo, HIGH and WARN finding (calibration aid).
    let verbose = std::env::var("SAFE_AI_SKILL_CORPUS_VERBOSE").as_deref() == Ok("1");

    let mut mismatches = Vec::new();
    let mut highs = Vec::new();
    let mut blocks = Vec::new();
    let mut elapsed = Duration::ZERO;
    for (pack, sha, expected) in &m.rows {
        let dir = root.join(&m.packs_dir).join(pack);
        assert_eq!(
            &git(&dir, &["rev-parse", "HEAD"]),
            sha,
            "{pack} is not at its pin"
        );
        let start = Instant::now();
        let report = rules::scan_pack(&dir);
        let took = start.elapsed();
        elapsed += took;
        let got = grade_name(rules::grade(&report));
        eprintln!(
            "{pack:24} {got:6} {:>5} findings {took:>10.1?}",
            report.findings.len()
        );
        if verbose {
            for c in &report.combos {
                eprintln!("    combo {} at {}:{:?}", c.rule, c.path.display(), c.line);
            }
            for f in report
                .findings
                .iter()
                .filter(|f| f.effective_sev() >= rules::Severity::Warn)
            {
                let sev = if f.effective_sev() == rules::Severity::High {
                    "high"
                } else {
                    "warn"
                };
                eprintln!(
                    "    {sev:5} {} at {}:{:?}",
                    f.rule,
                    f.path.display(),
                    f.line
                );
            }
        }
        match rules::grade(&report) {
            Grade::Block => blocks.push(format!("{pack}: {:?}", report.combos)),
            Grade::High => {
                let why: Vec<String> = report
                    .findings
                    .iter()
                    .filter(|f| f.effective_sev() == rules::Severity::High)
                    .take(3)
                    .map(|f| format!("{}@{}:{}", f.rule, f.path.display(), f.line.unwrap_or(0)))
                    .collect();
                highs.push(format!("{pack}: {}", why.join(", ")));
            }
            _ => {}
        }
        if got != expected {
            mismatches.push(format!("{pack}: graded {got}, manifest expects {expected}"));
        }
    }
    eprintln!("scan time for {} packs: {elapsed:?}", m.rows.len());
    // The first pass reads a possibly cold page cache (a fresh clone, or a rebuild that evicted
    // it); the budget is for scanning, so the faster of two passes is what gets asserted.
    let rescan = Instant::now();
    for (pack, _, _) in &m.rows {
        rules::scan_pack(&root.join(&m.packs_dir).join(pack));
    }
    let warm = rescan.elapsed();
    eprintln!("warm rescan: {warm:?}");
    let best = elapsed.min(warm);
    eprintln!("HIGH packs ({}):\n  {}", highs.len(), highs.join("\n  "));
    assert!(
        blocks.is_empty(),
        "ai-kit packs must not BLOCK:\n{}",
        blocks.join("\n")
    );
    assert!(highs.len() <= 14, "too many HIGH packs ({})", highs.len());
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    if !cfg!(debug_assertions) {
        assert!(
            best < Duration::from_secs(5),
            "corpus scan took {elapsed:?} (warm rescan {warm:?})"
        );
    }
}
