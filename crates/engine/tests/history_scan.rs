//! #10: the git history of a pack is scanned at `verify add|check` from the object store
//! directly (loose objects and packfiles), never by running git.
//!
//! The fixtures are built with the `git` CLI in a temp dir (test setup only); every assertion
//! goes through the engine's own reader. Suites skip when `git` is not installed.

mod common;

use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use common::{Invocation, TempDir};
use safe_ai_skill::verify::gitobj::{self, Budget, Kind, Limits, Repo, Store};
use safe_ai_skill::verify::history::{self, HistoryReport};
use safe_ai_skill::verify::rules::{self, Grade};

fn have_git() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Run git for fixture setup, isolated from the user's config.
fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "-c",
            "commit.gpgsign=false",
        ])
        .args([
            "-c",
            "init.defaultBranch=main",
            "-c",
            "core.hooksPath=/dev/null",
        ])
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_DATE", "1700000000 +0000")
        .env("GIT_COMMITTER_DATE", "1700000000 +0000")
        .output()
        .expect("run git");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A pack repo with a benign SKILL.md committed.
fn repo(tmp: &TempDir) -> std::path::PathBuf {
    let dir = tmp.join("pack");
    fs::create_dir_all(&dir).unwrap();
    git(&dir, &["init", "-q"]);
    fs::write(
        dir.join("SKILL.md"),
        "---\nname: stream\ndescription: d\n---\n# Stream\n",
    )
    .unwrap();
    git(&dir, &["add", "."]);
    git(&dir, &["commit", "-qm", "initial"]);
    dir
}

fn commit_all(dir: &Path, message: &str) {
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-qm", message]);
}

/// The #10 stealer shape: a padded `eval(atob(...))` after a closing brace.
fn stealer_line() -> String {
    format!(
        "}});{}eval(\"global.o='x';\"+atob('{}'))\n",
        " ".repeat(500),
        "Z2xvYmFsLnJlcXVpcmU9cmVxdWlyZTs=".repeat(4)
    )
}

/// Benign JS large enough that git stores later versions as deltas.
fn benign_js() -> String {
    (0..300)
        .map(|i| format!("export function f{i}(a) {{ return a + {i}; }}\n"))
        .collect()
}

fn check(dir: &Path) -> serde_json::Value {
    let tmp = TempDir::new("hist-check");
    let run = Invocation::new(&["verify", "check", dir.to_str().unwrap()])
        .plugin_data(tmp.path())
        .home(tmp.path())
        .run();
    run.json()
}

fn kinds(v: &serde_json::Value) -> Vec<String> {
    v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["kind"].as_str().unwrap().to_string())
        .collect()
}

fn history_paths(h: &HistoryReport) -> Vec<String> {
    h.report
        .findings
        .iter()
        .map(|f| f.path.display().to_string())
        .chain(h.report.combos.iter().map(|c| c.path.display().to_string()))
        .collect()
}

fn unlimited() -> Limits {
    Limits {
        max_bytes: u64::MAX,
        max_objects: u64::MAX,
        max_object: 16 * 1024 * 1024,
        deadline: Instant::now().checked_add(Duration::from_secs(60)),
    }
}

#[test]
fn a_payload_only_in_history_blocks_verify_check() {
    if !have_git() {
        return;
    }
    let tmp = TempDir::new("hist-loose");
    let dir = repo(&tmp);
    fs::create_dir_all(dir.join("src")).unwrap();
    fs::write(
        dir.join("src/watch.js"),
        format!("run(() => {{\n{}", stealer_line()),
    )
    .unwrap();
    commit_all(&dir, "feat: watcher");
    fs::remove_file(dir.join("src/watch.js")).unwrap();
    commit_all(&dir, "chore: drop watcher");

    // The checkout alone is clean.
    assert_eq!(rules::grade(&rules::scan_pack(&dir)), Grade::Clean);

    let h = history::scan(&dir);
    assert!(h.unscanned.is_empty(), "{:?}", h.unscanned);
    assert_eq!(rules::grade(&h.report), Grade::Block, "{:?}", h.report);
    assert!(
        h.report.combos.iter().any(
            |c| c.rule == "padding_sink" && c.path.to_string_lossy().ends_with(":src/watch.js")
        ),
        "{:?}",
        h.report.combos
    );

    let v = check(&dir);
    assert_eq!(v["verdict"], "block", "{v}");
    assert!(kinds(&v).iter().any(|k| k == "padding_sink"), "{v}");
}

#[test]
fn a_payload_in_a_delta_compressed_packfile_is_found() {
    if !have_git() {
        return;
    }
    let tmp = TempDir::new("hist-pack");
    let dir = repo(&tmp);
    fs::create_dir_all(dir.join("test")).unwrap();
    let base = benign_js();
    fs::write(dir.join("test/decode.test.js"), &base).unwrap();
    commit_all(&dir, "test: decoder");
    fs::write(
        dir.join("test/decode.test.js"),
        format!("{base}{}", stealer_line()),
    )
    .unwrap();
    commit_all(&dir, "test: more cases");
    fs::write(dir.join("test/decode.test.js"), format!("{base}// done\n")).unwrap();
    commit_all(&dir, "test: tidy");
    git(&dir, &["repack", "-adq", "--depth=50", "--window=50"]);
    git(&dir, &["prune-packed"]);
    let verify = git(&dir, &["verify-pack", "-v", &pack_idx(&dir)]);
    assert!(
        verify.contains("chain length"),
        "fixture has no deltas: {verify}"
    );

    let h = history::scan(&dir);
    assert!(h.unscanned.is_empty(), "{:?}", h.unscanned);
    assert_eq!(rules::grade(&h.report), Grade::Block, "{:?}", h.report);
    assert!(
        history_paths(&h)
            .iter()
            .any(|p| p.starts_with("git:") && p.ends_with(":test/decode.test.js")),
        "{:?}",
        history_paths(&h)
    );
}

fn pack_idx(dir: &Path) -> String {
    fs::read_dir(dir.join(".git/objects/pack"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "idx"))
        .expect("an idx")
        .to_string_lossy()
        .into_owned()
}

#[test]
fn the_reader_matches_git_for_every_object() {
    if !have_git() {
        return;
    }
    let tmp = TempDir::new("hist-cat");
    let dir = repo(&tmp);
    let base = benign_js();
    for i in 0..6 {
        fs::write(dir.join("lib.js"), format!("{base}// rev {i}\n")).unwrap();
        fs::write(dir.join(format!("n{i}.md")), format!("note {i}\n")).unwrap();
        commit_all(&dir, &format!("rev {i}"));
    }
    git(&dir, &["repack", "-adq", "--depth=50"]);
    // One more loose commit on top of the pack.
    fs::write(dir.join("lib.js"), "loose\n").unwrap();
    commit_all(&dir, "loose");

    let repo = Repo::open(&dir).unwrap().unwrap();
    let mut budget = Budget::new(unlimited());
    let mut store = Store::open(&repo, &mut budget);
    let ids = store.ids();
    let listed = git(&dir, &["cat-file", "--batch-all-objects", "--batch-check"]);
    assert_eq!(ids.len(), listed.lines().count());
    for id in ids {
        let hex = gitobj::hex(&id);
        let obj = store.read(&id, &mut budget).unwrap();
        let ty = match obj.kind {
            Kind::Commit => "commit",
            Kind::Tree => "tree",
            Kind::Blob => "blob",
            Kind::Tag => "tag",
        };
        let raw = Command::new("git")
            .args(["cat-file", ty, &hex])
            .current_dir(&dir)
            .output()
            .unwrap();
        assert_eq!(&*obj.data, &raw.stdout[..], "{ty} {hex}");
        let (kind, size) = store.info(&id, &mut budget).unwrap();
        assert_eq!((kind, size as usize), (obj.kind, obj.data.len()), "{hex}");
    }
    assert_eq!(
        repo.head(),
        gitobj::parse_hex(git(&dir, &["rev-parse", "HEAD"]).trim().as_bytes())
    );
}

#[test]
fn an_amended_away_payload_is_still_found() {
    if !have_git() {
        return;
    }
    let tmp = TempDir::new("hist-amend");
    let dir = repo(&tmp);
    fs::write(
        dir.join("run.js"),
        format!("go(() => {{\n{}", stealer_line()),
    )
    .unwrap();
    commit_all(&dir, "feat: runner");
    fs::write(dir.join("run.js"), "go(() => {});\n").unwrap();
    git(&dir, &["add", "-A"]);
    git(&dir, &["commit", "-q", "--amend", "-m", "feat: runner"]);
    git(&dir, &["reflog", "expire", "--expire=now", "--all"]);

    let h = history::scan(&dir);
    assert_eq!(rules::grade(&h.report), Grade::Block, "{:?}", h.report);
}

#[test]
fn checked_out_content_is_not_reported_twice() {
    if !have_git() {
        return;
    }
    let tmp = TempDir::new("hist-dup");
    let dir = repo(&tmp);
    fs::write(
        dir.join("run.js"),
        format!("go(() => {{\n{}", stealer_line()),
    )
    .unwrap();
    commit_all(&dir, "feat: runner");

    let h = history::scan(&dir);
    assert!(
        h.report.findings.is_empty() && h.report.combos.is_empty(),
        "{:?}",
        h.report
    );
    assert!(h.stats.in_checkout >= 2, "{:?}", h.stats);
    // A local edit of the checkout leaves the committed version in history: it is scanned.
    fs::write(dir.join("run.js"), "go(() => {});\n").unwrap();
    assert_eq!(rules::grade(&history::scan(&dir).report), Grade::Block);
}

#[test]
fn a_docs_commit_that_adds_code_is_flagged() {
    if !have_git() {
        return;
    }
    let tmp = TempDir::new("hist-docs");
    let dir = repo(&tmp);
    fs::write(dir.join("README.md"), "# Stream\n").unwrap();
    fs::create_dir_all(dir.join("examples")).unwrap();
    fs::write(dir.join("examples/watch.ts"), "export const x = 1;\n").unwrap();
    commit_all(&dir, "Update README.md");

    let h = history::scan(&dir);
    let f = h
        .report
        .findings
        .iter()
        .find(|f| f.rule == "docs_commit_code")
        .unwrap_or_else(|| panic!("{:?}", h.report));
    assert!(
        f.path.to_string_lossy().ends_with(":examples/watch.ts"),
        "{f:?}"
    );
    assert_eq!(rules::grade(&h.report), Grade::Warn);
    let v = check(&dir);
    // Report-only: shown, but it never holds `add`/`install`.
    assert_eq!(v["verdict"], "pass", "{v}");
    assert!(kinds(&v).iter().any(|k| k == "docs_commit_code"), "{v}");

    // An honest docs commit touching only docs is not flagged.
    let tmp2 = TempDir::new("hist-docs-ok");
    let ok = repo(&tmp2);
    fs::write(ok.join("README.md"), "# Stream\nmore\n").unwrap();
    fs::write(ok.join("run.sh"), "#!/bin/sh\necho hi\n").unwrap();
    commit_all(&ok, "feat: runner");
    fs::write(ok.join("README.md"), "# Stream\nfixed\n").unwrap();
    commit_all(&ok, "docs: fix typo");
    let h = history::scan(&ok);
    assert!(
        h.report
            .findings
            .iter()
            .all(|f| f.rule != "docs_commit_code"),
        "{:?}",
        h.report
    );
}

#[test]
fn a_docs_commit_that_slips_in_a_sink_blocks() {
    if !have_git() {
        return;
    }
    let tmp = TempDir::new("hist-docs-sink");
    let dir = repo(&tmp);
    fs::create_dir_all(dir.join("src")).unwrap();
    fs::write(dir.join("src/watch.js"), "export const x = 1;\n").unwrap();
    commit_all(&dir, "feat: watcher");
    fs::write(dir.join("README.md"), "# Stream\n").unwrap();
    // A single HIGH (reads the Solana keypair), still checked out: no history finding of its
    // own, but the docs commit that introduced it is the attack shape.
    fs::write(
        dir.join("src/watch.js"),
        "const fs = require('fs');\nconst k = fs.readFileSync(require('os').homedir() + '/.config/solana/id.json');\n",
    )
    .unwrap();
    commit_all(&dir, "Update README.md");
    assert_eq!(rules::grade(&rules::scan_pack(&dir)), Grade::High);

    let h = history::scan(&dir);
    let sink = h
        .report
        .combos
        .iter()
        .find(|c| c.rule == "docs_commit_sink")
        .unwrap_or_else(|| panic!("{:?}", h.report));
    assert!(
        sink.path.to_string_lossy().ends_with(":src/watch.js"),
        "{sink:?}"
    );
    assert_eq!(sink.parts, vec!["docs_commit_code", "secret_read"]);
    assert_eq!(check(&dir)["verdict"], "block");
}

#[test]
fn a_docs_commit_editing_around_an_existing_sink_does_not_block() {
    if !have_git() {
        return;
    }
    let tmp = TempDir::new("hist-docs-old-sink");
    let dir = repo(&tmp);
    fs::create_dir_all(dir.join("src")).unwrap();
    let body = "const fs = require('fs');\nconst k = fs.readFileSync(require('os').homedir() + '/.config/solana/id.json');\n";
    fs::write(
        dir.join("src/wallet.js"),
        format!("// loads the wallet\n{body}"),
    )
    .unwrap();
    commit_all(&dir, "feat: wallet");
    fs::write(
        dir.join("src/wallet.js"),
        format!("// Loads the CLI wallet keypair.\n{body}"),
    )
    .unwrap();
    commit_all(&dir, "docs: clarify wallet comment");

    let h = history::scan(&dir);
    assert!(
        h.report.combos.iter().all(|c| c.rule != "docs_commit_sink"),
        "{:?}",
        h.report
    );
    assert!(h
        .report
        .findings
        .iter()
        .any(|f| f.rule == "docs_commit_code"));
}

#[test]
fn exhausted_budgets_report_unscanned_never_clean() {
    if !have_git() {
        return;
    }
    let tmp = TempDir::new("hist-budget");
    let dir = repo(&tmp);
    fs::write(
        dir.join("run.js"),
        format!("go(() => {{\n{}", stealer_line()),
    )
    .unwrap();
    commit_all(&dir, "feat: runner");
    fs::remove_file(dir.join("run.js")).unwrap();
    commit_all(&dir, "chore: drop");

    let cases: [(&str, Limits); 4] = [
        (
            "bytes",
            Limits {
                max_bytes: 64,
                ..unlimited()
            },
        ),
        (
            "objects",
            Limits {
                max_objects: 2,
                ..unlimited()
            },
        ),
        (
            "time",
            Limits {
                deadline: Some(Instant::now()),
                ..unlimited()
            },
        ),
        (
            "size cap",
            Limits {
                max_object: 16,
                ..unlimited()
            },
        ),
    ];
    for (what, limits) in cases {
        let h = history::scan_with(&dir, limits);
        assert!(
            h.unscanned.iter().any(|u| u.contains(what)),
            "{what}: {:?}",
            h.unscanned
        );
        assert!(
            h.report
                .findings
                .iter()
                .any(|f| f.rule == "history_unscanned"),
            "{what}: {:?}",
            h.report
        );
        assert!(rules::grade(&h.report) >= Grade::Warn, "{what}");
        let legacy = h.legacy();
        let f = legacy
            .findings
            .iter()
            .find(|f| f.kind == "history_unscanned")
            .unwrap();
        assert!(f.detail.contains(what), "{}", f.detail);
    }
}

/// Deterministic xorshift for the corruption sweep.
fn rng(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for e in fs::read_dir(from).unwrap().flatten() {
        let target = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_tree(&e.path(), &target);
        } else {
            fs::copy(e.path(), &target).unwrap();
        }
    }
}

#[test]
fn corrupted_objects_never_panic_and_are_reported() {
    if !have_git() {
        return;
    }
    let tmp = TempDir::new("hist-corrupt");
    let dir = repo(&tmp);
    let base = benign_js();
    for i in 0..4 {
        fs::write(dir.join("lib.js"), format!("{base}// {i}\n")).unwrap();
        commit_all(&dir, &format!("rev {i}"));
    }
    git(&dir, &["repack", "-adq"]);
    fs::write(dir.join("loose.js"), "loose\n").unwrap();
    commit_all(&dir, "loose");

    // Flip bytes across the pack, the index and a loose object, many times over.
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    let mut stack = vec![dir.join(".git/objects")];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).unwrap().flatten() {
            if e.file_type().unwrap().is_dir() {
                stack.push(e.path());
            } else {
                files.push(e.path().strip_prefix(&dir).unwrap().to_path_buf());
            }
        }
    }
    files.sort();
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    for round in 0..60 {
        let work = tmp.join(format!("w{round}"));
        copy_tree(&dir, &work);
        let victim = work.join(&files[(rng(&mut seed) as usize) % files.len()]);
        let mut bytes = fs::read(&victim).unwrap();
        if bytes.is_empty() {
            continue;
        }
        match round % 3 {
            0 => {
                for _ in 0..8 {
                    let at = (rng(&mut seed) as usize) % bytes.len();
                    bytes[at] ^= (rng(&mut seed) as u8) | 1;
                }
            }
            1 => bytes.truncate((rng(&mut seed) as usize) % bytes.len()),
            _ => {
                let at = (rng(&mut seed) as usize) % bytes.len();
                bytes[at..].fill(0xff);
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&victim, fs::Permissions::from_mode(0o644));
        }
        fs::write(&victim, &bytes).unwrap();
        let h = history::scan_with(&work, unlimited());
        let _ = h.legacy();
        fs::remove_dir_all(&work).unwrap();
    }

    // A corrupted loose blob is reported, not skipped silently.
    let blob_id = git(&dir, &["hash-object", "-w", "--stdin"]);
    let blob_id = blob_id.trim();
    let loose = dir
        .join(".git/objects")
        .join(&blob_id[..2])
        .join(&blob_id[2..]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&loose, fs::Permissions::from_mode(0o644)).unwrap();
    }
    fs::write(&loose, b"\x78\x9cnot zlib at all").unwrap();
    let h = history::scan_with(&dir, unlimited());
    assert!(
        h.unscanned.iter().any(|u| u.contains("corrupt")),
        "{:?}",
        h.unscanned
    );

    // An enumerated loose object that cannot be opened is reported, not skipped.
    #[cfg(unix)]
    {
        fs::remove_file(&loose).unwrap();
        std::os::unix::fs::symlink("/dev/null", &loose).unwrap();
        let h = history::scan_with(&dir, unlimited());
        assert!(
            h.unscanned.iter().any(|u| u.contains("corrupt")),
            "{:?}",
            h.unscanned
        );
    }
}

#[test]
fn a_gitdir_file_is_followed_only_into_the_pack_or_its_submodule_dir() {
    if !have_git() {
        return;
    }
    let tmp = TempDir::new("hist-gitdir");
    let dir = repo(&tmp);
    fs::write(
        dir.join("run.js"),
        format!("go(() => {{\n{}", stealer_line()),
    )
    .unwrap();
    commit_all(&dir, "feat: runner");
    fs::remove_file(dir.join("run.js")).unwrap();
    commit_all(&dir, "chore: drop");
    // Submodule layout: the superproject keeps the pack's git dir in `.git/modules/<path>`.
    fs::create_dir_all(tmp.join(".git/modules")).unwrap();
    let modules = tmp.join(".git/modules/pack");
    fs::rename(dir.join(".git"), &modules).unwrap();
    fs::write(dir.join(".git"), "gitdir: ../.git/modules/pack\n").unwrap();
    assert_eq!(rules::grade(&history::scan(&dir).report), Grade::Block);

    // A pointer anywhere else (an unrelated repository) is not followed.
    let other = tmp.join("elsewhere/repo.git");
    fs::create_dir_all(other.parent().unwrap()).unwrap();
    fs::rename(&modules, &other).unwrap();
    for target in [
        other.display().to_string(),
        "../elsewhere/repo.git".to_string(),
    ] {
        fs::write(dir.join(".git"), format!("gitdir: {target}\n")).unwrap();
        let h = history::scan(&dir);
        assert!(
            h.unscanned.iter().any(|u| u.contains("outside the pack")),
            "{target}: {:?}",
            h.unscanned
        );
        assert!(h.report.combos.is_empty(), "{:?}", h.report);
        assert!(h
            .report
            .findings
            .iter()
            .any(|f| f.rule == "history_unscanned"));
    }

    #[cfg(unix)]
    {
        fs::remove_file(dir.join(".git")).unwrap();
        std::os::unix::fs::symlink(&other, dir.join(".git")).unwrap();
        let h = history::scan(&dir);
        assert!(
            h.unscanned.iter().any(|u| u.contains("symlink")),
            "{:?}",
            h.unscanned
        );
        assert!(rules::grade(&h.report) >= Grade::Warn);

        // A commondir leading out of the pack is refused too.
        fs::remove_file(dir.join(".git")).unwrap();
        fs::create_dir_all(dir.join(".git")).unwrap();
        fs::write(dir.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::write(dir.join(".git/commondir"), format!("{}\n", other.display())).unwrap();
        let h = history::scan(&dir);
        assert!(
            h.unscanned.iter().any(|u| u.contains("commondir")),
            "{:?}",
            h.unscanned
        );
    }
}

/// `T0` empty, `T_i = {a: T_{i-1}, b: T_{i-1}}`: 2^levels paths over `levels + 1` trees.
fn tree_bomb(dir: &Path, levels: usize) -> String {
    let mut tree = git_stdin(dir, &["mktree"], "").trim().to_string();
    for _ in 0..levels {
        let body = format!("040000 tree {tree}\ta\n040000 tree {tree}\tb\n");
        tree = git_stdin(dir, &["mktree"], &body).trim().to_string();
    }
    tree
}

fn git_stdin(dir: &Path, args: &[&str], input: &str) -> String {
    use std::io::Write;
    let mut child = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@t")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@t")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("run git");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "git {args:?}");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn a_shared_subtree_dag_costs_linear_work() {
    if !have_git() {
        return;
    }
    let tmp = TempDir::new("hist-dag");
    let dir = repo(&tmp);
    let bomb = tree_bomb(&dir, 40);
    let root = git_stdin(&dir, &["mktree"], &format!("040000 tree {bomb}\tdocsdir\n"))
        .trim()
        .to_string();
    let head = git(&dir, &["rev-parse", "HEAD"]).trim().to_string();
    // A docs-described commit on a side branch (the diff walk) ...
    let side = git(
        &dir,
        &["commit-tree", &root, "-p", &head, "-m", "docs: update"],
    )
    .trim()
    .to_string();
    git(&dir, &["update-ref", "refs/heads/side", &side]);
    for (what, setup) in [("side branch", None), ("HEAD", Some(&side))] {
        // ... and the same tree as HEAD (the checkout walk).
        if let Some(c) = setup {
            git(&dir, &["update-ref", "refs/heads/main", c]);
        }
        let t0 = Instant::now();
        let h = history::scan(&dir);
        let took = t0.elapsed();
        assert!(
            took < history::HISTORY_TIME + Duration::from_secs(5),
            "{what}: took {took:?}"
        );
        assert!(h.stats.commits >= 2, "{what}: {:?}", h.stats);
    }
}

#[test]
fn a_renamed_payload_is_scanned_under_every_name() {
    if !have_git() {
        return;
    }
    let tmp = TempDir::new("hist-rename");
    let dir = repo(&tmp);
    let payload = format!("go(() => {{\n{}", stealer_line());
    fs::write(dir.join("notes.txt"), &payload).unwrap();
    commit_all(&dir, "notes");
    git(&dir, &["mv", "notes.txt", "index.js"]);
    commit_all(&dir, "rename");
    // Checked out again under the harmless name: the code-name version is still history.
    git(&dir, &["mv", "index.js", "notes.txt"]);
    commit_all(&dir, "rename back");

    let h = history::scan(&dir);
    assert!(
        h.report
            .combos
            .iter()
            .any(|c| c.rule == "padding_sink" && c.path.to_string_lossy().ends_with(":index.js")),
        "{:?}",
        h.report
    );
}

#[test]
fn no_git_dir_means_no_history_findings() {
    let tmp = TempDir::new("hist-none");
    fs::write(tmp.join("SKILL.md"), "# x\n").unwrap();
    let h = history::scan(tmp.path());
    assert!(h.report.findings.is_empty() && h.unscanned.is_empty());
}

#[cfg(unix)]
#[test]
fn verify_check_never_runs_git() {
    if !have_git() {
        return;
    }
    let tmp = TempDir::new("hist-nogit");
    let dir = repo(&tmp);
    fs::write(dir.join("README.md"), "# x\n").unwrap();
    commit_all(&dir, "docs: readme");
    // A `git` first on PATH that leaves a marker if anything runs it, plus a repo config that
    // would run a program if git were invoked on the tree.
    let bin = tmp.join("bin");
    fs::create_dir_all(&bin).unwrap();
    let marker = tmp.join("ran");
    let shim = bin.join("git");
    fs::write(&shim, format!("#!/bin/sh\ntouch '{}'\n", marker.display())).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();
    let mut cfg = fs::read_to_string(dir.join(".git/config")).unwrap();
    cfg.push_str(&format!(
        "[core]\n\tfsmonitor = touch '{}'\n",
        marker.display()
    ));
    fs::write(dir.join(".git/config"), cfg).unwrap();

    let data = TempDir::new("hist-nogit-data");
    let path = format!("{}:/usr/bin:/bin", bin.display());
    let run = Invocation::new(&["verify", "check", dir.to_str().unwrap()])
        .plugin_data(data.path())
        .home(data.path())
        .env("PATH", &path)
        .run();
    assert!(run.json()["verdict"].is_string(), "{}", run.stdout);
    assert!(!marker.exists(), "verify check ran git");
}
