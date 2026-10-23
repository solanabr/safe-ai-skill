//! `verify check`, `add` and `install` grade a directory with the SessionStart sweep's rule
//! engine, report format and per-tier action (issue #5), through the built binary.
//!
//! A documentation-only plain-text match is a WARN at every tier and never blocks; the issue
//! #10 stealer shape (a combo) is blocked and denied at every tier but Off, which only reports.

mod common;

use common::{Invocation, Run, TempDir, TEST_HOOKS};
use safe_ai_skill::policy::tier::Tier;
use std::path::Path;

/// The issue's reproduction: one documentation line naming the default keypair.
const ISSUE5_DOC: &str = "Load the payer with signerFromFile(\"~/.config/solana/id.json\").\n";

fn tiers() -> Vec<Tier> {
    let mut all = Vec::new();
    if TEST_HOOKS {
        all.push(Tier::Off);
    }
    all.extend([Tier::Relaxed, Tier::Medium, Tier::High]);
    all
}

struct World {
    root: TempDir,
    home: TempDir,
    data: TempDir,
}

impl World {
    fn new(tag: &str) -> World {
        World {
            root: TempDir::new(&format!("{tag}-root")),
            home: TempDir::new(&format!("{tag}-home")),
            data: TempDir::new(&format!("{tag}-data")),
        }
    }

    /// `mkdir -p demo/.claude/skills/docs-only` with the issue's `SKILL.md`.
    fn put_docs_only(&self) -> &'static str {
        let rel = "demo/.claude/skills/docs-only";
        std::fs::create_dir_all(self.root.join(rel)).unwrap();
        std::fs::write(self.root.join(rel).join("SKILL.md"), ISSUE5_DOC).unwrap();
        rel
    }

    /// The issue #10 stealer shape (a combo BLOCK).
    fn put_stealer(&self) -> &'static str {
        let rel = "demo/.claude/skills/stealer";
        let shape = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/corpus/shapes/issue10-stealer");
        copy_tree(&shape, &self.root.join(rel));
        rel
    }

    fn run(&self, args: &[&str], tier: Tier) -> Run {
        let run = Invocation::new(args)
            .plugin_data(self.data.path())
            .home(self.home.path())
            .cwd(self.root.path())
            .tier(tier)
            .stdin("{}")
            .run();
        assert_eq!(run.code, Some(0), "{}\n{}", run.stdout, run.stderr);
        run
    }

    fn check(&self, rel: &str, tier: Tier) -> serde_json::Value {
        self.run(&["verify", "check", rel], tier).json()
    }
}

fn copy_tree(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap().flatten() {
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &to);
        } else if entry.file_name() != "shape.json" {
            std::fs::copy(entry.path(), &to).unwrap();
        }
    }
}

fn report(v: &serde_json::Value) -> String {
    v["report"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap().to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_issue5_docs_only_reproduction_never_blocks() {
    let w = World::new("chk-docs");
    let rel = w.put_docs_only();
    for tier in tiers() {
        let v = w.check(rel, tier);
        assert_eq!(v["tier"], tier.label(), "{v}");
        assert_eq!(v["state"], "warned", "{tier:?}: {v}");
        assert_eq!(v["verdict"], "warn", "{tier:?}: {v}");
        assert_eq!(
            v["findings"],
            serde_json::json!([{
                "rule": "secret_read", "sev": "warn", "path": "SKILL.md", "line": 1, "ctx": "doc"
            }]),
            "{tier:?}"
        );
        let text = report(&v);
        assert!(
            text.contains(&format!("WARN skill `docs-only` ({rel}): warnings only"))
                && text.contains(&format!("{rel}/SKILL.md:1 secret_read (warn, doc)"))
                && text.contains("reported only"),
            "{tier:?}: {text}"
        );
        assert!(
            w.root.join(rel).join("SKILL.md").exists(),
            "moved at {tier:?}"
        );
    }
}

#[test]
fn the_issue10_stealer_is_blocked_and_denied_at_every_tier_but_off() {
    let w = World::new("chk-stealer");
    let rel = w.put_stealer();
    for tier in tiers() {
        let v = w.check(rel, tier);
        assert_eq!(v["state"], "blocked", "{tier:?}: {v}");
        let want = if tier == Tier::Off { "warn" } else { "block" };
        assert_eq!(v["verdict"], want, "{tier:?}: {v}");
        assert!(
            v["findings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["sev"] == "block"),
            "{v}"
        );
        let text = report(&v);
        assert!(text.contains("BLOCK skill `stealer`"), "{text}");
        if tier == Tier::Off {
            assert!(text.contains("nothing is denied"), "{text}");
        } else {
            // Approval never clears a combination rule, so no approve hint.
            assert!(
                text.contains("fix or remove the pack") && !text.contains("verify approve"),
                "{text}"
            );
        }
    }
}

#[test]
fn a_code_keypair_read_is_denied_at_high_only() {
    let w = World::new("chk-high");
    let rel = "demo/.claude/skills/loader";
    std::fs::create_dir_all(w.root.join(rel)).unwrap();
    std::fs::write(w.root.join(rel).join("SKILL.md"), "# loader\n").unwrap();
    std::fs::write(
        w.root.join(rel).join("load.sh"),
        "#!/bin/sh\n\ncat ~/.config/solana/id.json\n",
    )
    .unwrap();
    for tier in tiers() {
        let v = w.check(rel, tier);
        assert_eq!(v["state"], "unreviewed", "{tier:?}: {v}");
        let want = if tier == Tier::High { "block" } else { "warn" };
        assert_eq!(v["verdict"], want, "{tier:?}: {v}");
    }
}

#[test]
fn a_missing_directory_is_an_error_not_a_pass() {
    let w = World::new("chk-missing");
    let run = Invocation::new(&["verify", "check", "nope"])
        .plugin_data(w.data.path())
        .home(w.home.path())
        .cwd(w.root.path())
        .run();
    assert_eq!(run.code, Some(1), "{}", run.stdout);
    assert!(run.json()["error"].is_string(), "{}", run.stdout);
}

#[test]
fn add_follows_the_same_grading() {
    let w = World::new("chk-add");
    let docs = w.put_docs_only();
    let stealer = w.put_stealer();
    for tier in tiers() {
        let v = w
            .run(&["add", "skill", docs, "--offline", "--yes"], tier)
            .json();
        assert_eq!(v["state"], "warned", "{tier:?}: {v}");
        assert_eq!(v["proceed"], true, "{tier:?}: {v}");
        // A combination BLOCK needs `--force` at every tier, Off included.
        for flags in [&["--offline"][..], &["--offline", "--yes"][..]] {
            let mut args = vec!["add", "skill", stealer];
            args.extend_from_slice(flags);
            let v = w.run(&args, tier).json();
            assert_eq!(v["state"], "blocked", "{tier:?}: {v}");
            assert_eq!(v["reason"], "combo", "{tier:?}: {v}");
            assert_eq!(v["status"], "blocked", "{tier:?} {flags:?}: {v}");
            assert_eq!(v["proceed"], false, "{tier:?}: {v}");
        }
        let v = w
            .run(&["add", "skill", stealer, "--offline", "--force"], tier)
            .json();
        assert_eq!(v["status"], "force_proceed", "{tier:?}: {v}");
        let v = w
            .run(&["add", "repo", docs, "--offline", "--yes"], tier)
            .json();
        assert_eq!(
            (&v["state"], &v["status"]),
            (
                &serde_json::json!("warned"),
                &serde_json::json!("warn_proceed")
            ),
            "{v}"
        );
    }
}

#[test]
fn add_of_a_missing_local_path_is_an_error() {
    let w = World::new("chk-add-missing");
    let run = Invocation::new(&["add", "skill", "./typo", "--offline"])
        .plugin_data(w.data.path())
        .home(w.home.path())
        .cwd(w.root.path())
        .run();
    assert_eq!(run.code, Some(1), "{}", run.stdout);
    let v = run.json();
    assert_eq!(v["status"], "error", "{v}");
    assert!(v["run"].is_null(), "{v}");
}

#[test]
fn verify_check_lists_info_findings_and_errors_on_a_file() {
    let w = World::new("chk-info");
    let rel = "demo/.claude/skills/mcp";
    std::fs::create_dir_all(w.root.join(rel)).unwrap();
    std::fs::write(w.root.join(rel).join("SKILL.md"), "# mcp\n").unwrap();
    std::fs::write(
        w.root.join(rel).join(".mcp.json"),
        r#"{"mcpServers":{"h":{"command":"npx","args":["-y","h-mcp@latest"]}}}"#,
    )
    .unwrap();
    let v = w.check(rel, Tier::High);
    assert_eq!(
        (&v["state"], &v["verdict"]),
        (&serde_json::json!("clean"), &serde_json::json!("pass"))
    );
    assert!(v["reason"].is_null(), "{v}");
    assert!(
        v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["sev"] == "info" && f["rule"] == "unpinned_npx"),
        "{v}"
    );
    let run = Invocation::new(&["verify", "check", &format!("{rel}/SKILL.md")])
        .plugin_data(w.data.path())
        .home(w.home.path())
        .cwd(w.root.path())
        .run();
    assert_eq!(run.code, Some(1), "{}", run.stdout);
}

#[test]
fn install_installs_the_docs_only_pack_and_holds_the_stealer() {
    for tier in tiers() {
        let w = World::new("chk-install");
        w.put_docs_only();
        w.put_stealer();
        let from = w.root.join("demo/.claude/skills");
        let into = w.root.join("into");
        let v = w
            .run(
                &[
                    "install",
                    "--from",
                    from.to_str().unwrap(),
                    "--home",
                    into.to_str().unwrap(),
                    "--yes",
                ],
                tier,
            )
            .json();
        assert_eq!(v["status"], "done", "{v}");
        assert!(
            v["installed"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s == "docs-only"),
            "{tier:?}: {v}"
        );
        // A combination BLOCK is held at every tier, Off included, unless `--force`.
        let held = v["held"].as_array().unwrap();
        assert!(
            held.iter().any(|h| h["skill"] == "stealer"
                && h["state"] == "blocked"
                && h["reason"] == "combo"
                && h["report"].as_array().is_some_and(|r| !r.is_empty())),
            "{tier:?}: {v}"
        );
        let forced = w
            .run(
                &[
                    "install",
                    "--from",
                    from.to_str().unwrap(),
                    "--home",
                    into.to_str().unwrap(),
                    "--force",
                ],
                tier,
            )
            .json();
        assert!(
            forced["installed"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s == "stealer"),
            "{tier:?}: {forced}"
        );
        assert!(
            v["flagged"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["skill"] == "docs-only" && f["rule"] == "secret_read"),
            "{v}"
        );
    }
}

/// A project whose `.claude/skills/<name>` holds `skill_md`.
fn in_place_project(w: &World, name: &str, skill_md: &str) -> std::path::PathBuf {
    let pack = w.root.join("proj/.claude/skills").join(name);
    std::fs::create_dir_all(&pack).unwrap();
    std::fs::write(pack.join("SKILL.md"), skill_md).unwrap();
    pack
}

fn in_place(w: &World, flags: &[&str], tier: Tier) -> serde_json::Value {
    let mut args = vec!["install"];
    args.extend_from_slice(flags);
    let run = Invocation::new(&args)
        .plugin_data(w.data.path())
        .home(w.home.path())
        .cwd(&w.root.join("proj"))
        .tier(tier)
        .stdin("{}")
        .run();
    assert_eq!(run.code, Some(0), "{}\n{}", run.stdout, run.stderr);
    run.json()
}

#[test]
fn in_place_install_holds_a_warned_pack_until_yes() {
    for tier in tiers() {
        let w = World::new("chk-inplace");
        in_place_project(&w, "docs-only", ISSUE5_DOC);
        let v = in_place(&w, &[], tier);
        assert!(
            v["held"]
                .as_array()
                .unwrap()
                .iter()
                .any(|h| h["skill"] == "docs-only" && h["state"] == "warned"),
            "{tier:?}: {v}"
        );
        let v = in_place(&w, &["--yes"], tier);
        assert_eq!(
            v["verified"],
            serde_json::json!(["docs-only"]),
            "{tier:?}: {v}"
        );
    }
}

#[test]
fn in_place_install_leaves_a_lock_pinned_pack_unedited() {
    let w = World::new("chk-inplace-lock");
    let body = "---\nname: tele\ntelemetryTier: full\n---\n\n```bash\ncurl -s -X POST \"https://x.convex.cloud/api/mutation\" -d '{\"path\":\"telemetry:record\"}'\n```\n";
    let pack = in_place_project(&w, "tele", body);
    let hash = safe_ai_skill::verify::state::tree_hash(&pack.canonicalize().unwrap());
    std::fs::create_dir_all(w.root.join("proj/.safe-ai-skill")).unwrap();
    std::fs::write(
        w.root.join("proj/.safe-ai-skill/packs.lock"),
        format!(r#"{{"packs":[{{"path":".claude/skills/tele","tree_hash":"{hash}"}}]}}"#),
    )
    .unwrap();
    let v = in_place(&w, &["--yes"], Tier::Relaxed);
    assert_eq!(
        std::fs::read_to_string(pack.join("SKILL.md")).unwrap(),
        body,
        "edited despite the lock pin: {v}"
    );
    assert!(
        v["not_neutralized"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n["skill"] == "tele"
                && n["reason"]
                    .as_str()
                    .is_some_and(|r| r.contains("packs.lock"))),
        "{v}"
    );
    assert_eq!(v["verified"], serde_json::json!(["tele"]), "{v}");
}
