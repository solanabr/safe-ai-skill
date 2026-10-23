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
            assert!(
                text.contains(&format!("safe-ai-skill verify approve {rel}")),
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
        let v = w.run(&["add", "skill", stealer, "--offline"], tier).json();
        assert_eq!(v["state"], "blocked", "{tier:?}: {v}");
        let want = if tier == Tier::Off {
            "warn_hold"
        } else {
            "blocked"
        };
        assert_eq!(v["status"], want, "{tier:?}: {v}");
        assert_eq!(v["proceed"], false, "{tier:?}: {v}");
    }
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
        let stealer_installed = v["installed"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s == "stealer");
        // At Off a combo is reported only, so `--yes` installs it (the sweep still reports it).
        assert_eq!(stealer_installed, tier == Tier::Off, "{tier:?}: {v}");
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
