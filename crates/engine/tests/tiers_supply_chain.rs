//! Supply chain per tier (D8 v2 spec §6, issue #17), through the built binary.
//!
//! The same pack, probed by the Skill tool, a typed `/slash`, Read, Grep and Bash, at each
//! tier: Off only reports, Relaxed and Medium deny a blocked (combo, drift, `packs.lock`
//! mismatch) or unscanned pack, High also denies an unreviewed HIGH heuristic pack until the
//! user trusts it. Nothing moves unless the user's policy says `on_block: move`, and then never
//! a pack git tracks. Tier Off through the binary needs `--features test-hooks`, so the Off
//! rows run there only. The `SAFE_AI_SKILL_CORPUS=1` test runs the ai-kit corpus.

mod common;

use common::{permission_decision, Invocation, Run, TempDir, TEST_HOOKS};
use safe_ai_skill::policy::tier::Tier;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A script reading the default keypair: a code-context HIGH finding (`secret_read`).
const KEYPAIR_SCRIPT: &str = "#!/bin/sh\n\ncat ~/.config/solana/id.json\n";

/// The tiers a test can run: Off needs `test-hooks`.
fn tiers() -> Vec<Tier> {
    let mut all = Vec::new();
    if TEST_HOOKS {
        all.push(Tier::Off);
    }
    all.extend([Tier::Relaxed, Tier::Medium, Tier::High]);
    all
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

struct World {
    project: TempDir,
    home: TempDir,
    data: TempDir,
    plugin: TempDir,
}

/// The five ways a pack can be reached, each the exact outcome: `"deny"` / `"block"`, or `""`
/// for no opinion (empty stdout). Any other decision (an `ask`, an `allow`) fails a comparison.
#[derive(Debug, PartialEq, Eq)]
struct Reach {
    skill: String,
    slash: String,
    read: String,
    grep: String,
    bash: String,
}

impl Reach {
    fn all(denied: bool) -> Reach {
        let say = |word: &str| {
            if denied {
                word.to_string()
            } else {
                String::new()
            }
        };
        Reach {
            skill: say("deny"),
            slash: say("block"),
            read: say("deny"),
            grep: say("deny"),
            bash: say("deny"),
        }
    }
}

impl World {
    /// A world whose policy is the embedded default, or moves blocked packs when `moving`.
    fn new(tag: &str, moving: bool) -> World {
        let w = World {
            project: TempDir::new(&format!("{tag}-proj")),
            home: TempDir::new(&format!("{tag}-home")),
            data: TempDir::new(&format!("{tag}-data")),
            plugin: TempDir::new(&format!("{tag}-plugin")),
        };
        std::fs::create_dir_all(w.plugin.join("policy")).unwrap();
        let on_block = if moving { "move" } else { "deny" };
        std::fs::write(
            w.plugin.join("policy/default.policy.yaml"),
            format!(
                "version: 1\nsupply_chain:\n  verify_skills_dirs: [ \".claude/skills\" ]\n  \
                 verify_ext_submodules: true\n  ext_dir: \".claude/skills/ext\"\n  \
                 on_block: {on_block}\n"
            ),
        )
        .unwrap();
        w
    }

    fn cwd(&self) -> &str {
        self.project.path().to_str().unwrap()
    }

    fn skills(&self) -> PathBuf {
        self.project.path().join(".claude/skills")
    }

    /// The issue #10 stealer shape (a combo BLOCK on first sight) as `<skills>/<dir>`.
    fn put_stealer(&self, dir: &str) -> PathBuf {
        let shape = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/corpus/shapes/issue10-stealer");
        let to = self.skills().join(dir);
        copy_tree(&shape, &to);
        to
    }

    /// A pack whose script reads the keypair: a HIGH heuristic finding, unreviewed.
    fn put_high(&self, dir: &str) -> PathBuf {
        let to = self.put_clean(dir);
        std::fs::write(to.join("load.sh"), KEYPAIR_SCRIPT).unwrap();
        to
    }

    fn put_clean(&self, dir: &str) -> PathBuf {
        let to = self.skills().join(dir);
        std::fs::create_dir_all(&to).unwrap();
        std::fs::write(to.join("SKILL.md"), format!("# {dir}\n")).unwrap();
        to
    }

    fn inv<'a>(&'a self, args: &[&str], tier: Tier) -> Invocation<'a> {
        Invocation::new(args)
            .plugin_data(self.data.path())
            .home(self.home.path())
            .env("CLAUDE_PLUGIN_ROOT", self.plugin.path().to_str().unwrap())
            .tier(tier)
    }

    fn session(&self, tier: Tier) -> Run {
        let run = self
            .inv(&["verify", "session"], tier)
            .stdin(
                serde_json::json!({"session_id":"it-sc","hook_event_name": "SessionStart", "source": "startup", "cwd": self.cwd()})
                    .to_string(),
            )
            .run();
        assert_eq!(run.code, Some(0), "{}", run.stderr);
        run
    }

    /// `(systemMessage, additionalContext)` of a session, `("", "")` when silent.
    fn report(&self, tier: Tier) -> (String, String) {
        let run = self.session(tier);
        if run.stdout.trim().is_empty() {
            return (String::new(), String::new());
        }
        let v = run.json();
        (
            v["systemMessage"].as_str().unwrap_or_default().to_string(),
            v["hookSpecificOutput"]["additionalContext"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
        )
    }

    fn pre(&self, sub: &str, tool: &str, input: serde_json::Value, tier: Tier) -> (String, String) {
        let run = self
            .inv(&[sub], tier)
            .stdin(
                serde_json::json!({
                    "hook_event_name": "PreToolUse", "session_id": "s", "cwd": self.cwd(),
                    "tool_name": tool, "tool_input": input,
                })
                .to_string(),
            )
            .run();
        assert_eq!(run.code, Some(0), "{}", run.stderr);
        if run.stdout.trim().is_empty() {
            return (String::new(), String::new());
        }
        let v = run.json();
        // A Grep with no pack opinion still gets the secret-file exclusion glob (an
        // `updatedInput` with no decision): that is the only output besides a decision.
        let decision = permission_decision(&v).unwrap_or_else(|| {
            assert!(
                v["hookSpecificOutput"].get("updatedInput").is_some()
                    && v["hookSpecificOutput"].get("permissionDecision").is_none(),
                "output without a decision: {}",
                run.stdout
            );
            String::new()
        });
        (
            decision,
            v["hookSpecificOutput"]["permissionDecisionReason"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
        )
    }

    fn slash_outcome(&self, name: &str, tier: Tier) -> String {
        let run = self
            .inv(&["gate-prompt-expansion"], tier)
            .stdin(
                serde_json::json!({
                    "hook_event_name": "UserPromptExpansion", "cwd": self.cwd(),
                    "expansion_type": "slash_command", "command_name": name,
                    "command_args": "", "command_source": "projectSettings",
                    "prompt": format!("/{name}"),
                })
                .to_string(),
            )
            .run();
        assert_eq!(run.code, Some(0), "{}", run.stderr);
        if run.stdout.trim().is_empty() {
            return String::new();
        }
        run.json()["decision"].as_str().unwrap_or("?").to_string()
    }

    /// Probe `<skills>/<dir>` (whose skill is `name`) every way.
    fn reach(&self, dir: &str, name: &str, tier: Tier) -> Reach {
        let pack = self.skills().join(dir);
        let outcome = |(d, _): (String, String)| d;
        Reach {
            skill: outcome(self.pre(
                "gate-skill",
                "Skill",
                serde_json::json!({"skill": name}),
                tier,
            )),
            slash: self.slash_outcome(name, tier),
            read: outcome(self.pre(
                "gate-read",
                "Read",
                serde_json::json!({"file_path": pack.join("SKILL.md")}),
                tier,
            )),
            grep: outcome(self.pre(
                "gate-read",
                "Grep",
                serde_json::json!({"pattern": "x", "path": pack}),
                tier,
            )),
            bash: outcome(self.pre(
                "gate-bash-secrets",
                "Bash",
                serde_json::json!({"command": format!("cat {}/SKILL.md", pack.display())}),
                tier,
            )),
        }
    }

    /// Assert the pack is denied (or not) every way at every tier, `off_denies` for Off.
    fn assert_matrix(&self, dir: &str, name: &str, expect: impl Fn(Tier) -> bool) {
        for tier in tiers() {
            assert_eq!(
                self.reach(dir, name, tier),
                Reach::all(expect(tier)),
                "{dir} at {tier:?}"
            );
        }
    }
}

/// The session reported no pack (a `test-hooks` run prints the tier line of its tier.json).
fn assert_no_pack_report(run: &Run) {
    assert!(
        !run.stdout.contains("BLOCK") && !run.stdout.contains("WARN"),
        "{}",
        run.stdout
    );
}

/// Denied below Off, reported only at Off.
fn hard(tier: Tier) -> bool {
    tier != Tier::Off
}

/// Denied at High only.
fn high_only(tier: Tier) -> bool {
    tier == Tier::High
}

fn never(_: Tier) -> bool {
    false
}

#[test]
fn a_combo_block_is_denied_in_place_at_every_tier_but_off_and_never_moved() {
    let w = World::new("sc-combo", false);
    let pack = w.put_stealer("stealer");
    w.put_clean("fine");
    let (sys, ctx) = w.report(Tier::Relaxed);
    assert!(sys.contains("BLOCK") && ctx.contains("BLOCK"), "{sys}");
    w.assert_matrix("stealer", "stealer", hard);
    w.assert_matrix("stealer", "solana-stream", hard);
    assert!(pack.join("SKILL.md").exists(), "never moved");
    for tier in tiers() {
        w.session(tier);
        assert!(
            pack.join("SKILL.md").exists(),
            "moved by a session at {tier:?}"
        );
    }
    w.assert_matrix("fine", "fine", never);
}

#[test]
fn drift_from_the_pin_is_denied_like_a_combo() {
    let w = World::new("sc-drift", false);
    let pack = w.put_clean("drifty");
    assert_no_pack_report(&w.session(Tier::Relaxed));
    std::fs::write(pack.join("SKILL.md"), "# drifty, edited\n").unwrap();
    assert!(w.session(Tier::Relaxed).stdout.contains("BLOCK"));
    w.assert_matrix("drifty", "drifty", hard);
    assert!(pack.join("SKILL.md").exists());
}

#[test]
fn a_packs_lock_mismatch_is_denied_like_a_combo() {
    let w = World::new("sc-lock", false);
    let pack = w.put_clean("locky");
    std::fs::create_dir_all(w.project.join(".safe-ai-skill")).unwrap();
    std::fs::write(
        w.project.join(".safe-ai-skill/packs.lock"),
        r#"{"packs":[{"path":".claude/skills/locky","tree_hash":"0000000000000000000000000000000000000000000000000000000000000000"}]}"#,
    )
    .unwrap();
    assert!(w.session(Tier::Relaxed).stdout.contains("BLOCK"));
    w.assert_matrix("locky", "locky", hard);
    assert!(pack.join("SKILL.md").exists());
}

#[test]
fn an_unscanned_pack_is_denied_from_stored_state_like_a_block() {
    use safe_ai_skill::datadir::DataDir;
    use safe_ai_skill::verify::grading::Grade;
    use safe_ai_skill::verify::state::{self, PackEntry, PackKind, PackStatus, State};
    let w = World::new("sc-unscanned", false);
    let pack = w.put_clean("huge");
    let dir = DataDir {
        path: w.data.path().to_path_buf(),
        trusted: false,
    };
    let key = pack.canonicalize().unwrap().to_string_lossy().into_owned();
    let mut st = State {
        version: state::STATE_VERSION,
        ..State::default()
    };
    st.packs.insert(
        key,
        PackEntry {
            kind: PackKind::Skill,
            tree_hash: String::new(),
            head: None,
            first_seen: 1,
            last_scanned_hash: String::new(),
            grade: Grade::High,
            state: PackStatus::Unreviewed,
            findings: Vec::new(),
            more_findings: 0,
            flagged_rules: vec![state::SCAN_BUDGET_RULE.to_string()],
            reason: Some(state::Reason::Heuristic),
            names: vec!["huge".to_string()],
            names_incomplete: true,
            escaping: Vec::new(),
            approved: false,
            fingerprint: String::new(),
            hashed_sweep: 0,
            quarantined_to: None,
            note: None,
        },
    );
    state::store(&dir, &st).unwrap();
    for tier in tiers() {
        let read = |tool: &str, input: serde_json::Value| w.pre("gate-read", tool, input, tier).0;
        let bash = w
            .pre(
                "gate-bash-secrets",
                "Bash",
                serde_json::json!({"command": format!("cat {}/SKILL.md", pack.display())}),
                tier,
            )
            .0;
        let got = (
            read(
                "Read",
                serde_json::json!({"file_path": pack.join("SKILL.md")}),
            ),
            read("Grep", serde_json::json!({"pattern": "x", "path": pack})),
            bash,
        );
        let want = if hard(tier) { "deny" } else { "" }.to_string();
        assert_eq!(
            got,
            (want.clone(), want.clone(), want),
            "unscanned at {tier:?}"
        );
    }
}

#[test]
fn a_high_heuristic_is_reported_below_high_and_denied_at_high() {
    let w = World::new("sc-high", false);
    let pack = w.put_high("keys");
    let (sys, _) = w.report(Tier::Relaxed);
    assert!(
        sys.contains("WARN") && sys.contains("not reviewed yet"),
        "{sys}"
    );
    w.assert_matrix("keys", "keys", high_only);
    assert!(pack.join("load.sh").exists());
}

#[test]
fn a_committed_packs_lock_matching_a_high_pack_does_not_clear_it_at_high() {
    let w = World::new("sc-high-lock", false);
    let pack = w.put_high("keys");
    let hash = safe_ai_skill::verify::state::tree_hash(&pack);
    std::fs::create_dir_all(w.project.join(".safe-ai-skill")).unwrap();
    std::fs::write(
        w.project.join(".safe-ai-skill/packs.lock"),
        format!(r#"{{"packs":[{{"path":".claude/skills/keys","tree_hash":"{hash}"}}]}}"#),
    )
    .unwrap();
    w.session(Tier::Relaxed);
    // The lock settles it to a warning below High (as in 1.1.0) ...
    w.assert_matrix("keys", "keys", high_only);
    // ... and High still lists it for the user to trust.
    let (sys, _) = w.report(Tier::High);
    assert!(sys.contains("tier high denies 1 skill pack(s)"), "{sys}");
}

#[test]
fn a_clean_pack_has_no_opinion_at_every_tier() {
    let w = World::new("sc-clean", false);
    w.put_clean("fine");
    assert_no_pack_report(&w.session(Tier::Relaxed));
    w.assert_matrix("fine", "fine", never);
}

#[test]
fn the_report_names_pack_rule_location_and_the_approve_command() {
    let w = World::new("sc-report", false);
    w.put_stealer("stealer");
    for tier in [Tier::Relaxed, Tier::Medium, Tier::High] {
        let (sys, ctx) = w.report(tier);
        assert!(
            sys.contains("stealer") && ctx.contains("stealer"),
            "{tier:?}: {sys}"
        );
        assert!(sys.contains("exec_b64_literal"), "{sys}");
        assert!(sys.contains(".ts:"), "path:line missing: {sys}");
        assert!(
            sys.contains("safe-ai-skill verify approve"),
            "approve command missing: {sys}"
        );
        assert!(sys.contains("denied until approved"), "{sys}");
    }
}

#[test]
fn tier_high_prints_one_trust_line_listing_the_denied_heuristic_packs() {
    let w = World::new("sc-trust-line", false);
    w.put_high("keys-a");
    w.put_high("keys-b");
    w.put_clean("fine");
    let (sys, ctx) = w.report(Tier::High);
    let line = sys
        .lines()
        .find(|l| l.contains("tier high denies"))
        .unwrap_or_else(|| panic!("no tier high line: {sys}"));
    assert!(line.contains("2 skill pack(s)") && line.contains("keys-a") && line.contains("keys-b"));
    assert!(line.contains("safe-ai-skill verify trust"), "{line}");
    assert!(!line.contains("fine"));
    assert_eq!(sys.matches("tier high denies").count(), 1);
    assert!(ctx.contains("tier high denies") && !ctx.contains("verify trust <pack dir>"));
    // Below High the same packs are reported once, with no denial line.
    let lower = World::new("sc-trust-line-low", false);
    lower.put_high("keys-a");
    let (sys, _) = lower.report(Tier::Relaxed);
    assert!(!sys.contains("tier high denies"), "{sys}");
}

#[cfg(feature = "test-hooks")]
#[test]
fn off_reports_a_block_but_says_nothing_is_denied() {
    let w = World::new("sc-off-report", false);
    w.put_stealer("stealer");
    let (sys, ctx) = w.report(Tier::Off);
    assert!(sys.contains("BLOCK") && sys.contains("stealer"), "{sys}");
    assert!(
        sys.contains("the tier is off and nothing is denied"),
        "{sys}"
    );
    assert!(!sys.contains("denied until approved"), "{sys}");
    assert!(ctx.contains("tier off"), "{ctx}");
}

#[cfg(feature = "test-hooks")]
#[test]
fn after_verify_trust_a_high_pack_has_no_opinion_even_at_high() {
    use safe_ai_skill::datadir::DataDir;
    use safe_ai_skill::{confirm, verify};
    let w = World::new("sc-trusted", false);
    let pack = w.put_high("keys");
    w.session(Tier::Relaxed);
    assert_eq!(w.reach("keys", "keys", Tier::High), Reach::all(true));
    let dir = DataDir {
        path: w.data.path().to_path_buf(),
        trusted: true,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let canonical = pack.canonicalize().unwrap();
    // In-process, a request binds to this process's Claude Code session if it has one.
    let session = std::env::var("CLAUDE_CODE_SESSION_ID").unwrap_or_else(|_| "it".into());
    let req = verify::request_trust(&dir, &canonical).expect("a trust request");
    let code = confirm::announce_pending_for(&dir, now, &session)
        .into_iter()
        .find(|a| a.id.as_str() == req.id)
        .expect("announced")
        .code
        .as_str()
        .to_string();
    let confirmed = match confirm::confirm_attempt_for(
        &dir,
        &format!("safe-ai-skill confirm {code}"),
        now,
        &session,
    ) {
        confirm::Attempt::Confirmed(c) => c,
        other => panic!("not confirmed: {other:?}"),
    };
    verify::apply_confirmed(&dir, &confirmed).expect("trusted");
    for tier in tiers() {
        assert_eq!(w.reach("keys", "keys", tier), Reach::all(false), "{tier:?}");
    }
    // Edited content is new content: untrusted again.
    std::fs::write(pack.join("load.sh"), format!("{KEYPAIR_SCRIPT}# edited\n")).unwrap();
    let after = w.reach("keys", "keys", Tier::High);
    assert_eq!(after.skill, "deny", "{after:?}");
}

#[cfg(feature = "test-hooks")]
#[test]
fn a_trusted_combo_pack_still_denies() {
    use safe_ai_skill::datadir::DataDir;
    use safe_ai_skill::verify::{state, trust};
    let w = World::new("sc-trusted-combo", false);
    let pack = w.put_stealer("stealer");
    w.session(Tier::Relaxed);
    let hash = state::tree_hash(&pack);
    let dir = DataDir {
        path: w.data.path().to_path_buf(),
        trusted: true,
    };
    let rules: Vec<String> = ["padding_sink", "exec_b64_literal", "eval_decoder"]
        .iter()
        .map(|r| r.to_string())
        .collect();
    trust::add(&dir, &hash, &rules, "stealer", 1).unwrap();
    w.session(Tier::Relaxed);
    w.assert_matrix("stealer", "stealer", hard);
}

#[test]
fn on_block_move_moves_an_untracked_combo_pack_and_prints_origin_and_restore() {
    let w = World::new("sc-move", true);
    let pack = w.put_stealer("stealer");
    w.put_clean("fine");
    let origin = pack.canonicalize().unwrap();
    let (sys, ctx) = w.report(Tier::Relaxed);
    assert!(!pack.exists(), "moved out of the project");
    let moved = std::fs::read_dir(w.data.join("quarantine"))
        .unwrap()
        .flatten()
        .next()
        .expect("a quarantined copy")
        .path();
    assert!(moved.join("SKILL.md").exists());
    for text in [&sys, &ctx] {
        assert!(text.contains("MOVED"), "{text}");
        assert!(
            text.contains(&format!("origin {}", origin.display())),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "restore with `mv '{}' '{}'`",
                moved.display(),
                origin.display()
            )),
            "{text}"
        );
    }
    // A combo is never approvable, so the line does not offer approve as the restore path.
    assert!(!sys.contains("or `safe-ai-skill verify approve"), "{sys}");
    // The pack stays denied wherever it is reached from.
    for tier in [Tier::Relaxed, Tier::High] {
        let skill = w.pre(
            "gate-skill",
            "Skill",
            serde_json::json!({"skill": "stealer"}),
            tier,
        );
        assert_eq!(skill.0, "deny", "{tier:?}");
        let read = w.pre(
            "gate-read",
            "Read",
            serde_json::json!({"file_path": moved.join("SKILL.md")}),
            tier,
        );
        assert_eq!(read.0, "deny", "{tier:?}");
    }
    assert!(w.skills().join("fine/SKILL.md").exists());
}

#[test]
fn on_block_move_never_moves_a_drifted_pack_a_git_index_lists() {
    let w = World::new("sc-move-git", true);
    let pack = w.put_clean("tracked");
    let git = |args: &[&str]| {
        let out = Command::new("git")
            .args(["-c", "user.name=t", "-c", "user.email=t@t"])
            .args(args)
            .current_dir(w.project.path())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    git(&["init", "-q"]);
    git(&["add", ".claude"]);
    assert_no_pack_report(&w.session(Tier::Relaxed));
    std::fs::write(pack.join("SKILL.md"), "# tracked, edited\n").unwrap();
    for tier in [Tier::Relaxed, Tier::Medium, Tier::High] {
        let (sys, ctx) = w.report(tier);
        assert!(pack.join("SKILL.md").exists(), "moved at {tier:?}");
        for text in [&sys, &ctx] {
            assert!(
                text.contains("not moved: tracked by git"),
                "{tier:?}: {text}"
            );
            assert!(!text.contains("MOVED"), "{text}");
        }
        assert!(!w.data.join("quarantine").exists());
    }
    // Denied in place.
    assert_eq!(w.reach("tracked", "tracked", Tier::High), Reach::all(true));
}

#[test]
fn on_block_move_never_moves_a_gitmodules_path() {
    let w = World::new("sc-move-gm", true);
    let pack = w.put_stealer("ext/jupiter");
    std::fs::write(
        w.project.join(".gitmodules"),
        "[submodule \"jupiter\"]\n\tpath = .claude/skills/ext/jupiter\n\turl = https://example.invalid/j\n",
    )
    .unwrap();
    for tier in [Tier::Relaxed, Tier::High] {
        let (sys, _) = w.report(tier);
        assert!(pack.join("SKILL.md").exists(), "moved at {tier:?}");
        assert!(sys.contains("not moved: tracked by git"), "{sys}");
        assert!(!w.data.join("quarantine").exists());
    }
    assert_eq!(
        w.pre(
            "gate-skill",
            "Skill",
            serde_json::json!({"skill": "jupiter"}),
            Tier::Medium
        )
        .0,
        "deny"
    );
}

#[cfg(feature = "test-hooks")]
#[test]
fn off_moves_nothing_even_with_on_block_move() {
    let w = World::new("sc-move-off", true);
    let pack = w.put_stealer("stealer");
    w.session(Tier::Off);
    assert!(pack.join("SKILL.md").exists());
    assert!(!w.data.join("quarantine").exists());
}

#[test]
fn a_repo_cannot_turn_moving_on() {
    let w = World::new("sc-repo-move", false);
    let pack = w.put_stealer("stealer");
    std::fs::create_dir_all(w.project.join(".safe-ai-skill")).unwrap();
    std::fs::write(
        w.project.join(".safe-ai-skill/policy.yaml"),
        "supply_chain:\n  on_block: move\n",
    )
    .unwrap();
    for tier in [Tier::Relaxed, Tier::High] {
        w.session(tier);
        assert!(
            pack.join("SKILL.md").exists(),
            "a repo policy moved a pack at {tier:?}"
        );
    }
}

/// The ai-kit corpus (`SAFE_AI_SKILL_CORPUS=1`, pinned at f70345d in `rules_corpus`'s
/// manifest): read from `SAFE_AI_SKILL_CORPUS_DIR`, a kit checkout with the `ext` submodules
/// populated, copied to a temp project so nothing is ever moved in the original. Relaxed: 0
/// denied, 0 moved. High: 0 moved and one denial per HIGH pack of the manifest (13 with every
/// pack present). `on_block: move` is on, so the submodule guard is what keeps the packs.
#[test]
fn aikit_corpus_relaxed_denies_and_moves_nothing_and_high_denies_the_high_packs() {
    if std::env::var("SAFE_AI_SKILL_CORPUS").as_deref() != Ok("1") {
        eprintln!("aikit corpus (supply chain): skipped (set SAFE_AI_SKILL_CORPUS=1 to run)");
        return;
    }
    let source = PathBuf::from(
        std::env::var_os("SAFE_AI_SKILL_CORPUS_DIR")
            .expect("SAFE_AI_SKILL_CORPUS_DIR must name an ai-kit checkout with ext populated"),
    );
    let manifest = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/corpus/aikit.manifest.tsv"),
    )
    .unwrap();
    let rows: Vec<(String, String)> = manifest
        .lines()
        .filter(|l| !l.starts_with('#') && !l.starts_with("pack\t"))
        .filter_map(|l| {
            let mut f = l.split('\t');
            Some((f.next()?.to_string(), f.nth(1)?.to_string()))
        })
        .collect();
    assert_eq!(rows.len(), 46, "manifest rows");
    let w = World::new("sc-corpus", true);
    let ext = source.join(".claude/skills/ext");
    let dst = w.project.path().to_path_buf();
    std::fs::create_dir_all(dst.join(".claude/skills")).unwrap();
    let status = Command::new("cp")
        .arg("-R")
        .arg(&ext)
        .arg(dst.join(".claude/skills/ext"))
        .status()
        .unwrap();
    assert!(status.success(), "copying the corpus");
    for f in [".gitmodules", ".git"] {
        if source.join(f).is_file() {
            std::fs::copy(source.join(f), dst.join(f)).unwrap();
        }
    }
    let present: Vec<&(String, String)> = rows
        .iter()
        .filter(|(p, _)| dst.join(".claude/skills/ext").join(p).is_dir())
        .collect();
    let expect_high = present.iter().filter(|(_, g)| g == "high").count();
    eprintln!(
        "corpus packs present: {} of 46, HIGH expected: {expect_high}",
        present.len()
    );
    assert!(
        present.len() == 46 || std::env::var("SAFE_AI_SKILL_CORPUS_PARTIAL").as_deref() == Ok("1"),
        "{} of 46 corpus packs present; set SAFE_AI_SKILL_CORPUS_PARTIAL=1 to accept",
        present.len()
    );
    let before: Vec<String> = present.iter().map(|(p, _)| p.clone()).collect();
    let denied = |tier: Tier| -> Vec<String> {
        let mut out = Vec::new();
        for (pack, _) in &present {
            let file = w.skills().join("ext").join(pack).join("SKILL.md");
            let read = w.pre(
                "gate-read",
                "Read",
                serde_json::json!({"file_path": file}),
                tier,
            );
            if read.0 == "deny" {
                out.push(pack.clone());
            }
        }
        out
    };
    for tier in [Tier::Relaxed, Tier::High] {
        let started = std::time::Instant::now();
        w.session(tier);
        eprintln!("corpus sweep at {tier:?}: {:?}", started.elapsed());
        for pack in &before {
            assert!(
                w.skills().join("ext").join(pack).is_dir(),
                "{pack} moved at {tier:?}"
            );
        }
        assert!(
            !w.data.join("quarantine").exists(),
            "something was quarantined at {tier:?}"
        );
    }
    assert!(
        denied(Tier::Relaxed).is_empty(),
        "relaxed denied: {:?}",
        denied(Tier::Relaxed)
    );
    let high = denied(Tier::High);
    let wanted: Vec<&str> = present
        .iter()
        .filter(|(_, g)| g == "high")
        .map(|(p, _)| p.as_str())
        .collect();
    let mut got: Vec<&str> = high.iter().map(String::as_str).collect();
    got.sort_unstable();
    let mut wanted_sorted = wanted.clone();
    wanted_sorted.sort_unstable();
    assert_eq!(got, wanted_sorted, "high denies exactly the HIGH packs");
    // The Skill tool agrees for a denied pack and a clean one.
    if let Some(pack) = wanted.first() {
        assert_eq!(
            w.pre(
                "gate-skill",
                "Skill",
                serde_json::json!({"skill": pack}),
                Tier::High
            )
            .0,
            "deny"
        );
        assert_eq!(
            w.pre(
                "gate-skill",
                "Skill",
                serde_json::json!({"skill": pack}),
                Tier::Relaxed
            )
            .0,
            ""
        );
    }
}

#[test]
fn on_block_move_leaves_a_symlinked_pack_in_place_and_says_why() {
    let w = World::new("sc-move-link", true);
    let target = w.project.join("vendor/evil");
    copy_tree(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/corpus/shapes/issue10-stealer"),
        &target,
    );
    std::fs::create_dir_all(w.skills()).unwrap();
    let link = w.skills().join("evil");
    #[cfg(unix)]
    std::os::unix::fs::symlink("../../vendor/evil", &link).unwrap();
    #[cfg(not(unix))]
    return;
    for tier in [Tier::Relaxed, Tier::High] {
        let (sys, ctx) = w.report(tier);
        assert!(
            link.symlink_metadata().unwrap().file_type().is_symlink(),
            "{tier:?}"
        );
        assert!(target.join("SKILL.md").exists());
        assert!(!w.data.join("quarantine").exists(), "{tier:?}");
        for text in [&sys, &ctx] {
            assert!(text.contains("BLOCK"), "{text}");
            assert!(
                text.contains("not moved: the pack directory is a symlink"),
                "{text}"
            );
            assert!(!text.contains("MOVED"), "{text}");
        }
    }
    assert_eq!(
        w.pre(
            "gate-skill",
            "Skill",
            serde_json::json!({"skill": "evil"}),
            Tier::Relaxed
        )
        .0,
        "deny"
    );
}

#[cfg(unix)]
#[test]
fn a_fifo_gitmodules_cannot_stall_the_sweep_or_lose_the_block() {
    let w = World::new("sc-move-fifo", true);
    let pack = w.put_stealer("stealer");
    let fifo = w.skills().join(".gitmodules");
    let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let started = std::time::Instant::now();
    let (sys, ctx) = w.report(Tier::Relaxed);
    assert!(started.elapsed().as_secs() < 30, "{:?}", started.elapsed());
    assert!(pack.join("SKILL.md").exists(), "never moved");
    for text in [&sys, &ctx] {
        assert!(
            text.contains("BLOCK") && text.contains("not moved: tracked by git"),
            "{text}"
        );
    }
    // The BLOCK is in the stored state, so Read, Grep and Bash deny with no Skill call first.
    assert_eq!(
        w.reach("stealer", "no-such-skill", Tier::Medium).read,
        "deny"
    );
    assert_eq!(
        w.reach("stealer", "no-such-skill", Tier::Medium).bash,
        "deny"
    );
}
