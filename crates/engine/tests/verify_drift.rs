//! Sandboxed `verify session` sweep: TOFU drift, swept roots, and `verify approve`.
//!
//! Places a clean fixture skill under a sandbox project's `.claude/skills`, pins it with a first
//! `verify session` sweep, tampers one byte, then re-runs `verify session` and asserts the drift
//! is reported (a WARN in the SessionStart `systemMessage` + `additionalContext`) while the skill
//! stays where it is. Also covers which roots are swept (the user-scope `~/.claude/skills` only
//! when the policy lists it) and `verify approve` restoring packs that an earlier version moved
//! into `quarantine/`.
//!
//! Fully hermetic: the project, HOME and CLAUDE_PLUGIN_DATA are sandbox temp dirs, so the sweep
//! scans only the fixtures and writes lockfile/quarantine only inside the sandbox.

mod common;

use common::{Invocation, Run, TempDir};
use std::path::{Path, PathBuf};

/// A telemetry preamble (outbound POST): a High finding wherever it is swept.
const TELEMETRY_SKILL_MD: &str = "# Personal\n\n\
```bash\ncurl -s -X POST \"$U/api/mutation\" -d '{}'\n```\n";

/// `<project>/.claude/skills` — the default (project-scope) skills root.
fn skills_root(project: &Path) -> PathBuf {
    project.join(".claude").join("skills")
}

/// The in-repo plugin root, whose `policy/default.policy.yaml` is the shipped default policy.
fn shipped_plugin_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("plugins")
        .join("safe-ai-skill")
}

/// SessionStart payload for a session in `project`.
fn payload(project: &Path) -> String {
    serde_json::json!({
        "hook_event_name": "SessionStart",
        "source": "startup",
        "cwd": project.to_str().unwrap()
    })
    .to_string()
}

/// Run `verify session` with `project` as the hook payload `cwd`.
fn verify_session(project: &Path, home: &Path, data: &Path) -> Run {
    Invocation::new(&["verify", "session"])
        .plugin_data(data)
        .home(home)
        .stdin(payload(project))
        .run()
}

/// The parsed SessionStart emit, or `None` when the sweep had nothing to report (empty stdout).
fn emit(run: &Run) -> Option<serde_json::Value> {
    assert_eq!(
        run.code,
        Some(0),
        "verify session must exit 0: {}",
        run.stderr
    );
    if run.stdout.trim().is_empty() {
        None
    } else {
        Some(run.json())
    }
}

/// `(systemMessage, additionalContext)` of a SessionStart report; both must be present.
fn messages(v: &serde_json::Value) -> (String, String) {
    let inner = &v["hookSpecificOutput"];
    assert_eq!(inner["hookEventName"], "SessionStart", "{v}");
    let sys = v["systemMessage"]
        .as_str()
        .unwrap_or_else(|| panic!("no systemMessage: {v}"))
        .to_string();
    let ctx = inner["additionalContext"]
        .as_str()
        .unwrap_or_else(|| panic!("no additionalContext: {v}"))
        .to_string();
    (sys, ctx)
}

/// The sandbox lockfile, parsed (`{}` when no sweep has written one).
fn lockfile(data: &Path) -> serde_json::Value {
    std::fs::read_to_string(data.join("lockfile.json"))
        .map(|body| serde_json::from_str(&body).unwrap())
        .unwrap_or_else(|_| serde_json::json!({}))
}

/// Seed a pack that an earlier version moved to `<data>/quarantine/<name>`.
fn seed_quarantined(data: &Path, name: &str) {
    let dir = data.join("quarantine").join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("SKILL.md"), format!("# {name}\n")).unwrap();
}

/// Run `verify approve <name>` from the project dir (as a user would in a terminal).
fn approve(project: &Path, home: &Path, data: &Path, name: &str) -> serde_json::Value {
    let run = Invocation::new(&["verify", "approve", name])
        .plugin_data(data)
        .home(home)
        .cwd(project)
        .stdin("{}")
        .run();
    let v = run.json();
    assert_eq!(v["status"], "approved", "approve failed: {}", run.stdout);
    v
}

#[test]
fn drift_is_reported_without_moving() {
    let project = TempDir::new("drift-proj");
    let home = TempDir::new("drift-home");
    let data = TempDir::new("drift-data");

    // Seed a clean fixture skill under the project's .claude/skills.
    let skill = skills_root(project.path()).join("address-formatter");
    std::fs::create_dir_all(&skill).unwrap();
    std::fs::write(
        skill.join("SKILL.md"),
        "# Address Formatter\n\nFormats Solana addresses for display.\n",
    )
    .unwrap();

    // 1. First sweep pins the clean skill (TOFU) and has nothing to report.
    let first = verify_session(project.path(), home.path(), data.path());
    assert!(
        emit(&first).is_none(),
        "clean first sweep must emit nothing: {}",
        first.stdout
    );
    assert!(
        lockfile(data.path())["skills"]
            .get("address-formatter")
            .is_some(),
        "skill not pinned after the first sweep"
    );

    // 2. Tamper one byte in the pinned skill.
    let md_path = skill.join("SKILL.md");
    let mut body = std::fs::read_to_string(&md_path).unwrap();
    body.push('X'); // single-byte mutation → tree hash changes
    std::fs::write(&md_path, body).unwrap();

    // 3. Second sweep reports the drift: a WARN naming the skill, to the user and the model.
    let second = emit(&verify_session(project.path(), home.path(), data.path()))
        .expect("drift must be reported");
    let (sys, ctx) = messages(&second);
    for (field, text) in [("systemMessage", &sys), ("additionalContext", &ctx)] {
        let lower = text.to_lowercase();
        assert!(
            lower.contains("warn")
                && lower.contains("address-formatter")
                && lower.contains("drift"),
            "{field} did not report the drifted skill: {text:?}"
        );
    }

    // Report-only: the drifted skill stays in the skills root; nothing is quarantined.
    assert!(
        md_path.exists(),
        "drifted skill was removed from the skills root"
    );
    assert!(
        !data.path().join("quarantine").exists(),
        "nothing may be moved to quarantine"
    );
}

#[test]
fn user_scope_skills_not_swept_by_default() {
    let project = TempDir::new("scope-proj");
    let home = TempDir::new("scope-home");
    let data = TempDir::new("scope-data");
    let personal = home.path().join(".claude").join("skills").join("personal");
    std::fs::create_dir_all(&personal).unwrap();
    std::fs::write(personal.join("SKILL.md"), TELEMETRY_SKILL_MD).unwrap();

    // Both the embedded default (plugin root without a policy file) and the shipped
    // `default.policy.yaml` sweep only the project's `.claude/skills`.
    for plugin_root in [home.path().to_path_buf(), shipped_plugin_root()] {
        let run = Invocation::new(&["verify", "session"])
            .plugin_data(data.path())
            .home(home.path())
            .env("CLAUDE_PLUGIN_ROOT", plugin_root.to_str().unwrap())
            .stdin(payload(project.path()))
            .run();
        assert!(
            emit(&run).is_none(),
            "~/.claude/skills swept with plugin root {}: {}",
            plugin_root.display(),
            run.stdout
        );
    }
    assert!(personal.join("SKILL.md").exists());
    assert!(
        lockfile(data.path())["skills"].get("personal").is_none(),
        "a user-scope skill was pinned"
    );
}

#[test]
fn user_scope_skills_swept_when_listed_in_policy() {
    let project = TempDir::new("listed-proj");
    let home = TempDir::new("listed-home");
    let data = TempDir::new("listed-data");
    let plugin_root = TempDir::new("listed-plugin");
    std::fs::create_dir_all(plugin_root.join("policy")).unwrap();
    std::fs::write(
        plugin_root.join("policy").join("default.policy.yaml"),
        "version: 1\nsupply_chain:\n  verify_skills_dirs: [ \"~/.claude/skills\", \".claude/skills\" ]\n",
    )
    .unwrap();
    let personal = home.path().join(".claude").join("skills").join("personal");
    std::fs::create_dir_all(&personal).unwrap();
    std::fs::write(personal.join("SKILL.md"), TELEMETRY_SKILL_MD).unwrap();

    let run = Invocation::new(&["verify", "session"])
        .plugin_data(data.path())
        .home(home.path())
        .env("CLAUDE_PLUGIN_ROOT", plugin_root.path().to_str().unwrap())
        .stdin(payload(project.path()))
        .run();
    let v = emit(&run).expect("a listed user-scope root must be swept");
    let (sys, ctx) = messages(&v);
    let at = "~/.claude/skills/personal/SKILL.md:4";
    for text in [&sys, &ctx] {
        assert!(
            text.contains("WARN") && text.contains(at),
            "user-scope skill not reported at {at}: {text:?}"
        );
    }
    assert!(
        personal.join("SKILL.md").exists(),
        "user-scope skill was moved"
    );
}

#[test]
fn approve_restores_quarantined_skill_to_first_scan_dir() {
    // A pack an earlier version moved to quarantine/ goes back under the first swept root.
    let project = TempDir::new("approve-proj");
    let home = TempDir::new("approve-home");
    let data = TempDir::new("approve-data");
    seed_quarantined(data.path(), "pda-helper");

    let v = approve(project.path(), home.path(), data.path(), "pda-helper");

    let restored = skills_root(project.path()).join("pda-helper");
    assert!(
        restored.join("SKILL.md").exists(),
        "approve did not restore under {}: {v}",
        restored.display()
    );
    assert!(
        !data.path().join("quarantine").join("pda-helper").exists(),
        "quarantine entry should be consumed on approve"
    );
    assert_eq!(
        lockfile(data.path())["skills"]["pda-helper"]["scan"],
        "approved"
    );
}

#[test]
fn approve_restores_gitmodules_ext_pack_to_its_submodule_path() {
    // A quarantined `ext/` submodule goes back to the path `.gitmodules` declares for it.
    let project = TempDir::new("approve-ext-proj");
    let home = TempDir::new("approve-ext-home");
    let data = TempDir::new("approve-ext-data");
    std::fs::write(
        project.path().join(".gitmodules"),
        "[submodule \".claude/skills/ext/solana-dev\"]\n\
         \tpath = .claude/skills/ext/solana-dev\n\
         \turl = https://github.com/solana-foundation/solana-dev-skill\n",
    )
    .unwrap();
    seed_quarantined(data.path(), "solana-dev");

    let v = approve(project.path(), home.path(), data.path(), "solana-dev");

    let restored = skills_root(project.path()).join("ext").join("solana-dev");
    assert!(
        restored.join("SKILL.md").exists(),
        "approve did not restore the submodule to {}: {v}",
        restored.display()
    );
    assert!(!data.path().join("quarantine").join("solana-dev").exists());
    let lock = lockfile(data.path());
    assert_eq!(lock["ext"]["solana-dev"]["scan"], "approved", "{lock}");
    assert!(lock["skills"].get("solana-dev").is_none(), "{lock}");
}
