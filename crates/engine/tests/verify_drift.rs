//! Sandboxed TOFU drift detection for `verify session`.
//!
//! Places a clean fixture skill under the sandbox `~/.claude/skills` (HOME overridden), pins
//! it with a first `verify session` sweep, tampers one byte, then re-runs `verify session`
//! and asserts the drift is caught: the skill is quarantined under the sandbox plugin-data
//! and a loud warning is injected into the SessionStart `additionalContext`.
//!
//! Fully hermetic: HOME + CLAUDE_PLUGIN_DATA are both sandbox temp dirs, so the sweep scans
//! only the fixture and writes lockfile/quarantine only inside the sandbox.

mod common;

use common::{Invocation, TempDir};
use std::path::{Path, PathBuf};

/// `<home>/.claude/skills` — where the default policy roots resolve under the sandbox HOME.
fn skills_root(home: &Path) -> PathBuf {
    home.join(".claude").join("skills")
}

/// Run `verify session` in the sandbox and return the parsed SessionStart emit.
fn verify_session(home: &Path, data: &Path) -> serde_json::Value {
    let payload = serde_json::json!({
        "hook_event_name": "SessionStart",
        "source": "startup",
        "cwd": home.to_str().unwrap()
    })
    .to_string();
    let run = Invocation::new(&["verify", "session"])
        .plugin_data(data)
        .home(home)
        .stdin(payload)
        .run();
    run.json()
}

#[test]
fn drift_is_detected_and_quarantined() {
    let home = TempDir::new("drift-home");
    let data = TempDir::new("drift-data");

    // Seed a clean fixture skill under the sandbox ~/.claude/skills.
    let skill = skills_root(home.path()).join("address-formatter");
    std::fs::create_dir_all(&skill).unwrap();
    std::fs::write(
        skill.join("SKILL.md"),
        "# Address Formatter\n\nFormats Solana addresses for display.\n",
    )
    .unwrap();

    // 1. First sweep pins the clean skill (TOFU). Nothing should be quarantined.
    let first = verify_session(home.path(), data.path());
    assert_eq!(
        first["hookSpecificOutput"]["reloadSkills"], false,
        "clean first sweep should not reload skills: {first}"
    );
    // The lockfile must now carry the pin.
    let lockfile = data.path().join("lockfile.json");
    assert!(lockfile.exists(), "lockfile not written after first sweep");
    let lock_body = std::fs::read_to_string(&lockfile).unwrap();
    assert!(
        lock_body.contains("address-formatter"),
        "skill not pinned: {lock_body}"
    );
    // Skill is still in place (not quarantined).
    assert!(skill.join("SKILL.md").exists());

    // 2. Tamper one byte in the pinned skill.
    let md_path = skill.join("SKILL.md");
    let mut body = std::fs::read_to_string(&md_path).unwrap();
    body.push('X'); // single-byte mutation → tree hash changes
    std::fs::write(&md_path, body).unwrap();

    // 3. Second sweep must detect drift → quarantine + warn + reloadSkills.
    let second = verify_session(home.path(), data.path());
    let inner = &second["hookSpecificOutput"];
    assert_eq!(
        inner["reloadSkills"], true,
        "drift should trigger reloadSkills: {second}"
    );
    let ctx = inner["additionalContext"].as_str().unwrap_or("");
    assert!(
        ctx.contains("address-formatter"),
        "warning did not name the drifted skill: {ctx:?}"
    );
    assert!(
        ctx.to_lowercase().contains("quarantin") || ctx.to_lowercase().contains("drift"),
        "warning did not mention quarantine/drift: {ctx:?}"
    );

    // The drifted skill was moved out of the skills root into the sandbox quarantine.
    assert!(
        !skill.join("SKILL.md").exists(),
        "drifted skill should have been removed from the skills root"
    );
    let quarantined = data
        .path()
        .join("quarantine")
        .join("address-formatter")
        .join("SKILL.md");
    assert!(
        quarantined.exists(),
        "drifted skill not found in sandbox quarantine"
    );
}

#[test]
fn approve_restores_quarantined_skill() {
    // After a drift quarantine, `verify approve <name>` restores + re-pins the skill.
    let home = TempDir::new("approve-home");
    let data = TempDir::new("approve-data");

    let skill = skills_root(home.path()).join("pda-helper");
    std::fs::create_dir_all(&skill).unwrap();
    std::fs::write(skill.join("SKILL.md"), "# PDA Helper\n").unwrap();

    // Pin, tamper, re-sweep → quarantine.
    verify_session(home.path(), data.path());
    let md = skill.join("SKILL.md");
    let mut body = std::fs::read_to_string(&md).unwrap();
    body.push('Z');
    std::fs::write(&md, body).unwrap();
    let swept = verify_session(home.path(), data.path());
    assert_eq!(swept["hookSpecificOutput"]["reloadSkills"], true);
    assert!(data.path().join("quarantine").join("pda-helper").exists());

    // Approve restores it back under the first configured skills root (~/.claude/skills).
    let run = Invocation::new(&["verify", "approve", "pda-helper"])
        .plugin_data(data.path())
        .home(home.path())
        .stdin("{}")
        .run();
    let v = run.json();
    assert_eq!(v["status"], "approved", "approve failed: {}", run.stdout);

    // Restored on disk; quarantine entry consumed.
    assert!(
        skill.join("SKILL.md").exists(),
        "approve did not restore the skill"
    );
    assert!(
        !data.path().join("quarantine").join("pda-helper").exists(),
        "quarantine entry should be consumed on approve"
    );
}
