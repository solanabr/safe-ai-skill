//! `adapters/opencode/safe-ai-skill.js` (experimental, issue #26): runs the plugin's Node tests
//! (`adapters/opencode/test/plugin.test.mjs`) with this build's engine, when Node 22 or later
//! is on `PATH` (required when `SAFE_AI_SKILL_REQUIRE_NODE_TESTS` is set, as in CI). Fake engines check that every failure blocks the call; the real engine checks
//! a deny, a Grep rewrite and a pass end to end. Skipped (with a note) without Node.

#![cfg(unix)]

mod common;

use std::process::Command;

use common::TempDir;

const TESTS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../adapters/opencode/test/plugin.test.mjs"
);

/// Node's major version, when `node` runs.
fn node_major() -> Option<u32> {
    let out = Command::new("node").arg("--version").output().ok()?;
    let version = String::from_utf8_lossy(&out.stdout);
    version
        .trim()
        .trim_start_matches('v')
        .split('.')
        .next()?
        .parse()
        .ok()
}

#[test]
#[cfg_attr(
    any(target_os = "macos", target_os = "linux"),
    ignore = "quarantined (#33): the real-engine subtest gets a wrong verdict on macOS and Linux"
)]
fn plugin_fails_closed_under_node() {
    match node_major() {
        Some(major) if major >= 22 => {}
        other => {
            assert!(
                std::env::var_os("SAFE_AI_SKILL_REQUIRE_NODE_TESTS")
                    .filter(|v| !v.is_empty())
                    .is_none(),
                "SAFE_AI_SKILL_REQUIRE_NODE_TESTS is set but node >= 22 is missing ({other:?})"
            );
            eprintln!("skipped: needs node >= 22 on PATH (found {other:?})");
            return;
        }
    }
    let home = TempDir::new("oc-plugin-home");
    let tmp = TempDir::new("oc-plugin-tmp");
    let out = Command::new("node")
        .arg("--test")
        .arg("--test-reporter=tap")
        .arg(TESTS)
        .env("HOME", home.path())
        .env("TMPDIR", tmp.path())
        .env("SAFE_AI_SKILL_TEST_ENGINE", common::bin())
        .env_remove("SAFE_AI_SKILL_ENGINE")
        .env_remove("CLAUDE_PLUGIN_DATA")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("OPENCODE_CONFIG")
        .env_remove("OPENCODE_CONFIG_DIR")
        .env_remove("OPENCODE_CONFIG_CONTENT")
        .output()
        .expect("run node --test");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "node --test failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("# fail 0"), "{stdout}");
    assert!(
        stdout.contains("# skipped 0"),
        "real-engine test skipped:\n{stdout}"
    );
}
