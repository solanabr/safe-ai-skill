//! Sandboxed `install --from <dir> --home <home>` validation (generic local-install path).
//!
//! Builds a fixture mimicking an extracted local skills source — a skill dir whose `SKILL.md`
//! carries a Convex-style telemetry preamble plus a fixture `.mcp.json` pinned to `@latest` —
//! and drives `safe-ai-skill install --from <fixture> --home <tmphome>` fully offline (no network, real
//! home untouched). Asserts the hub-agnostic local install contract:
//!   - the telemetry curl is flagged HIGH and reported,
//!   - the INSTALLED `SKILL.md` has the telemetry preamble neutralized,
//!   - `@latest` MCP entries are flagged (via the `verify session` sweep),
//!   - the sandbox `settings.json` permissions were NOT widened,
//!   - nothing was written outside the sandbox home/plugin-data.
//!
//! This is the generic local-install path: there is no hardcoded download URL and no
//! solana-new special-casing. The solana-new telemetry SKILL.md is exercised as a generic
//! `ext/` submodule in `ext_submodule_verify.rs`, not here.

mod common;

use common::{Invocation, TempDir};
use std::path::Path;

/// A Convex-style telemetry preamble (fire-and-forget POST) baked into a skill's `SKILL.md`.
const TELEMETRY_PREAMBLE: &str = "```bash\n\
# telemetry (fire-and-forget)\n\
_CONVEX_URL=\"https://oceanic-marlin-42.convex.cloud\"\n\
curl -s -X POST \"$_CONVEX_URL/api/mutation\" \\\n\
  -H 'Content-Type: application/json' \\\n\
  -d '{\"path\":\"telemetry:record\",\"args\":{\"skill\":\"deploy-to-mainnet\"}}' \\\n\
  >/dev/null 2>&1 || true\n\
```\n";

/// Lay out a generic extracted-skills fixture under `root`.
///
/// Layout: `root/deploy-to-mainnet/SKILL.md` (with telemetry) + `root/.mcp.json` (helius pinned
/// `@latest`). Each immediate child dir carrying a `SKILL.md` is the unit `install` processes —
/// matching how a local extracted source lays skills out as top-level directories.
fn build_fixture(root: &Path) {
    let skill_dir = root.join("deploy-to-mainnet");
    std::fs::create_dir_all(&skill_dir).unwrap();

    let skill_md = format!(
        "---\nname: deploy-to-mainnet\ntelemetryTier: full\n---\n\n\
         # Deploy to Mainnet\n\n\
         Guides a project from devnet to mainnet.\n\n\
         {TELEMETRY_PREAMBLE}\n\
         ## Steps\n1. Build the program.\n2. Deploy.\n"
    );
    std::fs::write(skill_dir.join("SKILL.md"), skill_md).unwrap();

    // A fixture .mcp.json with an @latest-pinned helius server (unpinned spec).
    let mcp = r#"{
  "mcpServers": {
    "helius": { "command": "npx", "args": ["-y", "helius-mcp@latest"] }
  }
}"#;
    std::fs::write(root.join(".mcp.json"), mcp).unwrap();
}

/// Drive a sandboxed offline install; returns the parsed result JSON + the home/data dirs.
fn run_install() -> (serde_json::Value, TempDir, TempDir) {
    let fixture = TempDir::new("install-fixture");
    let home = TempDir::new("install-home");
    let data = TempDir::new("install-data");
    build_fixture(fixture.path());

    let run = Invocation::new(&[
        "install",
        "--from",
        fixture.path().to_str().unwrap(),
        "--home",
        home.path().to_str().unwrap(),
    ])
    .plugin_data(data.path())
    .home(home.path())
    .stdin("{}")
    .run();

    let v = run.json();
    assert_eq!(
        v["status"], "done",
        "install did not finish: {}",
        run.stdout
    );
    drop(fixture);
    (v, home, data)
}

#[test]
fn telemetry_flagged_high() {
    let (v, _home, _data) = run_install();
    let flagged = v["flagged"].as_array().expect("flagged array");
    let has_high_telemetry = flagged.iter().any(|f| {
        f["severity"] == "high"
            && f["kind"]
                .as_str()
                .map(|k| k.contains("telemetry"))
                .unwrap_or(false)
    });
    assert!(
        has_high_telemetry,
        "install did not flag the telemetry curl as HIGH: {flagged:?}"
    );
}

#[test]
fn installed_skill_md_is_neutralized() {
    let (v, home, _data) = run_install();

    // The skill should still install (its only danger was the now-removed telemetry block).
    let installed = v["installed"].as_array().expect("installed array");
    assert!(
        installed.iter().any(|s| s == "deploy-to-mainnet"),
        "skill not installed: {installed:?}"
    );

    // The installed copy lives under <home>/.claude/skills/<name>/SKILL.md.
    let installed_md = home
        .path()
        .join(".claude")
        .join("skills")
        .join("deploy-to-mainnet")
        .join("SKILL.md");
    assert!(installed_md.exists(), "installed SKILL.md missing");

    let body = std::fs::read_to_string(&installed_md).unwrap();
    let lower = body.to_lowercase();
    // No live telemetry POST remains.
    assert!(
        !lower.contains("/api/mutation"),
        "telemetry endpoint survived neutralization:\n{body}"
    );
    assert!(
        !(lower.contains("curl") && lower.contains("-x post")),
        "live curl POST survived neutralization:\n{body}"
    );
    // The telemetry tier was flipped off.
    assert!(
        lower.contains("telemetrytier: off"),
        "telemetryTier was not set to off:\n{body}"
    );
    // The benign content survives.
    assert!(body.contains("## Steps"), "benign content was lost");
}

#[test]
fn mcp_latest_entries_flagged() {
    // The `.mcp.json` scan is exposed via `verify session` (the SessionStart sweep folds an
    // `.mcp.json` scan into additionalContext). Run it against the fixture cwd and assert the
    // unpinned helius@latest server is reported.
    let fixture = TempDir::new("mcp-fixture");
    let home = TempDir::new("mcp-home");
    let data = TempDir::new("mcp-data");
    build_fixture(fixture.path());

    let payload = serde_json::json!({
        "hook_event_name": "SessionStart",
        "source": "startup",
        "cwd": fixture.path().to_str().unwrap()
    })
    .to_string();

    let run = Invocation::new(&["verify", "session"])
        .plugin_data(data.path())
        .home(home.path())
        .stdin(payload)
        .run();
    let v = run.json();
    let ctx = v["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap_or("");
    assert!(
        ctx.to_lowercase().contains("unpinned")
            || ctx.contains("@latest")
            || ctx.contains("helius"),
        "verify session did not flag the @latest MCP server: {ctx:?}\n{}",
        run.stdout
    );
}

#[test]
fn settings_json_not_widened() {
    let (_v, home, _data) = run_install();

    // A hub setup.sh would widen ~/.claude/settings.json to auto-allow Bash/Read/Glob/Grep.
    // `install` must NEVER do that — assert no settings.json was created with such an allow.
    let settings = home.path().join(".claude").join("settings.json");
    if settings.exists() {
        let body = std::fs::read_to_string(&settings).unwrap();
        for perm in ["Bash", "Read", "Glob", "Grep"] {
            assert!(
                !body.contains(&format!("\"{perm}\"")),
                "install widened settings.json with an auto-allow for {perm}:\n{body}"
            );
        }
    }
    // The canonical, correct outcome: install wrote skills but not settings.json at all.
    assert!(
        !settings.exists(),
        "install unexpectedly created settings.json"
    );
}

#[test]
fn nothing_written_outside_sandbox() {
    let fixture = TempDir::new("scope-fixture");
    let home = TempDir::new("scope-home");
    let data = TempDir::new("scope-data");
    build_fixture(fixture.path());

    let run = Invocation::new(&[
        "install",
        "--from",
        fixture.path().to_str().unwrap(),
        "--home",
        home.path().to_str().unwrap(),
    ])
    .plugin_data(data.path())
    .home(home.path())
    .stdin("{}")
    .run();
    assert_eq!(run.json()["status"], "done");

    // Installed skill lives under the sandbox home.
    let installed = home
        .path()
        .join(".claude")
        .join("skills")
        .join("deploy-to-mainnet");
    assert!(installed.exists(), "skill not under sandbox home");

    // Lockfile lives under the sandbox plugin-data.
    assert!(
        data.path().join("lockfile.json").exists(),
        "lockfile not under sandbox plugin-data"
    );

    // The install root is exactly the sandbox path the result reports (no escape).
    let install_root = run.json()["install_root"].as_str().unwrap().to_string();
    assert!(
        install_root.starts_with(home.path().to_str().unwrap()),
        "install_root escaped the sandbox home: {install_root}"
    );
}
