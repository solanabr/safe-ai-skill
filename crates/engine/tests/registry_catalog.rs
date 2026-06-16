//! Catalog (`skill-registry.json`) gating — end-to-end against the built `ssai` binary.
//!
//! Lays out a fixture project whose `.claude/skills/skill-registry.json` is a real subset of
//! solana-ai-kit's opt-in catalog (`phantom-mcp`, `x402-proxy-mcp`, plus two ordinary clean
//! entries), then drives `registry list` / `registry verify` / `add` with the project as the
//! process cwd (the catalog path resolves against `current_dir()`). Asserts:
//!   - `list` enumerates every entry with its opt-in status,
//!   - high-risk entries surface their forced class decision (`ask`) while ordinary entries do
//!     not, and `verify` records a `high_risk` count,
//!   - `add`-ing a high-risk entry is gated (held, no install command emitted) unless `--yes`,
//!   - `add`-ing an ordinary entry proceeds to the normal verify pipeline.
//!
//! Fully hermetic: isolated `CLAUDE_PLUGIN_DATA` + `HOME` temp dirs, `--offline` on `add` so no
//! network, fixture project is a temp dir.

mod common;

use common::{Invocation, TempDir};
use std::path::Path;

/// A representative subset of solana-ai-kit's `skill-registry.json` (canonical object form).
const REGISTRY_JSON: &str = r#"{
  "version": "1.0",
  "updated": "2026-06-15",
  "entries": [
    {
      "id": "anthropic-skills",
      "name": "Anthropic Skills",
      "type": "skill",
      "domain": "productivity",
      "description": "Anthropic's official skill collection.",
      "source": "https://github.com/anthropics/skills",
      "default_installed": false,
      "safety": "clean (curl references are Claude-API doc examples, not installers)",
      "tags": ["official"]
    },
    {
      "id": "ux-writing-skill",
      "name": "UX Writing Skill",
      "type": "skill",
      "domain": "ux-writing",
      "description": "Systematic UX microcopy.",
      "source": "https://github.com/content-designer/ux-writing-skill",
      "default_installed": false,
      "safety": "clean (one build-skill.sh builder, not runtime)",
      "tags": ["ux-writing"]
    },
    {
      "id": "x402-proxy-mcp",
      "name": "x402 Proxy MCP",
      "type": "mcp",
      "domain": "solana-infra",
      "description": "Agent-payments proxy MCP (x402).",
      "source": "https://www.npmjs.com/package/x402-proxy",
      "default_installed": false,
      "safety": "caution: BIP-39 key custody for agent payments — explicit opt-in only",
      "tags": ["x402", "payments", "mcp", "key-custody"]
    },
    {
      "id": "phantom-mcp",
      "name": "Phantom MCP",
      "type": "mcp",
      "domain": "solana-infra",
      "description": "Phantom wallet MCP — can sign/submit transactions.",
      "source": "https://www.npmjs.com/package/@phantom/mcp-server",
      "default_installed": false,
      "safety": "caution: wallet signing — can sign/submit transactions; explicit consent only",
      "tags": ["phantom", "wallet", "signing", "mcp"]
    }
  ]
}"#;

/// Build a fixture project at `root`: `<root>/.claude/skills/skill-registry.json`.
fn build_project(root: &Path) {
    let skills = root.join(".claude").join("skills");
    std::fs::create_dir_all(&skills).unwrap();
    std::fs::write(skills.join("skill-registry.json"), REGISTRY_JSON).unwrap();
}

/// Run a `registry`/`add` subcommand with the fixture project as cwd; return parsed JSON.
fn run_in_project(project: &Path, data: &Path, home: &Path, args: &[&str]) -> serde_json::Value {
    let run = Invocation::new(args)
        .plugin_data(data)
        .home(home)
        .cwd(project)
        .stdin("{}")
        .run();
    run.json()
}

#[test]
fn registry_list_enumerates_all_entries_with_opt_in() {
    let project = TempDir::new("reg-list-proj");
    let data = TempDir::new("reg-list-data");
    let home = TempDir::new("reg-list-home");
    build_project(project.path());

    let v = run_in_project(
        project.path(),
        data.path(),
        home.path(),
        &["registry", "list"],
    );
    assert_eq!(v["command"], "registry");
    assert_eq!(v["action"], "list");
    assert_eq!(v["count"], 4, "expected all 4 catalog entries: {v}");

    let entries = v["entries"].as_array().expect("entries array");
    // Every catalog entry is opt-in (default_installed:false).
    assert!(
        entries.iter().all(|e| e["opt_in"] == true),
        "all catalog entries should be opt-in: {entries:?}"
    );
    // The two reals are present.
    assert!(entries.iter().any(|e| e["id"] == "phantom-mcp"));
    assert!(entries.iter().any(|e| e["id"] == "x402-proxy-mcp"));
}

#[test]
fn registry_verify_surfaces_high_risk_decisions() {
    let project = TempDir::new("reg-verify-proj");
    let data = TempDir::new("reg-verify-data");
    let home = TempDir::new("reg-verify-home");
    build_project(project.path());

    let v = run_in_project(
        project.path(),
        data.path(),
        home.path(),
        &["registry", "verify"],
    );
    assert_eq!(v["action"], "verify");
    assert_eq!(
        v["high_risk"], 2,
        "phantom + x402 are the high-risk reals: {v}"
    );

    let entries = v["entries"].as_array().expect("entries array");
    let by_id = |id: &str| entries.iter().find(|e| e["id"] == id).cloned().unwrap();

    // phantom-mcp → wallet_signing, forced ask.
    let phantom = by_id("phantom-mcp");
    assert_eq!(phantom["risk_class"], "wallet_signing");
    assert_eq!(phantom["decision"], "ask");

    // x402-proxy-mcp → key_custody, forced ask.
    let x402 = by_id("x402-proxy-mcp");
    assert_eq!(x402["risk_class"], "key_custody");
    assert_eq!(x402["decision"], "ask");

    // Ordinary entries are not classified.
    let ux = by_id("ux-writing-skill");
    assert!(
        ux["risk_class"].is_null(),
        "ux skill should not be high-risk: {ux}"
    );
    let anthropic = by_id("anthropic-skills");
    assert!(
        anthropic["risk_class"].is_null(),
        "anthropic-skills 'curl references' must not match installer_script: {anthropic}"
    );
}

#[test]
fn registry_verify_audits_high_risk_entries() {
    let project = TempDir::new("reg-audit-proj");
    let data = TempDir::new("reg-audit-data");
    let home = TempDir::new("reg-audit-home");
    build_project(project.path());

    run_in_project(
        project.path(),
        data.path(),
        home.path(),
        &["registry", "verify"],
    );

    // `verify` should leave a loud audit record for each high-risk entry.
    let audit = data.path().join("audit.jsonl");
    assert!(audit.exists(), "verify did not write an audit log");
    let body = std::fs::read_to_string(&audit).unwrap();
    assert!(
        body.contains("registry_high_risk"),
        "no high-risk audit classification: {body}"
    );
    assert!(body.contains("phantom-mcp"), "phantom not audited: {body}");
    assert!(body.contains("x402-proxy-mcp"), "x402 not audited: {body}");
}

#[test]
fn add_high_risk_entry_is_gated() {
    let project = TempDir::new("add-hr-proj");
    let data = TempDir::new("add-hr-data");
    let home = TempDir::new("add-hr-home");
    build_project(project.path());

    // `add mcp phantom-mcp` resolves to the high-risk wallet-signing entry → held (ask), no
    // install command emitted, verify pipeline never runs.
    let v = run_in_project(
        project.path(),
        data.path(),
        home.path(),
        &["add", "mcp", "phantom-mcp", "--offline"],
    );
    assert_eq!(v["verdict"], "high_risk", "{v}");
    assert_eq!(v["status"], "high_risk_ask");
    assert_eq!(v["risk_class"], "wallet_signing");
    assert_eq!(v["decision"], "ask");
    assert_eq!(v["proceed"], false);
    assert!(
        v["run"].is_null(),
        "no install command should be emitted: {v}"
    );
}

#[test]
fn add_high_risk_by_source_url_is_gated() {
    let project = TempDir::new("add-src-proj");
    let data = TempDir::new("add-src-data");
    let home = TempDir::new("add-src-home");
    build_project(project.path());

    // Resolve by source URL (not id) — the x402 key-custody entry.
    let v = run_in_project(
        project.path(),
        data.path(),
        home.path(),
        &[
            "add",
            "mcp",
            "https://www.npmjs.com/package/x402-proxy",
            "--offline",
        ],
    );
    assert_eq!(v["verdict"], "high_risk", "{v}");
    assert_eq!(v["risk_class"], "key_custody");
    assert_eq!(v["proceed"], false);
}

#[test]
fn add_high_risk_with_yes_proceeds_to_pipeline() {
    let project = TempDir::new("add-yes-proj");
    let data = TempDir::new("add-yes-data");
    let home = TempDir::new("add-yes-home");
    build_project(project.path());

    // `--yes` is the explicit user confirmation: the high-risk gate records the confirmation
    // and falls through to the normal verify pipeline (which then produces its own verdict).
    let v = run_in_project(
        project.path(),
        data.path(),
        home.path(),
        &["add", "mcp", "phantom-mcp", "--offline", "--yes"],
    );
    assert_ne!(
        v["verdict"], "high_risk",
        "with --yes the gate should not short-circuit: {v}"
    );

    // The confirmation was audited.
    let body = std::fs::read_to_string(data.path().join("audit.jsonl")).unwrap_or_default();
    assert!(
        body.contains("add_high_risk_confirm"),
        "explicit confirmation not audited: {body}"
    );
}

#[test]
fn add_ordinary_entry_proceeds_normally() {
    let project = TempDir::new("add-ord-proj");
    let data = TempDir::new("add-ord-data");
    let home = TempDir::new("add-ord-home");
    build_project(project.path());

    // An ordinary catalog skill is not high-risk → it flows to the normal verify pipeline.
    let v = run_in_project(
        project.path(),
        data.path(),
        home.path(),
        &[
            "add",
            "skill",
            "https://github.com/content-designer/ux-writing-skill",
            "--offline",
        ],
    );
    assert_ne!(
        v["verdict"], "high_risk",
        "ordinary entry must not be gated: {v}"
    );
}

#[test]
fn registry_list_graceful_when_catalog_absent() {
    // No fixture project: the registry file is missing → empty catalog, no error.
    let data = TempDir::new("reg-empty-data");
    let home = TempDir::new("reg-empty-home");
    let empty = TempDir::new("reg-empty-proj"); // a project dir with no .claude/skills

    let v = run_in_project(
        empty.path(),
        data.path(),
        home.path(),
        &["registry", "list"],
    );
    assert_eq!(
        v["count"], 0,
        "absent catalog should be empty, not an error: {v}"
    );
    assert!(v["entries"].as_array().unwrap().is_empty());
}
