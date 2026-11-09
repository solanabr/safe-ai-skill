//! Catalog (`skill-registry.json`) gating — end-to-end against the built `safe-ai-skill` binary.
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

/// `name` and `version` joined with `@`, built at runtime (avoids fixture mangling).
fn at(name: &str, version: &str) -> String {
    format!("{name}{}{version}", '@')
}

/// Every spelling of a high-risk entry's package, not only its id or literal source.
fn high_risk_spellings() -> Vec<(String, &'static str)> {
    vec![
        ("@phantom/mcp-server".into(), "phantom-mcp"),
        (at("@phantom/mcp-server", "1.2.9"), "phantom-mcp"),
        (at("@Phantom/MCP-Server", "latest"), "phantom-mcp"),
        ("npm:@phantom/mcp-server".into(), "phantom-mcp"),
        (
            "https://npmjs.com/package/@phantom/mcp-server".into(),
            "phantom-mcp",
        ),
        (
            "https://www.npmjs.com/package/@phantom/mcp-server/v/1.2.9".into(),
            "phantom-mcp",
        ),
        ("x402-proxy".into(), "x402-proxy-mcp"),
        (at("x402-proxy", "0.1.0"), "x402-proxy-mcp"),
    ]
}

#[test]
fn add_high_risk_is_gated_under_every_spelling() {
    let project = TempDir::new("add-spell-proj");
    let data = TempDir::new("add-spell-data");
    let home = TempDir::new("add-spell-home");
    build_project(project.path());
    for (source, id) in high_risk_spellings() {
        let v = run_in_project(
            project.path(),
            data.path(),
            home.path(),
            &["add", "mcp", &source, "--offline"],
        );
        assert_eq!(
            (&v["status"], &v["entry_id"]),
            (&serde_json::json!("high_risk_ask"), &serde_json::json!(id)),
            "{source}: {v}"
        );
        assert!(v["run"].is_null(), "{source}: {v}");
    }
}

/// Online too: the gate needs no network and answers before any lookup (the lookups point at
/// a closed loopback port, so a gate that let a source through would still not reach out).
#[cfg(feature = "test-hooks")]
#[test]
fn add_high_risk_is_gated_under_every_spelling_online() {
    use safe_ai_skill::verify::{osv, provenance};
    let project = TempDir::new("add-spell-on-proj");
    let data = TempDir::new("add-spell-on-data");
    let home = TempDir::new("add-spell-on-home");
    build_project(project.path());
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let closed = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    for (source, id) in high_risk_spellings() {
        let run = Invocation::new(&["add", "mcp", &source])
            .plugin_data(data.path())
            .home(home.path())
            .cwd(project.path())
            .env(provenance::TEST_NPM_REGISTRY_ENV, &closed)
            .env(provenance::TEST_GITHUB_API_ENV, &closed)
            .env(osv::TEST_URL_ENV, &closed)
            .run();
        let v = run.json();
        assert_eq!(
            (&v["status"], &v["entry_id"]),
            (&serde_json::json!("high_risk_ask"), &serde_json::json!(id)),
            "{source}: {v}"
        );
    }
}

#[test]
fn add_a_confirmed_high_risk_id_grades_the_entry_source_not_a_package_of_that_name() {
    let project = TempDir::new("add-h3-proj");
    let data = TempDir::new("add-h3-data");
    let home = TempDir::new("add-h3-home");
    build_project(project.path());
    for (id, package, server) in [
        ("phantom-mcp", "@phantom/mcp-server", "mcp-server"),
        ("x402-proxy-mcp", "x402-proxy", "x402-proxy"),
    ] {
        let v = run_in_project(
            project.path(),
            data.path(),
            home.path(),
            &["add", "mcp", id, "--offline", "--yes"],
        );
        assert_eq!(
            (&v["source"], &v["catalog_entry"], &v["source_kind"]),
            (
                &serde_json::json!(id),
                &serde_json::json!(id),
                &serde_json::json!("npm")
            ),
            "{v}"
        );
        assert!(
            v["catalog_source"]
                .as_str()
                .is_some_and(|s| s.ends_with(package)),
            "{v}"
        );
        assert_eq!(
            v["run"],
            format!("claude mcp add {server} -- npx -y {package}"),
            "{v}"
        );
        let text = v.to_string();
        assert!(!text.contains(&format!("npx -y {id}")), "{v}");
    }
}

#[test]
fn add_an_ordinary_catalog_id_grades_its_source() {
    let project = TempDir::new("add-ord-id-proj");
    let data = TempDir::new("add-ord-id-data");
    let home = TempDir::new("add-ord-id-home");
    build_project(project.path());
    let v = run_in_project(
        project.path(),
        data.path(),
        home.path(),
        &["add", "skill", "ux-writing-skill", "--offline", "--yes"],
    );
    assert_eq!(
        (&v["source_kind"], &v["catalog_entry"], &v["status"]),
        (
            &serde_json::json!("github"),
            &serde_json::json!("ux-writing-skill"),
            &serde_json::json!("warn_proceed")
        ),
        "{v}"
    );
    assert_eq!(
        v["run"], "npx skills add https://github.com/content-designer/ux-writing-skill",
        "{v}"
    );
    // Another spelling of the same repository names the entry too.
    let v = run_in_project(
        project.path(),
        data.path(),
        home.path(),
        &[
            "add",
            "skill",
            "content-designer/ux-writing-skill",
            "--offline",
        ],
    );
    assert_eq!(v["catalog_entry"], "ux-writing-skill", "{v}");
}
