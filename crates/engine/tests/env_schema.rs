//! varlock `.env.schema` is readable by default (#14), guarded by a content check.
//!
//! Drives the real binary with the hook `cwd` at a sandbox project. The schema is on the
//! base `allow_read_globs`; every other `.env.*` file stays denied. A schema that holds
//! key material (keypair array, base58 secret key, private-key block) is denied anyway.

mod common;

use std::path::Path;

use common::{decision_label, Invocation, TempDir};
use safe_ai_skill::policy::{Policy, DEFAULT_POLICY_YAML};
use serde_json::json;

/// solanabr/ai-kit's real `.safe-ai-skill/policy.yaml` (byte-exact).
const AIKIT_POLICY: &str = include_str!("fixtures/aikit-policy.yaml");

const CLEAN_SCHEMA: &str = concat!(
    "# @defaultSensitive=true\n# ---\n",
    "# @required @type=string\nHELIUS_API_KEY=varlock(\"local:abc\")\n",
    "# @public\nSOLANA_CLUSTER=devnet\n",
    "# @public\nFEE_PAYER=9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin\n",
);

fn project() -> TempDir {
    TempDir::new("envschema-proj")
}

/// Run `sub` for `tool`/`tool_input` with the hook cwd at `cwd`; returns (label, reason).
fn gate_full(sub: &str, tool: &str, tool_input: serde_json::Value, cwd: &Path) -> (String, String) {
    let data = TempDir::new("envschema-data");
    let home = TempDir::new("envschema-home");
    let payload = json!({
        "session_id": "it-envschema",
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": tool_input,
    })
    .to_string();
    let run = Invocation::new(&[sub])
        .plugin_data(data.path())
        .home(home.path())
        .stdin(payload)
        .run();
    let label = decision_label(&run);
    let reason = if label.is_empty() {
        String::new()
    } else {
        run.json()["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap_or("")
            .to_string()
    };
    (label, reason)
}

fn read(cwd: &Path, path: impl AsRef<Path>) -> (String, String) {
    gate_full(
        "gate-read",
        "Read",
        json!({ "file_path": path.as_ref() }),
        cwd,
    )
}

fn bash_secrets(cwd: &Path, command: &str) -> String {
    gate_full(
        "gate-bash-secrets",
        "Bash",
        json!({ "command": command }),
        cwd,
    )
    .0
}

fn write(proj: &TempDir, rel: &str, body: impl AsRef<[u8]>) {
    let p = proj.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, body).unwrap();
}

#[test]
fn read_schema_has_no_opinion() {
    let proj = project();
    write(&proj, ".env.schema", CLEAN_SCHEMA);
    write(&proj, "sub/dir/.env.schema", CLEAN_SCHEMA);
    assert_eq!(read(proj.path(), proj.join(".env.schema")).0, "");
    assert_eq!(read(proj.path(), proj.join("sub/dir/.env.schema")).0, "");
    assert_eq!(read(proj.path(), ".env.schema").0, "");
    // The allow-list match is case-sensitive (an allow never widens by case folding), while
    // the env class is not: an upper-case name is an env file (1.1.0, #7).
    write(&proj, ".ENV.SCHEMA", CLEAN_SCHEMA);
    assert_eq!(read(proj.path(), proj.join(".ENV.SCHEMA")).0, "deny");
}

#[test]
fn read_other_env_files_still_deny() {
    let proj = project();
    for name in [
        ".env",
        ".env.local",
        ".env.production",
        ".env.schema.bak",
        ".env.schema.local",
    ] {
        write(&proj, name, "X=1\n");
        assert_eq!(read(proj.path(), proj.join(name)).0, "deny", "{name}");
    }
}

#[test]
fn grep_on_schema_has_no_opinion() {
    let proj = project();
    write(&proj, ".env.schema", CLEAN_SCHEMA);
    let (label, _) = gate_full(
        "gate-read",
        "Grep",
        json!({ "pattern": "API", "path": ".env.schema" }),
        proj.path(),
    );
    assert_eq!(label, "");
}

#[test]
fn bash_cat_schema_has_no_opinion_but_env_local_denies() {
    let proj = project();
    assert_eq!(bash_secrets(proj.path(), "cat .env.schema"), "");
    assert_eq!(bash_secrets(proj.path(), "cat sub/.env.schema"), "");
    assert_eq!(bash_secrets(proj.path(), "cat .env.local"), "deny");
    assert_eq!(bash_secrets(proj.path(), "cat .env.schema.local"), "deny");
}

fn assert_schema_secret_denied(body: &str) {
    let proj = project();
    write(&proj, ".env.schema", body);
    let (label, reason) = read(proj.path(), proj.join(".env.schema"));
    assert_eq!(label, "deny", "{body:?}");
    assert!(reason.contains("contains a secret value"), "{reason}");
    assert!(
        !reason.contains("1,2,3"),
        "reason echoed the secret: {reason}"
    );
}

#[test]
fn schema_with_keypair_array_denies() {
    let arr: Vec<String> = (0..64).map(|i| i.to_string()).collect();
    assert_schema_secret_denied(&format!("# @sensitive\nWALLET=[{}]\n", arr.join(",")));
}

#[test]
fn schema_with_base58_secret_key_denies() {
    let key = bs58::encode(vec![7u8; 64]).into_string();
    assert_schema_secret_denied(&format!("# @sensitive\nWALLET={key}\n"));
}

#[test]
fn schema_with_private_key_block_denies() {
    assert_schema_secret_denied(concat!(
        "KEY=\"-----BEGIN PRIVATE KEY-----\n",
        "MC4CAQAwBQYDK2VwBCIEIGv1,2,3\n-----END PRIVATE KEY-----\"\n"
    ));
}

#[test]
fn schema_with_api_key_and_credential_values_denies() {
    for body in [
        "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwx\n",
        "STRIPE_KEY=sk_\x6cive_abcdefghijklmnop1234\n",
        "T=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghij\n",
        "HELIUS_API_KEY=0a1b2c3d-4e5f-6789-abcd-ef0123456789\n",
        "DB_PASSWORD=hunter2\n",
        "GH_TOKEN=ghp_abc123\n",
        "APP_SECRET=\"s3cr3t\"\n",
        "SIGNER_PRIVATE_KEY=abc\n",
        "STRIPE_SECRET_KEY=abc123\n",
        "SECRET_KEY=abc123\n",
        "AUTH_KEY=abc123\n",
        "AWS_ACCESS_KEY=AKIA1234\n",
        "DB_SECRET_URL=abc123\n",
        "API_KEY=abc123 # note\n",
    ] {
        let proj = project();
        write(&proj, ".env.schema", body);
        let (label, reason) = read(proj.path(), proj.join(".env.schema"));
        assert_eq!(label, "deny", "{body:?}");
        assert!(reason.contains("contains a secret value"), "{reason}");
    }
}

#[test]
fn schema_with_non_literal_values_has_no_opinion() {
    let proj = project();
    write(
        &proj,
        ".env.schema",
        concat!(
            "# OPENAI_API_KEY=hunter2\nHELIUS_API_KEY=\nA_API_KEY=varlock(\"local:x\")\n",
            "B_API_KEY=exec(`op read x`)\nDB_PASSWORD=$DB_PASSWORD\nC_TOKEN=${C_TOKEN}\n",
            "D_SECRET=<paste here>\nE_TOKEN=xxx\nF_TOKEN=changeme\nG_TOKEN=your-token\n",
            "API_KEY= # @sensitive\nH_API_KEY=exec('op read x') # note\nSECRET_KEY=\n",
            "STRIPE_SECRET_KEY=$STRIPE\nPUBLIC_KEY=abc123\n",
        ),
    );
    assert_eq!(read(proj.path(), proj.join(".env.schema")).0, "");
}

#[cfg(unix)]
#[test]
fn hardlinked_env_named_schema_denies() {
    let proj = project();
    write(
        &proj,
        ".env",
        "HELIUS_API_KEY=0a1b2c3d-4e5f-6789-abcd-ef0123456789\nDB_PASSWORD=hunter2\n",
    );
    std::fs::hard_link(proj.join(".env"), proj.join(".env.schema")).unwrap();
    assert_eq!(read(proj.path(), proj.join(".env.schema")).0, "deny");
}

#[cfg(unix)]
#[test]
fn fifo_named_schema_denies_without_hanging() {
    let proj = project();
    let fifo = proj.join(".env.schema");
    let made = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(made.success());
    assert_eq!(read(proj.path(), &fifo).0, "deny");
}

#[test]
fn upper_case_schema_with_secret_denies() {
    let proj = project();
    let key = bs58::encode(vec![7u8; 64]).into_string();
    write(&proj, ".ENV.SCHEMA", format!("WALLET={key}\n"));
    assert_eq!(read(proj.path(), proj.join(".ENV.SCHEMA")).0, "deny");
}

#[test]
fn oversize_schema_denies() {
    let proj = project();
    write(&proj, ".env.schema", "# pad\n".repeat(64 * 1024 / 6 + 1));
    assert_eq!(read(proj.path(), proj.join(".env.schema")).0, "deny");
    // Exactly at the bound is fine.
    write(&proj, ".env.schema", "#".repeat(64 * 1024));
    assert_eq!(read(proj.path(), proj.join(".env.schema")).0, "");
}

#[test]
fn unreadable_schema_denies() {
    let proj = project();
    // A directory named like the schema cannot be read as a file.
    std::fs::create_dir_all(proj.join(".env.schema")).unwrap();
    assert_eq!(read(proj.path(), proj.join(".env.schema")).0, "deny");
}

#[cfg(unix)]
#[test]
fn schema_symlinked_to_env_denies() {
    let proj = project();
    write(&proj, ".env", "PLAIN=hunter2\n");
    std::os::unix::fs::symlink(proj.join(".env"), proj.join(".env.schema")).unwrap();
    assert_eq!(read(proj.path(), proj.join(".env.schema")).0, "deny");
}

#[test]
fn missing_schema_has_no_opinion() {
    let proj = project();
    assert_eq!(read(proj.path(), proj.join(".env.schema")).0, "");
}

#[test]
fn default_policy_allows_schema_and_aikit_overlay_keeps_it() {
    let base = Policy::from_sources(DEFAULT_POLICY_YAML, None, None, None);
    assert!(base
        .secrets
        .allow_read_globs
        .contains(&"**/.env.schema".to_string()));
    let aikit = Policy::from_sources(DEFAULT_POLICY_YAML, Some(AIKIT_POLICY), None, None);
    assert_eq!(
        aikit.secrets.allow_read_globs,
        base.secrets.allow_read_globs
    );
}

#[test]
fn repo_listing_only_env_example_removes_the_schema_allow() {
    let overlay = "secrets:\n  allow_read_globs: [\"**/.env.example\"]\n";
    let p = Policy::from_sources(DEFAULT_POLICY_YAML, Some(overlay), None, None);
    assert_eq!(
        p.secrets.allow_read_globs,
        vec!["**/.env.example".to_string()]
    );

    let proj = project();
    let cfg = proj.join(".safe-ai-skill");
    std::fs::create_dir_all(&cfg).unwrap();
    std::fs::write(cfg.join("policy.yaml"), overlay).unwrap();
    write(&proj, ".env.schema", CLEAN_SCHEMA);
    assert_eq!(read(proj.path(), proj.join(".env.schema")).0, "deny");
    assert_eq!(bash_secrets(proj.path(), "cat .env.schema"), "deny");
}

#[test]
fn deny_reason_for_env_local_is_unchanged() {
    let proj = project();
    let (label, reason) = read(proj.path(), proj.join(".env.local"));
    assert_eq!(label, "deny");
    assert!(reason.contains("is an env file"), "{reason}");
}
