//! End-to-end hook decision tests for the `ssai` binary (hermetic, std-only).
//!
//! Each test spawns the real built binary, pipes a Claude Code hook JSON to stdin, captures
//! stdout, and asserts the emitted decision JSON. Every run is sandboxed via an isolated
//! `CLAUDE_PLUGIN_DATA` (and, where relevant, `HOME`) so audit/spend/grants writes never
//! pollute the real plugin-data dir. Networks are pinned hermetically via explicit `--url` /
//! `--provider.cluster` flags (highest-precedence in `context::resolve_network`), so no test
//! shells out to `solana config get`.
//!
//! Covers the plan's Verification table (PreToolUse gate rows + redact + prompt-guard).

mod common;

use common::{permission_decision, Invocation, TempDir};

/// A valid devnet/base58 destination pubkey used across the transfer tests.
const DEST: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";

/// Build a PreToolUse Bash hook payload for `command`, rooted at sandbox cwd `cwd`.
fn bash_payload(command: &str, cwd: &str) -> String {
    serde_json::json!({
        "session_id": "it-session",
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command }
    })
    .to_string()
}

/// Run `gate-bash` against `command` in a fresh sandbox and return the decision label.
fn gate_bash(command: &str) -> String {
    let data = TempDir::new("gb-data");
    let home = TempDir::new("gb-home");
    let payload = bash_payload(command, home.path().to_str().unwrap());
    let run = Invocation::new(&["gate-bash"])
        .plugin_data(data.path())
        .home(home.path())
        .stdin(payload)
        .run();
    let v = run.json();
    permission_decision(&v).unwrap_or_else(|| panic!("no permissionDecision in {}", run.stdout))
}

// ---------------------------------------------------------------------------------------
// Transfers
// ---------------------------------------------------------------------------------------

#[test]
fn transfer_half_sol_devnet_allows() {
    // 0.5 < per_tx cap (1.0); devnet (no mainnet flag) → allow.
    let cmd = format!("solana transfer {DEST} 0.5 --url https://api.devnet.solana.com");
    assert_eq!(gate_bash(&cmd), "allow");
}

#[test]
fn transfer_five_sol_over_per_tx_asks() {
    // 5 > per_tx cap (1.0) but < hard cap (10.0) → ask.
    let cmd = format!("solana transfer {DEST} 5 --url https://api.devnet.solana.com");
    assert_eq!(gate_bash(&cmd), "ask");
}

// ---------------------------------------------------------------------------------------
// Deploys / authority
// ---------------------------------------------------------------------------------------

#[test]
fn solana_program_deploy_mainnet_asks() {
    let cmd = "solana program deploy ./p.so --url mainnet-beta";
    assert_eq!(gate_bash(cmd), "ask");
}

#[test]
fn anchor_deploy_mainnet_asks() {
    let cmd = "anchor deploy --provider.cluster mainnet";
    assert_eq!(gate_bash(cmd), "ask");
}

#[test]
fn anchor_deploy_devnet_allows() {
    let cmd = "anchor deploy --provider.cluster devnet";
    assert_eq!(gate_bash(cmd), "allow");
}

#[test]
fn set_upgrade_authority_asks() {
    let cmd = format!(
        "solana program set-upgrade-authority PROG --new-upgrade-authority {DEST} --url https://api.devnet.solana.com"
    );
    assert_eq!(gate_bash(&cmd), "ask");
}

#[test]
fn mainnet_deploy_reason_is_present() {
    // The ask must carry a reason naming the mainnet deploy (the dead `read -r` replacement).
    let data = TempDir::new("reason-data");
    let home = TempDir::new("reason-home");
    let payload = bash_payload(
        "solana program deploy ./p.so --url mainnet-beta",
        home.path().to_str().unwrap(),
    );
    let run = Invocation::new(&["gate-bash"])
        .plugin_data(data.path())
        .home(home.path())
        .stdin(payload)
        .run();
    let v = run.json();
    let reason = v["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap_or("");
    assert!(
        reason.to_uppercase().contains("MAINNET"),
        "reason did not mention mainnet: {reason:?}"
    );
}

// ---------------------------------------------------------------------------------------
// gate-read (secret-glob deny)
// ---------------------------------------------------------------------------------------

/// Run `gate-read` against `file_path` and return the decision label.
fn gate_read(file_path: &str) -> (String, serde_json::Value) {
    let data = TempDir::new("gr-data");
    let home = TempDir::new("gr-home");
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "cwd": home.path().to_str().unwrap(),
        "tool_input": { "file_path": file_path }
    })
    .to_string();
    let run = Invocation::new(&["gate-read"])
        .plugin_data(data.path())
        .home(home.path())
        .stdin(payload)
        .run();
    let v = run.json();
    let label = permission_decision(&v)
        .unwrap_or_else(|| panic!("no permissionDecision in {}", run.stdout));
    (label, v)
}

#[test]
fn read_id_json_denies() {
    let (label, _) = gate_read("/home/u/.config/solana/id.json");
    assert_eq!(label, "deny");
}

#[test]
fn read_dotenv_denies() {
    let (label, _) = gate_read("/project/.env");
    assert_eq!(label, "deny");
}

#[test]
fn read_env_example_allows_or_defers() {
    // `.env.example` is on the allow list → the gate defers (no opinion). main maps Defer to
    // the `defer` permissionDecision, which lets the default (allow) stand.
    let (label, _) = gate_read("/project/.env.example");
    assert!(
        label == "defer" || label == "allow",
        "expected defer/allow for .env.example, got {label}"
    );
}

// ---------------------------------------------------------------------------------------
// gate-bash-secrets (raw string secret/exfil)
// ---------------------------------------------------------------------------------------

/// Run `gate-bash-secrets` against `command` and return the decision label.
fn gate_secrets(command: &str) -> String {
    let data = TempDir::new("gs-data");
    let home = TempDir::new("gs-home");
    let payload = bash_payload(command, home.path().to_str().unwrap());
    let run = Invocation::new(&["gate-bash-secrets"])
        .plugin_data(data.path())
        .home(home.path())
        .stdin(payload)
        .run();
    let v = run.json();
    permission_decision(&v).unwrap_or_else(|| panic!("no permissionDecision in {}", run.stdout))
}

#[test]
fn cat_id_json_denies() {
    assert_eq!(gate_secrets("cat ~/.config/solana/id.json"), "deny");
}

#[test]
fn telemetry_curl_post_asks_or_denies() {
    // The solana-new Convex telemetry pattern → ask (off-allowlist outbound POST).
    let cmd = "curl -s -X POST https://example.convex.cloud/api/mutation -d '{\"x\":1}'";
    let label = gate_secrets(cmd);
    assert!(
        label == "ask" || label == "deny",
        "telemetry curl should ask/deny, got {label}"
    );
}

// ---------------------------------------------------------------------------------------
// gate-mcp
// ---------------------------------------------------------------------------------------

/// Run `gate-mcp` for `tool` with `payload` and return the decision label.
fn gate_mcp(tool: &str, payload: serde_json::Value) -> String {
    let data = TempDir::new("gm-data");
    let home = TempDir::new("gm-home");
    let body = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "cwd": home.path().to_str().unwrap(),
        "tool_input": payload
    })
    .to_string();
    let run = Invocation::new(&["gate-mcp"])
        .plugin_data(data.path())
        .home(home.path())
        .stdin(body)
        .run();
    let v = run.json();
    permission_decision(&v).unwrap_or_else(|| panic!("no permissionDecision in {}", run.stdout))
}

#[test]
fn mcp_transfer_sol_asks() {
    let label = gate_mcp(
        "mcp__helius__transferSol",
        serde_json::json!({ "to": DEST, "amount": 1.0 }),
    );
    assert_eq!(label, "ask");
}

#[test]
fn mcp_get_balance_defers() {
    // A read-only tool whose name is not sensitive and payload has no value-moving signal.
    let label = gate_mcp(
        "mcp__helius__getBalance",
        serde_json::json!({ "address": DEST }),
    );
    assert_eq!(label, "defer");
}

// ---------------------------------------------------------------------------------------
// redact (PostToolUse)
// ---------------------------------------------------------------------------------------

#[test]
fn redact_keypair_array_in_bash_output() {
    // A 64-int byte array in tool output must be redacted via updatedToolOutput.
    let arr: Vec<String> = (0..64).map(|i| (i % 256).to_string()).collect();
    let output = format!("keypair = [{}]", arr.join(","));
    let data = TempDir::new("redact-data");
    let body = serde_json::json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_output": output
    })
    .to_string();
    let run = Invocation::new(&["redact"])
        .plugin_data(data.path())
        .stdin(body)
        .run();
    let v = run.json();
    let updated = v["updatedToolOutput"]
        .as_str()
        .expect("expected updatedToolOutput");
    assert!(
        updated.contains("***REDACTED:keypair***"),
        "output not redacted: {updated}"
    );
    assert!(v.get("updatedMCPToolOutput").is_none());
}

#[test]
fn redact_clean_output_is_noop() {
    let data = TempDir::new("redact-clean");
    let body = serde_json::json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_output": "balance: 1.5 SOL"
    })
    .to_string();
    let run = Invocation::new(&["redact"])
        .plugin_data(data.path())
        .stdin(body)
        .run();
    // Clean output → empty object (no change).
    assert_eq!(run.json(), serde_json::json!({}));
}

// ---------------------------------------------------------------------------------------
// prompt-guard (UserPromptSubmit)
// ---------------------------------------------------------------------------------------

#[test]
fn prompt_with_seed_phrase_blocks() {
    let prompt = "here is my seed phrase: legal winner thank year wave sausage worth \
                  useful legal winner thank yellow";
    let data = TempDir::new("pg-data");
    let body = serde_json::json!({
        "hook_event_name": "UserPromptSubmit",
        "prompt": prompt
    })
    .to_string();
    let run = Invocation::new(&["prompt-guard"])
        .plugin_data(data.path())
        .stdin(body)
        .run();
    let v = run.json();
    assert_eq!(v["decision"], "block");
    assert!(v.get("reason").and_then(|r| r.as_str()).is_some());
}

#[test]
fn benign_prompt_is_empty_object() {
    let data = TempDir::new("pg-benign");
    let body = serde_json::json!({
        "hook_event_name": "UserPromptSubmit",
        "prompt": "how do I derive a PDA in Anchor?"
    })
    .to_string();
    let run = Invocation::new(&["prompt-guard"])
        .plugin_data(data.path())
        .stdin(body)
        .run();
    assert_eq!(run.json(), serde_json::json!({}));
}

// ---------------------------------------------------------------------------------------
// Audit sandboxing — confirm writes land in the sandbox, not the real plugin-data dir.
// ---------------------------------------------------------------------------------------

#[test]
fn gate_writes_audit_into_sandbox_only() {
    let data = TempDir::new("audit-data");
    let home = TempDir::new("audit-home");
    let cmd = format!("solana transfer {DEST} 0.5 --url https://api.devnet.solana.com");
    let payload = bash_payload(&cmd, home.path().to_str().unwrap());
    let run = Invocation::new(&["gate-bash"])
        .plugin_data(data.path())
        .home(home.path())
        .stdin(payload)
        .run();
    assert_eq!(permission_decision(&run.json()).as_deref(), Some("allow"));

    // The audit log must exist under the sandbox plugin-data dir.
    let audit = data.join("audit.jsonl");
    assert!(audit.exists(), "audit.jsonl not written to sandbox");
    let text = std::fs::read_to_string(&audit).unwrap();
    assert!(text.contains("allow"), "audit did not record the decision");
}
