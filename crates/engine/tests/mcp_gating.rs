//! MCP gate end-to-end decisions for the `safe-ai-skill` binary (hermetic, std-only).
//!
//! Drives `gate-mcp` with PreToolUse MCP hook payloads and asserts the emitted
//! `permissionDecision`. Covers the solana-ai-kit MCP surface:
//!   - `heliusWrite.sendSol` / `sendToken` / `stake*` → ask (value-moving),
//!   - `getBalance` → defer (read),
//!   - `phantom__signTransaction` / `x402__*` → ask (high-risk wallet-signing / key-custody),
//!   - the hook gates regardless of `enableAllProjectMcpServers` pre-approval — a PreToolUse
//!     `ask`/`deny` fires before (and survives) the permission check, so MCP pre-approval in the
//!     kit's settings cannot bypass `gate-mcp`. We assert the engine decision directly (the
//!     pre-approval lives in the host's settings, not in any safe-ai-skill input the gate reads).
//!
//! Fully hermetic: isolated `CLAUDE_PLUGIN_DATA` + `HOME` temp dirs, no network.

mod common;

use common::{permission_decision, Invocation, TempDir};

/// Build a PreToolUse MCP hook payload for `tool` with optional `input`.
fn mcp_payload(tool: &str, input: serde_json::Value) -> String {
    serde_json::json!({
        "session_id": "it-mcp",
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": input
    })
    .to_string()
}

/// Run `gate-mcp` against `tool`/`input` in a fresh sandbox; return the decision label.
fn gate_mcp(tool: &str, input: serde_json::Value) -> String {
    let data = TempDir::new("mcp-data");
    let home = TempDir::new("mcp-home");
    let run = Invocation::new(&["gate-mcp"])
        .plugin_data(data.path())
        .home(home.path())
        .stdin(mcp_payload(tool, input))
        .run();
    let v = run.json();
    permission_decision(&v).unwrap_or_else(|| panic!("no permissionDecision in {}", run.stdout))
}

const DEST: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";

// ---------------------------------------------------------------------------------------
// heliusWrite value-moving tools → ask
// ---------------------------------------------------------------------------------------

#[test]
fn helius_write_send_sol_asks() {
    let input = serde_json::json!({ "destination": DEST, "lamports": 1_000_000_000u64 });
    assert_eq!(gate_mcp("mcp__helius__heliusWrite.sendSol", input), "ask");
}

#[test]
fn helius_write_send_token_asks() {
    // Name-matched even without a payload (the `send` verb is in the sensitive pattern).
    assert_eq!(
        gate_mcp("mcp__helius__heliusWrite.sendToken", serde_json::json!({})),
        "ask"
    );
}

#[test]
fn helius_write_stake_asks() {
    assert_eq!(
        gate_mcp("mcp__helius__heliusWrite.stake", serde_json::json!({})),
        "ask"
    );
}

#[test]
fn helius_write_stake_delegate_asks() {
    assert_eq!(
        gate_mcp(
            "mcp__helius__heliusWrite.stakeDelegate",
            serde_json::json!({})
        ),
        "ask"
    );
}

// ---------------------------------------------------------------------------------------
// Reads → defer
// ---------------------------------------------------------------------------------------

#[test]
fn helius_get_balance_defers() {
    assert_eq!(
        gate_mcp("mcp__helius__getBalance", serde_json::json!({})),
        "defer"
    );
}

#[test]
fn helius_get_asset_defers() {
    let input = serde_json::json!({ "id": "So11111111111111111111111111111111111111112" });
    assert_eq!(gate_mcp("mcp__helius__getAsset", input), "defer");
}

// ---------------------------------------------------------------------------------------
// High-risk classes → ask
// ---------------------------------------------------------------------------------------

#[test]
fn phantom_sign_transaction_asks() {
    // Wallet-signing high-risk class (server `phantom` ⇒ id `phantom-mcp`).
    assert_eq!(
        gate_mcp("mcp__phantom__signTransaction", serde_json::json!({})),
        "ask"
    );
}

#[test]
fn phantom_sign_message_asks() {
    // `signMessage` lacks the "signing" keyword — only the server-id match catches it.
    assert_eq!(
        gate_mcp("mcp__phantom__signMessage", serde_json::json!({})),
        "ask"
    );
}

#[test]
fn x402_create_wallet_asks() {
    // Key-custody high-risk class (server `x402` ⇒ id `x402-proxy-mcp`).
    assert_eq!(
        gate_mcp("mcp__x402__createWallet", serde_json::json!({})),
        "ask"
    );
}

#[test]
fn x402_any_tool_asks() {
    // The whole x402 server is key-custody; even an innocuously-named tool gates.
    assert_eq!(gate_mcp("mcp__x402__status", serde_json::json!({})), "ask");
}

// ---------------------------------------------------------------------------------------
// Pre-approval does not bypass the gate
// ---------------------------------------------------------------------------------------

#[test]
fn enable_all_project_mcp_servers_does_not_bypass_gate() {
    // `enableAllProjectMcpServers: true` is a host-settings pre-approval; it is irrelevant to
    // the PreToolUse hook, which gates BEFORE the permission check and whose `ask` survives even
    // bypass modes. The gate reads only the tool name/payload — there is no input by which the
    // pre-approval could relax the decision. A high-risk call still asks regardless of any
    // permission-mode hint we attach to the payload.
    let data = TempDir::new("mcp-bypass-data");
    let home = TempDir::new("mcp-bypass-home");
    let payload = serde_json::json!({
        "session_id": "it-mcp",
        "hook_event_name": "PreToolUse",
        "permission_mode": "bypassPermissions",
        "tool_name": "mcp__phantom__signTransaction",
        "tool_input": {}
    })
    .to_string();
    let run = Invocation::new(&["gate-mcp"])
        .plugin_data(data.path())
        .home(home.path())
        .stdin(payload)
        .run();
    assert_eq!(
        permission_decision(&run.json()).as_deref(),
        Some("ask"),
        "pre-approval / bypass must not relax the high-risk MCP gate: {}",
        run.stdout
    );
}
