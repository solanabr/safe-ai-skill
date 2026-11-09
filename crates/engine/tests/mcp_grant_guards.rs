//! A confirmed `transfer` grant relaxes plain SOL transfers made through an MCP tool, and
//! nothing else: an MCP call that is really an authority change, an approval, a freeze, a
//! close or a burn, or that moves SPL tokens, stays an ask at every tier below High however
//! its tool is named, and nothing is debited.
#![cfg(feature = "test-hooks")]

mod common;

use common::{decision_label, Invocation, TempDir, Tier};
use safe_ai_skill::datadir::DataDir;
use safe_ai_skill::gate::Scope;
use safe_ai_skill::grants::{self, Grant, Grants};
use serde_json::{json, Value};

const DEST: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";
const WSOL: &str = "So11111111111111111111111111111111111111112";
const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

struct Sandbox {
    data: TempDir,
    home: TempDir,
    proj: TempDir,
    path: TempDir,
}

impl Sandbox {
    /// A sandbox whose trusted data dir holds one transfer grant with no `--to` restriction.
    fn with_transfer_grant(tag: &str) -> Sandbox {
        let sb = Sandbox {
            data: TempDir::new(&format!("{tag}-data")),
            home: TempDir::new(&format!("{tag}-home")),
            proj: TempDir::new(&format!("{tag}-proj")),
            path: TempDir::new(&format!("{tag}-path")),
        };
        let grant = Grant {
            id: "mcp-transfer".into(),
            scope: Scope::Transfer,
            programs: Vec::new(),
            to: Vec::new(),
            max_tx_sol: 1.0,
            budget_sol: 5.0,
            spent_sol: 0.0,
            expires_at: u64::MAX,
            danger: false,
        };
        grants::save(
            &sb.dir(),
            &Grants {
                grants: vec![grant],
            },
        )
        .unwrap();
        sb
    }

    fn dir(&self) -> DataDir {
        DataDir {
            path: self.data.path().to_path_buf(),
            trusted: true,
        }
    }

    fn spent(&self) -> f64 {
        grants::live(&self.dir()).grants[0].spent_sol
    }

    fn gate(&self, tier: Tier, tool: &str, input: &Value) -> String {
        let run = Invocation::new(&["gate-mcp"])
            .plugin_data(self.data.path())
            .home(self.home.path())
            .cwd(self.proj.path())
            .tier(tier)
            .env("PATH", self.path.path().to_str().unwrap())
            .stdin(
                json!({"session_id":"it-mcp-guards","cwd": self.proj.path(),
                       "hook_event_name":"PreToolUse","tool_name": tool,
                       "tool_input": input})
                .to_string(),
            )
            .run();
        decision_label(&run)
    }
}

/// Calls a transfer grant must never relax: each is an authority change, approval, freeze,
/// close or burn, or moves token units, whatever transfer word its name also carries.
fn guarded_calls() -> Vec<(&'static str, Value)> {
    vec![
        // Authority changes and approvals named with a transfer verb.
        (
            "mcp__tokenkit__transferMintAuthority",
            json!({"mint": WSOL, "newAuthority": DEST, "amount": 0.01}),
        ),
        (
            "mcp__tokenkit__transfer_authority",
            json!({"to": DEST, "amount": 0.01}),
        ),
        (
            "mcp__tokenkit__TRANSFER_SETAUTHORITY",
            json!({"to": DEST, "amount": 0.01}),
        ),
        (
            "mcp__tokenkit__transferOwnership",
            json!({"to": DEST, "amount": 0.01}),
        ),
        (
            "mcp__tokenkit__approveAndTransfer",
            json!({"to": DEST, "amount": 0.01}),
        ),
        (
            "mcp__tokenkit__revoke-and-send",
            json!({"to": DEST, "amount": 0.01}),
        ),
        (
            "mcp__tokenkit__freezeAndTransfer",
            json!({"to": DEST, "amount": 0.01}),
        ),
        (
            "mcp__tokenkit__thaw_then_send",
            json!({"to": DEST, "amount": 0.01}),
        ),
        // Closes and burns named with a transfer verb.
        (
            "mcp__tokenkit__closeAccountAndWithdraw",
            json!({"account": DEST, "destination": DEST, "amount": 0.01}),
        ),
        (
            "mcp__tokenkit__transfer_closeaccount",
            json!({"to": DEST, "amount": 0.01}),
        ),
        (
            "mcp__tokenkit__burnAndSend",
            json!({"to": DEST, "amount": 0.01}),
        ),
        // The verb in a routed tool's `action`.
        (
            "mcp__helius__heliusWrite",
            json!({"action": "transferMintAuthority", "to": DEST, "amount": 0.01}),
        ),
        (
            "mcp__helius__heliusWrite",
            json!({"params": {"action": "burnAndSend", "to": DEST, "amount": 0.01}}),
        ),
        // Token transfers whose tool name has no `token` word: the amount is token units.
        (
            "mcp__agentkit__transfer",
            json!({"to": DEST, "amount": 0.9, "mint": USDC}),
        ),
        (
            "mcp__agentkit__transfer",
            json!({"to": DEST, "amount": 0.9, "mint": WSOL}),
        ),
        (
            "mcp__agentkit__send",
            json!({"args": {"to": DEST, "amount": 0.5, "tokenMint": USDC}}),
        ),
        (
            "mcp__agentkit__transfer",
            json!({"to": DEST, "amount": 0.5, "tokenAmount": 500}),
        ),
        (
            "mcp__agentkit__transferSpl",
            json!({"to": DEST, "amount": 0.5}),
        ),
        (
            "mcp__wallet__transfer",
            json!({"to": DEST, "amount": 0.9, "token": USDC}),
        ),
        (
            "mcp__wallet__transfer",
            json!({"to": DEST, "amount": 0.9, "options": {"tokenMintAddress": USDC}}),
        ),
        (
            "mcp__agentkit__transferSPLToken",
            json!({"to": DEST, "amount": 0.9}),
        ),
        ("mcp__goat__send_ETH", json!({"to": DEST, "amount": "0.9"})),
        // A transfer that hands over an authority, or carries a pre-built transaction.
        (
            "mcp__wallet__transfer",
            json!({"to": DEST, "amount": 0.01, "newOwner": DEST}),
        ),
        (
            "mcp__solana__sendRawTransaction",
            json!({"transaction": "AQAB", "to": DEST, "amount": 0.01}),
        ),
        // A SOL amount the grant cannot read: a decoy key beside the real one, or send-max.
        (
            "mcp__helius__heliusWrite",
            json!({"action": "transferSol", "destination": DEST, "amount": 50, "lamports": 1}),
        ),
        (
            "mcp__helius__heliusWrite",
            json!({"action": "transferSol", "destination": DEST, "amount": 0.01,
                   "sendMax": true}),
        ),
        // The same shapes without a transfer verb.
        (
            "mcp__tokenkit__setAuthority",
            json!({"mint": WSOL, "newAuthority": DEST, "amount": 0.01}),
        ),
        (
            "mcp__tokenkit__closeAccount",
            json!({"account": DEST, "destination": DEST, "amount": 0.01}),
        ),
    ]
}

/// Plain SOL transfers the grant is meant to cover, including names with words that only look
/// like a guarded one (`closeout`) and a server whose name carries one.
fn sol_transfers() -> Vec<(&'static str, Value)> {
    vec![
        (
            "mcp__tokenkit__transferSol",
            json!({"to": DEST, "amount": 0.01}),
        ),
        (
            "mcp__helius__heliusWrite.sendSol",
            json!({"destination": DEST, "lamports": 10_000_000u64}),
        ),
        (
            "mcp__agentkit__transfer",
            json!({"to": DEST, "amount": 0.01}),
        ),
        (
            "mcp__payroll__sendCloseoutPayment",
            json!({"to": DEST, "amount": 0.01}),
        ),
        (
            "mcp__burn-tracker__sendSol",
            json!({"to": DEST, "amount": 0.01}),
        ),
        (
            "mcp__wallet__transfer",
            json!({"to": DEST, "amount": 0.01, "mint": null, "currency": "SOL"}),
        ),
        (
            "mcp__solana-tokens__transferSol",
            json!({"to": DEST, "amount": 0.01}),
        ),
    ]
}

#[test]
fn a_transfer_grant_relaxes_no_guarded_mcp_call() {
    let sb = Sandbox::with_transfer_grant("mcp-guards");
    for tier in [Tier::Off, Tier::Relaxed, Tier::Medium] {
        for (tool, input) in guarded_calls() {
            assert_eq!(
                sb.gate(tier, tool, &input),
                "ask",
                "{tier:?}: {tool} {input}"
            );
        }
    }
    assert_eq!(sb.spent(), 0.0, "a guarded call debited the grant");
    for (tool, input) in guarded_calls() {
        assert_eq!(
            sb.gate(Tier::High, tool, &input),
            "deny",
            "high: {tool} {input}"
        );
    }
    assert_eq!(sb.spent(), 0.0);
}

#[test]
fn a_transfer_grant_still_relaxes_plain_sol_transfers() {
    let sb = Sandbox::with_transfer_grant("mcp-sol");
    let mut expected = 0.0;
    for tier in [Tier::Off, Tier::Relaxed, Tier::Medium] {
        for (tool, input) in sol_transfers() {
            assert_eq!(
                sb.gate(tier, tool, &input),
                "allow",
                "{tier:?}: {tool} {input}"
            );
            expected += 0.01;
        }
    }
    assert!(
        (sb.spent() - expected).abs() < 1e-9,
        "{} vs {expected}",
        sb.spent()
    );
    // High never allows and consults no grant.
    for (tool, input) in sol_transfers() {
        assert_eq!(
            sb.gate(Tier::High, tool, &input),
            "deny",
            "high: {tool} {input}"
        );
    }
    assert!((sb.spent() - expected).abs() < 1e-9);
}
