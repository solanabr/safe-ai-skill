//! Irreversible-action and unknown-network guards for `gate-bash` (#13, spec D1.4–D1.7).
//!
//! Most tests drive `gates::bash::decide` in-process with a pinned network and assert on the
//! `Decision` value; no opinion is `Decision::Defer`. The end-to-end tests drive the built binary
//! with the network pinned by explicit flags (no `solana config get`), and accept no opinion as
//! either empty stdout or the legacy `defer` rendering, so they hold across the verdict-output
//! change.

mod common;

use common::{permission_decision, Invocation, Run, TempDir};
use safe_ai_skill::context::{Context, Network};
use safe_ai_skill::gate::{GateMeta, Scope};
use safe_ai_skill::gates::bash;
use safe_ai_skill::io::Decision;
use safe_ai_skill::policy::Policy;

/// A valid base58 destination pubkey.
const DEST: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";
/// A valid base58 mint pubkey.
const MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

/// Decide `command` in-process on `network` with the default policy (per-tx 1, hard 10,
/// daily 5) and an empty, isolated spend ledger.
fn decide(command: &str, network: Network) -> (Decision, GateMeta) {
    let data = TempDir::new("guards");
    let ctx = Context {
        network,
        plugin_data: data.path().to_path_buf(),
        project_dir: data.path().to_path_buf(),
    };
    bash::decide(command, &ctx, &Policy::default())
}

fn is_ask(d: &Decision) -> bool {
    matches!(d, Decision::Ask { .. })
}

fn is_deny(d: &Decision) -> bool {
    matches!(d, Decision::Deny { .. })
}

/// Run the `gate-bash` binary on `command` in a sandbox.
fn run_gate_bash(command: &str) -> Run {
    let data = TempDir::new("guards-data");
    let home = TempDir::new("guards-home");
    let payload = serde_json::json!({
        "session_id": "it-guards",
        "cwd": home.path().to_str().unwrap(),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command }
    })
    .to_string();
    Invocation::new(&["gate-bash"])
        .plugin_data(data.path())
        .home(home.path())
        .stdin(payload)
        .run()
}

/// The emitted decision label, or `None` for no opinion (empty stdout or legacy `defer`).
fn gate_bash(command: &str) -> Option<String> {
    let run = run_gate_bash(command);
    assert_eq!(run.code, Some(0), "stderr: {}", run.stderr);
    if run.stdout.trim().is_empty() {
        return None;
    }
    let label = permission_decision(&run.json())
        .unwrap_or_else(|| panic!("no permissionDecision in {}", run.stdout));
    (label != "defer").then_some(label)
}

// ---------------------------------------------------------------------------------------
// D1.6 irreversible actions: a hard-guard ask on every cluster, mainnet + `--final` denied.
// ---------------------------------------------------------------------------------------

#[test]
fn devnet_deploy_final_asks_as_hard_guard() {
    let (d, meta) = decide(
        "solana program deploy --url devnet --final ./p.so",
        Network::Devnet,
    );
    assert!(is_ask(&d), "{d:?}");
    assert!(meta.hard_guard);
    assert_eq!(meta.scope, Scope::Deploy);
}

#[test]
fn attached_um_deploy_final_denies() {
    let (d, meta) = decide("solana program deploy -um --final ./p.so", Network::Devnet);
    assert!(is_deny(&d), "{d:?}");
    assert!(d.reason().contains("yourself"), "{d:?}");
    assert!(meta.hard_guard);
}

#[test]
fn mainnet_set_upgrade_authority_final_denies() {
    let (d, _) = decide(
        "solana program set-upgrade-authority PROG --final",
        Network::Mainnet,
    );
    assert!(is_deny(&d), "{d:?}");
}

#[test]
fn anchor_deploy_final_passthrough_on_mainnet_denies() {
    let (d, _) = decide(
        "anchor deploy --provider.cluster mainnet -- --final",
        Network::Devnet,
    );
    assert!(is_deny(&d), "{d:?}");
    let (d, _) = decide(
        "anchor program deploy --final --provider.cluster mainnet",
        Network::Devnet,
    );
    assert!(is_deny(&d), "{d:?}");
}

#[test]
fn every_irreversible_command_asks_on_devnet_as_hard_guard() {
    let cases = [
        "solana program deploy --final ./p.so".to_string(),
        "solana program upgrade BUF PROG --final".to_string(),
        "solana program set-upgrade-authority PROG --final".to_string(),
        format!("solana program set-upgrade-authority PROG --new-upgrade-authority {DEST}"),
        "solana program close PROG".to_string(),
        format!("spl-token authorize {MINT} mint --disable"),
        format!("spl-token close {DEST}"),
        format!("spl-token close-mint {MINT}"),
        "anchor idl erase-authority --program-id PROG".to_string(),
        format!("anchor idl set-authority --program-id PROG --new-authority {DEST}"),
        "anchor idl close PROG".to_string(),
        "anchor legacy-idl erase-authority --program-id PROG".to_string(),
        format!("solana close-vote-account VOTE {DEST}"),
        "anchor program deploy --final".to_string(),
        "anchor program close PROG".to_string(),
    ];
    for cmd in &cases {
        for network in [Network::Devnet, Network::Testnet, Network::Localnet] {
            let (d, meta) = decide(cmd, network);
            assert!(is_ask(&d), "{cmd} on {network:?}: {d:?}");
            assert!(meta.hard_guard, "{cmd} on {network:?} must be a hard guard");
        }
    }
}

#[test]
fn irreversible_without_final_asks_on_mainnet() {
    // Only `--final` escalates to deny; other irreversible actions stay a hard-guard ask.
    for cmd in [
        format!("spl-token authorize {MINT} mint --disable"),
        format!("spl-token close-mint {MINT}"),
        "anchor idl erase-authority --program-id PROG".to_string(),
    ] {
        let (d, meta) = decide(&cmd, Network::Mainnet);
        assert!(is_ask(&d), "{cmd}: {d:?}");
        assert!(meta.hard_guard);
    }
}

#[test]
fn final_on_unknown_network_asks() {
    let (d, meta) = decide("solana program deploy --final ./p.so", Network::Unknown);
    assert!(is_ask(&d), "{d:?}");
    assert!(meta.hard_guard);
}

// ---------------------------------------------------------------------------------------
// Deploys: devnet/testnet/localnet → no opinion; mainnet → hard-guard ask; unknown → ask.
// ---------------------------------------------------------------------------------------

#[test]
fn devnet_deploy_has_no_opinion() {
    let (d, meta) = decide("solana program deploy --url devnet ./p.so", Network::Devnet);
    assert_eq!(d, Decision::Defer);
    assert_eq!(meta.scope, Scope::Deploy);
    assert!(!meta.hard_guard);
}

#[test]
fn identified_non_mainnet_deploys_have_no_opinion() {
    for network in [Network::Devnet, Network::Testnet, Network::Localnet] {
        for cmd in [
            "solana program deploy ./p.so",
            "solana program write-buffer ./p.so",
            "anchor deploy",
            "anchor upgrade target/deploy/p.so --program-id PROG",
            "anchor program deploy",
        ] {
            let (d, _) = decide(cmd, network);
            assert_eq!(d, Decision::Defer, "{cmd} on {network:?}");
        }
    }
}

#[test]
fn unknown_network_deploy_asks() {
    let (d, meta) = decide("solana program deploy ./p.so", Network::Unknown);
    assert!(is_ask(&d), "{d:?}");
    assert_eq!(meta.scope, Scope::Deploy);
    let (d, _) = decide("anchor deploy", Network::Unknown);
    assert!(is_ask(&d), "{d:?}");
}

#[test]
fn custom_rpc_url_is_unknown_not_config_fallback() {
    // An explicit URL that names no cluster must not fall back to the CLI config.
    let (d, _) = decide(
        "solana program deploy ./p.so --url https://rpc.example.com",
        Network::Devnet,
    );
    assert!(is_ask(&d), "{d:?}");
}

#[test]
fn mainnet_deploy_is_hard_guard_ask() {
    let (d, meta) = decide("solana program deploy ./p.so", Network::Mainnet);
    assert!(is_ask(&d), "{d:?}");
    assert!(meta.hard_guard);
}

// ---------------------------------------------------------------------------------------
// Unknown network: transfers and authority changes ask.
// ---------------------------------------------------------------------------------------

#[test]
fn unknown_network_transfer_within_cap_asks() {
    let (d, meta) = decide(&format!("solana transfer {DEST} 0.5"), Network::Unknown);
    assert!(is_ask(&d), "{d:?}");
    assert_eq!(meta.amount_sol, Some(0.5));
    let (d, _) = decide(
        &format!("spl-token transfer {MINT} 0.5 {DEST}"),
        Network::Unknown,
    );
    assert!(is_ask(&d), "{d:?}");
}

#[test]
fn unknown_network_over_hard_cap_still_denies() {
    let (d, _) = decide(&format!("solana transfer {DEST} 500"), Network::Unknown);
    assert!(is_deny(&d), "{d:?}");
}

#[test]
fn unknown_network_authority_asks() {
    let (d, meta) = decide(
        &format!("spl-token authorize {MINT} mint {DEST}"),
        Network::Unknown,
    );
    assert!(is_ask(&d), "{d:?}");
    assert!(meta.hard_guard);
}

#[test]
fn config_file_flag_without_url_is_unknown() {
    // `-C <file>` is not read here, so the cluster it names is unknown.
    let (d, _) = decide(
        &format!("solana transfer -C ./other.yml {DEST} 0.5"),
        Network::Devnet,
    );
    assert!(is_ask(&d), "{d:?}");
}

// ---------------------------------------------------------------------------------------
// Network flags: attached `-um`, `--url=m`, short clusters, several flags.
// ---------------------------------------------------------------------------------------

#[test]
fn attached_and_equals_mainnet_flags_ask() {
    for cmd in [
        format!("solana transfer -um {DEST} 0.5"),
        format!("solana transfer --url=m {DEST} 0.5"),
        format!("solana transfer -u=m {DEST} 0.5"),
        format!("solana transfer -vum {DEST} 0.5"),
        format!("solana transfer -uhttps://api.mainnet-beta.solana.com {DEST} 0.5"),
        format!("solana transfer -ud -um {DEST} 0.5"),
    ] {
        let (d, _) = decide(&cmd, Network::Devnet);
        assert!(is_ask(&d), "{cmd}: {d:?}");
    }
}

#[test]
fn attached_devnet_flag_allows_within_cap() {
    let (d, _) = decide(&format!("solana transfer -ud {DEST} 0.5"), Network::Mainnet);
    assert_eq!(d, Decision::Allow);
}

#[test]
fn mainnet_url_mentioning_localhost_is_mainnet() {
    let (d, _) = decide(
        &format!("solana transfer {DEST} 0.5 --url https://mainnet.helius-rpc.com/?x=localhost"),
        Network::Devnet,
    );
    assert!(is_ask(&d), "{d:?}");
}

#[test]
fn cluster_flag_in_another_segment_does_not_vouch_for_a_transfer() {
    // The resolved context took `devnet` from the echo segment; the transfer names no cluster.
    for cmd in [
        format!("echo --url devnet; solana transfer {DEST} 0.5"),
        format!("solana balance -ud && solana transfer {DEST} 0.5"),
    ] {
        let (d, _) = decide(&cmd, Network::Devnet);
        assert!(is_ask(&d), "{cmd}: {d:?}");
    }
    // A segment that names its own cluster keeps it.
    let (d, _) = decide(
        &format!("solana transfer {DEST} 0.5 -ud && solana balance"),
        Network::Mainnet,
    );
    assert_eq!(d, Decision::Allow);
}

#[test]
fn allow_never_covers_a_command_the_gate_does_not_know() {
    // The hook's allow would skip the prompt for the whole tool call, `rm` included.
    for cmd in [
        format!("rm -rf ./build && solana transfer {DEST} 0.5 -ud"),
        format!("solana transfer {DEST} 0.5 -ud | sh"),
    ] {
        let (d, _) = decide(&cmd, Network::Devnet);
        assert_eq!(d, Decision::Defer, "{cmd}");
    }
    // Nor may a grant relax the ask: it would allow the `rm` as well.
    let (d, meta) = decide(
        &format!("rm -rf ./build; solana transfer {DEST} 5 -ud"),
        Network::Devnet,
    );
    assert!(is_ask(&d), "{d:?}");
    assert!(meta.hard_guard);
    // A deny stays a deny.
    let (d, _) = decide(
        &format!("rm -rf ./build; solana transfer {DEST} 50 -ud"),
        Network::Devnet,
    );
    assert!(is_deny(&d), "{d:?}");
}

#[test]
fn allow_never_covers_command_or_process_substitution() {
    // The substitution runs code; as a flag value it would otherwise pass for a memo.
    for cmd in [
        format!("solana transfer {DEST} 0.5 -ud --with-memo \"$(reboot)\""),
        format!("solana transfer {DEST} 0.5 -ud --with-memo $(reboot)"),
        format!("solana transfer {DEST} 0.5 -ud --with-memo `reboot`"),
        format!("solana transfer {DEST} 0.5 -ud --with-memo <(reboot)"),
    ] {
        let (d, _) = decide(&cmd, Network::Devnet);
        assert_eq!(d, Decision::Defer, "{cmd}");
    }
}

#[test]
fn memo_text_does_not_name_a_cluster() {
    // A quoted memo containing `-ud` is not a cluster flag; the context network stands.
    let (d, _) = decide(
        &format!("solana transfer --with-memo \"pay -ud\" {DEST} 0.5"),
        Network::Mainnet,
    );
    assert!(is_ask(&d), "{d:?}");
}

// ---------------------------------------------------------------------------------------
// D1.5 amounts: positional only, flag values skipped, `ALL` accepted, ambiguous → ask.
// ---------------------------------------------------------------------------------------

#[test]
fn memo_value_is_not_the_amount_hard_cap_denies() {
    let (d, meta) = decide(
        &format!("solana transfer -ud --with-memo 0.0001 {DEST} 500"),
        Network::Devnet,
    );
    assert!(is_deny(&d), "{d:?}");
    assert_eq!(meta.amount_sol, Some(500.0));
}

#[test]
fn argument_taking_flag_values_are_skipped() {
    for flag in [
        "--with-memo",
        "--fee-payer",
        "--from",
        "--nonce",
        "--nonce-authority",
        "--blockhash",
        "--keypair",
        "-k",
        "--url",
        "-u",
        "--config",
        "-C",
        "--commitment",
        "--ws",
        "--output",
        "--signer",
        "--with-compute-unit-price",
    ] {
        let cmd = format!("solana transfer -ud {flag} 0.0001 {DEST} 500");
        let (d, meta) = decide(&cmd, Network::Devnet);
        assert!(is_deny(&d), "{cmd}: {d:?}");
        assert_eq!(meta.amount_sol, Some(500.0), "{cmd}");
    }
}

#[test]
fn from_keypair_then_positionals() {
    let (d, meta) = decide(
        &format!("solana transfer --from k.json {DEST} 1 -ud"),
        Network::Devnet,
    );
    assert_eq!(d, Decision::Allow);
    assert_eq!(meta.amount_sol, Some(1.0));
    assert_eq!(meta.destination.as_deref(), Some(DEST));
}

#[test]
fn memo_value_is_not_the_destination() {
    // A grant restricted to `to: [X]` must not match because X appears as a memo.
    let other = "8yQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";
    let (_, meta) = decide(
        &format!("solana transfer -ud --with-memo {other} {DEST} 0.5"),
        Network::Devnet,
    );
    assert_eq!(meta.destination.as_deref(), Some(DEST));
}

#[test]
fn spl_token_positionals_and_flags() {
    let src = "7yQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";
    let (d, meta) = decide(
        &format!(
            "spl-token transfer --from {src} {MINT} 0.5 {DEST} --fund-recipient --allow-unfunded-recipient -ud"
        ),
        Network::Devnet,
    );
    assert_eq!(d, Decision::Allow);
    assert_eq!(meta.amount_sol, Some(0.5));
    assert_eq!(
        meta.destination.as_deref(),
        Some(DEST),
        "recipient, not the mint"
    );
}

#[test]
fn transfer_all_asks_as_hard_guard() {
    for cmd in [
        format!("solana transfer {DEST} ALL -ud"),
        format!("spl-token transfer {MINT} ALL {DEST} -ud"),
    ] {
        let (d, meta) = decide(&cmd, Network::Devnet);
        assert!(is_ask(&d), "{cmd}: {d:?}");
        assert!(d.reason().contains("ALL"), "{d:?}");
        assert!(
            meta.hard_guard,
            "an unbounded amount cannot be relaxed by a grant"
        );
        assert_eq!(meta.amount_sol, None);
    }
}

#[test]
fn ambiguous_amounts_ask_as_hard_guard() {
    for cmd in [
        // Two candidate amounts.
        format!("solana transfer {DEST} 0.5 500"),
        // A second command on a new line.
        format!("solana transfer {DEST} 0.5\nsolana transfer {DEST} 500"),
        // A flag of unknown arity followed by a word.
        format!("solana transfer --mystery 0.5 {DEST} 500"),
        // Missing amount.
        format!("solana transfer {DEST}"),
        // Non-numeric / non-finite amounts.
        format!("solana transfer {DEST} $AMOUNT"),
        format!("solana transfer {DEST} inf"),
        format!("solana transfer -- {DEST} -5"),
    ] {
        let (d, meta) = decide(&cmd, Network::Devnet);
        assert!(is_ask(&d), "{cmd}: {d:?}");
        assert!(meta.hard_guard, "{cmd}");
        assert_eq!(meta.amount_sol, None, "{cmd}");
    }
}

#[test]
fn trailing_unknown_flag_and_fd_duplication_are_not_ambiguous() {
    for cmd in [
        format!("solana transfer {DEST} 0.5 -ud --brand-new-flag"),
        format!("solana transfer {DEST} 0.5 -ud 2>&1"),
        format!("solana transfer {DEST} 0.5 -ud 1>&2"),
        format!("solana transfer {DEST} 0.5 -ud --no-wait --allow-unfunded-recipient"),
    ] {
        let (d, meta) = decide(&cmd, Network::Devnet);
        assert_eq!(d, Decision::Allow, "{cmd}");
        assert_eq!(meta.amount_sol, Some(0.5), "{cmd}");
    }
}

#[test]
fn file_redirection_on_a_transfer_asks() {
    // A redirection writes a file: never part of an allowed transfer.
    for cmd in [
        format!("solana transfer {DEST} 0.5 -ud > out.log"),
        format!("solana transfer {DEST} 0.5 -ud >>~/.bashrc"),
    ] {
        let (d, _) = decide(&cmd, Network::Devnet);
        assert!(is_ask(&d), "{cmd}: {d:?}");
    }
}

#[test]
fn global_flag_value_cannot_masquerade_as_the_subcommand() {
    // `-k balance` is a keypair path; the subcommand is `transfer`.
    let (d, _) = decide(
        &format!("solana -k balance transfer {DEST} 500 -ud"),
        Network::Devnet,
    );
    assert!(is_deny(&d), "{d:?}");
    let (d, _) = decide(
        "solana -C show program deploy --final ./p.so -um",
        Network::Devnet,
    );
    assert!(is_deny(&d), "{d:?}");
}

#[test]
fn unknown_flag_before_the_subcommand_asks() {
    let (d, meta) = decide(
        &format!("solana --mystery balance transfer {DEST} 1"),
        Network::Devnet,
    );
    assert!(is_ask(&d), "{d:?}");
    assert!(meta.hard_guard);
}

// ---------------------------------------------------------------------------------------
// D1.7 read-only fast path: no opinion, trimmed of state-changing commands.
// ---------------------------------------------------------------------------------------

#[test]
fn read_only_fast_path_has_no_opinion() {
    for cmd in [
        "solana balance",
        "solana config get",
        "solana program show PROG",
        "spl-token accounts",
        "anchor build",
        "anchor keys list",
    ] {
        let (d, _) = decide(cmd, Network::Mainnet);
        assert_eq!(d, Decision::Defer, "{cmd}");
    }
}

#[test]
fn trimmed_commands_are_off_the_fast_path() {
    for cmd in [
        "spl-token gc",
        "anchor test",
        "anchor run deploy-script",
        "anchor idl fetch PROG",
        "anchor idl init --filepath target/idl/p.json PROG",
        "anchor idl erase-authority --program-id PROG",
        "solana config set --url mainnet-beta",
    ] {
        let (d, _) = decide(cmd, Network::Devnet);
        assert!(is_ask(&d), "{cmd}: {d:?}");
    }
}

// ---------------------------------------------------------------------------------------
// End to end (built binary; network pinned by flags).
// ---------------------------------------------------------------------------------------

#[test]
fn e2e_devnet_deploy_final_asks() {
    assert_eq!(
        gate_bash("solana program deploy --url devnet --final ./p.so").as_deref(),
        Some("ask")
    );
}

#[test]
fn e2e_um_deploy_final_denies() {
    assert_eq!(
        gate_bash("solana program deploy -um --final ./p.so").as_deref(),
        Some("deny")
    );
}

#[test]
fn e2e_devnet_deploy_has_no_opinion() {
    assert_eq!(gate_bash("solana program deploy --url devnet ./p.so"), None);
}

#[test]
fn e2e_anchor_devnet_deploy_has_no_opinion() {
    // Coexistence must not over-restrict: a devnet deploy yields to the normal permission flow,
    // so safe-ai-skill does not block the kit's devnet-first workflow.
    assert_eq!(gate_bash("anchor deploy --provider.cluster devnet"), None);
}

#[test]
fn e2e_unknown_network_deploy_asks() {
    assert_eq!(
        gate_bash("solana program deploy ./p.so --url https://rpc.example.com").as_deref(),
        Some("ask")
    );
}

#[test]
fn e2e_memo_amount_hard_cap_denies() {
    assert_eq!(
        gate_bash(&format!(
            "solana transfer -ud --with-memo 0.0001 {DEST} 500"
        ))
        .as_deref(),
        Some("deny")
    );
}

#[test]
fn e2e_attached_um_transfer_asks() {
    assert_eq!(
        gate_bash(&format!("solana transfer -um {DEST} 0.5")).as_deref(),
        Some("ask")
    );
}

#[test]
fn e2e_cluster_flag_in_echo_segment_asks() {
    assert_eq!(
        gate_bash(&format!("echo --url devnet; solana transfer {DEST} 0.5")).as_deref(),
        Some("ask")
    );
}

#[test]
fn e2e_idl_erase_authority_asks() {
    assert_eq!(
        gate_bash("anchor idl erase-authority --program-id PROG --provider.cluster devnet")
            .as_deref(),
        Some("ask")
    );
}

#[test]
fn e2e_compound_with_unknown_command_has_no_opinion() {
    assert_eq!(
        gate_bash(&format!(
            "rm -rf ./build && solana transfer {DEST} 0.5 --url devnet"
        )),
        None
    );
}
