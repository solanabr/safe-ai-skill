//! W5 (on-chain CLI) gap closure: authority verbs, token units (D3) and an unquoted glob in
//! `--url`.
//!
//! The fixture `fixtures/gap/w5-onchain.jsonl` runs through the real `gate-bash` binary with a
//! fake home, an isolated data dir and a stub `solana` that prints the CLI config's RPC URL.
//! The grant rows run the library pipeline (`bash::decide`, `relax::apply`, `headless::apply`)
//! with a confirmed grant for every grantable scope, as `tiers_onchain.rs` does.

mod common;

use std::path::Path;

use common::{decision_label, Invocation, TempDir, Tier};
use safe_ai_skill::context::{Context, Network};
use safe_ai_skill::datadir::DataDir;
use safe_ai_skill::gate::Scope;
use safe_ai_skill::gates::bash;
use safe_ai_skill::grants::{self, Grant, Grants};
use safe_ai_skill::io::Decision;
use safe_ai_skill::policy::Policy;
use safe_ai_skill::{headless, relax};
use serde_json::{json, Value};

const PK: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";
const MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const MAINNET: &str = "https://api.mainnet-beta.solana.com";

// ---------------------------------------------------------------------------------------
// Fixture through the binary
// ---------------------------------------------------------------------------------------

fn fixture() -> Vec<Value> {
    include_str!("fixtures/gap/w5-onchain.jsonl")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("fixture line is JSON"))
        .collect()
}

fn tier_of(word: &str) -> Tier {
    match word {
        "relaxed" => Tier::Relaxed,
        "medium" => Tier::Medium,
        "high" => Tier::High,
        other => panic!("fixture tier {other} is not supported through the binary"),
    }
}

/// The `json_rpc_url` a fixture's CLI config names, if any.
fn cli_url(case: &Value) -> Option<String> {
    let text = case["cwd_files"]["~/.config/solana/cli/config.yml"].as_str()?;
    text.lines()
        .find_map(|l| l.trim().strip_prefix("json_rpc_url:"))
        .map(|u| u.trim().to_string())
}

fn run_case(case: &Value) -> String {
    let home = TempDir::new("w5-home");
    let proj = TempDir::new("w5-proj");
    let data = TempDir::new("w5-data");
    let bin = TempDir::new("w5-path");
    if let Some(files) = case["cwd_files"].as_object() {
        for (rel, body) in files {
            if let Some(rel) = rel.strip_prefix("proj/") {
                std::fs::write(proj.join(rel), body.as_str().unwrap_or_default()).unwrap();
            }
        }
    }
    let path = match cli_url(case) {
        Some(url) => {
            let stub = bin.join("solana");
            std::fs::write(
                &stub,
                format!("#!/bin/sh\necho \"Config File: x\"\necho \"RPC URL: {url}\"\n"),
            )
            .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            format!("{}:/usr/bin:/bin", bin.path().display())
        }
        None => bin.path().display().to_string(),
    };
    let payload = json!({
        "session_id": "it-gap-w5",
        "hook_event_name": "PreToolUse",
        "tool_name": case["tool"],
        "cwd": proj.path(),
        "tool_input": case["tool_input"],
    });
    let run = Invocation::new(&["gate-bash"])
        .plugin_data(data.path())
        .home(home.path())
        .cwd(proj.path())
        .env("PATH", &path)
        .tier(tier_of(case["tier"].as_str().unwrap_or("relaxed")))
        .headless(case["headless"].as_bool().unwrap_or(false))
        .stdin(payload.to_string())
        .run();
    decision_label(&run)
}

#[cfg(unix)]
#[test]
fn fixture_cases_reach_their_verdict() {
    let mut failures = Vec::new();
    for case in fixture() {
        let want = case["want"].as_str().unwrap_or("?");
        let got = run_case(&case);
        if got != want {
            failures.push(format!(
                "{}: want {want:?}, got {got:?}: {}",
                case["id"], case["tool_input"]["command"]
            ));
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

// ---------------------------------------------------------------------------------------
// Library pipeline with grants
// ---------------------------------------------------------------------------------------

fn trusted(path: &Path) -> DataDir {
    DataDir {
        path: path.to_path_buf(),
        trusted: true,
    }
}

fn grant_everything(dir: &DataDir) {
    let grants = [
        Scope::Transfer,
        Scope::Swap,
        Scope::Deploy,
        Scope::Authority,
        Scope::Destructive,
    ]
    .iter()
    .enumerate()
    .map(|(i, scope)| Grant {
        id: format!("g-{i}"),
        scope: *scope,
        programs: Vec::new(),
        to: Vec::new(),
        max_tx_sol: 1_000.0,
        budget_sol: 1_000_000.0,
        spent_sol: 0.0,
        expires_at: u64::MAX,
        danger: true,
    })
    .collect();
    grants::save(dir, &Grants { grants }).unwrap();
}

/// The natural decision, its meta, and the final decision after grants and headless.
fn pipeline(
    command: &str,
    network: Network,
    tier: Tier,
    grant: bool,
    is_headless: bool,
) -> (Decision, safe_ai_skill::gate::GateMeta, Decision) {
    let data = TempDir::new("w5-lib");
    let dir = trusted(data.path());
    if grant {
        grant_everything(&dir);
    }
    let ctx = Context {
        network,
        anchor_network: network,
        plugin_data: data.path().to_path_buf(),
        project_dir: data.path().to_path_buf(),
    };
    let mut policy = Policy::default();
    policy.runtime.tier = tier;
    policy.runtime.headless = is_headless;
    let (natural, meta) = bash::decide(command, &ctx, &policy);
    let last = headless::apply(
        relax::apply(natural.clone(), &meta, &policy, &dir),
        is_headless,
    );
    (natural, meta, last)
}

fn label(d: &Decision) -> &'static str {
    match d {
        Decision::Defer => "",
        other => other.label(),
    }
}

fn authority_commands(cluster: &str) -> Vec<String> {
    vec![
        format!("solana stake-authorize S --new-stake-authority {PK} {cluster}"),
        format!("solana stake-authorize-checked S --new-stake-authority ~/k.json {cluster}"),
        format!("solana vote-authorize-voter V ~/w.json {PK} {cluster}"),
        format!("solana vote-authorize-voter-checked V ~/w.json ~/k.json {cluster}"),
        format!("solana vote-authorize-withdrawer V ~/w.json {PK} {cluster}"),
        format!("solana vote-authorize-withdrawer-checked V ~/w.json ~/k.json {cluster}"),
        format!("solana authorize-nonce-account N {PK} {cluster}"),
        format!("spl-token approve TOKENacct 1000000 {PK} {cluster}"),
        format!("spl-token authorize {MINT} mint {PK} {cluster}"),
    ]
}

#[test]
fn authority_verbs_are_hard_guard_authority_changes_no_grant_lifts() {
    for cluster in ["-um", "-ud", "-ul", ""] {
        for cmd in authority_commands(cluster) {
            let net = if cluster.is_empty() {
                Network::Unknown
            } else {
                Network::Devnet
            };
            let (natural, meta, last) = pipeline(&cmd, net, Tier::Relaxed, true, false);
            assert!(
                matches!(natural, Decision::Ask { .. }),
                "{cmd}: {natural:?}"
            );
            assert_eq!(meta.scope, Scope::Authority, "{cmd}");
            assert!(meta.hard_guard, "{cmd}: a grant must not cover it");
            assert_eq!(meta.amount_sol, None, "{cmd}: never a SOL amount");
            assert_eq!(label(&last), "ask", "{cmd} with a grant");
            let (_, _, hl) = pipeline(&cmd, net, Tier::Relaxed, true, true);
            assert_eq!(label(&hl), "deny", "{cmd} headless");
        }
        for cmd in authority_commands("-um") {
            let (_, _, high) = pipeline(&cmd, Network::Devnet, Tier::High, true, false);
            assert_eq!(label(&high), "deny", "{cmd} at High on mainnet");
        }
    }
}

#[test]
fn revoke_stays_a_plain_unclassified_write() {
    let (natural, meta, _) = pipeline(
        "spl-token revoke TOKENacct -um",
        Network::Devnet,
        Tier::Relaxed,
        false,
        false,
    );
    assert!(matches!(natural, Decision::Ask { .. }), "{natural:?}");
    assert_ne!(meta.scope, Scope::Authority);
}

#[test]
fn token_transfers_never_reach_sol_caps_or_grants() {
    for (cmd, amount) in [
        (
            format!("spl-token transfer {MINT} 0.5 {PK} --url {MAINNET}"),
            "0.5",
        ),
        (
            format!("spl-token transfer {MINT} 1000 {PK} --url {MAINNET}"),
            "1000",
        ),
        (
            format!("spl-token transfer {MINT} 0.5 {PK} --url https://rpc.acme.io/k"),
            "0.5",
        ),
        (format!("spl-token transfer {MINT} 0.5 {PK}"), "0.5"),
    ] {
        // `""` → the CLI default, unknown here.
        let (natural, meta, last) = pipeline(&cmd, Network::Unknown, Tier::Relaxed, true, false);
        let reason = natural.reason().to_string();
        assert!(
            matches!(natural, Decision::Ask { .. }),
            "{cmd}: {natural:?}"
        );
        assert!(
            reason.contains(&format!("{amount} tokens of {MINT}")),
            "{cmd}: {reason}"
        );
        assert!(
            !reason.contains(&format!("{amount} SOL")),
            "{cmd}: token amounts are not SOL: {reason}"
        );
        assert_eq!(meta.amount_sol, None, "{cmd}");
        assert!(meta.hard_guard, "{cmd}: no SOL grant covers a token amount");
        assert_eq!(label(&last), "ask", "{cmd} with a SOL transfer grant");
        let (_, _, hl) = pipeline(&cmd, Network::Unknown, Tier::Relaxed, true, true);
        assert_eq!(label(&hl), "deny", "{cmd} headless");
        let (_, _, high) = pipeline(&cmd, Network::Unknown, Tier::High, true, false);
        assert_eq!(label(&high), "deny", "{cmd} at High");
    }
}

#[test]
fn token_transfers_on_identified_devnet_or_localnet_get_no_opinion() {
    for cmd in [
        format!("spl-token transfer {MINT} 0.5 {PK} -ud"),
        format!("spl-token transfer {MINT} 5000 {PK} -ud"),
        format!("spl-token transfer {MINT} ALL {PK} -ul"),
        format!("spl-token transfer {MINT} 0.5 {PK}"),
    ] {
        let (natural, meta, _) = pipeline(&cmd, Network::Devnet, Tier::Relaxed, false, false);
        assert_eq!(natural, Decision::Defer, "{cmd}");
        assert_eq!(meta.amount_sol, None, "{cmd}");
    }
}

#[test]
fn sol_transfers_keep_their_caps() {
    let (d, meta, _) = pipeline(
        &format!("solana transfer {PK} 50 --url {MAINNET}"),
        Network::Devnet,
        Tier::Relaxed,
        false,
        false,
    );
    assert!(matches!(d, Decision::Deny { .. }), "{d:?}");
    assert_eq!(meta.amount_sol, Some(50.0));
}

#[test]
fn unquoted_query_glob_in_url_equals_the_quoted_form() {
    let pairs = [
        (
            format!("solana transfer {PK} 50 --url {MAINNET}/?x"),
            format!("solana transfer {PK} 50 --url '{MAINNET}/?x'"),
        ),
        (
            format!("solana --url {MAINNET}/?x transfer {PK} 50"),
            format!("solana --url '{MAINNET}/?x' transfer {PK} 50"),
        ),
        (
            format!("solana transfer {PK} 50 --url={MAINNET}/?x=1"),
            format!("solana transfer {PK} 50 '--url={MAINNET}/?x=1'"),
        ),
        (
            format!("solana transfer {PK} 0.5 --url https://api.devnet.solana.com/?x"),
            format!("solana transfer {PK} 0.5 --url 'https://api.devnet.solana.com/?x'"),
        ),
    ];
    for (bare, quoted) in pairs {
        for grant in [false, true] {
            let (b, bm, bl) = pipeline(&bare, Network::Devnet, Tier::Relaxed, grant, false);
            let (q, qm, ql) = pipeline(&quoted, Network::Devnet, Tier::Relaxed, grant, false);
            assert_eq!(b, q, "{bare}");
            assert_eq!(bm.amount_sol, qm.amount_sol, "{bare}");
            assert_eq!(bl, ql, "{bare} (grant {grant})");
        }
    }
}

#[test]
fn a_glob_before_the_url_path_stays_uncertain() {
    for cmd in [
        format!("solana transfer {PK} 0.5 --url https://api.devnet.solana.com?x"),
        format!("solana transfer {PK} 0.5 --url https://api.devnet.solana.co?"),
        format!("solana transfer {PK} 0.5 --url https://api.devnet.solana.com*/x"),
        format!("solana transfer {PK} 0.5 --url http://[::1]:8899"),
        format!("solana transfer {PK} 0.5 --url https://api.devnet.solana.com/$X"),
        format!("solana transfer {PK} 0.5 --url https://api.devnet.solana.com/{{a,b}}"),
        format!("solana transfer {PK} 0.5 --url api.devnet.solana.com/?x"),
    ] {
        let (d, _, _) = pipeline(&cmd, Network::Devnet, Tier::Relaxed, false, false);
        assert!(matches!(d, Decision::Ask { .. }), "{cmd}: {d:?}");
    }
}

/// Micro-benchmark of `bash::decide` over the difftest Bash payloads (a JSON list of command
/// strings at `$W5_BENCH_PAYLOADS`). Run with
/// `cargo test --release --test gap_w5-onchain -- --ignored --nocapture bench`.
#[test]
#[ignore = "benchmark; needs W5_BENCH_PAYLOADS"]
fn bench_decide_over_difftest_payloads() {
    let Ok(path) = std::env::var("W5_BENCH_PAYLOADS") else {
        return;
    };
    let cmds: Vec<String> = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let data = TempDir::new("w5-bench");
    let ctx = Context {
        network: Network::Devnet,
        anchor_network: Network::Devnet,
        plugin_data: data.path().to_path_buf(),
        project_dir: data.path().to_path_buf(),
    };
    let policy = Policy::default();
    const ROUNDS: u32 = 200;
    let started = std::time::Instant::now();
    for _ in 0..ROUNDS {
        for cmd in &cmds {
            std::hint::black_box(bash::decide(std::hint::black_box(cmd), &ctx, &policy));
        }
    }
    let calls = u128::from(ROUNDS) * cmds.len() as u128;
    let per = started.elapsed().as_nanos() / calls.max(1);
    println!(
        "bench: {} payloads x {ROUNDS} rounds, {per} ns/call",
        cmds.len()
    );
}

// ---------------------------------------------------------------------------------------
// Fix round: red-team R1, R2, R7, R8 and read-only lookups
// ---------------------------------------------------------------------------------------

/// The natural decision for `command` with the CLI default `network`, run in a project dir
/// holding `files` (relative path, content).
fn decide_in(command: &str, network: Network, files: &[(&str, &str)]) -> Decision {
    let proj = TempDir::new("w5-fix");
    for (rel, body) in files {
        std::fs::write(proj.join(rel), body).unwrap();
    }
    let ctx = Context {
        network,
        anchor_network: network,
        plugin_data: proj.path().to_path_buf(),
        project_dir: proj.path().to_path_buf(),
    };
    bash::decide(command, &ctx, &Policy::default()).0
}

#[test]
fn r1_a_backslash_ends_the_url_authority() {
    for url in [
        r"'https://evil.example\@api.devnet.solana.com'",
        r"'https://evil.example\api.devnet.solana.com'",
        "'https://api.devnet.solana.com%2e.evil.example'",
        "'https://api.devnet.solana.com\t.evil.example'",
        "'https://api.devnet.solana.com,evil.example'",
    ] {
        for cmd in [
            format!("solana transfer {PK} 0.5 --url {url}"),
            format!("spl-token transfer {MINT} 1000 {PK} --url {url}"),
        ] {
            let d = decide_in(&cmd, Network::Devnet, &[]);
            assert!(matches!(d, Decision::Ask { .. }), "{cmd}: {d:?}");
        }
    }
    // The plain host, with userinfo, keeps its cluster.
    let d = decide_in(
        &format!("solana transfer {PK} 0.5 --url https://u:p@api.devnet.solana.com"),
        Network::Unknown,
        &[],
    );
    assert_eq!(d, Decision::Allow);
}

const DECOY: &str = "address_labels:\n  k: |\n    json_rpc_url: https://api.devnet.solana.com\n\
json_rpc_url: https://rpc.mycorp.io\n";

#[test]
fn r2_only_a_single_top_level_json_rpc_url_counts() {
    let configs = [
        DECOY,
        "address_labels:\n  json_rpc_url: https://api.devnet.solana.com\njson_rpc_url: https://rpc.mycorp.io\n",
        "json_rpc_url: https://api.devnet.solana.com\njson_rpc_url: https://rpc.mycorp.io\n",
        "{json_rpc_url: https://api.devnet.solana.com}\n",
        "x: &u https://rpc.mycorp.io\njson_rpc_url: *u\n",
        "json_rpc_url: https://api.devnet.solana.com\n---\njson_rpc_url: https://rpc.mycorp.io\n",
        "json_rpc_url: [https://api.devnet.solana.com\n",
        "  json_rpc_url: https://api.devnet.solana.com\n",
    ];
    for body in configs {
        for cmd in [
            format!("solana -C c.yml transfer {PK} 0.5"),
            format!("spl-token -C c.yml transfer {MINT} 1000000 {PK}"),
        ] {
            let d = decide_in(&cmd, Network::Devnet, &[("c.yml", body)]);
            assert!(matches!(d, Decision::Ask { .. }), "{body:?} {cmd}: {d:?}");
        }
    }
    // A config as the CLI writes it keeps its cluster.
    let real = "---\njson_rpc_url: \"https://api.devnet.solana.com\"\nwebsocket_url: ''\n\
keypair_path: /k.json\naddress_labels:\n  \"11111111111111111111111111111111\": System Program\n\
commitment: confirmed\n";
    let d = decide_in(
        &format!("solana -C c.yml transfer {PK} 0.5"),
        Network::Unknown,
        &[("c.yml", real)],
    );
    assert_eq!(d, Decision::Allow);
}

#[test]
fn r7_only_feature_status_is_read_only() {
    for cmd in [
        "solana feature activate F.json -um",
        "solana feature revoke F.json -ud",
    ] {
        let d = decide_in(cmd, Network::Devnet, &[]);
        assert!(matches!(d, Decision::Ask { .. }), "{cmd}: {d:?}");
    }
    assert_eq!(
        decide_in("solana feature status -um", Network::Devnet, &[]),
        Decision::Defer
    );
}

#[test]
fn r8_more_authority_verbs_name_an_authority_change() {
    for cmd in [
        format!("solana stake-set-lockup S --new-custodian {PK} -ud"),
        "solana stake-set-lockup-checked S --new-custodian ~/c.json -ud".to_string(),
        "solana vote-update-validator V ~/id.json ~/w.json -ud".to_string(),
        format!("solana create-stake-account ~/s.json 1 --stake-authority {PK} -ud"),
        "solana create-stake-account-checked ~/s.json 1 --withdraw-authority ~/w.json -ud"
            .to_string(),
        format!("solana create-stake-account ~/s.json 1 --custodian {PK} -ud"),
        format!("solana create-nonce-account ~/n.json 1 --nonce-authority {PK} -ud"),
    ] {
        let d = decide_in(&cmd, Network::Devnet, &[]);
        assert!(
            matches!(&d, Decision::Ask { reason } if reason.contains("uthority change")),
            "{cmd}: {d:?}"
        );
    }
    // Without an authority flag a create stays the generic ask.
    let d = decide_in(
        "solana create-stake-account ~/s.json 1 -ud",
        Network::Devnet,
        &[],
    );
    assert!(
        matches!(&d, Decision::Ask { reason } if !reason.contains("uthority change")),
        "{d:?}"
    );
}

#[test]
fn account_lookups_are_read_only() {
    for cmd in [
        "solana stake-account S -ud",
        "solana vote-account V",
        "solana nonce-account N -um",
    ] {
        assert_eq!(
            decide_in(cmd, Network::Devnet, &[]),
            Decision::Defer,
            "{cmd}"
        );
    }
}
