//! Command parsing, network resolution, amounts, deadline and the indirection prefilter for
//! `gate-bash` (spec D1.3–D1.8, D6.3).
//!
//! In-process tests drive `gates::bash::decide` with pinned default networks; no opinion is
//! `Decision::Defer`. End-to-end tests drive the built binary with a stub `solana` on `PATH`.

mod common;

use std::path::Path;
use std::time::{Duration, Instant};

use common::{permission_decision, Invocation, Run, TempDir};
use safe_ai_skill::context::{Context, Network};
use safe_ai_skill::gate::GateMeta;
use safe_ai_skill::gates::bash;
use safe_ai_skill::io::Decision;
use safe_ai_skill::policy::Policy;

const DEST: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";

fn ctx_in(network: Network, anchor: Network, dir: &Path) -> Context {
    Context {
        network,
        anchor_network: anchor,
        plugin_data: dir.join("data"),
        project_dir: dir.to_path_buf(),
    }
}

/// Decide `command` with both default networks pinned to `network`.
fn decide(command: &str, network: Network) -> (Decision, GateMeta) {
    let dir = TempDir::new("parsing");
    bash::decide(
        command,
        &ctx_in(network, network, dir.path()),
        &Policy::default(),
    )
}

/// The always-on hook's prefilter for `command`, with a fresh data dir (the process env's
/// would be the developer's real one, or none: a missing spend ledger then asks).
fn prefilter(command: &str, policy: &Policy) -> Option<(Decision, GateMeta)> {
    let dir = TempDir::new("prefilter");
    let mut ctx = Context::build(command, Path::new("."));
    ctx.plugin_data = dir.join("data");
    bash::indirection_prefilter_in(command, &ctx, policy)
}

fn is_ask(d: &Decision) -> bool {
    matches!(d, Decision::Ask { .. })
}

fn is_deny(d: &Decision) -> bool {
    matches!(d, Decision::Deny { .. })
}

// ---------------------------------------------------------------------------------------
// A2 command parsing (D1.8)
// ---------------------------------------------------------------------------------------

#[test]
fn prefixed_and_wrapped_mainnet_transfers_are_gated() {
    for cmd in [
        format!("FOO=1 solana transfer -um {DEST} 1"),
        format!("env FOO=1 solana transfer -um {DEST} 1"),
        format!("env -i solana transfer -um {DEST} 1"),
        format!("sudo solana transfer -um {DEST} 1"),
        format!("sudo -u me -E solana transfer -um {DEST} 1"),
        format!("nohup solana transfer -um {DEST} 1 &"),
        format!("command solana transfer -um {DEST} 1"),
        format!("exec solana transfer -um {DEST} 1"),
        format!("time solana transfer -um {DEST} 1"),
        format!("/usr/local/bin/solana transfer -um {DEST} 1"),
        format!("\\solana transfer -um {DEST} 1"),
        format!("sol\"\"ana transfer -um {DEST} 1"),
    ] {
        let (d, _) = decide(&cmd, Network::Devnet);
        assert!(is_ask(&d), "{cmd}: {d:?}");
    }
}

#[test]
fn indirect_mainnet_transfers_are_gated() {
    for cmd in [
        format!("bash -c 'solana transfer -um {DEST} 1'"),
        format!("sh -lc \"solana transfer -um {DEST} 1\""),
        format!("echo $(solana transfer -um {DEST} 1)"),
        format!("echo `solana transfer -um {DEST} 1`"),
        format!("echo ok\nsolana transfer -um {DEST} 1"),
        format!("(cd x && solana transfer -um {DEST} 1)"),
        format!("eval 'solana transfer -um {DEST} 1'"),
        format!("bash <<EOF\nsolana transfer -um {DEST} 1\nEOF"),
        format!("bash <<< 'solana transfer -um {DEST} 1'"),
        format!("true & solana transfer -um {DEST} 1"),
        format!("find . -exec solana transfer -um {DEST} 1 \\;"),
        format!("f() {{ solana transfer -um {DEST} 1; }}; f"),
    ] {
        let (d, _) = decide(&cmd, Network::Devnet);
        assert!(is_ask(&d), "{cmd}: {d:?}");
    }
}

#[test]
fn unparseable_or_opaque_command_naming_solana_asks() {
    for cmd in [
        "echo \"unterminated solana transfer".to_string(),
        "echo $(solana transfer".to_string(),
        format!("echo 'solana transfer -um {DEST} 1' | bash"),
        "eval \"$CMD solana\"".to_string(),
        "S=solana; $S transfer x 1".to_string(),
        format!("python3 -c \"import os; os.system('solana transfer -um {DEST} 1')\""),
    ] {
        let (d, meta) = decide(&cmd, Network::Devnet);
        assert!(is_ask(&d), "{cmd}: {d:?}");
        assert!(meta.hard_guard, "{cmd}");
    }
}

#[test]
fn unrelated_commands_have_no_opinion() {
    for cmd in [
        "ls -la",
        "grep -r anchor src",
        "command -v solana",
        "echo \"it's fine\"",
        "cat <<'EOF' > notes.md\nwe use solana here; don't worry\nEOF",
        "git commit -m 'solana: fix'",
    ] {
        let (d, _) = decide(cmd, Network::Devnet);
        assert_eq!(d, Decision::Defer, "{cmd}");
    }
}

#[test]
fn separators_inside_quotes_do_not_split_a_transfer() {
    let (d, meta) = decide(
        &format!("solana transfer --with-memo \"a;b && c\" {DEST} 0.5"),
        Network::Devnet,
    );
    assert_eq!(d, Decision::Allow);
    assert_eq!(meta.amount_sol, Some(0.5));
}

#[test]
fn indirect_transfer_follows_spend_rules_but_the_prefilter_never_allows() {
    // Fully parsed, so the gate's own rules apply (fix round 2); the always-on hook that
    // routes it never emits the allow itself.
    let policy = Policy::default();
    for cmd in [
        format!("bash -c 'solana transfer -ud {DEST} 0.5'"),
        format!("sudo solana transfer -ud {DEST} 0.5"),
    ] {
        let (d, meta) = decide(&cmd, Network::Devnet);
        // `bash` itself is code the gate does not classify: no opinion rather than allow.
        assert!(
            matches!(d, Decision::Allow | Decision::Defer),
            "{cmd}: {d:?}"
        );
        assert!(!meta.hard_guard, "{cmd}");
        assert_eq!(prefilter(&cmd, &policy), None, "{cmd}");
    }
}

#[test]
fn newline_separates_commands() {
    // The second line is its own transfer: 500 is over the hard cap.
    let (d, _) = decide(
        &format!("solana transfer {DEST} 0.5\nsolana transfer {DEST} 500"),
        Network::Devnet,
    );
    assert!(is_deny(&d), "{d:?}");
}

#[test]
fn shell_expansions_make_a_transfer_ambiguous() {
    for cmd in [
        "solana transfer $D 0.5".to_string(),
        format!("solana transfer {DEST} 0.5 --with-memo $(echo x)"),
        format!("solana transfer {DEST} 0.5 $EXTRA"),
        format!("solana transfer {DEST} 0.5 *"),
        format!("solana transfer {DEST} {{0.5,500}}"),
        format!("solana --keypair $K transfer {DEST} 0.5"),
    ] {
        let (d, meta) = decide(&cmd, Network::Devnet);
        assert!(is_ask(&d), "{cmd}: {d:?}");
        assert!(meta.hard_guard, "{cmd}");
    }
    // An expansion before the subcommand hides it: ask even for a read-only-looking one.
    let (d, _) = decide("solana --keypair $K balance", Network::Devnet);
    assert!(is_ask(&d), "{d:?}");
    // After a read-only subcommand it changes nothing.
    let (d, _) = decide("solana balance $ADDR", Network::Devnet);
    assert_eq!(d, Decision::Defer);
    // A quoted expansion as a flag value is one word: the transfer stays clean.
    let (d, _) = decide(
        &format!("solana transfer --with-memo \"$NOTE\" {DEST} 0.5"),
        Network::Devnet,
    );
    assert_eq!(d, Decision::Allow);
}

#[test]
fn expansion_hiding_flags_makes_a_deploy_ask() {
    let (d, _) = decide("solana program deploy $SO", Network::Devnet);
    assert!(is_ask(&d), "{d:?}");
}

#[test]
fn empty_quoted_argument_is_a_positional() {
    let (d, _) = decide(&format!("solana transfer \"\" {DEST} 0.5"), Network::Devnet);
    assert!(is_ask(&d), "{d:?}");
}

// ---------------------------------------------------------------------------------------
// Carry-overs: `-u=`, unknown long flag before a `-`-word, redirections.
// ---------------------------------------------------------------------------------------

#[test]
fn empty_attached_url_is_unknown() {
    for cmd in [
        format!("solana transfer -u= d {DEST} 0.5"),
        format!("solana transfer --url= d {DEST} 0.5"),
    ] {
        let (d, _) = decide(&cmd, Network::Devnet);
        assert!(is_ask(&d), "{cmd}: {d:?}");
    }
}

#[test]
fn unknown_long_flag_before_a_cluster_flag_is_ambiguous() {
    let (d, _) = decide(
        &format!("solana transfer --mystery -ud {DEST} 0.5"),
        Network::Mainnet,
    );
    assert!(is_ask(&d), "{d:?}");
}

#[test]
fn descriptor_glued_to_a_redirection_is_not_the_amount() {
    // `1>f` redirects stdout: bash runs `solana transfer DEST` with no amount.
    let (d, _) = decide(&format!("solana transfer -ud {DEST} 1>f"), Network::Devnet);
    assert!(is_ask(&d), "{d:?}");
}

// ---------------------------------------------------------------------------------------
// A1 network resolution (D1.4)
// ---------------------------------------------------------------------------------------

#[test]
fn config_file_flag_is_read() {
    let dir = TempDir::new("cfgfile");
    std::fs::write(
        dir.join("mainnet.yml"),
        "---\njson_rpc_url: \"https://api.mainnet-beta.solana.com\"\nkeypair_path: k.json\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("dev.yml"),
        "json_rpc_url: https://api.devnet.solana.com\n",
    )
    .unwrap();
    let ctx = ctx_in(Network::Devnet, Network::Devnet, dir.path());
    let policy = Policy::default();
    for cmd in [
        format!("solana transfer -C ./mainnet.yml {DEST} 0.5"),
        format!("solana transfer --config=mainnet.yml {DEST} 0.5"),
        format!("solana transfer -C ./missing.yml {DEST} 0.5"),
        format!("solana transfer -C $CFG {DEST} 0.5"),
        format!("cd elsewhere && solana transfer -C dev.yml {DEST} 0.5"),
    ] {
        let (d, _) = bash::decide(&cmd, &ctx, &policy);
        assert!(is_ask(&d), "{cmd}: {d:?}");
    }
    // A devnet config file is devnet, whatever the default says.
    let mainnet_default = ctx_in(Network::Mainnet, Network::Mainnet, dir.path());
    let (d, _) = bash::decide(
        &format!("solana transfer -C dev.yml {DEST} 0.5"),
        &mainnet_default,
        &policy,
    );
    assert_eq!(d, Decision::Allow);
    // `-um` deploys and `--url=m` transfers are mainnet.
    let (d, _) = decide("solana program deploy -um --final ./p.so", Network::Devnet);
    assert!(is_deny(&d), "{d:?}");
    let (d, _) = decide(
        &format!("solana transfer --url=m {DEST} 0.5"),
        Network::Devnet,
    );
    assert!(is_ask(&d), "{d:?}");
}

#[test]
fn solana_commands_use_the_cli_default_and_anchor_its_own() {
    let dir = TempDir::new("defaults");
    // CLI config: mainnet. Anchor.toml: localnet.
    let ctx = ctx_in(Network::Mainnet, Network::Localnet, dir.path());
    let policy = Policy::default();
    let (d, meta) = bash::decide("solana program deploy ./p.so", &ctx, &policy);
    assert!(is_ask(&d), "{d:?}");
    // Class C (D8 v2 §2): a grantable ask on mainnet.
    assert!(!meta.hard_guard);
    assert_eq!(meta.scope, safe_ai_skill::gate::Scope::Deploy);
    let (d, _) = bash::decide("anchor deploy", &ctx, &policy);
    assert_eq!(d, Decision::Defer);
}

#[test]
fn config_changes_in_the_command_make_the_default_unknown() {
    let dir = TempDir::new("cfgchange");
    let ctx = ctx_in(Network::Devnet, Network::Localnet, dir.path());
    let policy = Policy::default();
    for cmd in [
        format!("export HOME=/tmp/other; solana transfer {DEST} 0.5"),
        format!("HOME=/tmp/other solana transfer {DEST} 0.5"),
        format!("source ./env.sh && solana transfer {DEST} 0.5"),
        "cd ../other && anchor deploy".to_string(),
        "ANCHOR_PROVIDER_URL=https://api.mainnet-beta.solana.com anchor deploy".to_string(),
    ] {
        let (d, _) = bash::decide(&cmd, &ctx, &policy);
        assert!(is_ask(&d), "{cmd}: {d:?}");
    }
}

#[test]
fn mainnet_deny_policy_denies_mainnet_value_moves() {
    let mut policy = Policy::default();
    policy.network.mainnet = "deny".to_string();
    let dir = TempDir::new("mainnetdeny");
    let ctx = ctx_in(Network::Mainnet, Network::Mainnet, dir.path());
    for cmd in [
        format!("solana transfer {DEST} 0.1"),
        "solana program deploy ./p.so".to_string(),
        "anchor deploy".to_string(),
    ] {
        let (d, _) = bash::decide(&cmd, &ctx, &policy);
        assert!(is_deny(&d), "{cmd}: {d:?}");
    }
    // Read-only commands keep no opinion; devnet is untouched.
    let (d, _) = bash::decide("solana balance", &ctx, &policy);
    assert_eq!(d, Decision::Defer);
    let (d, _) = bash::decide(&format!("solana transfer -ud {DEST} 0.1"), &ctx, &policy);
    assert_eq!(d, Decision::Allow);
}

// ---------------------------------------------------------------------------------------
// A3 amounts (D1.5)
// ---------------------------------------------------------------------------------------

#[test]
fn amounts_are_positional_and_exact() {
    let (d, meta) = decide(
        &format!("solana transfer --with-memo 0.0001 {DEST} 500"),
        Network::Devnet,
    );
    assert!(is_deny(&d), "{d:?}");
    assert_eq!(meta.amount_sol, Some(500.0));
    let (d, meta) = decide(
        &format!("solana transfer --from k.json {DEST} 1"),
        Network::Devnet,
    );
    assert_eq!(d, Decision::Allow);
    assert_eq!(meta.amount_sol, Some(1.0));
    let (d, meta) = decide(&format!("solana transfer {DEST} ALL"), Network::Devnet);
    assert!(is_ask(&d) && meta.hard_guard, "{d:?}");
    for amount in [
        "1 2",
        "1e3",
        "0x10",
        "+1",
        "1_000",
        "NaN",
        "inf",
        "1.2.3",
        ".",
        "9".repeat(400).as_str(),
    ] {
        let (d, meta) = decide(&format!("solana transfer {DEST} {amount}"), Network::Devnet);
        assert!(is_ask(&d), "{amount}: {d:?}");
        assert!(meta.hard_guard, "{amount}");
        assert_eq!(meta.amount_sol, None, "{amount}");
    }
    let (d, meta) = decide(&format!("solana transfer {DEST} .5"), Network::Devnet);
    assert_eq!(d, Decision::Allow);
    assert_eq!(meta.amount_sol, Some(0.5));
}

// ---------------------------------------------------------------------------------------
// A5 indirection prefilter (D6.3)
// ---------------------------------------------------------------------------------------

#[test]
fn prefilter_routes_indirect_solana_to_the_gate() {
    let policy = Policy::default();
    for cmd in [
        format!("bash -c 'solana transfer -um {DEST} 1'"),
        format!("eval \"solana transfer -um {DEST} 1\""),
        format!("echo x\nsolana transfer -um {DEST} 1"),
        format!("sudo solana transfer -um {DEST} 0.5"),
        format!("sol''ana transfer -um {DEST} 0.5"),
        format!("echo x | solana transfer -um {DEST} 1"),
        format!("false || solana transfer -um {DEST} 1"),
        "echo \"unterminated solana".to_string(),
        "bash -c 'anchor deploy --provider.cluster mainnet'".to_string(),
        format!("FOO=1 solana transfer -um {DEST} 1"),
    ] {
        match prefilter(&cmd, &policy) {
            Some((Decision::Ask { .. }, _)) => {}
            other => panic!("{cmd}: {other:?}"),
        }
    }
    // A fully parsed routed command keeps the gate's own meta: a grant may relax it.
    let (_, meta) = prefilter(&format!("sudo solana transfer -um {DEST} 0.5"), &policy).unwrap();
    assert!(!meta.hard_guard);
    let (d, _) = decide(
        "bash -c 'solana program deploy -um --final p.so'",
        Network::Devnet,
    );
    assert!(is_deny(&d), "{d:?}");
    assert!(matches!(
        prefilter("bash -c 'solana program deploy -um --final p.so'", &policy),
        Some((Decision::Deny { .. }, _))
    ));
}

#[test]
fn prefilter_leaves_direct_and_unrelated_commands_alone() {
    let policy = Policy::default();
    for cmd in [
        format!("solana transfer -um {DEST} 1"),
        "anchor deploy".to_string(),
        // Every family command is one gate-bash sees (`;` and `&&` split): it decides.
        format!("solana balance && solana transfer -um {DEST} 1"),
        format!("solana transfer -um {DEST} 1; echo done"),
        "cd app && anchor test".to_string(),
        format!("cd x && solana transfer -ud {DEST} 0.5"),
        "ls -la".to_string(),
        // Family mentions with read-only words only.
        "sudo solana balance".to_string(),
        "echo \"solana --version\"".to_string(),
        "node -e \"require('@coral-xyz/anchor')\"".to_string(),
        "cargo add solana-sdk anchor-lang".to_string(),
        "grep -r anchor src".to_string(),
        "bash -c 'solana balance'".to_string(),
        format!("bash -c 'solana transfer -ud {DEST} 0.5'"),
    ] {
        assert_eq!(prefilter(&cmd, &policy), None, "{cmd}");
    }
}

/// The review's probe rows (fix round 1): each got no opinion from either hook before.
fn probe_rows() -> Vec<String> {
    let t = format!("transfer -um {DEST} 1");
    vec![
        format!("command solana {t} -v"),
        format!("watch -n 100 'solana {t}'"),
        format!("hyperfine 'solana {t}'"),
        format!("script -q -c 'solana {t}' /dev/null"),
        format!("tmux new -d 'solana {t}'"),
        format!("flock l -c 'solana {t}'"),
        format!("nix-shell --run 'solana {t}'"),
        format!("parallel ::: 'solana {t}'"),
        format!("bash /dev/stdin <<EOF\nsolana {t}\nEOF"),
        format!(
            "python3 - <<'EOF'\nimport subprocess\nsubprocess.run(['solana','transfer','-um','{DEST}','1'])\nEOF"
        ),
        format!("f(){{ solana \"$@\"; }}; f {t}"),
        format!("=solana {t}"),
        format!("noglob solana {t}"),
        format!("nocorrect solana {t}"),
        format!("repeat 1 solana {t}"),
        format!("arch -arm64 solana {t}"),
        format!("sandbox-exec -n x solana {t}"),
        format!("solana.exe {t}"),
        format!("echo 'solana {t}' > x.sh; bash x.sh"),
        format!("SOLANA {t}"),
        format!("Solana {t}"),
        format!("case a in a) solana {t};; esac"),
        format!("for i in 1; solana {t}"),
        format!("pkexec solana {t}"),
        format!("sg grp -c 'solana {t}'"),
        format!("fakeroot solana {t}"),
        format!("numactl --cpunodebind=0 solana {t}"),
        format!("chpst -u me solana {t}"),
        format!("'C:\\bin\\solana.exe' {t}"),
    ]
}

#[test]
fn probe_rows_get_a_verdict_from_the_always_on_hook() {
    let policy = Policy::default();
    for cmd in probe_rows() {
        match prefilter(&cmd, &policy) {
            Some((Decision::Ask { .. } | Decision::Deny { .. }, _)) => {}
            other => panic!("{cmd}: {other:?}"),
        }
    }
}

/// Commands built from expansions around a family name (fix round 2): a hard-guard ask from
/// both hooks, whatever their words.
fn expansion_rows() -> Vec<String> {
    vec![
        "bash -c \"solana $X\"".to_string(),
        "eval \"solana $ARGS\"".to_string(),
        "sh -c \"spl-token $OP\"".to_string(),
        "printf 'solana %s' \"$A\" | sh".to_string(),
        "python3 -c \"import os; os.system('solana ' + os.environ['A'])\"".to_string(),
        "X=solana; $X $Y".to_string(),
        "eval \"$CMD solana\"".to_string(),
        "echo \"unterminated solana".to_string(),
        format!("S=transfer; solana $S -um {DEST} 1"),
    ]
}

#[test]
fn expansion_built_family_commands_ask_as_hard_guard() {
    let policy = Policy::default();
    for cmd in expansion_rows() {
        let (d, meta) = decide(&cmd, Network::Devnet);
        assert!(is_ask(&d) && meta.hard_guard, "{cmd}: {d:?}");
        match prefilter(&cmd, &policy) {
            Some((Decision::Ask { .. }, meta)) => assert!(meta.hard_guard, "{cmd}"),
            other => panic!("{cmd}: {other:?}"),
        }
    }
    // Two reasons: unparseable versus a family command the gate cannot fully see.
    let (unparsed, _) = decide("eval \"$CMD solana\"", Network::Devnet);
    let (unseen, _) = decide("X=solana; $X $Y", Network::Devnet);
    assert!(
        unparsed.reason().contains("Could not parse"),
        "{unparsed:?}"
    );
    assert!(unseen.reason().contains("expansion"), "{unseen:?}");
}

/// Round-3 rows: path-qualified programs in opaque code, write-then-run variants, and
/// dynamic programs with literal value-moving words. Each is a hard-guard ask from both hooks.
fn round3_rows() -> Vec<String> {
    let release = "~/.local/share/solana/install/active_release/bin/solana";
    vec![
        "bash -c \"./solana $X\"".to_string(),
        "eval \"./solana $ARGS\"".to_string(),
        "eval \"../bin/solana $A\"".to_string(),
        format!("bash -c \"{release} $X\""),
        "bash -c \"$HOME/.local/share/solana/install/active_release/bin/solana $X\"".to_string(),
        "python3 -c \"import os; os.system('./solana ' + os.environ['A'])\"".to_string(),
        format!("printf '{release} %s' \"$A\" | sh"),
        "bash -c \"./solana transfer -um $D 1\"".to_string(),
        format!("eval \"{release} transfer $A\""),
        format!("echo 'solana transfer -um {DEST} 1' > x.sh; cat x.sh | bash"),
        format!("echo 'solana transfer -um {DEST} 1' > x.sh; sh < x.sh"),
        format!("printf 'solana transfer -um {DEST} 1' | tee x.sh >/dev/null; bash x.sh"),
        format!(
            "echo \"import os; os.system('solana transfer -um {DEST} 1')\" > x.py && python3 x.py"
        ),
        format!("$(echo sol)ana transfer -um {DEST} 1"),
        format!("$(printf %s ./solana) transfer -um {DEST} 1"),
    ]
}

#[test]
fn round3_rows_ask_as_hard_guard_from_both_hooks() {
    let policy = Policy::default();
    for cmd in round3_rows() {
        let (d, meta) = decide(&cmd, Network::Devnet);
        assert!(is_ask(&d) && meta.hard_guard, "{cmd}: {d:?}");
        match prefilter(&cmd, &policy) {
            Some((Decision::Ask { .. }, meta)) => assert!(meta.hard_guard, "{cmd}"),
            other => panic!("{cmd}: {other:?}"),
        }
    }
}

#[test]
fn e2e_round3_rows_ask_in_the_secrets_hook() {
    let bin = stub_solana(MAINNET_STUB);
    let project = TempDir::new("round3-proj");
    for cmd in round3_rows() {
        let run = run_hook("gate-bash-secrets", &cmd, bin.path(), project.path(), &[]);
        assert_eq!(label(&run).as_deref(), Some("ask"), "{cmd}: {}", run.stdout);
    }
}

/// Fix round 4: ordinary commands that redirect, `tee`, or run a script, and English words
/// after an expanded program. Only emitted script text counts as a write, and a dynamic
/// program asks only when it could spell a family name: no opinion from either hook.
fn round4_quiet_rows() -> Vec<&'static str> {
    vec![
        "anchor build 2>&1 | tee build.log && ./scripts/post-build.sh",
        "grep solana Cargo.toml > deps.txt && ./scripts/check.sh",
        "cargo tree | grep solana > tree.txt; python3 analyze.py tree.txt",
        "git log --oneline | grep anchor > log.txt && bash scripts/summary.sh",
        "ls ~/.config/solana > out.txt; ./bin/report",
        "echo \"anchor build failed\" > notes.md; ./scripts/ci.sh",
        "$EDITOR close-notes.md",
        "$CARGO run --bin stake-pool-cli",
        "$PKG run deploy",
        "\"$PYTHON\" scripts/mint_nft.py create",
        "$GIT branch -d close-old-branch",
        "${CC:-cc} -o wrap wrap.c",
        "$(npm bin)/hardhat deploy",
    ]
}

#[test]
fn round4_quiet_rows_have_no_opinion() {
    let policy = Policy::default();
    for cmd in round4_quiet_rows() {
        let (d, _) = decide(cmd, Network::Mainnet);
        assert_eq!(d, Decision::Defer, "{cmd}");
        assert_eq!(prefilter(cmd, &policy), None, "{cmd}");
    }
}

/// Fix round 4: emitted scripts that are then run (every shape), and expansions that spell a
/// family program. Each is a hard-guard ask from both hooks.
fn round4_ask_rows() -> Vec<String> {
    let t = format!("solana transfer -um {DEST} 1");
    vec![
        format!("echo '{t}' > x.sh; cat x.sh | bash"),
        format!("echo '{t}' > x.sh; sh < x.sh"),
        format!("printf '{t}' | tee x.sh >/dev/null; bash x.sh"),
        format!("echo \"import os; os.system('{t}')\" > x.py && python3 x.py"),
        format!("echo '{t}' >> x.sh && zsh x.sh"),
        format!("echo '{t}' > x.sh; chmod +x x.sh; x.sh"),
        format!("echo '{t}' > x.sh; . ./x.sh"),
        format!("cat > x.sh <<EOF\n{t}\nEOF\nbash x.sh"),
        format!("cat <<< '{t}' > x.sh; bash x.sh"),
        format!("echo '{t}' > x.sh; xargs -a x.sh -I{{}} sh -c '{{}}'"),
        format!("$(echo sol)ana transfer -um {DEST} 1"),
        format!("$(printf %s ./solana) transfer -um {DEST} 1"),
        format!("${{S}}olana transfer -um {DEST} 1"),
        format!("$X transfer -um {DEST} 1"),
        // Fix round 5: dynamic programs and printf formats inside emitted scripts.
        format!("echo 'X=solana; $X transfer -um {DEST} 1' > x.sh; bash x.sh"),
        format!("echo 'for p in solana; do $p transfer -um {DEST} 1; done' > x.sh; bash x.sh"),
        format!("printf '%s' '{t}' > x.sh; bash x.sh"),
        format!("printf '%s ' solana transfer -um {DEST} 1 > x.sh; bash x.sh"),
        format!("echo '$(echo sol)ana transfer -um {DEST} 1' > x.sh; bash x.sh"),
        format!("tee x.sh <<< '{t}'; bash x.sh"),
        format!("tee x.sh <<EOF\n{t}\nEOF\nbash x.sh"),
        format!("printf 'solana %s -um %s %d' transfer {DEST} 1 > x.sh; bash x.sh"),
    ]
}

#[test]
fn round4_ask_rows_ask_as_hard_guard_from_both_hooks() {
    let policy = Policy::default();
    for cmd in round4_ask_rows() {
        let (d, meta) = decide(&cmd, Network::Devnet);
        assert!(is_ask(&d) && meta.hard_guard, "{cmd}: {d:?}");
        match prefilter(&cmd, &policy) {
            Some((Decision::Ask { .. }, meta)) => assert!(meta.hard_guard, "{cmd}"),
            other => panic!("{cmd}: {other:?}"),
        }
    }
    // The dynamic-program case has its own reason.
    let (d, _) = decide(
        &format!("${{S}}olana transfer -um {DEST} 1"),
        Network::Devnet,
    );
    assert!(d.reason().contains("expansion"), "{d:?}");
}

#[test]
fn e2e_round4_rows_in_the_secrets_hook() {
    let bin = stub_solana(MAINNET_STUB);
    let project = TempDir::new("round4-proj");
    for cmd in round4_ask_rows() {
        let run = run_hook("gate-bash-secrets", &cmd, bin.path(), project.path(), &[]);
        assert_eq!(label(&run).as_deref(), Some("ask"), "{cmd}: {}", run.stdout);
    }
    for cmd in round4_quiet_rows() {
        let run = run_hook("gate-bash-secrets", cmd, bin.path(), project.path(), &[]);
        assert_eq!(label(&run), None, "{cmd}: {}", run.stdout);
    }
}

#[test]
fn data_mentions_have_no_opinion() {
    let policy = Policy::default();
    for cmd in [
        "git commit -m \"fix solana transfer bug\"",
        "grep -r \"solana transfer\" docs/",
        "rg \"solana program\" src",
        "git log --grep \"solana config\"",
        "echo \"run anchor test\" && cargo build",
        "cd programs/anchor && cargo test",
        "vim programs/anchor/tests/run.rs",
        "ls ~/.config/solana && cat config.yml",
        "yarn add @coral-xyz/anchor && yarn test",
        "npm i @coral-xyz/anchor && npm run build",
        "node -e \"require('@coral-xyz/anchor'); x.transfer()\"",
    ] {
        let (d, _) = decide(cmd, Network::Devnet);
        assert_eq!(d, Decision::Defer, "{cmd}");
        assert_eq!(prefilter(cmd, &policy), None, "{cmd}");
    }
    // gate-bash's own rules decide these; the always-on hook defers to it.
    let (d, _) = decide("cd app && anchor test", Network::Devnet);
    assert!(is_ask(&d), "{d:?}");
    let (d, meta) = decide(
        &format!("cd x && solana transfer -ud {DEST} 0.5"),
        Network::Devnet,
    );
    assert_eq!(d, Decision::Defer);
    assert_eq!(meta.amount_sol, Some(0.5));
}

#[test]
fn probe_rows_ask_in_gate_bash_too() {
    for cmd in probe_rows() {
        let (d, _) = decide(&cmd, Network::Devnet);
        assert!(is_ask(&d) || is_deny(&d), "{cmd}: {d:?}");
    }
}

// ---------------------------------------------------------------------------------------
// End to end: stub `solana`, Anchor.toml, timeouts, deadline, prefilter hook.
// ---------------------------------------------------------------------------------------

/// A dir holding an executable `solana` stub running `body`.
fn stub_solana(body: &str) -> TempDir {
    let dir = TempDir::new("stub-bin");
    let path = dir.join("solana");
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    dir
}

/// Run `sub` on `command` with `bin` first on `PATH` and `cwd` as the hook cwd.
fn run_hook(sub: &str, command: &str, bin: &Path, cwd: &Path, extra: &[(&str, &str)]) -> Run {
    let data = TempDir::new("parse-data");
    let home = TempDir::new("parse-home");
    let payload = serde_json::json!({
        "session_id": "it-parsing",
        "cwd": cwd.to_str().unwrap(),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command }
    })
    .to_string();
    let path = format!("{}:/usr/bin:/bin", bin.display());
    let mut inv = Invocation::new(&[sub])
        .plugin_data(data.path())
        .home(home.path())
        .env("PATH", &path)
        .stdin(payload);
    for (k, v) in extra {
        inv = inv.env(k, v);
    }
    inv.run()
}

/// The emitted decision label, or `None` for no opinion.
fn label(run: &Run) -> Option<String> {
    assert_eq!(run.code, Some(0), "stderr: {}", run.stderr);
    if run.stdout.trim().is_empty() {
        return None;
    }
    permission_decision(&run.json())
}

const MAINNET_STUB: &str =
    "echo \"Config File: x\"\necho \"RPC URL: https://api.mainnet-beta.solana.com\"";

#[test]
fn e2e_anchor_toml_does_not_override_the_cli_config_for_solana() {
    let bin = stub_solana(MAINNET_STUB);
    let project = TempDir::new("anchor-proj");
    std::fs::write(
        project.join("Anchor.toml"),
        "[provider]\ncluster = \"localnet\"\nwallet = \"k.json\"\n",
    )
    .unwrap();
    let run = run_hook(
        "gate-bash",
        "solana program deploy ./p.so",
        bin.path(),
        project.path(),
        &[],
    );
    assert_eq!(label(&run).as_deref(), Some("ask"));
    // anchor reads Anchor.toml: localnet rules, no opinion.
    let run = run_hook(
        "gate-bash",
        "anchor deploy",
        bin.path(),
        project.path(),
        &[],
    );
    assert_eq!(label(&run), None, "{}", run.stdout);
    // From a subdirectory too (anchor discovers Anchor.toml upward).
    let sub = project.join("programs");
    std::fs::create_dir_all(&sub).unwrap();
    let run = run_hook("gate-bash", "anchor deploy", bin.path(), &sub, &[]);
    assert_eq!(label(&run), None, "{}", run.stdout);
}

#[test]
fn e2e_slow_solana_config_is_unknown_within_its_timeout() {
    let bin = stub_solana("sleep 30");
    let project = TempDir::new("slow-proj");
    let started = Instant::now();
    let run = run_hook(
        "gate-bash",
        &format!("solana transfer {DEST} 0.5"),
        bin.path(),
        project.path(),
        &[],
    );
    let elapsed = started.elapsed();
    assert_eq!(label(&run).as_deref(), Some("ask"), "{}", run.stdout);
    assert!(elapsed < Duration::from_secs(6), "took {elapsed:?}");
    assert!(run.stdout.contains("unidentified"), "{}", run.stdout);
}

#[test]
fn e2e_deadline_env_has_a_floor() {
    // 200 ms is below the 2 s floor: the gate still gets 2 s, and asks.
    let bin = stub_solana("sleep 30");
    let project = TempDir::new("deadline-proj");
    let started = Instant::now();
    let run = run_hook(
        "gate-bash",
        &format!("solana transfer {DEST} 0.5"),
        bin.path(),
        project.path(),
        &[("SAFE_AI_SKILL_DEADLINE_MS", "200")],
    );
    let elapsed = started.elapsed();
    assert_eq!(label(&run).as_deref(), Some("ask"), "{}", run.stdout);
    assert!(elapsed >= Duration::from_millis(1500), "took {elapsed:?}");
    assert!(elapsed < Duration::from_secs(6), "took {elapsed:?}");
}

#[test]
fn e2e_deadline_does_not_turn_a_deny_into_an_ask() {
    // A mainnet `--final` deploy is denied without touching the slow CLI; the shortest
    // deadline the env can set does not get in its way.
    let bin = stub_solana("sleep 30");
    let project = TempDir::new("deadline-deny");
    let run = run_hook(
        "gate-bash",
        "solana program deploy -um --final ./p.so",
        bin.path(),
        project.path(),
        &[("SAFE_AI_SKILL_DEADLINE_MS", "1")],
    );
    assert_eq!(label(&run).as_deref(), Some("deny"), "{}", run.stdout);
}

#[test]
fn e2e_probe_rows_ask_in_the_secrets_hook() {
    let bin = stub_solana(MAINNET_STUB);
    let project = TempDir::new("probe-proj");
    for cmd in probe_rows() {
        let run = run_hook("gate-bash-secrets", &cmd, bin.path(), project.path(), &[]);
        let got = label(&run);
        assert!(
            matches!(got.as_deref(), Some("ask" | "deny")),
            "{cmd}: {got:?} {}",
            run.stdout
        );
    }
}

#[test]
fn e2e_deadline_cannot_be_loosened() {
    // A larger value is ignored (8 s stays the bound); the run itself is fast.
    let bin = stub_solana(MAINNET_STUB);
    let project = TempDir::new("deadline-loose");
    let run = run_hook(
        "gate-bash",
        &format!("solana transfer {DEST} 0.5"),
        bin.path(),
        project.path(),
        &[("SAFE_AI_SKILL_DEADLINE_MS", "999999999")],
    );
    assert_eq!(label(&run).as_deref(), Some("ask"));
}

#[test]
fn e2e_secrets_hook_prefilters_indirection() {
    let bin = stub_solana(MAINNET_STUB);
    let project = TempDir::new("prefilter-proj");
    let run = run_hook(
        "gate-bash-secrets",
        &format!("bash -c 'solana transfer -um {DEST} 1'"),
        bin.path(),
        project.path(),
        &[],
    );
    assert_eq!(label(&run).as_deref(), Some("ask"), "{}", run.stdout);
    // A secret read still denies alongside.
    let run = run_hook(
        "gate-bash-secrets",
        &format!("bash -c 'solana transfer -um {DEST} 1'; cat ~/.config/solana/id.json"),
        bin.path(),
        project.path(),
        &[],
    );
    assert_eq!(label(&run).as_deref(), Some("deny"), "{}", run.stdout);
    // A direct command is left to gate-bash.
    let run = run_hook(
        "gate-bash-secrets",
        &format!("solana transfer -um {DEST} 1"),
        bin.path(),
        project.path(),
        &[],
    );
    assert_eq!(label(&run), None, "{}", run.stdout);
}
