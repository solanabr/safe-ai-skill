//! D8 v2 on-chain split (spec §2, §3; issue #18): Class U (unrecoverable, the shared list's
//! `irreversible` rows), default-wallet destruction, and Class C (counterparty) per tier.
//!
//! Library rows drive `gates::bash::decide` then the hook pipeline (`relax::apply`, then
//! `headless::apply`) with the tier set on the policy, so every tier, grants and headless are
//! covered without `test-hooks`. Binary rows feed command strings to `gate-bash`,
//! `gate-bash-secrets` and `gate-tamper` with `PATH` an empty dir (or a stub `solana`), a fake
//! `HOME` and an isolated data dir: no real CLI ever runs.

mod common;

use std::path::Path;

use common::{decision_label, Invocation, Run, TempDir, Tier};
use safe_ai_skill::context::{Context, Network};
use safe_ai_skill::datadir::DataDir;
use safe_ai_skill::gate::Scope;
use safe_ai_skill::gates::bash;
use safe_ai_skill::grants::{self, Grant, Grants};
use safe_ai_skill::io::Decision;
use safe_ai_skill::policy::Policy;
use safe_ai_skill::{headless, relax};
use serde_json::json;

const D: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";
const M: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const Q: &str = "8yQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";

const ALL_TIERS: [Tier; 4] = [Tier::Off, Tier::Relaxed, Tier::Medium, Tier::High];

// ---------------------------------------------------------------------------------------
// Library pipeline
// ---------------------------------------------------------------------------------------

/// How a library row runs.
#[derive(Clone, Copy)]
struct Setup {
    /// The CLI default cluster (and Anchor's) for commands naming none.
    default: Network,
    tier: Tier,
    /// A live confirmed grant for every grantable scope, unrestricted, with a large budget.
    grant: bool,
    headless: bool,
    mainnet_deny: bool,
}

impl Setup {
    fn at(tier: Tier) -> Setup {
        Setup {
            default: Network::Unknown,
            tier,
            grant: false,
            headless: false,
            mainnet_deny: false,
        }
    }
    fn default_net(mut self, net: Network) -> Setup {
        self.default = net;
        self
    }
    fn grant(mut self) -> Setup {
        self.grant = true;
        self
    }
    fn headless(mut self) -> Setup {
        self.headless = true;
        self
    }
    fn mainnet_deny(mut self) -> Setup {
        self.mainnet_deny = true;
        self
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

thread_local! {
    /// One data dir per test thread for each grant state: the gate only predicts spend, and
    /// a grant's budget outlasts every row.
    static DIRS: [TempDir; 2] = [TempDir::new("onchain-lib"), {
        let with_grant = TempDir::new("onchain-lib-grant");
        grant_everything(&trusted(with_grant.path()));
        with_grant
    }];
}

fn trusted(path: &Path) -> DataDir {
    DataDir {
        path: path.to_path_buf(),
        trusted: true,
    }
}

/// The final decision for `command` under `setup`, as the hook would emit it.
fn run_lib(command: &str, setup: Setup) -> Decision {
    DIRS.with(|dirs| {
        let data = &dirs[usize::from(setup.grant)];
        let dir = trusted(data.path());
        let ctx = Context {
            network: setup.default,
            anchor_network: setup.default,
            plugin_data: data.path().to_path_buf(),
            project_dir: data.path().to_path_buf(),
        };
        let mut policy = Policy::default();
        policy.runtime.tier = setup.tier;
        policy.runtime.headless = setup.headless;
        if setup.mainnet_deny {
            policy.network.mainnet = "deny".to_string();
        }
        let (natural, meta) = bash::decide(command, &ctx, &policy);
        headless::apply(relax::apply(natural, &meta, &policy, &dir), setup.headless)
    })
}

/// The emitted label: `allow`, `ask`, `deny`, or `""` for no opinion.
fn label(d: &Decision) -> &'static str {
    match d {
        Decision::Defer => "",
        other => other.label(),
    }
}

fn lib(command: &str, setup: Setup) -> &'static str {
    label(&run_lib(command, setup))
}

/// The labels across Off / Relaxed / Medium / High.
fn x4(command: &str, setup: impl Fn(Tier) -> Setup) -> [&'static str; 4] {
    ALL_TIERS.map(|t| lib(command, setup(t)))
}

// ---------------------------------------------------------------------------------------
// Class U
// ---------------------------------------------------------------------------------------

/// The brief's Class U commands with `{c}` where the cluster argument goes.
fn class_u_templates() -> Vec<String> {
    vec![
        "solana program deploy --final x.so {c}".into(),
        "anchor deploy {c} -- --final".into(),
        "anchor program deploy --final {c}".into(),
        "solana program upgrade B P --final {c}".into(),
        "solana program set-upgrade-authority P --final {c}".into(),
        "solana program-v4 finalize P {c}".into(),
        "solana program close P --bypass-warning {c}".into(),
        "solana program close BUF {c}".into(),
        "solana program close --buffers {c}".into(),
        "solana program close BUF --bypass-warning {c}".into(),
        "anchor program close BUF {c}".into(),
        format!("spl-token authorize {M} mint --disable {{c}}"),
        format!("spl-token close-mint {M} {{c}}"),
        format!("spl-token close {D} {{c}}"),
        format!("spl-token burn {D} 1 {{c}}"),
        "anchor idl erase-authority -p P {c}".into(),
        "anchor idl close P {c}".into(),
        format!("solana close-vote-account V {D} {{c}}"),
    ]
}

/// Each template with its wrapped forms (`env FOO=1 …`, `bash -c '…'`, `timeout 5 …`).
fn with_wrappers(cmd: &str) -> [String; 4] {
    [
        cmd.to_string(),
        format!("env FOO=1 {cmd}"),
        format!("bash -c '{cmd}'"),
        format!("timeout 5 {cmd}"),
    ]
}

/// Every Class U command (wrapped forms included) with cluster argument `cluster`.
fn class_u(cluster: &str) -> Vec<String> {
    class_u_templates()
        .iter()
        .flat_map(|t| with_wrappers(t.replace("{c}", cluster).trim_end()))
        .collect()
}

#[test]
fn class_u_denies_on_mainnet_testnet_and_unknown_at_every_tier() {
    for cluster in [
        "-um",
        "-ut",
        "--url mainnet-beta",
        "-C missing.yml",
        "-u $URL",
        "",
    ] {
        for cmd in class_u(cluster) {
            let setups: [fn(Tier) -> Setup; 3] = [
                Setup::at,
                |t| Setup::at(t).grant(),
                |t| Setup::at(t).headless(),
            ];
            for setup in setups {
                assert_eq!(x4(&cmd, setup), ["deny"; 4], "{cmd}");
            }
        }
    }
}

#[test]
fn class_u_on_a_mainnet_or_testnet_cli_default_denies() {
    for default in [Network::Mainnet, Network::Testnet, Network::Unknown] {
        for cmd in class_u("") {
            let got = x4(&cmd, |t| Setup::at(t).default_net(default));
            assert_eq!(got, ["deny"; 4], "{cmd} on {default:?}");
        }
    }
}

#[test]
fn class_u_asks_on_identified_localnet_and_devnet_and_no_grant_relaxes_it() {
    for cluster in ["-ul", "-ud", "--url devnet", "--url http://127.0.0.1:8899"] {
        for cmd in class_u(cluster) {
            assert_eq!(x4(&cmd, Setup::at), ["ask"; 4], "{cmd}");
            assert_eq!(x4(&cmd, |t| Setup::at(t).grant()), ["ask"; 4], "{cmd}");
            assert_eq!(x4(&cmd, |t| Setup::at(t).headless()), ["deny"; 4], "{cmd}");
        }
    }
    for default in [Network::Devnet, Network::Localnet] {
        for cmd in class_u("") {
            let got = x4(&cmd, |t| Setup::at(t).default_net(default).grant());
            assert_eq!(got, ["ask"; 4], "{cmd} on {default:?}");
        }
    }
}

#[test]
fn class_u_is_judged_on_the_cluster_the_command_names() {
    // A devnet default does not vouch for a command naming mainnet, nor a mainnet default
    // stop a devnet one from asking.
    let cmd = "solana program deploy --final x.so";
    assert_eq!(
        lib(
            &format!("{cmd} -um"),
            Setup::at(Tier::Relaxed).default_net(Network::Devnet)
        ),
        "deny"
    );
    assert_eq!(
        lib(
            &format!("{cmd} -ud"),
            Setup::at(Tier::Relaxed).default_net(Network::Mainnet)
        ),
        "ask"
    );
    // A flag value that reads as `-ud` (the memo's) names no cluster: unknown, deny.
    assert_eq!(
        lib(
            &format!("spl-token burn {D} 1 --with-memo -ud"),
            Setup::at(Tier::Relaxed).default_net(Network::Devnet)
        ),
        "deny"
    );
}

#[test]
fn class_u_deny_reasons_echo_the_command_and_the_cluster_source() {
    let cases = [
        ("solana program deploy --final x.so -um", "-um"),
        ("spl-token close-mint M -C missing.yml", "missing.yml"),
        ("anchor idl close P -u $URL", "$URL"),
    ];
    for (cmd, source) in cases {
        let d = run_lib(cmd, Setup::at(Tier::Relaxed));
        assert!(matches!(d, Decision::Deny { .. }), "{cmd}: {d:?}");
        let reason = d.reason();
        assert!(reason.contains(cmd), "{cmd}: {reason}");
        assert!(reason.contains(source), "{cmd}: {reason}");
        assert!(reason.contains("yourself"), "{cmd}: {reason}");
    }
    // No flag: the CLI default, not identified.
    let d = run_lib("spl-token close A", Setup::at(Tier::Relaxed));
    assert!(d.reason().contains("CLI config"), "{d:?}");
    assert!(d.reason().contains("unidentified"), "{d:?}");
    // Testnet is named as such.
    let d = run_lib("spl-token close A -ut", Setup::at(Tier::Relaxed));
    assert!(d.reason().contains("testnet"), "{d:?}");
}

#[test]
fn class_u_through_an_expansion_program_is_still_class_u() {
    // `$S` may be `solana`: an irreversible shape behind it is judged as one.
    for cmd in [
        "$S program deploy --final x.so -um",
        "S=solana; $S program close P --bypass-warning",
        "$T close-mint M -ut",
    ] {
        assert_eq!(x4(cmd, Setup::at), ["deny"; 4], "{cmd}");
    }
    // On devnet it asks like any Class U command, and an expansion program denies at High.
    assert_eq!(
        x4("$S program-v4 finalize P -ud", Setup::at),
        ["ask", "ask", "ask", "deny"]
    );
}

#[test]
fn class_u_path_qualified_and_ansi_c_quoted_programs() {
    for cmd in [
        "/usr/local/bin/solana program deploy --final x.so -um",
        "$'solana' program close P --bypass-warning -um",
        "$'\\x73pl-token' burn A 1 -um",
        "sudo spl-token close A -um",
        "nohup anchor idl close P --provider.cluster mainnet &",
    ] {
        assert_eq!(x4(cmd, Setup::at), ["deny"; 4], "{cmd}");
    }
}

#[test]
fn class_u_covers_extra_list_shapes() {
    for cmd in [
        "solana program write-buffer x.so --final -um".to_string(),
        "solana program-v4 deploy x.so --final -um".to_string(),
        "anchor program upgrade P --final --provider.cluster mainnet".to_string(),
        "anchor program set-upgrade-authority P --final --provider.cluster mainnet".to_string(),
        "anchor program write-buffer --final --provider.cluster mainnet".to_string(),
        format!("spl-token authorize {M} freeze --disable -um"),
    ] {
        assert_eq!(x4(&cmd, Setup::at), ["deny"; 4], "{cmd}");
    }
}

// ---------------------------------------------------------------------------------------
// Class C
// ---------------------------------------------------------------------------------------

fn class_c_value_rows(cluster: &str) -> Vec<String> {
    vec![
        format!("solana transfer {D} 0.5 {cluster}"),
        format!("spl-token transfer {M} 1 {D} {cluster}"),
        format!("solana program deploy x.so {cluster}"),
    ]
}

#[test]
fn class_c_on_mainnet_or_unknown_asks_below_high_and_denies_at_high() {
    for cluster in ["-um", "-C missing.yml", "-u $URL", ""] {
        for cmd in class_c_value_rows(cluster) {
            let cmd = cmd.trim_end();
            assert_eq!(x4(cmd, Setup::at), ["ask", "ask", "ask", "deny"], "{cmd}");
            // `$URL` may split into more words: a transfer's amount is then unclear, which no
            // grant can budget.
            let granted = if cluster.contains('$') && cmd.contains("transfer") {
                ["ask", "ask", "ask", "deny"]
            } else {
                ["allow", "allow", "allow", "deny"]
            };
            assert_eq!(
                x4(cmd, |t| Setup::at(t).grant()),
                granted,
                "{cmd} with a grant"
            );
            assert_eq!(x4(cmd, |t| Setup::at(t).headless()), ["deny"; 4], "{cmd}");
            let headless_granted = granted.map(|l| if l == "ask" { "deny" } else { l });
            assert_eq!(
                x4(cmd, |t| Setup::at(t).grant().headless()),
                headless_granted,
                "{cmd} with a grant, headless"
            );
        }
    }
}

#[test]
fn network_mainnet_deny_denies_class_c_at_every_tier() {
    for cmd in class_c_value_rows("-um") {
        assert_eq!(
            x4(&cmd, |t| Setup::at(t).mainnet_deny()),
            ["deny"; 4],
            "{cmd}"
        );
        assert_eq!(
            x4(&cmd, |t| Setup::at(t).mainnet_deny().grant()),
            ["deny"; 4],
            "{cmd}"
        );
    }
}

#[test]
fn class_c_high_deny_reason_names_the_tier_and_the_cluster() {
    let d = run_lib(
        &format!("solana transfer {D} 0.5 -um"),
        Setup::at(Tier::High),
    );
    let reason = d.reason();
    assert!(matches!(d, Decision::Deny { .. }), "{d:?}");
    assert!(
        reason.contains("high") && reason.contains("mainnet"),
        "{reason}"
    );
}

#[test]
fn devnet_transfer_within_cap_allows_below_high_only() {
    assert_eq!(
        x4(&format!("solana transfer {D} 0.5 -ud"), Setup::at),
        ["allow", "allow", "allow", ""]
    );
}

#[test]
fn localnet_deploy_has_no_opinion() {
    assert_eq!(
        x4("solana program deploy x.so -ul", Setup::at),
        ["", "", "", ""]
    );
    assert_eq!(
        x4("anchor deploy --provider.cluster localnet", Setup::at),
        ["", "", "", ""]
    );
}

#[test]
fn authority_changes_ask_on_devnet_and_deny_on_mainnet_at_high() {
    let rows = [
        format!("solana program set-upgrade-authority P --new-upgrade-authority {Q}"),
        format!("spl-token authorize {D} owner {Q}"),
    ];
    for row in &rows {
        let dev = format!("{row} -ud");
        assert_eq!(x4(&dev, Setup::at), ["ask"; 4], "{dev}");
        // A hard guard: no grant relaxes it.
        assert_eq!(x4(&dev, |t| Setup::at(t).grant()), ["ask"; 4], "{dev}");
        let main = format!("{row} -um");
        assert_eq!(
            x4(&main, Setup::at),
            ["ask", "ask", "ask", "deny"],
            "{main}"
        );
        assert_eq!(
            x4(&main, |t| Setup::at(t).grant()),
            ["ask", "ask", "ask", "deny"],
            "{main}"
        );
    }
}

#[test]
fn dynamic_program_asks_below_high_and_denies_at_high() {
    assert_eq!(
        x4(&format!("$S transfer {D} 1"), Setup::at),
        ["ask", "ask", "ask", "deny"]
    );
    assert_eq!(
        x4("$S transfer D 1", Setup::at),
        ["ask", "ask", "ask", "deny"]
    );
}

#[test]
fn read_only_commands_have_no_opinion() {
    assert_eq!(x4("solana balance -um", Setup::at), ["", "", "", ""]);
}

// ---------------------------------------------------------------------------------------
// Binary rows
// ---------------------------------------------------------------------------------------

/// A hermetic world: fake home, project, data dir, an empty `PATH` dir.
struct World {
    home: TempDir,
    proj: TempDir,
    data: TempDir,
    path: TempDir,
}

impl World {
    fn new(tag: &str) -> World {
        World {
            home: TempDir::new(&format!("{tag}-home")),
            proj: TempDir::new(&format!("{tag}-proj")),
            data: TempDir::new(&format!("{tag}-data")),
            path: TempDir::new(&format!("{tag}-path")),
        }
    }

    /// Put a stub `solana` on `PATH` printing `RPC URL: <url>` for `config get`.
    fn cli_config(&self, url: &str) {
        let stub = self.path.join("solana");
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
    }

    fn wallet(&self) -> std::path::PathBuf {
        self.home.join(".config/solana/id.json")
    }

    fn invocation<'a>(&'a self, sub: &str, payload: serde_json::Value) -> Invocation<'a> {
        let path = if self.path.join("solana").exists() {
            format!("{}:/usr/bin:/bin", self.path.path().display())
        } else {
            self.path.path().display().to_string()
        };
        Invocation::new(&[sub])
            .plugin_data(self.data.path())
            .home(self.home.path())
            .cwd(self.proj.path())
            .env("PATH", &path)
            .stdin(payload.to_string())
    }

    fn bash_payload(&self, command: &str) -> serde_json::Value {
        json!({"session_id":"it-onchain","hook_event_name":"PreToolUse","tool_name":"Bash",
               "cwd": self.proj.path(), "tool_input":{"command": command}})
    }

    fn run(&self, sub: &str, command: &str, tier: Tier, extra: &[(&str, &str)]) -> Run {
        let mut inv = self.invocation(sub, self.bash_payload(command));
        // Always the user's choice: with `test-hooks` that also trusts the data dir (grants).
        inv = inv.tier(tier);
        for (k, v) in extra {
            inv = inv.env(k, v);
        }
        inv.run()
    }

    /// The decision both Bash hooks together produce (Claude Code takes the strictest); both
    /// run for every Bash call (`hooks.json`, pinned by `hooks_json_runs_gate_bash_for_every_bash_call`).
    fn bash(&self, command: &str, tier: Tier) -> String {
        self.bash_env(command, tier, &[])
    }

    fn bash_env(&self, command: &str, tier: Tier, extra: &[(&str, &str)]) -> String {
        // Either order works: an audit log written before any state file no longer counts
        // today's budget as spent (spend.rs; pinned in tiers_matrix.rs).
        let labels = [
            decision_label(&self.run("gate-bash", command, tier, extra)),
            decision_label(&self.run("gate-bash-secrets", command, tier, extra)),
        ];
        strictest(&labels)
    }

    fn reason(&self, sub: &str, command: &str) -> String {
        let run = self.run(sub, command, Tier::Relaxed, &[]);
        run.json()["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap_or("")
            .to_string()
    }

    fn write(&self, tool: &str, path: &Path, tier: Tier) -> String {
        let key = if tool == "NotebookEdit" {
            "notebook_path"
        } else {
            "file_path"
        };
        let payload = json!({"session_id":"it-onchain","hook_event_name":"PreToolUse",
            "tool_name": tool, "cwd": self.proj.path(),
            "tool_input": {key: path, "content": "[1,2,3]", "old_string": "a", "new_string": "b"}});
        let mut inv = self.invocation("gate-tamper", payload);
        // Always the user's choice: with `test-hooks` that also trusts the data dir (grants).
        inv = inv.tier(tier);
        decision_label(&inv.run())
    }
}

fn strictest(labels: &[String]) -> String {
    let rank = |l: &str| match l {
        "deny" => 3,
        "ask" => 2,
        "allow" => 1,
        _ => 0,
    };
    labels
        .iter()
        .max_by_key(|l| rank(l))
        .cloned()
        .unwrap_or_default()
}

/// The tiers reachable through the binary: Off needs a trusted data dir (`test-hooks`).
fn binary_tiers() -> Vec<Tier> {
    if common::TEST_HOOKS {
        ALL_TIERS.to_vec()
    } else {
        vec![Tier::Relaxed, Tier::Medium, Tier::High]
    }
}

#[test]
fn e2e_class_u_wrapped_forms_deny_on_mainnet_testnet_and_unknown() {
    let w = World::new("onchain-u");
    for cluster in ["-um", "-ut", "-C missing.yml", ""] {
        for cmd in class_u(cluster) {
            assert_eq!(w.bash(&cmd, Tier::Relaxed), "deny", "{cmd}");
        }
    }
    for tier in binary_tiers() {
        assert_eq!(
            w.bash("bash -c 'spl-token burn A 1 -um'", tier),
            "deny",
            "{tier:?}"
        );
    }
}

#[test]
fn e2e_class_u_asks_on_devnet_and_denies_headless() {
    let w = World::new("onchain-u-dev");
    for cmd in class_u("-ud") {
        assert_eq!(w.bash(&cmd, Tier::Relaxed), "ask", "{cmd}");
    }
    for tier in binary_tiers() {
        assert_eq!(
            w.bash("timeout 5 spl-token close A -ul", tier),
            "ask",
            "{tier:?}"
        );
    }
    assert_eq!(
        w.bash_env(
            "env FOO=1 spl-token close A -ud",
            Tier::Relaxed,
            &[("SAFE_AI_SKILL_HEADLESS", "1")]
        ),
        "deny"
    );
}

#[test]
fn e2e_class_u_cluster_sources() {
    let w = World::new("onchain-u-src");
    // No `solana` on PATH: the CLI default is unknown.
    assert_eq!(w.bash("spl-token close-mint M", Tier::Relaxed), "deny");
    // CLI config devnet / localnet: ask; testnet / mainnet: deny.
    for (url, want) in [
        ("https://api.devnet.solana.com", "ask"),
        ("http://localhost:8899", "ask"),
        ("https://api.testnet.solana.com", "deny"),
        ("https://api.mainnet-beta.solana.com", "deny"),
        ("https://rpc.example.com", "deny"),
    ] {
        // A fresh data dir each: a trusted one caches the CLI's answer for 60 s.
        let fresh = World::new("onchain-u-cli");
        fresh.cli_config(url);
        assert_eq!(
            fresh.bash("spl-token close-mint M", Tier::Relaxed),
            want,
            "{url}"
        );
    }
    let reason = w.reason("gate-bash", "spl-token close-mint M");
    assert!(reason.contains("CLI config"), "{reason}");
    assert!(reason.contains("spl-token close-mint M"), "{reason}");
    // A `-C` file: its json_rpc_url; a missing one is unknown.
    std::fs::write(
        w.proj.join("dev.yml"),
        "json_rpc_url: https://api.devnet.solana.com\n",
    )
    .unwrap();
    assert_eq!(w.bash("spl-token close A -C dev.yml", Tier::Relaxed), "ask");
    assert_eq!(
        w.bash("spl-token close A -C missing.yml", Tier::Relaxed),
        "deny"
    );
    let reason = w.reason("gate-bash", "spl-token close A -C missing.yml");
    assert!(reason.contains("missing.yml"), "{reason}");
    // Anchor.toml devnet: ask; ANCHOR_PROVIDER_URL may only make it riskier.
    std::fs::write(
        w.proj.join("Anchor.toml"),
        "[provider]\ncluster = \"devnet\"\n",
    )
    .unwrap();
    assert_eq!(w.bash("anchor idl close P", Tier::Relaxed), "ask");
    assert_eq!(
        w.bash_env(
            "anchor idl close P",
            Tier::Relaxed,
            &[("ANCHOR_PROVIDER_URL", "https://api.mainnet-beta.solana.com")]
        ),
        "deny"
    );
    let reason = w.reason(
        "gate-bash",
        "anchor idl erase-authority -p P --provider.cluster m",
    );
    assert!(reason.contains("--provider.cluster"), "{reason}");
}

#[cfg(feature = "test-hooks")]
#[test]
fn e2e_class_u_on_devnet_is_never_granted() {
    let w = World::new("onchain-u-grant");
    grant_everything(&DataDir {
        path: w.data.path().to_path_buf(),
        trusted: true,
    });
    for tier in ALL_TIERS {
        for cmd in [
            "solana program close P --bypass-warning -ud",
            "spl-token burn A 1 -ul",
        ] {
            assert_eq!(w.bash(cmd, tier), "ask", "{cmd} {tier:?}");
        }
        // A covered Class C mainnet transfer is allowed below High.
        let want = if tier == Tier::High { "deny" } else { "allow" };
        assert_eq!(
            w.bash(&format!("solana transfer {D} 0.5 -um"), tier),
            want,
            "{tier:?}"
        );
    }
}

#[test]
fn e2e_class_c_tiers() {
    let w = World::new("onchain-c");
    for tier in binary_tiers() {
        let high = tier == Tier::High;
        let want = if high { "deny" } else { "ask" };
        for cmd in class_c_value_rows("-um") {
            assert_eq!(w.bash(&cmd, tier), want, "{cmd} {tier:?}");
        }
        assert_eq!(
            w.bash(&format!("$S transfer {D} 1"), tier),
            want,
            "{tier:?}"
        );
        let within = if high { "" } else { "allow" };
        let fresh = World::new("onchain-c-within");
        assert_eq!(
            fresh.bash(&format!("solana transfer {D} 0.5 -ud"), tier),
            within,
            "{tier:?}"
        );
        assert_eq!(w.bash("solana program deploy x.so -ul", tier), "");
        assert_eq!(w.bash("solana balance -um", tier), "");
    }
}

// ---------------------------------------------------------------------------------------
// Default-wallet destruction (cluster-independent, deny ×4)
// ---------------------------------------------------------------------------------------

#[test]
fn e2e_wallet_destruction_denies_at_every_tier() {
    let w = World::new("onchain-wallet");
    std::fs::create_dir_all(w.home.join(".config/solana")).unwrap();
    let cases = [
        "solana-keygen new --force",
        "solana-keygen new -f --no-bip39-passphrase",
        "solana-keygen recover -f",
        "solana-keygen recover 'prompt:?key=0/0' --force",
        "solana-keygen new -o ~/.config/solana/id.json --force",
        "solana-keygen new --outfile=$HOME/.config/solana/id.json -f",
        "bash -c 'solana-keygen new -f'",
        "env FOO=1 /usr/local/bin/solana-keygen new --force",
        "cp k.json ~/.config/solana/id.json",
        "cp id.json ~/.config/solana/",
        "mv ~/.config/solana/id.json /tmp/x",
        "rm ~/.config/solana/id.json",
        "rm -f \"$HOME/.config/solana/id.json\"",
        "echo [] > ~/.config/solana/id.json",
        "cat k.json | tee ~/.config/solana/id.json",
        "dd if=k.json of=~/.config/solana/id.json",
        "truncate -s 0 ~/.config/solana/id.json",
    ];
    for tier in binary_tiers() {
        for cmd in cases {
            assert_eq!(w.bash(cmd, tier), "deny", "{cmd} {tier:?}");
        }
        let abs = format!("rm {}", w.wallet().display());
        assert_eq!(w.bash(&abs, tier), "deny", "{abs}");
    }
    // Cluster flags change nothing.
    assert_eq!(
        w.bash("solana-keygen new --force -ud", Tier::Relaxed),
        "deny"
    );
    // Headless: still deny.
    assert_eq!(
        w.bash_env("rm ~/.config/solana/id.json", Tier::Relaxed, &[("CI", "1")]),
        "deny"
    );
    let reason = w.reason("gate-bash-secrets", "solana-keygen new --force");
    assert!(reason.contains("solana-keygen new --force"), "{reason}");
}

#[test]
fn e2e_wallet_writes_deny_at_every_tier() {
    let w = World::new("onchain-wallet-write");
    let cli = w.home.join(".config/solana/cli");
    std::fs::create_dir_all(&cli).unwrap();
    let custom = w.home.join("keys/main.json");
    std::fs::write(
        cli.join("config.yml"),
        format!(
            "json_rpc_url: https://api.devnet.solana.com\nkeypair_path: {}\n",
            custom.display()
        ),
    )
    .unwrap();
    for tier in binary_tiers() {
        for tool in ["Write", "Edit", "MultiEdit", "NotebookEdit"] {
            assert_eq!(w.write(tool, &w.wallet(), tier), "deny", "{tool} {tier:?}");
            assert_eq!(
                w.write(tool, &custom, tier),
                "deny",
                "{tool} custom {tier:?}"
            );
        }
        assert_eq!(w.bash(&format!("rm {}", custom.display()), tier), "deny");
        assert_eq!(
            w.bash(
                &format!("solana-keygen new -o {} --force", custom.display()),
                tier
            ),
            "deny"
        );
    }
    // A project keypair is the user's to manage.
    assert_eq!(
        w.write(
            "Write",
            &w.proj.join("target/deploy/p-keypair.json"),
            Tier::Relaxed
        ),
        ""
    );
}

#[test]
fn e2e_keygen_rows_with_no_opinion() {
    let w = World::new("onchain-keygen-no");
    for tier in binary_tiers() {
        for cmd in [
            "solana-keygen new -o target/deploy/p-keypair.json --force",
            "solana-keygen pubkey",
            "solana-keygen new --no-bip39-passphrase -o k.json",
            "solana-keygen new",
            "rm target/deploy/id.json",
        ] {
            assert_eq!(w.bash(cmd, tier), "", "{cmd} {tier:?}");
        }
    }
}

// ---------------------------------------------------------------------------------------
// Wiring: gate-bash runs for every Bash call
// ---------------------------------------------------------------------------------------

/// The PreToolUse `Bash` entries of the plugin's `hooks.json`: `(subcommand, if, onFailure)`.
fn bash_entries() -> Vec<(String, Option<String>, String)> {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../plugins/safe-ai-skill/hooks/hooks.json");
    let cfg: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    cfg["hooks"]["PreToolUse"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|g| g["matcher"] == "Bash")
        .flat_map(|g| g["hooks"].as_array().unwrap().clone())
        .map(|h| {
            let cmd = h["command"].as_str().unwrap();
            (
                cmd.rsplit(' ').next().unwrap().to_string(),
                h["if"].as_str().map(str::to_string),
                h["onFailure"].as_str().unwrap_or("").to_string(),
            )
        })
        .collect()
}

#[test]
fn hooks_json_runs_gate_bash_for_every_bash_call() {
    let entries = bash_entries();
    let gate_bash: Vec<_> = entries
        .iter()
        .filter(|(s, _, _)| s == "gate-bash")
        .collect();
    assert_eq!(gate_bash.len(), 1, "{entries:?}");
    let (_, filter, on_failure) = gate_bash[0];
    assert_eq!(
        filter, &None,
        "an `if` filter misses wrapped and keygen commands"
    );
    assert_eq!(on_failure, "block");
    // So wrapped, path-qualified, expansion and solana-keygen rows reach gate-bash itself.
    let w = World::new("onchain-wiring");
    for (cmd, want) in [
        ("env FOO=1 solana program deploy --final x.so -um", "deny"),
        ("bash -c 'spl-token close A -um'", "deny"),
        (
            "timeout 5 anchor idl close P --provider.cluster mainnet",
            "deny",
        ),
        (
            "/usr/local/bin/solana program close P --bypass-warning -um",
            "deny",
        ),
        ("$S transfer D 1", "ask"),
        ("solana-keygen new --force", "deny"),
        ("rm ~/.config/solana/id.json", "deny"),
    ] {
        let run = w.run("gate-bash", cmd, Tier::Relaxed, &[]);
        assert_eq!(decision_label(&run), want, "{cmd}");
    }
    // A wrapped within-cap devnet transfer is not allowed by the hook (only direct ones).
    let fresh = World::new("onchain-wiring-xfer");
    let run = fresh.run(
        "gate-bash",
        &format!("env FOO=1 solana transfer {D} 0.5 -ud"),
        Tier::Relaxed,
        &[],
    );
    assert_eq!(decision_label(&run), "");
}

#[test]
fn gate_bash_fast_path_is_silent_and_touches_nothing() {
    let w = World::new("onchain-fast");
    for cmd in [
        "ls -la",
        "cargo build --release",
        "git status && npm test",
        "make test",
    ] {
        let run = w.invocation("gate-bash", w.bash_payload(cmd)).run();
        assert_eq!(decision_label(&run), "", "{cmd}");
        assert!(run.stdout.is_empty() && run.stderr.is_empty(), "{cmd}");
    }
    // No policy, state or audit was loaded or written.
    assert_eq!(std::fs::read_dir(w.data.path()).unwrap().count(), 0);
}

#[test]
fn fast_path_lets_every_solana_shape_through() {
    for cmd in [
        "solana balance",
        "s\\olana transfer D 1",
        "sol''ana transfer D 1",
        "$'\\x73olana' transfer D 1",
        "$(echo sol)ana transfer D 1",
        "$S transfer D 1",
        "X=/opt/bin/SPL-TOKEN; $X close A",
        "python3 -c 'import os; os.system(\"anchor deploy\")'",
        "/usr/bin/solana-keygen new -f",
        "echo \"unterminated",
    ] {
        assert!(bash::may_concern(cmd), "{cmd}");
    }
    for cmd in ["ls -la", "cargo test", "make test", "git push origin main"] {
        assert!(!bash::may_concern(cmd), "{cmd}");
    }
}

// ---------------------------------------------------------------------------------------
// Fix round 1 (review F3): compounds, in-line cluster changes, unresolved programs, wallet
// directories and globs, fast path, work cap.
// ---------------------------------------------------------------------------------------

#[test]
fn a_grant_never_lifts_a_compound_holding_class_u_or_a_hard_guard() {
    let rows = [
        format!("solana transfer {D} 0.5 -um && spl-token burn A 1 -ud"),
        format!("solana transfer {D} 0.5 -um && solana program close P --bypass-warning -ul"),
        "solana program deploy x.so -um && anchor idl close P --provider.cluster devnet".to_string(),
        "solana program deploy x.so -um; solana program close BUF -ud".to_string(),
        format!(
            "solana transfer {D} 0.5 -um && solana program set-upgrade-authority P --new-upgrade-authority {Q} -um"
        ),
        format!("solana transfer {D} 0.5 -um && spl-token authorize {D} owner {Q} -ud"),
        // Two grantable actions: one grant covers one action.
        format!("solana transfer {D} 0.5 -um && solana transfer {D} 0.6 -um"),
    ];
    for cmd in &rows {
        let at = |t| Setup::at(t).default_net(Network::Devnet);
        assert_eq!(x4(cmd, at), ["ask", "ask", "ask", "deny"], "{cmd}");
        assert_eq!(
            x4(cmd, |t| at(t).grant()),
            ["ask", "ask", "ask", "deny"],
            "{cmd} grant"
        );
        assert_eq!(
            x4(cmd, |t| at(t).grant().headless()),
            ["deny"; 4],
            "{cmd} headless"
        );
    }
    // The order does not matter.
    let reversed = format!("spl-token burn A 1 -ud && solana transfer {D} 0.5 -um");
    assert_eq!(
        x4(&reversed, |t| Setup::at(t).grant()),
        ["ask", "ask", "ask", "deny"]
    );
    // Two within-cap devnet transfers are not one allow.
    let two = format!("solana transfer {D} 0.5 -ud && solana transfer {D} 0.5 -ud");
    assert_eq!(x4(&two, Setup::at)[1], "ask");
    // A single grantable action is still lifted by its grant.
    assert_eq!(
        x4(
            &format!("solana transfer {D} 0.5 -um && solana balance"),
            |t| Setup::at(t).grant()
        ),
        ["allow", "allow", "allow", "deny"]
    );
}

#[test]
fn a_cluster_change_earlier_in_the_line_moves_later_commands() {
    let dev = |t| Setup::at(t).default_net(Network::Devnet);
    for cmd in [
        "solana config set --url mainnet-beta && solana program close P --bypass-warning",
        "solana config set -um; spl-token burn A 1",
        "solana config set --url $RPC && spl-token close A",
        "cp main.yml ~/.config/solana/cli/config.yml && spl-token burn A 1",
        "echo 'json_rpc_url: https://api.mainnet-beta.solana.com' > ~/.config/solana/cli/config.yml; spl-token burn A 1",
        "sed -i s/devnet/mainnet-beta/ ~/.config/solana/cli/config.yml && anchor idl close P",
        "export ANCHOR_PROVIDER_URL=https://api.mainnet-beta.solana.com; anchor idl close P",
        "ANCHOR_PROVIDER_URL=https://api.mainnet-beta.solana.com anchor idl close P",
    ] {
        assert_eq!(x4(cmd, dev), ["deny"; 4], "{cmd}");
    }
    let d = run_lib(
        "solana config set -um && spl-token close-mint M",
        dev(Tier::Relaxed),
    );
    assert!(d.reason().contains("solana config set"), "{d:?}");
    // At High a Class C action after a mainnet config set denies.
    assert_eq!(
        lib(
            &format!("solana config set -um && solana transfer {D} 5"),
            dev(Tier::High)
        ),
        "deny"
    );
    assert_eq!(
        lib(
            "solana config set -um && solana program deploy x.so",
            dev(Tier::High)
        ),
        "deny"
    );
    // A change to devnet is the new value; an explicit flag still wins.
    let main = |t| Setup::at(t).default_net(Network::Mainnet);
    assert_eq!(
        x4("solana config set -ud && spl-token burn A 1", main),
        ["ask"; 4]
    );
    assert_eq!(
        x4("solana config set -ud && spl-token burn A 1 -um", main),
        ["deny"; 4]
    );
}

#[test]
fn unresolved_programs_get_the_full_gate() {
    for cmd in [
        "/usr/local/bin/sol*a program close P --bypass-warning -um",
        "/opt/bin/s[o]lana program close P --bypass-warning -um",
        "~/.local/share/solana/install/active_release/bin/sol?na program close P --bypass-warning -um",
        "printf 'so%sna' la | xargs -I@ @ program close P --bypass-warning -um",
        "printf solana | xargs -I {} {} program-v4 finalize P -um",
    ] {
        assert_eq!(x4(cmd, Setup::at), ["deny"; 4], "{cmd}");
        assert!(bash::may_concern(cmd), "{cmd}");
    }
    assert_eq!(
        x4(&format!("/opt/bin/s[o]lana transfer {D} 1"), Setup::at),
        ["ask", "ask", "ask", "deny"]
    );
    assert_eq!(
        x4("printf x | xargs -I@ @ --version", Setup::at),
        ["ask", "ask", "ask", "deny"]
    );
    // A glob naming no family program, as an argument or a program, has no opinion.
    assert_eq!(x4("ls /tmp/*.log", Setup::at), ["", "", "", ""]);
    assert_eq!(x4("./build/run-*.sh --fast", Setup::at), ["", "", "", ""]);
}

#[test]
fn class_c_high_reason_does_not_ask() {
    let d = run_lib(
        &format!("solana transfer {D} 0.5 -um"),
        Setup::at(Tier::High),
    );
    assert!(!d.reason().contains("approve to proceed"), "{d:?}");
}

#[test]
fn fast_path_follows_line_continuations() {
    for cmd in [
        "sol\\\nana program close P --bypass-warning -um",
        "spl-\\\ntoken burn A 1 -um",
        "\"sol\\\nana\" program close P --bypass-warning -um",
    ] {
        assert!(bash::may_concern(cmd), "{cmd:?}");
        assert_eq!(x4(cmd, Setup::at), ["deny"; 4], "{cmd:?}");
    }
    let w = World::new("onchain-continuation");
    let run = w.run(
        "gate-bash",
        "sol\\\nana program close P --bypass-warning -um",
        Tier::Relaxed,
        &[],
    );
    assert_eq!(decision_label(&run), "deny");
}

#[test]
fn oversized_or_deeply_nested_commands_ask_without_parsing() {
    let big = format!("echo solana {}", "a".repeat(bash::MAX_PARSE_BYTES));
    let nested = format!("echo {}x{}", "$(".repeat(3000), ")".repeat(3000));
    for cmd in [&big, &nested] {
        assert!(bash::over_work_cap(cmd));
        assert!(bash::may_concern(cmd));
        assert_eq!(x4(cmd, Setup::at), ["ask", "ask", "ask", "deny"]);
        assert_eq!(
            x4(cmd, |t| Setup::at(t).grant()),
            ["ask", "ask", "ask", "deny"]
        );
    }
    let w = World::new("onchain-cap");
    let started = std::time::Instant::now();
    let run = w.run("gate-bash", &nested, Tier::Relaxed, &[]);
    assert_eq!(decision_label(&run), "ask");
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    assert!(!bash::over_work_cap("echo $(date) ${HOME} `id`"));
}

#[test]
fn e2e_wallet_directories_globs_and_cd() {
    let w = World::new("onchain-wallet-dirs");
    let cli = w.home.join(".config/solana/cli");
    std::fs::create_dir_all(&cli).unwrap();
    let custom = w.home.join("keys/main-wallet.json");
    std::fs::write(
        cli.join("config.yml"),
        format!("keypair_path: {}\n", custom.display()),
    )
    .unwrap();
    let deny = [
        "rm -rf ~/.config/solana".to_string(),
        "rm -rf ~/.config".to_string(),
        "rm -rf ~".to_string(),
        "cd ~/.config && rm -r solana".to_string(),
        "cd ~ && rm -rf .config/solana/".to_string(),
        "rm ~/.config/solana/*.json".to_string(),
        "rm ~/.config/solana/id.*".to_string(),
        "rm ~/.config/s*/id.json".to_string(),
        "rm -rf ~/.config/s*".to_string(),
        "mv ~/.config/solana /tmp/old-solana".to_string(),
        "cd ~/.config/solana && solana-keygen new -o id.json --force".to_string(),
        "cd ~/.config/solana; solana-keygen new --force --outfile ./id.json".to_string(),
        "cd $SOMEWHERE && rm -rf solana".to_string(),
        "(cd ~/.config/solana && rm id.json)".to_string(),
        format!("rm -rf {}", w.home.join("keys").display()),
        format!("rm {}", custom.display()),
        "echo x >& ~/.config/solana/id.json".to_string(),
    ];
    for cmd in &deny {
        assert_eq!(w.bash(cmd, Tier::Relaxed), "deny", "{cmd}");
        // gate-bash alone (the blocking entry) denies too.
        let run = w.run("gate-bash", cmd, Tier::Relaxed, &[]);
        assert_eq!(decision_label(&run), "deny", "gate-bash: {cmd}");
    }
    for cmd in [
        "solana-keygen new --no-outfile --force",
        "rm -rf ~/.config/other",
        "rm -rf build",
        "mv build/x /tmp",
        "cd /tmp && rm id.json",
    ] {
        assert_eq!(w.bash(cmd, Tier::Relaxed), "", "{cmd}");
    }
    // Not the wallet, so gate-bash has no opinion; but `~/.config/solana/` is a credential
    // store (credentials.list), so gate-bash-secrets denies and the strictest verdict wins.
    let cmd = "rm ~/.config/solana/cli/*.bak";
    assert_eq!(
        decision_label(&w.run("gate-bash", cmd, Tier::Relaxed, &[])),
        "",
        "{cmd}"
    );
    assert_eq!(w.bash(cmd, Tier::Relaxed), "deny", "{cmd}");
}

// ---------------------------------------------------------------------------------------
// Fix round 2 (re-review 1): dynamic eval / -c scripts, find -exec {}, config writes after
// cd, joined reasons, unreadable High reason, size cap only when not ruled out.
// ---------------------------------------------------------------------------------------

#[test]
fn dynamic_eval_and_shell_c_scripts_are_judged_like_the_unwrapped_form() {
    for cmd in [
        r#"eval "$S program close P --bypass-warning -um""#,
        r#"eval "$(printf so)lana program close P --bypass-warning -um""#,
        "eval $(echo c29sYW5h | base64 -d) program close P --bypass-warning -um",
        r#"bash -c "$(printf 'so%sna' la) program close P --bypass-warning -um""#,
        r#"sh -lc "$T burn A 1 -ut""#,
        r#"eval "$S program close P --bypass-warning""#,
    ] {
        assert!(bash::may_concern(cmd), "{cmd}");
        assert_eq!(x4(cmd, Setup::at), ["deny"; 4], "{cmd}");
        assert_eq!(
            x4(cmd, |t| Setup::at(t).grant().headless()),
            ["deny"; 4],
            "{cmd}"
        );
    }
    // On devnet: the expansion's ask, denied at High.
    assert_eq!(
        x4(
            r#"eval "$S program close P --bypass-warning -ud""#,
            Setup::at
        ),
        ["ask", "ask", "ask", "deny"]
    );
    // A dynamic script with nothing solana-shaped keeps no opinion.
    assert_eq!(x4(r#"eval "$CMD --help""#, Setup::at), ["", "", "", ""]);
}

#[test]
fn find_exec_of_the_found_file_is_an_unresolved_program() {
    for cmd in [
        r"find /usr/local/bin -name 'sol*a' -exec {} program close P --bypass-warning -um \;",
        "find / -name spl-token -execdir {} burn A 1 -um +",
    ] {
        assert!(bash::may_concern(cmd), "{cmd}");
        assert_eq!(x4(cmd, Setup::at), ["deny"; 4], "{cmd}");
    }
    assert_eq!(
        x4(r"find . -name 'x*' -exec {} --version \;", Setup::at),
        ["ask", "ask", "ask", "deny"]
    );
    assert_eq!(
        x4(r"find . -name '*.tmp' -exec rm {} \;", Setup::at),
        ["", "", "", ""]
    );
}

#[test]
fn a_config_write_after_cd_makes_later_commands_unknown() {
    let dev = |t| Setup::at(t).default_net(Network::Devnet);
    for cmd in [
        "cd ~/.config/solana/cli && cp ~/main.yml config.yml && spl-token burn A 1",
        "cd ~/.config/solana/cli; echo 'json_rpc_url: x' > config.yml; spl-token close A",
        "cd $D && cp ~/main.yml config.yml && spl-token burn A 1",
    ] {
        assert_eq!(x4(cmd, dev), ["deny"; 4], "{cmd}");
    }
    // A project config.yml elsewhere changes nothing.
    assert_eq!(
        x4("cd app && cp a.yml config.yml && spl-token burn A 1", dev),
        ["ask"; 4]
    );
}

#[test]
fn a_joined_ask_names_the_riskiest_component() {
    let d = run_lib(
        &format!("solana config set -um && solana transfer {D} 5"),
        Setup::at(Tier::Medium).default_net(Network::Devnet),
    );
    let reason = d.reason();
    assert!(matches!(d, Decision::Ask { .. }), "{d:?}");
    let riskiest = reason.split("also:").next().unwrap_or("");
    assert!(
        riskiest.contains("mainnet") && riskiest.contains("solana transfer"),
        "{reason}"
    );
    assert!(reason.contains("solana config set"), "{reason}");
    assert!(reason.ends_with("approve to proceed"), "{reason}");
}

#[test]
fn unreadable_high_reason_does_not_ask() {
    let d = run_lib("$S transfer D 1", Setup::at(Tier::High));
    assert!(matches!(d, Decision::Deny { .. }), "{d:?}");
    assert!(!d.reason().contains("approve to proceed"), "{d:?}");
}

#[test]
fn any_command_over_the_size_cap_asks_whatever_it_names() {
    let body = "x".repeat(bash::MAX_PARSE_BYTES);
    let pad = format!(" #{body}");
    let w = World::new("onchain-cap-pad");
    // A large here-doc is a false positive the size cap accepts.
    let heredoc = format!("cat > notes.txt <<'EOF'\n{body}\nEOF");
    // Padding must not switch off the parse-based routing (re-review 2, R7).
    let padded = [
        format!("/usr/local/bin/sol*a program close P --bypass-warning -um{pad}"),
        format!(
            r"find /usr/local/bin -name 'sol*a' -exec {{}} program close P --bypass-warning -um \;{pad}"
        ),
        format!(r#"eval "$S program close P --bypass-warning -um"{pad}"#),
        format!("x=sol; ${{x}}ana program close P --bypass-warning -um{pad}"),
        format!("rm -rf ~/.c*{pad}"),
        format!("spl-token burn A 1 -um{pad}"),
        heredoc,
    ];
    for cmd in &padded {
        let head: String = cmd.chars().take(60).collect();
        assert!(bash::over_work_cap(cmd), "{head}");
        assert!(bash::may_concern(cmd), "{head}");
        assert_eq!(x4(cmd, Setup::at), ["ask", "ask", "ask", "deny"], "{head}");
        assert_eq!(
            decision_label(&w.run("gate-bash", cmd, Tier::Relaxed, &[])),
            "ask",
            "{head}"
        );
        assert_eq!(
            decision_label(&w.run("gate-bash", cmd, Tier::High, &[])),
            "deny",
            "{head}"
        );
        assert_eq!(
            decision_label(&w.run("gate-bash", cmd, Tier::Relaxed, &[("CI", "1")])),
            "deny",
            "{head}"
        );
    }
    // `>` still routes a small command to the full gate.
    assert!(bash::may_concern("make 2>&1"));
}

#[test]
fn e2e_xargs_fed_wallet_paths_deny() {
    let w = World::new("onchain-wallet-xargs");
    for cmd in [
        "echo ~/.config/solana/id.json | xargs rm",
        "echo ~/.config/solana | xargs rm -rf",
        "printf '%s\\n' ~/.config/solana/id.json | xargs -I{} mv {} /tmp/",
        "echo k.json ~/.config/solana/id.json | xargs cp",
    ] {
        assert_eq!(w.bash(cmd, Tier::Relaxed), "deny", "{cmd}");
        assert_eq!(
            decision_label(&w.run("gate-bash", cmd, Tier::Relaxed, &[])),
            "deny",
            "gate-bash: {cmd}"
        );
    }
    for cmd in ["ls build | xargs rm -rf", "echo id.json | xargs cat"] {
        assert_eq!(w.bash(cmd, Tier::Relaxed), "", "{cmd}");
    }
}

#[test]
fn e2e_wallet_shapes_inside_dynamic_scripts() {
    let w = World::new("onchain-wallet-eval");
    for cmd in [
        r#"eval "rm $HOME/.config/solana/id.json""#,
        r#"bash -c "$X; solana-keygen new --force""#,
        r#"eval "rm -rf ~/.config/$WHAT""#,
    ] {
        assert_eq!(w.bash(cmd, Tier::Relaxed), "deny", "{cmd}");
        assert_eq!(
            decision_label(&w.run("gate-bash", cmd, Tier::Relaxed, &[])),
            "deny",
            "gate-bash: {cmd}"
        );
    }
}
