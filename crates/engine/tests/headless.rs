//! The headless rule (shared contract §3.3, D8 v2 spec §7) end to end: any signal turns it on,
//! nothing turns it off, every `ask` becomes a `deny`, env escapes are ignored, and only a grant
//! the user confirmed beforehand still passes (below High). No headless row emits `ask`.

mod common;

use common::{decision_label, Invocation, TempDir, Tier};
use safe_ai_skill::datadir::DataDir;
use safe_ai_skill::gate::{GateMeta, Scope};
use safe_ai_skill::grants::{self, Grant, Grants};
use safe_ai_skill::io::Decision;
use safe_ai_skill::policy::{Policy, DEFAULT_POLICY_YAML};
use safe_ai_skill::{headless, relax};
use serde_json::json;

const DEVNET_FINAL: &str = "solana program deploy x.so --final --url https://api.devnet.solana.com";
const MAINNET_DEPLOY: &str = "solana program deploy x.so --url mainnet-beta";

struct World {
    home: TempDir,
    proj: TempDir,
    data: TempDir,
}

impl World {
    fn new(tag: &str) -> World {
        World {
            home: TempDir::new(&format!("{tag}-home")),
            proj: TempDir::new(&format!("{tag}-proj")),
            data: TempDir::new(&format!("{tag}-data")),
        }
    }

    fn invocation<'a>(&'a self, no_tools: &'a TempDir, command: &str) -> Invocation<'a> {
        Invocation::new(&["gate-bash"])
            .plugin_data(self.data.path())
            .home(self.home.path())
            .cwd(self.proj.path())
            .env("PATH", no_tools.path().to_str().unwrap())
            .stdin(
                json!({"hook_event_name":"PreToolUse","tool_name":"Bash","cwd": self.proj.path(),
                       "tool_input":{"command": command}})
                .to_string(),
            )
    }

    fn bash(&self, command: &str, env: &[(&str, &str)]) -> (String, String) {
        let no_tools = TempDir::new("headless-path");
        let mut inv = self.invocation(&no_tools, command);
        for (k, v) in env {
            inv = inv.env(k, v);
        }
        let run = inv.run();
        let reason = if run.stdout.is_empty() {
            String::new()
        } else {
            run.json()["hookSpecificOutput"]["permissionDecisionReason"]
                .as_str()
                .unwrap_or("")
                .to_string()
        };
        (decision_label(&run), reason)
    }
}

#[test]
fn ci_true_turns_an_identified_devnet_final_into_a_deny() {
    let w = World::new("headless-ci");
    assert_eq!(w.bash(DEVNET_FINAL, &[]).0, "ask");
    let (label, reason) = w.bash(DEVNET_FINAL, &[("CI", "true")]);
    assert_eq!(label, "deny");
    assert!(
        reason.contains("headless") && reason.contains("run it yourself"),
        "{reason}"
    );
}

#[test]
fn nothing_turns_headless_off() {
    let w = World::new("headless-off");
    for env in [
        &[("CI", "true"), ("KIT_FIREWALL_HEADLESS", "0")][..],
        &[
            ("GITHUB_ACTIONS", "true"),
            ("SAFE_AI_SKILL_HEADLESS", "false"),
        ],
        &[("KIT_FIREWALL_HEADLESS", "1"), ("CI", "0")],
    ] {
        assert_eq!(w.bash(DEVNET_FINAL, env).0, "deny", "{env:?}");
    }
}

#[test]
fn confirm_mainnet_is_ignored_when_headless() {
    let w = World::new("headless-confirm");
    let env = [("SAFE_AI_SKILL_HEADLESS", "1"), ("CONFIRM_MAINNET", "1")];
    assert_eq!(w.bash(MAINNET_DEPLOY, &env).0, "deny");
    assert_eq!(w.bash(MAINNET_DEPLOY, &[("CONFIRM_MAINNET", "1")]).0, "ask");
}

#[test]
fn no_headless_row_emits_ask() {
    let w = World::new("headless-noask");
    let env = [("CI", "1")];
    for command in [
        DEVNET_FINAL,
        MAINNET_DEPLOY,
        "solana program deploy x.so",
        "solana transfer 9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin 50 -ud",
        "solana program set-upgrade-authority P --new-upgrade-authority Q -ud",
        "$S transfer D 1",
    ] {
        let (label, _) = w.bash(command, &env);
        assert_ne!(label, "ask", "{command}");
    }
    // Unreadable payloads too.
    let run = Invocation::new(&["gate-bash"])
        .plugin_data(w.data.path())
        .home(w.home.path())
        .env("CI", "1")
        .stdin("{not json")
        .run();
    assert_eq!(decision_label(&run), "deny");
}

fn deploy_grant(dir: &DataDir) {
    let grant = Grant {
        id: "g-deploy".into(),
        scope: Scope::Deploy,
        programs: Vec::new(),
        to: Vec::new(),
        max_tx_sol: 0.0,
        budget_sol: 0.0,
        spent_sol: 0.0,
        expires_at: u64::MAX,
        danger: false,
    };
    grants::save(
        dir,
        &Grants {
            grants: vec![grant],
        },
    )
    .unwrap();
}

/// The hook pipeline (relaxation, then the headless rule) for a grantable deploy `ask`.
#[test]
fn a_confirmed_grant_still_passes_headless_below_high_only() {
    let data = TempDir::new("headless-grant");
    let dir = DataDir {
        path: data.path().to_path_buf(),
        trusted: true,
    };
    deploy_grant(&dir);
    let meta = GateMeta::new(Scope::Deploy, false);
    let ask = || Decision::Ask {
        reason: "Deploy to an unidentified network — approve to proceed".into(),
    };
    let mut policy = Policy::from_sources(DEFAULT_POLICY_YAML, None);
    for (tier, want) in [
        (Tier::Off, "allow"),
        (Tier::Relaxed, "allow"),
        (Tier::Medium, "allow"),
        (Tier::High, "deny"),
    ] {
        policy.runtime.tier = tier;
        let out = headless::apply(relax::apply(ask(), &meta, &policy, &dir), true);
        assert_eq!(out.label(), want, "{tier:?}");
    }
    // A hard guard is never relaxed, so headless denies it.
    policy.runtime.tier = Tier::Relaxed;
    let hard = GateMeta::new(Scope::Deploy, true);
    assert_eq!(
        headless::apply(relax::apply(ask(), &hard, &policy, &dir), true).label(),
        "deny"
    );
}

/// Through the binary: needs a trusted data dir, so only in `test-hooks` builds.
#[cfg(feature = "test-hooks")]
#[test]
fn binary_headless_grant_allows_at_relaxed_and_denies_at_high() {
    let unknown_deploy = "solana program deploy x.so";
    for (tier, want) in [(Tier::Relaxed, "allow"), (Tier::High, "deny")] {
        let w = World::new("headless-bin");
        let dir = DataDir {
            path: w.data.path().to_path_buf(),
            trusted: true,
        };
        deploy_grant(&dir);
        let no_tools = TempDir::new("headless-path");
        let run = w
            .invocation(&no_tools, unknown_deploy)
            .tier(tier)
            .headless(true)
            .run();
        assert_eq!(decision_label(&run), want, "{tier:?}");
    }
}
