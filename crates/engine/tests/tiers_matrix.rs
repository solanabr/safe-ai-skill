//! The D8 v2 tier matrix (F8): every F1 (credentials), F2 (project env), F3 (on-chain) and F5
//! (supply chain) brief row at Off / Relaxed / Medium / High, through the real hook entries.
//!
//! The entries a tool call reaches are read from `plugins/safe-ai-skill/hooks/hooks.json`
//! (every PreToolUse block whose matcher matches the tool), each runs as its own process, and
//! the combined outcome is the strictest (Claude Code: deny > ask > allow). Every entry's
//! stdout is checked exactly: empty (no opinion, exit 0) or one JSON object for the right event
//! whose decision is `allow`, `ask` or `deny` (or, for a Grep, an `updatedInput` with no
//! decision). No entry may print `defer`. Every deny row is asserted at Off: Off is not DISABLE.
//!
//! Tier Off, a loosened `env_read`, grants and the sandbox state need an authenticated
//! `tier.json` and the sandbox override, which only `--features test-hooks` builds honour, so
//! the whole file runs there; rows for the raw env-read opt-in also need `env-read-opt-in`.
//! HOME, the data dir and PATH (an empty dir) are temp dirs: no real CLI ever runs.
#![cfg(feature = "test-hooks")]

mod common;

use std::path::{Path, PathBuf};

use common::{EnvRead, Invocation, Run, SandboxMode, TempDir, Tier};
use safe_ai_skill::datadir::DataDir;
use safe_ai_skill::gate::Scope;
use safe_ai_skill::grants::{self, Grant, Grants};
use serde_json::{json, Value};

const TIERS: [Tier; 4] = [Tier::Off, Tier::Relaxed, Tier::Medium, Tier::High];

const D: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";
const M: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const Q: &str = "8yQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";

const DENY4: [&str; 4] = ["deny"; 4];
const ASK4: [&str; 4] = ["ask"; 4];
const NO4: [&str; 4] = [""; 4];
/// Ask below High, deny at High.
const ASK_HIGH_DENY: [&str; 4] = ["ask", "ask", "ask", "deny"];

// ---------------------------------------------------------------------------------------
// hooks.json
// ---------------------------------------------------------------------------------------

/// The subcommands hooks.json runs for a PreToolUse call of `tool`, in file order.
fn entries_for(tool: &str) -> Vec<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../plugins/safe-ai-skill/hooks/hooks.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut out = Vec::new();
    for block in v["hooks"]["PreToolUse"].as_array().unwrap() {
        let matcher = block["matcher"].as_str().unwrap_or("");
        let hit = matcher.split('|').any(|alt| match alt.strip_suffix(".*") {
            Some(prefix) => tool.starts_with(prefix),
            None => alt == tool,
        });
        if !hit {
            continue;
        }
        for hook in block["hooks"].as_array().unwrap() {
            assert!(hook.get("if").is_none(), "conditional entry: {hook}");
            let cmd = hook["command"].as_str().unwrap();
            let sub = cmd.split_whitespace().skip(1).collect::<Vec<_>>().join(" ");
            out.push(sub);
        }
    }
    assert!(!out.is_empty(), "no hooks.json entry for {tool}");
    out
}

/// The exact outcome of one entry: `""`, `allow`, `ask`, `deny`, or `update` (an
/// `updatedInput` with no decision). Panics on any other stdout, a non-zero exit or `defer`.
fn outcome(run: &Run, event: &str) -> String {
    assert_eq!(run.code, Some(0), "exit {:?}: {}", run.code, run.stderr);
    assert!(!run.stdout.contains("defer"), "defer printed: {}", run.stdout);
    if run.stdout.is_empty() {
        return String::new();
    }
    assert!(
        run.stdout.trim_end().lines().count() == 1,
        "more than one line: {}",
        run.stdout
    );
    let v = run.json();
    let obj = v.as_object().expect("a JSON object");
    for key in obj.keys() {
        assert!(
            matches!(key.as_str(), "hookSpecificOutput" | "systemMessage"),
            "unexpected key {key}: {}",
            run.stdout
        );
    }
    let hso = &v["hookSpecificOutput"];
    assert_eq!(hso["hookEventName"], event, "{}", run.stdout);
    match hso.get("permissionDecision").and_then(Value::as_str) {
        Some("allow") => "allow".to_string(),
        Some(d @ ("ask" | "deny")) => {
            let reason = hso["permissionDecisionReason"].as_str().unwrap_or("");
            assert!(!reason.is_empty(), "{d} without a reason: {}", run.stdout);
            d.to_string()
        }
        Some(other) => panic!("decision {other}: {}", run.stdout),
        None => {
            assert!(hso.get("updatedInput").is_some(), "no decision: {}", run.stdout);
            "update".to_string()
        }
    }
}

fn rank(label: &str) -> u8 {
    match label {
        "deny" => 4,
        "ask" => 3,
        "allow" => 2,
        "update" => 1,
        _ => 0,
    }
}

fn strictest(labels: Vec<String>) -> String {
    labels
        .into_iter()
        .max_by_key(|l| rank(l))
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------------------
// World
// ---------------------------------------------------------------------------------------

/// Who chose what for one run.
#[derive(Clone, Copy)]
struct Setup {
    tier: Tier,
    env_read: Option<EnvRead>,
    sandbox: Option<SandboxMode>,
    headless: bool,
}

impl Setup {
    fn at(tier: Tier) -> Setup {
        Setup {
            tier,
            env_read: None,
            sandbox: None,
            headless: false,
        }
    }
    fn env_read(mut self, e: EnvRead, sandbox: SandboxMode) -> Setup {
        self.env_read = Some(e);
        self.sandbox = Some(sandbox);
        self
    }
    fn headless(mut self) -> Setup {
        self.headless = true;
        self
    }
}

/// Fake home, project, data dir, plugin root and an empty `PATH` dir.
struct World {
    home: TempDir,
    proj: TempDir,
    data: TempDir,
    path: TempDir,
    plugin: TempDir,
}

impl World {
    fn new(tag: &str) -> World {
        let w = World {
            home: TempDir::new(&format!("mx-{tag}-home")),
            proj: TempDir::new(&format!("mx-{tag}-proj")),
            data: TempDir::new(&format!("mx-{tag}-data")),
            path: TempDir::new(&format!("mx-{tag}-path")),
            plugin: TempDir::new(&format!("mx-{tag}-plugin")),
        };
        std::fs::create_dir_all(w.proj.join(".git")).unwrap();
        w
    }

    fn put(&self, rel: &str, body: &str) -> PathBuf {
        let path = self.proj.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, body).unwrap();
        path
    }

    fn invocation<'a>(&'a self, args: &[&str], setup: Setup, stdin: String) -> Invocation<'a> {
        let mut inv = Invocation::new(args)
            .plugin_data(self.data.path())
            .home(self.home.path())
            .cwd(self.proj.path())
            .env("PATH", self.path.path().to_str().unwrap())
            .env("CLAUDE_PLUGIN_ROOT", self.plugin.path().to_str().unwrap())
            .tier(setup.tier)
            .headless(setup.headless)
            .stdin(stdin);
        if let Some(e) = setup.env_read {
            inv = inv.env_read(e);
        }
        if let Some(s) = setup.sandbox {
            inv = inv.sandbox(s);
        }
        inv
    }

    /// One PreToolUse call through every hooks.json entry for `tool`; the strictest outcome.
    fn pre(&self, setup: Setup, tool: &str, input: &Value) -> String {
        let payload = json!({
            "session_id": "it-matrix", "hook_event_name": "PreToolUse",
            "cwd": self.proj.path(), "tool_name": tool, "tool_input": input,
        })
        .to_string();
        strictest(
            entries_for(tool)
                .iter()
                .map(|sub| {
                    let args: Vec<&str> = sub.split(' ').collect();
                    let run = self.invocation(&args, setup, payload.clone()).run();
                    outcome(&run, "PreToolUse")
                })
                .collect(),
        )
    }

    fn x4(&self, tool: &str, input: &Value) -> [String; 4] {
        TIERS.map(|t| self.pre(Setup::at(t), tool, input))
    }

    fn x4_with(&self, tool: &str, input: &Value, setup: impl Fn(Tier) -> Setup) -> [String; 4] {
        TIERS.map(|t| self.pre(setup(t), tool, input))
    }

    fn grant_everything(&self) {
        let dir = DataDir {
            path: self.data.path().to_path_buf(),
            trusted: true,
        };
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
        grants::save(&dir, &Grants { grants }).unwrap();
    }
}

fn bash(command: &str) -> Value {
    json!({ "command": command })
}

fn read(path: &str) -> Value {
    json!({ "file_path": path })
}

/// Assert `got == want` for a row, naming it.
fn check(row: &str, got: [String; 4], want: [&str; 4]) {
    assert_eq!(got.map(|s| s), want.map(String::from), "row: {row}");
}

// ---------------------------------------------------------------------------------------
// Spend ledger (fresh install): an audit log written first must not spend the budget.
// ---------------------------------------------------------------------------------------

#[test]
fn a_fresh_install_allows_a_within_cap_devnet_transfer_after_another_hook_audited() {
    // No tier.json (it would create the state key first): the default tier, as installed.
    let w = World::new("ledger");
    let run = |command: &str| {
        let payload = json!({
            "session_id": "it-matrix", "hook_event_name": "PreToolUse",
            "cwd": w.proj.path(), "tool_name": "Bash", "tool_input": bash(command),
        })
        .to_string();
        strictest(
            entries_for("Bash")
                .iter()
                .map(|sub| {
                    let run = Invocation::new(&[sub.as_str()])
                        .plugin_data(w.data.path())
                        .home(w.home.path())
                        .cwd(w.proj.path())
                        .env("PATH", w.path.path().to_str().unwrap())
                        .stdin(payload.clone())
                        .run();
                    outcome(&run, "PreToolUse")
                })
                .collect(),
        )
    };
    // A denied read writes the audit log before any state file exists.
    assert_eq!(run("cat ~/.aws/credentials"), "deny");
    assert!(w.data.join("audit.jsonl").exists());
    assert!(!w.data.join("key").exists());
    assert_eq!(run(&format!("solana transfer {D} 0.5 -ud")), "allow");
}
