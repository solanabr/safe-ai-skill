//! Tier selection (D8 v2 spec §1.2-§1.3, §9; shared contract §3): the effective tier for every
//! source, the lowering confirmation, forged state, `env_read`, and migration.
//!
//! The CLI and hooks run as the real binary in a temp HOME and data dir. That data dir lives
//! under the temp dir, which is never trusted (spec D2.8), so the effective tier is read back
//! through the library with the same directory marked trusted, as it is under
//! `~/.claude/plugins/data` in a real install.

mod common;

use std::path::Path;

use common::{Invocation, Run, TempDir};
use safe_ai_skill::datadir::DataDir;
use safe_ai_skill::policy::tier::{self, EnvRead, Resolution, Tier, TierSource};
use safe_ai_skill::policy::{Policy, DEFAULT_POLICY_YAML};
use safe_ai_skill::tierstate;
use serde_json::json;

const KIT_POLICY: &str = include_str!("fixtures/aikit/policy.yaml");
const KIT_SECURITY: &str = include_str!("fixtures/aikit/security/kit-relaxed.json");

struct World {
    home: TempDir,
    proj: TempDir,
    data: TempDir,
}

impl World {
    fn new(tag: &str) -> World {
        let w = World {
            home: TempDir::new(&format!("{tag}-home")),
            proj: TempDir::new(&format!("{tag}-proj")),
            data: TempDir::new(&format!("{tag}-data")),
        };
        std::fs::create_dir_all(w.proj.join(".git")).unwrap();
        w
    }

    /// The data dir as gates see it in a real install (trusted).
    fn dir(&self) -> DataDir {
        DataDir {
            path: self.data.path().to_path_buf(),
            trusted: true,
        }
    }

    fn root(&self) -> std::path::PathBuf {
        tier::project_root(self.proj.path())
    }

    fn resolve_in(&self, cwd: &Path, dir: &DataDir, env: &[(&str, &str)]) -> Resolution {
        let policy = Policy::load(cwd);
        let lookup = |k: &str| {
            env.iter()
                .find(|(key, _)| *key == k)
                .map(|(_, v)| v.to_string())
        };
        tier::resolve(&tier::project_root(cwd), dir, &policy, &lookup)
    }

    fn resolve(&self, env: &[(&str, &str)]) -> Resolution {
        self.resolve_in(self.proj.path(), &self.dir(), env)
    }

    fn write(&self, rel: &str, body: &str) {
        let path = self.proj.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    fn cli(&self, args: &[&str]) -> Run {
        Invocation::new(args)
            .plugin_data(self.data.path())
            .home(self.home.path())
            .cwd(self.proj.path())
            .run()
    }

    fn hook(&self, sub: &[&str], payload: serde_json::Value) -> Run {
        let no_tools = TempDir::new("tiers-path");
        Invocation::new(sub)
            .plugin_data(self.data.path())
            .home(self.home.path())
            .cwd(self.proj.path())
            .env("PATH", no_tools.path().to_str().unwrap())
            .stdin(payload.to_string())
            .run()
    }

    /// The code the PostToolUse `pending-notice` hook shows the user.
    fn code_shown(&self) -> String {
        let run = self.hook(
            &["pending-notice"],
            json!({"session_id":"it-tiers","hook_event_name":"PostToolUse","tool_name":"Bash","cwd": self.proj.path(),
                   "tool_input":{"command":"safe-ai-skill tier off"}}),
        );
        let msg = run.json()["systemMessage"].as_str().unwrap().to_string();
        msg.split("safe-ai-skill confirm ")
            .nth(1)
            .unwrap()
            .chars()
            .take(8)
            .collect()
    }

    fn prompt(&self, prompt: &str) -> Run {
        self.hook(
            &["prompt-guard"],
            json!({"session_id":"it-tiers","hook_event_name":"UserPromptSubmit","cwd": self.proj.path(),"prompt": prompt}),
        )
    }

    fn session(&self) -> String {
        let run = self.hook(
            &["verify", "session"],
            json!({"session_id":"it-tiers","hook_event_name":"SessionStart","source":"startup","cwd": self.proj.path()}),
        );
        if run.stdout.trim().is_empty() {
            String::new()
        } else {
            run.json()["systemMessage"]
                .as_str()
                .unwrap_or("")
                .to_string()
        }
    }
}

fn noted(r: &Resolution, needle: &str) -> bool {
    r.notes.iter().any(|n| n.contains(needle))
}

// ---------------------------------------------------------------------------------------
// The user's choice and its confirmation
// ---------------------------------------------------------------------------------------

#[test]
fn nothing_selected_is_relaxed() {
    let w = World::new("tiers-none");
    let r = w.resolve(&[]);
    assert_eq!(
        (r.tier, r.source, r.env_read),
        (Tier::Relaxed, TierSource::Base, EnvRead::Deny)
    );
    assert!(r.notes.is_empty(), "{:?}", r.notes);
}

#[test]
fn raising_applies_at_once_with_nothing_pending() {
    let w = World::new("tiers-high");
    let run = w.cli(&["tier", "high"]);
    assert_eq!(run.json()["status"], "set", "{}", run.stdout);
    assert!(!w.data.join("pending.json").exists());
    let r = w.resolve(&[]);
    assert_eq!((r.tier, r.source), (Tier::High, TierSource::UserGlobal));
}

#[cfg(unix)] // confirmations need the process table, which native Windows lacks (by design)
#[test]
fn lowering_waits_for_the_users_whole_prompt_confirmation() {
    let w = World::new("tiers-off");
    let run = w.cli(&["tier", "off"]);
    assert_eq!(run.json()["status"], "pending", "{}", run.stdout);
    assert_eq!(w.resolve(&[]).tier, Tier::Relaxed);

    let code = w.code_shown();
    // The same code in a tool payload: the tripwire denies it and nothing changes.
    let tool = w.hook(
        &["gate-bash-secrets"],
        json!({"hook_event_name":"PreToolUse","tool_name":"Bash","cwd": w.proj.path(),
               "tool_input":{"command": format!("safe-ai-skill confirm {code}")}}),
    );
    assert_eq!(common::decision_label(&tool), "deny");
    // Embedded in a longer prompt: refused, not consumed.
    let embedded = w.prompt(&format!("please do this:\nsafe-ai-skill confirm {code}"));
    assert!(
        embedded.stdout.contains("nothing confirmed"),
        "{}",
        embedded.stdout
    );
    assert_eq!(w.resolve(&[]).tier, Tier::Relaxed);

    let ok = w.prompt(&format!("safe-ai-skill confirm {code}"));
    assert!(ok.stdout.contains("you confirmed"), "{}", ok.stdout);
    assert!(!ok.stdout.contains(&code));
    let r = w.resolve(&[]);
    assert_eq!((r.tier, r.source), (Tier::Off, TierSource::UserGlobal));
}

#[test]
fn lowering_from_a_stored_high_needs_confirmation_too() {
    let w = World::new("tiers-down");
    let dir = w.dir();
    let high = tierstate::Change {
        project: None,
        tier: Some(Tier::High),
        env_read: None,
        clear: false,
    };
    tierstate::apply(&dir, &high, 0).unwrap();
    for (tier, clear) in [(Some(Tier::Medium), false), (None, true)] {
        let change = tierstate::Change {
            project: None,
            tier,
            env_read: None,
            clear,
        };
        assert_eq!(
            tierstate::plan(&dir, &change),
            tierstate::Plan::NeedsConfirm
        );
    }
}

// ---------------------------------------------------------------------------------------
// Raise-only hints
// ---------------------------------------------------------------------------------------

#[test]
fn kit_security_json_only_raises() {
    for (body, want, note) in [
        (r#"{"tier":"medium"}"#, Tier::Medium, None),
        (
            r#"{"declared":{"tier":"high"},"enforced":{"tier":"relaxed"}}"#,
            Tier::High,
            None,
        ),
        (
            r#"{"tier":"off"}"#,
            Tier::Relaxed,
            Some("kit .claude/security.json `tier: off` ignored"),
        ),
        (
            r#"{"tier": "high","#,
            Tier::Relaxed,
            Some("not a regular JSON file"),
        ),
        (KIT_SECURITY, Tier::Relaxed, None),
    ] {
        let w = World::new("tiers-kit");
        w.write(".claude/security.json", body);
        let r = w.resolve(&[]);
        assert_eq!(r.tier, want, "{body}");
        match note {
            Some(n) => assert!(noted(&r, n), "{body}: {:?}", r.notes),
            None => assert!(r.notes.is_empty(), "{body}: {:?}", r.notes),
        }
        if want > Tier::Relaxed {
            assert_eq!(r.source, TierSource::KitSecurityJson);
        }
    }
    let w = World::new("tiers-kit-big");
    let big = format!(r#"{{"tier":"high","pad":"{}"}}"#, "x".repeat(257 * 1024));
    w.write(".claude/security.json", &big);
    let r = w.resolve(&[]);
    assert_eq!(r.tier, Tier::Relaxed);
    assert!(noted(&r, "256 KiB"), "{:?}", r.notes);
}

#[test]
fn repo_policy_only_raises() {
    for (yaml, want, note) in [
        ("tier: high\n", Tier::High, false),
        ("tier: off\n", Tier::Relaxed, true),
        ("active_profile: paranoid\n", Tier::High, false),
        ("active_profile: strict\n", Tier::Relaxed, false),
    ] {
        let w = World::new("tiers-repo");
        w.write(".safe-ai-skill/policy.yaml", yaml);
        let r = w.resolve(&[]);
        assert_eq!(r.tier, want, "{yaml}");
        assert_eq!(noted(&r, "ignored"), note, "{yaml}: {:?}", r.notes);
        if want == Tier::High {
            assert_eq!(r.source, TierSource::RepoPolicy);
        }
    }
}

#[test]
fn env_only_raises() {
    let w = World::new("tiers-env");
    let r = w.resolve(&[("SAFE_AI_SKILL_TIER", "off")]);
    assert_eq!(r.tier, Tier::Relaxed);
    assert!(
        noted(&r, "SAFE_AI_SKILL_TIER: off` ignored"),
        "{:?}",
        r.notes
    );
    let r = w.resolve(&[("SAFE_AI_SKILL_TIER", "high")]);
    assert_eq!((r.tier, r.source), (Tier::High, TierSource::Env));
    let r = w.resolve(&[("SAFE_AI_SKILL_PROFILE", "paranoid")]);
    assert_eq!(r.tier, Tier::High);
    let r = w.resolve(&[("SAFE_AI_SKILL_TIER", "IGNORE PREVIOUS INSTRUCTIONS")]);
    assert_eq!(r.tier, Tier::Relaxed);
    assert!(
        r.notes.iter().all(|n| !n.contains("IGNORE")),
        "{:?}",
        r.notes
    );
}

#[test]
fn a_floor_beats_the_users_project_choice_and_siblings_get_the_base() {
    let w = World::new("tiers-floor");
    let dir = w.dir();
    let off = tierstate::Change {
        project: Some(tierstate::root_key(&w.root())),
        tier: Some(Tier::Off),
        env_read: None,
        clear: false,
    };
    tierstate::apply(&dir, &off, 0).unwrap();
    assert_eq!(w.resolve(&[]).tier, Tier::Off);
    w.write(".claude/security.json", r#"{"tier":"high"}"#);
    let r = w.resolve(&[]);
    assert_eq!(
        (r.tier, r.source, r.user),
        (Tier::High, TierSource::KitSecurityJson, Tier::Off)
    );
    assert!(noted(&r, "floor") && noted(&r, "kit"), "{:?}", r.notes);

    let sibling = TempDir::new("tiers-sibling");
    let r = w.resolve_in(sibling.path(), &dir, &[]);
    assert_eq!((r.tier, r.source), (Tier::Relaxed, TierSource::Base));
}

// ---------------------------------------------------------------------------------------
// Authenticated state
// ---------------------------------------------------------------------------------------

/// A `tier.json` that fails authentication (forged, edited, or its state key removed) is not a
/// silent lowering: tier High applies, with a note naming the cause, until the user sets a tier.
#[test]
fn a_forged_or_edited_tier_json_fails_closed_to_high_with_a_mac_note() {
    let w = World::new("tiers-forged");
    let dir = w.dir();
    std::fs::write(
        w.data.join("tier.json"),
        r#"{"v":1,"mac":"00","gen":1,"body":{"v":1,"global":{"tier":"off"},"projects":{}}}"#,
    )
    .unwrap();
    let r = w.resolve(&[]);
    assert_eq!((r.tier, r.source), (Tier::High, TierSource::StateTampered));
    assert!(noted(&r, "MAC"), "{:?}", r.notes);
    assert!(noted(&r, "tier high applies"), "{:?}", r.notes);

    // A genuine file edited by hand afterwards.
    let _ = std::fs::remove_file(w.data.join("tier.json"));
    let set = |tier| tierstate::Change {
        project: None,
        tier: Some(tier),
        env_read: None,
        clear: false,
    };
    tierstate::apply(&dir, &set(Tier::High), 0).unwrap();
    let text = std::fs::read_to_string(w.data.join("tier.json")).unwrap();
    std::fs::write(
        w.data.join("tier.json"),
        text.replace("\"high\"", "\"off\""),
    )
    .unwrap();
    let r = w.resolve(&[]);
    assert_eq!((r.tier, r.source), (Tier::High, TierSource::StateTampered));
    assert!(noted(&r, "MAC"), "{:?}", r.notes);

    // Lowering from a tampered file needs the confirmation; `tier off` is not immediate.
    assert_eq!(
        tierstate::plan(&dir, &set(Tier::Off)),
        tierstate::Plan::NeedsConfirm
    );
    // `tier high` replaces the file at once.
    assert_eq!(
        tierstate::plan(&dir, &set(Tier::High)),
        tierstate::Plan::Immediate
    );

    // A genuine file whose state key was removed.
    tierstate::apply(&dir, &set(Tier::Off), 0).unwrap();
    assert_eq!(w.resolve(&[]).tier, Tier::Off);
    std::fs::remove_file(w.data.join("key")).unwrap();
    let r = w.resolve(&[]);
    assert_eq!((r.tier, r.source), (Tier::High, TierSource::StateTampered));
    assert!(noted(&r, "key"), "{:?}", r.notes);
}

/// The binary: `status` and SessionStart name the cause; `tier high` clears it at once.
#[test]
fn a_tampered_tier_json_is_reported_by_status_and_session_start() {
    if !common::TEST_HOOKS {
        return;
    }
    let w = World::new("tiers-forged-bin");
    std::fs::write(
        w.data.join("tier.json"),
        r#"{"v":1,"mac":"00","gen":1,"body":{"v":1,"global":{"tier":"off"},"projects":{}}}"#,
    )
    .unwrap();
    let trusted = |args: &[&str]| {
        Invocation::new(args)
            .plugin_data(w.data.path())
            .home(w.home.path())
            .cwd(w.proj.path())
            .env(safe_ai_skill::datadir::TEST_TRUST_ENV, "1")
            .run()
    };
    let status = trusted(&["status"]).json();
    assert_eq!(status["tier"], "high", "{status}");
    assert_eq!(status["tier_state"], "failed authentication", "{status}");
    let session = Invocation::new(&["verify", "session"])
        .plugin_data(w.data.path())
        .home(w.home.path())
        .cwd(w.proj.path())
        .env(safe_ai_skill::datadir::TEST_TRUST_ENV, "1")
        .stdin(
            json!({"session_id":"it-tiers","hook_event_name":"SessionStart","source":"startup","cwd": w.proj.path()})
                .to_string(),
        )
        .run();
    assert!(
        session.stdout.contains("tier.json failed authentication"),
        "{}",
        session.stdout
    );
    let run = trusted(&["tier", "relaxed"]);
    assert_ne!(run.json()["status"], "set", "{}", run.stdout);
    assert_eq!(trusted(&["status"]).json()["tier"], "high");
    let run = trusted(&["tier", "high"]);
    assert_eq!(run.json()["status"], "set", "{}", run.stdout);
    let status = trusted(&["status"]).json();
    assert_eq!(
        (status["tier"].as_str(), status["tier_state"].as_str()),
        (Some("high"), Some("valid")),
        "{status}"
    );
}

#[test]
fn an_untrusted_data_dir_selects_nothing() {
    let w = World::new("tiers-untrusted");
    let off = tierstate::Change {
        project: None,
        tier: Some(Tier::Off),
        env_read: Some(EnvRead::Tier),
        clear: false,
    };
    tierstate::apply(&w.dir(), &off, 0).unwrap();
    let untrusted = DataDir {
        trusted: false,
        ..w.dir()
    };
    let r = w.resolve_in(w.proj.path(), &untrusted, &[]);
    assert_eq!((r.tier, r.env_read), (Tier::Relaxed, EnvRead::Deny));
    assert!(noted(&r, "untrusted"), "{:?}", r.notes);
}

// ---------------------------------------------------------------------------------------
// env_read
// ---------------------------------------------------------------------------------------

#[cfg(unix)] // confirmations need the process table, which native Windows lacks (by design)
#[test]
fn env_read_tier_in_the_repo_is_ignored_and_the_users_waits_for_confirmation() {
    let w = World::new("tiers-envread");
    w.write(".safe-ai-skill/policy.yaml", "secrets:\n  env_read: tier\n");
    let policy = Policy::load(w.proj.path());
    assert!(
        policy
            .ignored_overrides
            .iter()
            .any(|n| n.starts_with("secrets.env_read")),
        "{:?}",
        policy.ignored_overrides
    );
    assert_eq!(w.resolve(&[]).env_read, EnvRead::Deny);

    let w = World::new("tiers-envread-user");
    let run = w.cli(&["tier", "--env-read", "tier"]);
    assert_eq!(run.json()["status"], "pending", "{}", run.stdout);
    assert_eq!(w.resolve(&[]).env_read, EnvRead::Deny);
    let code = w.code_shown();
    assert!(w
        .prompt(&format!("safe-ai-skill confirm {code}"))
        .stdout
        .contains("you confirmed"));
    assert_eq!(w.resolve(&[]).env_read, EnvRead::Tier);
    // Tightening applies at once.
    let deny = tierstate::Change {
        project: None,
        tier: None,
        env_read: Some(EnvRead::Deny),
        clear: false,
    };
    assert_eq!(tierstate::plan(&w.dir(), &deny), tierstate::Plan::Immediate);
    tierstate::apply(&w.dir(), &deny, 0).unwrap();
    assert_eq!(w.resolve(&[]).env_read, EnvRead::Deny);
}

// ---------------------------------------------------------------------------------------
// Migration (spec §9)
// ---------------------------------------------------------------------------------------

#[test]
fn v1_profiles_migrate_to_tiers_once() {
    for (profile, tier, needle) in [
        ("strict", Tier::Relaxed, "now deny"),
        ("paranoid", Tier::High, "tier high"),
        ("autopilot", Tier::Relaxed, "allow --scope transfer"),
        ("off", Tier::Relaxed, "safe-ai-skill tier off"),
    ] {
        let w = World::new("tiers-migrate");
        std::fs::write(
            w.data.join("mode.json"),
            format!(r#"{{"profile":"{profile}","set_at":5}}"#),
        )
        .unwrap();
        let first = w.session();
        assert!(first.contains(needle), "{profile}: {first}");
        assert_eq!(w.resolve(&[]).tier, tier, "{profile}");
        assert!(!w.session().contains(needle), "{profile}: shown twice");
        if profile == "off" {
            assert!(w.data.join("mode.json.v1-unmigrated").exists());
        }
    }
}

#[test]
fn the_kit_policy_yaml_loads_with_only_documented_notes() {
    let p = Policy::from_sources(DEFAULT_POLICY_YAML, Some(KIT_POLICY));
    assert!(!p.is_fail_closed());
    assert!(p.ignored_overrides.is_empty(), "{:?}", p.ignored_overrides);
    assert!(p.repo_tier_hints.is_empty());
    assert_eq!(p.repo_env_read, None);
    assert_eq!(
        p.secrets.allow_read_globs,
        vec!["**/.env.example".to_string(), "**/.env.schema".to_string()]
    );
}

// ---------------------------------------------------------------------------------------
// The tests/common builder
// ---------------------------------------------------------------------------------------

fn show(inv: Invocation) -> serde_json::Value {
    inv.run().json()
}

#[test]
fn builder_kit_security_and_sandbox_reach_the_binary() {
    let w = World::new("tiers-builder");
    let v = show(
        Invocation::new(&["tier"])
            .plugin_data(w.data.path())
            .home(w.home.path())
            .cwd(w.proj.path())
            .kit_security(r#"{"tier":"medium"}"#)
            .sandbox(common::SandboxMode::On),
    );
    assert_eq!(v["tier"], "medium", "{v}");
    assert_eq!(v["source"], "kit .claude/security.json");
    if cfg!(target_os = "macos") || common::TEST_HOOKS {
        assert_eq!(v["sandbox"], "on", "{v}");
    }
    let v = show(
        Invocation::new(&["tier"])
            .plugin_data(w.data.path())
            .home(w.home.path())
            .cwd(w.proj.path())
            .sandbox(common::SandboxMode::Off),
    );
    assert_eq!(v["sandbox"], "off", "{v}");
    assert!(v["line"].as_str().unwrap().contains("(hooks only)"), "{v}");
}

#[test]
fn builder_tier_selects_the_users_tier() {
    let w = World::new("tiers-builder-tier");
    let v = show(
        Invocation::new(&["tier"])
            .plugin_data(w.data.path())
            .home(w.home.path())
            .cwd(w.proj.path())
            .tier(Tier::High),
    );
    assert_eq!(v["tier"], "high", "{v}");
    if common::TEST_HOOKS {
        let w = World::new("tiers-builder-off");
        let v = show(
            Invocation::new(&["tier"])
                .plugin_data(w.data.path())
                .home(w.home.path())
                .cwd(w.proj.path())
                .tier(Tier::Off)
                .env_read(EnvRead::Ask),
        );
        assert_eq!(
            (v["tier"].as_str(), v["source"].as_str()),
            (Some("off"), Some("your setting")),
            "{v}"
        );
        assert_eq!(v["env_read"], "ask", "{v}");
    }
}

#[test]
fn agents_may_request_a_tier_but_not_write_tier_json() {
    let w = World::new("tiers-tripwire");
    for command in [
        "safe-ai-skill tier off",
        "safe-ai-skill tier high --project",
    ] {
        let run = w.hook(
            &["gate-bash-secrets"],
            json!({"hook_event_name":"PreToolUse","tool_name":"Bash","cwd": w.proj.path(),
                   "tool_input":{"command": command}}),
        );
        assert_eq!(common::decision_label(&run), "", "{command}");
    }
    let target = w.data.join("tier.json");
    let write = w.hook(
        &["gate-tamper"],
        json!({"hook_event_name":"PreToolUse","tool_name":"Write","cwd": w.proj.path(),
               "tool_input":{"file_path": target, "content": "{}"}}),
    );
    assert_eq!(common::decision_label(&write), "deny");
    let echo = w.hook(
        &["gate-bash-secrets"],
        json!({"hook_event_name":"PreToolUse","tool_name":"Bash","cwd": w.proj.path(),
               "tool_input":{"command": format!("echo '{{}}' > {}", common::sh_path(&target))}}),
    );
    assert_eq!(common::decision_label(&echo), "deny");
}

// ---------------------------------------------------------------------------------------
// Fix round 1: base spoofing, base floor, untrusted note, replay
// ---------------------------------------------------------------------------------------

/// A `CLAUDE_PLUGIN_ROOT` whose default policy says `tier` / `env_read` as given.
fn evil_root(tier_line: &str, env_read: &str) -> TempDir {
    let root = TempDir::new("tiers-evil-root");
    std::fs::create_dir_all(root.join("policy")).unwrap();
    let text = DEFAULT_POLICY_YAML
        .replace("tier: relaxed", tier_line)
        .replace("env_read: deny", &format!("env_read: {env_read}"));
    std::fs::write(root.join("policy/default.policy.yaml"), text).unwrap();
    root
}

/// `tier --clear` (global and `--project`) stays pending even when the agent points
/// `CLAUDE_PLUGIN_ROOT` at a default policy whose base equals the stored tier (review #1).
#[cfg(feature = "test-hooks")]
#[test]
fn a_spoofed_plugin_root_cannot_make_clear_immediate() {
    let evil = evil_root("tier: high", "deny");
    for project in [false, true] {
        let w = World::new("tiers-spoof");
        let cli = |args: &[&str], spoof: bool| {
            let mut inv = Invocation::new(args)
                .plugin_data(w.data.path())
                .home(w.home.path())
                .cwd(w.proj.path())
                .env(safe_ai_skill::datadir::TEST_TRUST_ENV, "1");
            if spoof {
                inv = inv.env("CLAUDE_PLUGIN_ROOT", evil.path().to_str().unwrap());
            }
            inv.run().json()
        };
        let mut set = vec!["tier", "high"];
        let mut clear = vec!["tier", "--clear"];
        if project {
            set.push("--project");
            clear.push("--project");
        }
        assert_eq!(cli(&set, false)["status"], "set");
        assert_eq!(cli(&clear, true)["status"], "pending", "project={project}");
        assert_eq!(w.resolve(&[]).tier, Tier::High, "project={project}");
        assert_eq!(cli(&["tier"], false)["tier"], "high");
    }
}

/// The plugin default policy is floored at relaxed and its env_read pinned to deny (review #2).
#[test]
fn the_plugin_default_policy_cannot_lower_or_open_env_reads() {
    let w = World::new("tiers-base-floor");
    let evil = evil_root("tier: off", "tier");
    let v = Invocation::new(&["tier"])
        .plugin_data(w.data.path())
        .home(w.home.path())
        .cwd(w.proj.path())
        .env("CLAUDE_PLUGIN_ROOT", evil.path().to_str().unwrap())
        .run()
        .json();
    assert_eq!(
        (v["tier"].as_str(), v["env_read"].as_str()),
        (Some("relaxed"), Some("deny")),
        "{v}"
    );
    let notes = v["policy_notes"].to_string();
    assert!(
        notes.contains("tier:") && notes.contains("secrets.env_read"),
        "{v}"
    );
    // A higher base still applies.
    let high = evil_root("tier: high", "deny");
    let v = Invocation::new(&["tier"])
        .plugin_data(w.data.path())
        .home(w.home.path())
        .cwd(w.proj.path())
        .env("CLAUDE_PLUGIN_ROOT", high.path().to_str().unwrap())
        .run()
        .json();
    assert_eq!(v["tier"], "high", "{v}");
}

/// An untrusted data dir falls back to relaxed and says so at SessionStart and in status.
#[test]
fn an_untrusted_data_dir_is_named_at_session_start_and_in_status() {
    let w = World::new("tiers-untrusted-note");
    let high = tierstate::Change {
        project: None,
        tier: Some(Tier::High),
        env_read: None,
        clear: false,
    };
    tierstate::apply(&w.dir(), &high, 0).unwrap();
    let session = w.session();
    assert!(
        session.starts_with("safe-ai-skill tier: relaxed"),
        "{session}"
    );
    assert!(
        session.contains("user tier ignored: data dir untrusted"),
        "{session}"
    );
    let status = w.cli(&["status"]).json();
    assert_eq!(status["tier"], "relaxed");
    assert!(
        status["tier_notes"]
            .to_string()
            .contains("user tier ignored: data dir untrusted"),
        "{status}"
    );
}

/// Restoring an older, genuine tier.json (a lower tier) does not verify: tier High applies.
#[test]
fn a_replayed_tier_json_fails_closed_to_high() {
    let w = World::new("tiers-replay");
    let dir = w.dir();
    let set = |tier| tierstate::Change {
        project: None,
        tier: Some(tier),
        env_read: None,
        clear: false,
    };
    tierstate::apply(&dir, &set(Tier::Off), 0).unwrap();
    let old = std::fs::read(w.data.join("tier.json")).unwrap();
    tierstate::apply(&dir, &set(Tier::High), 1).unwrap();
    assert_eq!(w.resolve(&[]).tier, Tier::High);
    std::fs::write(w.data.join("tier.json"), old).unwrap();
    let r = w.resolve(&[]);
    assert_eq!((r.tier, r.source), (Tier::High, TierSource::StateTampered));
    assert!(noted(&r, "MAC"), "{:?}", r.notes);
}

/// Deleting tier.json after a tier was set is not a silent lowering: tier High applies, with a
/// note, until the user sets a tier again.
#[test]
fn a_deleted_tier_json_fails_closed_to_high_with_a_note() {
    let w = World::new("tiers-deleted");
    let dir = w.dir();
    let set = |tier| tierstate::Change {
        project: None,
        tier: Some(tier),
        env_read: None,
        clear: false,
    };
    tierstate::apply(&dir, &set(Tier::Off), 0).unwrap();
    std::fs::remove_file(w.data.join("tier.json")).unwrap();
    let r = w.resolve(&[]);
    assert_eq!((r.tier, r.source), (Tier::High, TierSource::StateDeleted));
    assert!(noted(&r, "tier.json was deleted"), "{:?}", r.notes);

    if common::TEST_HOOKS {
        let trusted = |args: &[&str]| {
            Invocation::new(args)
                .plugin_data(w.data.path())
                .home(w.home.path())
                .cwd(w.proj.path())
                .env(safe_ai_skill::datadir::TEST_TRUST_ENV, "1")
                .run()
        };
        let status = trusted(&["status"]).json();
        assert_eq!(status["tier"], "high", "{status}");
        assert_eq!(status["tier_state"], "deleted", "{status}");
        let session = Invocation::new(&["verify", "session"])
            .plugin_data(w.data.path())
            .home(w.home.path())
            .cwd(w.proj.path())
            .env(safe_ai_skill::datadir::TEST_TRUST_ENV, "1")
            .stdin(
                json!({"session_id":"it-tiers","hook_event_name":"SessionStart","source":"startup","cwd": w.proj.path()})
                    .to_string(),
            )
            .run();
        assert!(
            session.stdout.contains("tier.json was deleted"),
            "{}",
            session.stdout
        );
        // `tier relaxed` lowers from High: a pending request, nothing applied.
        let run = trusted(&["tier", "relaxed"]);
        assert_ne!(run.json()["status"], "set", "{}", run.stdout);
        assert_eq!(trusted(&["status"]).json()["tier"], "high");
        // `tier high` re-creates the file at once.
        let run = trusted(&["tier", "high"]);
        assert_eq!(run.json()["status"], "set", "{}", run.stdout);
        let status = trusted(&["status"]).json();
        assert_eq!(
            (status["tier"].as_str(), status["tier_state"].as_str()),
            (Some("high"), Some("valid")),
            "{status}"
        );
    }
}
