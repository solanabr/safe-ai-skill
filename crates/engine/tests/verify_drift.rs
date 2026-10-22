//! Sandboxed `verify session` sweep: state v2 drift, swept roots, and `verify approve`.
//!
//! Places a clean fixture skill under a sandbox project's `.claude/skills`, records it with a
//! first `verify session` sweep, tampers one byte, then re-runs `verify session` and asserts the
//! drift is a BLOCK (in the SessionStart `systemMessage` + `additionalContext`) on every session,
//! the skill staying where it is. `verify approve` only creates a pending request: nothing
//! changes until the user confirms its nonce (the confirmation itself is covered by the
//! library tests). Also covers which roots are swept (the user-scope `~/.claude/skills` only
//! when the policy lists it, or for packs `install --from` put there), `.mcp.json` findings, and
//! `verify approve` of packs that an earlier version moved into `quarantine/`.
//!
//! Fully hermetic: the project, HOME and CLAUDE_PLUGIN_DATA are sandbox temp dirs, so the sweep
//! scans only the fixtures and writes state only inside the sandbox.

mod common;

use common::{Invocation, Run, TempDir};
use std::path::{Path, PathBuf};

/// A script reading the default keypair: a code-context High finding wherever it is swept.
const KEYPAIR_SCRIPT: &str = "#!/bin/sh\n\ncat ~/.config/solana/id.json\n";

/// `<project>/.claude/skills` — the default (project-scope) skills root.
fn skills_root(project: &Path) -> PathBuf {
    project.join(".claude").join("skills")
}

/// The in-repo plugin root, whose `policy/default.policy.yaml` is the shipped default policy.
fn shipped_plugin_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("plugins")
        .join("safe-ai-skill")
}

/// SessionStart payload for a session in `project`.
fn payload(project: &Path) -> String {
    serde_json::json!({
        "hook_event_name": "SessionStart",
        "source": "startup",
        "cwd": project.to_str().unwrap()
    })
    .to_string()
}

/// Run `verify session` with `project` as the hook payload `cwd`.
fn verify_session(project: &Path, home: &Path, data: &Path) -> Run {
    Invocation::new(&["verify", "session"])
        .plugin_data(data)
        .home(home)
        .stdin(payload(project))
        .run()
}

/// The parsed SessionStart emit, or `None` when the sweep had nothing to report (empty stdout).
fn emit(run: &Run) -> Option<serde_json::Value> {
    assert_eq!(
        run.code,
        Some(0),
        "verify session must exit 0: {}",
        run.stderr
    );
    if run.stdout.trim().is_empty() {
        None
    } else {
        Some(run.json())
    }
}

/// `(systemMessage, additionalContext)` of a SessionStart report; both must be present.
fn messages(v: &serde_json::Value) -> (String, String) {
    let inner = &v["hookSpecificOutput"];
    assert_eq!(inner["hookEventName"], "SessionStart", "{v}");
    let sys = v["systemMessage"]
        .as_str()
        .unwrap_or_else(|| panic!("no systemMessage: {v}"))
        .to_string();
    let ctx = inner["additionalContext"]
        .as_str()
        .unwrap_or_else(|| panic!("no additionalContext: {v}"))
        .to_string();
    (sys, ctx)
}

/// The sandbox lockfile, parsed (`{}` when nothing has written one).
fn lockfile(data: &Path) -> serde_json::Value {
    std::fs::read_to_string(data.join("lockfile.json"))
        .map(|body| serde_json::from_str(&body).unwrap())
        .unwrap_or_else(|_| serde_json::json!({}))
}

/// The state v2 entry whose key ends with `suffix` (the body of the MAC'd `state.json`).
fn state_entry(data: &Path, suffix: &str) -> Option<serde_json::Value> {
    let body = std::fs::read_to_string(data.join("state.json")).ok()?;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    v["body"]["packs"]
        .as_object()?
        .iter()
        .find(|(k, _)| k.ends_with(suffix))
        .map(|(_, e)| e.clone())
}

/// Seed a pack that an earlier version moved to `<data>/quarantine/<name>`.
fn seed_quarantined(data: &Path, name: &str) {
    let dir = data.join("quarantine").join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("SKILL.md"), format!("# {name}\n")).unwrap();
}

/// Run `verify approve <name>` from `cwd` (as a user would in a terminal): a pending request.
fn approve_from(cwd: &Path, home: &Path, data: &Path, name: &str) -> serde_json::Value {
    let run = Invocation::new(&["verify", "approve", name])
        .plugin_data(data)
        .home(home)
        .cwd(cwd)
        .stdin("{}")
        .run();
    let v = run.json();
    assert_eq!(v["status"], "pending", "approve failed: {}", run.stdout);
    // A request id only: the confirmation code never reaches the agent (WS-B).
    let id = v["request"].as_str().unwrap_or_default();
    assert!(id.starts_with('r'), "{v}");
    assert!(v.get("nonce").is_none(), "{v}");
    assert!(
        !run.stdout.contains("safe-ai-skill confirm ") && !run.stderr.contains("confirm 0"),
        "{}",
        run.stdout
    );
    v
}

/// Run `verify approve <name>` from the project dir.
fn approve(project: &Path, home: &Path, data: &Path, name: &str) -> serde_json::Value {
    approve_from(project, home, data, name)
}

/// Append one byte to `file` so its pack's tree hash changes.
fn tamper(file: &Path) {
    let mut body = std::fs::read_to_string(file).unwrap();
    body.push('X');
    std::fs::write(file, body).unwrap();
}

/// Assert `run` reports a drift BLOCK for `name`, to both the user and the model.
fn assert_drift_blocked(run: &Run, name: &str) {
    let v = emit(run).unwrap_or_else(|| panic!("drift of {name} not reported"));
    let (sys, ctx) = messages(&v);
    for (field, text) in [("systemMessage", &sys), ("additionalContext", &ctx)] {
        let lower = text.to_lowercase();
        assert!(
            lower.contains("block") && lower.contains(name) && lower.contains("drift"),
            "{field} did not report the drifted {name}: {text:?}"
        );
    }
}

#[test]
fn drift_blocks_every_session_and_approve_only_requests() {
    let project = TempDir::new("drift-proj");
    let home = TempDir::new("drift-home");
    let data = TempDir::new("drift-data");

    // Seed a clean fixture skill under the project's .claude/skills.
    let skill = skills_root(project.path()).join("address-formatter");
    std::fs::create_dir_all(&skill).unwrap();
    std::fs::write(
        skill.join("SKILL.md"),
        "# Address Formatter\n\nFormats Solana addresses for display.\n",
    )
    .unwrap();

    // 1. First sweep records the clean skill (TOFU) and has nothing to report.
    let first = verify_session(project.path(), home.path(), data.path());
    assert!(
        emit(&first).is_none(),
        "clean first sweep must emit nothing: {}",
        first.stdout
    );
    let pinned =
        state_entry(data.path(), "/address-formatter").expect("recorded")["tree_hash"].clone();
    assert!(pinned.is_string(), "skill not pinned after the first sweep");

    // 2. Tamper one byte in the pinned skill: every following session blocks it.
    let md_path = skill.join("SKILL.md");
    tamper(&md_path);
    for _ in 0..2 {
        assert_drift_blocked(
            &verify_session(project.path(), home.path(), data.path()),
            "address-formatter",
        );
    }
    // The pin is kept, the skill stays in the skills root, nothing is quarantined.
    let e = state_entry(data.path(), "/address-formatter").unwrap();
    assert_eq!(e["tree_hash"], pinned, "a drifted pack must keep its pin");
    assert_eq!(e["state"], "blocked");
    assert_eq!(e["reason"], "drift");
    assert!(md_path.exists(), "drifted skill was moved");
    assert!(
        !data.path().join("quarantine").exists(),
        "nothing may be moved to quarantine"
    );

    // 3. `verify approve` (which the agent could run) only creates a pending request.
    let v = approve(
        project.path(),
        home.path(),
        data.path(),
        "address-formatter",
    );
    assert!(
        v["summary"]
            .as_str()
            .unwrap_or_default()
            .contains("approve in place"),
        "{v}"
    );
    assert_drift_blocked(
        &verify_session(project.path(), home.path(), data.path()),
        "address-formatter",
    );
}

#[test]
fn install_managed_user_skills_swept_personal_ones_not() {
    let project = TempDir::new("managed-proj");
    let home = TempDir::new("managed-home");
    let data = TempDir::new("managed-data");
    let source = TempDir::new("managed-src");
    std::fs::create_dir_all(source.join("managed")).unwrap();
    std::fs::write(
        source.join("managed").join("SKILL.md"),
        "# Managed\nFormats lamports.\n",
    )
    .unwrap();

    // `install --from` puts the pack under ~/.claude/skills and pins it with its source.
    let run = Invocation::new(&["install", "--from", source.path().to_str().unwrap()])
        .plugin_data(data.path())
        .home(home.path())
        .stdin("{}")
        .run();
    assert_eq!(run.json()["installed"][0], "managed", "{}", run.stdout);
    let user_skills = home.path().join(".claude").join("skills");
    // A personal skill next to it, never installed through safe-ai-skill.
    std::fs::create_dir_all(user_skills.join("personal")).unwrap();
    std::fs::write(
        user_skills.join("personal").join("SKILL.md"),
        "# Personal\n",
    )
    .unwrap();

    let first = verify_session(project.path(), home.path(), data.path());
    assert!(emit(&first).is_none(), "{}", first.stdout);

    tamper(&user_skills.join("managed").join("SKILL.md"));
    tamper(&user_skills.join("personal").join("SKILL.md"));
    let second = verify_session(project.path(), home.path(), data.path());
    assert_drift_blocked(&second, "managed");
    let (sys, ctx) = messages(&emit(&second).unwrap());
    assert!(ctx.contains("~/.claude/skills/managed"), "{ctx:?}");
    for text in [&sys, &ctx] {
        assert!(!text.contains("personal"), "personal skill swept: {text:?}");
    }
    assert!(lockfile(data.path())["skills"].get("personal").is_none());
    assert!(state_entry(data.path(), "/personal").is_none());
}

#[test]
fn install_from_an_absolute_claude_skills_dir_is_swept() {
    // `install --from ~/solana-ai-kit/.claude/skills`: the shell hands over an absolute
    // `…/.claude/skills` path, which must still count as an install into ~/.claude/skills.
    let project = TempDir::new("kit-proj");
    let home = TempDir::new("kit-home");
    let data = TempDir::new("kit-data");
    let kit = TempDir::new("kit-src");
    let skills = kit.join("kit").join(".claude").join("skills");
    std::fs::create_dir_all(skills.join("managed")).unwrap();
    std::fs::write(
        skills.join("managed").join("SKILL.md"),
        "# Managed\nFormats lamports.\n",
    )
    .unwrap();

    let run = Invocation::new(&["install", "--from", skills.to_str().unwrap()])
        .plugin_data(data.path())
        .home(home.path())
        .stdin("{}")
        .run();
    assert_eq!(run.json()["installed"][0], "managed", "{}", run.stdout);

    // The pin carries the install marker and the canonical source.
    let pin = lockfile(data.path())["skills"]["managed"].clone();
    assert_eq!(pin["origin"], "install", "{pin}");
    let canonical = std::fs::canonicalize(&skills).unwrap();
    assert_eq!(pin["source"], canonical.to_str().unwrap(), "{pin}");

    let first = verify_session(project.path(), home.path(), data.path());
    assert!(emit(&first).is_none(), "{}", first.stdout);
    tamper(
        &home
            .path()
            .join(".claude")
            .join("skills")
            .join("managed")
            .join("SKILL.md"),
    );
    assert_drift_blocked(
        &verify_session(project.path(), home.path(), data.path()),
        "managed",
    );
}

#[test]
fn in_place_install_marks_its_pins() {
    // `install` without `--from` verifies the project's `.claude/skills` in place; its pins are
    // marked, so a same-named personal skill is never taken for an installed one.
    let project = TempDir::new("inplace-proj");
    let other = TempDir::new("inplace-other");
    let home = TempDir::new("inplace-home");
    let data = TempDir::new("inplace-data");
    let helper = skills_root(project.path()).join("helper");
    std::fs::create_dir_all(&helper).unwrap();
    std::fs::write(helper.join("SKILL.md"), "# Helper\n").unwrap();

    let run = Invocation::new(&["install"])
        .plugin_data(data.path())
        .home(home.path())
        .cwd(project.path())
        .stdin("{}")
        .run();
    assert_eq!(run.json()["verified"][0], "helper", "{}", run.stdout);
    assert_eq!(
        lockfile(data.path())["skills"]["helper"]["origin"],
        "in-place"
    );

    // A personal `~/.claude/skills/helper`, seen from another project, is not that pin's pack.
    let personal = home.path().join(".claude").join("skills").join("helper");
    std::fs::create_dir_all(&personal).unwrap();
    std::fs::write(personal.join("SKILL.md"), "# Someone else's helper\n").unwrap();
    let run = verify_session(other.path(), home.path(), data.path());
    assert!(emit(&run).is_none(), "{}", run.stdout);
}

#[test]
fn mcp_json_findings_carry_path_line_for_user_and_model() {
    let project = TempDir::new("mcp-proj");
    let home = TempDir::new("mcp-home");
    let data = TempDir::new("mcp-data");
    std::fs::write(
        project.path().join(".mcp.json"),
        "{\n  \"mcpServers\": {\n    \"helius\": { \"command\": \"npx\", \"args\": [\"-y\", \"helius-mcp@latest\"] }\n  }\n}\n",
    )
    .unwrap();

    let v = emit(&verify_session(project.path(), home.path(), data.path()))
        .expect("the @latest MCP server must be reported");
    let (sys, ctx) = messages(&v);
    for (field, text) in [("systemMessage", &sys), ("additionalContext", &ctx)] {
        assert!(
            text.contains("helius") && text.contains(".mcp.json:3"),
            "{field} lacks helius at .mcp.json:3: {text:?}"
        );
    }
    assert!(ctx.contains("unpinned_mcp"), "{ctx:?}");
}

#[test]
fn user_scope_skills_not_swept_by_default() {
    let project = TempDir::new("scope-proj");
    let home = TempDir::new("scope-home");
    let data = TempDir::new("scope-data");
    let personal = home.path().join(".claude").join("skills").join("personal");
    std::fs::create_dir_all(&personal).unwrap();
    std::fs::write(personal.join("SKILL.md"), "# Personal\n").unwrap();
    std::fs::write(personal.join("load.sh"), KEYPAIR_SCRIPT).unwrap();

    // Both the embedded default (plugin root without a policy file) and the shipped
    // `default.policy.yaml` sweep only the project's `.claude/skills`.
    for plugin_root in [home.path().to_path_buf(), shipped_plugin_root()] {
        let run = Invocation::new(&["verify", "session"])
            .plugin_data(data.path())
            .home(home.path())
            .env("CLAUDE_PLUGIN_ROOT", plugin_root.to_str().unwrap())
            .stdin(payload(project.path()))
            .run();
        assert!(
            emit(&run).is_none(),
            "~/.claude/skills swept with plugin root {}: {}",
            plugin_root.display(),
            run.stdout
        );
    }
    assert!(personal.join("SKILL.md").exists());
    assert!(
        state_entry(data.path(), "/personal").is_none(),
        "a user-scope skill was recorded"
    );
}

#[test]
fn user_scope_skills_swept_when_listed_in_policy() {
    let project = TempDir::new("listed-proj");
    let home = TempDir::new("listed-home");
    let data = TempDir::new("listed-data");
    let plugin_root = TempDir::new("listed-plugin");
    std::fs::create_dir_all(plugin_root.join("policy")).unwrap();
    std::fs::write(
        plugin_root.join("policy").join("default.policy.yaml"),
        "version: 1\nsupply_chain:\n  verify_skills_dirs: [ \"~/.claude/skills\", \".claude/skills\" ]\n",
    )
    .unwrap();
    let personal = home.path().join(".claude").join("skills").join("personal");
    std::fs::create_dir_all(&personal).unwrap();
    std::fs::write(personal.join("SKILL.md"), "# Personal\n").unwrap();
    std::fs::write(personal.join("load.sh"), KEYPAIR_SCRIPT).unwrap();

    let run = Invocation::new(&["verify", "session"])
        .plugin_data(data.path())
        .home(home.path())
        .env("CLAUDE_PLUGIN_ROOT", plugin_root.path().to_str().unwrap())
        .stdin(payload(project.path()))
        .run();
    let v = emit(&run).expect("a listed user-scope root must be swept");
    let (sys, ctx) = messages(&v);
    let at = "~/.claude/skills/personal/load.sh:3";
    for text in [&sys, &ctx] {
        assert!(
            text.contains("WARN") && text.contains(at),
            "user-scope skill not reported at {at}: {text:?}"
        );
    }
    assert!(
        personal.join("SKILL.md").exists(),
        "user-scope skill was moved"
    );
    assert_eq!(
        state_entry(data.path(), "/personal").unwrap()["state"],
        "unreviewed"
    );
}

#[test]
fn approve_of_a_quarantined_skill_requests_a_restore_to_user_skills() {
    // Without a `.gitmodules` entry, a pack an earlier version moved to quarantine/ would go back
    // to `~/.claude/skills`, where 1.0.0 swept (and moved) it from, once the user confirms.
    let project = TempDir::new("approve-proj");
    let home = TempDir::new("approve-home");
    let data = TempDir::new("approve-data");
    seed_quarantined(data.path(), "pda-helper");

    let v = approve(project.path(), home.path(), data.path(), "pda-helper");

    let summary = v["summary"].as_str().unwrap_or_default();
    assert!(
        summary.contains("restore") && summary.contains(".claude/skills/pda-helper"),
        "{v}"
    );
    // Nothing moved yet.
    assert!(data.path().join("quarantine").join("pda-helper").exists());
    assert!(!home.path().join(".claude/skills/pda-helper").exists());
}

#[test]
fn approve_of_a_quarantined_submodule_targets_its_gitmodules_path() {
    // A quarantined `ext/` submodule goes back to the path `.gitmodules` declares for it, even
    // when approve runs from a subdirectory of the repo.
    let project = TempDir::new("approve-ext-proj");
    let home = TempDir::new("approve-ext-home");
    let data = TempDir::new("approve-ext-data");
    std::fs::create_dir_all(project.path().join(".git")).unwrap();
    std::fs::write(
        project.path().join(".gitmodules"),
        "[submodule \".claude/skills/ext/solana-dev\"]\n\
         \tpath = .claude/skills/ext/solana-dev\n\
         \turl = https://github.com/solana-foundation/solana-dev-skill\n",
    )
    .unwrap();
    let nested = project.path().join("programs").join("vault");
    std::fs::create_dir_all(&nested).unwrap();
    seed_quarantined(data.path(), "solana-dev");

    let v = approve_from(&nested, home.path(), data.path(), "solana-dev");

    let summary = v["summary"].as_str().unwrap_or_default();
    assert!(
        summary.contains("restore the quarantined ext")
            && summary.contains(".claude/skills/ext/solana-dev"),
        "{v}"
    );
    assert!(data.path().join("quarantine").join("solana-dev").exists());
}

#[test]
fn approve_of_an_unknown_pack_is_an_error() {
    let project = TempDir::new("approve-none-proj");
    let home = TempDir::new("approve-none-home");
    let data = TempDir::new("approve-none-data");
    let run = Invocation::new(&["verify", "approve", "ghost"])
        .plugin_data(data.path())
        .home(home.path())
        .cwd(project.path())
        .stdin("{}")
        .run();
    let v = run.json();
    assert_eq!(v["status"], "error", "{v}");
    assert!(v.get("nonce").is_none());
}

#[test]
fn trust_is_refused_for_an_untrusted_data_dir() {
    // A CLAUDE_PLUGIN_DATA outside the Claude Code plugin data root: trust would be ignored.
    let project = TempDir::new("trust-proj");
    let home = TempDir::new("trust-home");
    let data = TempDir::new("trust-data");
    let pack = skills_root(project.path()).join("p");
    std::fs::create_dir_all(&pack).unwrap();
    std::fs::write(pack.join("SKILL.md"), "# p\n").unwrap();
    let run = Invocation::new(&["verify", "trust", pack.to_str().unwrap()])
        .plugin_data(data.path())
        .home(home.path())
        .cwd(project.path())
        .stdin("{}")
        .run();
    let v = run.json();
    assert_eq!(v["status"], "error", "{v}");
    assert!(
        v["error"].as_str().unwrap_or_default().contains("ignored"),
        "{v}"
    );
}

#[test]
fn a_drifted_pack_is_never_moved_at_any_tier_by_default() {
    use safe_ai_skill::policy::tier::Tier;
    let project = TempDir::new("drift-tiers-proj");
    let home = TempDir::new("drift-tiers-home");
    let data = TempDir::new("drift-tiers-data");
    let skill = skills_root(project.path()).join("address-formatter");
    std::fs::create_dir_all(&skill).unwrap();
    std::fs::write(skill.join("SKILL.md"), "# Address Formatter\n").unwrap();
    assert!(emit(&verify_session(project.path(), home.path(), data.path())).is_none());
    tamper(&skill.join("SKILL.md"));
    for tier in [Tier::Relaxed, Tier::Medium, Tier::High] {
        let run = Invocation::new(&["verify", "session"])
            .plugin_data(data.path())
            .home(home.path())
            .tier(tier)
            .stdin(payload(project.path()))
            .run();
        let (sys, ctx) = messages(&emit(&run).expect("a drift report"));
        for text in [&sys, &ctx] {
            assert!(
                text.contains("BLOCK") && text.contains("address-formatter"),
                "{text}"
            );
            assert!(!text.contains("MOVED"), "{text}");
        }
        assert!(sys.contains("safe-ai-skill verify approve"), "{sys}");
        assert!(skill.join("SKILL.md").exists(), "moved at {tier:?}");
        assert!(!data.path().join("quarantine").exists());
    }
}
