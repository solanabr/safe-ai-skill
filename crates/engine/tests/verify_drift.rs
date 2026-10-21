//! Sandboxed `verify session` sweep: TOFU drift, swept roots, and `verify approve`.
//!
//! Places a clean fixture skill under a sandbox project's `.claude/skills`, pins it with a first
//! `verify session` sweep, tampers one byte, then re-runs `verify session` and asserts the drift
//! is reported (a WARN in the SessionStart `systemMessage` + `additionalContext`) on every
//! session, the skill staying where it is, until `verify approve` re-pins it. Also covers which
//! roots are swept (the user-scope `~/.claude/skills` only when the policy lists it, or for packs
//! `install --from` put there), `.mcp.json` findings, and `verify approve` restoring packs that an
//! earlier version moved into `quarantine/`.
//!
//! Fully hermetic: the project, HOME and CLAUDE_PLUGIN_DATA are sandbox temp dirs, so the sweep
//! scans only the fixtures and writes lockfile/quarantine only inside the sandbox.

mod common;

use common::{Invocation, Run, TempDir};
use std::path::{Path, PathBuf};

/// A telemetry preamble (outbound POST): a High finding wherever it is swept.
const TELEMETRY_SKILL_MD: &str = "# Personal\n\n\
```bash\ncurl -s -X POST \"$U/api/mutation\" -d '{}'\n```\n";

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

/// The sandbox lockfile, parsed (`{}` when no sweep has written one).
fn lockfile(data: &Path) -> serde_json::Value {
    std::fs::read_to_string(data.join("lockfile.json"))
        .map(|body| serde_json::from_str(&body).unwrap())
        .unwrap_or_else(|_| serde_json::json!({}))
}

/// Seed a pack that an earlier version moved to `<data>/quarantine/<name>`.
fn seed_quarantined(data: &Path, name: &str) {
    let dir = data.join("quarantine").join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("SKILL.md"), format!("# {name}\n")).unwrap();
}

/// Run `verify approve <name>` from `cwd` (as a user would in a terminal).
fn approve_from(cwd: &Path, home: &Path, data: &Path, name: &str) -> serde_json::Value {
    let run = Invocation::new(&["verify", "approve", name])
        .plugin_data(data)
        .home(home)
        .cwd(cwd)
        .stdin("{}")
        .run();
    let v = run.json();
    assert_eq!(v["status"], "approved", "approve failed: {}", run.stdout);
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

/// Assert `run` reports a drift WARN for `name`, to both the user and the model.
fn assert_drift_reported(run: &Run, name: &str) {
    let v = emit(run).unwrap_or_else(|| panic!("drift of {name} not reported"));
    let (sys, ctx) = messages(&v);
    for (field, text) in [("systemMessage", &sys), ("additionalContext", &ctx)] {
        let lower = text.to_lowercase();
        assert!(
            lower.contains("warn") && lower.contains(name) && lower.contains("drift"),
            "{field} did not report the drifted {name}: {text:?}"
        );
    }
}

#[test]
fn drift_warns_every_session_until_approved() {
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

    // 1. First sweep pins the clean skill (TOFU) and has nothing to report.
    let first = verify_session(project.path(), home.path(), data.path());
    assert!(
        emit(&first).is_none(),
        "clean first sweep must emit nothing: {}",
        first.stdout
    );
    let pinned = lockfile(data.path())["skills"]["address-formatter"]["sha256"].clone();
    assert!(pinned.is_string(), "skill not pinned after the first sweep");

    // 2. Tamper one byte in the pinned skill: every following session reports the drift.
    let md_path = skill.join("SKILL.md");
    tamper(&md_path);
    for _ in 0..2 {
        assert_drift_reported(
            &verify_session(project.path(), home.path(), data.path()),
            "address-formatter",
        );
    }
    // The pin is kept, the skill stays in the skills root, nothing is quarantined.
    assert_eq!(
        lockfile(data.path())["skills"]["address-formatter"]["sha256"],
        pinned,
        "a drifted pack must keep its pin until approved"
    );
    assert!(md_path.exists(), "drifted skill was moved");
    assert!(
        !data.path().join("quarantine").exists(),
        "nothing may be moved to quarantine"
    );

    // 3. Approving re-pins the skill where it is; the next session is clean.
    let v = approve(
        project.path(),
        home.path(),
        data.path(),
        "address-formatter",
    );
    let in_place = v["pinned_in_place"][0].as_str().unwrap_or_default();
    assert!(
        Path::new(in_place).ends_with(".claude/skills/address-formatter"),
        "{v}"
    );
    assert_eq!(
        lockfile(data.path())["skills"]["address-formatter"]["scan"],
        "approved"
    );
    let last = verify_session(project.path(), home.path(), data.path());
    assert!(
        emit(&last).is_none(),
        "approved content re-reported: {}",
        last.stdout
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
    assert_drift_reported(&second, "managed");
    let (sys, ctx) = messages(&emit(&second).unwrap());
    assert!(ctx.contains("~/.claude/skills/managed"), "{ctx:?}");
    for text in [&sys, &ctx] {
        assert!(!text.contains("personal"), "personal skill swept: {text:?}");
    }
    assert!(lockfile(data.path())["skills"].get("personal").is_none());
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
    std::fs::write(personal.join("SKILL.md"), TELEMETRY_SKILL_MD).unwrap();

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
        lockfile(data.path())["skills"].get("personal").is_none(),
        "a user-scope skill was pinned"
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
    std::fs::write(personal.join("SKILL.md"), TELEMETRY_SKILL_MD).unwrap();

    let run = Invocation::new(&["verify", "session"])
        .plugin_data(data.path())
        .home(home.path())
        .env("CLAUDE_PLUGIN_ROOT", plugin_root.path().to_str().unwrap())
        .stdin(payload(project.path()))
        .run();
    let v = emit(&run).expect("a listed user-scope root must be swept");
    let (sys, ctx) = messages(&v);
    let at = "~/.claude/skills/personal/SKILL.md:4";
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
}

#[test]
fn approve_restores_quarantined_skill_to_user_skills() {
    // Without a `.gitmodules` entry, a pack an earlier version moved to quarantine/ goes back to
    // `~/.claude/skills`, where 1.0.0 swept (and moved) it from.
    let project = TempDir::new("approve-proj");
    let home = TempDir::new("approve-home");
    let data = TempDir::new("approve-data");
    seed_quarantined(data.path(), "pda-helper");

    let v = approve(project.path(), home.path(), data.path(), "pda-helper");

    let restored = home
        .path()
        .join(".claude")
        .join("skills")
        .join("pda-helper");
    assert!(
        restored.join("SKILL.md").exists(),
        "approve did not restore under {}: {v}",
        restored.display()
    );
    assert!(!skills_root(project.path()).join("pda-helper").exists());
    assert!(
        !data.path().join("quarantine").join("pda-helper").exists(),
        "quarantine entry should be consumed on approve"
    );
    assert_eq!(
        lockfile(data.path())["skills"]["pda-helper"]["scan"],
        "approved"
    );
}

#[test]
fn approve_restores_gitmodules_ext_pack_to_its_submodule_path() {
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

    let restored = skills_root(project.path()).join("ext").join("solana-dev");
    assert!(
        restored.join("SKILL.md").exists(),
        "approve did not restore the submodule to {}: {v}",
        restored.display()
    );
    assert!(!data.path().join("quarantine").join("solana-dev").exists());
    let lock = lockfile(data.path());
    assert_eq!(lock["ext"]["solana-dev"]["scan"], "approved", "{lock}");
    assert!(lock["skills"].get("solana-dev").is_none(), "{lock}");
}
