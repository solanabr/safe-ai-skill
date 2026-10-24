//! Enforcement of a blocked skill pack in place (spec D2.6), end to end through the hooks:
//! `gate-skill` (PreToolUse `Skill`), `gate-prompt-expansion` (`UserPromptExpansion` and a
//! raw `/name` in `UserPromptSubmit`), `gate-read` (Read/Grep/Glob) and `gate-bash-secrets`
//! (every Bash call). A pack is blocked here by drift: recorded by a first sweep, then edited.

mod common;

use common::{permission_decision, Invocation, Run, TempDir};
use safe_ai_skill::policy::tier::Tier;
use std::path::PathBuf;

struct Fixture {
    project: TempDir,
    home: TempDir,
    data: TempDir,
}

impl Fixture {
    /// `.claude/skills/ext/evil` (blocked) and `.claude/skills/fine` (clean).
    fn new(tag: &str) -> Fixture {
        let f = Fixture {
            project: TempDir::new(&format!("{tag}-proj")),
            home: TempDir::new(&format!("{tag}-home")),
            data: TempDir::new(&format!("{tag}-data")),
        };
        let evil = f.evil();
        std::fs::create_dir_all(&evil).unwrap();
        std::fs::write(evil.join("SKILL.md"), "---\nname: evil-tool\n---\n# evil\n").unwrap();
        std::fs::write(evil.join("s1.sh"), "echo one\n").unwrap();
        let fine = f.skills().join("fine");
        std::fs::create_dir_all(&fine).unwrap();
        std::fs::write(fine.join("SKILL.md"), "# fine\n").unwrap();
        assert!(f.session().stdout.trim().is_empty());
        std::fs::write(evil.join("s1.sh"), "echo one\necho two\n").unwrap();
        assert!(f.session().stdout.contains("BLOCK"));
        f
    }

    fn skills(&self) -> PathBuf {
        self.project.path().join(".claude").join("skills")
    }

    fn evil(&self) -> PathBuf {
        self.skills().join("ext").join("evil")
    }

    fn cwd(&self) -> &str {
        self.project.path().to_str().unwrap()
    }

    fn run(&self, args: &[&str], stdin: serde_json::Value) -> Run {
        Invocation::new(args)
            .plugin_data(self.data.path())
            .home(self.home.path())
            .stdin(stdin.to_string())
            .run()
    }

    fn session(&self) -> Run {
        self.run(
            &["verify", "session"],
            serde_json::json!({"hook_event_name": "SessionStart", "source": "startup", "cwd": self.cwd()}),
        )
    }

    fn pretool(&self, sub: &str, tool: &str, input: serde_json::Value) -> Run {
        self.run(
            &[sub],
            serde_json::json!({
                "hook_event_name": "PreToolUse", "session_id": "s", "cwd": self.cwd(),
                "tool_name": tool, "tool_input": input,
            }),
        )
    }
}

/// The decision a PreToolUse run emitted (`""` for no opinion), with its reason.
fn decision(run: &Run) -> (String, String) {
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    if run.stdout.trim().is_empty() {
        return (String::new(), String::new());
    }
    let v = run.json();
    (
        permission_decision(&v).unwrap_or_default(),
        v["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    )
}

fn assert_denied_naming_the_pack(run: &Run) {
    let (d, reason) = decision(run);
    assert_eq!(d, "deny", "{}", run.stdout);
    assert!(
        reason.contains("ext/evil") && reason.contains("verify approve"),
        "{reason}"
    );
}

#[test]
fn skill_tool_on_a_blocked_pack_is_denied_and_a_clean_one_is_not() {
    let f = Fixture::new("sg-skill");
    for name in ["evil", "evil-tool"] {
        assert_denied_naming_the_pack(&f.pretool(
            "gate-skill",
            "Skill",
            serde_json::json!({"skill": name}),
        ));
    }
    let (d, _) = decision(&f.pretool("gate-skill", "Skill", serde_json::json!({"skill": "fine"})));
    assert_eq!(d, "");
    assert!(f.evil().join("SKILL.md").exists(), "never moved");
}

#[test]
fn a_pack_edited_mid_session_is_denied_on_its_next_use() {
    let f = Fixture::new("sg-toctou");
    let fine = f.skills().join("fine");
    std::fs::write(fine.join("SKILL.md"), "# fine, now edited\n").unwrap();
    let (d, reason) =
        decision(&f.pretool("gate-skill", "Skill", serde_json::json!({"skill": "fine"})));
    assert_eq!(d, "deny", "{reason}");
    assert!(reason.contains("skills/fine"), "{reason}");
}

#[test]
fn typed_slash_commands_are_blocked_at_both_prompt_events() {
    let f = Fixture::new("sg-slash");
    let upe = f.run(
        &["gate-prompt-expansion"],
        serde_json::json!({
            "hook_event_name": "UserPromptExpansion", "cwd": f.cwd(),
            "expansion_type": "slash_command", "command_name": "evil", "command_args": "now",
            "command_source": "projectSettings", "prompt": "/evil now",
        }),
    );
    let ups = f.run(
        &["gate-prompt-expansion"],
        serde_json::json!({"hook_event_name": "UserPromptSubmit", "cwd": f.cwd(), "prompt": "/evil-tool now"}),
    );
    for run in [&upe, &ups] {
        assert_eq!(run.code, Some(0));
        let v = run.json();
        assert_eq!(v["decision"], "block", "{v}");
        assert!(v["reason"].as_str().unwrap().contains("ext/evil"), "{v}");
    }
    for prompt in ["/fine go", "please look at evil", "/clear"] {
        let run = f.run(
            &["gate-prompt-expansion"],
            serde_json::json!({"hook_event_name": "UserPromptSubmit", "cwd": f.cwd(), "prompt": prompt}),
        );
        assert!(run.stdout.trim().is_empty(), "{prompt}: {}", run.stdout);
    }
}

#[test]
fn reads_and_shell_access_under_a_blocked_pack_are_denied() {
    let f = Fixture::new("sg-paths");
    let inside = f.evil().join("s1.sh");
    assert_denied_naming_the_pack(&f.pretool(
        "gate-read",
        "Read",
        serde_json::json!({"file_path": inside}),
    ));
    assert_denied_naming_the_pack(&f.pretool(
        "gate-read",
        "Grep",
        serde_json::json!({"pattern": "echo", "path": ".claude/skills/ext/evil"}),
    ));
    let (d, _) = decision(&f.pretool(
        "gate-read",
        "Read",
        serde_json::json!({"file_path": f.skills().join("fine/SKILL.md")}),
    ));
    assert_eq!(d, "");

    for cmd in [
        "cd .claude/skills; cd ext; cd evil; sh s*.sh",
        "sh .claude/skills/ext/e*/s1.sh",
    ] {
        assert_denied_naming_the_pack(&f.pretool(
            "gate-bash-secrets",
            "Bash",
            serde_json::json!({"command": cmd}),
        ));
    }
    for cmd in ["cd elsewhere && ls", "ls .claude/skills"] {
        let (d, _) = decision(&f.pretool(
            "gate-bash-secrets",
            "Bash",
            serde_json::json!({"command": cmd}),
        ));
        assert_eq!(d, "", "{cmd}");
    }
}

#[test]
fn nothing_blocked_means_the_gates_stay_silent() {
    let project = TempDir::new("sg-none-proj");
    let home = TempDir::new("sg-none-home");
    let data = TempDir::new("sg-none-data");
    let skill = project.path().join(".claude/skills/fine");
    std::fs::create_dir_all(&skill).unwrap();
    std::fs::write(skill.join("SKILL.md"), "# fine\n").unwrap();
    let cwd = project.path().to_str().unwrap();
    for (sub, tool, input) in [
        ("gate-skill", "Skill", serde_json::json!({"skill": "fine"})),
        (
            "gate-read",
            "Read",
            serde_json::json!({"file_path": skill.join("SKILL.md")}),
        ),
        (
            "gate-bash-secrets",
            "Bash",
            serde_json::json!({"command": "cat .claude/skills/fine/SKILL.md"}),
        ),
    ] {
        let run = Invocation::new(&[sub])
            .plugin_data(data.path())
            .home(home.path())
            .stdin(
                serde_json::json!({
                    "hook_event_name": "PreToolUse", "cwd": cwd,
                    "tool_name": tool, "tool_input": input,
                })
                .to_string(),
            )
            .run();
        assert_eq!((run.code, run.stdout.trim()), (Some(0), ""), "{sub}");
    }
}

#[test]
fn a_project_wide_grep_reaching_a_blocked_pack_is_denied() {
    let f = Fixture::new("sg-grep");
    std::fs::create_dir_all(f.project.path().join("src")).unwrap();
    assert_denied_naming_the_pack(&f.pretool(
        "gate-read",
        "Grep",
        serde_json::json!({"pattern": "echo"}),
    ));
    let (d, _) = decision(&f.pretool(
        "gate-read",
        "Grep",
        serde_json::json!({"pattern": "echo", "path": "src"}),
    ));
    assert_eq!(d, "");
}

#[test]
fn an_oversized_slash_prompt_for_a_blocked_pack_is_blocked() {
    let f = Fixture::new("sg-big");
    let mut prompt = String::from("/evil ");
    prompt.push_str(&"x".repeat(1024 * 1024 + 16));
    let body = serde_json::json!({"hook_event_name": "UserPromptSubmit", "prompt": prompt});
    let run = Invocation::new(&["gate-prompt-expansion"])
        .plugin_data(f.data.path())
        .home(f.home.path())
        .cwd(f.project.path())
        .stdin(body.to_string())
        .run();
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    let v = run.json();
    assert_eq!(v["decision"], "block", "{v}");
    // An oversized ordinary prompt is not.
    let body = serde_json::json!({
        "hook_event_name": "UserPromptSubmit",
        "prompt": "x".repeat(1024 * 1024 + 16),
    });
    let run = Invocation::new(&["gate-prompt-expansion"])
        .plugin_data(f.data.path())
        .home(f.home.path())
        .cwd(f.project.path())
        .stdin(body.to_string())
        .run();
    assert!(run.stdout.trim().is_empty(), "{}", run.stdout);
}

#[test]
fn home_relative_paths_into_a_blocked_user_pack_are_denied() {
    let project = TempDir::new("sg-home-proj");
    let home = TempDir::new("sg-home-home");
    let data = TempDir::new("sg-home-data");
    let plugin = TempDir::new("sg-home-plugin");
    std::fs::create_dir_all(plugin.join("policy")).unwrap();
    std::fs::write(
        plugin.join("policy").join("default.policy.yaml"),
        "version: 1\nsupply_chain:\n  verify_skills_dirs: [ \"~/.claude/skills\", \".claude/skills\" ]\n",
    )
    .unwrap();
    let pack = home.path().join(".claude/skills/hpack");
    std::fs::create_dir_all(&pack).unwrap();
    std::fs::write(pack.join("SKILL.md"), "# hpack\n").unwrap();
    let cwd = project.path().to_str().unwrap();
    let run = |args: &[&str], stdin: serde_json::Value| {
        Invocation::new(args)
            .plugin_data(data.path())
            .home(home.path())
            .env("CLAUDE_PLUGIN_ROOT", plugin.path().to_str().unwrap())
            .stdin(stdin.to_string())
            .run()
    };
    let session = serde_json::json!({"hook_event_name": "SessionStart", "cwd": cwd});
    assert!(run(&["verify", "session"], session.clone())
        .stdout
        .trim()
        .is_empty());
    std::fs::write(pack.join("SKILL.md"), "# hpack, edited\n").unwrap();
    assert!(run(&["verify", "session"], session)
        .stdout
        .contains("BLOCK"));
    for cmd in [
        "cat $HOME/.claude/skills/hpack/SKILL.md",
        "cat ${HOME}/.claude/skills/hpack/SKILL.md",
        "cat ~/.claude/skills/hpack/SKILL.md",
        "cd; cd .claude/skills/hpack",
    ] {
        let out = run(
            &["gate-bash-secrets"],
            serde_json::json!({
                "hook_event_name": "PreToolUse", "cwd": cwd, "tool_name": "Bash",
                "tool_input": {"command": cmd},
            }),
        );
        let (d, reason) = decision(&out);
        assert_eq!(d, "deny", "{cmd}: {}", out.stdout);
        assert!(reason.contains("hpack"), "{reason}");
    }
    // An unreadable expansion whose name lies past the readable head is blocked while a
    // user-level pack (loaded in every project) is blocked.
    let other = TempDir::new("sg-home-other");
    let body = format!(
        r#"{{"hook_event_name":"UserPromptExpansion","cwd":"{}","prompt":"{}","command_name":"anything"}}"#,
        other.path().display(),
        "x".repeat(1024 * 1024 + 16)
    );
    let out = Invocation::new(&["gate-prompt-expansion"])
        .plugin_data(data.path())
        .home(home.path())
        .cwd(other.path())
        .env("CLAUDE_PLUGIN_ROOT", plugin.path().to_str().unwrap())
        .stdin(body)
        .run();
    assert_eq!(out.json()["decision"], "block", "{}", out.stdout);
}

#[test]
fn an_unreadable_prompt_is_judged_in_the_payload_cwd() {
    let f = Fixture::new("sg-cwd");
    let elsewhere = TempDir::new("sg-cwd-elsewhere");
    let body = format!(
        r#"{{"hook_event_name":"UserPromptSubmit","cwd":"{}","prompt":"/evil {}"}}"#,
        f.cwd(),
        "x".repeat(1024 * 1024 + 16)
    );
    let run = Invocation::new(&["gate-prompt-expansion"])
        .plugin_data(f.data.path())
        .home(f.home.path())
        .cwd(elsewhere.path())
        .stdin(body)
        .run();
    assert_eq!(run.json()["decision"], "block", "{}", run.stdout);
}

#[test]
fn a_blocked_pack_stays_denied_at_medium_and_high_with_the_tier_selected() {
    let f = Fixture::new("sg-tiers");
    for tier in [Tier::Medium, Tier::High] {
        let run = Invocation::new(&["gate-skill"])
            .plugin_data(f.data.path())
            .home(f.home.path())
            .tier(tier)
            .stdin(
                serde_json::json!({
                    "hook_event_name": "PreToolUse", "cwd": f.cwd(),
                    "tool_name": "Skill", "tool_input": {"skill": "evil"},
                })
                .to_string(),
            )
            .run();
        assert_denied_naming_the_pack(&run);
    }
    assert!(f.evil().join("SKILL.md").exists(), "never moved");
}

#[test]
fn a_clean_pack_is_not_touched_by_the_high_tier() {
    let f = Fixture::new("sg-high-clean");
    let run = Invocation::new(&["gate-skill"])
        .plugin_data(f.data.path())
        .home(f.home.path())
        .tier(Tier::High)
        .stdin(
            serde_json::json!({
                "hook_event_name": "PreToolUse", "cwd": f.cwd(),
                "tool_name": "Skill", "tool_input": {"skill": "fine"},
            })
            .to_string(),
        )
        .run();
    assert_eq!((run.code, run.stdout.trim()), (Some(0), ""));
}
