//! Enforcement of a blocked skill pack in place (spec D2.6), end to end through the hooks:
//! `gate-skill` (PreToolUse `Skill`), `gate-prompt-expansion` (`UserPromptExpansion` and a
//! raw `/name` in `UserPromptSubmit`), `gate-read` (Read/Grep/Glob) and `gate-bash-secrets`
//! (every Bash call). A pack is blocked here by drift: recorded by a first sweep, then edited.

mod common;

use common::{permission_decision, Invocation, Run, TempDir};
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
