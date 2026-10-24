//! A custom `$CLAUDE_CONFIG_DIR` (it replaces `~/.claude`) is protected like `~/.claude`:
//! transcripts under `projects/` and the config dir's credentials file are read-denied
//! through Read, Grep (root and exclusion globs) and Bash, including words that name the
//! config dir as a literal `$CLAUDE_CONFIG_DIR` / `${CLAUDE_CONFIG_DIR}`.

mod common;

use common::{decision_label, Invocation, Run, TempDir};
use serde_json::{json, Value};

struct World {
    home: TempDir,
    cfg: TempDir,
    proj: TempDir,
    data: TempDir,
}

impl World {
    fn new(tag: &str) -> World {
        let w = World {
            home: TempDir::new(&format!("{tag}-home")),
            cfg: TempDir::new(&format!("{tag}-cfg")),
            proj: TempDir::new(&format!("{tag}-proj")),
            data: TempDir::new(&format!("{tag}-data")),
        };
        std::fs::create_dir_all(w.cfg.join("projects/p")).unwrap();
        std::fs::write(
            w.cfg.join("projects/p/t.jsonl"),
            "safe-ai-skill confirm 12345678\n",
        )
        .unwrap();
        w
    }

    fn run(&self, sub: &str, tool: &str, input: Value) -> Run {
        Invocation::new(&[sub])
            .plugin_data(self.data.path())
            .home(self.home.path())
            .cwd(self.proj.path())
            .env("CLAUDE_CONFIG_DIR", self.cfg.path().to_str().unwrap())
            .stdin(
                json!({"hook_event_name":"PreToolUse","tool_name": tool,
                       "cwd": self.proj.path(), "tool_input": input})
                .to_string(),
            )
            .run()
    }

    fn cfg(&self, rel: &str) -> String {
        let base = common::sh_path(self.cfg.path());
        if rel.is_empty() {
            base
        } else {
            format!("{base}/{rel}")
        }
    }
}

#[test]
fn read_and_grep_roots_inside_the_config_dir_transcripts_deny() {
    let w = World::new("cfgdir-roots");
    let read = w.run(
        "gate-read",
        "Read",
        json!({"file_path": w.cfg("projects/p/t.jsonl")}),
    );
    assert_eq!(decision_label(&read), "deny");
    for path in [w.cfg("projects"), w.cfg("projects/p")] {
        let run = w.run(
            "gate-read",
            "Grep",
            json!({"pattern":"confirm","path": path}),
        );
        assert_eq!(decision_label(&run), "deny", "{path}");
    }
}

#[test]
fn a_grep_over_the_config_dir_excludes_its_transcripts_and_credentials() {
    let w = World::new("cfgdir-excl");
    let name = w
        .cfg
        .path()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_ascii_lowercase();
    let two_case = |s: &str| -> String {
        s.chars()
            .map(|c| {
                if c.is_ascii_alphabetic() {
                    format!("[{}{}]", c.to_ascii_lowercase(), c.to_ascii_uppercase())
                } else {
                    c.to_string()
                }
            })
            .collect()
    };
    for path in [w.cfg(""), w.cfg("").rsplit_once('/').unwrap().0.to_string()] {
        let run = w.run(
            "gate-read",
            "Grep",
            json!({"pattern":"confirm","path": path}),
        );
        let glob = run.json()["hookSpecificOutput"]["updatedInput"]["glob"]
            .as_str()
            .unwrap_or_else(|| panic!("{}", run.stdout))
            .to_string();
        for part in [
            two_case(&format!("**/{name}/projects/**")),
            two_case(&format!("**/{name}/.credentials.json")),
        ] {
            assert!(glob.contains(&part), "{path}: {part} not in {glob}");
        }
    }
    // Searched from inside it (path omitted, `.`): ripgrep prints `projects/…`.
    let run = Invocation::new(&["gate-read"])
        .plugin_data(w.data.path())
        .home(w.home.path())
        .cwd(w.cfg.path())
        .env("CLAUDE_CONFIG_DIR", &w.cfg(""))
        .stdin(
            json!({"hook_event_name":"PreToolUse","tool_name":"Grep","cwd": w.cfg(""),
                   "tool_input":{"pattern":"confirm"}})
            .to_string(),
        )
        .run();
    let glob = run.json()["hookSpecificOutput"]["updatedInput"]["glob"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        glob.contains(&format!(",{}", two_case("projects/**"))),
        "{glob}"
    );
}

#[test]
fn bash_words_naming_the_config_dir_variable_deny() {
    let w = World::new("cfgdir-bash");
    for command in [
        "grep -r confirm $CLAUDE_CONFIG_DIR/projects".to_string(),
        "grep -r confirm ${CLAUDE_CONFIG_DIR}/projects/p".to_string(),
        "cat \"$CLAUDE_CONFIG_DIR\"/projects/p/t.jsonl".to_string(),
        "grep -r confirm $CLAUDE_CONFIG_DIR".to_string(),
        "rg confirm ${CLAUDE_CONFIG_DIR:-~/.claude}".to_string(),
        "cd $CLAUDE_CONFIG_DIR && grep -r confirm .".to_string(),
        "cat $CLAUDE_CONFIG_DIR/.credentials.json".to_string(),
        format!("grep -r confirm {}", w.cfg("projects")),
        format!("grep -r confirm {}", w.cfg("")),
    ] {
        let run = w.run("gate-bash-secrets", "Bash", json!({ "command": command }));
        assert_eq!(decision_label(&run), "deny", "{command}: {}", run.stdout);
    }
    for command in [
        "ls $CLAUDE_CONFIG_DIR",
        "echo $CLAUDE_CONFIG_DIR_X/projects",
        "grep -r confirm src",
    ] {
        let run = w.run("gate-bash-secrets", "Bash", json!({ "command": command }));
        assert_eq!(decision_label(&run), "", "{command}: {}", run.stdout);
    }
}

#[test]
fn the_default_config_dir_stays_protected_beside_a_custom_one() {
    let w = World::new("cfgdir-default");
    let home = w.home.path().to_str().unwrap().to_string();
    std::fs::create_dir_all(w.home.join(".claude/projects/p")).unwrap();
    let read = w.run(
        "gate-read",
        "Read",
        json!({"file_path": format!("{home}/.claude/projects/p/t.jsonl")}),
    );
    assert_eq!(decision_label(&read), "deny");
    let run = w.run(
        "gate-bash-secrets",
        "Bash",
        json!({"command": "grep -r confirm ~/.claude/projects"}),
    );
    assert_eq!(decision_label(&run), "deny");
}

#[cfg(unix)]
#[test]
fn bash_reads_through_cd_relative_paths_and_symlinks_deny() {
    let w = World::new("cfgdir-rel");
    let home = w.home.path().to_path_buf();
    std::fs::create_dir_all(home.join(".claude/projects/p")).unwrap();
    std::fs::write(home.join(".claude/projects/p/t.jsonl"), "x\n").unwrap();
    std::os::unix::fs::symlink(w.cfg.path(), w.proj.join("link")).unwrap();
    std::os::unix::fs::symlink(w.cfg.join("projects"), w.proj.join("plink")).unwrap();
    std::os::unix::fs::symlink(home.join(".claude"), w.proj.join("hlink")).unwrap();
    for command in [
        "cd $CLAUDE_CONFIG_DIR; cat projects/p/t.jsonl",
        "cd $CLAUDE_CONFIG_DIR && cat projects/p/t.jsonl",
        "cat link/projects/p/t.jsonl",
        "cat link/projects/p/*",
        "grep -r x plink",
        "cd ~/.claude && cat projects/p/t.jsonl",
        "cd ~/.claude/projects/p && cat t.jsonl",
        "cat hlink/projects/p/t.jsonl",
    ] {
        let run = w.run("gate-bash-secrets", "Bash", json!({ "command": command }));
        assert_eq!(decision_label(&run), "deny", "{command}: {}", run.stdout);
    }
    let run = w.run(
        "gate-bash-secrets",
        "Bash",
        json!({"command": "cat link/settings.json"}),
    );
    assert_eq!(decision_label(&run), "", "{}", run.stdout);
}

#[test]
fn mcp_directory_arguments_holding_claude_state_deny() {
    let w = World::new("cfgdir-mcp");
    std::fs::create_dir_all(w.home.join(".claude")).unwrap();
    std::fs::create_dir_all(w.proj.join("src")).unwrap();
    let home = w.home.path().to_str().unwrap().to_string();
    for path in [w.cfg(""), format!("{home}/.claude"), home.clone()] {
        let run = w.run(
            "gate-mcp",
            "mcp__filesystem__search_files",
            json!({"path": path, "pattern": "confirm"}),
        );
        assert_eq!(decision_label(&run), "deny", "{path}: {}", run.stdout);
    }
    let src = w.proj.join("src").to_str().unwrap().to_string();
    let run = w.run(
        "gate-mcp",
        "mcp__filesystem__search_files",
        json!({"path": src, "pattern": "confirm"}),
    );
    assert_eq!(decision_label(&run), "", "{}", run.stdout);
}
