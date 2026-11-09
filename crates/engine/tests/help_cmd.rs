//! `--help`, `-h` and `help [<command>]`, and `<command> --help|-h`: usage on stdout and exit 0,
//! printed before any handler runs, so a help request never performs the action. Unknown
//! subcommands and the hook entry points keep their behaviour.

mod common;

use std::path::Path;

use common::{Invocation, Run, TempDir};

/// The commands whose usage `help <command>` and `<command> --help|-h` print.
const COMMANDS: &[&str] = &[
    "tier", "mode", "allow", "revoke", "status", "session", "firewall", "env", "verify", "add",
    "install", "registry", "doctor",
];

/// Run `args` with a fresh plugin data dir, home and project dir, and assert that all three are
/// still empty afterwards: nothing was written.
fn run_writing_nothing(args: &[&str]) -> Run {
    let data = TempDir::new("help-data");
    let home = TempDir::new("help-home");
    let project = TempDir::new("help-proj");
    let run = Invocation::new(args)
        .plugin_data(data.path())
        .home(home.path())
        .cwd(project.path())
        .stdin("")
        .run();
    for dir in [data.path(), home.path(), project.path()] {
        assert_eq!(
            entries(dir),
            Vec::<String>::new(),
            "{args:?} wrote into {dir:?}"
        );
    }
    run
}

fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("read dir")
        .map(|e| {
            e.expect("dir entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

fn assert_help(run: &Run, what: &str) {
    assert_eq!(run.code, Some(0), "{what}: {}", run.stderr);
    assert!(!run.stdout.trim().is_empty(), "{what}: empty stdout");
    assert_eq!(run.stderr, "", "{what}");
}

#[test]
fn help_flags_print_the_overview() {
    let overview = run_writing_nothing(&["--help"]);
    assert_help(&overview, "--help");
    for args in [
        &["-h"][..],
        &["help"],
        &["help", "help"],
        &["help", "--help"],
    ] {
        let run = run_writing_nothing(args);
        assert_help(&run, &format!("{args:?}"));
        assert_eq!(run.stdout, overview.stdout, "{args:?}");
    }
    let text = &overview.stdout;
    assert!(text.contains("usage: safe-ai-skill <command>"), "{text}");
    assert!(text.contains("docs/cli.md"), "{text}");
    for cmd in COMMANDS.iter().filter(|c| **c != "mode").chain(&["adapt"]) {
        assert!(
            text.lines().any(|l| l.starts_with(&format!("  {cmd} "))),
            "overview should list `{cmd}`:\n{text}"
        );
    }
}

#[test]
fn command_help_is_the_same_three_ways() {
    for cmd in COMMANDS {
        let help = run_writing_nothing(&["help", cmd]);
        assert_help(&help, &format!("help {cmd}"));
        assert!(
            help.stdout.contains(&format!("safe-ai-skill {cmd}")),
            "help {cmd}:\n{}",
            help.stdout
        );
        for flag in ["--help", "-h"] {
            let run = run_writing_nothing(&[cmd, flag]);
            assert_help(&run, &format!("{cmd} {flag}"));
            assert_eq!(run.stdout, help.stdout, "{cmd} {flag}");
        }
    }
}

#[test]
fn env_help_is_envs_own_usage() {
    let run = run_writing_nothing(&["help", "env"]);
    for line in [
        "safe-ai-skill env keys",
        "safe-ai-skill env set",
        "safe-ai-skill env unset",
        "safe-ai-skill env init-schema",
    ] {
        assert!(run.stdout.contains(line), "{line}:\n{}", run.stdout);
    }
    assert_eq!(run_writing_nothing(&["env", "help"]).stdout, run.stdout);
}

#[test]
fn help_flag_after_the_command_never_runs_it() {
    // Control: a bare `revoke` writes the grants file and an audit entry.
    let data = TempDir::new("help-revoke");
    let run = Invocation::new(&["revoke"])
        .plugin_data(data.path())
        .stdin("")
        .run();
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert!(
        data.join("grants.json").exists(),
        "{:?}",
        entries(data.path())
    );

    for args in [
        &["revoke", "--help"][..],
        &["revoke", "-h"],
        &["revoke", "--help", "--now"],
    ] {
        let run = run_writing_nothing(args);
        assert_help(&run, &format!("{args:?}"));
        assert!(
            run.stdout.contains("safe-ai-skill revoke"),
            "{}",
            run.stdout
        );
    }
}

#[test]
fn install_help_pins_nothing_in_the_project() {
    let data = TempDir::new("help-install-data");
    let project = TempDir::new("help-install-proj");
    let skill = project.join(".claude/skills/demo");
    std::fs::create_dir_all(&skill).expect("create skill dir");
    std::fs::write(skill.join("SKILL.md"), "---\nname: demo\n---\nhello\n").expect("SKILL.md");
    let run = Invocation::new(&["install", "--help"])
        .plugin_data(data.path())
        .home(project.path())
        .cwd(project.path())
        .stdin("")
        .run();
    assert_help(&run, "install --help");
    assert_eq!(entries(data.path()), Vec::<String>::new());
    assert_eq!(entries(&project.join(".claude")), ["skills"]);
    assert_eq!(entries(&skill), ["SKILL.md"]);
}

#[test]
fn help_for_an_unknown_command_is_a_usage_error() {
    for args in [
        &["help", "bogus"][..],
        &["--help", "bogus"],
        &["help", "confirm"],
    ] {
        let run = run_writing_nothing(args);
        assert_eq!(run.code, Some(3), "{args:?}");
        assert_eq!(run.stdout, "", "{args:?}");
        assert!(
            run.stderr
                .contains(&format!("unknown subcommand `{}`", args[1])),
            "{args:?}: {:?}",
            run.stderr
        );
    }
}

#[test]
fn unknown_subcommands_keep_exit_3_with_or_without_help() {
    for args in [
        &["bogus"][..],
        &["bogus", "--help"],
        &["bogus", "-h"],
        &["Help"],
        &["--HELP"],
    ] {
        let run = run_writing_nothing(args);
        assert_eq!(run.code, Some(3), "{args:?}");
        assert_eq!(run.stdout, "", "{args:?}");
        assert_eq!(
            run.stderr.trim(),
            format!("safe-ai-skill: unknown subcommand `{}`", args[0]),
            "{args:?}"
        );
    }
}

#[test]
fn help_names_hook_entry_points_without_running_them() {
    for cmd in ["gate-bash", "redact", "prompt-guard", "session-end"] {
        let run = run_writing_nothing(&["help", cmd]);
        assert_help(&run, &format!("help {cmd}"));
        assert!(run.stdout.contains("hook"), "help {cmd}:\n{}", run.stdout);
    }
    let adapt = run_writing_nothing(&["help", "adapt"]);
    assert_help(&adapt, "help adapt");
    for line in [
        "safe-ai-skill adapt codex <gate-bash|",
        "safe-ai-skill adapt opencode <gate-bash|",
    ] {
        assert!(adapt.stdout.contains(line), "{line}:\n{}", adapt.stdout);
    }
}

/// Run `args` on `body` in a fresh data dir and home.
fn run_hook(args: &[&str], body: &str) -> Run {
    let data = TempDir::new("help-hook-data");
    let home = TempDir::new("help-hook-home");
    Invocation::new(args)
        .plugin_data(data.path())
        .home(home.path())
        .cwd(home.path())
        .stdin(body)
        .run()
}

#[test]
fn hook_entry_points_ignore_a_help_flag() {
    let bash = r#"{"session_id":"h","cwd":"/","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}"#;
    for (args, body) in [
        (&["gate-bash"][..], ""),
        (&["gate-bash"], bash),
        (&["gate-read"], ""),
        (&["redact"], ""),
        (&["adapt"], bash),
        (&["adapt", "codex"], bash),
    ] {
        let plain = run_hook(args, body);
        for flag in ["--help", "-h"] {
            let mut with_flag = args.to_vec();
            with_flag.insert(1, flag);
            let run = run_hook(&with_flag, body);
            assert_eq!(run.code, plain.code, "{with_flag:?}");
            assert_eq!(run.stdout, plain.stdout, "{with_flag:?}");
        }
    }
}

#[test]
fn version_ignores_a_help_flag() {
    let run = run_writing_nothing(&["--version", "--help"]);
    assert_eq!(run.code, Some(0));
    assert_eq!(
        run.stdout.trim(),
        format!("safe-ai-skill {}", env!("CARGO_PKG_VERSION"))
    );
}
