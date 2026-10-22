//! The CLI, run from the user's terminal without `$CLAUDE_PLUGIN_DATA`, uses the data dir the
//! hooks use (`~/.claude/plugins/data/safe-ai-skill-*`) and never `~/.safe-ai-skill` or the cwd.

mod common;

use common::{Invocation, TempDir};

#[test]
fn cli_without_plugin_data_uses_the_hooks_dir() {
    let home = TempDir::new("ddir-home");
    let data = home.join(".claude/plugins/data/safe-ai-skill-stbr");
    std::fs::create_dir_all(&data).unwrap();
    let cwd = TempDir::new("ddir-cwd");

    let run = Invocation::new(&["revoke"])
        .home(home.path())
        .cwd(cwd.path())
        .run();
    assert_eq!(
        run.code,
        Some(0),
        "stdout: {}\nstderr: {}",
        run.stdout,
        run.stderr
    );
    assert!(
        data.join("audit.jsonl").is_file(),
        "revoke audits into the hooks' dir"
    );
    let status = Invocation::new(&["status"])
        .home(home.path())
        .cwd(cwd.path())
        .run();
    assert!(
        status.stdout.contains("safe-ai-skill-stbr"),
        "status should report the hooks' dir: {}",
        status.stdout
    );
    assert!(!home.join(".safe-ai-skill").exists());
    assert!(!cwd.join(".safe-ai-skill").exists());
}

#[test]
fn cli_honours_claude_config_dir() {
    let home = TempDir::new("ddir-cfg");
    let data = home.join("cfg/plugins/data/safe-ai-skill-safe-ai-skill");
    std::fs::create_dir_all(&data).unwrap();
    let cfg = home.join("cfg");
    let run = Invocation::new(&["status"])
        .home(home.path())
        .env("CLAUDE_CONFIG_DIR", cfg.to_str().unwrap())
        .run();
    assert!(
        run.stdout.contains("safe-ai-skill-safe-ai-skill"),
        "{}",
        run.stdout
    );
}

#[test]
fn cli_without_any_data_dir_errors_with_guidance() {
    let home = TempDir::new("ddir-none");
    let cwd = TempDir::new("ddir-none-cwd");
    for args in [
        &["mode", "strict"][..],
        &["allow", "--scope", "transfer"],
        &["status"],
    ] {
        let run = Invocation::new(args)
            .home(home.path())
            .cwd(cwd.path())
            .run();
        assert_eq!(run.code, Some(1), "{args:?}: {}", run.stdout);
        assert!(
            run.stderr.contains("CLAUDE_PLUGIN_DATA"),
            "{args:?}: {}",
            run.stderr
        );
        assert!(run.json()["error"]
            .as_str()
            .is_some_and(|e| e.contains("CLAUDE_PLUGIN_DATA")));
    }
    assert!(!home.join(".safe-ai-skill").exists());
    assert!(!cwd.join(".safe-ai-skill").exists());
}
