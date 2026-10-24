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
        &["allow", "--scope", "transfer", "--for", "30m"],
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

#[test]
fn cli_before_the_first_session_says_to_start_one() {
    let home = TempDir::new("ddir-first");
    std::fs::create_dir_all(home.join(".claude/plugins/cache/stbr/safe-ai-skill/1.1.0")).unwrap();
    let run = Invocation::new(&["tier", "off"])
        .home(home.path())
        .cwd(home.path())
        .run();
    assert_eq!(run.code, Some(1), "{}", run.stdout);
    let error = run.json()["error"].as_str().unwrap().to_string();
    assert!(
        error.contains("installed but has no data dir yet")
            && error.contains("Start a Claude Code session"),
        "{error}"
    );
    assert!(
        !home.join(".claude/plugins/data").exists(),
        "nothing is created"
    );
}

#[cfg(unix)] // confirmations need the process table, which native Windows lacks (by design)
#[test]
fn status_lists_pending_requests_without_their_codes() {
    let home = TempDir::new("ddir-pending");
    let data = home.join(".claude/plugins/data/safe-ai-skill-stbr");
    std::fs::create_dir_all(&data).unwrap();
    let run = Invocation::new(&["tier", "off"])
        .home(home.path())
        .cwd(home.path())
        .run();
    let id = run.json()["request"].as_str().unwrap().to_string();
    // A prompt announces the code (shown to the user only).
    let shown = Invocation::new(&["prompt-guard"])
        .home(home.path())
        .cwd(home.path())
        .plugin_data(&data)
        .stdin(
            serde_json::json!({"session_id":"it-ddir","hook_event_name":"UserPromptSubmit","prompt":"hi",
                               "cwd": home.path()})
            .to_string(),
        )
        .run();
    let msg = shown.json()["systemMessage"].as_str().unwrap().to_string();
    let code: String = msg
        .split("safe-ai-skill confirm ")
        .nth(1)
        .unwrap()
        .chars()
        .take(8)
        .collect();
    let status = Invocation::new(&["status"])
        .home(home.path())
        .cwd(home.path())
        .run();
    let v = status.json();
    let pending = v["pending"].as_array().unwrap_or_else(|| panic!("{v}"));
    assert_eq!(pending.len(), 1, "{v}");
    assert_eq!(pending[0]["request"], id.as_str());
    assert_eq!(pending[0]["kind"], "tier");
    assert!(pending[0]["created_at"].as_u64().unwrap() > 0);
    assert_eq!(pending[0]["announced"], true);
    assert!(pending[0]["how_to_confirm"]
        .as_str()
        .unwrap()
        .contains("safe-ai-skill confirm <code>"));
    assert!(
        !status.stdout.contains(&code),
        "the code must never be listed"
    );
}
