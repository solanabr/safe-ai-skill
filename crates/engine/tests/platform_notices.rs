//! SessionStart platform notices (spec D5.1, D5.5): duplicate installs and an old Claude
//! Code, driven through the real `verify session` binary.

mod common;

use common::{Invocation, TempDir};

fn session(home: &TempDir, cc_version: &str) -> common::Run {
    let data = home.join("data");
    let project = home.join("project");
    std::fs::create_dir_all(&project).unwrap();
    Invocation::new(&["verify", "session"])
        .stdin(format!(
            r#"{{"hook_event_name":"SessionStart","source":"startup","cwd":"{}"}}"#,
            project.display()
        ))
        .plugin_data(&data)
        .home(home.path())
        .cwd(&project)
        .env("CLAUDE_CONFIG_DIR", home.join(".claude").to_str().unwrap())
        .env("CLAUDE_CODE_VERSION", cc_version)
        .run()
}

fn write_installed(home: &TempDir, json: &str) {
    let dir = home.join(".claude").join("plugins");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("installed_plugins.json"), json).unwrap();
}

#[test]
fn duplicate_install_and_old_claude_code_are_reported() {
    let home = TempDir::new("platform-dup");
    write_installed(
        &home,
        r#"{"version":2,"plugins":{"safe-ai-skill@stbr":[{}],"safe-ai-skill@safe-ai-skill":[{}]}}"#,
    );
    let run = session(&home, "2.1.200");
    assert_eq!(run.code, Some(0), "stderr: {}", run.stderr);
    let v = run.json();
    for field in [
        &v["systemMessage"],
        &v["hookSpecificOutput"]["additionalContext"],
    ] {
        let text = field.as_str().unwrap_or_default();
        assert!(text.contains("installed more than once"), "{v}");
        assert!(text.contains("safe-ai-skill@stbr"), "{v}");
        assert!(text.contains("older than 2.1.295"), "{v}");
    }
}

#[test]
fn single_install_on_current_claude_code_says_nothing_about_the_platform() {
    let home = TempDir::new("platform-ok");
    write_installed(
        &home,
        r#"{"version":2,"plugins":{"safe-ai-skill@safe-ai-skill":[{}]}}"#,
    );
    let run = session(&home, "2.1.304");
    assert_eq!(run.code, Some(0), "stderr: {}", run.stderr);
    assert!(
        !run.stdout.contains("installed more than once"),
        "{}",
        run.stdout
    );
    assert!(!run.stdout.contains("older than"), "{}", run.stdout);
}

#[test]
fn a_fifo_installed_plugins_does_not_stall_the_session() {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let home = TempDir::new("platform-fifo");
        let dir = home.join(".claude").join("plugins");
        std::fs::create_dir_all(&dir).unwrap();
        let fifo = dir.join("installed_plugins.json");
        let c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let run = session(&home, "2.1.304");
        assert_eq!(run.code, Some(0), "stderr: {}", run.stderr);
    }
}

/// The harness strips the Windows notice from `verify session` output on Windows (see
/// `common::without_windows_notice`); check that rewrite on fixed inputs, on every platform.
#[test]
fn the_harness_reads_a_windows_session_as_unix_would() {
    let notice = "safe-ai-skill on Windows: the shell gates cover the Bash tool (Git Bash) only; \
                  PowerShell tool calls are not gated.";
    let tier = "safe-ai-skill tier: relaxed (hooks only) (default); sandbox: off; lists: x";
    let emit = |sys: &str, ctx: &str| {
        serde_json::json!({
            "systemMessage": sys,
            "hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": ctx},
        })
        .to_string()
    };
    let quiet = format!("{tier}\n{notice}");
    assert_eq!(common::without_windows_notice(&emit(&quiet, &quiet)), "");
    let tipped = common::without_windows_notice(&emit(&format!("{quiet}\ntip"), &quiet));
    let v: serde_json::Value = serde_json::from_str(&tipped).unwrap();
    assert_eq!(v, serde_json::json!({"systemMessage": "tip"}));
    let busy = format!("{tier}\nBLOCK x\n{notice}");
    let v: serde_json::Value =
        serde_json::from_str(&common::without_windows_notice(&emit(&busy, &busy))).unwrap();
    let kept = format!("{tier}\nBLOCK x");
    assert_eq!(v["systemMessage"], kept.as_str());
    assert_eq!(v["hookSpecificOutput"]["additionalContext"], kept.as_str());
    let high = "safe-ai-skill tier: high (project); sandbox: off; lists: x";
    let v: serde_json::Value = serde_json::from_str(&common::without_windows_notice(&emit(
        &format!("{high}\n{notice}"),
        &format!("{high}\n{notice}"),
    )))
    .unwrap();
    assert_eq!(v["systemMessage"], high);
    assert_eq!(common::without_windows_notice(""), "");
}
