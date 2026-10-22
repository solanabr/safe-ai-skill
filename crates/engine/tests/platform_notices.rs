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
