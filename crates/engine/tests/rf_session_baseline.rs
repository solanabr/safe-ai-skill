//! SessionStart records the settings files' disabling switches (`configchange::record_baseline`),
//! so a switch that was there before the session does not make `gate-config` block an
//! unrelated later edit of its file, while a switch added during the session still blocks.
//! Needs a trusted data dir in a temp home: `test-hooks` builds only.
#![cfg(feature = "test-hooks")]

mod common;

use std::path::Path;

use common::{Invocation, TempDir};
use serde_json::json;

const SWITCHED: &str = r#"{"disableAllHooks": true}"#;
const SWITCHED_EDITED: &str = r#"{"disableAllHooks": true, "model": "sonnet"}"#;

struct World {
    home: TempDir,
    data: TempDir,
    proj: TempDir,
}

impl World {
    fn new(tag: &str) -> Self {
        let world = World {
            home: TempDir::outside_home(&format!("{tag}-home")),
            data: TempDir::outside_home(&format!("{tag}-data")),
            proj: TempDir::outside_home(&format!("{tag}-proj")),
        };
        std::fs::create_dir_all(world.proj.join(".claude")).unwrap();
        world
    }

    fn settings(&self, text: &str) {
        std::fs::write(self.proj.join(".claude/settings.local.json"), text).unwrap();
    }

    fn run(&self, args: &[&str], stdin: serde_json::Value) -> common::Run {
        Invocation::new(args)
            .plugin_data(self.data.path())
            .home(self.home.path())
            .cwd(self.proj.path())
            .env(safe_ai_skill::datadir::TEST_TRUST_ENV, "1")
            .stdin(stdin.to_string())
            .run()
    }

    fn session_start(&self) {
        let run = self.run(
            &["verify", "session"],
            json!({
                "session_id": "rf-baseline",
                "hook_event_name": "SessionStart",
                "source": "startup",
                "cwd": self.proj.path(),
            }),
        );
        assert_eq!(run.code, Some(0), "{}", run.stderr);
    }

    /// `gate-config` on a change to the local settings file: whether it blocks.
    fn config_change_blocks(&self) -> bool {
        let file = self.proj.join(".claude/settings.local.json");
        let run = self.run(
            &["gate-config"],
            json!({
                "session_id": "rf-baseline",
                "hook_event_name": "ConfigChange",
                "source": "local_settings",
                "file_path": file,
                "cwd": self.proj.path(),
            }),
        );
        assert_eq!(run.code, Some(0), "{}", run.stderr);
        match run.stdout.trim() {
            "" => false,
            out => {
                let v: serde_json::Value = serde_json::from_str(out).unwrap();
                assert_eq!(v["decision"], "block", "{out}");
                true
            }
        }
    }
}

fn data_has_snapshot(data: &Path) -> bool {
    std::fs::read_dir(data)
        .into_iter()
        .flatten()
        .flatten()
        .any(|e| e.path().join("configchange.json").is_file())
        || data.join("configchange.json").is_file()
}

#[test]
fn a_switch_set_before_the_session_does_not_block_a_later_edit() {
    // Control: no session start, so no baseline: the old switch counts as new and blocks.
    let control = World::new("rf-base-ctl");
    control.settings(SWITCHED);
    control.settings(SWITCHED_EDITED);
    assert!(control.config_change_blocks(), "control did not block");

    let world = World::new("rf-base");
    world.settings(SWITCHED);
    world.session_start();
    assert!(
        data_has_snapshot(world.data.path()),
        "SessionStart wrote no baseline under {}",
        world.data.path().display()
    );
    world.settings(SWITCHED_EDITED);
    assert!(
        !world.config_change_blocks(),
        "an unrelated edit of a file whose switch predates the session was blocked"
    );
}

#[test]
fn a_switch_added_during_the_session_still_blocks() {
    let world = World::new("rf-base-new");
    world.settings(r#"{"model": "sonnet"}"#);
    world.session_start();
    world.settings(SWITCHED_EDITED);
    assert!(world.config_change_blocks(), "a new switch was let through");
}
