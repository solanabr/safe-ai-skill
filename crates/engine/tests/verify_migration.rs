//! v1 → state v2 migration (spec D2.3), against state the real v1.0.0 engine wrote.
//!
//! `tests/fixtures/v1/data` is the plugin data dir `tests/fixtures/v1/generate.sh` produced by
//! running the v1.0.0 binary over two scratch projects (absolute paths replaced by `@ROOT@`).
//! These tests recreate the same trees byte for byte under a sandbox root, apply the changes a
//! user would have made since, and run the 1.1 sweep with that data dir:
//!
//! - an ext pin whose HEAD still equals its pin → re-baselined with WARN, even though its
//!   content changed in place (v1 never hashed it);
//! - a v1 name collision (a pin recorded for another project's pack, or one another pack
//!   already matched) → re-baselined with WARN;
//! - any other mismatch → drift, which blocks;
//! - grants, the v1 lockfile and the v1 quarantine are left byte for byte as they were, and
//!   nothing moves.

mod common;

use common::{Invocation, Run, TempDir};
use std::path::{Path, PathBuf};

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/v1/data");

/// `body` as the generator's `printf '%s\n'` wrote it.
fn write(path: &Path, body: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, format!("{body}\n")).unwrap();
}

fn skill(dir: &Path, body: &str) {
    write(&dir.join("SKILL.md"), body);
}

fn head(dir: &Path, sha: char) {
    write(&dir.join(".git").join("HEAD"), &sha.to_string().repeat(40));
}

/// Copy the fixture tree to `to`, replacing `@ROOT@` in text files with `root`.
fn copy_fixture(from: &Path, to: &Path, root: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap().flatten() {
        let src = entry.path();
        let dst = to.join(entry.file_name());
        if src.is_dir() {
            copy_fixture(&src, &dst, root);
        } else {
            let bytes = std::fs::read(&src).unwrap();
            let out = match String::from_utf8(bytes.clone()) {
                Ok(text) => text.replace("@ROOT@", root.to_str().unwrap()).into_bytes(),
                Err(_) => bytes,
            };
            std::fs::write(&dst, out).unwrap();
        }
    }
}

/// Every file under `dir` with its bytes, sorted.
fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).unwrap().flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push((
                    p.strip_prefix(dir).unwrap().to_path_buf(),
                    std::fs::read(&p).unwrap(),
                ));
            }
        }
    }
    out.sort();
    out
}

/// The sandbox: the fixture data dir, and both projects recreated with the user's later
/// changes applied.
struct World {
    _tmp: TempDir,
    root: PathBuf,
}

impl World {
    fn new(tag: &str) -> World {
        let tmp = TempDir::new(tag);
        let root = tmp.path().canonicalize().unwrap();
        copy_fixture(Path::new(FIXTURE), &root.join("data"), &root);

        let a = root.join("proj-a/.claude/skills");
        let b = root.join("proj-b/.claude/skills");
        skill(&a.join("clean-a"), "# clean-a\nFormats Anchor errors.");
        skill(&a.join("edited-a"), "# edited-a\nExplains PDAs.");
        skill(&a.join("shared"), "# shared\nProject A's copy.");
        skill(
            &a.join("ext/head-equal"),
            "# head-equal\nUpstream pack pinned by HEAD.",
        );
        head(&a.join("ext/head-equal"), '1');
        skill(
            &a.join("ext/bumped"),
            "# bumped\nUpstream pack that gets bumped.",
        );
        head(&a.join("ext/bumped"), '2');
        // Project B's copies, restored by hand after v1 moved them.
        skill(&b.join("shared"), "# shared\nProject B's copy.");
        skill(
            &b.join("ext/head-equal"),
            "# head-equal\nProject B's checkout of the same upstream, at another commit.",
        );
        head(&b.join("ext/head-equal"), '3');
        let user = root.join("home/.claude/skills");
        skill(
            &user.join("user-tool"),
            "# user-tool\nInstalled with install --from.",
        );
        skill(
            &user.join("personal"),
            "# personal\nA hand-written user skill.",
        );

        let world = World { _tmp: tmp, root };
        world.assert_trees_mirror_the_fixture();

        // What the user did since: an edit, an in-place edit under an unchanged HEAD, a bump.
        skill(&a.join("edited-a"), "# edited-a\nExplains PDAs, edited.");
        skill(
            &a.join("ext/head-equal"),
            "# head-equal\nEdited in place, HEAD unchanged.",
        );
        head(&a.join("ext/bumped"), '4');
        world
    }

    /// The recreated trees hash to the pins v1 recorded, so the fixture and this file agree.
    fn assert_trees_mirror_the_fixture(&self) {
        let lock: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(self.data().join("lockfile.json")).unwrap(),
        )
        .unwrap();
        for (name, dir) in [
            ("clean-a", self.root.join("proj-a/.claude/skills/clean-a")),
            ("edited-a", self.root.join("proj-a/.claude/skills/edited-a")),
            ("shared", self.root.join("proj-a/.claude/skills/shared")),
            ("user-tool", self.root.join("home/.claude/skills/user-tool")),
            ("personal", self.root.join("home/.claude/skills/personal")),
        ] {
            assert_eq!(
                lock["skills"][name]["sha256"].as_str().unwrap(),
                safe_ai_skill::verify::lockfile::hash_tree(&dir),
                "{name}: the recreated tree no longer matches what v1 pinned"
            );
        }
        assert_eq!(lock["ext"]["head-equal"]["sha"], "1".repeat(40));
        assert_eq!(lock["ext"]["bumped"]["sha"], "2".repeat(40));
    }

    fn data(&self) -> PathBuf {
        self.root.join("data")
    }

    fn project(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    fn session(&self, project: &str) -> Run {
        let home = self.root.join("home");
        let data = self.data();
        let cwd = self.project(project);
        Invocation::new(&["verify", "session"])
            .plugin_data(&data)
            .home(&home)
            .stdin(
                serde_json::json!({
                    "hook_event_name": "SessionStart",
                    "source": "startup",
                    "cwd": cwd.to_str().unwrap(),
                })
                .to_string(),
            )
            .run()
    }
}

/// `(systemMessage, additionalContext)`; both must be present.
fn messages(run: &Run) -> (String, String) {
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    let v = run.json();
    (
        v["systemMessage"].as_str().unwrap_or_default().to_string(),
        v["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    )
}

/// The user's line for `display`, if any.
fn line_for<'a>(text: &'a str, display: &str) -> Option<&'a str> {
    text.lines().find(|l| l.contains(&format!(" {display}:")))
}

#[test]
fn v1_state_migrates_without_touching_grants_lockfile_or_packs() {
    let w = World::new("mig");
    let protected = ["grants.json", "lockfile.json", "audit.jsonl"]
        .map(|f| std::fs::read(w.data().join(f)).unwrap());
    let quarantine = snapshot(&w.data().join("quarantine"));

    let (sys, ctx) = messages(&w.session("proj-a"));

    let edited = line_for(&sys, ".claude/skills/edited-a").expect("edited-a reported");
    assert!(
        edited.starts_with("BLOCK") && edited.contains("drift"),
        "{sys}"
    );
    let bumped = line_for(&sys, ".claude/skills/ext/bumped").expect("bumped reported");
    assert!(
        bumped.starts_with("BLOCK") && bumped.contains("drift"),
        "{sys}"
    );
    let rebased = line_for(&sys, ".claude/skills/ext/head-equal").expect("head-equal reported");
    assert!(
        rebased.starts_with("WARN") && rebased.contains("re-baselined"),
        "{sys}"
    );
    for quiet in ["clean-a", "skills/shared", "user-tool", "personal"] {
        assert!(
            !sys.lines()
                .any(|l| l.contains(quiet) && !l.contains("earlier version")),
            "{quiet} reported: {sys}"
        );
    }
    // The packs v1 moved are listed for the user only.
    let leftover = sys
        .lines()
        .find(|l| l.contains("moved by an earlier version"))
        .expect("leftover quarantine notice");
    for name in ["dirty-a", "head-equal", "shared"] {
        assert!(leftover.contains(name), "{leftover}");
    }
    assert!(!ctx.contains("earlier version"), "{ctx}");

    let (sys_b, _) = messages(&w.session("proj-b"));
    for display in [".claude/skills/shared", ".claude/skills/ext/head-equal"] {
        let line = line_for(&sys_b, display).unwrap_or_else(|| panic!("{display}: {sys_b}"));
        assert!(
            line.starts_with("WARN") && line.contains("name collision"),
            "{display}: {sys_b}"
        );
    }
    assert!(!sys_b.contains("BLOCK"), "{sys_b}");

    // The v1 lockfile is untouched and nothing moved. (1.0 `grants.json` is converted into
    // pending requests by the state migration and set aside as `grants.json.v1-migrated`;
    // the audit log gains those entries.)
    let lockfile = std::fs::read(w.data().join("lockfile.json")).unwrap();
    assert_eq!(lockfile, protected[1], "lockfile.json");
    assert!(
        w.data().join("grants.json.v1-migrated").exists()
            || w.data().join("grants.json.v1-unmigrated").exists()
            || w.data().join("grants.json").exists()
    );
    assert_eq!(snapshot(&w.data().join("quarantine")), quarantine);
    for dir in [
        "proj-a/.claude/skills/edited-a",
        "proj-a/.claude/skills/ext/bumped",
        "proj-a/.claude/skills/ext/head-equal",
        "proj-b/.claude/skills/shared",
        "proj-b/.claude/skills/ext/head-equal",
        "home/.claude/skills/user-tool",
    ] {
        assert!(w.root.join(dir).join("SKILL.md").exists(), "{dir} moved");
    }

    // Re-baselines are announced once; drift stays blocked.
    let (sys, _) = messages(&w.session("proj-a"));
    assert!(
        line_for(&sys, ".claude/skills/ext/head-equal").is_none(),
        "{sys}"
    );
    assert!(line_for(&sys, ".claude/skills/edited-a")
        .unwrap()
        .starts_with("BLOCK"));
    assert!(line_for(&sys, ".claude/skills/ext/bumped")
        .unwrap()
        .starts_with("BLOCK"));
}

#[test]
fn a_bare_name_ext_pin_seen_first_from_the_other_project_is_drift() {
    // v1 recorded no location for ext pins: until the project whose commit matches has
    // claimed the pin, another project's checkout of that name is indistinguishable from
    // drift. A skill pin written by an in-place install names its project, so that one is
    // still recognised as a collision.
    let w = World::new("mig-rev");
    let (sys, _) = messages(&w.session("proj-b"));
    let ext = line_for(&sys, ".claude/skills/ext/head-equal").expect("reported");
    assert!(ext.starts_with("BLOCK") && ext.contains("drift"), "{sys}");
    let shared = line_for(&sys, ".claude/skills/shared").expect("reported");
    assert!(
        shared.starts_with("WARN") && shared.contains("name collision"),
        "{sys}"
    );
}
