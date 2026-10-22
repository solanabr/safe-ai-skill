//! SessionStart sweep budget (spec D2.9): a full sweep of an ai-kit-sized tree stays under 5 s.
//!
//! The corpus is synthetic but shaped like the ai-kit checkout the budget was measured on
//! (46 packs, ~13.5k files of docs and code). Debug builds scan several times slower than the
//! shipped release build, so they get proportionally more slack; CI's release run holds the
//! real 5 s line.

mod common;

use common::{Invocation, TempDir};
use std::time::{Duration, Instant};

const PACKS: usize = 46;
const DIRS_PER_PACK: usize = 21;
const FILES_PER_DIR: usize = 14;

fn file_body(pack: usize, dir: usize, file: usize) -> (String, String) {
    let (ext, line) = match file % 4 {
        0 => (
            "md",
            "Use the client to fetch the account and decode it with the IDL.\n",
        ),
        1 => (
            "ts",
            "export const fetchThing = async (rpc: Rpc) => rpc.getAccountInfo(addr);\n",
        ),
        2 => (
            "py",
            "def decode(data: bytes) -> dict:\n    return {\"len\": len(data)}\n",
        ),
        _ => ("json", "{\"name\": \"fixture\", \"version\": \"1.0.0\"}\n"),
    };
    (format!("f{pack}-{dir}-{file}.{ext}"), line.repeat(40))
}

#[test]
fn full_sweep_of_an_aikit_sized_tree_fits_the_budget() {
    let project = TempDir::new("perf-proj");
    let home = TempDir::new("perf-home");
    let data = TempDir::new("perf-data");
    let root = project.path().join(".claude").join("skills").join("ext");
    let mut files = 0usize;
    for p in 0..PACKS {
        let pack = root.join(format!("pack-{p:02}"));
        std::fs::create_dir_all(&pack).unwrap();
        std::fs::write(
            pack.join("SKILL.md"),
            format!("---\nname: pack-{p}\n---\n# pack\n"),
        )
        .unwrap();
        for d in 0..DIRS_PER_PACK {
            let dir = pack.join(format!("d{d}"));
            std::fs::create_dir_all(&dir).unwrap();
            for f in 0..FILES_PER_DIR {
                let (name, body) = file_body(p, d, f);
                std::fs::write(dir.join(name), body).unwrap();
                files += 1;
            }
        }
    }
    assert!(files > 13_000, "{files}");

    let payload = serde_json::json!({
        "hook_event_name": "SessionStart",
        "source": "startup",
        "cwd": project.path().to_str().unwrap(),
    })
    .to_string();
    let started = Instant::now();
    let run = Invocation::new(&["verify", "session"])
        .plugin_data(data.path())
        .home(home.path())
        .stdin(payload)
        .run();
    let took = started.elapsed();
    assert_eq!(run.code, Some(0), "{}", run.stderr);

    let budget = if cfg!(debug_assertions) {
        Duration::from_secs(20)
    } else {
        Duration::from_secs(5)
    };
    assert!(
        took < budget,
        "sweep of {files} files took {took:?} (budget {budget:?})"
    );
}
