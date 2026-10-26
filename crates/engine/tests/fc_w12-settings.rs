//! W12: `safe-ai-skill firewall apply|show|check` — the settings manager (X1–X9, P14, P21, T3,
//! T6). Library-level: apply/show/check on temp project dirs, idempotence, user rules kept,
//! lowering parked for confirmation, `sandbox.enabled` never written false.

mod common;

use std::path::{Path, PathBuf};

use common::TempDir;
use safe_ai_skill::datadir::DataDir;
use safe_ai_skill::firewall::{self, json, rules, Command, Ctx, Outcome, RECORD_FILE};
use safe_ai_skill::policy::tier::Tier;
use safe_ai_skill::statefile;
use serde_json::Value;

struct Env {
    _root: TempDir,
    project: PathBuf,
    data: DataDir,
}

impl Env {
    fn new(tag: &str) -> Env {
        let root = TempDir::outside_home(&format!("w12-{tag}"));
        let project = std::fs::canonicalize(root.path()).unwrap().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let data_path = std::fs::canonicalize(root.path()).unwrap().join("data");
        std::fs::create_dir_all(&data_path).unwrap();
        Env {
            _root: root,
            project,
            data: DataDir {
                path: data_path,
                trusted: true,
            },
        }
    }

    fn ctx(&self, effective: Tier) -> Ctx<'_> {
        Ctx {
            dir: &self.data,
            cwd: &self.project,
            effective,
            home: None,
            now: 1_000,
        }
    }

    fn settings(&self) -> PathBuf {
        self.project.join(".claude/settings.local.json")
    }

    fn text(&self) -> String {
        std::fs::read_to_string(self.settings()).unwrap_or_default()
    }

    fn doc(&self) -> json::Json {
        json::parse(&self.text()).unwrap()
    }

    fn apply(&self, tier: Option<Tier>, effective: Tier) -> Outcome {
        firewall::run(
            &Command::Apply {
                tier,
                project: false,
                dry_run: false,
            },
            &self.ctx(effective),
        )
    }
}

fn ok(o: Outcome) -> Value {
    match o {
        Outcome::Ok(v) => v,
        other => panic!("expected Ok, got {other:?}"),
    }
}

fn strings(doc: &json::Json, path: &str) -> Vec<String> {
    doc.at(path)
        .map(|v| v.strings().into_iter().map(str::to_string).collect())
        .unwrap_or_default()
}

fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

#[test]
fn apply_relaxed_writes_sandbox_block() {
    let e = Env::new("relaxed");
    let v = ok(e.apply(None, Tier::Relaxed));
    assert_eq!(v["status"], "applied");
    assert_eq!(v["created"], true);
    let d = e.doc();
    assert_eq!(d.at("sandbox.enabled"), Some(&json::Json::Bool(true)));
    assert_eq!(
        d.at("sandbox.network.allowLocalBinding"),
        Some(&json::Json::Bool(true))
    );
    assert!(
        d.at("permissions").is_none(),
        "no permission rules at relaxed"
    );
    let deny_read = strings(&d, "sandbox.filesystem.denyRead");
    assert!(deny_read.contains(&"~/.ssh".to_string()));
    assert!(!deny_read.contains(&"~/.npmrc".to_string()));
    assert!(!deny_read.iter().any(|g| g.starts_with("~/.config/solana")));
    assert!(strings(&d, "sandbox.network.deniedDomains").contains(&"webhook.site".to_string()));
    assert!(!strings(&d, "sandbox.network.deniedDomains").contains(&"api.telegram.org".into()));
    assert_eq!(
        strings(&d, "sandbox.excludedCommands"),
        rules::EXCLUDED_COMMANDS
    );
    assert!(strings(&d, "sandbox.filesystem.allowWrite").contains(&"~/.cargo".to_string()));
    assert!(strings(&d, "sandbox.filesystem.denyWrite").contains(&"~/.zshrc".to_string()));
}

#[test]
fn medium_and_high_add_their_rules() {
    let e = Env::new("high");
    ok(e.apply(Some(Tier::Medium), Tier::Relaxed));
    let d = e.doc();
    // The `bash -c` deny is written at High only.
    assert!(strings(&d, "permissions.deny").is_empty());
    assert!(strings(&d, "sandbox.filesystem.denyRead").contains(&"~/.npmrc".to_string()));
    assert!(strings(&d, "sandbox.network.deniedDomains").contains(&"api.telegram.org".into()));
    assert!(d
        .at("permissions.blockReadsOutsideWorkingDirectories")
        .is_none());

    ok(e.apply(Some(Tier::High), Tier::Medium));
    let d = e.doc();
    assert_eq!(
        d.at("permissions.blockReadsOutsideWorkingDirectories"),
        Some(&json::Json::Bool(true))
    );
    assert!(strings(&d, "sandbox.filesystem.denyRead").contains(&"~/".to_string()));
    assert!(strings(&d, "sandbox.filesystem.allowRead").contains(&"~/.cargo/registry".into()));
    assert!(strings(&d, "sandbox.network.deniedDomains").contains(&"*.vercel.app".into()));
    // Naming a tier also records it as the user's tier, as `safe-ai-skill tier` does.
    let choice = safe_ai_skill::tierstate::user_choice(&e.data, &e.project);
    assert_eq!(choice.tier.map(|(t, _)| t), Some(Tier::High));
}

#[test]
fn second_apply_is_a_byte_identical_no_op() {
    let e = Env::new("idem");
    ok(e.apply(None, Tier::Medium));
    let first = e.text();
    let v = ok(e.apply(None, Tier::Medium));
    assert_eq!(v["status"], "unchanged");
    assert_eq!(e.text(), first);
    assert!(v["changes"].as_array().unwrap().is_empty());
}

#[test]
fn user_rules_keys_and_layout_survive() {
    let e = Env::new("user");
    let original = "{\n    \"model\": \"opus\",\n    \"permissions\": {\n        \"allow\": [\n            \"Bash(ls *)\"\n        ],\n        \"deny\": [\n            \"Read(./private/**)\"\n        ]\n    },\n    \"sandbox\": {\n        \"filesystem\": {\n            \"denyRead\": [\n                \"~/mine\"\n            ]\n        }\n    },\n    \"hooks\": {}\n}\n";
    write(&e.settings(), original);
    ok(e.apply(Some(Tier::High), Tier::Relaxed));
    let text = e.text();
    assert!(text.starts_with("{\n    \"model\": \"opus\""), "{text}");
    let d = e.doc();
    assert_eq!(strings(&d, "permissions.allow"), ["Bash(ls *)"]);
    assert_eq!(
        strings(&d, "permissions.deny"),
        ["Read(./private/**)", "Bash(bash -c *)"]
    );
    assert_eq!(strings(&d, "sandbox.filesystem.denyRead")[0], "~/mine");
    assert!(d.get("hooks").is_some());

    // Back down to Off (confirmed): the user's file comes back byte for byte.
    let parked = e.apply(Some(Tier::Off), Tier::High);
    let Outcome::Park { payload, .. } = parked else {
        panic!("lowering must park: {parked:?}")
    };
    firewall::apply_confirmed(&e.data, &payload, None, 2_000).unwrap();
    assert_eq!(e.text(), original);
}

#[test]
fn lowering_is_parked_and_writes_nothing() {
    let e = Env::new("lower");
    ok(e.apply(Some(Tier::High), Tier::Relaxed));
    let high = e.text();
    for (named, effective) in [
        (Some(Tier::Relaxed), Tier::High),
        (None, Tier::Medium),
        (Some(Tier::Off), Tier::High),
    ] {
        match e.apply(named, effective) {
            Outcome::Park { summary, payload } => {
                assert!(summary.starts_with("firewall apply "), "{summary}");
                assert!(payload["settings"].as_str().is_some());
            }
            other => panic!("{named:?}/{effective:?}: expected Park, got {other:?}"),
        }
        assert_eq!(e.text(), high, "nothing written before confirmation");
    }
    // Raising and re-applying the same tier stay immediate.
    assert_eq!(
        ok(e.apply(Some(Tier::High), Tier::High))["status"],
        "unchanged"
    );

    // Confirmed, the lower block replaces the higher one exactly.
    let Outcome::Park { payload, .. } = e.apply(Some(Tier::Relaxed), Tier::High) else {
        panic!()
    };
    let done = firewall::apply_confirmed(&e.data, &payload, None, 3_000).unwrap();
    assert!(done.contains("relaxed"), "{done}");
    let fresh = Env::new("lower-fresh");
    ok(fresh.apply(None, Tier::Relaxed));
    // The block names each project's root, so compare with the roots masked.
    let masked = |env: &Env| {
        env.text()
            .replace(env.project.to_string_lossy().as_ref(), "<root>")
    };
    assert_eq!(masked(&e), masked(&fresh));
    let choice = safe_ai_skill::tierstate::user_choice(&e.data, &e.project);
    assert_eq!(choice.tier.map(|(t, _)| t), Some(Tier::Relaxed));
}

#[test]
fn tampered_or_deleted_record_fails_closed() {
    let e = Env::new("tamper");
    ok(e.apply(None, Tier::Relaxed));
    std::fs::remove_file(e.data.path.join(RECORD_FILE)).unwrap();
    assert!(
        matches!(e.apply(None, Tier::Relaxed), Outcome::Park { .. }),
        "a deleted record counts as High"
    );
    std::fs::write(e.data.path.join(RECORD_FILE), "{\"v\":1}").unwrap();
    assert!(matches!(e.apply(None, Tier::Medium), Outcome::Park { .. }));
    assert_eq!(ok(e.apply(None, Tier::High))["status"], "applied");
}

#[test]
fn live_file_sets_the_floor_without_a_record() {
    let e = Env::new("inferred");
    ok(e.apply(None, Tier::High));
    // A fresh data dir has no record at all; the file itself still shows High.
    let fresh = e.data.path.with_file_name("data2");
    std::fs::create_dir_all(&fresh).unwrap();
    let other = DataDir {
        path: fresh,
        trusted: true,
    };
    let ctx = Ctx {
        dir: &other,
        ..e.ctx(Tier::Relaxed)
    };
    let o = firewall::run(
        &Command::Apply {
            tier: None,
            project: false,
            dry_run: false,
        },
        &ctx,
    );
    assert!(matches!(o, Outcome::Park { .. }), "{o:?}");
    let doc = json::parse("{\"sandbox\":{\"enabled\":true}}").unwrap();
    assert_eq!(firewall::inferred_tier(&doc), Some(Tier::Relaxed));
    assert_eq!(firewall::inferred_tier(&json::Json::Obj(vec![])), None);
}

#[test]
fn untrusted_data_dir_refuses_lowering() {
    let mut e = Env::new("untrusted");
    ok(e.apply(None, Tier::High));
    e.data.trusted = false;
    assert!(matches!(e.apply(None, Tier::Relaxed), Outcome::Error(_)));
    let r = Env::new("untrusted-raise");
    let mut r = r;
    r.data.trusted = false;
    ok(r.apply(None, Tier::Relaxed));
    ok(r.apply(None, Tier::Medium));
}

#[test]
fn sandbox_enabled_is_never_written_false() {
    let e = Env::new("never-false");
    ok(e.apply(None, Tier::Relaxed));
    let Outcome::Park { payload, .. } = e.apply(Some(Tier::Off), Tier::Relaxed) else {
        panic!()
    };
    firewall::apply_confirmed(&e.data, &payload, None, 2_000).unwrap();
    assert!(!e.text().contains("false"), "{}", e.text());
    assert!(e.doc().at("sandbox").is_none());

    // A user's own false is kept and reported, never flipped.
    let u = Env::new("user-false");
    write(&u.settings(), "{\"sandbox\":{\"enabled\":false}}");
    let v = ok(u.apply(None, Tier::High));
    assert_eq!(
        u.doc().at("sandbox.enabled"),
        Some(&json::Json::Bool(false))
    );
    assert!(v["left_as_is"].to_string().contains("sandbox.enabled"));
    for tier in [Tier::Off, Tier::Relaxed, Tier::Medium, Tier::High] {
        let b = rules::plan(tier, &["x.example"], &rules::MachineInputs::default());
        assert!(b.scalars.iter().all(|s| rules::SCALARS.contains(s)));
    }
}

#[test]
fn dry_run_writes_nothing() {
    let e = Env::new("dry");
    let v = ok(firewall::run(
        &Command::Apply {
            tier: Some(Tier::High),
            project: false,
            dry_run: true,
        },
        &e.ctx(Tier::Relaxed),
    ));
    assert_eq!(v["status"], "dry-run");
    assert_eq!(v["needs_confirmation"], false);
    assert!(!e.settings().exists());
    assert!(!statefile::was_stored(&e.data, RECORD_FILE));
}

#[cfg(unix)]
#[test]
fn symlinked_settings_are_refused() {
    let e = Env::new("link");
    let elsewhere = e.project.parent().unwrap().join("elsewhere.json");
    std::fs::write(&elsewhere, "{}").unwrap();
    std::fs::create_dir_all(e.project.join(".claude")).unwrap();
    std::os::unix::fs::symlink(&elsewhere, e.settings()).unwrap();
    assert!(matches!(e.apply(None, Tier::High), Outcome::Error(_)));
    assert_eq!(std::fs::read_to_string(&elsewhere).unwrap(), "{}");
}

#[test]
fn invalid_json_is_refused_and_left() {
    let e = Env::new("badjson");
    write(&e.settings(), "{ not json");
    assert!(matches!(e.apply(None, Tier::High), Outcome::Error(_)));
    assert_eq!(e.text(), "{ not json");
}

#[test]
fn duplicated_keys_are_refused_and_reported() {
    let e = Env::new("dupkeys");
    let text = "{\n  \"sandbox\": {\n    \"enabled\": true\n  },\n  \"sandbox\": {\n    \"enabled\": false\n  }\n}\n";
    write(&e.settings(), text);
    let err = match e.apply(Some(Tier::Relaxed), Tier::Relaxed) {
        Outcome::Error(m) => m,
        o => panic!("expected a refusal, got {o:?}"),
    };
    assert!(err.contains("sandbox"), "{err}");
    assert!(err.contains("settings.local.json"), "{err}");
    assert_eq!(e.text(), text, "the file is left as it is");
    assert!(matches!(
        statefile::load::<firewall::RecordFile>(&e.data, RECORD_FILE),
        statefile::Loaded::Missing
    ));
    // What Claude Code reads (the last occurrence) is what the floor sees.
    assert_eq!(firewall::inferred_tier(&e.doc()), None);

    // Applied first, then duplicated by hand: check reports it.
    let d = Env::new("dupkeys-after");
    ok(d.apply(None, Tier::Relaxed));
    let applied = d.text();
    let dup = applied.replacen(
        "{\n",
        "{\n  \"sandbox\": {\n    \"enabled\": false\n  },\n",
        1,
    );
    // The writer appends its block after the user's keys, so put the user's copy last.
    let last = format!(
        "{},\n  \"sandbox\": {{\n    \"enabled\": false\n  }}\n}}\n",
        applied.trim_end().trim_end_matches('}').trim_end()
    );
    for t in [dup, last] {
        std::fs::write(d.settings(), &t).unwrap();
        let v = match firewall::run(&Command::Check, &d.ctx(Tier::Relaxed)) {
            Outcome::Drift(v) => v,
            o => panic!("{o:?}"),
        };
        assert!(
            v["drift"]
                .as_array()
                .unwrap()
                .iter()
                .any(|x| x["kind"] == "duplicate-key"),
            "{v}"
        );
        assert!(matches!(d.apply(None, Tier::Relaxed), Outcome::Error(_)));
        assert_eq!(d.text(), t);
    }
    let note = firewall::session_note(&d.ctx(Tier::Relaxed)).unwrap();
    assert!(note.contains("repeats"), "{note}");
}

#[test]
fn project_root_is_written_absolute_from_a_subdirectory_at_high() {
    let e = Env::new("rootsub");
    std::fs::create_dir_all(e.project.join(".git")).unwrap();
    let sub = e.project.join("a/b");
    std::fs::create_dir_all(&sub).unwrap();
    let ctx = Ctx {
        dir: &e.data,
        cwd: &sub,
        effective: Tier::High,
        home: None,
        now: 1_000,
    };
    let apply = Command::Apply {
        tier: None,
        project: false,
        dry_run: false,
    };
    ok(firewall::run(&apply, &ctx));
    let root = e.project.to_string_lossy().into_owned();
    let d = e.doc();
    for list in [
        "sandbox.filesystem.allowWrite",
        "sandbox.filesystem.allowRead",
    ] {
        let got = strings(&d, list);
        assert!(got.contains(&root), "{list}: {got:?}");
        assert!(got.contains(&".".to_string()), "{list}: {got:?}");
    }
    // A rule-set-1 block (relative entries only) is brought up to date by the resync.
    let text = e.text().replace(&format!("        \"{root}\",\n"), "");
    assert!(!text.contains(&format!("\"{root}\"")), "{text}");
    std::fs::write(e.settings(), &text).unwrap();
    let mut file: firewall::RecordFile = match statefile::load(&e.data, RECORD_FILE) {
        statefile::Loaded::Valid(f) => f,
        _ => panic!(),
    };
    for rec in file.targets.values_mut() {
        rec.rule_set_version = 1;
        for v in rec.rule_ids.values_mut() {
            v.retain(|x| *x != root);
        }
    }
    statefile::store(&e.data, RECORD_FILE, &file).unwrap();
    assert!(firewall::session_resync(&ctx).is_some());
    let d = e.doc();
    for list in [
        "sandbox.filesystem.allowWrite",
        "sandbox.filesystem.allowRead",
    ] {
        assert!(strings(&d, list).contains(&root), "{list}");
    }
    assert!(firewall::check(&ctx).drift.is_empty());
}

#[test]
fn repo_git_dir_is_written_absolute_from_a_subdirectory() {
    let e = Env::new("gitsub");
    std::fs::create_dir_all(e.project.join(".git")).unwrap();
    let sub = e.project.join("a/b");
    std::fs::create_dir_all(&sub).unwrap();
    let ctx = Ctx {
        dir: &e.data,
        cwd: &sub,
        effective: Tier::Relaxed,
        home: None,
        now: 1_000,
    };
    let apply = Command::Apply {
        tier: None,
        project: false,
        dry_run: false,
    };
    ok(firewall::run(&apply, &ctx));
    let w = strings(&e.doc(), "sandbox.filesystem.allowWrite");
    let abs = e.project.join(".git").to_string_lossy().into_owned();
    assert!(w.contains(&abs), "{w:?}");
    assert!(!w.contains(&".git".to_string()), "{w:?}");

    // A record from rule set 1 owns the relative `.git`: the resync removes it.
    let mut text = e.text().replace(&format!("\"{abs}\""), "\".git\"");
    assert!(text.contains("\".git\""));
    std::fs::write(e.settings(), &text).unwrap();
    let mut file: firewall::RecordFile = match statefile::load(&e.data, RECORD_FILE) {
        statefile::Loaded::Valid(f) => f,
        _ => panic!(),
    };
    for rec in file.targets.values_mut() {
        rec.rule_set_version = 1;
        for v in rec.rule_ids.values_mut() {
            for x in v.iter_mut() {
                if *x == abs {
                    *x = ".git".to_string();
                }
            }
        }
    }
    statefile::store(&e.data, RECORD_FILE, &file).unwrap();
    assert!(firewall::session_resync(&ctx).is_some());
    text = e.text();
    let w = strings(&e.doc(), "sandbox.filesystem.allowWrite");
    assert!(w.contains(&abs), "{text}");
    assert!(!w.contains(&".git".to_string()), "{text}");
}

#[test]
fn check_and_show_report_drift() {
    let e = Env::new("drift");
    let v = match firewall::run(&Command::Check, &e.ctx(Tier::Relaxed)) {
        Outcome::Drift(v) => v,
        o => panic!("{o:?}"),
    };
    assert_eq!(v["drift"][0]["kind"], "not-applied");
    assert!(firewall::session_note(&e.ctx(Tier::Relaxed)).is_none());

    ok(e.apply(None, Tier::Medium));
    assert!(matches!(
        firewall::run(&Command::Check, &e.ctx(Tier::Medium)),
        Outcome::Ok(_)
    ));
    assert!(firewall::session_note(&e.ctx(Tier::Medium)).is_none());

    // Declared above enforced.
    let note = firewall::session_note(&e.ctx(Tier::High)).unwrap();
    assert!(note.contains("declared"), "{note}");

    // A recorded rule removed from the file.
    let text = e.text().replace("        \"~/.npmrc\",\n", "");
    assert_ne!(text, e.text(), "the Medium denyRead holds ~/.npmrc");
    std::fs::write(e.settings(), text).unwrap();
    let r = firewall::check(&e.ctx(Tier::Medium));
    assert!(r.drift.iter().any(|d| d.kind == "absent"), "{r:?}");
    assert!(r.absent.iter().any(|a| a.contains(".npmrc")));

    let s = firewall::show(&e.ctx(Tier::Medium));
    assert_eq!(s["action"], "show");
    assert_eq!(s["enforced"], "medium");
    // No permission deny at Medium; the sandbox lists carry the block.
    assert_eq!(
        s["declared_block"]["lists"]["permissions.deny"]
            .as_u64()
            .unwrap_or(0),
        0
    );
    assert!(
        s["declared_block"]["lists"]["sandbox.filesystem.denyRead"]
            .as_u64()
            .unwrap_or(0)
            > 0
    );

    // Re-apply restores it.
    ok(e.apply(None, Tier::Medium));
    assert!(firewall::check(&e.ctx(Tier::Medium)).drift.is_empty());
}

#[test]
fn session_resync_reapplies_an_older_rule_set_and_never_lowers() {
    let e = Env::new("resync");
    ok(e.apply(None, Tier::High));
    let mut file: firewall::RecordFile = match statefile::load(&e.data, RECORD_FILE) {
        statefile::Loaded::Valid(f) => f,
        _ => panic!(),
    };
    for rec in file.targets.values_mut() {
        rec.rule_set_version = 0;
    }
    statefile::store(&e.data, RECORD_FILE, &file).unwrap();
    assert!(firewall::session_note(&e.ctx(Tier::High))
        .unwrap()
        .contains("rule set 0"));
    let before = e.text();
    let note = firewall::session_resync(&e.ctx(Tier::Relaxed)).unwrap();
    assert!(note.contains("tier high"), "{note}");
    assert_eq!(e.text(), before, "same rules, same bytes");
    assert!(firewall::session_resync(&e.ctx(Tier::Relaxed)).is_none());
    // Raised declared tier is caught up.
    let m = Env::new("resync-raise");
    ok(m.apply(None, Tier::Relaxed));
    assert!(firewall::session_resync(&m.ctx(Tier::Medium)).is_some());
    assert!(strings(&m.doc(), "sandbox.filesystem.denyRead").contains(&"~/.npmrc".to_string()));
}

#[test]
fn parse_args_shapes() {
    let a = |v: &[&str]| firewall::parse_args(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    assert_eq!(
        a(&["apply", "high", "--project", "--dry-run"]),
        Ok(Command::Apply {
            tier: Some(Tier::High),
            project: true,
            dry_run: true
        })
    );
    assert_eq!(a(&["show"]), Ok(Command::Show));
    assert_eq!(a(&["check"]), Ok(Command::Check));
    assert!(a(&["apply", "bogus"]).is_err());
    assert!(a(&["apply", "--project"]).is_err());
    assert!(a(&["apply", "high", "low"]).is_err());
    assert!(a(&[]).is_err());
}

/// Release micro-benchmark of the SessionStart drift check (the only hook-path entry point).
/// `cargo test --release --test fc_w12-settings -- --ignored --nocapture`
#[test]
#[ignore]
fn bench_session_note() {
    let e = Env::new("bench");
    ok(e.apply(None, Tier::High));
    let n = 2_000;
    let start = std::time::Instant::now();
    for _ in 0..n {
        std::hint::black_box(firewall::session_note(&e.ctx(Tier::High)));
    }
    let per = start.elapsed() / n;
    println!("session_note: {per:?} per call over {n} calls");
}
