//! `safe-ai-skill env keys` with a varlock `.env.schema` beside the env file, and
//! `safe-ai-skill env init-schema` (spec D3.8.4). The schema is parsed natively; varlock is
//! never run, and no value is ever printed or copied.

mod common;

use std::fs;
use std::path::Path;

use common::{Invocation, Run, TempDir};

const SECRET: &str = "sk_\x6cive_51HxYzSECRETvalue000";

fn env(dir: &Path, args: &[&str]) -> Run {
    let mut full = vec!["env"];
    full.extend_from_slice(args);
    Invocation::new(&full).cwd(dir).home(dir).run()
}

fn assert_no_secret(run: &Run) {
    assert!(
        !run.stdout.contains(SECRET),
        "stdout leaked: {}",
        run.stdout
    );
    assert!(
        !run.stderr.contains(SECRET),
        "stderr leaked: {}",
        run.stderr
    );
}

fn project() -> TempDir {
    let dir = TempDir::new("env-spec");
    fs::write(
        dir.join(".env"),
        format!("STRIPE_KEY={SECRET}\nRPC_URL=https://api.devnet.solana.com\nEXTRA=1\n"),
    )
    .unwrap();
    fs::write(
        dir.join(".env.schema"),
        "# @defaultSensitive=false\n# ---\n# @sensitive @required\n# @type=string(startsWith=sk_)\nSTRIPE_KEY=\n# @type=url\nRPC_URL=\n# @required\nWEBHOOK_SECRET=\n",
    )
    .unwrap();
    dir
}

#[test]
fn keys_text_annotates_from_the_schema() {
    let dir = project();
    let run = env(dir.path(), &["keys"]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_no_secret(&run);
    let out = &run.stdout;
    let row = |key: &str| {
        out.lines()
            .find(|l| l.split_whitespace().nth(1) == Some(key))
            .unwrap_or_else(|| panic!("no {key} row:\n{out}"))
            .to_string()
    };
    assert!(
        out.lines().next().unwrap().contains("schema=.env.schema"),
        "{out}"
    );
    assert!(
        row("STRIPE_KEY").ends_with("[sensitive required type=string]"),
        "{out}"
    );
    assert!(row("RPC_URL").ends_with("[type=url]"), "{out}");
    assert!(row("EXTRA").ends_with("[undeclared]"), "{out}");
    assert!(
        out.contains("# declared in .env.schema but unset: WEBHOOK_SECRET (required)"),
        "{out}"
    );
}

#[test]
fn keys_json_carries_schema_fields() {
    let dir = project();
    let run = env(dir.path(), &["keys", "--json"]);
    assert_no_secret(&run);
    let v: serde_json::Value = serde_json::from_str(run.stdout.trim()).unwrap();
    assert_eq!(v["schema"], ".env.schema");
    let keys = v["keys"].as_array().unwrap();
    let stripe = keys.iter().find(|k| k["key"] == "STRIPE_KEY").unwrap();
    assert_eq!(stripe["schema"]["declared"], true);
    assert_eq!(stripe["schema"]["sensitive"], true);
    assert_eq!(stripe["schema"]["required"], true);
    assert_eq!(stripe["schema"]["type"], "string");
    let rpc = keys.iter().find(|k| k["key"] == "RPC_URL").unwrap();
    assert_eq!(rpc["schema"]["sensitive"], false);
    assert!(rpc["schema"]["required"].is_null(), "not declared: {rpc}");
    let extra = keys.iter().find(|k| k["key"] == "EXTRA").unwrap();
    assert_eq!(extra["schema"]["declared"], false);
    assert_eq!(
        v["declared_unset"],
        serde_json::json!([{ "key": "WEBHOOK_SECRET", "required": true, "sensitive": false }])
    );
}

#[test]
fn keys_without_a_schema_are_unchanged() {
    let dir = TempDir::new("env-spec-plain");
    fs::write(dir.join(".env"), "A=1\n").unwrap();
    let run = env(dir.path(), &["keys"]);
    assert!(!run.stdout.contains("schema"), "{}", run.stdout);
    assert!(!run.stdout.contains('['), "{}", run.stdout);
}

#[test]
fn init_schema_writes_keys_only_and_refuses_to_overwrite() {
    let dir = TempDir::new("env-spec-init");
    fs::write(
        dir.join(".env"),
        format!("# comment\nexport STRIPE_KEY={SECRET}\nRPC_URL=\"https://x.example.com/?k=v\"\nSTRIPE_KEY=again-{SECRET}\n#OLD=1\n"),
    )
    .unwrap();
    let run = env(dir.path(), &["init-schema"]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_no_secret(&run);
    assert!(
        run.stdout.contains("wrote .env.schema (2 keys"),
        "{}",
        run.stdout
    );
    let schema = fs::read_to_string(dir.join(".env.schema")).unwrap();
    assert!(
        !schema.contains(SECRET) && !schema.contains("example.com"),
        "{schema}"
    );
    assert!(schema.contains("# @defaultSensitive=true\n"), "{schema}");
    assert!(schema.contains("\n# ---\n"), "{schema}");
    assert!(schema.ends_with("STRIPE_KEY=\nRPC_URL=\n"), "{schema}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(dir.join(".env.schema"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o644);
    }

    let again = env(dir.path(), &["init-schema"]);
    assert_eq!(again.code, Some(1));
    assert!(again.stderr.contains("already exists"), "{}", again.stderr);
    assert_eq!(fs::read_to_string(dir.join(".env.schema")).unwrap(), schema);
}

#[test]
fn init_schema_from_another_env_file_writes_beside_it() {
    let dir = TempDir::new("env-spec-init2");
    fs::create_dir_all(dir.join("app")).unwrap();
    fs::write(dir.join("app/.env.local"), "TOKEN=abcdefghijklmnop\n").unwrap();
    let run = env(dir.path(), &["init-schema", "app/.env.local"]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    let schema = fs::read_to_string(dir.join("app/.env.schema")).unwrap();
    assert!(schema.ends_with("TOKEN=\n"), "{schema}");
    assert!(!schema.contains("abcdefghijklmnop"));
}

#[test]
fn init_schema_refuses_non_env_files() {
    let dir = TempDir::new("env-spec-init3");
    fs::write(dir.join("notes.txt"), "A=1\n").unwrap();
    let run = env(dir.path(), &["init-schema", "notes.txt"]);
    assert_eq!(run.code, Some(1));
    assert!(!dir.join(".env.schema").exists());
}

#[test]
fn env_set_refuses_the_schema() {
    let dir = project();
    let run = Invocation::new(&["env", "set", ".env.schema", "K"])
        .cwd(dir.path())
        .home(dir.path())
        .stdin("v")
        .run();
    assert_eq!(run.code, Some(1));
    assert!(
        run.stderr.contains(".env.schema holds keys"),
        "{}",
        run.stderr
    );
}

// ---------------------------------------------------------------------------------------
// C8 SessionStart tip and C6 doctor
// ---------------------------------------------------------------------------------------

fn session(project: &Path, data: &Path, home: &Path) -> Run {
    Invocation::new(&["verify", "session"])
        .plugin_data(data)
        .home(home)
        .stdin(
            serde_json::json!({
                "hook_event_name": "SessionStart",
                "source": "startup",
                "cwd": project,
            })
            .to_string(),
        )
        .run()
}

#[test]
fn session_tip_once_when_env_files_lack_a_schema() {
    let proj = TempDir::new("tip-proj");
    let data = TempDir::new("tip-data");
    let home = TempDir::new("tip-home");
    fs::write(proj.join(".env"), format!("K={SECRET}\n")).unwrap();
    let first = session(proj.path(), data.path(), home.path());
    assert_no_secret(&first);
    let v: serde_json::Value = serde_json::from_str(first.stdout.trim()).unwrap();
    let msg = v["systemMessage"].as_str().unwrap_or_default();
    assert!(msg.contains("safe-ai-skill env init-schema"), "{msg}");
    let second = session(proj.path(), data.path(), home.path());
    assert!(
        !second.stdout.contains("init-schema"),
        "tip repeats: {}",
        second.stdout
    );
}

#[test]
fn session_tip_silent_with_a_schema_or_without_env_files() {
    let data = TempDir::new("tip-data2");
    let home = TempDir::new("tip-home2");
    let with_schema = TempDir::new("tip-schema");
    fs::write(with_schema.join(".env"), "K=v\n").unwrap();
    fs::write(with_schema.join(".env.schema"), "# ---\nK=\n").unwrap();
    let none = TempDir::new("tip-none");
    fs::write(none.join(".env.example"), "K=\n").unwrap();
    for proj in [&with_schema, &none] {
        let run = session(proj.path(), data.path(), home.path());
        assert!(!run.stdout.contains("init-schema"), "{}", run.stdout);
    }
}

#[test]
fn doctor_recommends_sandbox_deny_read() {
    let home = TempDir::new("doctor-home");
    let proj = TempDir::new("doctor-proj");
    let run = Invocation::new(&["doctor"])
        .home(home.path())
        .cwd(proj.path())
        .run();
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    let out = &run.stdout;
    assert!(out.contains("sandbox: not enabled"), "{out}");
    for glob in [
        "**/*-keypair.json",
        "~/.config/solana/*.json",
        "**/.env",
        "~/.ssh/id_*",
    ] {
        assert!(out.contains(glob), "{glob}: {out}");
    }
    assert!(out.contains("\"denyRead\""), "{out}");

    fs::create_dir_all(home.join(".claude")).unwrap();
    let globs: Vec<String> = safe_ai_skill::doctor::RECOMMENDED_DENY_READ
        .iter()
        .map(|g| g.to_string())
        .collect();
    fs::write(
        home.join(".claude/settings.json"),
        serde_json::json!({ "sandbox": { "enabled": true, "filesystem": { "denyRead": globs } } })
            .to_string(),
    )
    .unwrap();
    let ok = Invocation::new(&["doctor"])
        .home(home.path())
        .cwd(proj.path())
        .run();
    assert!(ok.stdout.contains("sandbox: enabled"), "{}", ok.stdout);
    assert!(
        ok.stdout.contains("denyRead: all recommended"),
        "{}",
        ok.stdout
    );
}
