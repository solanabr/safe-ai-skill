//! Gap closure W3 (env dumps, decisions D2 and D5): the fixture
//! `tests/fixtures/gap/w3-envdump.jsonl` through `envread::decide_bash` and
//! `envread::production_verdict`, and the PostToolUse redaction of env-dump output end to end.

mod common;

use common::{Invocation, TempDir};
use safe_ai_skill::gate::Verdict;
use safe_ai_skill::gates::envread;
use safe_ai_skill::policy::tier::{EnvRead, Tier};
use safe_ai_skill::redact;
use serde_json::{json, Value};

fn label(v: Option<Verdict>) -> &'static str {
    match v {
        None | Some(Verdict::NoOpinion) | Some(Verdict::Allow(_)) => "allow",
        Some(Verdict::Ask(_)) => "ask",
        Some(Verdict::Deny(_)) => "deny",
    }
}

fn fixture() -> Vec<Value> {
    let text = include_str!("fixtures/gap/w3-envdump.jsonl");
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[test]
fn fixture_cases_reach_their_verdict() {
    let mut failures = Vec::new();
    for case in fixture() {
        let id = case["id"].as_str().unwrap();
        let want = case["want"].as_str().unwrap();
        let tier = Tier::parse(case["tier"].as_str().unwrap()).unwrap();
        let got = match case["tool"].as_str().unwrap() {
            "Bash" => label(envread::decide_bash(
                case["tool_input"]["command"].as_str().unwrap(),
            )),
            "EnvRead" => label(envread::production_verdict(
                tier,
                EnvRead::Tier,
                case["tool_input"]["file"].as_str().unwrap(),
                true,
                "env keys / env set".into(),
            )),
            other => panic!("{id}: unknown tool {other}"),
        };
        if got != want {
            failures.push(format!(
                "{id} ({}): want {want}, got {got}",
                case["tool_input"]
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn production_names() {
    for name in [
        ".env.production",
        ".env.prod",
        ".ENV.PRODUCTION.local",
        ".env.prod.eu",
    ] {
        assert!(envread::is_production_env_name(name), "{name}");
    }
    for name in [
        ".env",
        ".env.local",
        ".env.development",
        ".env.production.example",
        "prod.env",
    ] {
        assert!(!envread::is_production_env_name(name), "{name}");
    }
    // The user's `env_read: deny` and non-project files keep their rows.
    let v = |tier, env_read, project| {
        label(envread::production_verdict(
            tier,
            env_read,
            "apps/web/.env.production",
            project,
            String::new(),
        ))
    };
    assert_eq!(v(Tier::Off, EnvRead::Deny, true), "deny");
    assert_eq!(v(Tier::Off, EnvRead::Tier, false), "deny");
    assert_eq!(v(Tier::Relaxed, EnvRead::Tier, true), "deny");
    assert_eq!(v(Tier::Off, EnvRead::Tier, true), "allow");
}

#[test]
fn secret_env_names() {
    for name in [
        "HELIUS_API_KEY",
        "GITHUB_TOKEN",
        "AWS_SECRET_ACCESS_KEY",
        "DB_PASSWORD",
        "PGPASSWD",
        "WALLET_MNEMONIC",
        "SEED_PHRASE",
        "PRIVATE_KEY",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "OAUTH_CLIENT",
        "AUTHORIZATION",
        "apikey",
        "UPGRADE_AUTHORITY_KEYPAIR",
    ] {
        assert!(redact::is_secret_env_name(name), "{name}");
    }
    for name in [
        "PATH",
        "HOME",
        "SOLANA_PUBKEY",
        "MINT_PUBLIC_KEY",
        "UPGRADE_AUTHORITY",
        "GIT_AUTHOR_NAME",
        "GIT_AUTHOR_EMAIL",
        "SSH_AUTH_SOCK",
        "TOKENIZERS_PARALLELISM",
        "PYTHONHASHSEED",
        "AUTHOR",
        "",
    ] {
        assert!(!redact::is_secret_env_name(name), "{name}");
    }
}

#[test]
fn env_dump_shapes_are_blanked() {
    let cases = [
        (
            "HELIUS_API_KEY=abc123\nPATH=/usr/bin\n",
            "HELIUS_API_KEY=***REDACTED:env***\nPATH=/usr/bin\n",
        ),
        (
            "declare -x GITHUB_TOKEN=\"gh_1\"\ndeclare -x HOME=\"/h\"",
            "declare -x GITHUB_TOKEN=\"***REDACTED:env***\"\ndeclare -x HOME=\"/h\"",
        ),
        (
            "export DB_PASSWORD=hunter2",
            "export DB_PASSWORD=***REDACTED:env***",
        ),
        (
            "DB_PASSWORD='multi\nline'\nX=1",
            "DB_PASSWORD='***REDACTED:env***'\nX=1",
        ),
        (
            "A_TOKEN='it'\\''s'\nB=2",
            "A_TOKEN='***REDACTED:env***'\nB=2",
        ),
        ("MY_SECRET=$'a\\'b'\n", "MY_SECRET=$'***REDACTED:env***'\n"),
        (
            "K_TOKEN=x\0PATH=/bin\0",
            "K_TOKEN=***REDACTED:env***\0PATH=/bin\0",
        ),
        (
            "environ({'HELIUS_API_KEY': 'abc', 'HOME': '/h'})",
            "environ({'HELIUS_API_KEY': '***REDACTED:env***', 'HOME': '/h'})",
        ),
        (
            "{ HELIUS_API_KEY: 'abc', HOME: '/h' }",
            "{ HELIUS_API_KEY: '***REDACTED:env***', HOME: '/h' }",
        ),
        (
            "{\"API_TOKEN\": \"t\\\"x\"}",
            "{\"API_TOKEN\": \"***REDACTED:env***\"}",
        ),
    ];
    for (input, want) in cases {
        assert_eq!(
            redact::scrub_env_lines(input).as_deref(),
            Some(want),
            "{input:?}"
        );
    }
    for quiet in [
        "PATH=/usr/bin\nHOME=/h",
        "EMPTY_TOKEN=\n",
        "SOLANA_PUBKEY=9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",
        "x = api_key=1 inside a line",
        "{\"tokenProgram\": \"Tokenkeg\"}",
        "A_KEY=«redacted:A_KEY»",
    ] {
        assert_eq!(redact::scrub_env_lines(quiet), None, "{quiet:?}");
    }
}

#[test]
fn redact_hook_blanks_printenv_output_but_not_read_output() {
    let project = TempDir::new("w3-proj");
    let home = TempDir::new("w3-home");
    let data = TempDir::new("w3-data");
    let run = |tool: &str, response: Value| {
        Invocation::new(&["redact"])
            .plugin_data(data.path())
            .home(home.path())
            .stdin(
                json!({
                    "hook_event_name": "PostToolUse",
                    "cwd": project.path(),
                    "tool_name": tool,
                    "tool_input": {"command": "printenv"},
                    "tool_response": response,
                })
                .to_string(),
            )
            .run()
    };
    let out = run(
        "Bash",
        json!({"stdout": "HOME=/h\nDB_PASSWORD=hunter2\nGITHUB_TOKEN=x1\n", "stderr": "", "interrupted": false}),
    );
    let v = out.json();
    assert_eq!(
        v["hookSpecificOutput"]["updatedToolOutput"]["stdout"],
        "HOME=/h\nDB_PASSWORD=***REDACTED:env***\nGITHUB_TOKEN=***REDACTED:env***\n",
        "{v}"
    );
    assert_eq!(
        v["hookSpecificOutput"]["updatedToolOutput"]["interrupted"],
        false
    );
    // A Read of a config file is not env-dump output: no env-line pass.
    let out = run(
        "Read",
        json!({"type": "text", "file": {"filePath": "/p/app.ini", "content": "DB_PASSWORD=hunter2\n"}}),
    );
    assert!(out.stdout.trim().is_empty(), "{}", out.stdout);
}

/// Before/after cost over the 231 difftest payloads: `cargo test --release --test
/// gap_w3-envdump -- --ignored --nocapture`. Set `W3_BENCH` to the results2.json path.
#[test]
#[ignore]
fn bench_decide_bash() {
    let Ok(path) = std::env::var("W3_BENCH") else {
        return;
    };
    let rows: Vec<Value> = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    for r in &rows {
        let case = &r["case"];
        if let (Some(c), true) = (case["input"]["command"].as_str(), case["tool"] == "Bash") {
            if let Some(Verdict::Deny(_)) = envread::decide_bash(c) {
                println!("deny {} want={} {c}", case["id"], case["want"]);
            }
        }
    }
    let commands: Vec<String> = rows
        .iter()
        .filter(|r| r["case"]["tool"] == "Bash")
        .filter_map(|r| r["case"]["input"]["command"].as_str().map(str::to_string))
        .collect();
    let rounds = 2000;
    let t = std::time::Instant::now();
    for _ in 0..rounds {
        for c in &commands {
            std::hint::black_box(safe_ai_skill::context::shell::parse(c));
        }
    }
    let parse = t.elapsed();
    let t = std::time::Instant::now();
    for _ in 0..rounds {
        for c in &commands {
            std::hint::black_box(envread::decide_bash(c));
        }
    }
    let decide = t.elapsed();
    let n = (rounds * commands.len()) as f64;
    println!(
        "{} Bash payloads x {rounds}: shell::parse {:.2} us/cmd, decide_bash {:.2} us/cmd",
        commands.len(),
        parse.as_secs_f64() * 1e6 / n,
        decide.as_secs_f64() * 1e6 / n
    );
    let text = "HOME=/h\nDB_PASSWORD=hunter2\n".repeat(2000);
    let t = std::time::Instant::now();
    for _ in 0..50 {
        std::hint::black_box(redact::scrub_env_lines(&text));
    }
    println!(
        "scrub_env_lines on {} KiB: {:.1} us",
        text.len() / 1024,
        t.elapsed().as_secs_f64() * 1e6 / 50.0
    );
}
