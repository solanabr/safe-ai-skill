//! G5 fixture: key and secret file hygiene (`gates::keyfiles`), the git staging gate with the
//! headless conversion, and the SessionStart sweep.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use safe_ai_skill::gates::keyfiles;
use safe_ai_skill::headless;
use safe_ai_skill::io::Decision;
use safe_ai_skill::policy::tier::Tier;
use serde_json::Value;

const FIXTURE: &str = include_str!("fixtures/ex/g5-keyfiles.jsonl");

/// Other writers' fixtures, read as a benign check: no case this gate fires on may want none.
const OTHERS: &[&str] = &[
    include_str!("fixtures/gap/w1-tamper.jsonl"),
    include_str!("fixtures/gap/w2-exfil.jsonl"),
    include_str!("fixtures/gap/w3-envdump.jsonl"),
    include_str!("fixtures/gap/w4-fetchexec.jsonl"),
    include_str!("fixtures/gap/w5-onchain.jsonl"),
    include_str!("fixtures/gap/w6-mcp-encoded.jsonl"),
    include_str!("fixtures/fc/w8-git.jsonl"),
    include_str!("fixtures/fc/w10-tamper2.jsonl"),
    include_str!("fixtures/fc/w14-reads.jsonl"),
    include_str!("fixtures/fc/w4b-fetchexec.jsonl"),
    include_str!("fixtures/fc/w5b-onchain.jsonl"),
];

fn label(decision: &Decision) -> &'static str {
    match decision {
        Decision::Ask { .. } => "A",
        Decision::Deny { .. } => "D",
        _ => "-",
    }
}

/// One HOME (and an empty global git ignore) for the whole test process, so the user's own
/// ignore rules cannot change a verdict. Every test sets the same values, so the order does not
/// matter.
fn isolate() -> PathBuf {
    static HOME: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    HOME.get_or_init(|| {
        let home =
            std::env::temp_dir().join(format!("safe-ai-skill-g5-home-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(home.join(".config")).unwrap();
        let home = home.canonicalize().unwrap();
        std::env::set_var("HOME", &home);
        std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
        home
    })
    .clone()
}

fn temp(tag: &str) -> PathBuf {
    isolate();
    let base = std::env::temp_dir().join(format!(
        "safe-ai-skill-g5-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    base.canonicalize().unwrap()
}

fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .args(["-c", "user.name=t", "-c", "user.email=t@t"])
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {out:?}");
}

fn write(dir: &Path, rel: &str, body: &str) {
    let path = dir.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, body).unwrap();
}

/// A git repository holding the case's files, with `tracked` added to the index and `modify`
/// rewritten afterwards.
fn setup(case: &Value, tag: &str) -> PathBuf {
    let dir = temp(tag);
    git(&dir, &["init", "-q"]);
    if let Some(files) = case["cwd_files"].as_object() {
        for (rel, body) in files {
            write(&dir, rel, body.as_str().unwrap_or(""));
        }
    }
    if let Some(tracked) = case["tracked"].as_array() {
        let mut args = vec!["add", "-f", "--"];
        args.extend(tracked.iter().filter_map(Value::as_str));
        git(&dir, &args);
    }
    if let Some(modify) = case["modify"].as_object() {
        for (rel, body) in modify {
            write(&dir, rel, body.as_str().unwrap_or(""));
        }
    }
    dir
}

fn run(command: &str, cwd: &Path, tier: Tier, headless_session: bool) -> Decision {
    let verdict = keyfiles::decide_bash(command, cwd, tier);
    let decision = verdict.map(Decision::from).unwrap_or(Decision::Defer);
    headless::apply(decision, headless_session)
}

fn bash_cases(text: &str) -> Vec<Value> {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .filter(|c| c["tool"] == "Bash" && c["tool_input"]["command"].is_string())
        .collect()
}

#[test]
fn fixture_cases() {
    let mut failures = Vec::new();
    for (n, case) in bash_cases(FIXTURE).iter().enumerate() {
        let id = case["id"].as_str().unwrap();
        let command = case["tool_input"]["command"].as_str().unwrap();
        let tier = Tier::parse(case["tier"].as_str().unwrap()).unwrap();
        let dir = setup(case, &format!("fx{n}"));
        let got = run(command, &dir, tier, case["headless"].as_bool().unwrap());
        if label(&got) != case["want"].as_str().unwrap() {
            failures.push(format!("{id}: want {}, got {got:?}", case["want"]));
        }
        if let Decision::Ask { reason } | Decision::Deny { reason } = &got {
            for body in case["cwd_files"]
                .as_object()
                .into_iter()
                .flat_map(|o| o.values())
            {
                let body = body.as_str().unwrap_or("");
                if body.len() > 8 && reason.contains(body.trim()) {
                    failures.push(format!("{id}: reason prints file content"));
                }
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn reasons_are_one_sentence_ending_in_a_remedy() {
    for (n, case) in bash_cases(FIXTURE).iter().enumerate() {
        if case["want"] == "-" || case["headless"] == true {
            continue;
        }
        let command = case["tool_input"]["command"].as_str().unwrap();
        let tier = Tier::parse(case["tier"].as_str().unwrap()).unwrap();
        let dir = setup(case, &format!("rs{n}"));
        if let Decision::Ask { reason } | Decision::Deny { reason } =
            run(command, &dir, tier, false)
        {
            assert!(reason.ends_with('.'), "{reason}");
            assert_eq!(reason.matches(". ").count(), 0, "{reason}");
            assert!(reason.contains(".gitignore"), "{reason}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn other_fixtures_wanting_none_stay_silent() {
    let mut fired = Vec::new();
    for (t, text) in OTHERS.iter().enumerate() {
        for (n, case) in bash_cases(text).iter().enumerate() {
            if case["want"] != "-" {
                continue;
            }
            let command = case["tool_input"]["command"].as_str().unwrap();
            if !keyfiles::may_concern(command) {
                continue;
            }
            let tier = Tier::parse(case["tier"].as_str().unwrap_or("relaxed")).unwrap();
            let dir = setup(case, &format!("o{t}-{n}"));
            let got = run(
                command,
                &dir,
                tier,
                case["headless"].as_bool().unwrap_or(false),
            );
            if label(&got) != "-" {
                fired.push(format!("{}: {got:?}", case["id"]));
            }
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
    assert!(fired.is_empty(), "{}", fired.join("\n"));
}

// ---- SessionStart sweep ----------------------------------------------------------------

#[cfg(unix)]
fn chmod(dir: &Path, rel: &str, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir.join(rel), std::fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(unix)]
#[test]
fn sweep_reports_readable_tracked_and_unignored_key_files() {
    let dir = temp("sweep");
    git(&dir, &["init", "-q"]);
    write(&dir, ".gitignore", ".env\n");
    write(&dir, ".env", "API_KEY=sk_live_sweep_value\n");
    chmod(&dir, ".env", 0o644);
    write(&dir, "config/.env.production", "DB_PASSWORD=sweep_pw\n");
    chmod(&dir, "config/.env.production", 0o600);
    write(&dir, "store/app.p12", "\u{0}bin");
    chmod(&dir, "store/app.p12", 0o600);
    git(&dir, &["add", "-f", "store/app.p12"]);
    let notice = keyfiles::session_notice(&dir).expect("a notice");
    assert!(!notice.contains('\n'), "{notice}");
    assert!(
        notice.contains(".env (env file with values: group/world-readable)"),
        "{notice}"
    );
    assert!(
        notice.contains("config/.env.production (env file with values: not in .gitignore)"),
        "{notice}"
    );
    assert!(
        notice.contains("store/app.p12 (PKCS#12 key store: tracked by git)"),
        "{notice}"
    );
    assert!(!notice.contains("sk_live_sweep_value") && !notice.contains("sweep_pw"));
    assert!(notice.starts_with("safe-ai-skill key hygiene: 3 key or secret files need attention"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn sweep_is_silent_on_a_tidy_project() {
    let dir = temp("tidy");
    git(&dir, &["init", "-q"]);
    write(&dir, ".gitignore", ".env\n*.key\n");
    write(&dir, ".env", "API_KEY=x1\n");
    chmod(&dir, ".env", 0o600);
    write(&dir, ".env.example", "API_KEY=\n");
    write(&dir, "id_ed25519.pub", "ssh-ed25519 AAAA u@h\n");
    write(
        &dir,
        "certs/ca.pem",
        &format!(
            "{0}BEGIN CERTIFICATE{0}\nMIIDdzCCAl+gAwIBAgIEAgAAuTANBgkq\n{0}END CERTIFICATE{0}\n",
            "-----"
        ),
    );
    write(&dir, "node_modules/pkg/.env", "LEAK=1\n");
    write(&dir, "target/debug/.env", "LEAK=1\n");
    write(&dir, "src/main.rs", "fn main() {}\n");
    git(&dir, &["add", ".gitignore", ".env.example", "src/main.rs"]);
    assert_eq!(keyfiles::session_notice(&dir), None);
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn sweep_lists_tracked_key_files_removed_from_the_tree() {
    let dir = temp("removed");
    git(&dir, &["init", "-q"]);
    write(&dir, "deploy/release.jks", "\u{0}\u{1}");
    git(&dir, &["add", "deploy/release.jks"]);
    std::fs::remove_file(dir.join("deploy/release.jks")).unwrap();
    let notice = keyfiles::session_notice(&dir).expect("a notice");
    assert!(
        notice.contains("deploy/release.jks (Java key store: tracked by git)"),
        "{notice}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sweep_skips_a_home_directory_without_a_repository() {
    let home = isolate();
    write(&home, ".env", "API_KEY=x\n");
    assert_eq!(keyfiles::session_notice(&home), None);
    let _ = std::fs::remove_file(home.join(".env"));
}

#[test]
fn sweep_is_bounded() {
    let dir = temp("bounded");
    git(&dir, &["init", "-q"]);
    for i in 0..3000 {
        write(&dir, &format!("d{}/f{i}.rs", i % 50), "x\n");
    }
    write(&dir, "deep/a/b/c/d/e/f/g/h/i/j/.env", "K=v\n");
    let start = Instant::now();
    let _ = keyfiles::session_notice(&dir);
    assert!(start.elapsed().as_millis() < 2000);
    let found = keyfiles::sweep(&dir, keyfiles::SESSION_CAPS);
    assert!(
        found.iter().all(|f| !f.rel.starts_with("deep/")),
        "{found:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Release micro-benchmark: the prefilter over every Bash payload in this and the other
/// fixtures, and the full decision on this fixture's git cases.
/// `cargo test --release --test ex_g5-keyfiles -- --ignored --nocapture`.
#[test]
#[ignore]
fn bench() {
    let mut commands: Vec<String> = Vec::new();
    for text in std::iter::once(FIXTURE).chain(OTHERS.iter().copied()) {
        for case in bash_cases(text) {
            commands.push(case["tool_input"]["command"].as_str().unwrap().to_string());
        }
    }
    let empty = temp("bench");
    git(&empty, &["init", "-q"]);
    let iterations = 200;
    let start = Instant::now();
    for _ in 0..iterations {
        for command in &commands {
            std::hint::black_box(keyfiles::decide_bash(command, &empty, Tier::High));
        }
    }
    let total = start.elapsed();
    let calls = iterations * commands.len();
    let silent = commands
        .iter()
        .filter(|c| !keyfiles::may_concern(c))
        .count();
    println!(
        "bench: {} payloads ({silent} prefiltered out) x {iterations} = {calls} calls in \
         {total:?} ({:.2} us/call, empty repo)",
        commands.len(),
        total.as_secs_f64() * 1e6 / calls as f64
    );
    let cases = bash_cases(FIXTURE);
    let mut worst = 0f64;
    let mut sum = 0f64;
    for (n, case) in cases.iter().enumerate() {
        let dir = setup(case, &format!("b{n}"));
        let command = case["tool_input"]["command"].as_str().unwrap();
        let t = Instant::now();
        for _ in 0..20 {
            std::hint::black_box(keyfiles::decide_bash(command, &dir, Tier::High));
        }
        let us = t.elapsed().as_secs_f64() * 1e6 / 20.0;
        worst = worst.max(us);
        sum += us;
        let _ = std::fs::remove_dir_all(&dir);
    }
    println!(
        "bench: fixture repos: {:.1} us/call mean, {worst:.1} us worst over {} cases",
        sum / cases.len() as f64,
        cases.len()
    );
    let t = Instant::now();
    let _ = keyfiles::session_notice(&empty);
    println!("bench: session sweep of an empty repo {:?}", t.elapsed());
    let _ = std::fs::remove_dir_all(&empty);
}
