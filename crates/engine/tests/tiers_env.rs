//! D8 v2 project env by tier (spec §2 rows, §1.4; F2): raw reads (Read, Bash readers, varlock
//! printers) with the default `env_read: deny`, the user-scope opt-ins `tier` and `ask` (only
//! while the sandbox is on), schemas and templates, writes (Write/Edit/MultiEdit, agent
//! `env set|unset`), and redaction, including the opted-in Read → Edit round trip that must
//! never clobber the file.
//!
//! Rows that need `Tier::Off`, a loosened `env_read` or a forced sandbox state go through an
//! authenticated `tier.json` and the sandbox override, which only `--features test-hooks`
//! builds honour (`tests/common`); the verdict table itself is also pinned library-level.

mod common;

use std::path::Path;

use common::{decision_label, EnvRead, Invocation, Run, SandboxMode, TempDir, Tier, TEST_HOOKS};
use safe_ai_skill::gate::Verdict;
use safe_ai_skill::gates::envread;
use safe_ai_skill::sandbox::SandboxState;
use serde_json::{json, Value};

const TIERS: [Tier; 4] = [Tier::Off, Tier::Relaxed, Tier::Medium, Tier::High];

/// The tiers a binary run can select in this build (`Off` needs `test-hooks`).
fn tiers() -> Vec<Tier> {
    TIERS
        .into_iter()
        .filter(|t| TEST_HOOKS || *t != Tier::Off)
        .collect()
}

/// A 32-char value under a secret-looking key.
const HELIUS: &str = "hk7Qw2Lp9Xz4Rt6Yb1Nc8Vd3Fg5Hj0Ks";
const DB_URL: &str = "postgres://app:pw_5f4e3d2c1b0a9988@db.internal:5432/app";

/// A project dir with env files, a separate HOME and data dir, and an empty `PATH` (so
/// `varlock` is never found and never run).
struct Proj {
    project: TempDir,
    home: TempDir,
    data: TempDir,
    path: TempDir,
}

/// Who chose what: the effective tier, the user's `env_read` (if any) and the sandbox.
#[derive(Clone, Copy)]
struct Setup {
    tier: Tier,
    env_read: Option<EnvRead>,
    sandbox: Option<SandboxMode>,
    /// Force the sandbox state `unknown` (Linux without bwrap, Windows); `test-hooks` only.
    unknown_sandbox: bool,
}

impl Setup {
    fn at(tier: Tier) -> Self {
        Setup {
            tier,
            env_read: None,
            sandbox: None,
            unknown_sandbox: false,
        }
    }

    #[cfg(feature = "test-hooks")]
    fn env_read(mut self, env_read: EnvRead) -> Self {
        self.env_read = Some(env_read);
        self
    }

    fn sandbox(mut self, mode: SandboxMode) -> Self {
        self.sandbox = Some(mode);
        self
    }

    #[cfg(feature = "test-hooks")]
    fn sandbox_unknown(mut self) -> Self {
        self.unknown_sandbox = true;
        self
    }
}

impl Proj {
    fn new() -> Self {
        let p = Proj {
            project: TempDir::new("tenv-proj"),
            home: TempDir::new("tenv-home"),
            data: TempDir::new("tenv-data"),
            path: TempDir::new("tenv-path"),
        };
        p.write(
            ".env",
            &format!("HELIUS_KEY={HELIUS}\nCLUSTER=devnet\nDATABASE_URL={DB_URL}\n"),
        );
        p.write(
            "apps/web/.env.local",
            "WEB_SECRET_TOKEN=web_tok_aaaaaaaaaaaa\n",
        );
        p.write(".envrc", "export DIRENV_TOKEN=direnv_bbbbbbbbbbbb\n");
        p
    }

    fn write(&self, rel: &str, body: &str) {
        let path = self.project.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, body).unwrap();
    }

    fn run(&self, setup: Setup, args: &[&str], stdin: String) -> Run {
        let mut inv = Invocation::new(args)
            .plugin_data(self.data.path())
            .home(self.home.path())
            .cwd(self.project.path())
            .env("PATH", self.path.path().to_str().unwrap())
            .tier(setup.tier)
            .stdin(stdin);
        if let Some(env_read) = setup.env_read {
            inv = inv.env_read(env_read);
        }
        if let Some(mode) = setup.sandbox {
            inv = inv.sandbox(mode);
        }
        if setup.unknown_sandbox {
            inv = inv.env(safe_ai_skill::sandbox::TEST_OVERRIDE_ENV, "unknown");
        }
        inv.run()
    }

    fn pre(&self, setup: Setup, sub: &str, tool: &str, input: Value) -> Run {
        let payload = json!({
            "hook_event_name": "PreToolUse",
            "cwd": self.project.path(),
            "tool_name": tool,
            "tool_input": input,
        });
        self.run(setup, &[sub], payload.to_string())
    }

    fn read(&self, setup: Setup, file: &str) -> Run {
        self.pre(setup, "gate-read", "Read", json!({ "file_path": file }))
    }

    fn bash(&self, setup: Setup, command: &str) -> Run {
        self.pre(
            setup,
            "gate-bash-secrets",
            "Bash",
            json!({ "command": command }),
        )
    }

    fn tamper(&self, setup: Setup, tool: &str, input: Value) -> Run {
        self.pre(setup, "gate-tamper", tool, input)
    }

    fn redact(&self, setup: Setup, tool: &str, input: Value, response: Value) -> Run {
        let payload = json!({
            "hook_event_name": "PostToolUse",
            "cwd": self.project.path(),
            "tool_name": tool,
            "tool_input": input,
            "tool_response": response,
        });
        self.run(setup, &["redact"], payload.to_string())
    }
}

fn reason(run: &Run) -> String {
    run.json()["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// The spec's verdict cell for `tier` in a row `[off, relaxed, medium, high]`.
fn cell(row: [&'static str; 4], tier: Tier) -> &'static str {
    let i = TIERS.iter().position(|t| *t == tier).unwrap();
    row[i]
}

/// Every raw-read form of the §2 raw-read and varlock-printer rows.
enum Form {
    Read(&'static str),
    Bash(&'static str),
}

const RAW_FORMS: [Form; 8] = [
    Form::Read("./.env"),
    Form::Read("apps/web/.env.local"),
    Form::Read(".envrc"),
    Form::Bash("cat .env"),
    Form::Bash("grep K .env"),
    Form::Bash("source .env"),
    Form::Bash("varlock printenv"),
    Form::Bash("varlock load --format json"),
];

fn raw(p: &Proj, setup: Setup, form: &Form) -> Run {
    match form {
        Form::Read(f) => p.read(setup, f),
        Form::Bash(c) => p.bash(setup, c),
    }
}

fn form_name(form: &Form) -> &'static str {
    match form {
        Form::Read(f) | Form::Bash(f) => f,
    }
}

/// Assert one §2 row for every raw-read form at every tier this build can select.
fn assert_raw_row(p: &Proj, base: Setup, row: [&'static str; 4]) {
    for tier in tiers() {
        let setup = Setup { tier, ..base };
        for form in &RAW_FORMS {
            let run = raw(p, setup, form);
            assert_eq!(
                decision_label(&run),
                cell(row, tier),
                "{} at {}: {}",
                form_name(form),
                tier.label(),
                run.stdout
            );
        }
    }
}

// ---------------------------------------------------------------------------------------
// Library-level verdict table (no test-hooks needed)
// ---------------------------------------------------------------------------------------

fn kind(v: &Option<Verdict>) -> &'static str {
    match v {
        None | Some(Verdict::NoOpinion) => "",
        Some(Verdict::Allow(_)) => "allow",
        Some(Verdict::Ask(_)) => "ask",
        Some(Verdict::Deny(_)) => "deny",
    }
}

fn text(v: &Option<Verdict>) -> String {
    match v {
        Some(Verdict::Ask(r) | Verdict::Deny(r)) => r.clone(),
        _ => String::new(),
    }
}

#[test]
fn envread_verdict_table_matches_the_spec() {
    let msg = || "safe-ai-skill: .env is an env file. Use safe-ai-skill env keys .env".to_string();
    let rows: [(EnvRead, SandboxState, [&str; 4]); 9] = [
        (EnvRead::Deny, SandboxState::On, ["deny"; 4]),
        (EnvRead::Deny, SandboxState::Off, ["deny"; 4]),
        (EnvRead::Deny, SandboxState::Unknown, ["deny"; 4]),
        (EnvRead::Tier, SandboxState::On, ["", "", "deny", "deny"]),
        (EnvRead::Tier, SandboxState::Off, ["deny"; 4]),
        (EnvRead::Tier, SandboxState::Unknown, ["deny"; 4]),
        (
            EnvRead::Ask,
            SandboxState::On,
            ["ask", "ask", "ask", "deny"],
        ),
        (EnvRead::Ask, SandboxState::Off, ["deny"; 4]),
        (EnvRead::Ask, SandboxState::Unknown, ["deny"; 4]),
    ];
    for (env_read, sandbox, row) in rows {
        for tier in TIERS {
            let v = envread::verdict(tier, env_read, sandbox, msg());
            assert_eq!(
                kind(&v),
                cell(row, tier),
                "env_read {} sandbox {} tier {}",
                env_read.label(),
                sandbox.label(),
                tier.label()
            );
            let why = text(&v);
            if env_read != EnvRead::Deny && sandbox != SandboxState::On {
                assert!(
                    why.contains("opt-in suspended: sandbox not on"),
                    "{tier:?} {env_read:?} {sandbox:?}: {why}"
                );
            }
            if !why.is_empty() {
                assert!(why.contains("env keys"), "{why}");
                assert!(why.contains("env set"), "{why}");
            }
        }
    }
}

#[test]
fn a_declared_sandbox_without_platform_support_is_not_on() {
    use safe_ai_skill::sandbox::{from_declared, Declared};
    assert_eq!(from_declared(Declared::On, false), SandboxState::Unknown);
    assert_eq!(from_declared(Declared::Unset, true), SandboxState::Off);
    assert_eq!(
        from_declared(Declared::ExplicitlyOff, true),
        SandboxState::Off
    );
    for tier in TIERS {
        let v = envread::verdict(tier, EnvRead::Tier, SandboxState::Unknown, String::new());
        assert_eq!(kind(&v), "deny", "{tier:?}");
    }
}

// ---------------------------------------------------------------------------------------
// Raw reads through the binary
// ---------------------------------------------------------------------------------------

#[test]
fn default_raw_env_reads_deny_at_every_tier() {
    let p = Proj::new();
    assert_raw_row(&p, Setup::at(Tier::Relaxed), ["deny"; 4]);
}

#[test]
fn denied_raw_reads_point_to_the_env_cli_and_varlock() {
    let p = Proj::new();
    p.write(
        ".env.schema",
        "# @defaultSensitive=true\n# ---\nHELIUS_KEY=\n",
    );
    for tier in tiers() {
        for form in &RAW_FORMS {
            let why = reason(&raw(&p, Setup::at(tier), form));
            let what = form_name(form);
            assert!(why.contains("env keys"), "{what}: {why}");
            assert!(why.contains("env set"), "{what}: {why}");
            assert!(why.contains("varlock"), "{what}: {why}");
        }
    }
}

#[test]
fn a_repo_env_read_ask_stays_deny() {
    let p = Proj::new();
    p.write(".safe-ai-skill/policy.yaml", "secrets:\n  env_read: ask\n");
    assert_raw_row(&p, Setup::at(Tier::Relaxed), ["deny"; 4]);
    // Not even with the sandbox declared on.
    assert_raw_row(
        &p,
        Setup::at(Tier::Relaxed).sandbox(SandboxMode::On),
        ["deny"; 4],
    );
}

#[cfg(feature = "test-hooks")]
#[test]
fn user_env_read_tier_with_the_sandbox_on_follows_the_tier() {
    let p = Proj::new();
    let base = Setup::at(Tier::Relaxed)
        .env_read(EnvRead::Tier)
        .sandbox(SandboxMode::On);
    assert_raw_row(&p, base, ["", "", "deny", "deny"]);
}

#[cfg(feature = "test-hooks")]
#[test]
fn user_env_read_ask_with_the_sandbox_on_asks_below_high() {
    let p = Proj::new();
    let base = Setup::at(Tier::Relaxed)
        .env_read(EnvRead::Ask)
        .sandbox(SandboxMode::On);
    assert_raw_row(&p, base, ["ask", "ask", "ask", "deny"]);
}

#[cfg(feature = "test-hooks")]
#[test]
fn the_opt_in_is_suspended_unless_the_sandbox_is_on() {
    let p = Proj::new();
    for env_read in [EnvRead::Tier, EnvRead::Ask] {
        let opted = Setup::at(Tier::Relaxed).env_read(env_read);
        for base in [
            opted,
            opted.sandbox(SandboxMode::Off),
            opted.sandbox(SandboxMode::Unset),
            opted.sandbox_unknown(),
        ] {
            assert_raw_row(&p, base, ["deny"; 4]);
            let why = reason(&p.read(base, ".env"));
            assert!(why.contains("opt-in suspended: sandbox not on"), "{why}");
            assert!(why.contains("env keys"), "{why}");
        }
    }
}

#[cfg(feature = "test-hooks")]
#[test]
fn a_repo_can_tighten_the_users_opt_in() {
    let p = Proj::new();
    p.write(".safe-ai-skill/policy.yaml", "secrets:\n  env_read: deny\n");
    let base = Setup::at(Tier::Relaxed)
        .env_read(EnvRead::Tier)
        .sandbox(SandboxMode::On);
    assert_raw_row(&p, base, ["deny"; 4]);
}

#[cfg(feature = "test-hooks")]
#[test]
fn headless_turns_an_opted_in_ask_into_deny() {
    let p = Proj::new();
    let run = Invocation::new(&["gate-read"])
        .plugin_data(p.data.path())
        .home(p.home.path())
        .cwd(p.project.path())
        .tier(Tier::Relaxed)
        .env_read(EnvRead::Ask)
        .sandbox(SandboxMode::On)
        .headless(true)
        .stdin(
            json!({
                "hook_event_name": "PreToolUse",
                "cwd": p.project.path(),
                "tool_name": "Read",
                "tool_input": { "file_path": ".env" },
            })
            .to_string(),
        )
        .run();
    assert_eq!(decision_label(&run), "deny");
}

#[cfg(feature = "test-hooks")]
#[test]
fn an_opted_in_read_never_opens_key_material() {
    let p = Proj::new();
    let base = Setup::at(Tier::Relaxed)
        .env_read(EnvRead::Tier)
        .sandbox(SandboxMode::On);
    let keypair: Vec<String> = (0..64).map(|i| ((i * 7) % 256).to_string()).collect();
    p.write("deploy-keypair.json", &format!("[{}]", keypair.join(",")));
    assert_eq!(decision_label(&p.read(base, "deploy-keypair.json")), "deny");
    assert_eq!(
        decision_label(&p.bash(base, "cat deploy-keypair.json")),
        "deny"
    );
    assert_eq!(decision_label(&p.read(base, ".env")), "");
}

// ---------------------------------------------------------------------------------------
// Schemas and templates
// ---------------------------------------------------------------------------------------

/// A 64-byte Solana secret key in base58 (deterministic, not a real key).
fn bs58_secret() -> String {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let bytes: Vec<u8> = (0..64u32).map(|i| ((i * 37 + 11) % 256) as u8).collect();
    let mut digits: Vec<u8> = vec![0];
    for &b in &bytes {
        let mut carry = b as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    digits
        .iter()
        .rev()
        .map(|d| ALPHABET[*d as usize] as char)
        .collect()
}

#[test]
fn schemas_and_templates_have_no_opinion_at_every_tier() {
    let p = Proj::new();
    p.write(
        ".env.schema",
        "# @defaultSensitive=true\n# ---\nHELIUS_KEY=\n",
    );
    p.write(".env.example", "HELIUS_KEY=\nCLUSTER=devnet\n");
    for tier in tiers() {
        for file in [".env.schema", ".env.example"] {
            let run = p.read(Setup::at(tier), file);
            assert_eq!(decision_label(&run), "", "{file} at {}", tier.label());
        }
    }
}

#[test]
fn a_schema_holding_a_secret_key_denies_at_every_tier() {
    let p = Proj::new();
    p.write(
        ".env.schema",
        &format!("# ---\n# @sensitive\nDEPLOYER={}\n", bs58_secret()),
    );
    for tier in tiers() {
        let run = p.read(Setup::at(tier), ".env.schema");
        assert_eq!(decision_label(&run), "deny", "at {}", tier.label());
    }
}

// ---------------------------------------------------------------------------------------
// Writes
// ---------------------------------------------------------------------------------------

const WRITE_ROW: [&str; 4] = ["", "", "deny", "deny"];

fn file_writes(p: &Proj) -> Vec<(&'static str, Value)> {
    let env = p.project.join(".env");
    let env = env.to_str().unwrap();
    vec![
        ("Write", json!({ "file_path": env, "content": "A=1\n" })),
        (
            "Edit",
            json!({ "file_path": ".env", "old_string": "CLUSTER=devnet", "new_string": "CLUSTER=localnet" }),
        ),
        (
            "MultiEdit",
            json!({ "file_path": "apps/web/.env.local", "edits": [{ "old_string": "a", "new_string": "b" }] }),
        ),
        ("Write", json!({ "file_path": ".envrc", "content": "x\n" })),
    ]
}

#[test]
fn writes_to_project_env_files_deny_at_medium_and_high() {
    let p = Proj::new();
    for tier in tiers() {
        for (tool, input) in file_writes(&p) {
            let run = p.tamper(Setup::at(tier), tool, input.clone());
            assert_eq!(
                decision_label(&run),
                cell(WRITE_ROW, tier),
                "{tool} {input} at {}",
                tier.label()
            );
        }
    }
    let why = reason(&p.tamper(
        Setup::at(Tier::Medium),
        "Write",
        file_writes(&p)[0].1.clone(),
    ));
    assert!(why.contains("medium"), "{why}");
    assert!(why.contains("env"), "{why}");
}

#[test]
fn writes_to_templates_schemas_and_plain_files_have_no_opinion() {
    let p = Proj::new();
    for tier in tiers() {
        for file in [".env.example", ".env.schema", "src/env.rs", "README.md"] {
            let run = p.tamper(
                Setup::at(tier),
                "Write",
                json!({ "file_path": file, "content": "x\n" }),
            );
            assert_eq!(decision_label(&run), "", "{file} at {}", tier.label());
        }
    }
}

#[test]
fn a_symlink_to_an_env_file_is_a_write_to_it() {
    #[cfg(unix)]
    {
        let p = Proj::new();
        std::os::unix::fs::symlink(p.project.join(".env"), p.project.join("config.txt")).unwrap();
        let run = p.tamper(
            Setup::at(Tier::Medium),
            "Edit",
            json!({ "file_path": "config.txt", "old_string": "a", "new_string": "b" }),
        );
        assert_eq!(decision_label(&run), "deny");
    }
}

#[test]
fn agent_env_set_and_unset_deny_at_medium_and_high() {
    let p = Proj::new();
    let commands = [
        "printf v | safe-ai-skill env set .env K",
        "safe-ai-skill env unset .env K",
        "printf %s v | /opt/plugin/bin/safe-ai-skill env set apps/web/.env.local K",
        "bash -c 'printf v | safe-ai-skill env set .env K'",
        "cd apps && safe-ai-skill env unset .env.local K",
        "FOO=1 env -u X safe-ai-skill env set --multiline .env K < /dev/null",
        "timeout 5 safe-ai-skill env set .env K",
        "echo ok; $(safe-ai-skill env unset .env K)",
    ];
    for tier in tiers() {
        for cmd in commands {
            let run = p.bash(Setup::at(tier), cmd);
            assert_eq!(
                decision_label(&run),
                cell(WRITE_ROW, tier),
                "{cmd} at {}",
                tier.label()
            );
        }
    }
    let why = reason(&p.bash(Setup::at(Tier::High), commands[0]));
    assert!(why.contains("high"), "{why}");
    assert!(why.contains("env set"), "{why}");
}

#[test]
fn env_keys_and_mentions_have_no_opinion_at_every_tier() {
    let p = Proj::new();
    for tier in tiers() {
        for cmd in [
            "safe-ai-skill env keys .env",
            "safe-ai-skill env keys apps/web/.env.local --json",
            "safe-ai-skill env init-schema",
            "echo safe-ai-skill env set .env K",
            "git commit -m 'docs: safe-ai-skill env set usage'",
            "grep -r 'env unset' docs",
        ] {
            let run = p.bash(Setup::at(tier), cmd);
            assert_eq!(decision_label(&run), "", "{cmd} at {}", tier.label());
        }
    }
}

#[test]
fn bash_in_place_edits_are_not_claimed_by_the_write_gate() {
    // No Bash write coverage (spec §8): only the sandbox's denyWrite closes these. With the
    // default `env_read: deny` the raw-read rule still denies `sed … .env` (sed reads it).
    let policy = safe_ai_skill::policy::Policy::default();
    let cwd = Path::new("/p");
    for tier in TIERS {
        for cmd in [
            "sed -i s/a/b/ .env",
            "perl -pi -e s/a/b/ .env",
            "echo A=1 >> .env",
        ] {
            let v = safe_ai_skill::gates::envwrite::decide_cli(cmd, cwd, &policy, tier);
            assert!(v.is_none(), "{cmd} at {}: {v:?}", tier.label());
        }
    }
}

#[cfg(feature = "test-hooks")]
#[test]
fn bash_in_place_edits_have_no_opinion_once_raw_reads_are_open() {
    let p = Proj::new();
    let opted = Setup::at(Tier::Relaxed)
        .env_read(EnvRead::Tier)
        .sandbox(SandboxMode::On);
    for tier in TIERS {
        let run = p.bash(Setup { tier, ..opted }, "sed -i s/a/b/ .env");
        assert_eq!(
            decision_label(&run),
            cell(["", "", "deny", "deny"], tier),
            "at {}",
            tier.label()
        );
    }
}

// ---------------------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------------------

fn updated(run: &Run) -> Value {
    run.json()["hookSpecificOutput"]["updatedToolOutput"].clone()
}

#[test]
fn test_output_with_an_env_value_is_redacted_at_every_tier() {
    let p = Proj::new();
    let stdout = format!("anchor test\n  provider: HELIUS_KEY={HELIUS}\n  1 passing\n");
    for tier in tiers() {
        let run = p.redact(
            Setup::at(tier),
            "Bash",
            json!({ "command": "anchor test" }),
            json!({ "stdout": stdout, "stderr": "", "interrupted": false, "isImage": false }),
        );
        let out = updated(&run);
        assert_eq!(
            out["stdout"],
            "anchor test\n  provider: HELIUS_KEY=«redacted:HELIUS_KEY»\n  1 passing\n",
            "at {}",
            tier.label()
        );
    }
}

fn read_response(file: &Path, content: &str) -> Value {
    let lines = content.lines().count();
    json!({
        "type": "text",
        "file": {
            "filePath": file,
            "content": content,
            "numLines": lines,
            "startLine": 1,
            "totalLines": lines
        }
    })
}

#[test]
fn a_raw_env_read_response_is_never_rewritten() {
    // Only an opted-in read gets this far (otherwise the read gate denied it), and a rewritten
    // response would be written back by the next Edit or Write.
    let p = Proj::new();
    let env = p.project.join(".env");
    let content = std::fs::read_to_string(&env).unwrap();
    let run = p.redact(
        Setup::at(Tier::Relaxed),
        "Read",
        json!({ "file_path": env }),
        read_response(&env, &content),
    );
    assert!(run.stdout.trim().is_empty(), "{}", run.stdout);
    // The same text from any other file is still scrubbed.
    let notes = p.project.join("notes.txt");
    let run = p.redact(
        Setup::at(Tier::Relaxed),
        "Read",
        json!({ "file_path": notes }),
        read_response(&notes, &content),
    );
    let out = updated(&run);
    assert!(
        out["file"]["content"]
            .as_str()
            .unwrap()
            .contains("«redacted:HELIUS_KEY»"),
        "{out}"
    );
    // And a Bash dump of the env file is scrubbed too.
    let run = p.redact(
        Setup::at(Tier::Relaxed),
        "Bash",
        json!({ "command": "cat .env" }),
        json!({ "stdout": content, "stderr": "" }),
    );
    assert!(updated(&run)["stdout"]
        .as_str()
        .unwrap()
        .contains("«redacted:HELIUS_KEY»"));
}

#[cfg(unix)]
#[test]
fn a_read_through_a_symlink_to_an_env_file_is_never_rewritten() {
    let p = Proj::new();
    let link = p.project.join("settings.txt");
    std::os::unix::fs::symlink(p.project.join(".env"), &link).unwrap();
    let content = std::fs::read_to_string(p.project.join(".env")).unwrap();
    let run = p.redact(
        Setup::at(Tier::Relaxed),
        "Read",
        json!({ "file_path": link }),
        read_response(&link, &content),
    );
    assert!(run.stdout.trim().is_empty(), "{}", run.stdout);
}

#[test]
fn a_non_opted_env_read_never_reaches_redact() {
    let p = Proj::new();
    for tier in tiers() {
        assert_eq!(decision_label(&p.read(Setup::at(tier), ".env")), "deny");
    }
}

#[cfg(feature = "test-hooks")]
/// Apply an Edit the way Claude Code does: `old_string` must occur exactly once in the file.
fn apply_edit(file: &Path, old: &str, new: &str) {
    let text = std::fs::read_to_string(file).unwrap();
    assert_eq!(
        text.matches(old).count(),
        1,
        "Edit old_string must be unique"
    );
    std::fs::write(file, text.replacen(old, new, 1)).unwrap();
}

#[cfg(feature = "test-hooks")]
#[test]
fn opted_in_read_then_edit_keeps_the_real_values() {
    let p = Proj::new();
    let opted = Setup::at(Tier::Relaxed)
        .env_read(EnvRead::Tier)
        .sandbox(SandboxMode::On);
    let env = p.project.join(".env");
    let before = std::fs::read_to_string(&env).unwrap();

    // 1. Read is allowed (no opinion) ...
    assert_eq!(decision_label(&p.read(opted, ".env")), "");
    // 2. ... and its response reaches the model unchanged.
    let post = p.redact(
        opted,
        "Read",
        json!({ "file_path": env }),
        read_response(&env, &before),
    );
    assert!(post.stdout.trim().is_empty(), "{}", post.stdout);
    let seen = before.clone();

    // 3. The model edits one line, quoting what it saw, and the write gate lets it through.
    let old = seen.lines().find(|l| l.starts_with("CLUSTER=")).unwrap();
    let edit = json!({ "file_path": env, "old_string": old, "new_string": "CLUSTER=localnet" });
    assert_eq!(decision_label(&p.tamper(opted, "Edit", edit)), "");
    apply_edit(&env, old, "CLUSTER=localnet");

    // 4. A whole-file Write of what it saw, with that line changed, is equally safe.
    let rewritten = std::fs::read_to_string(&env).unwrap();
    let write = json!({ "file_path": env, "content": rewritten });
    assert_eq!(decision_label(&p.tamper(opted, "Write", write)), "");

    let after = std::fs::read_to_string(&env).unwrap();
    assert!(after.contains(&format!("HELIUS_KEY={HELIUS}\n")), "{after}");
    assert!(
        after.contains(&format!("DATABASE_URL={DB_URL}\n")),
        "{after}"
    );
    assert!(after.contains("CLUSTER=localnet\n"), "{after}");
    assert!(!after.contains("redacted"), "{after}");
    assert_eq!(after, before.replace("CLUSTER=devnet", "CLUSTER=localnet"));
}

#[test]
fn a_scrubbed_read_would_have_clobbered_the_file() {
    // The control for the round trip: the value scrub on this content does change it, so the
    // round trip above proves the exemption, not an absence of values.
    let values = safe_ai_skill::env::values::load(Proj::new().project.path());
    let content = format!("HELIUS_KEY={HELIUS}\nCLUSTER=devnet\n");
    let scrubbed = safe_ai_skill::redact::scrub_values(&content, &values).unwrap();
    assert!(scrubbed.contains("«redacted:HELIUS_KEY»"), "{scrubbed}");
}

/// An opted-in env argument must not end the scan of the rest of the command: key material
/// after it still denies. Today `secrets.rs` (F4's file) returns the first env-class verdict,
/// even no-opinion, so the reader and redirect rules stop at `.env`. Fix (in
/// `secrets::decide_segment`, `decide_redirects` and the `git show` loop): return a
/// `secret_arg_decision` only when it is not `Decision::Defer`.
#[cfg(feature = "test-hooks")]
#[test]
#[ignore = "needs secrets.rs to keep scanning past an opted-in env argument (F4 / F8)"]
fn an_opted_in_env_argument_does_not_hide_key_material_after_it() {
    let p = Proj::new();
    let opted = Setup::at(Tier::Relaxed)
        .env_read(EnvRead::Tier)
        .sandbox(SandboxMode::On);
    let keypair: Vec<String> = (0..64).map(|i| ((i * 7) % 256).to_string()).collect();
    p.write("deploy-keypair.json", &format!("[{}]", keypair.join(",")));
    for cmd in [
        "cat .env ~/.ssh/id_rsa",
        "cat .env deploy-keypair.json",
        "cat < .env ~/.config/solana/id.json",
        "head .env -n 3 wallet-keypair.json",
    ] {
        assert_eq!(decision_label(&p.bash(opted, cmd)), "deny", "{cmd}");
    }
}

/// Same for a directory Grep whose glob names an env file and key material: with the opt-in
/// the env verdict is no opinion and `read::decide_grep` (F0's file) returns it, skipping the
/// key-material exclusion rewrite. Fix: when `env_verdict` is `Defer`, fall through to the
/// exclusion rewrite instead of returning.
#[cfg(feature = "test-hooks")]
#[test]
#[ignore = "needs read::decide_grep to fall through to the exclusion rewrite (F0 / F8)"]
fn an_opted_in_grep_glob_keeps_the_key_material_exclusion() {
    let p = Proj::new();
    let opted = Setup::at(Tier::Relaxed)
        .env_read(EnvRead::Tier)
        .sandbox(SandboxMode::On);
    let run = p.pre(
        opted,
        "gate-read",
        "Grep",
        json!({ "pattern": "1", "path": p.project.path(), "glob": "{.env,*-keypair.json}" }),
    );
    assert!(!run.stdout.trim().is_empty(), "no exclusion or decision");
}
