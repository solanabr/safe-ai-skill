//! Spec D3 / D3.8 end to end: the secret path matcher behind `gate-read` (Read, Grep, Glob),
//! MCP path arguments, the Bash reader and varlock rules in `gate-bash-secrets`, and the
//! PostToolUse `redact` contract (`tool_response` in, `hookSpecificOutput.updatedToolOutput`
//! out, shaped per tool) with value-based scrubbing.

mod common;

use std::path::Path;

use common::{decision_label, Invocation, Run, TempDir};
use serde_json::{json, Value};

/// A project dir and a separate HOME, both sandboxed.
struct Sandbox {
    project: TempDir,
    home: TempDir,
    data: TempDir,
    /// `CLAUDE_PLUGIN_ROOT` carrying a custom default policy, when a test needs one.
    root: Option<TempDir>,
    /// An empty dir used as `PATH`, so `varlock` is never found unless a test installs it.
    path: TempDir,
}

impl Sandbox {
    fn new() -> Self {
        Sandbox {
            project: TempDir::new("d3-proj"),
            home: TempDir::new("d3-home"),
            data: TempDir::new("d3-data"),
            root: None,
            path: TempDir::new("d3-path"),
        }
    }

    /// Use the shipped default policy with `edit` applied to its text.
    fn with_policy(mut self, edit: impl Fn(String) -> String) -> Self {
        let shipped = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../plugins/safe-ai-skill/policy/default.policy.yaml"),
        )
        .unwrap();
        let root = TempDir::new("d3-root");
        std::fs::create_dir_all(root.join("policy")).unwrap();
        std::fs::write(root.join("policy/default.policy.yaml"), edit(shipped)).unwrap();
        self.root = Some(root);
        self
    }

    fn write(&self, rel: &str, body: &str) {
        let path = self.project.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, body).unwrap();
    }

    fn run(&self, sub: &str, payload: Value) -> Run {
        let mut inv = Invocation::new(&[sub])
            .plugin_data(self.data.path())
            .home(self.home.path())
            .env("PATH", self.path.path().to_str().unwrap())
            .stdin(payload.to_string());
        if let Some(root) = &self.root {
            inv = inv.env("CLAUDE_PLUGIN_ROOT", root.path().to_str().unwrap());
        }
        inv.run()
    }

    fn pre(&self, sub: &str, tool: &str, input: Value) -> Run {
        self.run(
            sub,
            json!({
                "hook_event_name": "PreToolUse",
                "cwd": self.project.path(),
                "tool_name": tool,
                "tool_input": input,
            }),
        )
    }

    fn read(&self, file_path: &str) -> String {
        decision_label(&self.pre("gate-read", "Read", json!({ "file_path": file_path })))
    }

    fn bash(&self, command: &str) -> Run {
        self.pre("gate-bash-secrets", "Bash", json!({ "command": command }))
    }

    fn redact(&self, tool: &str, response: Value) -> Run {
        self.run(
            "redact",
            json!({
                "hook_event_name": "PostToolUse",
                "cwd": self.project.path(),
                "tool_name": tool,
                "tool_input": {},
                "tool_response": response,
            }),
        )
    }
}

fn reason(run: &Run) -> String {
    run.json()["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

fn assert_silent(run: &Run, what: &str) {
    assert!(
        run.stdout.trim().is_empty(),
        "{what}: expected no output, got {}",
        run.stdout
    );
    assert_eq!(run.code, Some(0), "{what}: {}", run.stderr);
}

fn keypair_json() -> String {
    let arr: Vec<String> = (0..64).map(|i| ((i * 7) % 256).to_string()).collect();
    format!("[{}]", arr.join(","))
}

// ---------------------------------------------------------------------------------------
// C1 Read: path matcher
// ---------------------------------------------------------------------------------------

#[test]
fn read_env_class_variants_deny() {
    let sb = Sandbox::new();
    for path in [
        ".ENV",
        ".Env.Local",
        "prod.env",
        ".envrc",
        ".dev.vars",
        r"C:\p\.env",
        ".env::$DATA",
        "/a/b/../.env",
        ".varlock-frozen-env",
        "~/.config/solana/cli/config.yml",
    ] {
        assert_eq!(sb.read(path), "deny", "{path}");
    }
}

#[test]
fn read_templates_and_plain_files_have_no_opinion() {
    let sb = Sandbox::new();
    for path in [
        ".env.example",
        "/proj/.env.sample",
        ".env.template",
        ".env.dist",
        "src/main.rs",
    ] {
        assert_eq!(sb.read(path), "", "{path}");
    }
}

#[test]
fn read_hard_deny_trees_deny_even_when_missing() {
    let sb = Sandbox::new();
    for path in [
        "~/.config/solana/id.json",
        "/home/someone/.config/solana/devnet.json",
        "wallet-keypair.json",
        "~/.ssh/id_ed25519",
        "~/.superstack/config.json",
        "~/.config/varlock/cache/blob",
    ] {
        assert_eq!(sb.read(path), "deny", "{path}");
    }
}

#[cfg(unix)]
#[test]
fn read_symlinks_are_matched_on_the_resolved_path() {
    let sb = Sandbox::new();
    sb.write(".env", "TOKEN=abcdefghijklmnop\n");
    let link = sb.project.join("notes.txt");
    std::os::unix::fs::symlink(sb.project.join(".env"), &link).unwrap();
    assert_eq!(sb.read(link.to_str().unwrap()), "deny");
    assert_eq!(sb.read("notes.txt"), "deny", "relative to the hook cwd");
    let example = sb.project.join(".env.example");
    std::os::unix::fs::symlink(sb.project.join(".env"), &example).unwrap();
    assert_eq!(sb.read(example.to_str().unwrap()), "deny");
}

#[test]
fn read_keypair_content_denies_by_content() {
    let sb = Sandbox::new();
    sb.write("foo.json", &keypair_json());
    assert_eq!(sb.read("foo.json"), "deny");
    sb.write("config/id.json", &keypair_json());
    assert_eq!(sb.read("config/id.json"), "deny");
    sb.write("b58.txt", &bs58_secret());
    assert_eq!(sb.read("b58.txt"), "deny");
}

fn bs58_secret() -> String {
    // 64 bytes of base58: the shape of an exported Phantom/solana secret key.
    let bytes: Vec<u8> = (0..64u8)
        .map(|i| i.wrapping_mul(37).wrapping_add(11))
        .collect();
    bs58_encode(&bytes)
}

/// Minimal base58 (Bitcoin alphabet) so the test needs no dev-dependency.
fn bs58_encode(input: &[u8]) -> String {
    const ALPHA: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut digits: Vec<u8> = Vec::new();
    for &byte in input {
        let mut carry = u32::from(byte);
        for d in digits.iter_mut() {
            carry += u32::from(*d) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let zeros = input.iter().take_while(|&&b| b == 0).count();
    let mut out: String = "1".repeat(zeros);
    out.extend(digits.iter().rev().map(|&d| ALPHA[d as usize] as char));
    out
}

#[test]
fn read_id_json_only_when_it_sniffs() {
    let sb = Sandbox::new();
    sb.write("data/id.json", r#"{"id": 7, "name": "not a key"}"#);
    assert_eq!(sb.read("data/id.json"), "");
}

#[cfg(unix)]
#[test]
fn read_unreadable_suspects_deny() {
    use std::os::unix::fs::PermissionsExt;
    let sb = Sandbox::new();
    sb.write("id.json", "{}");
    sb.write("tls.key", "x");
    for name in ["id.json", "tls.key"] {
        let p = sb.project.join(name);
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read(&p).is_ok() {
            return; // running as root: permissions are not enforced
        }
        assert_eq!(sb.read(name), "deny", "{name}");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

#[test]
fn read_pem_denies_private_keys_only() {
    let sb = Sandbox::new();
    sb.write(
        "cert.pem",
        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
    );
    assert_eq!(sb.read("cert.pem"), "");
    sb.write(
        "bundle.pem",
        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n-----BEGIN EC PRIVATE KEY-----\nMHc\n",
    );
    assert_eq!(sb.read("bundle.pem"), "deny");
    sb.write("notes.md", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl\n");
    assert_eq!(
        sb.read("notes.md"),
        "deny",
        "private-key content under any name"
    );
}

#[test]
fn read_deny_message_names_the_env_commands() {
    let sb = Sandbox::new();
    let run = sb.pre("gate-read", "Read", json!({ "file_path": ".env.local" }));
    let why = reason(&run);
    assert!(why.contains("safe-ai-skill env keys .env.local"), "{why}");
    assert!(
        why.contains("printf %s '<value>' | safe-ai-skill env set .env.local KEY"),
        "{why}"
    );
    assert!(
        why.contains("safe-ai-skill env unset .env.local KEY"),
        "{why}"
    );
    assert!(!why.contains("varlock"), "no schema, no varlock: {why}");
}

#[test]
fn read_deny_message_mentions_varlock_only_with_a_schema() {
    let sb = Sandbox::new();
    sb.write(".env.schema", "# @defaultSensitive=true\n# ---\nAPI_KEY=\n");
    let why = reason(&sb.pre("gate-read", "Read", json!({ "file_path": ".env" })));
    assert!(why.contains("varlock run -- <cmd>"), "{why}");
    assert!(why.contains("varlock load --agent"), "{why}");
}

#[test]
fn read_env_read_ask_policy_asks_for_env_but_not_hard_classes() {
    let sb = Sandbox::new().with_policy(|p| p.replace("env_read: deny", "env_read: ask"));
    assert_eq!(sb.read(".env"), "ask");
    assert_eq!(sb.read("~/.config/solana/id.json"), "deny");
    sb.write("k.json", &keypair_json());
    assert_eq!(sb.read("k.json"), "deny");
}

#[test]
fn repo_cannot_set_env_read_ask() {
    let sb = Sandbox::new();
    sb.write(".safe-ai-skill/policy.yaml", "secrets:\n  env_read: ask\n");
    assert_eq!(sb.read(".env"), "deny");
}

#[test]
fn read_env_schema_is_guarded() {
    let sb = Sandbox::new();
    sb.write(
        ".env.schema",
        "# @defaultSensitive=true\n# ---\n# @type=url\nRPC_URL=\nAPI_KEY=varlock(\"local:abc\")\n",
    );
    assert_eq!(sb.read(".env.schema"), "");
    sb.write(
        "a/.env.schema",
        &format!("# ---\nWALLET={}\n", keypair_json()),
    );
    let run = sb.pre("gate-read", "Read", json!({ "file_path": "a/.env.schema" }));
    assert_eq!(decision_label(&run), "deny");
    assert!(reason(&run).contains("secret value"), "{}", reason(&run));
    sb.write(
        "b/.env.schema",
        "# ---\n# @sensitive\nSTRIPE_KEY=sk_\x6cive_51HxYzAbCdEfGhIjKlMnOpQr\n",
    );
    let run = sb.pre("gate-read", "Read", json!({ "file_path": "b/.env.schema" }));
    assert_eq!(decision_label(&run), "deny");
    let why = reason(&run);
    assert!(why.contains("STRIPE_KEY") && why.contains("L3"), "{why}");
    assert!(!why.contains("sk_live"), "never echo the value: {why}");
}

#[test]
fn repo_can_remove_schema_from_the_allow_list() {
    let sb = Sandbox::new();
    sb.write(".env.schema", "# ---\nAPI_KEY=\n");
    sb.write(
        ".safe-ai-skill/policy.yaml",
        "secrets:\n  allow_read_globs: [\"**/.env.example\"]\n",
    );
    assert_eq!(sb.read(".env.schema"), "deny");
    assert_eq!(sb.read(".env.example"), "");
    assert_eq!(sb.read(".env.sample"), "deny");
}

// ---------------------------------------------------------------------------------------
// C2 Grep / Glob / MCP
// ---------------------------------------------------------------------------------------

const EXCLUSION_HEAD: &str = "!{**/.[eE][nN][vV],**/.[eE][nN][vV].*";

#[test]
fn grep_on_a_secret_file_or_secret_glob_denies() {
    let sb = Sandbox::new();
    sb.write(".env", "A=1\n");
    for input in [
        json!({ "pattern": "KEY", "path": ".env" }),
        json!({ "pattern": "KEY", "path": sb.project.join(".ENV") }),
        json!({ "pattern": "KEY", "glob": ".env*" }),
        json!({ "pattern": "KEY", "glob": "**/*.env" }),
        json!({ "pattern": "KEY", "glob": "{.envrc,*.md}" }),
        json!({ "pattern": "KEY", "glob": "*-keypair.json" }),
        json!({ "pattern": "KEY", "path": "~/.config/solana" }),
    ] {
        let run = sb.pre("gate-read", "Grep", input.clone());
        assert_eq!(decision_label(&run), "deny", "{input}");
    }
}

#[test]
fn grep_on_a_directory_gets_an_exclusion_rewrite_without_a_decision() {
    let sb = Sandbox::new();
    std::fs::create_dir_all(sb.project.join("src")).unwrap();
    for (input, glob) in [
        (json!({ "pattern": ".env", "path": "src" }), None),
        (json!({ "pattern": "TOKEN" }), None),
        (
            json!({ "pattern": "fn", "glob": "*.rs", "output_mode": "content" }),
            Some("*.rs"),
        ),
        (json!({ "pattern": "x", "glob": "*.json" }), Some("*.json")),
    ] {
        let run = sb.pre("gate-read", "Grep", input.clone());
        let v = run.json();
        let out = &v["hookSpecificOutput"];
        assert_eq!(out["hookEventName"], "PreToolUse", "{input}");
        assert!(out.get("permissionDecision").is_none(), "{v}");
        let updated = &out["updatedInput"];
        let new_glob = updated["glob"].as_str().unwrap();
        match glob {
            Some(g) => assert!(new_glob.starts_with(&format!("{g} !{{")), "{new_glob}"),
            None => assert!(new_glob.starts_with("!{"), "{new_glob}"),
        }
        assert!(new_glob.contains(EXCLUSION_HEAD), "{new_glob}");
        assert!(new_glob.ends_with('}'), "{new_glob}");
        // Everything else is the model's input, unchanged.
        let mut rest = updated.clone();
        rest.as_object_mut().unwrap().remove("glob");
        let mut orig = input.clone();
        orig.as_object_mut().unwrap().remove("glob");
        assert_eq!(rest, orig);
    }
}

#[test]
fn grep_on_a_plain_file_has_no_opinion() {
    let sb = Sandbox::new();
    sb.write("README.md", "hello\n");
    let run = sb.pre(
        "gate-read",
        "Grep",
        json!({ "pattern": "env", "path": "README.md" }),
    );
    assert_silent(&run, "grep README.md");
}

#[test]
fn glob_is_never_gated() {
    let sb = Sandbox::new();
    for pattern in [".env*", "**/.env", "~/.config/solana/*.json"] {
        let run = sb.pre("gate-read", "Glob", json!({ "pattern": pattern }));
        assert_silent(&run, pattern);
    }
}

#[test]
fn mcp_path_arguments_are_read_checked() {
    let sb = Sandbox::new();
    sb.write(".env", "A=1\n");
    for (tool, input) in [
        (
            "mcp__context-mode__ctx_execute_file",
            json!({ "path": ".env", "language": "shell", "code": "cat" }),
        ),
        (
            "mcp__fs__read_multiple",
            json!({ "args": { "paths": ["README.md", "/srv/app/.ENV.local"] } }),
        ),
        (
            "mcp__fs__read",
            json!({ "file": "~/.config/solana/id.json" }),
        ),
        ("mcp__fs__read", json!({ "file": "deploy-keypair.json" })),
    ] {
        let run = sb.pre("gate-mcp", tool, input.clone());
        assert_eq!(decision_label(&run), "deny", "{tool} {input}");
    }
}

#[test]
fn mcp_prose_mentioning_env_has_no_opinion() {
    let sb = Sandbox::new();
    let run = sb.pre(
        "gate-mcp",
        "mcp__notes__append",
        json!({ "text": "remember to update your .env file", "tags": ["todo"] }),
    );
    assert_silent(&run, "prose");
}

// ---------------------------------------------------------------------------------------
// Bash: reader nudge list and varlock rules (D3.6, D3.8.5)
// ---------------------------------------------------------------------------------------

#[test]
fn bash_readers_on_env_deny() {
    let sb = Sandbox::new();
    for cmd in [
        "sudo cat .env",
        "source .env",
        ". ./.env",
        "grep KEY .env",
        "sed -n 1p .env.local",
        "awk 1 .env",
        "nl .env",
        "tac .env",
        "git show HEAD:.env",
        "wc -l < .env",
        "FOO=1 cat .env",
        "env -i cat .ENV",
        "cat config/prod.env",
        "less .envrc",
    ] {
        let run = sb.bash(cmd);
        assert_eq!(decision_label(&run), "deny", "{cmd}");
        assert!(
            reason(&run).contains("safe-ai-skill env keys"),
            "{cmd}: {}",
            reason(&run)
        );
    }
    for cmd in [
        "cat .env.example",
        "grep -r TODO src",
        "echo .env",
        "ls -la .env",
    ] {
        assert_silent(&sb.bash(cmd), cmd);
    }
}

#[test]
fn bash_varlock_value_printing_commands_deny() {
    let sb = Sandbox::new();
    for cmd in [
        "varlock load --format json",
        "varlock load -f env",
        "varlock load --format=shell",
        "varlock load --format json-full",
        "varlock printenv API_KEY",
        "npx varlock printenv API_KEY",
        "pnpm exec varlock reveal API_KEY",
        "bunx varlock reveal API_KEY",
        "VAR=1 varlock reveal API_KEY",
        "varlock freeze --out -",
        "varlock freeze --allow-plaintext",
        "varlock proxy token",
    ] {
        let run = sb.bash(cmd);
        assert_eq!(decision_label(&run), "deny", "{cmd}");
        let why = reason(&run);
        assert!(why.contains("varlock load --agent"), "{cmd}: {why}");
    }
}

#[test]
fn bash_varlock_safe_commands_have_no_opinion_or_ask() {
    let sb = Sandbox::new();
    for cmd in [
        "varlock load",
        "varlock load --agent",
        "varlock load --agent --format json",
        "varlock load -f json --agent",
        "varlock explain API_KEY",
        "varlock audit",
        "varlock run -- node app.js",
        "varlock freeze --out .frozen",
        "varlock proxy start",
    ] {
        assert_silent(&sb.bash(cmd), cmd);
    }
    for cmd in [
        "varlock run --no-redact-stdout -- node app.js",
        "_VARLOCK_REDACT_STDOUT=0 varlock run -- node app.js",
    ] {
        assert_eq!(decision_label(&sb.bash(cmd)), "ask", "{cmd}");
    }
}

#[test]
fn bash_env_read_ask_applies_to_readers_and_varlock() {
    let sb = Sandbox::new().with_policy(|p| p.replace("env_read: deny", "env_read: ask"));
    assert_eq!(decision_label(&sb.bash("cat .env")), "ask");
    assert_eq!(decision_label(&sb.bash("varlock printenv K")), "ask");
    assert_eq!(decision_label(&sb.bash("cat wallet-keypair.json")), "deny");
}

#[test]
fn bash_deny_message_mentions_varlock_run_with_a_schema_only() {
    let sb = Sandbox::new();
    let plain = reason(&sb.bash("cat .env"));
    assert!(!plain.contains("varlock"), "{plain}");
    sb.write(".env.schema", "# ---\nK=\n");
    let with_schema = reason(&sb.bash("cat .env"));
    assert!(
        with_schema.contains("varlock run -- <cmd>"),
        "{with_schema}"
    );
}

#[cfg(unix)]
#[test]
fn bash_deny_message_mentions_varlock_when_installed() {
    use std::os::unix::fs::PermissionsExt;
    let sb = Sandbox::new();
    let bin = sb.path.join("varlock");
    std::fs::write(&bin, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let why = reason(&sb.bash("cat .env"));
    assert!(why.contains("varlock run -- <cmd>"), "{why}");
}

// ---------------------------------------------------------------------------------------
// C5 redact contract
// ---------------------------------------------------------------------------------------

const VALUE: &str = "hx_live_9f8e7d6c5b4a3210";

fn env_sandbox() -> Sandbox {
    let sb = Sandbox::new();
    sb.write(
        ".env",
        &format!("HELIUS_API_KEY={VALUE}\nCLUSTER=devnet\nSHORT=abc\n"),
    );
    sb
}

fn updated(run: &Run) -> Value {
    let v = run.json();
    assert_eq!(
        v["hookSpecificOutput"]["hookEventName"], "PostToolUse",
        "{v}"
    );
    assert!(
        v.get("updatedToolOutput").is_none(),
        "top-level key is inert: {v}"
    );
    v["hookSpecificOutput"]["updatedToolOutput"].clone()
}

#[test]
fn redact_read_shape_golden() {
    let sb = env_sandbox();
    let response = json!({
        "type": "text",
        "file": {
            "filePath": "/p/notes.txt",
            "content": format!("token: {VALUE}\ncluster: devnet\n"),
            "numLines": 2,
            "startLine": 1,
            "totalLines": 2
        }
    });
    let run = sb.redact("Read", response);
    assert_eq!(
        updated(&run),
        json!({
            "type": "text",
            "file": {
                "filePath": "/p/notes.txt",
                "content": "token: «redacted:HELIUS_API_KEY»\ncluster: devnet\n",
                "numLines": 2,
                "startLine": 1,
                "totalLines": 2
            }
        })
    );
}

#[test]
fn redact_bash_shape_golden() {
    let sb = env_sandbox();
    let response = json!({
        "stdout": format!("export HELIUS_API_KEY={VALUE}\n"),
        "stderr": format!("warn: key {VALUE} rotated\n"),
        "interrupted": false,
        "isImage": false
    });
    assert_eq!(
        updated(&sb.redact("Bash", response)),
        json!({
            "stdout": "export HELIUS_API_KEY=«redacted:HELIUS_API_KEY»\n",
            "stderr": "warn: key «redacted:HELIUS_API_KEY» rotated\n",
            "interrupted": false,
            "isImage": false
        })
    );
}

#[test]
fn redact_grep_shape_golden() {
    let sb = env_sandbox();
    let response = json!({
        "mode": "content",
        "numFiles": 1,
        "filenames": [],
        "content": format!("app.txt:1:KEY={VALUE}"),
        "numLines": 1
    });
    assert_eq!(
        updated(&sb.redact("Grep", response)),
        json!({
            "mode": "content",
            "numFiles": 1,
            "filenames": [],
            "content": "app.txt:1:KEY=«redacted:HELIUS_API_KEY»",
            "numLines": 1
        })
    );
}

#[test]
fn redact_mcp_shapes_golden() {
    let sb = env_sandbox();
    let blocks = json!([{ "type": "text", "text": format!("cfg {VALUE}") }]);
    assert_eq!(
        updated(&sb.redact("mcp__context-mode__ctx_execute", blocks)),
        json!([{ "type": "text", "text": "cfg «redacted:HELIUS_API_KEY»" }])
    );
    let text = json!(format!("raw {VALUE}"));
    assert_eq!(
        updated(&sb.redact("mcp__x__y", text)),
        json!("raw «redacted:HELIUS_API_KEY»")
    );
}

#[test]
fn redact_patterns_still_apply_and_clean_output_is_silent() {
    let sb = Sandbox::new();
    let run = sb.redact(
        "Bash",
        json!({ "stdout": format!("k = {}", keypair_json()), "stderr": "" }),
    );
    let out = updated(&run);
    assert!(
        out["stdout"]
            .as_str()
            .unwrap()
            .contains("***REDACTED:keypair***"),
        "{out}"
    );
    assert_silent(
        &sb.redact(
            "Bash",
            json!({ "stdout": "balance: 1.5 SOL devnet", "stderr": "" }),
        ),
        "clean",
    );
}

#[test]
fn redact_skips_short_safe_and_placeholder_values() {
    let sb = Sandbox::new();
    sb.write(
        ".env",
        "CLUSTER=mainnet-beta\nPORT=8899\nSHORT=abcdefg\nPH=your-api-key-here\nRPC=https://api.devnet.solana.com\nCMD=exec(op read op://vault/item)\n",
    );
    let run = sb.redact(
        "Bash",
        json!({ "stdout": "mainnet-beta 8899 abcdefg your-api-key-here https://api.devnet.solana.com exec(op read op://vault/item)", "stderr": "" }),
    );
    assert_silent(&run, "nothing secret");
}

#[test]
fn redact_reads_every_env_class_file_including_nested() {
    let sb = Sandbox::new();
    sb.write(".env.local", "LOCAL_TOKEN=loc_aaaaaaaaaaaa\n");
    sb.write(".env.production", "PROD_TOKEN=prd_bbbbbbbbbbbb\n");
    sb.write("apps/web/.env", "WEB_TOKEN=web_cccccccccccc\n");
    sb.write(".env.example", "EXAMPLE=not_a_secret_value\n");
    let out = updated(&sb.redact(
        "Bash",
        json!({ "stdout": "loc_aaaaaaaaaaaa prd_bbbbbbbbbbbb web_cccccccccccc not_a_secret_value", "stderr": "" }),
    ));
    assert_eq!(
        out["stdout"],
        "«redacted:LOCAL_TOKEN» «redacted:PROD_TOKEN» «redacted:WEB_TOKEN» not_a_secret_value"
    );
}

#[test]
fn redact_schema_sensitivity_only_widens() {
    let url = "https://rpc.example.com/v1";
    let token = "tok_dddddddddddd";
    let without = Sandbox::new();
    without.write(".env", &format!("RPC_URL={url}\nTOKEN={token}\n"));
    let out = updated(&without.redact("Bash", json!({ "stdout": format!("{url} {token}") })));
    assert_eq!(
        out["stdout"],
        format!("{url} «redacted:TOKEN»"),
        "public URL kept"
    );

    let with = Sandbox::new();
    with.write(".env", &format!("RPC_URL={url}\nTOKEN={token}\n"));
    with.write(
        ".env.schema",
        "# @defaultSensitive=true\n# ---\nRPC_URL=\nTOKEN=\n",
    );
    let out = updated(&with.redact("Bash", json!({ "stdout": format!("{url} {token}") })));
    assert_eq!(
        out["stdout"], "«redacted:RPC_URL» «redacted:TOKEN»",
        "sensitive URL scrubbed"
    );

    let public = Sandbox::new();
    public.write(".env", &format!("RPC_URL={url}\nTOKEN={token}\n"));
    public.write(
        ".env.schema",
        "# @defaultSensitive=false\n# ---\n# @public\nRPC_URL=\n# @sensitive=false\nTOKEN=\n",
    );
    let out = updated(&public.redact("Bash", json!({ "stdout": format!("{url} {token}") })));
    assert_eq!(
        out["stdout"],
        format!("{url} «redacted:TOKEN»"),
        "@public/@sensitive=false never exempt a value"
    );
}

#[test]
fn redact_scans_tool_responses_past_one_mib() {
    let sb = env_sandbox();
    let filler = "x".repeat(2 * 1024 * 1024);
    let out = updated(&sb.redact(
        "Bash",
        json!({ "stdout": format!("{filler}\n{VALUE}\n"), "stderr": "" }),
    ));
    assert!(out["stdout"]
        .as_str()
        .unwrap()
        .ends_with("\n«redacted:HELIUS_API_KEY»\n"));
}

#[test]
fn redact_fails_open_past_its_bound() {
    let sb = env_sandbox();
    let filler = "x".repeat(9 * 1024 * 1024);
    let run = sb.redact(
        "Bash",
        json!({ "stdout": format!("{filler}\n{VALUE}\n"), "stderr": "" }),
    );
    assert_silent(&run, "oversized");
}

#[test]
fn redact_never_prints_values_on_stderr() {
    let sb = env_sandbox();
    let run = sb.redact("Bash", json!({ "stdout": VALUE }));
    assert!(!run.stderr.contains(VALUE), "{}", run.stderr);
    assert!(!run.stdout.contains(VALUE), "{}", run.stdout);
}
