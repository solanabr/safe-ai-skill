//! PostToolUse `redact` end to end (#24): the exact payloads Claude Code sends (hooks reference,
//! "PostToolUse input": the result arrives as `tool_response`, shaped per tool; MCP calls also
//! carry `mcp_server`) go through the built engine and through the plugin shim staged beside it,
//! and the exact stdout is asserted. The answer must be
//! `{"hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":<same shape>}}`
//! ("PostToolUse decision control"), or nothing when the output is clean.

mod common;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use common::{bin, TempDir};
use serde_json::{json, Value};

const ENV_VALUE: &str = "hl_9f8e7d6c5b4a39281706";
const UUID: &str = "3f2a9c1e-7b4d-4e8a-9c2f-1a2b3c4d5e6f";
const GHP: &str = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789";
const JWT: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.\
                   SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
const MNEMONIC: &str = "abandon ability able about above absent absorb abstract absurd abuse \
                        access accident";

fn base58_secret() -> String {
    bs58::encode((1u8..=64).collect::<Vec<u8>>()).into_string()
}

fn keypair_array() -> String {
    let bytes: Vec<String> = (0..64).map(|i| ((i * 7 + 3) % 256).to_string()).collect();
    format!("[{}]", bytes.join(","))
}

/// A project with a `.env`, a scratch HOME and plugin data dir, and (on unix) a plugin `bin/`
/// holding the shim and this build's engine, stamped like a release.
struct World {
    root: TempDir,
    env: Vec<(String, String)>,
}

impl World {
    fn new() -> Self {
        Self::with_env(&format!("HELIUS_API_KEY={ENV_VALUE}\nCLUSTER=devnet\n"))
    }

    fn with_env(dotenv: &str) -> Self {
        let root = TempDir::new("redact-e2e");
        for d in ["proj", "home/.claude", "data", "plugin/bin"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        std::fs::write(root.join("proj/.env"), dotenv).unwrap();
        let w = World {
            root,
            env: Vec::new(),
        };
        #[cfg(unix)]
        w.stage_shim();
        w
    }

    fn proj(&self) -> PathBuf {
        self.root.join("proj")
    }

    /// Copy the shim and the engine into `plugin/bin`, stamping the engine's sha256 into the
    /// shim constant for this platform (what `scripts/stamp-shim.sh` does at release).
    #[cfg(unix)]
    fn stage_shim(&self) {
        use sha2::{Digest, Sha256};
        use std::os::unix::fs::PermissionsExt;
        let plat = match (std::env::consts::OS, std::env::consts::ARCH) {
            ("macos", "aarch64") => "darwin-arm64",
            ("macos", "x86_64") => "darwin-x64",
            ("linux", "x86_64") => "linux-x64",
            ("linux", "aarch64") => "linux-arm64",
            other => panic!("no shim platform for {other:?}"),
        };
        let engine = std::fs::read(bin()).unwrap();
        let sha: String = Sha256::digest(&engine)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let dir = self.root.join("plugin/bin");
        let engine_path = dir.join(format!("safe-ai-skill-{plat}"));
        std::fs::write(&engine_path, &engine).unwrap();
        let src = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../plugins/safe-ai-skill/bin/safe-ai-skill");
        let key = format!("sha256_{}=", plat.replace('-', "_"));
        let shim: String = std::fs::read_to_string(src)
            .unwrap()
            .lines()
            .map(|l| {
                if l.starts_with(&key) {
                    format!("{key}{sha}\n")
                } else {
                    format!("{l}\n")
                }
            })
            .collect();
        assert!(shim.contains(&format!("{key}{sha}")), "shim has no {key}");
        let shim_path = dir.join("safe-ai-skill");
        std::fs::write(&shim_path, shim).unwrap();
        for p in [&engine_path, &shim_path] {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    fn run(&self, program: &Path, payload: &Value) -> (String, Option<i32>) {
        let home = self.root.join("home");
        let mut cmd = Command::new(program);
        cmd.arg("redact")
            .current_dir(self.proj())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &home)
            .env("CLAUDE_CONFIG_DIR", home.join(".claude"))
            .env("CLAUDE_PLUGIN_DATA", self.root.join("data"))
            .envs(self.env.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        for k in ["SystemRoot", "TEMP", "TMP", "USERPROFILE"] {
            if let Ok(v) = std::env::var(k) {
                cmd.env(k, v);
            }
        }
        let mut child = cmd.spawn().expect("spawn");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(payload.to_string().as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.stderr.is_empty(),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        (String::from_utf8(out.stdout).unwrap(), out.status.code())
    }

    /// Run `payload` through the engine and (on unix) the shim: both exit 0 and print the
    /// same bytes, which are returned.
    fn output(&self, payload: &Value) -> String {
        let (engine, code) = self.run(Path::new(bin()), payload);
        assert_eq!(code, Some(0), "engine");
        if cfg!(unix) {
            let (shim, code) = self.run(&self.root.join("plugin/bin/safe-ai-skill"), payload);
            assert_eq!(code, Some(0), "shim");
            assert_eq!(shim, engine, "shim and engine differ");
        }
        engine
    }

    /// [`World::output`] parses to `expected` (`None`: no output, no change).
    fn assert_redact(&self, payload: &Value, expected: Option<Value>) {
        let out = self.output(payload);
        match expected {
            None => assert_eq!(out, "", "expected no change"),
            Some(v) => {
                let got: Value =
                    serde_json::from_str(&out).unwrap_or_else(|e| panic!("{e}: {out}"));
                assert_eq!(got, v);
            }
        }
    }

    /// The common PostToolUse fields Claude Code sends (hooks reference example).
    fn payload(&self, tool: &str, input: Value, response: Value) -> Value {
        json!({
            "session_id": "abc123",
            "transcript_path": "/Users/u/.claude/projects/p/00893aaf-19fa-41d2-8238-13269b9b3ca0.jsonl",
            "cwd": self.proj(),
            "permission_mode": "default",
            "hook_event_name": "PostToolUse",
            "tool_name": tool,
            "tool_input": input,
            "tool_response": response,
            "tool_use_id": "toolu_01ABC123",
            "duration_ms": 12
        })
    }
}

fn updated(output: Value) -> Option<Value> {
    Some(
        json!({ "hookSpecificOutput": { "hookEventName": "PostToolUse", "updatedToolOutput": output } }),
    )
}

#[test]
fn bash_issue_payload_is_redacted_in_place() {
    let w = World::new();
    let stdout = format!(
        "PATH=/usr/bin\nPRIVATE_KEY={}\nHELIUS_API_KEY={UUID}\n",
        base58_secret()
    );
    let payload = w.payload(
        "Bash",
        json!({ "command": "env", "description": "Print environment" }),
        json!({ "stdout": stdout, "stderr": "", "interrupted": false, "isImage": false }),
    );
    let expected = updated(json!({
        "interrupted": false,
        "isImage": false,
        "stderr": "",
        "stdout": "PATH=/usr/bin\nPRIVATE_KEY=***REDACTED:base58_secret_key***\nHELIUS_API_KEY=***REDACTED:api_key***\n"
    }));
    w.assert_redact(&payload, expected);
    // The exact bytes too (one line of JSON; serde_json's default sorted keys).
    assert_eq!(
        w.output(&payload),
        r#"{"hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":{"interrupted":false,"isImage":false,"stderr":"","stdout":"PATH=/usr/bin\nPRIVATE_KEY=***REDACTED:base58_secret_key***\nHELIUS_API_KEY=***REDACTED:api_key***\n"}}}"#
    );
}

#[test]
fn bash_every_pattern_class_and_env_value_in_stdout_and_stderr() {
    let w = World::new();
    let sk_ant = format!("sk-ant-api03-{}", "A".repeat(80));
    let stdout = format!(
        "b58 {}\nkp {}\nmnemonic: {MNEMONIC}\ngh {GHP}\nanthropic {sk_ant}\njwt {JWT}\n",
        base58_secret(),
        keypair_array()
    );
    let payload = w.payload(
        "Bash",
        json!({ "command": "./show.sh" }),
        json!({
            "stdout": stdout,
            "stderr": format!("warn: using {ENV_VALUE}\n"),
            "interrupted": false,
            "isImage": false
        }),
    );
    w.assert_redact(
        &payload,
        updated(json!({
            "interrupted": false,
            "isImage": false,
            "stderr": "warn: using «redacted:HELIUS_API_KEY»\n",
            "stdout": "b58 ***REDACTED:base58_secret_key***\nkp ***REDACTED:keypair***\n\
                       mnemonic: ***REDACTED:seed_phrase***\ngh ***REDACTED:api_key***\n\
                       anthropic ***REDACTED:api_key***\njwt ***REDACTED:jwt***\n"
        })),
    );
}

#[test]
fn bash_image_result_keeps_stdout_and_scrubs_stderr() {
    let w = World::new();
    let image = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk";
    let payload = w.payload(
        "Bash",
        json!({ "command": "cat shot.png" }),
        json!({ "stdout": image, "stderr": format!("key {ENV_VALUE}"), "interrupted": false, "isImage": true }),
    );
    w.assert_redact(
        &payload,
        updated(json!({
            "interrupted": false,
            "isImage": true,
            "stderr": "key «redacted:HELIUS_API_KEY»",
            "stdout": image
        })),
    );
}

#[test]
fn read_text_result_is_redacted_in_place() {
    let w = World::new();
    let file = w.proj().join("notes.md").to_string_lossy().into_owned();
    let content = format!(
        "rpc key: {ENV_VALUE}\nwallet = {}\ncluster: devnet\n",
        keypair_array()
    );
    let payload = w.payload(
        "Read",
        json!({ "file_path": file }),
        json!({
            "type": "text",
            "file": { "filePath": file, "content": content, "numLines": 3, "startLine": 1, "totalLines": 3 }
        }),
    );
    w.assert_redact(
        &payload,
        updated(json!({
            "type": "text",
            "file": {
                "filePath": file,
                "content": "rpc key: «redacted:HELIUS_API_KEY»\nwallet = ***REDACTED:keypair***\ncluster: devnet\n",
                "numLines": 3,
                "startLine": 1,
                "totalLines": 3
            }
        })),
    );
}

#[test]
fn mcp_results_are_redacted_in_every_shape() {
    let w = World::new();
    let mcp = |response: Value| {
        let mut p = w.payload(
            "mcp__helius__getAccountInfo",
            json!({ "address": "ArFcixTu2krBEotzSzS8paV5c23JcbHRzUmV9Q2r9zHJ" }),
            response,
        );
        p["mcp_server"] = json!({ "name": "helius", "source": "user" });
        p
    };
    // Content blocks.
    w.assert_redact(
        &mcp(json!([{ "type": "text", "text": format!("api key {ENV_VALUE}, token {GHP}") }])),
        updated(json!([{ "type": "text", "text": "api key «redacted:HELIUS_API_KEY», token ***REDACTED:api_key***" }])),
    );
    // Plain string.
    w.assert_redact(
        &mcp(json!(format!("secret {}", base58_secret()))),
        updated(json!("secret ***REDACTED:base58_secret_key***")),
    );
    // Object with structured content.
    w.assert_redact(
        &mcp(json!({ "structuredContent": { "owner": "11111111111111111111111111111111", "jwt": JWT } })),
        updated(json!({ "structuredContent": { "owner": "11111111111111111111111111111111", "jwt": "***REDACTED:jwt***" } })),
    );
}

#[test]
fn clean_results_and_payloads_without_tool_response_print_nothing() {
    let w = World::new();
    w.assert_redact(
        &w.payload(
            "Bash",
            json!({ "command": "solana balance" }),
            json!({ "stdout": "1.5 SOL\n", "stderr": "", "interrupted": false, "isImage": false }),
        ),
        None,
    );
    // `tool_output` is not a Claude Code field (the hooks reference names only
    // `tool_response`): a payload carrying only it has nothing to redact.
    let mut legacy = w.payload("Bash", json!({ "command": "env" }), Value::Null);
    legacy.as_object_mut().unwrap().remove("tool_response");
    legacy["tool_output"] = json!(format!("HELIUS_API_KEY={UUID}"));
    w.assert_redact(&legacy, None);
}

#[test]
fn bare_and_keygen_seed_phrases_are_redacted() {
    let w = World::new();
    let phrase = "scheme spot photo card baby mountain device kick cradle pact join borrow";
    let keygen = format!(
        "Wrote new keypair to /tmp/k.json\n====\npubkey: 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU\n====\n\
         Save this seed phrase to recover your new keypair:\n{phrase}\n====\n"
    );
    let payload = w.payload(
        "Bash",
        json!({ "command": "solana-keygen new --no-bip39-passphrase -o /tmp/k.json" }),
        json!({ "stdout": keygen, "stderr": phrase, "interrupted": false, "isImage": false }),
    );
    w.assert_redact(
        &payload,
        updated(json!({
            "interrupted": false,
            "isImage": false,
            "stderr": "***REDACTED:seed_phrase***",
            "stdout": "Wrote new keypair to /tmp/k.json\n====\npubkey: 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU\n====\n\
                       Save this seed phrase to recover your new keypair:\n***REDACTED:seed_phrase***\n====\n"
        })),
    );
}

#[test]
fn grep_content_result_is_redacted_in_place() {
    let w = World::new();
    let payload = w.payload(
        "Grep",
        json!({ "pattern": "KEY", "path": w.proj(), "output_mode": "content" }),
        json!({
            "mode": "content",
            "numFiles": 2,
            "filenames": [],
            "content": format!("src/cfg.ts:3:const key = \"{ENV_VALUE}\"\nlog.txt:9:jwt {JWT}"),
            "numLines": 2
        }),
    );
    w.assert_redact(
        &payload,
        updated(json!({
            "mode": "content",
            "numFiles": 2,
            "filenames": [],
            "content": "src/cfg.ts:3:const key = \"«redacted:HELIUS_API_KEY»\"\nlog.txt:9:jwt ***REDACTED:jwt***",
            "numLines": 2
        })),
    );
}

/// A raw `.env` Read the tier permits (Relaxed, the default) comes back unchanged through the
/// shim; at High, where the read gate denies it, the same response is value-scrubbed.
#[test]
fn a_permitted_env_read_is_not_rewritten_through_the_shim() {
    let dotenv = format!("HELIUS_KEY={ENV_VALUE}\nCLUSTER=devnet\n");
    let mut w = World::with_env(&dotenv);
    let file = w.proj().join(".env").to_string_lossy().into_owned();
    let payload = w.payload(
        "Read",
        json!({ "file_path": file }),
        json!({
            "type": "text",
            "file": { "filePath": file, "content": dotenv, "numLines": 2, "startLine": 1, "totalLines": 2 }
        }),
    );
    w.assert_redact(&payload, None);
    let scrubbed = updated(json!({
        "type": "text",
        "file": {
            "filePath": file,
            "content": "HELIUS_KEY=«redacted:HELIUS_KEY»\nCLUSTER=devnet\n",
            "numLines": 2,
            "startLine": 1,
            "totalLines": 2
        }
    }));
    w.env = vec![("SAFE_AI_SKILL_TIER".to_string(), "high".to_string())];
    w.assert_redact(&payload, scrubbed);
}

/// The PostToolUse `redact` matcher in hooks.json (a JavaScript regex: it holds `.`/`*`, per
/// the hooks reference "Matcher patterns") matches every tool these payloads name.
#[test]
fn hooks_json_redact_matcher_covers_the_tested_tools() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../plugins/safe-ai-skill/hooks/hooks.json");
    let hooks: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let entry = hooks["hooks"]["PostToolUse"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| {
            e["hooks"].as_array().unwrap().iter().any(|h| {
                h["command"]
                    .as_str()
                    .unwrap_or_default()
                    .ends_with(" redact")
            })
        })
        .expect("a PostToolUse redact hook");
    let matcher = entry["matcher"].as_str().unwrap();
    // Alternatives of literal names and `prefix.*`: evaluate them as the unanchored regex does.
    assert!(
        matcher
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_|.*".contains(&b)),
        "matcher {matcher} needs a real regex evaluator"
    );
    let matches = |tool: &str| {
        matcher.split('|').any(|alt| match alt.strip_suffix(".*") {
            Some(prefix) => tool.contains(prefix),
            None => !alt.contains(['.', '*']) && tool.contains(alt),
        })
    };
    for tool in [
        "Bash",
        "Read",
        "Grep",
        "mcp__helius__getAccountInfo",
        "mcp__plugin_kit_ctx__run",
    ] {
        assert!(matches(tool), "{matcher} misses {tool}");
    }
    for h in entry["hooks"].as_array().unwrap() {
        assert_eq!(h["onFailure"], "continue");
        assert!(h["timeout"].as_u64().is_some_and(|t| t >= 10));
    }
}
