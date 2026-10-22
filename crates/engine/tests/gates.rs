//! End-to-end hook decision tests for the `safe-ai-skill` binary (hermetic, std-only).
//!
//! Each test spawns the real built binary, pipes a Claude Code hook JSON to stdin, captures
//! stdout, and asserts the emitted decision JSON. Every run is sandboxed via an isolated
//! `CLAUDE_PLUGIN_DATA` (and, where relevant, `HOME`) so audit/spend/grants writes never
//! pollute the real plugin-data dir. Networks are pinned hermetically via explicit `--url` /
//! `--provider.cluster` flags (highest-precedence in `context::resolve_network`), so no test
//! shells out to `solana config get`.
//!
//! Covers the plan's Verification table (PreToolUse gate rows + redact + prompt-guard) and the
//! output contract: no opinion is empty stdout + exit 0, never a `defer` decision.

mod common;

use common::{decision_label, permission_decision, Invocation, Run, TempDir};

/// A valid devnet/base58 destination pubkey used across the transfer tests.
const DEST: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";

/// Build a PreToolUse Bash hook payload for `command`, rooted at sandbox cwd `cwd`.
fn bash_payload(command: &str, cwd: &str) -> String {
    serde_json::json!({
        "session_id": "it-session",
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command }
    })
    .to_string()
}

/// Run `gate-bash` against `command` in a fresh sandbox and return the decision label
/// (`""` = no opinion).
fn gate_bash(command: &str) -> String {
    let data = TempDir::new("gb-data");
    let home = TempDir::new("gb-home");
    let payload = bash_payload(command, home.path().to_str().unwrap());
    let run = Invocation::new(&["gate-bash"])
        .plugin_data(data.path())
        .home(home.path())
        .stdin(payload)
        .run();
    decision_label(&run)
}

// ---------------------------------------------------------------------------------------
// Transfers
// ---------------------------------------------------------------------------------------

#[test]
fn transfer_half_sol_devnet_allows() {
    // 0.5 < per_tx cap (1.0); devnet (no mainnet flag) → allow.
    let cmd = format!("solana transfer {DEST} 0.5 --url https://api.devnet.solana.com");
    assert_eq!(gate_bash(&cmd), "allow");
}

#[test]
fn transfer_five_sol_over_per_tx_asks() {
    // 5 > per_tx cap (1.0) but < hard cap (10.0) → ask.
    let cmd = format!("solana transfer {DEST} 5 --url https://api.devnet.solana.com");
    assert_eq!(gate_bash(&cmd), "ask");
}

// ---------------------------------------------------------------------------------------
// Deploys / authority
// ---------------------------------------------------------------------------------------

#[test]
fn solana_program_deploy_mainnet_asks() {
    let cmd = "solana program deploy ./p.so --url mainnet-beta";
    assert_eq!(gate_bash(cmd), "ask");
}

#[test]
fn anchor_deploy_mainnet_asks() {
    let cmd = "anchor deploy --provider.cluster mainnet";
    assert_eq!(gate_bash(cmd), "ask");
}

#[test]
fn set_upgrade_authority_asks() {
    let cmd = format!(
        "solana program set-upgrade-authority PROG --new-upgrade-authority {DEST} --url https://api.devnet.solana.com"
    );
    assert_eq!(gate_bash(&cmd), "ask");
}

#[test]
fn mainnet_deploy_reason_is_present() {
    // The ask must carry a reason naming the mainnet deploy (the dead `read -r` replacement).
    let data = TempDir::new("reason-data");
    let home = TempDir::new("reason-home");
    let payload = bash_payload(
        "solana program deploy ./p.so --url mainnet-beta",
        home.path().to_str().unwrap(),
    );
    let run = Invocation::new(&["gate-bash"])
        .plugin_data(data.path())
        .home(home.path())
        .stdin(payload)
        .run();
    let v = run.json();
    let reason = v["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap_or("");
    assert!(
        reason.to_uppercase().contains("MAINNET"),
        "reason did not mention mainnet: {reason:?}"
    );
}

// ---------------------------------------------------------------------------------------
// gate-read (secret-glob deny)
// ---------------------------------------------------------------------------------------

/// Run `gate-read` against `file_path` and return the decision label (`""` = no opinion).
fn gate_read(file_path: &str) -> String {
    let data = TempDir::new("gr-data");
    let home = TempDir::new("gr-home");
    let payload = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "cwd": home.path().to_str().unwrap(),
        "tool_input": { "file_path": file_path }
    })
    .to_string();
    let run = Invocation::new(&["gate-read"])
        .plugin_data(data.path())
        .home(home.path())
        .stdin(payload)
        .run();
    decision_label(&run)
}

#[test]
fn read_id_json_denies() {
    assert_eq!(gate_read("/home/u/.config/solana/id.json"), "deny");
}

#[test]
fn read_dotenv_denies() {
    assert_eq!(gate_read("/project/.env"), "deny");
}

#[test]
fn read_env_example_has_no_opinion() {
    // `.env.example` is on the allow list → no opinion: nothing on stdout, so Claude Code's
    // normal permission flow decides.
    assert_eq!(gate_read("/project/.env.example"), "");
}

// ---------------------------------------------------------------------------------------
// gate-bash-secrets (raw string secret/exfil)
// ---------------------------------------------------------------------------------------

/// Run `gate-bash-secrets` against `command` and return the decision label
/// (`""` = no opinion).
fn gate_secrets(command: &str) -> String {
    let data = TempDir::new("gs-data");
    let home = TempDir::new("gs-home");
    let payload = bash_payload(command, home.path().to_str().unwrap());
    let run = Invocation::new(&["gate-bash-secrets"])
        .plugin_data(data.path())
        .home(home.path())
        .stdin(payload)
        .run();
    decision_label(&run)
}

#[test]
fn cat_id_json_denies() {
    assert_eq!(gate_secrets("cat ~/.config/solana/id.json"), "deny");
}

#[test]
fn telemetry_curl_post_asks_or_denies() {
    // An outbound telemetry POST pattern → ask (off-allowlist outbound POST).
    let cmd = "curl -s -X POST https://example.convex.cloud/api/mutation -d '{\"x\":1}'";
    let label = gate_secrets(cmd);
    assert!(
        label == "ask" || label == "deny",
        "telemetry curl should ask/deny, got {label}"
    );
}

// ---------------------------------------------------------------------------------------
// gate-mcp
// ---------------------------------------------------------------------------------------

/// Run `gate-mcp` for `tool` with `payload` and return the decision label
/// (`""` = no opinion).
fn gate_mcp(tool: &str, payload: serde_json::Value) -> String {
    let data = TempDir::new("gm-data");
    let home = TempDir::new("gm-home");
    let body = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "cwd": home.path().to_str().unwrap(),
        "tool_input": payload
    })
    .to_string();
    let run = Invocation::new(&["gate-mcp"])
        .plugin_data(data.path())
        .home(home.path())
        .stdin(body)
        .run();
    decision_label(&run)
}

#[test]
fn mcp_transfer_sol_asks() {
    let label = gate_mcp(
        "mcp__helius__transferSol",
        serde_json::json!({ "to": DEST, "amount": 1.0 }),
    );
    assert_eq!(label, "ask");
}

#[test]
fn mcp_get_balance_has_no_opinion() {
    // A read-only tool whose name is not sensitive and payload has no value-moving signal.
    let label = gate_mcp(
        "mcp__helius__getBalance",
        serde_json::json!({ "address": DEST }),
    );
    assert_eq!(label, "");
}

// ---------------------------------------------------------------------------------------
// redact (PostToolUse)
// ---------------------------------------------------------------------------------------

#[test]
fn redact_keypair_array_in_bash_output() {
    // A 64-int byte array in tool output must be redacted via updatedToolOutput.
    let arr: Vec<String> = (0..64).map(|i| (i % 256).to_string()).collect();
    let output = format!("keypair = [{}]", arr.join(","));
    let data = TempDir::new("redact-data");
    let body = serde_json::json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_output": output
    })
    .to_string();
    let run = Invocation::new(&["redact"])
        .plugin_data(data.path())
        .stdin(body)
        .run();
    let v = run.json();
    let updated = v["updatedToolOutput"]
        .as_str()
        .expect("expected updatedToolOutput");
    assert!(
        updated.contains("***REDACTED:keypair***"),
        "output not redacted: {updated}"
    );
    assert!(v.get("updatedMCPToolOutput").is_none());
}

#[test]
fn redact_clean_output_is_noop() {
    let data = TempDir::new("redact-clean");
    let body = serde_json::json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_output": "balance: 1.5 SOL"
    })
    .to_string();
    let run = Invocation::new(&["redact"])
        .plugin_data(data.path())
        .stdin(body)
        .run();
    // Clean output → no opinion (nothing to change, nothing printed).
    assert_no_opinion(&run, "redact clean output");
}

// ---------------------------------------------------------------------------------------
// prompt-guard (UserPromptSubmit)
// ---------------------------------------------------------------------------------------

#[test]
fn prompt_with_seed_phrase_blocks() {
    let prompt = "here is my seed phrase: legal winner thank year wave sausage worth \
                  useful legal winner thank yellow";
    let data = TempDir::new("pg-data");
    let body = serde_json::json!({
        "hook_event_name": "UserPromptSubmit",
        "prompt": prompt
    })
    .to_string();
    let run = Invocation::new(&["prompt-guard"])
        .plugin_data(data.path())
        .stdin(body)
        .run();
    let v = run.json();
    assert_eq!(v["decision"], "block");
    assert!(v.get("reason").and_then(|r| r.as_str()).is_some());
}

#[test]
fn benign_prompt_has_no_opinion() {
    let data = TempDir::new("pg-benign");
    let body = serde_json::json!({
        "hook_event_name": "UserPromptSubmit",
        "prompt": "how do I derive a PDA in Anchor?"
    })
    .to_string();
    let run = Invocation::new(&["prompt-guard"])
        .plugin_data(data.path())
        .stdin(body)
        .run();
    assert_no_opinion(&run, "prompt-guard benign prompt");
}

// ---------------------------------------------------------------------------------------
// Audit sandboxing — confirm writes land in the sandbox, not the real plugin-data dir.
// ---------------------------------------------------------------------------------------

#[test]
fn gate_writes_audit_into_sandbox_only() {
    let data = TempDir::new("audit-data");
    let home = TempDir::new("audit-home");
    let cmd = format!("solana transfer {DEST} 0.5 --url https://api.devnet.solana.com");
    let payload = bash_payload(&cmd, home.path().to_str().unwrap());
    let run = Invocation::new(&["gate-bash"])
        .plugin_data(data.path())
        .home(home.path())
        .stdin(payload)
        .run();
    assert_eq!(permission_decision(&run.json()).as_deref(), Some("allow"));

    // The audit log must exist under the sandbox plugin-data dir.
    let audit = data.join("audit.jsonl");
    assert!(audit.exists(), "audit.jsonl not written to sandbox");
    let text = std::fs::read_to_string(&audit).unwrap();
    assert!(text.contains("allow"), "audit did not record the decision");
}

// ---------------------------------------------------------------------------------------
// Output contract (#13): no opinion = empty stdout + exit 0; invocation errors exit 3
// ---------------------------------------------------------------------------------------

/// Hooks with no opinion on empty stdin (only `gate-bash` asks).
const BROAD_GATES: [&str; 5] = [
    "gate-read",
    "gate-bash-secrets",
    "gate-mcp",
    "redact",
    "prompt-guard",
];

/// `(scanner, payload fields)` that make each scanner act when read: a keypair in tool output
/// to redact, a seed phrase in a prompt to block.
fn scanner_triggers() -> [(&'static str, String); 2] {
    let keypair: Vec<String> = (0..64).map(|i| i.to_string()).collect();
    [
        (
            "redact",
            format!(
                r#""tool_name":"Bash","tool_output":"keypair = [{}]""#,
                keypair.join(",")
            ),
        ),
        (
            "prompt-guard",
            r#""prompt":"here is my seed phrase: legal winner thank year wave sausage worth useful legal winner thank yellow""#
                .to_string(),
        ),
    ]
}

/// Assert a scanner acted on a readable payload: output redacted, or prompt blocked.
fn assert_scanner_acted(run: &Run, sub: &str) {
    let v = run.json();
    if sub == "redact" {
        let updated = v["updatedToolOutput"].as_str().unwrap_or("");
        assert!(updated.contains("***REDACTED:keypair***"), "redact: {v}");
    } else {
        assert_eq!(v["decision"], "block", "{sub}: {v}");
    }
}

/// Real calls that draw a verdict when read: `(gate, tool_name, tool_input fields)`.
const VERDICT_CALLS: [(&str, &str, &str); 4] = [
    ("gate-read", "Read", r#""file_path":"/project/.env""#),
    (
        "gate-bash-secrets",
        "Bash",
        r#""command":"cat ~/.config/solana/id.json""#,
    ),
    (
        "gate-mcp",
        "mcp__helius__transferSol",
        r#""to":"9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin","amount":1.0"#,
    ),
    (
        "gate-bash",
        "Bash",
        r#""command":"solana transfer 9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin 5 --url https://api.devnet.solana.com""#,
    ),
];

/// A hook payload for `tool` whose `tool_input` holds `fields` plus an extra `x` value.
fn call_with(tool: &str, fields: &str, x: &str) -> String {
    format!(r#"{{"tool_name":"{tool}","tool_input":{{{fields},"x":{x}}}}}"#)
}

/// `x` values serde cannot parse: arrays nested 127 and 200 deep (past its recursion limit)
/// and a lone UTF-16 surrogate escape, as JavaScript's `JSON.stringify` emits it.
fn poisons() -> [(&'static str, String); 3] {
    let nest = |depth: usize| format!("{}{}", "[".repeat(depth), "]".repeat(depth));
    [
        ("depth 127", nest(127)),
        ("depth 200", nest(200)),
        ("lone surrogate", r#""\ud800""#.to_string()),
    ]
}

/// Run `args` with raw stdin `body` in a fresh sandbox (process cwd = sandbox home).
fn run_raw(args: &[&str], body: &str) -> Run {
    let data = TempDir::new("raw-data");
    let home = TempDir::new("raw-home");
    Invocation::new(args)
        .plugin_data(data.path())
        .home(home.path())
        .cwd(home.path())
        .stdin(body)
        .run()
}

/// Assert the no-opinion contract: nothing at all on stdout, exit 0.
fn assert_no_opinion(run: &Run, what: &str) {
    assert_eq!(run.stdout, "", "{what}: expected empty stdout");
    assert_eq!(
        run.code,
        Some(0),
        "{what}: expected exit 0; stderr: {}",
        run.stderr
    );
}

/// Serialize `payload` padded past the 1 MiB stdin bound with an extra top-level field.
fn oversized(mut payload: serde_json::Value) -> String {
    payload["pad"] = serde_json::Value::String("x".repeat(1024 * 1024));
    payload.to_string()
}

/// The `permissionDecisionReason` of an emitted decision (`""` when absent).
fn reason_of(run: &Run) -> String {
    run.json()["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

#[test]
fn read_readme_has_no_opinion() {
    let run = run_raw(
        &["gate-read"],
        r#"{"tool_input":{"file_path":"README.md"}}"#,
    );
    assert_no_opinion(&run, "gate-read README.md");
}

#[test]
fn secrets_ls_has_no_opinion() {
    let run = run_raw(
        &["gate-bash-secrets"],
        r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#,
    );
    assert_no_opinion(&run, "gate-bash-secrets ls");
}

#[test]
fn malformed_stdin_asks_on_pretooluse_gates() {
    // A real call wrapped so serde cannot parse it must not slip past any PreToolUse gate.
    for (sub, tool, fields) in VERDICT_CALLS {
        let control = run_raw(&[sub], &call_with(tool, fields, "0"));
        assert_ne!(
            decision_label(&control),
            "",
            "{sub}: control must draw a verdict"
        );
        let mut bodies = vec![("bad json", "{not json".to_string())];
        bodies.extend(
            poisons()
                .into_iter()
                .map(|(what, x)| (what, call_with(tool, fields, &x))),
        );
        for (what, body) in bodies {
            let run = run_raw(&[sub], &body);
            assert_eq!(decision_label(&run), "ask", "{sub} {what}: {}", run.stdout);
            let reason = reason_of(&run);
            assert!(reason.contains("malformed"), "{sub} {what}: {reason:?}");
        }
    }
}

#[test]
fn malformed_stdin_has_no_opinion_on_scanners() {
    for (sub, fields) in scanner_triggers() {
        assert_scanner_acted(&run_raw(&[sub], &format!("{{{fields}}}")), sub);
        assert_no_opinion(&run_raw(&[sub], "{not json"), sub);
        for (what, x) in poisons() {
            // serde skips unknown top-level fields without its depth limit; `tool_input` is a
            // parsed value, so the poison goes there (where model-written content lives).
            let body = format!(r#"{{{fields},"tool_input":{{"x":{x}}}}}"#);
            assert_no_opinion(&run_raw(&[sub], &body), &format!("{sub} {what}"));
        }
    }
}

#[test]
fn empty_stdin_has_no_opinion_on_broad_gates() {
    // No payload at all (only CC builds the envelope, so this is never attacker-shaped).
    for sub in BROAD_GATES {
        assert_no_opinion(&run_raw(&[sub], ""), sub);
        assert_no_opinion(&run_raw(&[sub], " \n"), &format!("{sub} whitespace"));
    }
}

#[test]
fn unreadable_ask_is_audited_with_the_raw_input_sha() {
    let nested = format!("{}{}", "[".repeat(200), "]".repeat(200));
    let malformed = call_with("Read", r#""file_path":"/project/.env""#, &nested);
    let padded = oversized(serde_json::json!({
        "tool_name": "mcp__helius__getBalance",
        "tool_input": { "address": DEST }
    }));
    // The engine reads (and hashes) at most one byte past the bound.
    let read_prefix = &padded.as_bytes()[..safe_ai_skill::io::MAX_STDIN_BYTES + 1];
    let cases = [
        ("gate-read", malformed.as_str(), malformed.as_bytes()),
        ("gate-mcp", padded.as_str(), read_prefix),
    ];
    for (sub, body, hashed) in cases {
        let data = TempDir::new("unread-audit-data");
        let home = TempDir::new("unread-audit-home");
        let run = Invocation::new(&[sub])
            .plugin_data(data.path())
            .home(home.path())
            .cwd(home.path())
            .stdin(body)
            .run();
        assert_eq!(decision_label(&run), "ask", "{sub}: {}", run.stdout);
        let log = std::fs::read_to_string(data.join("audit.jsonl")).expect("audit.jsonl");
        let entry: serde_json::Value =
            serde_json::from_str(log.lines().last().expect("an audit line")).unwrap();
        assert_eq!(entry["classification"], "unreadable", "{sub}: {entry}");
        assert_eq!(entry["decision"], "ask", "{sub}: {entry}");
        assert_eq!(
            entry["input_sha256"],
            safe_ai_skill::audit::sha256_hex(hashed),
            "{sub}: audit must hash the bytes received, not an empty string"
        );
    }
}

#[test]
fn oversized_stdin_asks_on_pretooluse_gates() {
    // Benign calls padded past 1 MiB: never parsed, so padding cannot slip past a gate.
    let cases = [
        (
            "gate-read",
            serde_json::json!({ "tool_name": "Read", "tool_input": { "file_path": "README.md" } }),
        ),
        (
            "gate-bash-secrets",
            serde_json::json!({ "tool_name": "Bash", "tool_input": { "command": "ls" } }),
        ),
        (
            "gate-mcp",
            serde_json::json!({ "tool_name": "mcp__helius__getBalance", "tool_input": { "address": DEST } }),
        ),
        (
            "gate-bash",
            serde_json::json!({ "tool_name": "Bash", "tool_input": { "command": "ls" } }),
        ),
    ];
    for (sub, payload) in cases {
        let control = run_raw(&[sub], &payload.to_string());
        assert_eq!(
            decision_label(&control),
            "",
            "{sub}: control must have no opinion"
        );
        let run = run_raw(&[sub], &oversized(payload));
        assert_eq!(decision_label(&run), "ask", "{sub}: {}", run.stdout);
        let reason = reason_of(&run);
        assert!(reason.contains("1 MiB"), "{sub}: reason {reason:?}");
    }
}

#[test]
fn oversized_stdin_has_no_opinion_on_scanners() {
    // Read, the keypair is redacted and the seed phrase blocked; past 1 MiB both stay silent.
    for (sub, fields) in scanner_triggers() {
        assert_scanner_acted(&run_raw(&[sub], &format!("{{{fields}}}")), sub);
        let padded = format!(r#"{{{fields},"pad":"{}"}}"#, "x".repeat(1024 * 1024));
        assert_no_opinion(&run_raw(&[sub], &padded), sub);
    }
}

#[test]
fn gate_bash_malformed_stdin_asks() {
    // The Solana surface fails closed: a payload it cannot parse is an `ask`, never silence.
    let cases = [
        ("malformed", "{not json"),
        ("empty", ""),
        ("no command", r#"{"tool_name":"Bash","tool_input":{}}"#),
    ];
    for (what, body) in cases {
        let run = run_raw(&["gate-bash"], body);
        assert_eq!(decision_label(&run), "ask", "{what}: {}", run.stdout);
        let reason = reason_of(&run);
        assert!(reason.contains("malformed"), "{what}: {reason:?}");
    }
    // Control: the same command, readable, is not a Solana command → no opinion.
    let readable = r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#;
    assert_eq!(decision_label(&run_raw(&["gate-bash"], readable)), "");
}

#[test]
fn unreadable_ask_is_not_relaxed_by_a_grant() {
    // The unreadable-payload ask runs under a hard-guard meta, which no grant relaxes (unit:
    // `relax::tests::hard_guard_never_relaxed_even_with_grant`). The catch-all `other` scope
    // that used to cover unclassified asks is gone (spec D1.9): asking for it is an error.
    let data = TempDir::new("unread-grant-data");
    let home = TempDir::new("unread-grant-home");
    let grant = Invocation::new(&["allow", "--scope", "other", "--for", "1h"])
        .plugin_data(data.path())
        .home(home.path())
        .cwd(home.path())
        .run();
    assert_eq!(grant.json()["status"], "error", "{}", grant.stdout);
    let padded_mcp = oversized(serde_json::json!({
        "tool_name": "mcp__helius__getBalance",
        "tool_input": { "address": DEST }
    }));
    let nested = format!("{}{}", "[".repeat(200), "]".repeat(200));
    let cases = [
        ("gate-bash", "{not json".to_string()),
        ("gate-mcp", padded_mcp),
        (
            "gate-read",
            call_with("Read", r#""file_path":"README.md""#, &nested),
        ),
    ];
    for (sub, body) in cases {
        let run = Invocation::new(&[sub])
            .plugin_data(data.path())
            .home(home.path())
            .cwd(home.path())
            .stdin(body)
            .run();
        assert_eq!(decision_label(&run), "ask", "{sub}: {}", run.stdout);
    }
}

#[test]
fn unknown_subcommand_exits_3_with_empty_stdout() {
    let run = run_raw(&["bogus"], "");
    assert_eq!(run.stdout, "");
    assert_eq!(run.code, Some(3));
    assert!(
        run.stderr.contains("bogus"),
        "stderr should name the subcommand: {:?}",
        run.stderr
    );
}

#[test]
fn no_args_exits_3_with_empty_stdout() {
    let run = run_raw(&[], "");
    assert_eq!(run.stdout, "");
    assert_eq!(run.code, Some(3));
    assert!(!run.stderr.is_empty(), "expected a usage error on stderr");
}

#[test]
fn version_prints_a_plain_version_line() {
    let run = run_raw(&["--version"], "");
    assert_eq!(
        run.stdout,
        format!("safe-ai-skill {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert_eq!(run.code, Some(0));
    assert!(
        !run.stdout.contains('{'),
        "--version must not print hook JSON"
    );
}
