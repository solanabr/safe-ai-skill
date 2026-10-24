//! `adapt opencode <gate>` end to end (experimental, issue #26).
//!
//! Payloads are what `adapters/opencode/safe-ai-skill.js` sends from opencode's
//! `tool.execute.before(input: {tool, sessionID, callID}, output: {args})`, plus the plugin's
//! `directory`, `worktree` and configured MCP server names. Tool ids and argument names follow
//! `anomalyco/opencode@v1.19.4`: `bash {command, workdir?}`, `read {filePath}`,
//! `grep {pattern, path?, include?}`, `glob {pattern, path?}`, `write {filePath, content}`,
//! `edit {filePath, oldString, newString}`, `apply_patch {patchText}`, MCP tools
//! `sanitize(server) + "_" + sanitize(tool)`. opencode has no ask outcome, so `adapt opencode`
//! must print nothing, a deny, or (gate-read only) an `updatedInput` rewrite.

mod common;

use common::{permission_decision, Invocation, Run, TempDir};
use serde_json::{json, Value};

const MAINNET_DEPLOY: &str = "solana program deploy x.so --url mainnet-beta";
const DEST: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";
const SUFFIX: &str = safe_ai_skill::adapt_opencode::ASK_SUFFIX;

struct World {
    home: TempDir,
    proj: TempDir,
    data: TempDir,
    env: Vec<(String, String)>,
}

impl World {
    fn new(tag: &str) -> World {
        World {
            home: TempDir::new(&format!("{tag}-home")),
            proj: TempDir::new(&format!("{tag}-proj")),
            data: TempDir::new(&format!("{tag}-data")),
            env: Vec::new(),
        }
    }

    fn with_env(mut self, key: &str, val: &str) -> World {
        self.env.push((key.to_string(), val.to_string()));
        self
    }

    fn payload(&self, tool: &str, args: Value) -> String {
        json!({
            "tool": tool,
            "sessionID": "ses_01JABCDEF",
            "callID": "toolu_01",
            "args": args,
            "directory": self.proj.path(),
            "worktree": self.proj.path(),
            "mcpServers": [],
        })
        .to_string()
    }

    fn run(&self, args: &[&str], body: String) -> Run {
        let no_tools = TempDir::new("oc-path");
        let mut inv = Invocation::new(args)
            .plugin_data(self.data.path())
            .home(self.home.path())
            .cwd(self.proj.path())
            .env("PATH", no_tools.path().to_str().unwrap())
            .stdin(body);
        for (k, v) in &self.env {
            inv = inv.env(k, v);
        }
        inv.run()
    }

    fn oc(&self, gate: &str, tool: &str, args: Value) -> Run {
        self.run(&["adapt", "opencode", gate], self.payload(tool, args))
    }
}

/// The decision label (`""` for no output, `"rewrite"` for an `updatedInput`), checking exit 0
/// and that opencode never sees an `ask` or an `allow`.
fn label(run: &Run) -> String {
    assert_eq!(run.code, Some(0), "stderr: {}", run.stderr);
    if run.stdout.is_empty() {
        return String::new();
    }
    assert!(!run.stdout.contains('\n'), "one line: {}", run.stdout);
    let v = run.json();
    if v["hookSpecificOutput"].get("updatedInput").is_some() {
        assert!(v["hookSpecificOutput"].get("permissionDecision").is_none());
        return "rewrite".into();
    }
    let label = permission_decision(&v).unwrap_or_default();
    assert_eq!(label, "deny", "deny or nothing: {}", run.stdout);
    label
}

fn reason(run: &Run) -> String {
    run.json()["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

fn patch(headers: &[&str]) -> Value {
    let mut text = String::from("*** Begin Patch\n");
    for h in headers {
        text.push_str(h);
        text.push_str("\n+x\n");
    }
    text.push_str("*** End Patch\n");
    json!({ "patchText": text })
}

#[test]
fn bash_ask_becomes_deny_with_the_opencode_reason() {
    let w = World::new("oc-ask");
    let run = w.oc("gate-bash", "bash", json!({ "command": MAINNET_DEPLOY }));
    assert_eq!(label(&run), "deny");
    assert!(reason(&run).ends_with(SUFFIX), "{}", run.stdout);
    assert!(!reason(&run).contains("approve to proceed"));
}

#[test]
fn benign_calls_are_no_output() {
    let w = World::new("oc-benign");
    std::fs::write(w.proj.join("README.md"), "hi").unwrap();
    for gate in ["gate-bash", "gate-bash-secrets"] {
        let run = w.oc(
            gate,
            "bash",
            json!({ "command": "ls -la", "description": "list" }),
        );
        assert_eq!(label(&run), "", "{gate}");
    }
    let cases = [
        ("gate-read", "read", json!({ "filePath": "README.md" })),
        ("gate-read", "glob", json!({ "pattern": "**/*.rs" })),
        (
            "gate-tamper",
            "write",
            json!({ "filePath": "src/new.rs", "content": "fn main() {}" }),
        ),
        (
            "gate-tamper",
            "edit",
            json!({ "filePath": "README.md", "oldString": "hi", "newString": "hello" }),
        ),
        (
            "gate-tamper",
            "apply_patch",
            patch(&["*** Add File: src/a.rs", "*** Update File: README.md"]),
        ),
    ];
    for (gate, tool, args) in cases {
        let run = w.oc(gate, tool, args);
        assert_eq!(label(&run), "", "{tool}: {}", run.stdout);
    }
}

#[test]
fn secret_reads_deny_through_read_and_the_shell() {
    let w = World::new("oc-secret");
    std::fs::write(w.proj.join(".env"), "KEY=v").unwrap();
    let run = w.oc("gate-read", "read", json!({ "filePath": ".env" }));
    assert_eq!(label(&run), "deny");
    let wallet = w.home.join(".config/solana/id.json");
    std::fs::create_dir_all(wallet.parent().unwrap()).unwrap();
    std::fs::write(&wallet, format!("{:?}", vec![1u8; 64])).unwrap();
    let run = w.oc(
        "gate-read",
        "read",
        json!({ "filePath": wallet.to_str().unwrap() }),
    );
    assert_eq!(label(&run), "deny");
    let run = w.oc(
        "gate-bash-secrets",
        "bash",
        json!({ "command": "cat ~/.config/solana/id.json" }),
    );
    assert_eq!(label(&run), "deny");
}

#[test]
fn grep_without_include_gets_the_exclusion_as_its_include() {
    let w = World::new("oc-grep");
    let run = w.oc("gate-read", "grep", json!({ "pattern": "secret" }));
    assert_eq!(label(&run), "rewrite", "{}", run.stdout);
    let updated = &run.json()["hookSpecificOutput"]["updatedInput"];
    assert_eq!(updated["pattern"], "secret");
    let include = updated["include"].as_str().unwrap();
    assert!(include.starts_with("!{"), "{include}");
    assert!(
        updated.get("glob").is_none(),
        "opencode args only: {updated}"
    );
}

#[test]
fn grep_include_is_kept_for_code_files_and_denied_otherwise() {
    let w = World::new("oc-grep-include");
    for include in ["*.ts", "**/*.{ts,tsx}", "*.rs"] {
        let run = w.oc(
            "gate-read",
            "grep",
            json!({ "pattern": "x", "include": include }),
        );
        assert_eq!(label(&run), "", "{include}: {}", run.stdout);
    }
    for include in ["*.json", "*", "*.{ts,json}", "config/**"] {
        let run = w.oc(
            "gate-read",
            "grep",
            json!({ "pattern": "x", "include": include }),
        );
        assert_eq!(label(&run), "deny", "{include}");
        assert!(reason(&run).contains("include"), "{}", run.stdout);
    }
}

#[test]
fn grep_into_a_credential_dir_denies() {
    let w = World::new("oc-grep-root");
    let dir = w.home.join(".config/solana");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("id.json"), format!("{:?}", vec![1u8; 64])).unwrap();
    let run = w.oc(
        "gate-read",
        "grep",
        json!({ "pattern": "1", "path": dir.to_str().unwrap() }),
    );
    assert_eq!(label(&run), "deny", "{}", run.stdout);
}

#[test]
fn writes_into_the_data_dir_deny() {
    let w = World::new("oc-tamper");
    let target = w.data.join("grants.json");
    let run = w.oc(
        "gate-tamper",
        "write",
        json!({ "filePath": target.to_str().unwrap(), "content": "{}" }),
    );
    assert_eq!(label(&run), "deny");
    let header = format!("*** Add File: {}", target.display());
    let run = w.oc(
        "gate-tamper",
        "apply_patch",
        patch(&["*** Add File: src/ok.rs", &header]),
    );
    assert_eq!(label(&run), "deny");
}

#[test]
fn opencode_config_and_plugin_code_are_protected_from_file_tools() {
    let w = World::new("oc-cfg");
    let global = w.home.join(".config/opencode/plugins/safe-ai-skill.js");
    let paths = [
        ".opencode/plugins/safe-ai-skill.js".to_string(),
        ".opencode/plugins/later.ts".to_string(),
        ".opencode/tools/helper.js".to_string(),
        ".opencode/package.json".to_string(),
        "opencode.json".to_string(),
        "opencode.jsonc".to_string(),
        global.display().to_string(),
        w.home
            .join(".config/opencode/opencode.json")
            .display()
            .to_string(),
    ];
    for p in &paths {
        for (tool, args) in [
            ("write", json!({ "filePath": p, "content": "x" })),
            (
                "edit",
                json!({ "filePath": p, "oldString": "a", "newString": "b" }),
            ),
            ("apply_patch", patch(&[&format!("*** Update File: {p}")])),
        ] {
            let run = w.oc("gate-tamper", tool, args);
            assert_eq!(label(&run), "deny", "{tool} {p}");
            assert!(reason(&run).contains("opencode config"), "{}", run.stdout);
        }
    }
    let run = w.oc(
        "gate-tamper",
        "apply_patch",
        patch(&["*** Update File: notes.md\n*** Move to: .opencode/plugins/x.js"]),
    );
    assert_eq!(label(&run), "deny");
}

#[test]
fn config_dirs_from_the_environment_are_protected() {
    let xdg = TempDir::new("oc-xdg");
    let custom = TempDir::new("oc-cfgdir");
    let cfg_file = TempDir::new("oc-cfgfile");
    let cfg = cfg_file.join("team.json");
    let w = World::new("oc-envcfg")
        .with_env("XDG_CONFIG_HOME", xdg.path().to_str().unwrap())
        .with_env("OPENCODE_CONFIG_DIR", custom.path().to_str().unwrap())
        .with_env("OPENCODE_CONFIG", cfg.to_str().unwrap());
    for target in [
        xdg.join("opencode/plugins/evil.js"),
        custom.join("plugins/evil.js"),
        custom.join("tools/x.ts"),
        cfg.clone(),
    ] {
        let run = w.oc(
            "gate-tamper",
            "write",
            json!({ "filePath": target.to_str().unwrap(), "content": "x" }),
        );
        assert_eq!(label(&run), "deny", "{}", target.display());
        let command = format!("cp /tmp/x {}", common::sh_path(&target));
        let run = w.oc("gate-bash-secrets", "bash", json!({ "command": command }));
        assert_eq!(label(&run), "deny", "{command}");
    }
}

#[test]
fn shell_writes_to_opencode_config_deny_and_reads_pass() {
    let w = World::new("oc-shell");
    std::fs::create_dir_all(w.proj.join(".opencode/plugins")).unwrap();
    std::fs::write(w.proj.join(".opencode/plugins/safe-ai-skill.js"), "//").unwrap();
    std::fs::write(w.proj.join("opencode.json"), "{}").unwrap();
    for command in [
        "rm -rf .opencode",
        "mv .opencode .opencode.off",
        "rm .opencode/plugins/*",
        "echo 'export const X = 1' > .opencode/plugins/later.js",
        "cp /tmp/evil.js .opencode/tools/",
        "printf '{}' | tee opencode.json",
        "sed -i '' 's/safe-ai-skill//' opencode.json",
        "cat /dev/null > ~/.config/opencode/opencode.json",
        "python3 -c \"open('.opencode/plugins/x.js','w').write('')\"",
        "git checkout -- .opencode",
        "find . -name '*.js' -delete",
    ] {
        let run = w.oc("gate-bash-secrets", "bash", json!({ "command": command }));
        assert_eq!(label(&run), "deny", "{command}");
    }
    for command in [
        "cat .opencode/plugins/safe-ai-skill.js",
        "ls -la .opencode",
        "jq .mcp opencode.json",
        "git diff opencode.json",
        "find .opencode -name '*.js'",
        "safe-ai-skill status",
        "cargo test",
    ] {
        let run = w.oc("gate-bash-secrets", "bash", json!({ "command": command }));
        assert_eq!(label(&run), "", "{command}: {}", run.stdout);
    }
}

#[test]
fn the_engine_binary_is_protected() {
    let w = World::new("oc-engine");
    let engine = std::path::Path::new(common::bin());
    let run = w.oc(
        "gate-tamper",
        "write",
        json!({ "filePath": engine.to_str().unwrap(), "content": "#!/bin/sh" }),
    );
    assert_eq!(label(&run), "deny");
    for command in [
        format!("rm -f {}", common::sh_path(engine)),
        format!("cp /tmp/x {}", common::sh_path(engine)),
        format!("chmod -x {}", common::sh_path(engine)),
    ] {
        let run = w.oc("gate-bash-secrets", "bash", json!({ "command": command }));
        assert_eq!(label(&run), "deny", "{command}");
    }
}

#[test]
fn a_workdir_is_where_relative_paths_resolve() {
    let w = World::new("oc-workdir");
    let wallet = w.home.join("keys");
    std::fs::create_dir_all(&wallet).unwrap();
    std::fs::write(wallet.join(".env"), "K=v").unwrap();
    let run = w.oc(
        "gate-bash-secrets",
        "bash",
        json!({ "command": "cat .env", "workdir": wallet.to_str().unwrap() }),
    );
    assert_eq!(label(&run), "deny", "{}", run.stdout);
}

#[test]
fn mcp_names_are_rebuilt_from_the_project_config() {
    let w = World::new("oc-mcp");
    std::fs::write(
        w.proj.join("opencode.jsonc"),
        r#"{
            // servers
            "mcp": {
                "helius": { "type": "remote", "url": "https://mcp.helius.dev" },
                "solana-dev": { "type": "local", "command": ["x"] }, // trailing comma
            },
        }"#,
    )
    .unwrap();
    let input = json!({ "destination": DEST, "lamports": 1_000_000_000u64 });
    let run = w.oc("gate-mcp", "helius_transferSol", input);
    assert_eq!(label(&run), "deny");
    let r = reason(&run);
    assert!(r.contains("transferSol"), "{r}");
    assert!(!r.contains("helius_transferSol"), "server split off: {r}");
    assert!(r.ends_with(SUFFIX), "{r}");
    let run = w.oc("gate-mcp", "helius_getBalance", json!({ "address": DEST }));
    assert_eq!(label(&run), "");
    let run = w.oc("gate-mcp", "solana-dev_search_docs", json!({ "q": "pda" }));
    assert_eq!(label(&run), "");
}

#[test]
fn unknown_and_ambiguous_mcp_names_are_gated_on_every_word() {
    let w = World::new("oc-mcp-unknown");
    // No config: the server is unknown, the whole name is judged.
    let run = w.oc(
        "gate-mcp",
        "phantom_signTransaction",
        json!({ "tx": "AAAA" }),
    );
    assert_eq!(label(&run), "deny", "{}", run.stdout);
    let input = json!({ "destination": DEST, "lamports": 1_000_000_000u64 });
    let run = w.oc("gate-mcp", "wallet_tools_transfer", input.clone());
    assert_eq!(label(&run), "deny");
    // Two configured servers prefix the name: ambiguous, still gated.
    let body = json!({
        "tool": "pay_ops_send", "sessionID": "s", "callID": "c", "args": input,
        "directory": w.proj.path(), "mcpServers": ["pay", "pay_ops"],
    });
    let run = w.run(&["adapt", "opencode", "gate-mcp"], body.to_string());
    assert_eq!(label(&run), "deny");
    // A plain read on an unknown server passes.
    let run = w.oc("gate-mcp", "docs_lookup", json!({ "q": "x" }));
    assert_eq!(label(&run), "");
}

#[test]
fn servers_from_the_plugin_payload_are_used() {
    let w = World::new("oc-mcp-payload");
    let body = json!({
        "tool": "helius_transferSol", "sessionID": "s", "callID": "c",
        "args": { "destination": DEST, "lamports": 1_000_000_000u64 },
        "directory": w.proj.path(), "mcpServers": ["helius"],
    });
    let run = w.run(&["adapt", "opencode", "gate-mcp"], body.to_string());
    assert_eq!(label(&run), "deny");
    assert!(
        !reason(&run).contains("helius_transferSol"),
        "{}",
        run.stdout
    );
}

#[test]
fn mcp_resource_reads_get_the_path_check() {
    let w = World::new("oc-mcp-res");
    std::fs::write(w.proj.join(".env"), "K=v").unwrap();
    let env = w.proj.join(".env");
    let run = w.oc(
        "gate-mcp",
        "read_mcp_resource",
        json!({ "server": "fs", "uri": env.to_str().unwrap() }),
    );
    assert_eq!(label(&run), "deny", "{}", run.stdout);
}

#[test]
fn unreadable_or_misrouted_payloads_deny() {
    let w = World::new("oc-malformed");
    for gate in safe_ai_skill::adapt_opencode::GATES {
        for body in ["{not json", "", "[]", r#"{"tool":"bash"}"#] {
            let run = w.run(&["adapt", "opencode", gate], body.to_string());
            assert_eq!(label(&run), "deny", "{gate} {body:?}");
        }
    }
    for (gate, tool, args) in [
        ("gate-mcp", "bash", json!({ "command": "ls" })),
        ("gate-bash", "read", json!({ "filePath": "x" })),
        ("gate-tamper", "bash", json!({ "command": "ls" })),
        (
            "gate-read",
            "write",
            json!({ "filePath": "x", "content": "" }),
        ),
        ("gate-bash", "bash", json!({ "cmd": "ls" })),
        ("gate-tamper", "apply_patch", json!({ "patch": "x" })),
    ] {
        let run = w.oc(gate, tool, args);
        assert_eq!(label(&run), "deny", "{gate} {tool}");
    }
}

#[test]
fn usage_errors_exit_3_with_no_output() {
    let w = World::new("oc-usage");
    let body = w.payload("bash", json!({ "command": "ls" }));
    for args in [
        &["adapt", "opencode"][..],
        &["adapt", "opencode", "gate-skill"],
        &["adapt", "opencode", "redact"],
        &["adapt", "opencode", "gate-nope"],
        &["adapt", "opencode", "gate-bash", "extra"],
    ] {
        let run = w.run(args, body.clone());
        assert_eq!(run.code, Some(3), "{args:?}");
        assert!(run.stdout.is_empty(), "{args:?}: {}", run.stdout);
    }
}

#[test]
fn oversized_patches_deny() {
    let w = World::new("oc-bigpatch");
    let headers: Vec<String> = (0..=safe_ai_skill::adapt::MAX_PATCH_PATHS)
        .map(|i| format!("*** Add File: src/f{i}.rs"))
        .collect();
    let refs: Vec<&str> = headers.iter().map(String::as_str).collect();
    let run = w.oc("gate-tamper", "apply_patch", patch(&refs));
    assert_eq!(label(&run), "deny");
}

#[cfg(feature = "test-hooks")]
#[test]
fn a_panic_still_denies_with_exit_0() {
    let w = World::new("oc-panic").with_env("SAFE_AI_SKILL_TEST_PANIC", "1");
    let run = w.oc("gate-bash", "bash", json!({ "command": "ls" }));
    assert_eq!(label(&run), "deny", "{}", run.stderr);
}
