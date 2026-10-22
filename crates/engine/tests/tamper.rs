//! End-to-end tests for the self-grant / state-tamper tripwire (spec D4.3).
//!
//! The tripwire has two entry points, both driven through the real binary:
//! - `gate-bash-secrets` (the unconditional Bash hook) denies a command that references
//!   safe-ai-skill state or runs the binary with a mutating subcommand;
//! - `gate-tamper` (the `Write|Edit|MultiEdit|NotebookEdit` hook) denies a write whose target is
//!   safe-ai-skill state.
//!
//! Every run is hermetic: `HOME`, `CLAUDE_PLUGIN_DATA`, `CLAUDE_PLUGIN_ROOT` and the session cwd
//! are fresh temp dirs.

mod common;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use common::{permission_decision, Invocation, Run};
use serde_json::{json, Value};

/// A self-cleaning temp dir. Unlike `common::TempDir` (`safe-ai-skill-it-…`), its name is not a
/// `safe-ai-skill-*` component, which the tripwire treats as a plugin data dir.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("tw-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        Scratch(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn join(&self, rel: impl AsRef<Path>) -> PathBuf {
        self.0.join(rel)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Isolated HOME, plugin data dir, plugin root and project dir for one test.
/// `$CLAUDE_CONFIG_DIR` is `<home>/cfg`, a second config dir besides `<home>/.claude`.
struct Sandbox {
    home: Scratch,
    /// `$CLAUDE_PLUGIN_DATA`, laid out as Claude Code does: `~/.claude/plugins/data/<plugin>-<mkt>`.
    data: PathBuf,
    root: Scratch,
    project: Scratch,
}

impl Sandbox {
    fn new(tag: &str) -> Self {
        let home = Scratch::new(&format!("{tag}-home"));
        let data = home.join(".claude/plugins/data/safe-ai-skill-stbr");
        std::fs::create_dir_all(&data).expect("create plugin data dir");
        Sandbox {
            home,
            data,
            root: Scratch::new(&format!("{tag}-root")),
            project: Scratch::new(&format!("{tag}-proj")),
        }
    }

    fn home(&self) -> String {
        self.home.path().display().to_string()
    }

    fn data(&self) -> String {
        self.data.display().to_string()
    }

    fn root(&self) -> String {
        self.root.path().display().to_string()
    }

    fn project(&self) -> String {
        self.project.path().display().to_string()
    }

    fn run(&self, sub: &str, tool: &str, tool_input: Value) -> Run {
        self.run_at(&self.project(), sub, tool, tool_input)
    }

    /// Run with the session (hook `cwd` and `$CLAUDE_PROJECT_DIR`) at `cwd`.
    fn run_at(&self, cwd: &str, sub: &str, tool: &str, tool_input: Value) -> Run {
        let payload = json!({
            "session_id": "it-tamper",
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": tool_input,
        });
        self.invoke(sub, payload.to_string(), cwd)
    }

    /// Run `sub` on a raw (possibly unreadable) stdin body.
    fn raw(&self, sub: &str, body: String) -> Run {
        self.invoke(sub, body, &self.project())
    }

    fn invoke(&self, sub: &str, body: String, project_dir: &str) -> Run {
        Invocation::new(&[sub])
            .plugin_data(&self.data)
            .home(self.home.path())
            .env("CLAUDE_PLUGIN_ROOT", &self.root())
            .env("CLAUDE_CONFIG_DIR", &format!("{}/cfg", self.home()))
            .env("CLAUDE_PROJECT_DIR", project_dir)
            .stdin(body)
            .run()
    }

    /// Run the unconditional Bash hook (`gate-bash-secrets`) on `command`.
    fn bash(&self, command: &str) -> Run {
        self.run("gate-bash-secrets", "Bash", json!({ "command": command }))
    }

    /// Run the file-tool tripwire (`gate-tamper`) for `tool` with `tool_input`.
    fn file(&self, tool: &str, tool_input: Value) -> Run {
        self.run("gate-tamper", tool, tool_input)
    }

    /// `Write` of `path` (content is irrelevant to the tripwire).
    fn write(&self, path: &str) -> Run {
        self.file("Write", json!({ "file_path": path, "content": "{}" }))
    }
}

/// The emitted decision, or `None` when the gate had no opinion. No opinion is empty stdout
/// only; an emitted `defer` is a verdict and fails any no-opinion assertion.
fn verdict(run: &Run) -> Option<String> {
    if run.stdout.is_empty() {
        return None;
    }
    let label = permission_decision(&run.json())
        .unwrap_or_else(|| panic!("no permissionDecision in {}", run.stdout));
    Some(label)
}

fn reason(run: &Run) -> String {
    run.json()["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

fn assert_deny(run: &Run, what: &str) {
    assert_eq!(
        verdict(run).as_deref(),
        Some("deny"),
        "expected deny for {what}\nstdout: {}\nstderr: {}",
        run.stdout,
        run.stderr
    );
}

fn assert_no_opinion(run: &Run, what: &str) {
    assert_eq!(
        verdict(run),
        None,
        "expected no opinion for {what}\nstdout: {}",
        run.stdout
    );
}

// ---------------------------------------------------------------------------------------
// Bash: binary + mutating subcommand
// ---------------------------------------------------------------------------------------

#[test]
fn bash_self_grant_denies() {
    let sb = Sandbox::new("tw-allow");
    let run = sb.bash("safe-ai-skill allow --scope transfer --for 24h");
    assert_deny(&run, "safe-ai-skill allow");
}

#[test]
fn bash_npx_scoped_package_allow_denies() {
    let sb = Sandbox::new("tw-npx");
    assert_deny(
        &sb.bash("npx @stbr/safe-ai-skill allow"),
        "npx @stbr/safe-ai-skill allow",
    );
}

#[test]
fn bash_env_prefixed_absolute_mode_denies() {
    let sb = Sandbox::new("tw-mode");
    assert_deny(
        &sb.bash("FOO=1 /x/safe-ai-skill mode autopilot"),
        "FOO=1 /x/safe-ai-skill mode autopilot",
    );
}

#[test]
fn bash_mutating_subcommands_deny() {
    let sb = Sandbox::new("tw-mut");
    for cmd in [
        "safe-ai-skill verify approve evil-skill",
        "safe-ai-skill verify trust evil-skill",
        "safe-ai-skill revoke",
        "safe-ai-skill confirm 1234-5678",
        "safe-ai-skill grant transfer",
        "bash -c 'safe-ai-skill allow --scope swap --for 1h'",
        "SAFE=1 env safe-ai-skill-darwin-arm64 mode autopilot",
        "npx -y @stbr/safe-ai-skill@1.0.1 'allow' --scope transfer",
        "python3 -c \"import subprocess; subprocess.run(['safe-ai-skill','allow','--scope','transfer'])\"",
        "node -e \"require('child_process').execSync('safe-ai-skill mode autopilot')\"",
        "cargo run -q -p safe-ai-skill -- allow --scope transfer --for 1h",
        "safe-ai-skill $(echo allow) --scope transfer",
        "Safe-AI-Skill ALLOW --scope transfer",
    ] {
        assert_deny(&sb.bash(cmd), cmd);
    }
}

#[test]
fn bash_install_and_hook_only_verify_deny() {
    // `install` re-pins drifted packs and bare `verify` / `verify session` TOFU-pin packs never
    // seen before: hook-only or user-terminal, never agent-run.
    let sb = Sandbox::new("tw-pin");
    for cmd in [
        "safe-ai-skill install",
        "safe-ai-skill install --yes",
        "safe-ai-skill install --from ./packs",
        "npx @stbr/safe-ai-skill install --from /tmp/p.tgz --home /tmp/h",
        "safe-ai-skill verify",
        "safe-ai-skill verify session",
        "safe-ai-skill verify $(echo session)",
        "echo hi && safe-ai-skill verify; ls",
        "$(which safe-ai-skill) verify session",
        "bash -c 'safe-ai-skill install'",
    ] {
        assert_deny(&sb.bash(cmd), cmd);
    }
}

#[test]
fn bash_env_subcommand_has_no_opinion() {
    // Placeholder for WS-C: the `env` subcommand is the sanctioned way to touch `.env`.
    let sb = Sandbox::new("tw-env");
    assert_no_opinion(
        &sb.bash("safe-ai-skill env keys .env"),
        "safe-ai-skill env keys .env",
    );
}

#[test]
fn bash_read_only_subcommands_have_no_opinion() {
    let sb = Sandbox::new("tw-ro");
    for cmd in [
        "safe-ai-skill status",
        "safe-ai-skill verify check ./skills/foo",
        "safe-ai-skill --version",
        "safe-ai-skill mode",
        "npx @stbr/safe-ai-skill status",
    ] {
        assert_no_opinion(&sb.bash(cmd), cmd);
    }
}

#[test]
fn bash_runs_plugin_binary_from_cache_path_read_only() {
    let sb = Sandbox::new("tw-cachebin");
    let bin = format!(
        "{}/.claude/plugins/cache/stbr/safe-ai-skill/1.0.1/bin/safe-ai-skill",
        sb.home()
    );
    assert_no_opinion(
        &sb.bash(&format!("{bin} env keys .env")),
        "cache binary env",
    );
    assert_no_opinion(
        &sb.bash(&format!("\"{bin}\" status")),
        "cache binary status",
    );
    assert_deny(&sb.bash(&format!("{bin} allow")), "cache binary allow");
}

// ---------------------------------------------------------------------------------------
// Bash: references to protected state
// ---------------------------------------------------------------------------------------

#[test]
fn bash_python_write_to_data_dir_denies() {
    let sb = Sandbox::new("tw-py");
    let cmd = format!(
        "python3 -c \"open('{}/.claude/plugins/data/safe-ai-skill-stbr/grants.json','w')\"",
        sb.home()
    );
    assert_deny(&sb.bash(&cmd), &cmd);
}

#[test]
fn bash_python_write_to_custom_plugin_data_denies() {
    let sb = Sandbox::new("tw-pydata");
    let cmd = format!(
        "python3 -c \"import json; json.dump({{}}, open('{}/grants.json','w'))\"",
        sb.data()
    );
    assert_deny(&sb.bash(&cmd), &cmd);
}

#[test]
fn bash_state_references_deny() {
    let sb = Sandbox::new("tw-paths");
    let home = sb.home();
    let root = sb.root();
    for cmd in [
        "cat \"$HOME/.Safe-AI-Skill/grants.json\"".to_string(),
        "echo '{}' > \"${HOME}\"/.claude/plugins/data/safe-ai-skill-stbr/mode.json".to_string(),
        "rm -f $CLAUDE_PLUGIN_DATA/spend.json".to_string(),
        "rm ~/.safe-ai-skill/lockfile.json".to_string(),
        "cp evil.json .safe-ai-skill/grants.json".to_string(),
        "cd .safe-ai-skill && echo '{}' > netcache.json".to_string(),
        "ln -s /tmp/x ~/.claude/plugins/data/safe-ai-skill-stbr".to_string(),
        format!("tail {home}/.claude/plugins/data/safe-ai-skill-stbr/audit.jsonl"),
        format!("cat {home}/.claude/plugins/data/x/../safe-ai-skill-stbr/grants.json"),
        "sed -i '' s/x/y/ ~/.claude/plugins/cache/stbr/safe-ai-skill/1.0.1/hooks/hooks.json"
            .to_string(),
        format!(
            "cp /tmp/evil {home}/.claude/plugins/cache/stbr/safe-ai-skill/1.0.1/bin/safe-ai-skill"
        ),
        format!("echo '{{}}' > {root}/hooks/hooks.json"),
    ] {
        assert_deny(&sb.bash(&cmd), &cmd);
    }
}

#[test]
fn bash_relative_and_glob_data_dir_paths_deny() {
    let sb = Sandbox::new("tw-reldata");
    for cmd in [
        "cd ~/.claude/plugins/data && echo '{\"profile\":\"autopilot\"}' > safe-ai-skill-stbr/mode.json",
        "cd ~/.claude/plugins/data && rm -rf safe-ai-skill-*",
        "cd ~/.claude/plugins && rm -rf data/safe-ai-skill-stbr",
        "ln -s ~/.claude/plugins/data /tmp/d && echo '{}' > /tmp/d/safe-ai-skill-stbr/mode.json",
        "rm -rf ~/.claude/plugins/data/*-stbr",
        "cat ~/.claude/plugins/data/*stbr/grants.json",
        "cat ~/.claude/plugins/d*/safe-ai-skill-stbr/grants.json",
        "echo x > ~/.claude/plugins/data/[s]afe-ai-skill-stbr/mode.json",
        "rm -rf ~/.[s]afe-ai-skill",
        "ls ~someone/.safe-ai-skill",
        "python3 -c \"import os; open(os.environ['CLAUDE_PLUGIN_DATA'] + '/grants.json', 'w')\"",
    ] {
        assert_deny(&sb.bash(cmd), cmd);
    }
}

#[test]
fn bash_computed_or_split_binary_with_mutating_subcommand_denies() {
    let sb = Sandbox::new("tw-computed");
    for cmd in [
        "safe-ai-\\\nskill allow",
        "safe-ai-skill al\\\nlow",
        "$(which safe-ai-skill) allow",
        "\"$(command -v safe-ai-skill)\" mode autopilot",
        "$(find / -name safe-ai-skill -type f | head -1) allow",
        "safe-ai-skill${IFS}allow",
    ] {
        assert_deny(&sb.bash(cmd), cmd);
    }
}

#[test]
fn bash_cd_into_data_dir_then_glob_or_brace_denies() {
    let sb = Sandbox::new("tw-cdglob");
    for cmd in [
        "cd ~/.claude/plugins/data && rm -rf saf*stbr",
        "cd ~/.claude/plugins/data && rm -rf *-skill-stbr",
        "cd ~/.claude/plugins/data && rm -rf sa*",
        "cd ~/.claude/plugins/data && rm -rf ./*",
        "cd ~/.claude/plugins/data && rm -rf safe-ai-skill-{stbr,x}",
        "cd ~/.claude/plugins/data && rm -rf safe-ai-skill-st{b,}r",
        "cd ~/.claude/plugins && cd data && cat */grants.json",
    ] {
        assert_deny(&sb.bash(cmd), cmd);
    }
    for cmd in [
        "cd ~/.claude/plugins/data && ls",
        "cd ~/.claude/plugins && ls -la",
    ] {
        assert_no_opinion(&sb.bash(cmd), cmd);
    }
}

#[test]
fn checkout_named_like_the_plugin_has_no_opinion() {
    let sb = Sandbox::new("tw-fork");
    let fork = sb.project.join("safe-ai-skill-fork");
    std::fs::create_dir_all(fork.join("src")).expect("create checkout");
    let fork = fork.display().to_string();
    for cmd in [
        format!("cd {fork} && cargo test"),
        "git clone https://github.com/solanabr/safe-ai-skill safe-ai-skill-dev".to_string(),
        "ls safe-ai-skill-dev/src && cat safe-ai-skill-v2/Cargo.toml".to_string(),
    ] {
        assert_no_opinion(&sb.bash(&cmd), &cmd);
    }
    // Inside the checkout: the hook cwd and $CLAUDE_PROJECT_DIR are the checkout.
    let bash = sb.run_at(
        &fork,
        "gate-bash-secrets",
        "Bash",
        json!({ "command": format!("cargo test && cat {fork}/README.md") }),
    );
    assert_no_opinion(&bash, "bash inside the checkout");
    for path in ["src/main.rs".to_string(), format!("{fork}/src/main.rs")] {
        let run = sb.run_at(
            &fork,
            "gate-tamper",
            "Write",
            json!({ "file_path": path, "content": "fn main() {}" }),
        );
        assert_no_opinion(&run, &path);
    }
}

#[test]
fn project_root_named_like_the_live_data_dir_has_no_opinion() {
    // A checkout named exactly like the live data dir (`safe-ai-skill-stbr`): its own components
    // never count, but the same name elsewhere on an absolute path still does.
    let sb = Sandbox::new("tw-root");
    let checkout = sb.project.join("safe-ai-skill-stbr");
    std::fs::create_dir_all(checkout.join("src")).expect("create checkout");
    let checkout = checkout.display().to_string();
    let bash = sb.run_at(
        &checkout,
        "gate-bash-secrets",
        "Bash",
        json!({ "command": format!("cat {checkout}/README.md") }),
    );
    assert_no_opinion(&bash, "bash in the project root");
    let write = sb.run_at(
        &checkout,
        "gate-tamper",
        "Write",
        json!({ "file_path": format!("{checkout}/src/main.rs"), "content": "" }),
    );
    assert_no_opinion(&write, "write in the project root");
    let cmd =
        "ln -s ~/.claude/plugins/data /tmp/d && echo '{}' > /tmp/d/safe-ai-skill-stbr/mode.json";
    assert_deny(&sb.bash(cmd), cmd);
}

#[test]
fn bash_brace_alternatives_deny() {
    let sb = Sandbox::new("tw-brace");
    for cmd in [
        "echo x > ~/.claude/plugins/{data,}/safe-ai-skill-stbr/mode.json",
        "echo x > ~/.claude/plugins/da{t,}a/safe-ai-skill-stbr/mode.json",
        "echo x > ~/.claude/{plugins,x}/data/safe-ai-skill-stbr/mode.json",
        "ls /tmp/{d,e}/safe-ai-skill-stbr/x",
    ] {
        assert_deny(&sb.bash(cmd), cmd);
    }
    for cmd in [
        "mkdir -p src/{bin,lib} && cp main.{rs,bak}",
        "find . -name x -exec grep -l y {} +",
    ] {
        assert_no_opinion(&sb.bash(cmd), cmd);
    }
}

#[test]
fn bash_dir_tools_and_tracked_dirs_deny() {
    let sb = Sandbox::new("tw-tracked");
    for cmd in [
        "env -C ~/.claude/plugins/data rm -rf sa*",
        "git -C ~/.claude/plugins/data clean -fdx -- *-stbr",
        "cd ~/.claude/plugins && rm -rf data/*",
        "cd ~/.claude && rm -rf plugins/data/safe-ai-skill-stbr",
    ] {
        assert_deny(&sb.bash(cmd), cmd);
    }
    // A session sitting in the data dir: bare file names are inside it.
    let data = sb.data();
    let run = |cmd: &str| {
        sb.run_at(
            &data,
            "gate-bash-secrets",
            "Bash",
            json!({ "command": cmd }),
        )
    };
    assert_deny(
        &run("echo x > grants.json"),
        "echo x > grants.json in the data dir",
    );
    assert_no_opinion(&run("ls -la"), "ls -la in the data dir");
}

#[test]
fn bash_near_misses_have_no_opinion() {
    // A glob inside another plugin's cache dir, `.safe-ai-skill` named without a `cd` into it, a
    // glob that cannot reach a dotfile, a read-only computed binary, and a release tag name.
    let sb = Sandbox::new("tw-near");
    for cmd in [
        "ls ~/.claude/plugins/cache/stbr/ai-kit/1.0.0/skills/*",
        "cat .safe-ai-skill/policy.yaml src/state.json",
        "ls ~/*",
        "$(which safe-ai-skill) status",
        "git tag safe-ai-skill--v1.0.1",
    ] {
        assert_no_opinion(&sb.bash(cmd), cmd);
    }
}

#[test]
fn bash_unrelated_commands_have_no_opinion() {
    let sb = Sandbox::new("tw-benign");
    for cmd in [
        "cargo test",
        "grep -rn grants.json crates/engine/src",
        "cat .safe-ai-skill/policy.yaml",
        "mkdir -p .safe-ai-skill",
        "ls ~/.claude/plugins/data",
        "git log -- plugins/safe-ai-skill/bin/safe-ai-skill",
        "git clone https://github.com/solanabr/safe-ai-skill",
    ] {
        assert_no_opinion(&sb.bash(cmd), cmd);
    }
}

#[test]
fn deny_reason_tells_model_the_user_must_run_it() {
    let sb = Sandbox::new("tw-reason");
    let grant = sb.bash("safe-ai-skill allow --scope transfer --for 24h");
    let write = sb.write(&format!("{}/.safe-ai-skill/grants.json", sb.home()));
    for run in [grant, write] {
        assert_deny(&run, "reason probe");
        let reason = reason(&run);
        assert!(
            reason.contains("user") && reason.contains("themselves"),
            "reason must tell the model the user has to run it: {reason}"
        );
    }
}

// ---------------------------------------------------------------------------------------
// Write|Edit|MultiEdit|NotebookEdit (gate-tamper)
// ---------------------------------------------------------------------------------------

#[test]
fn write_data_dir_grants_denies() {
    let sb = Sandbox::new("tw-write");
    let path = format!(
        "{}/.claude/plugins/data/safe-ai-skill-stbr/grants.json",
        sb.home()
    );
    assert_deny(&sb.write(&path), &path);
    assert_deny(
        &sb.write("~/.claude/plugins/data/safe-ai-skill-stbr/grants.json"),
        "tilde data dir",
    );
}

#[test]
fn file_tools_on_protected_state_deny() {
    let sb = Sandbox::new("tw-files");
    let home = sb.home();
    let cases = [
        (
            "Edit",
            json!({ "file_path": format!("{home}/.safe-ai-skill/mode.json"), "old_string": "a", "new_string": "b" }),
        ),
        (
            "MultiEdit",
            json!({ "file_path": format!("{}/.safe-ai-skill/spend.json", sb.project()), "edits": [] }),
        ),
        (
            "NotebookEdit",
            json!({ "notebook_path": format!("{}/x.ipynb", sb.data()), "new_source": "" }),
        ),
        (
            "Write",
            json!({ "file_path": format!("{}/hooks/hooks.json", sb.root()), "content": "{}" }),
        ),
        (
            "Write",
            json!({ "file_path": format!("{home}/.claude/plugins/cache/stbr/safe-ai-skill/1.0.1/policy/default.policy.yaml"), "content": "" }),
        ),
        (
            "Write",
            json!({ "file_path": format!("{}/.safe-ai-skill/audit.jsonl", sb.project()), "content": "" }),
        ),
        (
            "Write",
            json!({ "file_path": format!("{home}/.Claude/Plugins/Data/Safe-AI-Skill-stbr/Grants.json"), "content": "" }),
        ),
        (
            "Write",
            json!({ "file_path": "C:\\Users\\u\\.claude\\plugins\\data\\safe-ai-skill-stbr\\grants.json", "content": "" }),
        ),
        (
            "Write",
            json!({ "file_path": format!("{home}/.claude/plugins/data/x/../safe-ai-skill-stbr/mode.json"), "content": "" }),
        ),
    ];
    for (tool, input) in cases {
        let what = format!("{tool} {input}");
        assert_deny(&sb.file(tool, input), &what);
    }
}

#[test]
fn project_policy_and_ordinary_files_have_no_opinion() {
    let sb = Sandbox::new("tw-okfiles");
    for path in [
        format!("{}/.safe-ai-skill/policy.yaml", sb.project()),
        format!("{}/src/main.rs", sb.project()),
        format!("{}/README.md", sb.root()),
    ] {
        assert_no_opinion(&sb.write(&path), &path);
    }
}

#[cfg(unix)]
#[test]
fn write_through_symlink_into_data_dir_denies() {
    let sb = Sandbox::new("tw-link");
    let target = sb.home.join(".claude/plugins/data/safe-ai-skill-stbr");
    std::fs::create_dir_all(&target).unwrap();
    std::os::unix::fs::symlink(&target, sb.project.join("state")).unwrap();
    let path = format!("{}/state/grants.json", sb.project());
    assert_deny(&sb.write(&path), &path);
}

#[test]
fn every_installed_data_dir_name_is_protected() {
    // `safe-ai-skill-safe-ai-skill` after the marketplace rename, `safe-ai-skill-stbr` for
    // ai-kit users, and either under `$CLAUDE_CONFIG_DIR` instead of `~/.claude`.
    let sb = Sandbox::new("tw-names");
    let home = sb.home();
    for cmd in [
        "cat ~/.claude/plugins/data/safe-ai-skill-safe-ai-skill/grants.json".to_string(),
        "cat ~/.claude/plugins/data/safe-ai-skill-stbr/grants.json".to_string(),
        "echo {} > $CLAUDE_CONFIG_DIR/plugins/data/safe-ai-skill-stbr/mode.json".to_string(),
        "rm \"${CLAUDE_CONFIG_DIR}\"/plugins/data/safe-ai-skill-safe-ai-skill/spend.json"
            .to_string(),
        "rm -rf ~/.claude/plugins/data/safe-ai-skill-*".to_string(),
        format!("cp x {home}/cfg/plugins/data/safe-ai-skill-safe-ai-skill/lockfile.json"),
        "sed -i s/a/b/ ~/.claude/plugins/cache/safe-ai-skill/safe-ai-skill/1.1.0/hooks/hooks.json"
            .to_string(),
    ] {
        assert_deny(&sb.bash(&cmd), &cmd);
    }
    for path in [
        format!("{home}/.claude/plugins/data/safe-ai-skill-safe-ai-skill/grants.json"),
        format!("{home}/cfg/plugins/data/safe-ai-skill-stbr/mode.json"),
        format!("{home}/.claude/plugins/cache/safe-ai-skill/safe-ai-skill/1.1.0/hooks/hooks.json"),
    ] {
        assert_deny(&sb.write(&path), &path);
    }
}

#[test]
fn unreadable_payload_asks() {
    let sb = Sandbox::new("tw-unread");
    let deep = format!(
        r#"{{"tool_name":"Write","tool_input":{{"file_path":{}"x"{}}}}}"#,
        "[".repeat(200),
        "]".repeat(200)
    );
    let oversized = json!({
        "tool_name": "Write",
        "cwd": sb.project(),
        "tool_input": {
            "file_path": format!("{}/big.json", sb.project()),
            "content": "x".repeat(1 << 20),
        },
    })
    .to_string();
    for (what, body) in [
        (
            "malformed",
            r#"{"tool_name":"Write","tool_input":{"file_path":"#.to_string(),
        ),
        (
            "lone surrogate",
            r#"{"tool_name":"Write","tool_input":{"file_path":"/p/\ud800x"}}"#.to_string(),
        ),
        (
            "wrong field type",
            json!({ "tool_name": "Write", "cwd": 5, "tool_input": { "file_path": "/p/x" } })
                .to_string(),
        ),
        ("nested too deep", deep),
        ("oversized", oversized),
    ] {
        let run = sb.raw("gate-tamper", body);
        assert_eq!(
            verdict(&run).as_deref(),
            Some("ask"),
            "{what}: {}",
            run.stdout
        );
    }
    let audit = std::fs::read_to_string(sb.data.join("audit.jsonl")).expect("audit.jsonl");
    assert!(
        audit.contains("\"unreadable\""),
        "unreadable asks are audited as unreadable: {audit}"
    );
}

#[test]
fn empty_payload_has_no_opinion() {
    let sb = Sandbox::new("tw-empty");
    assert_no_opinion(&sb.raw("gate-tamper", String::new()), "empty stdin");
    assert_no_opinion(&sb.raw("gate-tamper", " \n".to_string()), "blank stdin");
}

#[test]
fn tamper_deny_is_audited() {
    let sb = Sandbox::new("tw-audit");
    let run = sb.write(&format!("{}/.safe-ai-skill/grants.json", sb.home()));
    assert_deny(&run, "audit probe");
    let audit = std::fs::read_to_string(sb.data.join("audit.jsonl")).expect("audit.jsonl");
    assert!(
        audit.contains("\"tamper\"") && audit.contains("deny"),
        "tamper deny not audited: {audit}"
    );
}

// ---------------------------------------------------------------------------------------
// Hook wiring
// ---------------------------------------------------------------------------------------

#[test]
fn hooks_json_wires_tamper_gate_for_file_tools() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../plugins/safe-ai-skill/hooks/hooks.json");
    let hooks: Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("read hooks.json"))
            .expect("hooks.json is JSON");
    let entry = hooks["hooks"]["PreToolUse"]
        .as_array()
        .expect("PreToolUse array")
        .iter()
        .find(|e| e["matcher"] == "Write|Edit|MultiEdit|NotebookEdit")
        .expect("Write|Edit|MultiEdit|NotebookEdit matcher");
    let hook = &entry["hooks"][0];
    assert!(
        hook["command"]
            .as_str()
            .unwrap_or("")
            .ends_with("/bin/safe-ai-skill gate-tamper"),
        "{hook}"
    );
    assert_eq!(hook["timeout"], 10, "{hook}");
    assert_eq!(hook["onFailure"], "continue", "{hook}");
    assert!(
        hook.get("if").is_none(),
        "tripwire must be unconditional: {hook}"
    );
}

// ---------------------------------------------------------------------------------------
// Adversarial inputs: the hook must answer, quickly, and never fail open
// ---------------------------------------------------------------------------------------

/// The Bash hook's verdict on `command` and how long the process took.
fn timed_bash(sb: &Sandbox, command: &str) -> (Run, std::time::Duration) {
    let start = std::time::Instant::now();
    let run = sb.bash(command);
    (run, start.elapsed())
}

/// Well under the 10 s hook timeout, loose enough for a debug build on a busy CI runner: the
/// work budget's 2 s deadline is what keeps the hook inside it.
const HOOK_DEADLINE: std::time::Duration = std::time::Duration::from_secs(8);

/// `command` must be answered with one of `allowed` (`None` = no opinion), exit 0, in time.
fn assert_answers(sb: &Sandbox, what: &str, command: &str, allowed: &[Option<&str>]) {
    let (run, took) = timed_bash(sb, command);
    assert_eq!(run.code, Some(0), "{what}: crashed\nstderr: {}", run.stderr);
    let got = verdict(&run);
    assert!(
        allowed.contains(&got.as_deref()),
        "{what}: got {got:?}, want one of {allowed:?}\nstderr: {}",
        run.stderr
    );
    assert!(took < HOOK_DEADLINE, "{what}: took {took:?}");
}

const SECRET_READ: &str = "; cat ~/.config/solana/id.json";

#[test]
fn huge_brace_sequences_never_fail_open() {
    // 40k+ brace groups in one word used to recurse once per group and abort on a stack
    // overflow: empty stdout, so both the tripwire and the secret-read guard were skipped.
    let sb = Sandbox::new("tw-braces");
    for (what, word) in [
        ("{a,b} x40k", "{a,b}".repeat(40_000)),
        ("{a..b} x60k", "{a..b}".repeat(60_000)),
        ("{,} x60k", "{,}".repeat(60_000)),
    ] {
        let deny_or_ask = [Some("deny"), Some("ask")];
        assert_answers(
            &sb,
            what,
            &format!("echo {word}{SECRET_READ}"),
            &deny_or_ask,
        );
        assert_answers(
            &sb,
            what,
            &format!("echo {word} > ~/.claude/plugins/data/safe-ai-skill-stbr/mode.json"),
            &deny_or_ask,
        );
        assert_answers(&sb, what, &format!("echo {word}"), &[None, Some("ask")]);
    }
}

#[test]
fn unclosed_braces_are_linear() {
    // Each unclosed `{` used to rescan the rest of the word: 120 KB took 13.5 s.
    let sb = Sandbox::new("tw-unclosed");
    let word = "{a,".repeat(40_000);
    assert_answers(
        &sb,
        "unclosed {a,",
        &format!("echo {word}{SECRET_READ}"),
        &[Some("deny"), Some("ask")],
    );
    let nested = format!("{}b{}", "{a,".repeat(40_000), "}".repeat(40_000));
    assert_answers(
        &sb,
        "nested {a,{a,…}}",
        &format!("echo {nested}{SECRET_READ}"),
        &[Some("deny"), Some("ask")],
    );
}

#[test]
fn work_budget_exhaustion_asks() {
    // A chain of relative `cd`s just under the 1 MiB stdin cap (so the payload is read, not
    // refused as oversized) is more than the tripwire will inspect: it must ask (a hard
    // guard), never answer with no opinion.
    let sb = Sandbox::new("tw-budget");
    let chain = "cd x && ".repeat(((1 << 20) - 4096) / 8);
    let (run, took) = timed_bash(&sb, &chain);
    assert_eq!(verdict(&run).as_deref(), Some("ask"), "{}", run.stderr);
    assert!(
        reason(&run).contains("too complex to inspect"),
        "{}",
        reason(&run)
    );
    assert!(took < HOOK_DEADLINE, "took {took:?}");
    assert_answers(
        &sb,
        "cd chain + secret read",
        &format!("{chain}true{SECRET_READ}"),
        &[Some("deny"), Some("ask")],
    );
}

#[test]
fn megabyte_of_ordinary_words_answers_in_time() {
    let sb = Sandbox::new("tw-mib");
    let mib = 1 << 20;
    for (what, command) in [
        ("{a,b} words", format!("echo {}", "{a,b} ".repeat(mib / 6))),
        ("glob words", format!("ls {}", "src/*.rs ".repeat(mib / 9))),
        ("glob chars", format!("echo {}", "*?[".repeat(mib / 3))),
        ("$HOME words", format!("echo {}*", "$HOME".repeat(mib / 5))),
        ("-C flags", format!("env {}", "-C ".repeat(mib / 3))),
        ("${IFS runs", format!("echo {}", "${IFS".repeat(mib / 5))),
    ] {
        assert_answers(&sb, what, &command, &[None, Some("ask")]);
    }
}

// ---------------------------------------------------------------------------------------
// The `plugins/data` rule is anchored to Claude Code's config dir
// ---------------------------------------------------------------------------------------

#[test]
fn project_plugins_data_dir_has_no_opinion() {
    let sb = Sandbox::new("tw-projdata");
    std::fs::create_dir_all(sb.project.join("src/plugins/data")).unwrap();
    for cmd in [
        "cd src/plugins/data && rm -f *.tmp",
        "rm -rf src/plugins/data/*",
        "rm -rf ./src/plugins/data/safe-ai-skill-x",
    ] {
        assert_no_opinion(&sb.bash(cmd), cmd);
    }
    let home = sb.home();
    for cmd in [
        "cd ~/.claude/plugins/data && rm -f *.tmp".to_string(),
        "rm -rf ~/.claude/plugins/data/*".to_string(),
        format!("cd {home}/.claude && rm -rf plugins/data/*"),
    ] {
        assert_deny(&sb.bash(&cmd), &cmd);
    }
}

#[test]
fn custom_config_dir_plugins_data_is_protected() {
    let sb = Sandbox::new("tw-cfgdir");
    let home = sb.home();
    let cfg = format!("{home}/cfg");
    for cmd in [
        format!("rm -rf {cfg}/plugins/data/*"),
        format!("cd {cfg}/plugins/data && rm -rf sa*"),
        format!("cp x {cfg}/plugins/data/safe-ai-skill-safe-ai-skill/lockfile.json"),
    ] {
        assert_deny(&sb.bash(&cmd), &cmd);
    }
    for cmd in [
        format!("rm -rf {home}/other/plugins/data/*"),
        format!("cd {home}/other/plugins/data && rm -rf *.tmp"),
    ] {
        assert_no_opinion(&sb.bash(&cmd), &cmd);
    }
}
