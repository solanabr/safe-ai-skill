//! Shared helpers for the `safe-ai-skill` integration test suites.
//!
//! Every helper here is std-only (no dev-deps). The built binary path is provided by Cargo
//! through `env!("CARGO_BIN_EXE_safe-ai-skill")`, so the suites drive the real binary end-to-end:
//! write a hook JSON to stdin, capture stdout, parse the emitted decision.
//!
//! Each integration test binary (`gates`, `bootstrap_sandbox`, `verify_drift`) includes this
//! module and uses a different subset of helpers, so unused-helper warnings are expected and
//! suppressed crate-wide here.
#![allow(dead_code)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub use safe_ai_skill::policy::tier::{EnvRead, Tier};

/// Whether these tests (and the binary under test) were built with `--features test-hooks`,
/// which honours the trusted-data-dir and sandbox overrides [`Invocation`] sets.
pub const TEST_HOOKS: bool = cfg!(feature = "test-hooks");

/// Env vars that make a session headless (contract §3.3): cleared from every run unless
/// [`Invocation::headless`] asks for it.
const HEADLESS_VARS: [&str; 7] = [
    "SAFE_AI_SKILL_HEADLESS",
    "KIT_FIREWALL_HEADLESS",
    "CI",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "BUILDKITE",
    "JENKINS_URL",
];

/// The declared Claude Code sandbox for [`Invocation::sandbox`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxMode {
    /// `sandbox.enabled: true` (on a supported platform).
    On,
    /// `sandbox.enabled: false`.
    Off,
    /// Not declared anywhere.
    Unset,
}

/// Absolute path to the built `safe-ai-skill` binary (Cargo-provided).
pub fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_safe-ai-skill")
}

/// Monotonic-ish unique suffix for sandbox dir names (pid + counter + time).
fn unique() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}-{}-{}", std::process::id(), t, n)
}

/// A self-cleaning temporary directory under `$TMPDIR`.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Create a fresh, empty temp dir tagged with `tag`.
    pub fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!("safe-ai-skill-it-{tag}-{}", unique()));
        std::fs::create_dir_all(&path).expect("create temp dir");
        TempDir { path }
    }

    /// The directory path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Join a child path.
    pub fn join(&self, rel: impl AsRef<Path>) -> PathBuf {
        self.path.join(rel)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Output of a binary invocation.
pub struct Run {
    pub stdout: String,
    pub stderr: String,
    pub code: Option<i32>,
}

impl Run {
    /// Parse stdout as JSON (panics with context on failure — a test bug).
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(self.stdout.trim()).unwrap_or_else(|e| {
            panic!(
                "stdout was not valid JSON: {e}\n--- stdout ---\n{}\n--- stderr ---\n{}",
                self.stdout, self.stderr
            )
        })
    }
}

/// Builder for a sandboxed `safe-ai-skill` invocation.
///
/// Always sets `CLAUDE_PLUGIN_DATA` to an isolated dir so audit/spend/grants/lockfile writes
/// never touch the real plugin-data dir. Optionally overrides `HOME` and `SAFE_AI_SKILL_HOME`
/// and clears the tier, profile, headless and CI variables, `ANCHOR_PROVIDER_URL` and
/// `CLAUDE_PLUGIN_DATA` inheritance to keep the run hermetic (not headless by default).
///
/// Tier setup (D8 v2):
///
/// - [`Invocation::tier`] / [`Invocation::env_read`] write an authenticated `tier.json` `global`
///   entry in the plugin data dir (requires [`Invocation::plugin_data`]). With `test-hooks`
///   the binary trusts that dir, so any tier and `env_read` apply as the user's choice.
///   Without it the dir is untrusted: a tier at or above Relaxed is set through the raise-only
///   `SAFE_AI_SKILL_TIER` instead, and `Tier::Off` or `env_read: deny` panic (they need
///   `--features test-hooks`).
/// - [`Invocation::sandbox`] sets, with `test-hooks`, the engine's sandbox override; without it a
///   `<cwd>/.claude/settings.local.json` (requires [`Invocation::cwd`] = the payload cwd; on
///   Linux without a system `bwrap`, `On` reads as unknown).
/// - [`Invocation::kit_security`] writes `<cwd>/.claude/security.json` (requires `cwd`).
/// - [`Invocation::headless`] sets `SAFE_AI_SKILL_HEADLESS=1`.
pub struct Invocation<'a> {
    args: Vec<String>,
    stdin: Option<String>,
    plugin_data: Option<&'a Path>,
    home: Option<&'a Path>,
    cwd: Option<&'a Path>,
    extra_env: Vec<(String, String)>,
    tier: Option<Tier>,
    env_read: Option<EnvRead>,
    sandbox: Option<SandboxMode>,
    kit_security: Option<String>,
    headless: bool,
}

impl<'a> Invocation<'a> {
    /// Start an invocation for subcommand `args` (e.g. `["gate-bash"]`).
    pub fn new(args: &[&str]) -> Self {
        Invocation {
            args: args.iter().map(|s| s.to_string()).collect(),
            stdin: None,
            plugin_data: None,
            home: None,
            cwd: None,
            extra_env: Vec::new(),
            tier: None,
            env_read: None,
            sandbox: None,
            kit_security: None,
            headless: false,
        }
    }

    /// Select `tier` as the user's choice (see the type docs).
    pub fn tier(mut self, tier: Tier) -> Self {
        self.tier = Some(tier);
        self
    }

    /// Select `env_read` as the user's choice (see the type docs).
    pub fn env_read(mut self, env_read: EnvRead) -> Self {
        self.env_read = Some(env_read);
        self
    }

    /// Declare the Claude Code sandbox (see the type docs).
    pub fn sandbox(mut self, mode: SandboxMode) -> Self {
        self.sandbox = Some(mode);
        self
    }

    /// Write `json` as the kit's `<cwd>/.claude/security.json`.
    pub fn kit_security(mut self, json: impl Into<String>) -> Self {
        self.kit_security = Some(json.into());
        self
    }

    /// Run headless (`SAFE_AI_SKILL_HEADLESS=1`) or not (the default).
    pub fn headless(mut self, on: bool) -> Self {
        self.headless = on;
        self
    }

    /// Materialise the tier setup: files written, env pairs to set.
    fn tier_setup(&self) -> Vec<(String, String)> {
        let mut env = Vec::new();
        let user_choice = self.env_read.is_some() || self.tier.is_some();
        if user_choice && TEST_HOOKS {
            let data = self
                .plugin_data
                .expect(".tier/.env_read need .plugin_data(dir)");
            let dir = safe_ai_skill::datadir::DataDir {
                path: data.to_path_buf(),
                trusted: true,
            };
            let change = safe_ai_skill::tierstate::Change {
                project: None,
                tier: Some(self.tier.unwrap_or(Tier::Relaxed)),
                env_read: self.env_read,
                clear: false,
            };
            safe_ai_skill::tierstate::apply(&dir, &change, 0).expect("write tier.json");
            env.push((
                safe_ai_skill::datadir::TEST_TRUST_ENV.to_string(),
                "1".to_string(),
            ));
        } else if user_choice {
            match self.tier {
                Some(Tier::Off) => {
                    panic!("Tier::Off through the binary needs --features test-hooks")
                }
                Some(t) if t > Tier::Relaxed => {
                    env.push(("SAFE_AI_SKILL_TIER".into(), t.label().into()))
                }
                _ => {}
            }
            if self.env_read == Some(EnvRead::Deny) {
                panic!("env_read: deny through the binary needs --features test-hooks");
            }
        }
        if let Some(mode) = self.sandbox {
            if TEST_HOOKS {
                let word = match mode {
                    SandboxMode::On => "on",
                    SandboxMode::Off | SandboxMode::Unset => "off",
                };
                env.push((
                    safe_ai_skill::sandbox::TEST_OVERRIDE_ENV.to_string(),
                    word.to_string(),
                ));
            } else if mode != SandboxMode::Unset {
                let cwd = self.cwd.expect(".sandbox needs .cwd(project)");
                std::fs::create_dir_all(cwd.join(".claude")).expect("create .claude");
                let body = format!(r#"{{"sandbox":{{"enabled":{}}}}}"#, mode == SandboxMode::On);
                std::fs::write(cwd.join(".claude/settings.local.json"), body)
                    .expect("write settings.local.json");
            }
        }
        if let Some(json) = &self.kit_security {
            let cwd = self.cwd.expect(".kit_security needs .cwd(project)");
            std::fs::create_dir_all(cwd.join(".claude")).expect("create .claude");
            std::fs::write(cwd.join(".claude/security.json"), json).expect("write security.json");
        }
        if self.headless {
            env.push(("SAFE_AI_SKILL_HEADLESS".into(), "1".into()));
        }
        env
    }

    /// Feed `body` to the process stdin.
    pub fn stdin(mut self, body: impl Into<String>) -> Self {
        self.stdin = Some(body.into());
        self
    }

    /// Sandbox the plugin-data dir (audit/spend/grants/lockfile live here).
    pub fn plugin_data(mut self, dir: &'a Path) -> Self {
        self.plugin_data = Some(dir);
        self
    }

    /// Override `HOME` (so `~/...` expansions stay inside the sandbox).
    pub fn home(mut self, dir: &'a Path) -> Self {
        self.home = Some(dir);
        self
    }

    /// Set the process working directory (so `current_dir()`-relative resolution — the
    /// catalog `registry_path` and the `add` registry lookup — points at a fixture project).
    pub fn cwd(mut self, dir: &'a Path) -> Self {
        self.cwd = Some(dir);
        self
    }

    /// Set an extra env var.
    pub fn env(mut self, key: &str, val: &str) -> Self {
        self.extra_env.push((key.to_string(), val.to_string()));
        self
    }

    /// Run the binary and capture its output.
    pub fn run(self) -> Run {
        let mut cmd = Command::new(bin());
        cmd.args(&self.args);
        if let Some(dir) = self.cwd {
            cmd.current_dir(dir);
        }
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        // Hermetic env: clear inherited knobs that could perturb a decision.
        cmd.env_remove("SAFE_AI_SKILL_PROFILE");
        cmd.env_remove("SAFE_AI_SKILL_TIER");
        cmd.env_remove(safe_ai_skill::datadir::TEST_TRUST_ENV);
        cmd.env_remove(safe_ai_skill::sandbox::TEST_OVERRIDE_ENV);
        for var in HEADLESS_VARS {
            cmd.env_remove(var);
        }
        cmd.env_remove("ANCHOR_PROVIDER_URL");
        cmd.env_remove("SAFE_AI_SKILL_HOME");
        // The CLI resolves the hooks' data dir from these and HOME: never the real one.
        cmd.env_remove("CLAUDE_PLUGIN_DATA");
        cmd.env_remove("CLAUDE_CONFIG_DIR");
        cmd.env_remove("CLAUDE_CODE_VERSION");
        cmd.env_remove("CLAUDE_CODE_EXECPATH");
        // The developer's own Claude Code session must not bind or see test requests.
        cmd.env_remove("CLAUDE_CODE_SESSION_ID");

        if let Some(pd) = self.plugin_data {
            cmd.env("CLAUDE_PLUGIN_DATA", pd);
        }
        let home = match self.home {
            Some(home) => home.to_path_buf(),
            None => std::env::temp_dir().join("safe-ai-skill-it-no-home"),
        };
        cmd.env("HOME", &home);
        // Data-dir discovery uses the OS user-database home, not HOME; `CLAUDE_CONFIG_DIR`
        // replaces it, so point that at the fake home too (an explicit `.env` overrides).
        cmd.env("CLAUDE_CONFIG_DIR", home.join(".claude"));
        for (k, v) in self.tier_setup().iter().chain(&self.extra_env) {
            cmd.env(k, v);
        }

        let mut child = cmd.spawn().expect("spawn safe-ai-skill");
        if let Some(body) = &self.stdin {
            // The child may finish and close stdin before we drain the whole body;
            // a resulting BrokenPipe is benign (it already read what it needed).
            match child
                .stdin
                .take()
                .expect("stdin pipe")
                .write_all(body.as_bytes())
            {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
                Err(e) => panic!("write stdin: {e}"),
            }
        }
        let out = child.wait_with_output().expect("wait safe-ai-skill");
        let mut stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        if cfg!(windows) && self.args.len() >= 2 && self.args[..2] == ["verify", "session"] {
            stdout = without_windows_notice(&stdout);
        }
        Run {
            stdout,
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            code: out.status.code(),
        }
    }
}

/// The Windows scope notice every SessionStart carries on Windows (`platform.rs`).
const WINDOWS_NOTICE: &str = "safe-ai-skill on Windows: the shell gates cover the Bash tool \
                              (Git Bash) only; PowerShell tool calls are not gated.";

/// A `verify session` emit as it would read on unix: the Windows notice removed and, when it
/// was the only thing said to the model, the plain-default tier line it brought along too
/// (a clean default session is silent). Tests about the notice itself are unit tests.
pub fn without_windows_notice(stdout: &str) -> String {
    let Ok(mut v) = serde_json::from_str::<serde_json::Value>(stdout.trim()) else {
        return stdout.to_string();
    };
    let strip = |text: &str| -> String {
        text.lines()
            .filter(|l| *l != WINDOWS_NOTICE)
            .collect::<Vec<_>>()
            .join("\n")
    };
    let plain_default = |text: &str| {
        text.starts_with("safe-ai-skill tier: relaxed")
            && text.contains(" (default); sandbox: ")
            && !text.contains('\n')
    };
    let ctx = v["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .map(strip)
        .unwrap_or_default();
    let drop_tier = plain_default(&ctx);
    let fields: [&[&str]; 2] = [
        &["hookSpecificOutput", "additionalContext"],
        &["systemMessage"],
    ];
    for path in fields {
        let (parent, key) = match path {
            [k] => (&mut v, *k),
            [p, k] => (&mut v[*p], *k),
            _ => unreachable!(),
        };
        let Some(text) = parent.get(key).and_then(|t| t.as_str()).map(strip) else {
            continue;
        };
        let mut lines: Vec<&str> = text.lines().collect();
        if drop_tier && lines.first().is_some_and(|l| plain_default(l)) {
            lines.remove(0);
        }
        let text = lines.join("\n");
        let Some(map) = parent.as_object_mut() else {
            continue;
        };
        if text.is_empty() {
            map.remove(key);
        } else {
            map.insert(key.to_string(), serde_json::Value::String(text));
        }
    }
    let hso_left = v["hookSpecificOutput"]
        .as_object()
        .is_some_and(|m| m.keys().any(|k| k != "hookEventName"));
    if !hso_left {
        if let Some(map) = v.as_object_mut() {
            map.remove("hookSpecificOutput");
        }
    }
    if v.as_object().is_some_and(|m| m.is_empty()) {
        return String::new();
    }
    format!("{v}\n")
}

/// `p` as a Bash command spells it: `/`-separated (`C:/…` under Git Bash, where a backslash
/// is a shell escape). Unchanged on unix.
pub fn sh_path(p: &Path) -> String {
    p.to_str().expect("UTF-8 temp path").replace('\\', "/")
}

/// Extract `hookSpecificOutput.permissionDecision` from a PreToolUse emit.
pub fn permission_decision(v: &serde_json::Value) -> Option<String> {
    v.get("hookSpecificOutput")?
        .get("permissionDecision")?
        .as_str()
        .map(str::to_string)
}

/// The `permissionDecision` a PreToolUse gate run emitted, or `""` when it printed nothing
/// (no opinion: empty stdout, exit 0). Panics on a non-zero exit or on any other output.
pub fn decision_label(run: &Run) -> String {
    assert_eq!(
        run.code,
        Some(0),
        "gate exited {:?}\n--- stderr ---\n{}",
        run.code,
        run.stderr
    );
    if run.stdout.is_empty() {
        return String::new();
    }
    permission_decision(&run.json())
        .unwrap_or_else(|| panic!("no permissionDecision in {}", run.stdout))
}
