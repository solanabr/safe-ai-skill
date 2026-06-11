//! Shared helpers for the `ssai` integration test suites.
//!
//! Every helper here is std-only (no dev-deps). The built binary path is provided by Cargo
//! through `env!("CARGO_BIN_EXE_ssai")`, so the suites drive the real binary end-to-end:
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

/// Absolute path to the built `ssai` binary (Cargo-provided).
pub fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_ssai")
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
        let path = std::env::temp_dir().join(format!("ssai-it-{tag}-{}", unique()));
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

/// Builder for a sandboxed `ssai` invocation.
///
/// Always sets `CLAUDE_PLUGIN_DATA` to an isolated dir so audit/spend/grants/lockfile writes
/// never touch the real plugin-data dir. Optionally overrides `HOME` and `SAFE_SOLANA_AI_HOME`
/// and clears `SAFE_SOLANA_AI_PROFILE`/`ANCHOR_PROVIDER_URL`/`CLAUDE_PLUGIN_DATA` inheritance
/// to keep the run hermetic.
pub struct Invocation<'a> {
    args: Vec<String>,
    stdin: Option<String>,
    plugin_data: Option<&'a Path>,
    home: Option<&'a Path>,
    extra_env: Vec<(String, String)>,
}

impl<'a> Invocation<'a> {
    /// Start an invocation for subcommand `args` (e.g. `["gate-bash"]`).
    pub fn new(args: &[&str]) -> Self {
        Invocation {
            args: args.iter().map(|s| s.to_string()).collect(),
            stdin: None,
            plugin_data: None,
            home: None,
            extra_env: Vec::new(),
        }
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

    /// Set an extra env var.
    pub fn env(mut self, key: &str, val: &str) -> Self {
        self.extra_env.push((key.to_string(), val.to_string()));
        self
    }

    /// Run the binary and capture its output.
    pub fn run(self) -> Run {
        let mut cmd = Command::new(bin());
        cmd.args(&self.args);
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        // Hermetic env: clear inherited knobs that could perturb a decision.
        cmd.env_remove("SAFE_SOLANA_AI_PROFILE");
        cmd.env_remove("ANCHOR_PROVIDER_URL");
        cmd.env_remove("SAFE_SOLANA_AI_HOME");

        if let Some(pd) = self.plugin_data {
            cmd.env("CLAUDE_PLUGIN_DATA", pd);
        }
        if let Some(home) = self.home {
            cmd.env("HOME", home);
        }
        for (k, v) in &self.extra_env {
            cmd.env(k, v);
        }

        let mut child = cmd.spawn().expect("spawn ssai");
        if let Some(body) = &self.stdin {
            child
                .stdin
                .take()
                .expect("stdin pipe")
                .write_all(body.as_bytes())
                .expect("write stdin");
        }
        let out = child.wait_with_output().expect("wait ssai");
        Run {
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            code: out.status.code(),
        }
    }
}

/// Extract `hookSpecificOutput.permissionDecision` from a PreToolUse emit.
pub fn permission_decision(v: &serde_json::Value) -> Option<String> {
    v.get("hookSpecificOutput")?
        .get("permissionDecision")?
        .as_str()
        .map(str::to_string)
}
