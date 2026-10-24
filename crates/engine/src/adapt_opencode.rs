//! opencode adapter (experimental, issue #26): `safe-ai-skill adapt opencode <gate>`.
//!
//! The plugin in `adapters/opencode/` calls this from opencode's `tool.execute.before` hook
//! with `{tool, sessionID, callID, args, directory, worktree, mcpServers}` on stdin. Field
//! names follow `anomalyco/opencode@v1.19.4` (`packages/plugin/src/index.ts`, `src/tool/*.ts`).
//!
//! - **Input.** [`prepare`] turns that into the Claude-shaped payload the gates read: tool
//!   ids `bash`/`read`/`grep`/`glob`/`write`/`edit`/`apply_patch` become `Bash`/`Read`/…,
//!   camelCase args (`filePath`, `oldString`, `patchText`, `include`) become the Claude fields,
//!   a `workdir` becomes the cwd, and an MCP tool `<server>_<tool>` becomes
//!   `mcp__<server>__<tool>` when exactly one configured server name is its prefix
//!   ([`mcp_tool_name`]); otherwise the whole name stands in for both parts, so every check
//!   sees every word of it.
//! - **Output.** [`render`]: `ask` becomes `deny` (with [`ASK_SUFFIX`]), `allow` becomes no
//!   output. The plugin throws on a deny. A Grep rewrite is printed as `updatedInput` holding
//!   opencode args ([`grep_rewrite`]), which the plugin copies into the call's `args`.
//! - **What guards the guard.** opencode loads every file in `.opencode/` and its config dirs
//!   as plugins, tools or config, with no trust check, so a write there could replace or
//!   outrun the plugin. [`Targets`] names those places and the engine binary;
//!   [`Targets::path_reason`] and [`Targets::bash_reason`] deny writes to them.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde_json::{json, Map, Value};

use crate::adapt::{absolute, canonical_prefix, lexical};
use crate::io::Decision;

/// The gates `adapt opencode` runs.
pub const GATES: [&str; 5] = [
    "gate-bash",
    "gate-bash-secrets",
    "gate-read",
    "gate-tamper",
    "gate-mcp",
];

/// Appended to an `ask` reason when opencode gets it as a `deny`.
pub const ASK_SUFFIX: &str = "opencode plugins cannot ask for approval, so safe-ai-skill \
     blocked it: run it yourself, approve it in a Claude Code session, or confirm a grant there \
     first where one applies.";

/// opencode's built-in tools that no gate reads. Any other tool id goes to `gate-mcp`.
pub const UNGATED: &[&str] = &[
    "task",
    "todowrite",
    "todoread",
    "question",
    "webfetch",
    "websearch",
    "plan_exit",
    "plan_enter",
    "invalid",
    "skill",
    "lsp",
    "execute",
    "list_mcp_resources",
    "list_mcp_resource_templates",
];

/// Largest opencode config file read for MCP server names.
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// Translate a decision for opencode: an `ask` becomes a `deny` (minus any "approve to
/// proceed" tail, plus [`ASK_SUFFIX`]) and an `allow` becomes no opinion.
pub fn render(decision: &Decision) -> Decision {
    match decision {
        Decision::Ask { reason } => {
            let base = reason
                .trim_end()
                .trim_end_matches("— approve to proceed")
                .trim_end_matches(|c: char| c.is_whitespace() || c == '.' || c == '—');
            Decision::Deny {
                reason: format!("{base}. {ASK_SUFFIX}"),
            }
        }
        Decision::Allow => Decision::Defer,
        other => other.clone(),
    }
}

/// What `adapt opencode` does with a payload.
#[derive(Debug)]
pub enum Prepared {
    /// Run the gate on this Claude-shaped payload.
    Gate(Vec<u8>),
    /// Deny without running the gate (a write to a [`Targets`] location); the payload is the
    /// translated one, for the audit.
    Deny { reason: String, payload: Vec<u8> },
    /// The payload cannot be read, or names a tool this gate does not handle.
    Malformed(String),
}

/// The opencode args of the call being judged, kept for [`grep_rewrite`].
static ORIGINAL_ARGS: OnceLock<Map<String, Value>> = OnceLock::new();

/// Translate the plugin's payload for `gate` ([`GATES`]) and apply the opencode
/// self-protection ([`Targets`]).
pub fn prepare(gate: &str, raw: &[u8]) -> Prepared {
    let payload: Value = match serde_json::from_slice(raw) {
        Ok(v) => v,
        Err(_) => return Prepared::Malformed("the payload is not JSON".into()),
    };
    let text = |k: &str| payload.get(k).and_then(Value::as_str);
    let Some(tool) = text("tool").filter(|t| !t.is_empty()) else {
        return Prepared::Malformed("the payload names no tool".into());
    };
    let Some(args) = payload.get("args").and_then(Value::as_object) else {
        return Prepared::Malformed(format!("`{tool}` has no args object"));
    };
    let _ = ORIGINAL_ARGS.set(args.clone());
    let directory = text("directory")
        .filter(|d| Path::new(d).is_absolute())
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let arg = |k: &str| args.get(k).and_then(Value::as_str);
    let mut cwd = directory.clone();
    let (tool_name, tool_input) = match (gate, tool) {
        ("gate-bash" | "gate-bash-secrets", "bash") => {
            let Some(command) = arg("command") else {
                return Prepared::Malformed("`bash` has no command".into());
            };
            if let Some(w) = arg("workdir").filter(|w| !w.is_empty()) {
                cwd = lexical(&directory.join(w));
            }
            ("Bash".to_string(), json!({ "command": command }))
        }
        ("gate-read", "read") => ("Read".into(), json!({ "file_path": arg("filePath") })),
        ("gate-read", "glob") => (
            "Glob".into(),
            json!({ "pattern": arg("pattern"), "path": arg("path") }),
        ),
        ("gate-read", "grep") => {
            let mut input = Map::new();
            input.insert("pattern".into(), json!(arg("pattern")));
            if let Some(p) = arg("path") {
                input.insert("path".into(), json!(p));
            }
            if let Some(g) = arg("include") {
                input.insert("glob".into(), json!(g));
            }
            ("Grep".into(), Value::Object(input))
        }
        ("gate-tamper", "write") => (
            "Write".into(),
            json!({ "file_path": arg("filePath"), "content": arg("content") }),
        ),
        ("gate-tamper", "edit") => (
            "Edit".into(),
            json!({
                "file_path": arg("filePath"),
                "old_string": arg("oldString"),
                "new_string": arg("newString"),
            }),
        ),
        ("gate-tamper", "apply_patch") => {
            let Some(patch) = arg("patchText") else {
                return Prepared::Malformed("`apply_patch` has no patchText".into());
            };
            ("apply_patch".into(), json!({ "command": patch }))
        }
        ("gate-mcp", "read_mcp_resource") => {
            let server = sanitize(arg("server").unwrap_or("unknown"));
            (
                format!("mcp__{server}__read_mcp_resource"),
                Value::Object(args.clone()),
            )
        }
        ("gate-mcp", t) if !is_builtin(t) => {
            let mut servers = configured_servers(&directory);
            if let Some(list) = payload.get("mcpServers").and_then(Value::as_array) {
                servers.extend(list.iter().filter_map(Value::as_str).map(str::to_string));
            }
            (mcp_tool_name(t, &servers), Value::Object(args.clone()))
        }
        _ => {
            return Prepared::Malformed(format!(
                "opencode tool `{tool}` is not handled by `{gate}`"
            ))
        }
    };
    let translated = json!({
        "session_id": text("sessionID"),
        "cwd": cwd,
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input,
    });
    let bytes = serde_json::to_vec(&translated).unwrap_or_default();
    let targets = || Targets::from_env(&directory);
    let reason = match tool {
        "write" | "edit" => arg("filePath").and_then(|p| targets().path_reason(p, &cwd)),
        "apply_patch" => {
            let targets = targets();
            crate::adapt::patch_paths(arg("patchText").unwrap_or(""))
                .iter()
                .find_map(|p| targets.path_reason(p, &cwd))
        }
        "bash" if gate == "gate-bash-secrets" => {
            targets().bash_reason(arg("command").unwrap_or(""), &cwd)
        }
        _ => None,
    };
    match reason {
        Some(reason) => Prepared::Deny {
            reason,
            payload: bytes,
        },
        None => Prepared::Gate(bytes),
    }
}

fn is_builtin(tool: &str) -> bool {
    UNGATED.contains(&tool)
        || matches!(
            tool,
            "bash" | "read" | "grep" | "glob" | "write" | "edit" | "apply_patch"
        )
}

/// opencode's MCP name sanitizer (`src/mcp/catalog.ts`): anything outside `[A-Za-z0-9_-]`
/// becomes `_`.
pub fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// The `mcp__<server>__<tool>` name for opencode tool `tool` (`sanitize(server) + "_" +
/// sanitize(tool)`): split after the one configured server name that prefixes it. With no
/// such server, or more than one (`a` and `a_b` both prefix `a_b_c`), the server is unknown
/// and the whole name is used as both parts.
pub fn mcp_tool_name(tool: &str, servers: &[String]) -> String {
    let mut prefixes: Vec<String> = servers.iter().map(|s| sanitize(s)).collect();
    prefixes.sort();
    prefixes.dedup();
    let hits: Vec<&String> = prefixes
        .iter()
        .filter(|s| {
            tool.strip_prefix(s.as_str())
                .and_then(|rest| rest.strip_prefix('_'))
                .is_some_and(|t| !s.is_empty() && !t.is_empty())
        })
        .collect();
    match hits.as_slice() {
        [server] => format!("mcp__{server}__{}", &tool[server.len() + 1..]),
        _ => format!("mcp__{tool}__{tool}"),
    }
}

/// MCP server names from the opencode config files the engine can read: the global config
/// dir's `config.json`/`opencode.json(c)`, `$OPENCODE_CONFIG`, `opencode.json(c)` and
/// `.opencode/opencode.json(c)` in `dir` and every directory above it,
/// `$OPENCODE_CONFIG_DIR/opencode.json(c)` and `$OPENCODE_CONFIG_CONTENT`.
pub fn configured_servers(dir: &Path) -> Vec<String> {
    let mut files: Vec<PathBuf> = Vec::new();
    if let Some(global) = global_config_dir() {
        files.extend(["config.json", "opencode.json", "opencode.jsonc"].map(|f| global.join(f)));
    }
    if let Some(f) = env_path("OPENCODE_CONFIG") {
        files.push(f);
    }
    for d in lexical(dir).ancestors() {
        for rel in [
            "opencode.json",
            "opencode.jsonc",
            ".opencode/opencode.json",
            ".opencode/opencode.jsonc",
        ] {
            files.push(d.join(rel));
        }
    }
    if let Some(d) = env_path("OPENCODE_CONFIG_DIR") {
        files.extend(["opencode.json", "opencode.jsonc"].map(|f| d.join(f)));
    }
    let mut texts: Vec<String> = files
        .iter()
        .filter(|f| std::fs::metadata(f).is_ok_and(|m| m.is_file() && m.len() <= MAX_CONFIG_BYTES))
        .filter_map(|f| std::fs::read_to_string(f).ok())
        .collect();
    if let Ok(content) = std::env::var("OPENCODE_CONFIG_CONTENT") {
        texts.push(content);
    }
    let mut names = Vec::new();
    for text in texts {
        let Ok(v) = serde_json::from_str::<Value>(&strip_jsonc(&text)) else {
            continue;
        };
        if let Some(mcp) = v.get("mcp").and_then(Value::as_object) {
            names.extend(mcp.keys().cloned());
        }
    }
    names
}

/// JSONC to JSON: `//` and `/* */` comments outside strings removed, and a comma before a
/// closing `}` or `]` dropped.
pub fn strip_jsonc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_string = false;
    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            match c {
                '\\' => {
                    if let Some(n) = chars.next() {
                        out.push(n);
                    }
                }
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match (c, chars.peek()) {
            ('"', _) => {
                in_string = true;
                out.push(c);
            }
            ('/', Some('/')) => {
                for n in chars.by_ref() {
                    if n == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            ('/', Some('*')) => {
                chars.next();
                let mut prev = ' ';
                for n in chars.by_ref() {
                    if prev == '*' && n == '/' {
                        break;
                    }
                    prev = n;
                }
                out.push(' ');
            }
            (']' | '}', _) => {
                let trimmed = out.trim_end().len();
                if out[..trimmed].ends_with(',') {
                    out.truncate(trimmed - 1);
                }
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

fn env_path(key: &str) -> Option<PathBuf> {
    std::env::var_os(key)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

fn home() -> Option<PathBuf> {
    env_path("HOME")
}

/// opencode's global config dir: `$XDG_CONFIG_HOME/opencode`, else `~/.config/opencode`.
fn global_config_dir() -> Option<PathBuf> {
    env_path("XDG_CONFIG_HOME")
        .or_else(|| home().map(|h| h.join(".config")))
        .map(|d| d.join("opencode"))
}

/// What becomes of a Grep rewrite (the credential-file exclusion) under opencode.
#[derive(Debug, PartialEq)]
pub enum Rewrite {
    /// Print these args as `updatedInput`.
    Args(Value),
    /// The call needs no change.
    Keep,
    /// Block the call.
    Deny(String),
}

/// File extensions an opencode Grep `include` may name and still run unchanged: none of them
/// is a credential file's.
const CODE_EXTS: &[&str] = &[
    "rs", "ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs", "py", "go", "md", "mdx", "sol",
    "move", "c", "h", "cc", "cpp", "hpp", "cxx", "java", "kt", "kts", "swift", "rb", "php", "cs",
    "css", "scss", "sass", "less", "html", "htm", "vue", "svelte", "lua", "zig", "sql", "graphql",
    "proto",
];

/// Map the gate's Grep rewrite (`glob` with a ` !{…}` exclusion appended) onto opencode's
/// grep, which passes `include` to ripgrep as one `--glob`:
///
/// - no `include`: the exclusion becomes the `include` (ripgrep searches every file it does
///   not match);
/// - an `include` of code files only (`*.rs`, `**/*.{ts,tsx}`, extensions in [`CODE_EXTS`])
///   that no excluded name matches: unchanged, since it cannot reach a credential file;
/// - any other `include`: denied, because one glob cannot both include and exclude.
///
/// Outside opencode the rewrite passes unchanged.
pub fn grep_rewrite(updated: Value) -> Rewrite {
    if !crate::adapt::is_opencode() {
        return Rewrite::Args(updated);
    }
    let original = ORIGINAL_ARGS.get().cloned().unwrap_or_default();
    let glob = updated
        .get("glob")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let include = original
        .get("include")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if include.is_empty() {
        let mut args = original;
        args.insert("include".into(), Value::String(glob));
        return Rewrite::Args(Value::Object(args));
    }
    let exclusion = glob.strip_prefix(&include).unwrap_or(&glob).trim();
    if include_is_code_only(&include, exclusion) {
        return Rewrite::Keep;
    }
    Rewrite::Deny(format!(
        "safe-ai-skill: this search would cover credential files, and opencode's grep takes one \
         `include` glob, so safe-ai-skill cannot exclude them from `{include}`. Search without \
         `include`, give an include of code files only (like `*.ts`), or narrow `path`."
    ))
}

fn include_is_code_only(include: &str, exclusion: &str) -> bool {
    let excluded = exclusion_names(exclusion);
    expand_one_brace(include).iter().all(|alt| {
        let name = alt.strip_prefix("**/").unwrap_or(alt);
        let Some(ext) = name.strip_prefix("*.") else {
            return false;
        };
        let ext = ext.to_ascii_lowercase();
        if !CODE_EXTS.contains(&ext.as_str()) {
            return false;
        }
        let probe = format!("x.{ext}");
        !excluded.iter().any(|p| p.matches(&probe))
    })
}

/// The last-component patterns of a `!{a,b,…}` exclusion, minus pure wildcards (a directory
/// exclusion like `**/.ssh/**`).
fn exclusion_names(exclusion: &str) -> Vec<glob::Pattern> {
    let inner = exclusion
        .trim()
        .trim_start_matches('!')
        .trim_start_matches('{')
        .trim_end_matches('}');
    split_top_level(inner)
        .iter()
        .filter_map(|alt| alt.rsplit('/').next())
        .filter(|last| !last.chars().all(|c| c == '*') && !last.is_empty())
        .filter_map(|last| glob::Pattern::new(last).ok())
        .collect()
}

fn split_top_level(text: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut cur = String::new();
    for c in text.chars() {
        match c {
            '{' | '[' => depth += 1,
            '}' | ']' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(std::mem::take(&mut cur));
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    parts.push(cur);
    parts
}

/// `a.{x,y}` → `a.x`, `a.y`; more than one brace group, or none, is left as is.
fn expand_one_brace(glob: &str) -> Vec<String> {
    let (Some(open), Some(close)) = (glob.find('{'), glob.find('}')) else {
        return vec![glob.to_string()];
    };
    if close < open || glob[close + 1..].contains('{') {
        return vec![glob.to_string()];
    }
    glob[open + 1..close]
        .split(',')
        .map(|alt| format!("{}{alt}{}", &glob[..open], &glob[close + 1..]))
        .collect()
}

/// Commands that only read their arguments.
const READ_ONLY: &[&str] = &[
    "cat",
    "less",
    "more",
    "head",
    "tail",
    "ls",
    "stat",
    "file",
    "wc",
    "grep",
    "rg",
    "jq",
    "diff",
    "cmp",
    "sha256sum",
    "shasum",
    "md5",
    "md5sum",
    "which",
    "type",
    "readlink",
    "realpath",
    "test",
    "[",
    "echo",
    "printf",
    "true",
    "basename",
    "dirname",
    "tree",
    "bat",
    "pwd",
    "cd",
];

/// Commands that write, move or remove their arguments (for the engine binary by name).
const MUTATORS: &[&str] = &[
    "rm", "mv", "cp", "ln", "chmod", "chown", "truncate", "install", "unlink", "dd", "tee", "sed",
    "perl", "shred", "touch", "rsync", "curl", "wget",
];

/// Wrappers skipped when finding the command a segment runs.
const PREFIXES: &[&str] = &[
    "sudo", "env", "exec", "nohup", "nice", "time", "builtin", "command",
];

/// Locations an opencode session must not write: what opencode loads as plugins, tools or
/// config, and the engine the plugin runs.
#[derive(Debug, Clone, Default)]
pub struct Targets {
    home: Option<PathBuf>,
    /// Whole directories: the global config dir and `$OPENCODE_CONFIG_DIR` (as given and
    /// canonical).
    dirs: Vec<PathBuf>,
    /// Single files: `$OPENCODE_CONFIG`, the engine (this executable and `safe-ai-skill` on
    /// `PATH`).
    files: Vec<PathBuf>,
    /// Existing files under the protected places, for the shell scanner's delete, move and
    /// ancestor checks.
    existing: Vec<PathBuf>,
}

impl Targets {
    /// Read `HOME`, `XDG_CONFIG_HOME`, `OPENCODE_CONFIG`, `OPENCODE_CONFIG_DIR`, `PATH` and the
    /// current executable; list what exists of them and of `.opencode/` and `opencode.json(c)`
    /// in `dir` and every directory above it.
    pub fn from_env(dir: &Path) -> Self {
        let mut t = Targets {
            home: home(),
            ..Targets::default()
        };
        for d in [global_config_dir(), env_path("OPENCODE_CONFIG_DIR")]
            .into_iter()
            .flatten()
        {
            push_spellings(&mut t.dirs, d);
        }
        if let Some(f) = env_path("OPENCODE_CONFIG") {
            push_spellings(&mut t.files, f);
        }
        if let Ok(exe) = std::env::current_exe() {
            push_spellings(&mut t.files, exe);
        }
        if let Some(path) = std::env::var_os("PATH") {
            for d in std::env::split_paths(&path).filter(|d| d.is_absolute()) {
                let candidate = d.join("safe-ai-skill");
                if candidate.exists() {
                    push_spellings(&mut t.files, candidate);
                }
            }
        }
        let mut existing: Vec<PathBuf> = t.files.iter().filter(|f| f.exists()).cloned().collect();
        let mut roots: Vec<PathBuf> = t.dirs.clone();
        for d in lexical(dir).ancestors() {
            roots.push(d.join(".opencode"));
            for f in ["opencode.json", "opencode.jsonc"] {
                let file = d.join(f);
                if file.is_file() {
                    existing.push(file);
                }
            }
        }
        if let Some(h) = &t.home {
            roots.push(h.join(".opencode"));
        }
        for root in roots.iter().filter(|r| r.is_dir()) {
            existing.extend(
                walkdir::WalkDir::new(root)
                    .max_depth(3)
                    .into_iter()
                    .filter_map(Result::ok)
                    .filter(|e| e.file_type().is_file())
                    .take(200)
                    .map(|e| e.into_path()),
            );
        }
        existing.sort();
        existing.dedup();
        t.existing = existing;
        t
    }

    /// Why an opencode session may not write `target` (a file tool path or a patch path), or
    /// `None`: a `.opencode` directory anywhere on the path, an `opencode.json(c)`, anything
    /// in the global config dir or `$OPENCODE_CONFIG_DIR`, `$OPENCODE_CONFIG`, or the engine.
    /// Symlinks in the existing part of the path are resolved too.
    pub fn path_reason(&self, target: &str, cwd: &Path) -> Option<String> {
        let lexical_path = absolute(target, cwd, self.home.as_deref());
        let canonical = canonical_prefix(&lexical_path);
        for full in [&lexical_path, &canonical] {
            let comps = lower_components(full);
            let config_name = comps
                .last()
                .is_some_and(|f| f == "opencode.json" || f == "opencode.jsonc");
            let in_dir = comps.iter().any(|c| c == ".opencode")
                || self.dirs.iter().any(|d| starts_with(&comps, d));
            if config_name || in_dir {
                return Some(format!(
                    "safe-ai-skill: `{target}` is opencode config, plugin or tool code, which \
                     opencode loads without a trust check and which runs safe-ai-skill's gates; \
                     edit it yourself, outside the agent."
                ));
            }
            if self.files.iter().any(|f| lower_components(f) == comps) {
                return Some(format!(
                    "safe-ai-skill: `{target}` is the safe-ai-skill engine or opencode config \
                     the plugin relies on; changing it would turn the gates off. Do it \
                     yourself, outside the agent."
                ));
            }
        }
        None
    }

    /// Why an opencode shell command may not run, judged on its words (nothing is run):
    ///
    /// - deletes, moves and overwrites of an existing protected file or a directory holding
    ///   it (globs, `cd`, `find -delete`, `git` rewrites), through the wallet gate's scanner;
    /// - any mention of `.opencode`, `opencode.json`, `.config/opencode` or a protected
    ///   directory or file, unless every command in it only reads;
    /// - the engine named by a writing command.
    pub fn bash_reason(&self, command: &str, cwd: &Path) -> Option<String> {
        if let Some(what) = crate::gates::wallet::clobber_of(command, cwd, &self.existing) {
            return Some(format!(
                "safe-ai-skill: {what}, which the opencode plugin needs (opencode config, \
                 plugin code or the safe-ai-skill engine); do it yourself, outside the agent."
            ));
        }
        let lower = command.to_ascii_lowercase();
        let mut needles: Vec<String> = [".opencode", "opencode.json", ".config/opencode"]
            .map(String::from)
            .to_vec();
        for p in self.dirs.iter().chain(self.files.iter()) {
            needles.push(p.to_string_lossy().to_ascii_lowercase());
        }
        let command = &without_fd_redirects(command);
        let segments = segments(command);
        if needles.iter().any(|n| lower.contains(n.as_str())) && !only_reads(command, &segments) {
            return Some(
                "safe-ai-skill: this command names opencode config, plugin or tool code (or the \
                 safe-ai-skill engine) and does more than read it; opencode loads those without a \
                 trust check. Do it yourself, outside the agent."
                    .into(),
            );
        }
        let engine_write = segments.iter().any(|words| {
            words
                .first()
                .is_some_and(|w| MUTATORS.contains(&w.as_str()))
                && words
                    .iter()
                    .skip(1)
                    .any(|w| w.rsplit('/').next() == Some("safe-ai-skill"))
        });
        engine_write.then(|| {
            "safe-ai-skill: this command writes a file named safe-ai-skill, which may be the \
             engine the opencode plugin runs; do it yourself, outside the agent."
                .into()
        })
    }
}

/// `command` without the redirections that write no file (`2>&1`, `>&2`, `>/dev/null`).
fn without_fd_redirects(command: &str) -> String {
    [
        "2>&1",
        "1>&2",
        ">&2",
        ">&1",
        "2>/dev/null",
        ">/dev/null",
        "> /dev/null",
    ]
    .iter()
    .fold(command.to_string(), |acc, r| acc.replace(r, " "))
}

/// The commands of a shell line, each as its words from the program on (assignments and
/// [`PREFIXES`] dropped), split on `;`, `|`, `&`, newlines, parentheses and backticks. Quotes
/// are removed, not honoured, so a quoted separator splits too (which only adds commands).
fn segments(command: &str) -> Vec<Vec<String>> {
    command
        .split([';', '|', '&', '\n', '(', ')', '`'])
        .map(|seg| {
            seg.split_whitespace()
                .map(|w| w.trim_matches(['\'', '"']).to_string())
                .skip_while(|w| {
                    let base = w.rsplit('/').next().unwrap_or(w);
                    (w.contains('=') && !w.starts_with('=')) || PREFIXES.contains(&base)
                })
                .collect::<Vec<String>>()
        })
        .filter(|words| !words.is_empty())
        .map(|mut words| {
            if let Some(first) = words.first_mut() {
                *first = first.rsplit('/').next().unwrap_or(first).to_string();
            }
            words
        })
        .collect()
}

/// Whether every command only reads: each program is in [`READ_ONLY`] (or `find` without an
/// action, or a read-only `git` subcommand) and nothing is redirected to a file.
fn only_reads(command: &str, segments: &[Vec<String>]) -> bool {
    if command.contains('>') {
        return false;
    }
    segments.iter().all(|words| {
        let program = words[0].as_str();
        let rest = &words[1..];
        match program {
            "find" => !rest.iter().any(|w| {
                matches!(
                    w.as_str(),
                    "-delete" | "-exec" | "-execdir" | "-ok" | "-okdir" | "-fprint" | "-fls"
                )
            }),
            "git" => rest
                .iter()
                .find(|w| !w.starts_with('-'))
                .is_some_and(|sub| matches!(sub.as_str(), "status" | "diff" | "log" | "show")),
            p => READ_ONLY.contains(&p),
        }
    })
}

fn push_spellings(list: &mut Vec<PathBuf>, path: PathBuf) {
    let lexical_path = lexical(&path);
    let canonical = canonical_prefix(&lexical_path);
    for p in [lexical_path, canonical] {
        if !list.contains(&p) {
            list.push(p);
        }
    }
}

fn lower_components(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(s.to_string_lossy().to_ascii_lowercase()),
            _ => None,
        })
        .collect()
}

fn starts_with(comps: &[String], dir: &Path) -> bool {
    let d = lower_components(dir);
    !d.is_empty() && comps.len() >= d.len() && comps[..d.len()] == d[..]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn targets() -> Targets {
        Targets {
            home: Some(PathBuf::from("/home/u")),
            dirs: vec![
                PathBuf::from("/home/u/.config/opencode"),
                PathBuf::from("/opt/occfg"),
            ],
            files: vec![
                PathBuf::from("/home/u/.local/bin/safe-ai-skill"),
                PathBuf::from("/etc/oc.json"),
            ],
            existing: Vec::new(),
        }
    }

    #[test]
    fn ask_becomes_deny_and_allow_becomes_no_output() {
        let ask = Decision::Ask {
            reason: "MAINNET DEPLOY — approve to proceed".into(),
        };
        assert_eq!(
            render(&ask),
            Decision::Deny {
                reason: format!("MAINNET DEPLOY. {ASK_SUFFIX}")
            }
        );
        assert_eq!(render(&Decision::Allow), Decision::Defer);
        let deny = Decision::Deny { reason: "x".into() };
        assert_eq!(render(&deny), deny);
        assert_eq!(render(&Decision::Defer), Decision::Defer);
    }

    #[test]
    fn mcp_names_split_after_the_one_matching_server() {
        let servers = vec!["helius".to_string(), "my.server".to_string()];
        assert_eq!(
            mcp_tool_name("helius_transferSol", &servers),
            "mcp__helius__transferSol"
        );
        assert_eq!(
            mcp_tool_name("my_server_get_x", &servers),
            "mcp__my_server__get_x"
        );
        // No configured server: unknown, whole name both ways.
        assert_eq!(
            mcp_tool_name("phantom_signTransaction", &servers),
            "mcp__phantom_signTransaction__phantom_signTransaction"
        );
        // Two servers prefix it: ambiguous, unknown.
        let both = vec!["a".to_string(), "a_b".to_string()];
        assert_eq!(mcp_tool_name("a_b_c", &both), "mcp__a_b_c__a_b_c");
        // The server name alone is not a tool.
        assert_eq!(mcp_tool_name("helius_", &servers), "mcp__helius___helius_");
    }

    #[test]
    fn jsonc_comments_and_trailing_commas_are_stripped() {
        let text = r#"{
            // a comment with "quotes"
            "mcp": { "helius": { "url": "https://x//y" }, /* block */ "solana-dev": {}, },
            "s": "/* not a comment */",
        }"#;
        let v: Value = serde_json::from_str(&strip_jsonc(text)).unwrap();
        let keys: Vec<&String> = v["mcp"].as_object().unwrap().keys().collect();
        assert_eq!(keys, ["helius", "solana-dev"]);
        assert_eq!(v["mcp"]["helius"]["url"], "https://x//y");
        assert_eq!(v["s"], "/* not a comment */");
    }

    #[test]
    fn opencode_config_plugins_and_the_engine_are_protected() {
        let cwd = Path::new("/w/proj");
        let t = targets();
        for p in [
            ".opencode/plugins/safe-ai-skill.js",
            ".opencode/plugins/evil.ts",
            ".opencode/tools/x.js",
            ".OPENCODE/opencode.json",
            "opencode.json",
            "sub/../opencode.jsonc",
            "/w/opencode.json",
            "~/.config/opencode/plugins/safe-ai-skill.js",
            "/home/u/.config/opencode/package.json",
            "/opt/occfg/opencode.json",
            "/etc/oc.json",
            "~/.local/bin/safe-ai-skill",
            "~/.opencode/plugins/x.js",
        ] {
            assert!(t.path_reason(p, cwd).is_some(), "{p}");
        }
        for p in [
            "src/opencode.rs",
            "docs/opencode.md",
            "opencode/notes.md",
            "/home/u/.config/other/x",
            "bin/safe-ai-skill",
        ] {
            assert!(t.path_reason(p, cwd).is_none(), "{p}");
        }
    }

    #[test]
    fn shell_writes_to_protected_places_are_denied() {
        let cwd = Path::new("/w/proj");
        let t = targets();
        for c in [
            "rm -rf .opencode",
            "echo 'x' > .opencode/plugins/evil.js",
            "cp /tmp/x.js ~/.config/opencode/plugins/",
            "printf '{}' | tee opencode.json",
            "sed -i s/a/b/ opencode.jsonc",
            "python3 -c \"open('.opencode/plugins/x.js','w')\"",
            "git checkout -- .opencode",
            "cat x > /opt/occfg/opencode.json",
            "cp evil ~/.local/bin/safe-ai-skill",
            "mv a /etc/oc.json",
            "cd x && rm safe-ai-skill",
        ] {
            assert!(t.bash_reason(c, cwd).is_some(), "{c}");
        }
        for c in [
            "cat .opencode/plugins/safe-ai-skill.js",
            "ls -la .opencode",
            "grep -r mcp opencode.json 2>&1",
            "git diff opencode.json",
            "find .opencode -name '*.js'",
            "safe-ai-skill status",
            "which safe-ai-skill",
            "cargo build",
            "echo hello > out.txt",
        ] {
            assert!(t.bash_reason(c, cwd).is_none(), "{c}");
        }
    }

    #[test]
    fn code_only_includes_are_recognised() {
        let excl = "!{**/.[eE][nN][vV],**/[iI][dD].[jJ][sS][oO][nN],**/*.[pP][eE][mM],**/.[sS][sS][hH]/**}";
        assert!(include_is_code_only("*.ts", excl));
        assert!(include_is_code_only("**/*.{ts,tsx}", excl));
        assert!(include_is_code_only("*.RS", excl));
        assert!(!include_is_code_only("*.json", excl));
        assert!(!include_is_code_only("*.{ts,json}", excl));
        assert!(!include_is_code_only("*", excl));
        assert!(!include_is_code_only("src/**", excl));
        assert!(!include_is_code_only("*.pem", excl));
        // An exclusion that would match the extension wins.
        assert!(!include_is_code_only("*.ts", "!{**/*.[tT][sS]}"));
    }
}
