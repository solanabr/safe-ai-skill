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

/// The directory an opencode grep searches, kept for [`grep_rewrite`].
static GREP_ROOT: OnceLock<PathBuf> = OnceLock::new();

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
            // opencode resolves `path` with realpath (falling back to the path as given,
            // `core/src/fs-util.ts` `resolve`) and runs ripgrep in it when it is a directory,
            // else in its parent (`src/tool/grep.ts`): a file path, or a link to one, searches
            // the whole directory it is in, so it is judged as that directory.
            let given = match arg("path").filter(|p| !p.trim().is_empty()) {
                Some(p) => absolute(p, &directory, home().as_deref()),
                None => directory.clone(),
            };
            let mut root = std::fs::canonicalize(&given).unwrap_or(given);
            if !root.is_dir() {
                root = root.parent().map(Path::to_path_buf).unwrap_or(root);
            }
            let _ = GREP_ROOT.set(root.clone());
            let mut input = Map::new();
            input.insert("pattern".into(), json!(arg("pattern")));
            input.insert("path".into(), json!(root));
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
    let Ok(bytes) = serde_json::to_vec(&translated) else {
        return Prepared::Malformed("the payload could not be translated".into());
    };
    let plugin = text("pluginPath");
    let targets = || Targets::from_env(&directory, plugin);
    let reason = match tool {
        "write" | "edit" => arg("filePath").and_then(|p| {
            let added = arg("content").or(arg("newString")).unwrap_or("");
            let targets = targets();
            targets
                .path_reason(p, &cwd)
                .or_else(|| targets.rc_path_reason(p, added, &cwd))
        }),
        "apply_patch" => {
            let targets = targets();
            let patch = arg("patchText").unwrap_or("");
            crate::adapt::patch_paths(patch).iter().find_map(|p| {
                targets
                    .path_reason(p, &cwd)
                    .or_else(|| targets.rc_path_reason(p, patch, &cwd))
            })
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

/// The opencode config documents the engine can read, with the file each came from: the
/// global config dir's `config.json`/`opencode.json(c)`, `$OPENCODE_CONFIG`, `opencode.json(c)`
/// and `.opencode/opencode.json(c)` in `dir` and every directory above it,
/// `$OPENCODE_CONFIG_DIR/opencode.json(c)` and `$OPENCODE_CONFIG_CONTENT` (no file).
fn config_docs(dir: &Path) -> Vec<(Option<PathBuf>, Value)> {
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
    let parse = |text: &str| serde_json::from_str::<Value>(&strip_jsonc(text)).ok();
    let mut docs: Vec<(Option<PathBuf>, Value)> = files
        .into_iter()
        .filter(|f| std::fs::metadata(f).is_ok_and(|m| m.is_file() && m.len() <= MAX_CONFIG_BYTES))
        .filter_map(|f| {
            let v = parse(&std::fs::read_to_string(&f).ok()?)?;
            Some((Some(f), v))
        })
        .collect();
    if let Some(v) = std::env::var("OPENCODE_CONFIG_CONTENT")
        .ok()
        .and_then(|t| parse(&t))
    {
        docs.push((None, v));
    }
    docs
}

/// MCP server names (the keys of `mcp`) in the opencode config ([`config_docs`]).
pub fn configured_servers(dir: &Path) -> Vec<String> {
    config_docs(dir)
        .iter()
        .filter_map(|(_, v)| v.get("mcp").and_then(Value::as_object))
        .flat_map(|mcp| mcp.keys().cloned())
        .collect()
}

/// The files and directories that path-spec plugins in the opencode config name (`"plugin":
/// ["./x.ts", "file:///…", ["/abs/y.js", {…}]]`), resolved as opencode does: a `file://` URL
/// or an absolute path as is, a `.`-relative path against the declaring file's directory.
pub fn configured_plugin_paths(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for (file, doc) in config_docs(dir) {
        let Some(list) = doc.get("plugin").and_then(Value::as_array) else {
            continue;
        };
        let base = file
            .as_deref()
            .and_then(Path::parent)
            .map(Path::to_path_buf)
            .unwrap_or_else(|| dir.to_path_buf());
        for entry in list {
            let spec = entry
                .as_str()
                .or_else(|| entry.get(0).and_then(Value::as_str))
                .unwrap_or("");
            let path = if let Some(rest) = spec.strip_prefix("file://") {
                PathBuf::from(rest.replace("%20", " "))
            } else if spec.starts_with('.') || Path::new(spec).is_absolute() {
                base.join(spec)
            } else {
                continue;
            };
            out.push(lexical(&path));
        }
    }
    out
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
/// is a credential file's (an `.env.<ext>` file is the documented exception).
const CODE_EXTS: &[&str] = &[
    "rs", "ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs", "py", "go", "sol", "move", "c",
    "h", "cc", "cpp", "hpp", "cxx", "java", "kt", "kts", "swift", "rb", "php", "cs", "css", "scss",
    "sass", "less", "html", "htm", "vue", "svelte", "lua", "zig", "sql", "graphql", "proto",
];

/// Map the gate's Grep rewrite (`glob` with a ` !{…}` exclusion appended) onto opencode's
/// grep, which passes `include` to ripgrep as one `--glob`:
///
/// - no `include`: the exclusion becomes the `include` (ripgrep searches every file it does
///   not match); only `include` is printed, so no other arg is round-tripped;
/// - an `include` of code files only (`*.rs`, `**/*.{ts,tsx}`, extensions in [`CODE_EXTS`])
///   that no excluded name matches, searched outside `$HOME` and its ancestors: unchanged;
/// - any other `include`: denied, because one glob cannot both include and exclude (ripgrep
///   runs with `--hidden`, so a search of `$HOME` reaches its excluded directories).
///
/// Outside opencode the rewrite passes unchanged.
pub fn grep_rewrite(updated: Value) -> Rewrite {
    if !crate::adapt::is_opencode() {
        return Rewrite::Args(updated);
    }
    debug_assert!(
        ORIGINAL_ARGS.get().is_some(),
        "prepare() runs before the gate"
    );
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
        return Rewrite::Args(json!({ "include": glob }));
    }
    let exclusion = glob.strip_prefix(&include).unwrap_or(&glob).trim();
    // The root is canonical (see `prepare`); `/` has no components and reaches everything.
    let reaches_home = match (GREP_ROOT.get(), home()) {
        (Some(root), Some(home)) => {
            let home = std::fs::canonicalize(&home).unwrap_or(home);
            lower_components(root).is_empty() || starts_with(&lower_components(&home), root)
        }
        _ => true,
    };
    if !reaches_home && include_is_code_only(&include, exclusion) {
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

/// Shell startup files (relative to `$HOME`) whose `PATH` lines decide which engine the next
/// opencode start finds.
const RC_FILES: &[&str] = &[
    ".zshrc",
    ".zshenv",
    ".zprofile",
    ".zlogin",
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".profile",
    ".config/fish/config.fish",
];

fn same_file(a: &Path, b: &Path) -> bool {
    lower_components(a) == lower_components(b)
        || lower_components(&canonical_prefix(a)) == lower_components(&canonical_prefix(b))
}

/// Wrappers skipped when finding the command a segment runs.
const PREFIXES: &[&str] = &[
    "sudo", "env", "exec", "nohup", "nice", "time", "builtin", "command",
];

/// Locations an opencode session must not write: what opencode loads as plugins, tools or
/// config, the engine the plugin runs, and Claude Code's settings and plugins.
#[derive(Debug, Clone, Default)]
pub struct Targets {
    home: Option<PathBuf>,
    /// Whole directories: the global config dir, `$OPENCODE_CONFIG_DIR`, opencode's npm plugin
    /// cache, and directory plugins named in the config (as given and canonical).
    dirs: Vec<PathBuf>,
    /// Single files: `$OPENCODE_CONFIG`, this plugin, path plugins named in the config, and the
    /// engine (this executable and `safe-ai-skill` in every `PATH` directory, present or not).
    files: Vec<PathBuf>,
    /// Claude Code config dirs (`~/.claude`, `$CLAUDE_CONFIG_DIR`): their settings files and
    /// `plugins/` are protected.
    claude_dirs: Vec<PathBuf>,
    /// Existing files under the protected places, for the shell scanner's delete, move and
    /// ancestor checks.
    existing: Vec<PathBuf>,
}

/// opencode's cache dir, where it installs npm plugins: `$XDG_CACHE_HOME/opencode`, else
/// `~/.cache/opencode`.
fn cache_dir() -> Option<PathBuf> {
    env_path("XDG_CACHE_HOME")
        .or_else(|| home().map(|h| h.join(".cache")))
        .map(|d| d.join("opencode"))
}

impl Targets {
    /// Read `HOME`, `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`, `OPENCODE_CONFIG`,
    /// `OPENCODE_CONFIG_DIR`, `CLAUDE_CONFIG_DIR`, `PATH`, the current executable and the
    /// opencode config's `plugin` entries; `plugin` is this plugin's own file (from the
    /// payload). List what exists of them and of `.opencode/` and `opencode.json(c)` in `dir`
    /// and every directory above it.
    pub fn from_env(dir: &Path, plugin: Option<&str>) -> Self {
        let mut t = Targets {
            home: home(),
            ..Targets::default()
        };
        for d in [
            global_config_dir(),
            env_path("OPENCODE_CONFIG_DIR"),
            cache_dir(),
        ]
        .into_iter()
        .flatten()
        {
            push_spellings(&mut t.dirs, d);
        }
        if let Some(f) = env_path("OPENCODE_CONFIG") {
            push_spellings(&mut t.files, f);
        }
        let plugin = plugin.map(PathBuf::from).filter(|p| p.is_absolute());
        for p in configured_plugin_paths(dir).into_iter().chain(plugin) {
            if p.is_dir() {
                push_spellings(&mut t.dirs, p);
            } else {
                push_spellings(&mut t.files, p);
            }
        }
        if let Ok(exe) = std::env::current_exe() {
            push_spellings(&mut t.files, exe);
        }
        if let Some(path) = std::env::var_os("PATH") {
            for d in std::env::split_paths(&path).filter(|d| d.is_absolute()) {
                push_spellings(&mut t.files, d.join("safe-ai-skill"));
            }
        }
        for d in [
            t.home.as_ref().map(|h| h.join(".claude")),
            env_path("CLAUDE_CONFIG_DIR"),
        ]
        .into_iter()
        .flatten()
        {
            push_spellings(&mut t.claude_dirs, d);
        }
        let mut existing: Vec<PathBuf> = t.files.iter().filter(|f| f.is_file()).cloned().collect();
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
        for c in &t.claude_dirs {
            for f in ["settings.json", "settings.local.json"] {
                let file = c.join(f);
                if file.is_file() {
                    existing.push(file);
                }
            }
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
    /// in a protected directory, a protected file (the engine in any `PATH` directory, this
    /// plugin, `$OPENCODE_CONFIG`), or Claude Code's settings or plugins. Symlinks in the
    /// existing part of the path are resolved too.
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
                    "safe-ai-skill: `{target}` is the safe-ai-skill engine, the opencode plugin \
                     or config it relies on; changing it would turn the gates off. Do it \
                     yourself, outside the agent."
                ));
            }
            let settings = match comps.as_slice() {
                [.., dir, file] => {
                    (file == "settings.json" || file == "settings.local.json")
                        && (dir == ".claude"
                            || self.claude_dirs.iter().any(|c| {
                                full.parent()
                                    .is_some_and(|p| lower_components(p) == lower_components(c))
                            }))
                }
                _ => false,
            };
            let claude_plugins = self
                .claude_dirs
                .iter()
                .any(|c| starts_with(&comps, &c.join("plugins")));
            if settings || claude_plugins {
                return Some(format!(
                    "safe-ai-skill: `{target}` is Claude Code settings or plugin code, which runs \
                     safe-ai-skill's Claude Code hooks; an opencode session may not change it. \
                     Edit it yourself, outside the agent."
                ));
            }
        }
        None
    }

    /// Why a write of `added` text to `target` may not happen: `target` is a shell startup
    /// file ([`RC_FILES`] in `$HOME`) and the text mentions `PATH`, which could put a planted
    /// `safe-ai-skill` first on the `PATH` of the next opencode start.
    pub fn rc_path_reason(&self, target: &str, added: &str, cwd: &Path) -> Option<String> {
        let home = self.home.as_deref()?;
        let full = absolute(target, cwd, Some(home));
        let rc = RC_FILES.iter().any(|f| same_file(&full, &home.join(f)));
        (rc && added.contains("PATH")).then(|| {
            format!(
                "safe-ai-skill: this changes `PATH` in the shell startup file `{target}`, which \
                 could put another safe-ai-skill engine ahead of the real one at the next opencode \
                 start; edit it yourself, outside the agent."
            )
        })
    }

    /// Why an opencode shell command may not run, judged on its words (nothing is run):
    ///
    /// - deletes, moves and overwrites of an existing protected file or a directory holding
    ///   it (globs, `cd`, `find -delete`, `git` rewrites), through the wallet gate's scanner;
    /// - a mention of a protected place, unless every command in it only reads. Quotes and
    ///   backslashes are dropped first; a mention is `.opencode`, `opencode.json` or
    ///   `.config/opencode` in the text, a path word [`Targets::path_reason`] denies, or a glob
    ///   word matching one of those names or a protected file;
    /// - the engine named by a writing command or as a redirection target.
    pub fn bash_reason(&self, command: &str, cwd: &Path) -> Option<String> {
        if let Some(what) = crate::gates::wallet::clobber_of(command, cwd, &self.existing) {
            return Some(format!(
                "safe-ai-skill: {what}, which the opencode plugin needs (opencode config, \
                 plugin code, the safe-ai-skill engine or Claude Code settings); do it yourself, \
                 outside the agent."
            ));
        }
        let command = &without_fd_redirects(command);
        let flat: String = command
            .chars()
            .filter(|c| !matches!(c, '\'' | '"' | '\\'))
            .collect();
        let lower = flat.to_ascii_lowercase();
        let segments = segments(&flat);
        let mut needles: Vec<String> = [".opencode", "opencode.json", ".config/opencode"]
            .map(String::from)
            .to_vec();
        for p in self.dirs.iter().chain(self.files.iter()) {
            needles.push(p.to_string_lossy().to_ascii_lowercase());
        }
        let words: Vec<&str> = flat
            .split(|c: char| {
                c.is_whitespace()
                    || matches!(c, ';' | '|' | '&' | '(' | ')' | '<' | '>' | '=' | ',' | '`')
            })
            .filter(|w| !w.is_empty())
            .collect();
        let mentions = needles.iter().any(|n| lower.contains(n.as_str()))
            || words.iter().any(|w| self.word_mentions(w, cwd))
            || (flat.contains("PATH") && RC_FILES.iter().any(|rc| lower.contains(rc)));
        if mentions && !only_reads(&flat, &segments) {
            return Some(
                "safe-ai-skill: this command names opencode config, plugin or tool code, the \
                 safe-ai-skill engine, Claude Code settings or a shell startup file's PATH, and \
                 does more than read it. Do it yourself, outside the agent."
                    .into(),
            );
        }
        let is_engine = |w: &str| w.rsplit('/').next() == Some("safe-ai-skill");
        let mutator_write = segments.iter().any(|words| {
            words
                .first()
                .is_some_and(|w| MUTATORS.contains(&w.as_str()))
                && words.iter().skip(1).any(|w| is_engine(w))
        });
        let redirect_write = flat
            .split('>')
            .skip(1)
            .filter_map(|rest| {
                rest.trim_start_matches(['>', '|'])
                    .split_whitespace()
                    .next()
            })
            .any(is_engine);
        (mutator_write || redirect_write).then(|| {
            "safe-ai-skill: this command writes a file named safe-ai-skill, which may be the \
             engine the opencode plugin runs; do it yourself, outside the agent."
                .into()
        })
    }

    /// Whether a shell word names a protected place: as a path, or as a glob whose components
    /// can match `.opencode`, `opencode.json(c)` or `.config/opencode`, or whose expansion can
    /// match a protected file.
    fn word_mentions(&self, word: &str, cwd: &Path) -> bool {
        let globby = word.contains(['*', '?', '[']);
        if !globby {
            let path_like = word.contains('/') || word.starts_with('~') || word.starts_with('.');
            return path_like && self.path_reason(word, cwd).is_some();
        }
        let matches = |pattern: &str, name: &str| {
            glob::Pattern::new(pattern).is_ok_and(|p| {
                p.matches_with(
                    name,
                    glob::MatchOptions {
                        case_sensitive: false,
                        require_literal_separator: true,
                        require_literal_leading_dot: true,
                    },
                )
            })
        };
        let comps: Vec<&str> = word.split('/').collect();
        // A bare wildcard (`dir/*`) creates nothing, and its deletes of existing files are the
        // scanner's (`clobber_of`): only a component with a literal character names a file.
        // Under `.config`, though, `*` can expand to the existing `opencode` dir.
        let literal = |c: &str| c.chars().any(|ch| !matches!(ch, '*' | '?'));
        let named = comps.iter().enumerate().any(|(i, c)| {
            let name = literal(c)
                && [".opencode", "opencode.json", "opencode.jsonc"]
                    .iter()
                    .any(|n| matches(c, n));
            name || (i > 0 && matches(comps[i - 1], ".config") && matches(c, "opencode"))
        });
        if named {
            return true;
        }
        let full = absolute(word, cwd, self.home.as_deref());
        let full = full.to_string_lossy();
        let mut protected: Vec<PathBuf> = self.files.clone();
        for c in &self.claude_dirs {
            protected.extend(["settings.json", "settings.local.json"].map(|f| c.join(f)));
        }
        protected
            .iter()
            .any(|f| matches(&full, &f.to_string_lossy()))
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
                PathBuf::from("/usr/local/bin/safe-ai-skill"),
                PathBuf::from("/etc/oc.json"),
            ],
            claude_dirs: vec![PathBuf::from("/home/u/.claude"), PathBuf::from("/cc")],
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
            "~/.claude/settings.json",
            "/cc/settings.local.json",
            ".claude/settings.local.json",
            "~/.claude/plugins/cache/x/hooks/hooks.json",
            "/cc/plugins/marketplaces/m/x.sh",
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
            "printf x > ~/.local/bin/safe-ai-skill",
            "chmod +x ~/.local/bin/*",
            "cat x >safe-ai-skill",
            "mkdir -p .o''pencode/plugins && cp /tmp/evil.js .o''pencode/plugins/",
            "mkdir -p .o\\pencode/plugins",
            "cp /tmp/evil.js ~/.config/open\"\"code/plugins/a.js",
            "cp x .o?encode/plugins/",
            "cp x ~/.conf*/open*/plugins/",
            "cp x ~/.config/*/plugins/",
            "echo x > ~/.claude/settings.json",
            "cp hooks.json ~/.claude/plugins/cache/x/hooks/",
            "echo 'export PATH=~/bin2:$PATH' >> ~/.zshrc",
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
            "safe-ai-skill status > out.txt",
            "npx @stbr/safe-ai-skill add skill x",
            "which safe-ai-skill",
            "ls ~/.local/bin/*",
            "rm -f build/*.o",
            "chmod +x scripts/*",
            "cp dist/* /usr/local/lib/",
            "cat ~/.zshrc; echo $PATH",
            "echo 'alias ll=ls' >> ~/.zshrc",
            "cargo build",
            "echo hello > out.txt",
        ] {
            assert!(t.bash_reason(c, cwd).is_none(), "{c}");
        }
    }

    #[test]
    fn path_lines_in_shell_startup_files_are_denied() {
        let cwd = Path::new("/w/proj");
        let t = targets();
        assert!(t
            .rc_path_reason("~/.zshrc", "export PATH=~/bin2:$PATH", cwd)
            .is_some());
        assert!(t
            .rc_path_reason(
                "/home/u/.config/fish/config.fish",
                "fish_add_path ~/b; set PATH",
                cwd
            )
            .is_some());
        assert!(t.rc_path_reason("~/.zshrc", "alias ll=ls", cwd).is_none());
        assert!(t.rc_path_reason("notes/.zshrc", "PATH=x", cwd).is_none());
    }

    #[test]
    fn code_only_includes_are_recognised() {
        let excl = "!{**/.[eE][nN][vV],**/[iI][dD].[jJ][sS][oO][nN],**/*.[pP][eE][mM],**/.[sS][sS][hH]/**}";
        assert!(include_is_code_only("*.ts", excl));
        assert!(include_is_code_only("**/*.{ts,tsx}", excl));
        assert!(include_is_code_only("*.RS", excl));
        assert!(!include_is_code_only("*.md", excl));
        assert!(!include_is_code_only("*.json", excl));
        assert!(!include_is_code_only("*.{ts,json}", excl));
        assert!(!include_is_code_only("*", excl));
        assert!(!include_is_code_only("src/**", excl));
        assert!(!include_is_code_only("*.pem", excl));
        // An exclusion that would match the extension wins.
        assert!(!include_is_code_only("*.ts", "!{**/*.[tT][sS]}"));
    }
}
