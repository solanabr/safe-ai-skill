//! `safe-ai-skill env keys|set|unset`: read and edit env-class files without printing values
//! (#7, spec D3.4).
//!
//! Raw reads of env-class files are denied by the read gate; this subcommand is the sanctioned
//! path. `keys` lists keys with masked values ([`render`]); `set` takes the value on stdin so it
//! never appears in argv, the transcript or any output; `unset` removes a key. Edits are
//! byte-minimal ([`parse`] is lossless), verified by re-parsing, and atomic ([`write`]). Only
//! env-class files are accepted ([`is_env_class`]), so `env` is not a general file reader or
//! writer. `env keys` is never gated; an agent's `env set|unset` is denied at tier Medium and
//! High (by the `gate-bash-secrets` hook, and here as a backstop under `CLAUDECODE`).
//!
//! Exit codes: 0 ok; 1 refused or missing file, rejected stdin value, I/O error; 3 usage error
//! (bad arguments or key name) or a `--require`d key that is missing, empty or a placeholder.

use std::fs::{self, File};
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::gates::secretpath::{self, Class, TEMPLATES};
use parse::{EnvFile, Format};
use render::{Shown, Unmet};
use write::Change;

pub mod parse;
pub mod render;
pub mod schema;
pub mod values;
pub mod write;

const EXIT_ERROR: u8 = 1;
const EXIT_USAGE: u8 = 3;

/// Largest file `env` reads.
const MAX_FILE_BYTES: usize = 8 << 20;

const USAGE: &str = "usage:
  safe-ai-skill env keys [FILE] [--json] [--require K1,K2]
  printf %s '<value>' | safe-ai-skill env set FILE KEY [--multiline] [--all]
  safe-ai-skill env unset FILE KEY
  safe-ai-skill env init-schema [FILE]

Lists, sets and unsets keys of an env-class file (.env, .env.*, *.env, .envrc, .dev.vars,
~/.config/solana/cli/config.yml) without printing values. FILE defaults to .env. `set` reads
the value from stdin (one trailing newline is stripped); --multiline allows line breaks and
--all updates every duplicate. `keys --require` exits 3 when a key is missing, empty or a
placeholder. `keys` reads a varlock .env.schema beside FILE and annotates each key;
`init-schema` writes that schema from FILE's keys (no values copied, never overwrites).
From a Claude Code session, `set` and `unset` are refused at tier medium and high.
";

/// Whether `path` names an env-class file (spec D3.1, case-insensitive): `.env`, `.env.*`,
/// `*.env`, `.envrc`, `.dev.vars[.*]`, `.varlock-frozen-env`, or
/// `~/.config/solana/cli/config.yml`. Templates (`.env.example|.sample|.template|.dist`) and
/// the varlock `.env.schema` are not env-class. Windows separators, an NTFS `:stream` suffix
/// and trailing dots/spaces are normalised away first ([`secretpath::classify`]).
pub fn is_env_class(path: &Path) -> bool {
    secretpath::classify(&path.to_string_lossy()) == Class::Env
}

/// The one-time SessionStart tip for a project with env-class files and no `.env.schema`
/// (spec D3.8.6). Shown once per project directory: a marker under
/// `<plugin_data>/tips/` records it, and when the marker cannot be written the tip is skipped
/// (a tip that repeats every session is noise). Only `cwd` itself is checked.
pub fn schema_tip(cwd: &Path, plugin_data: &Path) -> Option<String> {
    if cwd.join(".env.schema").exists() {
        return None;
    }
    let has_env = fs::read_dir(cwd)
        .ok()?
        .flatten()
        .any(|entry| entry.file_type().is_ok_and(|t| t.is_file()) && is_env_class(&entry.path()));
    if !has_env {
        return None;
    }
    let id = fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    let mut hash = crate::audit::sha256_hex(id.to_string_lossy().as_bytes());
    hash.truncate(16);
    let dir = plugin_data.join("tips");
    fs::create_dir_all(&dir).ok()?;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dir.join(format!("env-schema-{hash}")))
        .ok()?;
    Some(
        "safe-ai-skill tip: add a .env.schema so the agent can see your config without reading secrets: `safe-ai-skill env init-schema` (keys only, no values copied). Plain .env keeps working; varlock is optional."
            .to_string(),
    )
}

fn is_template(path: &Path) -> bool {
    TEMPLATES.contains(&basename(path).as_str())
}

/// Lowercased final path component without an NTFS `:stream` suffix or trailing dots/spaces.
fn basename(path: &Path) -> String {
    let text = path.to_string_lossy();
    let base = text.rsplit(['/', '\\']).next().unwrap_or_default();
    let base = base.split(':').next().unwrap_or_default();
    base.trim_end_matches(['.', ' ']).to_ascii_lowercase()
}

/// Whether `path` is `$HOME/.config/solana/cli/config.yml` (case-insensitive; `$HOME` as set
/// or canonicalised, since resolved paths go through symlinked homes).
fn is_solana_cli_config(path: &Path) -> bool {
    const SUFFIX: &str = "/.config/solana/cli/config.yml";
    let candidate = normalize(&expand_tilde(&path.to_string_lossy()));
    if !candidate.ends_with(SUFFIX) {
        return false;
    }
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return false;
    };
    let matches = |h: &Path| format!("{}{SUFFIX}", normalize(h).trim_end_matches('/')) == candidate;
    matches(&home) || fs::canonicalize(&home).is_ok_and(|h| matches(&h))
}

fn normalize(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase()
}

fn expand_tilde(arg: &str) -> PathBuf {
    match (arg.strip_prefix("~/"), std::env::var_os("HOME")) {
        (Some(rest), Some(home)) => PathBuf::from(home).join(rest),
        _ => PathBuf::from(arg),
    }
}

/// `KEY` must match `[A-Za-z_][A-Za-z0-9_.]*`.
fn is_valid_key(key: &str) -> bool {
    let mut bytes = key.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
}

/// Set by Claude Code in the environment of the commands it runs (the agent's Bash tool, and
/// the user's `!` commands).
const AGENT_ENV: &str = "CLAUDECODE";

/// The tier check for `env set|unset` run from a Claude Code session (D8 v2 spec §2: agent
/// writes to project env files are denied at Medium and High). The `gate-bash-secrets` hook
/// denies the command first; this is the backstop for a form the hook did not recognise. The
/// tier is resolved for the process cwd exactly as for a hook, so a repo or env can only raise
/// it. Run from the user's own terminal (no `CLAUDECODE`), `env` is never refused.
fn agent_write_refusal(args: &[String]) -> Option<String> {
    let action = args.first().map(String::as_str)?;
    if !matches!(action, "set" | "unset") {
        return None;
    }
    std::env::var_os(AGENT_ENV).filter(|v| !v.is_empty())?;
    let cwd = std::env::current_dir().ok()?;
    let dir = crate::datadir::data_dir_with_cwd(Some(&cwd))
        .unwrap_or_else(|_| crate::datadir::unresolved());
    let root = crate::policy::tier::project_root(&cwd);
    let (policy, _) = crate::policy::load_runtime(
        &cwd,
        &dir,
        &|k| std::env::var(k).ok(),
        crate::sandbox::state(&root),
        false,
    );
    tier_refusal(action, policy.tier())
}

/// The refusal text for an agent's `env <action>` at `tier`, if that tier denies it.
fn tier_refusal(action: &str, tier: crate::policy::tier::Tier) -> Option<String> {
    (tier >= crate::policy::tier::Tier::Medium).then(|| {
        format!(
            "refusing `env {action}` from a Claude Code session: tier {} denies agent writes to project env files. Run it in your own terminal, or edit the file yourself. `safe-ai-skill env keys` still works.",
            tier.label()
        )
    })
}

/// A failed command. Messages never contain a value or an argument that could be one.
#[derive(Debug)]
struct Failure {
    code: u8,
    message: String,
    show_usage: bool,
}

impl Failure {
    fn usage(message: impl Into<String>) -> Self {
        Failure {
            code: EXIT_USAGE,
            message: message.into(),
            show_usage: true,
        }
    }

    fn error(message: impl Into<String>) -> Self {
        Failure {
            code: EXIT_ERROR,
            message: message.into(),
            show_usage: false,
        }
    }

    fn unmet(message: impl Into<String>) -> Self {
        Failure {
            code: EXIT_USAGE,
            message: message.into(),
            show_usage: false,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Help,
    Keys {
        file: String,
        json: bool,
        require: Vec<String>,
    },
    Set {
        file: String,
        key: String,
        multiline: bool,
        all: bool,
    },
    Unset {
        file: String,
        key: String,
    },
    InitSchema {
        file: String,
    },
}

const BAD_KEY: &str = "invalid key name (keys match [A-Za-z_][A-Za-z0-9_.]*)";

/// Parse the arguments after `env`. Errors never echo an argument: a value pasted into argv
/// by mistake (`env set FILE KEY VALUE`, `KEY=VALUE`, `--value=…`) must not be printed back.
fn parse_args(args: &[String]) -> Result<Command, Failure> {
    let Some((action, rest)) = args.split_first() else {
        return Err(Failure::usage("missing action (keys, set or unset)"));
    };
    let action = match action.as_str() {
        "keys" => "keys",
        "set" => "set",
        "unset" => "unset",
        "init-schema" => "init-schema",
        "help" | "--help" | "-h" => return Ok(Command::Help),
        _ => {
            return Err(Failure::usage(
                "unknown action (expected keys, set, unset or init-schema)",
            ))
        }
    };
    let (mut json, mut multiline, mut all) = (false, false, false);
    let mut require = Vec::new();
    let mut positional = Vec::new();
    let mut iter = rest.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--json" if action == "keys" => json = true,
            "--multiline" if action == "set" => multiline = true,
            "--all" if action == "set" => all = true,
            "--require" if action == "keys" => {
                let list = iter
                    .next()
                    .ok_or_else(|| Failure::usage("--require needs a comma-separated key list"))?;
                require = parse_key_list(list)?;
            }
            other if action == "keys" && other.starts_with("--require=") => {
                require = parse_key_list(&other["--require=".len()..])?;
            }
            other if other.starts_with('-') && other.len() > 1 => {
                return Err(Failure::usage(format!("unknown option for `env {action}`")));
            }
            other => positional.push(other.to_string()),
        }
    }
    let extra = || {
        Failure::usage(
            "unexpected argument (the value is read from stdin, never from the command line)",
        )
    };
    match action {
        "init-schema" => {
            if positional.len() > 1 {
                return Err(extra());
            }
            let file = positional.pop().unwrap_or_else(|| ".env".to_string());
            Ok(Command::InitSchema { file })
        }
        "keys" => {
            if positional.len() > 1 {
                return Err(extra());
            }
            let file = positional.pop().unwrap_or_else(|| ".env".to_string());
            Ok(Command::Keys {
                file,
                json,
                require,
            })
        }
        _ => {
            if positional.len() > 2 {
                return Err(extra());
            }
            let mut positional = positional.into_iter();
            let (Some(file), Some(key)) = (positional.next(), positional.next()) else {
                return Err(Failure::usage(format!("`env {action}` needs FILE and KEY")));
            };
            if !is_valid_key(&key) {
                return Err(Failure::usage(BAD_KEY));
            }
            if action == "set" {
                Ok(Command::Set {
                    file,
                    key,
                    multiline,
                    all,
                })
            } else {
                Ok(Command::Unset { file, key })
            }
        }
    }
}

fn parse_key_list(list: &str) -> Result<Vec<String>, Failure> {
    let keys: Vec<String> = list
        .split(',')
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .map(str::to_string)
        .collect();
    if keys.is_empty() {
        return Err(Failure::usage("--require needs at least one key"));
    }
    if !keys.iter().all(|k| is_valid_key(k)) {
        return Err(Failure::usage(format!("--require: {BAD_KEY}")));
    }
    Ok(keys)
}

/// A file `env` may operate on.
struct Target {
    /// Canonical path (symlinks resolved; for a new file, canonical parent plus name).
    path: PathBuf,
    /// How messages name the file: its basename, set only once it passed the env-class check.
    label: String,
    format: Format,
    /// Permission bits of the existing file; `None` when it does not exist yet.
    mode: Option<u32>,
}

/// Resolve FILE and check it is env-class. A symlink is followed and its target must be
/// env-class too, since that is the file read and written. Until a name has passed the check,
/// messages never name the file: a value pasted where FILE goes must not be printed back.
/// After it, they name only the basename.
fn resolve(file: &str) -> Result<Target, Failure> {
    let raw = expand_tilde(file);
    match fs::symlink_metadata(&raw) {
        Ok(meta) => {
            let link = meta.file_type().is_symlink();
            let path = match fs::canonicalize(&raw) {
                Ok(path) => path,
                Err(_) if link && is_env_class(&raw) => {
                    return Err(Failure::error(format!(
                        "refusing {}: its symlink target does not exist",
                        file_name(&raw)
                    )));
                }
                Err(e) if is_env_class(&raw) => {
                    return Err(Failure::error(format!("{}: {e}", file_name(&raw))));
                }
                Err(_) => return Err(refusal(&raw)),
            };
            if !is_env_class(&path) {
                return Err(if link && is_env_class(&raw) {
                    Failure::error(format!(
                        "refusing {}: its symlink target is not an env-class file",
                        file_name(&raw)
                    ))
                } else {
                    refusal(&path)
                });
            }
            let label = label_of(&raw, &path);
            let meta = fs::metadata(&path).map_err(|e| Failure::error(format!("{label}: {e}")))?;
            if !meta.is_file() {
                return Err(Failure::error(format!(
                    "refusing {label}: not a regular file"
                )));
            }
            Ok(Target {
                label,
                format: format_of(&path),
                mode: Some(mode_of(&meta)),
                path,
            })
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let Some(name) = raw.file_name() else {
                return Err(refusal(&raw));
            };
            let parent = match raw.parent() {
                Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
                _ => PathBuf::from("."),
            };
            let parent = match fs::canonicalize(&parent) {
                Ok(parent) => parent,
                Err(_) if is_env_class(&raw) => {
                    return Err(Failure::error(format!(
                        "{}: no such directory",
                        file_name(&raw)
                    )));
                }
                Err(_) => return Err(refusal(&raw)),
            };
            let path = parent.join(name);
            if !is_env_class(&path) {
                return Err(refusal(&path));
            }
            Ok(Target {
                label: label_of(&raw, &path),
                format: format_of(&path),
                mode: None,
                path,
            })
        }
        Err(e) => Err(Failure::error(format!(
            "refusing: cannot access the file ({e})"
        ))),
    }
}

/// The refusal for a file that is not env-class. It never names the file.
fn refusal(path: &Path) -> Failure {
    if basename(path) == ".env.schema" {
        Failure::error(
            "refusing: .env.schema holds keys and decorators, never values; read or edit it directly (env keys reads it next to the env file)",
        )
    } else if is_template(path) {
        Failure::error(
            "refusing: an env template (.env.example, .env.sample, .env.template, .env.dist) is not secret; read or edit it directly",
        )
    } else {
        Failure::error(
            "refusing: not an env-class file (env accepts .env, .env.*, *.env, .envrc, .dev.vars and ~/.config/solana/cli/config.yml)",
        )
    }
}

/// The final component of `path`, as given.
fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The basename to print: FILE's own when it is env-class, else its symlink target's (also
/// env-class at this point).
fn label_of(raw: &Path, target: &Path) -> String {
    if is_env_class(raw) {
        file_name(raw)
    } else {
        file_name(target)
    }
}

fn format_of(path: &Path) -> Format {
    if is_solana_cli_config(path) {
        Format::Yaml
    } else {
        Format::Dotenv
    }
}

#[cfg(unix)]
fn mode_of(meta: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn mode_of(_meta: &fs::Metadata) -> u32 {
    0o600
}

fn read_env(target: &Target) -> Result<EnvFile, Failure> {
    let label = &target.label;
    let mut bytes = Vec::new();
    File::open(&target.path)
        .and_then(|f| f.take((MAX_FILE_BYTES + 1) as u64).read_to_end(&mut bytes))
        .map_err(|e| Failure::error(format!("{label}: {e}")))?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(Failure::error(format!("{label}: larger than 8 MiB")));
    }
    Ok(EnvFile::parse_as(&bytes, target.format))
}

fn not_for_yaml(label: &str) -> Failure {
    Failure::error(format!(
        "refusing {label}: the Solana CLI config is changed with `solana config set`, not `env`"
    ))
}

fn reparse_refusal(label: &str) -> Failure {
    Failure::error(format!(
        "refusing to edit {label}: the change would alter how other lines parse (look for an unterminated quote); file unchanged"
    ))
}

fn warn(err: &mut dyn Write, message: &str) {
    let _ = writeln!(err, "safe-ai-skill env: warning: {message}");
}

fn keys(file: &str, json: bool, require: &[String], out: &mut dyn Write) -> Result<u8, Failure> {
    let target = resolve(file)?;
    let label = target.label.as_str();
    if target.mode.is_none() {
        let mut message = format!("{label}: no such file");
        if require.is_empty() {
            return Err(Failure::error(message));
        }
        let missing: Vec<(String, Unmet)> = require
            .iter()
            .map(|k| (k.clone(), Unmet::Missing))
            .collect();
        message.push_str(&format!(
            "; required keys not usable: {}",
            render::unmet_text(&missing)
        ));
        return Err(Failure::unmet(message));
    }
    let parsed = read_env(&target)?;
    let unmet = render::unmet(&parsed, require);
    let schema = match target.format {
        Format::Dotenv => schema_beside(&target.path),
        Format::Yaml => None,
    };
    let view = schema.as_ref().map(|schema| render::SchemaView {
        label: ".env.schema",
        schema,
    });
    let written = if json {
        let report = (!require.is_empty()).then_some(unmet.as_slice());
        writeln!(
            out,
            "{}",
            render::keys_json_with(label, &parsed, report, view)
        )
    } else {
        out.write_all(render::keys_text_with(label, &parsed, view).as_bytes())
    };
    written.map_err(|e| Failure::error(format!("cannot write output: {e}")))?;
    if unmet.is_empty() {
        return Ok(0);
    }
    Err(Failure::unmet(format!(
        "required keys not usable in {label}: {}",
        render::unmet_text(&unmet)
    )))
}

/// The `.env.schema` in the directory of `path`, parsed, when it is a regular file of at most
/// [`schema::MAX_SCHEMA_BYTES`].
fn schema_beside(path: &Path) -> Option<schema::Schema> {
    let schema_path = path.parent()?.join(".env.schema");
    let meta = fs::metadata(&schema_path).ok()?;
    if !meta.is_file() || meta.len() > schema::MAX_SCHEMA_BYTES as u64 {
        return None;
    }
    let mut bytes = Vec::new();
    File::open(&schema_path)
        .ok()?
        .take(schema::MAX_SCHEMA_BYTES as u64)
        .read_to_end(&mut bytes)
        .ok()?;
    Some(schema::Schema::parse(&bytes))
}

/// `env init-schema [FILE]`: write `.env.schema` beside FILE from its assigned keys. No value
/// is copied; every key is sensitive by default (`@defaultSensitive=true`, stricter than
/// `varlock init`); an existing schema is never overwritten.
fn init_schema(file: &str, out: &mut dyn Write) -> Result<u8, Failure> {
    let target = resolve(file)?;
    let label = target.label.as_str();
    if target.format == Format::Yaml {
        return Err(Failure::error(format!(
            "refusing {label}: the Solana CLI config is not a dotenv file"
        )));
    }
    if target.mode.is_none() {
        return Err(Failure::error(format!("{label}: no such file")));
    }
    let parsed = read_env(&target)?;
    let mut keys: Vec<&str> = Vec::new();
    for (_, entry) in parsed.entries() {
        if !keys.contains(&entry.key.as_str()) {
            keys.push(&entry.key);
        }
    }
    let mut text = format!(
        "# env-spec schema generated by `safe-ai-skill env init-schema` from {label}.\n\
         # Keys only: no values were copied. Commit this file; keep values in {label} or .env.local.\n\
         # Every key is sensitive by default; mark a non-secret key with `# @public` above it.\n\
         # Format: https://varlock.dev/env-spec/ (varlock is optional; dotenv tools read this file too).\n\
         # @defaultSensitive=true\n\
         # ---\n\n"
    );
    for key in &keys {
        text.push_str(key);
        text.push_str("=\n");
    }
    let dir = target.path.parent().unwrap_or(Path::new("."));
    let dest = dir.join(".env.schema");
    match write::create_new_atomic(&dest, text.as_bytes(), 0o644) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            return Err(Failure::error(
                ".env.schema already exists beside the file; not overwritten (edit it directly)",
            ))
        }
        Err(e) => return Err(Failure::error(format!("cannot write .env.schema: {e}"))),
    }
    let _ = writeln!(
        out,
        "wrote .env.schema ({} keys, no values copied) from {label}",
        keys.len()
    );
    Ok(0)
}

fn set(
    file: &str,
    key: &str,
    multiline: bool,
    all: bool,
    stdin: Stdin<'_>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<u8, Failure> {
    let target = resolve(file)?;
    let label = target.label.as_str();
    if target.format == Format::Yaml {
        return Err(not_for_yaml(label));
    }
    if stdin.is_tty {
        let _ = writeln!(
            err,
            "safe-ai-skill env: reading the value of {key} from stdin (end with Ctrl-D)"
        );
    }
    let mut raw = Vec::new();
    stdin
        .reader
        .take((write::MAX_VALUE_BYTES + 1) as u64)
        .read_to_end(&mut raw)
        .map_err(|e| Failure::error(format!("cannot read the value from stdin: {e}")))?;
    let value = write::normalize_value(&raw, multiline).map_err(|e| Failure::error(e.message()))?;

    let current = match target.mode {
        Some(_) => read_env(&target)?,
        None => EnvFile::parse(b""),
    };
    let envrc = basename(&target.path) == ".envrc";
    let export = write::export_for_new(&current, envrc);
    let plan =
        write::plan_set(&current, key, &value, all, export).map_err(|_| reparse_refusal(label))?;
    if target.mode.is_none() || plan.bytes != current.to_bytes() {
        write::atomic_replace(&target.path, &plan.bytes, target.mode.unwrap_or(0o600))
            .map_err(|e| Failure::error(format!("cannot write {label}: {e}")))?;
    }

    if !plan.duplicates.is_empty() && !all {
        let lines: Vec<String> = plan.duplicates.iter().map(|l| format!("L{l}")).collect();
        warn(
            err,
            &format!(
                "{key} is assigned {} times ({}); updated the last one, which dotenv loaders and `source` use (dotenvy keeps the first). Pass --all to update every one.",
                plan.duplicates.len(),
                lines.join(", ")
            ),
        );
    }
    let new_shown = Shown::of(&value);
    if target.mode.is_none() {
        let _ = writeln!(out, "created {label} (mode 0600)");
    }
    for change in &plan.changes {
        let _ = match change {
            Change::Added { line } => writeln!(out, "added {key} L{line} {new_shown}"),
            Change::Updated { line, old } => {
                let old_shown = Shown::of(old);
                if let (Some(a), Some(b)) = (old_shown.host(), new_shown.host()) {
                    if a != b {
                        warn(err, &format!("{key}: URL host changed {a} → {b}"));
                    }
                }
                writeln!(out, "updated {key} L{line} {}", render::change(old, &value))
            }
            Change::Unchanged { line } => writeln!(out, "unchanged {key} L{line}"),
        };
    }
    Ok(0)
}

fn unset(file: &str, key: &str, out: &mut dyn Write) -> Result<u8, Failure> {
    let target = resolve(file)?;
    let label = target.label.as_str();
    if target.format == Format::Yaml {
        return Err(not_for_yaml(label));
    }
    let Some(mode) = target.mode else {
        return Err(Failure::error(format!("{label}: no such file")));
    };
    let current = read_env(&target)?;
    let plan = write::plan_unset(&current, key).map_err(|_| reparse_refusal(label))?;
    if plan.removed.is_empty() {
        let _ = writeln!(out, "{key} not set in {label} (no change)");
        return Ok(0);
    }
    write::atomic_replace(&target.path, &plan.bytes, mode)
        .map_err(|e| Failure::error(format!("cannot write {label}: {e}")))?;
    let lines: Vec<String> = plan.removed.iter().map(|l| format!("L{l}")).collect();
    let _ = writeln!(out, "removed {key} {}", lines.join(", "));
    Ok(0)
}

/// Where `env set` reads the value.
pub struct Stdin<'a> {
    pub reader: &'a mut dyn Read,
    /// A terminal gets a hint that `set` is waiting for the value.
    pub is_tty: bool,
}

/// Run `env` with the arguments after `env`; returns the exit code.
pub fn run(args: &[String], stdin: Stdin<'_>, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let result = parse_args(args).and_then(|command| match command {
        Command::Help => {
            let _ = out.write_all(USAGE.as_bytes());
            Ok(0)
        }
        Command::Keys {
            file,
            json,
            require,
        } => keys(&file, json, &require, out),
        Command::Set {
            file,
            key,
            multiline,
            all,
        } => set(&file, &key, multiline, all, stdin, out, err),
        Command::Unset { file, key } => unset(&file, &key, out),
        Command::InitSchema { file } => init_schema(&file, out),
    });
    match result {
        Ok(code) => code,
        Err(failure) => {
            let _ = writeln!(err, "safe-ai-skill env: {}", failure.message);
            if failure.show_usage {
                let _ = err.write_all(USAGE.as_bytes());
            }
            failure.code
        }
    }
}

/// `safe-ai-skill env …` entry point.
pub fn main(args: &[String]) -> ExitCode {
    if let Some(refusal) = agent_write_refusal(args) {
        let _ = writeln!(io::stderr().lock(), "safe-ai-skill env: {refusal}");
        return ExitCode::from(EXIT_ERROR);
    }
    let stdin = io::stdin();
    let is_tty = stdin.is_terminal();
    let stdin = Stdin {
        reader: &mut stdin.lock(),
        is_tty,
    };
    let code = run(
        args,
        stdin,
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    );
    ExitCode::from(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_writes_are_refused_at_medium_and_high_only() {
        use crate::policy::tier::Tier;
        for action in ["set", "unset"] {
            assert!(tier_refusal(action, Tier::Off).is_none());
            assert!(tier_refusal(action, Tier::Relaxed).is_none());
            let why = tier_refusal(action, Tier::Medium).unwrap();
            assert!(why.contains("tier medium") && why.contains(action), "{why}");
            assert!(tier_refusal(action, Tier::High).is_some());
        }
        assert!(agent_write_refusal(&["keys".to_string()]).is_none());
        assert!(agent_write_refusal(&[]).is_none());
    }

    #[test]
    fn env_class_names() {
        for p in [
            ".env",
            "/a/b/.env",
            ".ENV",
            ".Env.Local",
            "prod.env",
            "PROD.ENV",
            ".envrc",
            ".dev.vars",
            ".env.production.local",
            ".env.example.local",
            "C:\\proj\\.env",
            "C:\\proj\\.env::$DATA",
            ".env.",
            "dir/sub/.envrc",
        ] {
            assert!(is_env_class(Path::new(p)), "{p}");
        }
        for p in [
            ".env.example",
            ".ENV.SAMPLE",
            ".env.template",
            ".env.dist",
            "env",
            ".envx",
            "environment",
            "notes.txt",
            "id.json",
            "wallet-keypair.json",
            ".env/x",
        ] {
            assert!(!is_env_class(Path::new(p)), "{p}");
        }
    }

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_args_accepts_the_three_forms() {
        assert_eq!(
            parse_args(&args(&["keys"])).unwrap(),
            Command::Keys {
                file: ".env".into(),
                json: false,
                require: vec![]
            }
        );
        assert_eq!(
            parse_args(&args(&["keys", "a.env", "--json", "--require=A, B"])).unwrap(),
            Command::Keys {
                file: "a.env".into(),
                json: true,
                require: vec!["A".into(), "B".into()]
            }
        );
        assert_eq!(
            parse_args(&args(&["set", "--all", "a.env", "K", "--multiline"])).unwrap(),
            Command::Set {
                file: "a.env".into(),
                key: "K".into(),
                multiline: true,
                all: true
            }
        );
        assert_eq!(
            parse_args(&args(&["unset", "a.env", "K"])).unwrap(),
            Command::Unset {
                file: "a.env".into(),
                key: "K".into()
            }
        );
    }

    #[test]
    fn parse_args_errors_never_echo_arguments() {
        let secret = "sk_\x6cive_51Hx9QbF2eZvKYlo";
        let cases = [
            args(&[secret]),
            args(&["set", ".env", "K", secret]),
            args(&["set", ".env", &format!("K={secret}")]),
            args(&["set", ".env", "K", &format!("--value={secret}")]),
            args(&["keys", "--require", &format!("A,{secret}-x")]),
        ];
        for case in cases {
            let failure = parse_args(&case).unwrap_err();
            assert_eq!(failure.code, EXIT_USAGE);
            assert!(!failure.message.contains(secret), "{}", failure.message);
        }
    }
}

#[cfg(test)]
pub(crate) mod testgen {
    //! Deterministic generators for the env property tests (seeded LCG; no extra crates).

    /// Knuth MMIX linear congruential generator.
    pub struct Lcg(u64);

    impl Lcg {
        pub fn new(seed: u64) -> Self {
            Lcg(seed ^ 0x9e37_79b9_7f4a_7c15)
        }

        pub fn next_u32(&mut self) -> u32 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (self.0 >> 33) as u32
        }

        /// Uniform in `0..n` (`n > 0`).
        pub fn below(&mut self, n: usize) -> usize {
            self.next_u32() as usize % n
        }

        /// True with probability `1 / n`.
        pub fn one_in(&mut self, n: usize) -> bool {
            self.below(n) == 0
        }

        pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
            &items[self.below(items.len())]
        }
    }

    /// Characters a value may contain (no NUL, no CR); `\n` only for multiline values.
    const VALUE_CHARS: &[&str] = &[
        "a", "Z", "q", "0", "7", "_", "-", ".", "/", ":", "@", "%", "+", ",", "=", "?", "&", "~",
        "$", "#", "'", "\"", "\\", "`", " ", "\t", "!", "*", "(", ")", "{", "}", ";", "|", "<",
        ">", "é", "✓",
    ];

    /// A random value; `multiline` allows line breaks.
    pub fn value(rng: &mut Lcg, multiline: bool) -> Vec<u8> {
        let len = rng.below(24);
        let mut out = Vec::new();
        for _ in 0..len {
            if multiline && rng.one_in(8) {
                out.push(b'\n');
            } else {
                out.extend_from_slice(rng.pick(VALUE_CHARS).as_bytes());
            }
        }
        out
    }

    /// A random high-entropy secret (never one of the verbatim words, never a URL).
    pub fn secret(rng: &mut Lcg) -> Vec<u8> {
        const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789_-+/";
        let len = 8 + rng.below(40);
        (0..len).map(|_| *rng.pick(ALPHABET)).collect()
    }

    pub const KEYS: &[&str] = &["A", "B_2", "HELIUS_API_KEY", "x.y", "_K", "DATABASE_URL"];

    /// A generated file and the assignments a correct parser must find in it.
    pub struct GenFile {
        pub bytes: Vec<u8>,
        /// `(key, value, export)` in file order.
        pub entries: Vec<(String, Vec<u8>, bool)>,
        pub commented: Vec<String>,
        /// No stray quotes: every edit must succeed.
        pub clean: bool,
    }

    const BARE_CHARS: &[u8] = b"aZq07_-./:@%+,=?&~$!*\"'\\#";
    const CLEAN_JUNK: &[&str] = &[
        "use nix",
        "source_up",
        "if true; then",
        "fi",
        "KEY",
        "1BAD=x",
        "MY-KEY=x",
        "=x",
        "",
        "   ",
        "# a comment",
        "#",
        "  # indented comment",
    ];
    const DIRTY_JUNK: &[&str] = &[
        "A=\"unterminated",
        "B='open",
        "\"stray",
        "C=\"x\" junk",
        "'",
        "D=\"a\\",
    ];

    /// Encode `value` as a bare dotenv value, or `None` if it can't be one.
    fn bare(value: &[u8]) -> Option<Vec<u8>> {
        let ok = value.iter().all(|b| BARE_CHARS.contains(b))
            && !matches!(value.first(), Some(b'\'' | b'"' | b'#'));
        ok.then(|| value.to_vec())
    }

    /// One `[indent][export ]KEY<sep>value[trailer]` line (without EOL) and its decoded value.
    fn entry_line(rng: &mut Lcg, eol: &[u8], key: &str, export: bool) -> (Vec<u8>, Vec<u8>) {
        let mut line = Vec::new();
        line.extend_from_slice(rng.pick(&["", " ", "\t"]).as_bytes());
        if export {
            line.extend_from_slice(rng.pick(&["export ", "export\t", "export  "]).as_bytes());
        }
        line.extend_from_slice(key.as_bytes());
        line.extend_from_slice(rng.pick(&["=", " = ", "= ", " ="]).as_bytes());
        let style = rng.below(3);
        let mut decoded = Vec::new();
        match style {
            0 => {
                // bare: no whitespace, never starts with a quote; `#` only right after a non-blank
                let len = rng.below(16);
                let raw: Vec<u8> = (0..len).map(|_| *rng.pick(BARE_CHARS)).collect();
                let raw = bare(&raw).unwrap_or_default();
                line.extend_from_slice(&raw);
                decoded = raw;
                if rng.one_in(3) {
                    line.extend_from_slice(rng.pick(&[" # note", "\t#x", "   "]).as_bytes());
                }
                return (line, decoded);
            }
            1 => {
                let value: Vec<u8> = value(rng, true)
                    .into_iter()
                    .filter(|&b| b != b'\'')
                    .collect();
                line.push(b'\'');
                for &b in &value {
                    if b == b'\n' {
                        line.extend_from_slice(eol);
                    } else {
                        line.push(b);
                    }
                }
                line.push(b'\'');
                decoded = value;
            }
            _ => {
                let value = value(rng, true);
                line.push(b'"');
                for &b in &value {
                    match b {
                        b'\\' => line.extend_from_slice(b"\\\\"),
                        b'"' => line.extend_from_slice(b"\\\""),
                        b'$' | b'`' if rng.one_in(2) => line.extend_from_slice(&[b'\\', b]),
                        b'\n' => line.extend_from_slice(eol),
                        _ => line.push(b),
                    }
                    decoded.push(b);
                    if rng.one_in(12) {
                        // A literal backslash pair: kept as written.
                        let c = *rng.pick(b"ntq0 ");
                        line.extend_from_slice(&[b'\\', c]);
                        decoded.extend_from_slice(&[b'\\', c]);
                    }
                }
                line.push(b'"');
            }
        }
        if rng.one_in(3) {
            line.extend_from_slice(rng.pick(&["  # note", " #x", "\t", " "]).as_bytes());
        }
        (line, decoded)
    }

    /// A random dotenv file built from grammar fragments. `allow_dirty` mixes in stray quotes.
    pub fn file(rng: &mut Lcg, allow_dirty: bool) -> GenFile {
        let crlf = rng.one_in(3);
        let mut out = Vec::new();
        if rng.one_in(5) {
            out.extend_from_slice(b"\xef\xbb\xbf");
        }
        let mut entries = Vec::new();
        let mut commented = Vec::new();
        let mut clean = true;
        let lines = rng.below(10);
        for _ in 0..lines {
            let eol: &[u8] = if crlf != rng.one_in(9) {
                b"\r\n"
            } else {
                b"\n"
            };
            match rng.below(10) {
                0..=5 => {
                    let key = *rng.pick(KEYS);
                    let export = rng.one_in(4);
                    let (line, value) = entry_line(rng, eol, key, export);
                    out.extend_from_slice(&line);
                    entries.push((key.to_string(), value, export));
                }
                6 => {
                    let key = *rng.pick(KEYS);
                    let line = rng.pick(&["#{k}=old", "# export {k}=x", "#  {k} = y"]);
                    out.extend_from_slice(line.replace("{k}", key).as_bytes());
                    commented.push(key.to_string());
                }
                7 if allow_dirty && rng.one_in(2) => {
                    out.extend_from_slice(rng.pick(DIRTY_JUNK).as_bytes());
                    clean = false;
                }
                _ => out.extend_from_slice(rng.pick(CLEAN_JUNK).as_bytes()),
            }
            out.extend_from_slice(eol);
        }
        if rng.one_in(3) {
            // No trailing newline.
            if out.ends_with(b"\r\n") {
                out.truncate(out.len() - 2);
            } else if out.ends_with(b"\n") {
                out.truncate(out.len() - 1);
            }
        }
        if !clean {
            // Stray quotes can capture later lines: only the bytes are meaningful.
            entries.clear();
            commented.clear();
        }
        GenFile {
            bytes: out,
            entries,
            commented,
            clean,
        }
    }

    /// Arbitrary bytes biased towards the grammar's special characters.
    pub fn bytes(rng: &mut Lcg) -> Vec<u8> {
        const SPECIAL: &[u8] = b"=\"'\\#\r\n \texport_AZ\x00\xef\xbb\xbf\xff$`";
        let len = rng.below(64);
        (0..len)
            .map(|_| {
                if rng.one_in(4) {
                    rng.next_u32() as u8
                } else {
                    *rng.pick(SPECIAL)
                }
            })
            .collect()
    }
}
