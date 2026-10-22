//! Literal secret values for the redact hook's value-based scrubbing (spec D3.5, D3.8.3).
//!
//! Collects the literal values of the project's env-class files (`.env`, `.env.local`,
//! `.env.<env>`, `*.env`, `.envrc`, `.dev.vars`, … found under the hook cwd) so PostToolUse
//! output can have them replaced by `«redacted:KEY»`. Only values a redactor can match and that
//! are plausibly secret are kept:
//! - at least [`MIN_VALUE_LEN`] bytes, and a literal (function calls such as `exec(…)`,
//!   `$(…)` and `$X` expansions have no literal and are never evaluated);
//! - not empty, a placeholder, or a verbatim-safe word (booleans, cluster monikers, log levels,
//!   small integers);
//! - a URL with no credentials (no userinfo, no query, no long path token) is public and kept
//!   out, unless a `.env.schema` in the same directory marks the key sensitive.
//!
//! A schema only widens the set: `@public` / `@sensitive=false` never remove a value the base
//! rule keeps (repo files only tighten). The walk is bounded (depth, entries, files, bytes), and
//! an unreadable file is skipped: the scrub is defence in depth and fails open.

use std::path::Path;

use super::parse::EnvFile;
use super::render::Shown;
use super::schema::{self, Schema, ValueKind};
use crate::gates::secretpath::{self, Class};

/// Shortest value scrubbed (shorter literals match too much ordinary output).
pub const MIN_VALUE_LEN: usize = 8;

const MAX_DEPTH: usize = 4;
const MAX_ENTRIES: usize = 5_000;
const MAX_FILES: usize = 64;
const MAX_FILE_BYTES: u64 = 1024 * 1024;
const MAX_VALUES: usize = 512;

/// Directories never descended into.
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "target",
    "dist",
    "build",
    ".next",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    ".cache",
];

/// A value to scrub and the key it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownValue {
    pub key: String,
    pub value: String,
}

/// The scrubbable values of every env-class file under `cwd`, longest first.
pub fn load(cwd: &Path) -> Vec<KnownValue> {
    let mut out: Vec<KnownValue> = Vec::new();
    let mut files = 0usize;
    let walker = walkdir::WalkDir::new(cwd)
        .max_depth(MAX_DEPTH)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            !(e.file_type().is_dir()
                && e.depth() > 0
                && e.file_name()
                    .to_str()
                    .is_some_and(|n| SKIP_DIRS.contains(&n)))
        })
        .take(MAX_ENTRIES);
    for entry in walker.flatten() {
        if files >= MAX_FILES || out.len() >= MAX_VALUES {
            break;
        }
        // Symlinks are followed only to a regular file (metadata, not the link itself).
        let path = entry.path();
        let is_file = std::fs::metadata(path).is_ok_and(|m| m.is_file());
        let env_class = secretpath::classify(&path.to_string_lossy()) == Class::Env;
        if !is_file || !env_class {
            continue;
        }
        files += 1;
        let Some(bytes) = read_bounded(path, MAX_FILE_BYTES) else {
            continue;
        };
        let schema = path
            .parent()
            .and_then(|dir| read_bounded(&dir.join(".env.schema"), schema::MAX_SCHEMA_BYTES as u64))
            .map(|b| Schema::parse(&b));
        collect(&bytes, schema.as_ref(), &mut out);
    }
    out.sort_by(|a, b| b.value.len().cmp(&a.value.len()).then(a.key.cmp(&b.key)));
    out.dedup_by(|a, b| a.value == b.value);
    out.truncate(MAX_VALUES);
    out
}

/// Add the scrubbable values of one env file.
pub fn collect(bytes: &[u8], schema: Option<&Schema>, out: &mut Vec<KnownValue>) {
    let file = EnvFile::parse(bytes);
    for (_, entry) in file.entries() {
        let ValueKind::Literal(value) = schema::value_kind(&file.body, entry) else {
            continue;
        };
        let sensitive = schema.is_some_and(|s| s.is_sensitive(&entry.key));
        if !scrubbable(&value, sensitive) {
            continue;
        }
        if let Ok(text) = String::from_utf8(value) {
            out.push(KnownValue {
                key: entry.key.clone(),
                value: text,
            });
        }
    }
}

/// Whether a literal value is scrubbed; `sensitive` (from a schema) also scrubs public URLs.
fn scrubbable(value: &[u8], sensitive: bool) -> bool {
    if value.len() < MIN_VALUE_LEN {
        return false;
    }
    match Shown::of(value) {
        Shown::Empty | Shown::Placeholder | Shown::Verbatim(_) => false,
        Shown::Url { .. } => sensitive || !is_public_url(value),
        Shown::Set { .. } => true,
    }
}

/// A URL carrying no credential: no userinfo, no query, and no path segment long enough to be
/// a key (`https://…/v2/<32-char key>`).
fn is_public_url(value: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(value) else {
        return false;
    };
    let Some((_, rest)) = text.split_once("://") else {
        return false;
    };
    if rest.contains(['@', '?', '#']) {
        return false;
    }
    rest.split('/').skip(1).all(|seg| seg.len() < 16)
}

fn read_bounded(path: &Path, max: u64) -> Option<Vec<u8>> {
    use std::io::Read;
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > max {
        return None;
    }
    let mut buf = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(max)
        .read_to_end(&mut buf)
        .ok()?;
    Some(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(env: &str, schema: Option<&str>) -> Vec<(String, String)> {
        let schema = schema.map(|s| Schema::parse(s.as_bytes()));
        let mut out = Vec::new();
        collect(env.as_bytes(), schema.as_ref(), &mut out);
        out.into_iter().map(|v| (v.key, v.value)).collect()
    }

    #[test]
    fn keeps_secret_literals_only() {
        let got = values(
            "A=supersecretvalue\nB=short\nC=production\nD=12345\nE=<your-key>\nF=exec(op read x)\nG=$(cat k)\nH=\"${A}-x\"\nI='lit$(x)eral'\nJ=https://api.devnet.solana.com\nK=https://u:p@db.example.com/x\nL=https://g.alchemy.com/v2/abcdefghijklmnopqrstuvwx\nM=https://rpc.example.com/?api-key=zzz\n",
            None,
        );
        let keys: Vec<&str> = got.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, vec!["A", "I", "K", "L", "M"]);
    }

    #[test]
    fn schema_sensitivity_adds_public_urls_but_never_removes() {
        let env = "RPC=https://rpc.example.com/v1\nTOKEN=tok_abcdefghij\n";
        assert_eq!(values(env, None).len(), 1);
        assert_eq!(values(env, Some("# ---\nRPC=\nTOKEN=\n")).len(), 2);
        let public = "# @defaultSensitive=false\n# ---\n# @public\nRPC=\n# @public\nTOKEN=\n";
        let got = values(env, Some(public));
        assert_eq!(
            got,
            vec![("TOKEN".to_string(), "tok_abcdefghij".to_string())]
        );
    }

    #[test]
    fn load_walks_bounded_and_skips_heavy_dirs() {
        let dir = std::env::temp_dir().join(format!("values-load-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("apps/web")).unwrap();
        std::fs::create_dir_all(dir.join("node_modules/pkg")).unwrap();
        std::fs::write(dir.join(".env"), "ROOT=root_value_1234\n").unwrap();
        std::fs::write(dir.join("apps/web/.env.local"), "WEB=web_value_12345\n").unwrap();
        std::fs::write(dir.join("node_modules/pkg/.env"), "NM=nm_value_123456\n").unwrap();
        std::fs::write(dir.join(".env.example"), "EX=example_value_1\n").unwrap();
        let got: Vec<String> = load(&dir).into_iter().map(|v| v.key).collect();
        assert_eq!(got.len(), 2, "{got:?}");
        assert!(got.contains(&"ROOT".to_string()) && got.contains(&"WEB".to_string()));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
