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
use crate::redact;

/// Shortest value scrubbed (shorter literals match too much ordinary output).
pub const MIN_VALUE_LEN: usize = 8;

const MAX_DEPTH: usize = 4;
/// Directories listed per walk (the budget goes to directories, not files).
const MAX_DIRS: usize = 2_000;
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
///
/// Breadth-first over directories: each directory's own env-class files are read (names are
/// classified before any `stat`) before deeper directories are listed, so a big tree spends
/// its budget on directories near the root and the root's `.env` is never skipped. Directory
/// symlinks are not followed; a symlinked env file counts when it resolves to a regular file.
pub fn load(cwd: &Path) -> Vec<KnownValue> {
    let mut out: Vec<KnownValue> = Vec::new();
    let mut files = 0usize;
    let mut queue = std::collections::VecDeque::from([(cwd.to_path_buf(), 0usize)]);
    let mut listed = 0usize;
    while let Some((dir, depth)) = queue.pop_front() {
        if listed >= MAX_DIRS || files >= MAX_FILES || out.len() >= MAX_VALUES {
            break;
        }
        listed += 1;
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut env_files = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                if depth < MAX_DEPTH && !SKIP_DIRS.contains(&name) {
                    queue.push_back((entry.path(), depth + 1));
                }
            } else if secretpath::classify(name) == Class::Env {
                env_files.push(entry.path());
            }
        }
        if env_files.is_empty() {
            continue;
        }
        let schema = read_bounded(&dir.join(".env.schema"), schema::MAX_SCHEMA_BYTES as u64)
            .map(|b| Schema::parse(&b));
        for path in env_files {
            if files >= MAX_FILES {
                break;
            }
            files += 1;
            if let Some(bytes) = read_bounded(&path, MAX_FILE_BYTES) {
                collect(&bytes, schema.as_ref(), &mut out);
            }
        }
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
        if !scrubbable(&entry.key, &value, sensitive) {
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

/// Whether a literal value is scrubbed (fix round 1 ruling):
/// - never: shorter than [`MIN_VALUE_LEN`], empty, a placeholder, a verbatim-safe word;
/// - never, unless the key name announces a secret: a public URL (unless schema-sensitive),
///   a bare hostname or IP, a cloud region, a plain word;
/// - otherwise only when the key is schema-sensitive, its name announces a secret, or the
///   value looks random (≥ 12 bytes and ≥ 3.0 bits/char of Shannon entropy).
fn scrubbable(key: &str, value: &[u8], sensitive: bool) -> bool {
    if value.len() < MIN_VALUE_LEN {
        return false;
    }
    let named = redact::is_secret_key_name(key);
    match Shown::of(value) {
        Shown::Empty | Shown::Placeholder | Shown::Verbatim(_) => return false,
        Shown::Url { .. } if !sensitive && !named && is_public_url(value) => return false,
        _ => {}
    }
    let text = String::from_utf8_lossy(value);
    if !named && is_plain_identifier(&text) {
        return false;
    }
    sensitive || named || (value.len() >= 12 && entropy(&text) >= 3.0)
}

/// Bare hostnames, IPs (v4/v6, optional port), cloud regions and plain words: shapes that
/// appear in ordinary output and source, never credentials by themselves.
fn is_plain_identifier(text: &str) -> bool {
    let host_port = text.rsplit_once(':').map_or(text, |(h, p)| {
        if !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()) {
            h
        } else {
            text
        }
    });
    let ipv4 = host_port.split('.').count() == 4
        && host_port
            .split('.')
            .all(|o| !o.is_empty() && o.len() <= 3 && o.parse::<u8>().is_ok());
    let ipv6 = text.contains("::") && text.bytes().all(|b| b.is_ascii_hexdigit() || b == b':');
    let hostname = host_port.contains('.')
        && host_port
            .split('.')
            .all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
        && host_port
            .rsplit('.')
            .next()
            .is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_alphabetic()));
    let parts: Vec<&str> = text.split('-').collect();
    let region = (3..=4).contains(&parts.len())
        && parts[..parts.len() - 1]
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_lowercase()))
        && parts
            .last()
            .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()));
    let word = text
        .bytes()
        .all(|b| b.is_ascii_alphabetic() || b == b'-' || b == b'_');
    ipv4 || ipv6 || hostname || region || word
}

/// Shannon entropy in bits per character.
fn entropy(text: &str) -> f64 {
    let mut counts = std::collections::HashMap::new();
    let mut total = 0usize;
    for c in text.chars() {
        *counts.entry(c).or_insert(0usize) += 1;
        total += 1;
    }
    if total == 0 {
        return 0.0;
    }
    let n = total as f64;
    counts
        .values()
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
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
            "API_KEY=supersecretvalue\nB=short\nC=production\nD=12345\nE=<your-key>\nF=exec(op read x)\nG=$(cat k)\nH=\"${A}-x\"\nI_TOKEN='lit$(x)eral'\nJ=https://api.devnet.solana.com\nK=https://u:p@db.example.com/x\nL=https://g.alchemy.com/v2/abcdefghijklmnopqrstuvwx\nM=https://rpc.example.com/?api-key=zzz\nN=Xq7#pL2vR9mK4wZ1\n",
            None,
        );
        let keys: Vec<&str> = got.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, vec!["API_KEY", "I_TOKEN", "K", "L", "M", "N"]);
    }

    #[test]
    fn plain_identifiers_are_not_scrubbed_unless_named() {
        let got = values(
            "DB_HOST=postgres\nREGION=us-east-1\nHOST=db.internal.example.com\nADDR=127.0.0.1:5432\nV6=fe80::1:2\nNAME=hello_world_app\nDB_PASSWORD=correcthorse\n",
            None,
        );
        assert_eq!(
            got,
            vec![("DB_PASSWORD".to_string(), "correcthorse".to_string())]
        );
        // A schema marking them sensitive does not make plain identifiers secret.
        let schema = values("DB_HOST=postgres\n", Some("# ---\nDB_HOST=\n"));
        assert!(schema.is_empty());
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
        std::fs::write(dir.join(".env"), "ROOT_TOKEN=root_value_1234\n").unwrap();
        std::fs::write(
            dir.join("apps/web/.env.local"),
            "WEB_TOKEN=web_value_12345\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("node_modules/pkg/.env"),
            "NM_TOKEN=nm_value_123456\n",
        )
        .unwrap();
        std::fs::write(dir.join(".env.example"), "EX_TOKEN=example_value_1\n").unwrap();
        let got: Vec<String> = load(&dir).into_iter().map(|v| v.key).collect();
        assert_eq!(got.len(), 2, "{got:?}");
        assert!(got.contains(&"ROOT_TOKEN".to_string()) && got.contains(&"WEB_TOKEN".to_string()));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_finds_root_and_shallow_env_files_in_big_trees() {
        let dir = std::env::temp_dir().join(format!("values-big-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // Thousands of files in an early directory must not starve the root or a shallow dir.
        std::fs::create_dir_all(dir.join("aaa/assets")).unwrap();
        for i in 0..6_000 {
            std::fs::write(dir.join(format!("aaa/assets/f{i}.txt")), "").unwrap();
        }
        std::fs::create_dir_all(dir.join("zzz")).unwrap();
        std::fs::write(dir.join(".env"), "ROOT_TOKEN=root_value_1234\n").unwrap();
        std::fs::write(dir.join("zzz/.env"), "Z_TOKEN=zzz_value_12345\n").unwrap();
        let got: Vec<String> = load(&dir).into_iter().map(|v| v.key).collect();
        assert!(got.contains(&"ROOT_TOKEN".to_string()), "{got:?}");
        assert!(got.contains(&"Z_TOKEN".to_string()), "{got:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
