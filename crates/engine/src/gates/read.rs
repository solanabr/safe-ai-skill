//! Read/Grep/Glob secret-glob gate.

use std::io::Read;
use std::path::{Path, PathBuf};

use glob::Pattern;

use crate::io::Decision;
use crate::policy::Policy;
use crate::redact;

/// Largest `.env.schema` the content guard will read.
const MAX_SCHEMA_BYTES: u64 = 64 * 1024;

/// Decide whether a read of `path` is permitted.
///
/// `allow_read_globs` take precedence: a path matching an allow glob is never denied
/// (returns [`Decision::Defer`]). Otherwise, a path matching any `deny_read_globs` glob
/// returns [`Decision::Deny`] with a reason naming the protected file class (the secret
/// path itself is never echoed beyond the requested path). A non-matching path returns
/// [`Decision::Defer`].
///
/// A leading `~` in either the path or a glob is expanded to the home directory (`$HOME`)
/// so `~/.config/solana/**` patterns match real absolute read paths. Scope is fixed
/// (`secret_read`), so `main.rs` wraps the result in a hard-guard
/// [`crate::gate::GateMeta`].
pub fn decide(path: &str, policy: &Policy) -> Decision {
    let candidate = expand_home(path);

    // Allow globs win: never deny an explicitly allowed path (e.g. `.env.example`).
    for glob in &policy.secrets.allow_read_globs {
        if glob_matches(glob, &candidate) {
            return Decision::Defer;
        }
    }

    for glob in &policy.secrets.deny_read_globs {
        if glob_matches(glob, &candidate) {
            return Decision::Deny {
                reason: format!(
                    "Protected secret file blocked ({}): reading credential material is denied.",
                    describe_class(glob)
                ),
            };
        }
    }

    Decision::Defer
}

/// Content guard for a read that [`decide`] let through: a varlock `.env.schema` is allowed
/// by default, but is denied when it holds key material, is larger than 64 KiB, is not a
/// regular file, or resolves (symlink) to a file that is not itself a `.env.schema`.
///
/// Relative paths resolve against the hook `cwd`. Any other file name, and a schema that does
/// not exist yet, return [`Decision::Defer`]. Never executes or parses the schema: it is a
/// bounded byte scan with the shared [`redact`] detectors.
pub fn guard_env_schema(path: &str, cwd: &Path) -> Decision {
    if !is_env_schema(path) {
        return Decision::Defer;
    }
    let mut full = PathBuf::from(expand_home(path));
    if full.is_relative() {
        full = cwd.join(full);
    }
    let real = match full.canonicalize() {
        Ok(real) => real,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Decision::Defer,
        Err(_) => return schema_denied("could not be resolved"),
    };
    if !real.to_str().map(is_env_schema).unwrap_or(false) {
        return schema_denied("resolves to a different file");
    }
    // Check the type before opening: opening a FIFO blocks the gate until a writer appears.
    if !std::fs::metadata(&real).is_ok_and(|m| m.is_file()) {
        return schema_denied("could not be read as a regular file");
    }
    let mut buf = Vec::new();
    let read =
        std::fs::File::open(&real).and_then(|f| f.take(MAX_SCHEMA_BYTES + 1).read_to_end(&mut buf));
    if read.is_err() {
        return schema_denied("could not be read as a regular file");
    }
    if buf.len() as u64 > MAX_SCHEMA_BYTES {
        return schema_denied("is larger than 64 KiB");
    }
    if redact::contains_key_material(&String::from_utf8_lossy(&buf)) {
        return Decision::Deny {
            reason:
                "Protected secret file blocked (.env.schema): the schema contains a secret value. \
                     A schema holds keys and decorators only; move the value to `.env.local`."
                    .into(),
        };
    }
    Decision::Defer
}

/// Whether the final component of `path` is `.env.schema` (case-insensitive: the same file
/// on a case-insensitive filesystem).
fn is_env_schema(path: &str) -> bool {
    path.rsplit('/')
        .next()
        .is_some_and(|base| base.eq_ignore_ascii_case(".env.schema"))
}

fn schema_denied(why: &str) -> Decision {
    Decision::Deny {
        reason: format!("Protected secret file blocked (.env.schema): the schema {why}."),
    }
}

/// Match a glob `pattern` against `candidate`, expanding a leading `~` in the pattern and
/// also testing the path's final component so that `**/foo` patterns match bare filenames.
fn glob_matches(pattern: &str, candidate: &str) -> bool {
    let expanded = expand_home(pattern);
    let Ok(compiled) = Pattern::new(&expanded) else {
        return false;
    };
    if compiled.matches(candidate) {
        return true;
    }
    // `glob` treats `**` as crossing directory boundaries, but a relative candidate like
    // `.env` should still match `**/.env`. Also test the basename for robustness.
    if let Some(base) = candidate.rsplit('/').next() {
        if base != candidate && compiled.matches(base) {
            return true;
        }
    }
    false
}

/// Expand a leading `~` (or `~/`) to the home directory. Other `~` uses are left intact.
fn expand_home(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{}/{}", home.trim_end_matches('/'), rest);
        }
    } else if path == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return home;
        }
    }
    path.to_string()
}

/// A short, non-sensitive description of the matched secret class for the deny reason.
fn describe_class(glob: &str) -> &'static str {
    let g = glob.to_ascii_lowercase();
    if g.contains("keypair") || g.contains("id.json") {
        "Solana keypair"
    } else if g.contains(".env") {
        "environment file"
    } else if g.contains(".pem") {
        "PEM private key"
    } else if g.contains("solana") {
        "Solana config directory"
    } else if g.contains("superstack") {
        "superstack config (credential token)"
    } else {
        "credential file"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;

    fn policy() -> Policy {
        // The embedded default policy carries the secret globs we test against.
        Policy::default()
    }

    #[test]
    fn deny_id_json() {
        let d = decide("/Users/dev/project/id.json", &policy());
        assert!(matches!(d, Decision::Deny { .. }));
    }

    #[test]
    fn deny_keypair_json() {
        let d = decide("/home/me/wallet-keypair.json", &policy());
        assert!(matches!(d, Decision::Deny { .. }));
    }

    #[test]
    fn deny_dotenv() {
        assert!(matches!(decide(".env", &policy()), Decision::Deny { .. }));
        assert!(matches!(
            decide("/srv/app/.env.local", &policy()),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn deny_pem() {
        let d = decide("/etc/ssl/private/server.pem", &policy());
        assert!(matches!(d, Decision::Deny { .. }));
    }

    #[test]
    fn deny_superstack_config() {
        std::env::set_var("HOME", "/home/tester");
        let d = decide("/home/tester/.superstack/config.json", &policy());
        assert!(matches!(d, Decision::Deny { .. }));
    }

    #[test]
    fn allow_env_example() {
        assert_eq!(decide(".env.example", &policy()), Decision::Defer);
        assert_eq!(decide("/proj/.env.example", &policy()), Decision::Defer);
    }

    #[test]
    fn allow_env_schema_but_not_its_siblings() {
        assert_eq!(decide(".env.schema", &policy()), Decision::Defer);
        assert_eq!(decide("/proj/sub/.env.schema", &policy()), Decision::Defer);
        for name in [".env.schema.bak", ".env.schema.local", ".env.local"] {
            assert!(
                matches!(decide(name, &policy()), Decision::Deny { .. }),
                "{name}"
            );
        }
    }

    #[test]
    fn guard_ignores_other_file_names() {
        assert_eq!(
            guard_env_schema("/nonexistent/.env.example", Path::new("/")),
            Decision::Defer
        );
        assert_eq!(
            guard_env_schema("/nonexistent/.env.schema", Path::new("/")),
            Decision::Defer
        );
    }

    #[test]
    fn allow_normal_source_file() {
        assert_eq!(decide("/proj/src/main.rs", &policy()), Decision::Defer);
    }

    #[test]
    fn tilde_expansion_solana_config() {
        std::env::set_var("HOME", "/home/tester");
        let d = decide("~/.config/solana/id.json", &policy());
        assert!(matches!(d, Decision::Deny { .. }));
    }
}
