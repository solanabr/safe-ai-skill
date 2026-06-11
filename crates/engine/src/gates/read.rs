//! Read/Grep/Glob secret-glob gate.

use glob::Pattern;

use crate::io::Decision;
use crate::policy::Policy;

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
