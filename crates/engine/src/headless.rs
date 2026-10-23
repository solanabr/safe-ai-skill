//! The headless rule (shared contract §3.3, D8 v2 spec §7), identical on the kit's side.
//!
//! Headless = any of: `SAFE_AI_SKILL_HEADLESS` or `KIT_FIREWALL_HEADLESS` = `1|true`; any of
//! `CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, `BUILDKITE`, `JENKINS_URL` set (non-empty) and not
//! `0|false`; `/dev/tty` cannot be opened for reading. Any signal turns it **on**; nothing turns
//! it off, because a repo's settings `env` can set every one of them (headless only tightens).
//!
//! When headless, [`apply`] turns every `ask` into a `deny` naming the interactive or grant
//! route: there is nobody to answer the dialog (under `claude -p` a hook `ask` is a denial
//! anyway). What still passes is a grant the user confirmed interactively beforehand, which
//! the relaxation layer has already turned into an `allow` (below High, grantable scopes only).
//! No env escape (`CONFIRM_MAINNET`, `CONFIRM_*`) is read, and `defer` is never emitted.
//!
//! The `/dev/tty` signal is wired but not consulted by the hooks yet ([`detect`] passes
//! `None`): processes Claude Code spawns were observed without a controlling terminal, so the
//! probe would make every interactive session headless. It is switched on once the live check
//! confirms what hook processes see.

use crate::io::Decision;

/// Explicit headless switches (`1` or `true`).
pub const SWITCH_VARS: [&str; 2] = ["SAFE_AI_SKILL_HEADLESS", "KIT_FIREWALL_HEADLESS"];

/// CI markers: set (non-empty) and not `0`/`false` means headless.
pub const CI_VARS: [&str; 5] = [
    "CI",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "BUILDKITE",
    "JENKINS_URL",
];

/// Appended to an `ask` reason when it becomes a headless `deny`.
pub const HEADLESS_SUFFIX: &str = "No interactive user can approve this (headless session): \
     approve it in an interactive session, confirm a grant there first where one applies, or \
     run it yourself.";

/// Whether the session is headless. `env` looks up a variable; `tty_readable` is the
/// `/dev/tty` probe (`None` when it is skipped).
pub fn is_headless(env: &dyn Fn(&str) -> Option<String>, tty_readable: Option<bool>) -> bool {
    let value = |k: &str| env(k).map(|v| v.trim().to_ascii_lowercase());
    let switched = SWITCH_VARS
        .iter()
        .any(|k| matches!(value(k).as_deref(), Some("1" | "true")));
    let ci = CI_VARS
        .iter()
        .any(|k| value(k).is_some_and(|v| !v.is_empty() && v != "0" && v != "false"));
    switched || ci || tty_readable == Some(false)
}

/// [`is_headless`] over the process environment (see the module docs on the `/dev/tty` probe).
pub fn detect() -> bool {
    is_headless(&|k| std::env::var(k).ok(), None)
}

/// Whether `/dev/tty` opens for reading; `None` where it does not exist.
pub fn tty_probe() -> Option<bool> {
    let path = std::path::Path::new("/dev/tty");
    if std::fs::symlink_metadata(path).is_err() {
        return None;
    }
    Some(std::fs::File::open(path).is_ok())
}

/// The headless post-processor: an `ask` becomes a `deny` (same reason plus
/// [`HEADLESS_SUFFIX`]); everything else passes unchanged.
pub fn apply(decision: Decision, headless: bool) -> Decision {
    match decision {
        Decision::Ask { reason } if headless => Decision::Deny {
            reason: format!("{reason} {HEADLESS_SUFFIX}"),
        },
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            pairs
                .iter()
                .find(|(key, _)| *key == k)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn any_signal_turns_it_on_and_nothing_turns_it_off() {
        assert!(!is_headless(&env(&[]), None));
        assert!(!is_headless(&env(&[]), Some(true)));
        assert!(is_headless(&env(&[]), Some(false)));
        for on in [
            ("CI", "true"),
            ("CI", "1"),
            ("GITHUB_ACTIONS", "true"),
            ("JENKINS_URL", "https://ci.example"),
            ("SAFE_AI_SKILL_HEADLESS", "1"),
            ("KIT_FIREWALL_HEADLESS", "TRUE"),
        ] {
            assert!(is_headless(&env(&[on]), None), "{on:?}");
        }
        for off in [
            ("CI", "0"),
            ("CI", "false"),
            ("CI", ""),
            ("SAFE_AI_SKILL_HEADLESS", "0"),
        ] {
            assert!(!is_headless(&env(&[off]), None), "{off:?}");
        }
        // An explicit 0 elsewhere never cancels a signal.
        assert!(is_headless(
            &env(&[
                ("CI", "true"),
                ("KIT_FIREWALL_HEADLESS", "0"),
                ("SAFE_AI_SKILL_HEADLESS", "false")
            ]),
            Some(true)
        ));
    }

    #[test]
    fn asks_become_denies_and_nothing_else_changes() {
        let ask = Decision::Ask {
            reason: "mainnet deploy".into(),
        };
        match apply(ask.clone(), true) {
            Decision::Deny { reason } => {
                assert!(reason.starts_with("mainnet deploy") && reason.contains("headless"))
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(apply(ask.clone(), false), ask);
        for d in [
            Decision::Allow,
            Decision::Defer,
            Decision::Deny { reason: "x".into() },
        ] {
            assert_eq!(apply(d.clone(), true), d);
        }
    }
}
