//! Command-form credential readers (D8 v2 spec §4; owned by F1): `gh auth token`,
//! `git credential fill`, `security find-generic-password -w`, `aws configure get *secret*`,
//! `npm config get *_authToken`, `docker-credential-* get`, `secret-tool lookup`, `pass show`,
//! `op read`, `bw get`, denied at every tier (Off included: Off is not DISABLE).
//!
//! These print a stored credential to the command's stdout, i.e. into the model's context.
//! They are plugin-internal (not path globs, not in the shared list). Matching is on the
//! parsed simple commands ([`crate::context::shell::parse`]: wrappers, `bash -c`, `$(…)` and
//! pipelines are already split out), by program name and subcommand words, never on
//! arguments' values except where the value is the secret selector (`aws configure get <name>`,
//! `npm config get <key>`). The same forms run by a subprocess, or encoded, are not seen: only
//! the sandbox closes those (`doctor` says so).
//!
//! Call line: `main::cmd_gate_bash_secrets` (the [`crate::gate::Verdict`] joins the secrets
//! gate's decision, strictest wins).

use std::path::Path;

use crate::context::shell::{self, SimpleCommand};
use crate::gate::Verdict;
use crate::policy::tier::Tier;
use crate::policy::Policy;

/// The verdict for a Bash `command` run in `cwd`; `None` is no opinion. Tier-independent.
pub fn decide(command: &str, cwd: &Path, policy: &Policy, tier: Tier) -> Option<Verdict> {
    let _ = (cwd, policy, tier);
    let parsed = shell::parse(command);
    parsed
        .commands
        .iter()
        .find_map(reader)
        .map(|what| Verdict::Deny(reason(what)))
}

fn reason(what: &str) -> String {
    format!(
        "Credential read blocked (`{what}`): the command prints a stored credential into the \
         session. Run it yourself in a terminal if you need it; credential stores are not \
         readable by the agent at any tier."
    )
}

/// The command's words after the program: `(flags, positionals)`, flags lowercased as written
/// (`-w`, `--show-token`), positionals lowercased.
struct Args {
    flags: Vec<String>,
    pos: Vec<String>,
}

impl Args {
    fn of(cmd: &SimpleCommand) -> Args {
        let mut flags = Vec::new();
        let mut pos = Vec::new();
        for word in cmd.words.iter().skip(1) {
            let text = word.text.to_ascii_lowercase();
            if text.len() > 1 && text.starts_with('-') {
                flags.push(text);
            } else {
                pos.push(text);
            }
        }
        Args { flags, pos }
    }

    fn flag(&self, names: &[&str]) -> bool {
        self.flags.iter().any(|f| names.contains(&f.as_str()))
    }

    /// A short-option cluster (`-w`, `-ga`, `-sw`) carrying `letter`.
    fn short(&self, letter: char) -> bool {
        self.flags
            .iter()
            .any(|f| !f.starts_with("--") && f[1..].contains(letter))
    }

    /// The positional following the first occurrence of `word`.
    fn after(&self, word: &str) -> Option<&str> {
        let i = self.pos.iter().position(|p| p == word)?;
        self.pos.get(i + 1).map(String::as_str)
    }

    /// The positional after `first` and `second` in sequence.
    fn after2(&self, first: &str, second: &str) -> Option<&str> {
        let i = self.pos.iter().position(|p| p == first)?;
        (self.pos.get(i + 1).map(String::as_str) == Some(second))
            .then(|| self.pos.get(i + 2).map(String::as_str).unwrap_or(""))
    }
}

/// The reader this simple command is, as the text to show.
fn reader(cmd: &SimpleCommand) -> Option<&'static str> {
    let program = cmd.program();
    let args = Args::of(cmd);
    let first = args.pos.first().map(String::as_str);
    match program.as_str() {
        "gh" => {
            if args.after2("auth", "token").is_some() {
                Some("gh auth token")
            } else if args.after("auth") == Some("status") && args.flag(&["-t", "--show-token"]) {
                Some("gh auth status --show-token")
            } else {
                None
            }
        }
        "git" => git_reader(cmd),
        "security" => match first {
            Some("find-generic-password" | "find-internet-password")
                if args.short('w') || args.short('g') =>
            {
                Some("security find-generic-password -w")
            }
            Some("dump-keychain") if args.short('d') => Some("security dump-keychain -d"),
            _ => None,
        },
        "aws" => {
            if args.after("configure") == Some("export-credentials") {
                return Some("aws configure export-credentials");
            }
            let name = args.after2("configure", "get")?;
            (name.contains("secret") || name.contains("session_token"))
                .then_some("aws configure get <secret>")
        }
        "npm" | "pnpm" | "yarn" => {
            let key = args
                .after2("config", "get")
                .or_else(|| args.after2("c", "get"))?;
            let token = key.contains("authtoken")
                || key.contains("authident")
                || key.ends_with("_auth")
                || key.ends_with("_password");
            token.then_some("npm config get <auth token>")
        }
        p if p.starts_with("docker-credential-") => {
            (first == Some("get")).then_some("docker-credential-* get")
        }
        "secret-tool" => matches!(first, Some("lookup" | "search")).then_some("secret-tool lookup"),
        "pass" => pass_reader(&args),
        "op" => {
            if matches!(first, Some("read" | "inject")) {
                Some("op read")
            } else if args.after2("item", "get").is_some() && args.flag(&["--reveal"]) {
                Some("op item get --reveal")
            } else if args.after2("document", "get").is_some() {
                Some("op document get")
            } else {
                None
            }
        }
        "bw" => match first {
            Some("get") => (args.after("get") != Some("template")).then_some("bw get"),
            Some("export") => Some("bw export"),
            Some("list") => (args.after("list") == Some("items")).then_some("bw list items"),
            _ => None,
        },
        _ => None,
    }
}

/// `git credential fill` and `git credential-<helper> get`, after git's global options.
fn git_reader(cmd: &SimpleCommand) -> Option<&'static str> {
    let mut words = cmd.words.iter().skip(1).map(|w| w.text.as_str());
    let sub = loop {
        let word = words.next()?;
        match word {
            "-C" | "-c" | "--git-dir" | "--work-tree" | "--namespace" | "--exec-path" => {
                words.next();
            }
            w if w.starts_with('-') => {}
            w => break w,
        }
    };
    let rest: Vec<&str> = words.collect();
    let helper_get = || rest.iter().any(|w| w.eq_ignore_ascii_case("get"));
    if sub == "credential" {
        return rest
            .iter()
            .find(|w| !w.starts_with('-'))
            .is_some_and(|w| w.eq_ignore_ascii_case("fill"))
            .then_some("git credential fill");
    }
    (sub.starts_with("credential-") && helper_get()).then_some("git credential-* get")
}

/// `pass show <entry>`, `pass grep`, and `pass <entry>` (which shows it); `pass ls`, `init`,
/// `insert`, `generate`, … do not print a secret.
fn pass_reader(args: &Args) -> Option<&'static str> {
    const OTHER: &[&str] = &[
        "init", "ls", "list", "find", "search", "insert", "add", "edit", "generate", "rm",
        "delete", "remove", "mv", "rename", "cp", "copy", "git", "help", "version",
    ];
    let first = args.pos.first()?.as_str();
    (matches!(first, "show" | "grep") || !OTHER.contains(&first)).then_some("pass show")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decide_text(command: &str) -> bool {
        let policy = Policy::default();
        decide(command, Path::new("/tmp"), &policy, Tier::Off).is_some()
    }

    #[test]
    fn readers_deny_at_every_tier() {
        let policy = Policy::default();
        for tier in [Tier::Off, Tier::Relaxed, Tier::Medium, Tier::High] {
            let verdict = decide("gh auth token", Path::new("/tmp"), &policy, tier);
            assert!(matches!(verdict, Some(Verdict::Deny(_))), "{tier:?}");
        }
    }

    #[test]
    fn wrapped_and_compound_forms_are_found() {
        for c in [
            "sudo gh auth token",
            "FOO=1 pass show x",
            "x && op read op://v/i/f",
            "gh auth token | pbcopy",
            "bash -c 'bw get password x'",
            "echo $(security find-generic-password -s x -w)",
            "/opt/homebrew/bin/GH auth token",
            "git -c credential.helper=x credential fill",
        ] {
            assert!(decide_text(c), "{c}");
        }
    }

    #[test]
    fn selectors_decide_aws_and_npm() {
        assert!(decide_text("aws configure get aws_secret_access_key"));
        assert!(decide_text("aws configure get default.aws_session_token"));
        assert!(!decide_text("aws configure get region"));
        assert!(!decide_text("aws configure get aws_access_key_id"));
        assert!(decide_text("npm config get //r.npmjs.org/:_authToken"));
        assert!(!decide_text("npm config get registry"));
        assert!(!decide_text("npm config get"));
    }

    #[test]
    fn near_misses_have_no_opinion() {
        for c in [
            "gh auth status",
            "gh pr list",
            "git credential reject",
            "git commit -m 'credential fill'",
            "security find-generic-password -s x",
            "pass ls",
            "pass insert x",
            "op whoami",
            "bw status",
            "bw get template item",
            "docker-credential-desktop list",
            "echo gh auth token",
            "",
        ] {
            assert!(!decide_text(c), "{c}");
        }
    }
}
