//! D8 v2 spec §4 (F1): home credential stores and command-form credential readers.
//!
//! Every row denies at every tier (Off too, with `--features test-hooks`: Off is not DISABLE).
//! Paths use a temp HOME; commands are only ever fed to the hook as strings.

mod common;

use common::{decision_label, Invocation, Run, TempDir, Tier, TEST_HOOKS};
use serde_json::{json, Value};

/// Tiers the binary can be run at in this build (Off needs the trusted data dir override).
fn tiers() -> Vec<Tier> {
    let mut all = vec![Tier::Relaxed, Tier::Medium, Tier::High];
    if TEST_HOOKS {
        all.insert(0, Tier::Off);
    }
    all
}

struct World {
    home: TempDir,
    proj: TempDir,
    data: TempDir,
}

impl World {
    fn new(tag: &str) -> World {
        let w = World {
            home: TempDir::new(&format!("{tag}-home")),
            proj: TempDir::new(&format!("{tag}-proj")),
            data: TempDir::new(&format!("{tag}-data")),
        };
        std::fs::create_dir_all(w.proj.join(".git")).unwrap();
        w
    }

    fn pre(&self, tier: Tier, sub: &str, tool: &str, input: Value) -> Run {
        Invocation::new(&[sub])
            .plugin_data(self.data.path())
            .home(self.home.path())
            .tier(tier)
            .stdin(
                json!({
                    "hook_event_name": "PreToolUse",
                    "cwd": self.proj.path(),
                    "tool_name": tool,
                    "tool_input": input,
                })
                .to_string(),
            )
            .run()
    }

    fn read(&self, tier: Tier, path: &str) -> String {
        decision_label(&self.pre(tier, "gate-read", "Read", json!({ "file_path": path })))
    }

    fn bash(&self, tier: Tier, command: &str) -> String {
        decision_label(&self.pre(
            tier,
            "gate-bash-secrets",
            "Bash",
            json!({ "command": command }),
        ))
    }
}

const READ_DENIED: &[&str] = &[
    "~/.ssh/id_ed25519",
    "~/.ssh/authorized_keys",
    "~/.ssh/id_rsa",
    "~/.aws/credentials",
    "~/.config/gh/hosts.yml",
    "~/.npmrc",
    "~/.docker/config.json",
    "~/.git-credentials",
    "~/.netrc",
    "~/.kube/config",
    "~/.gnupg/private-keys-v1.d/x.key",
    "~/Library/Keychains/login.keychain-db",
    "~/.mozilla/firefox/x.default/cookies.sqlite",
    "~/AppData/Local/Google/Chrome/User Data/Default/Cookies",
    "~/Library/Application Support/Google/Chrome/Default/Login Data",
    "~/Library/Application Support/Google/Chrome/Default/Local Extension Settings/\
     bfnaelmomeimhlpmgjnjophhpkkoljpa/000003.log",
    "~/.password-store/solana.gpg",
    // Case-insensitive targets (macOS, Windows): the matcher folds case on every host.
    "~/.SSH/ID_RSA",
    "~/.AWS/Credentials",
];

const READ_READABLE: &[&str] = &[
    "./docs/ssh.md",
    "~/.ssh/config",
    "~/.ssh/known_hosts",
    "~/.ssh/id_ed25519.pub",
    "src/main.rs",
];

#[test]
fn reads_of_home_credential_stores_deny_at_every_tier() {
    let w = World::new("cp-read");
    for tier in tiers() {
        for path in READ_DENIED {
            assert_eq!(w.read(tier, path), "deny", "{tier:?} {path}");
        }
        let absolute = w.home.join(".aws/credentials");
        assert_eq!(
            w.read(tier, absolute.to_str().unwrap()),
            "deny",
            "{tier:?} absolute"
        );
    }
}

#[test]
fn readable_ssh_files_and_ordinary_paths_have_no_opinion() {
    let w = World::new("cp-read-ok");
    for tier in tiers() {
        for path in READ_READABLE {
            let got = w.read(tier, path);
            assert_eq!(got, "", "{tier:?} {path}");
        }
    }
}

#[test]
fn a_symlink_to_a_credential_store_denies() {
    let w = World::new("cp-symlink");
    std::fs::create_dir_all(w.home.join(".aws")).unwrap();
    std::fs::write(w.home.join(".aws/credentials"), "[default]\n").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(w.home.join(".aws/credentials"), w.proj.join("k")).unwrap();
        for tier in tiers() {
            assert_eq!(w.read(tier, "k"), "deny", "{tier:?}");
            let run = w.pre(
                tier,
                "gate-mcp",
                "mcp__fs__read",
                json!({ "file": w.proj.join("k") }),
            );
            assert_eq!(decision_label(&run), "deny", "{tier:?} mcp");
        }
    }
}

#[test]
fn mcp_path_arguments_naming_a_credential_store_deny() {
    let w = World::new("cp-mcp");
    for tier in tiers() {
        for (tool, input) in [
            ("mcp__fs__read", json!({ "file": "~/.netrc" })),
            ("mcp__fs__read", json!({ "path": "~/.aws/credentials" })),
            (
                "mcp__fs__read_multiple",
                json!({ "args": { "paths": ["README.md", "~/.ssh/id_ed25519"] } }),
            ),
        ] {
            let run = w.pre(tier, "gate-mcp", tool, input.clone());
            assert_eq!(decision_label(&run), "deny", "{tier:?} {tool} {input}");
        }
    }
}

const BASH_DENIED: &[&str] = &[
    "cat ~/.git-credentials",
    "cat ~/.aws/credentials",
    "head -n 3 ~/.npmrc",
    "cat $HOME/.netrc",
    "gh auth token",
    "gh auth token --hostname github.com",
    "gh auth status --show-token",
    "git credential fill",
    "git -C /tmp credential fill",
    "git credential-osxkeychain get",
    "security find-generic-password -s x -w",
    "security find-internet-password -s x -w",
    "security find-generic-password -ga x",
    "aws configure get aws_secret_access_key",
    "aws --profile dev configure get aws_secret_access_key",
    "aws configure export-credentials",
    "npm config get //registry.npmjs.org/:_authToken",
    "yarn config get npmAuthToken",
    "docker-credential-osxkeychain get",
    "docker-credential-desktop get",
    "secret-tool lookup service x",
    "pass show solana",
    "pass solana",
    "op read op://v/i/f",
    "bw get password x",
    "bw get item x",
    // wrapped and compound forms
    "sudo gh auth token",
    "FOO=1 gh auth token",
    "echo hi && gh auth token",
    "gh auth token | pbcopy",
    "bash -c 'gh auth token'",
    "TOKEN=$(gh auth token)",
    "/usr/local/bin/gh auth token",
    "timeout 5 pass show solana",
];

const BASH_QUIET: &[&str] = &[
    "npm install",
    "gh pr list",
    "ls ~/.ssh",
    "cat ./docs/ssh.md",
    "security find-generic-password -s x",
    "security find-identity -v",
    "cat ~/.ssh/config",
    "cat ~/.ssh/known_hosts",
    "cat ~/.ssh/id_ed25519.pub",
    "gh auth status",
    "gh auth login",
    "git credential reject",
    "git commit -m 'credential fill'",
    "aws configure get region",
    "aws s3 ls",
    "npm config get registry",
    "npm config set //registry.npmjs.org/:_authToken x",
    "docker-credential-osxkeychain list",
    "pass ls",
    "pass init me",
    "op whoami",
    "bw status",
    "bw get template item",
    "echo gh auth token",
    "cargo build",
];

#[test]
fn command_form_and_path_readers_deny_at_every_tier() {
    let w = World::new("cp-bash");
    for tier in tiers() {
        for cmd in BASH_DENIED {
            assert_eq!(w.bash(tier, cmd), "deny", "{tier:?} {cmd}");
        }
    }
}

#[test]
fn ordinary_commands_and_non_secret_forms_have_no_opinion() {
    let w = World::new("cp-bash-ok");
    for tier in tiers() {
        for cmd in BASH_QUIET {
            assert_eq!(w.bash(tier, cmd), "", "{tier:?} {cmd}");
        }
    }
}

/// `rg --glob` is case-sensitive, so the engine writes every letter as a two-case class.
fn ci(glob: &str) -> String {
    glob.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                format!("[{}{}]", c.to_ascii_lowercase(), c.to_ascii_uppercase())
            } else {
                c.to_string()
            }
        })
        .collect()
}

fn grep(w: &World, tier: Tier, input: Value) -> Run {
    w.pre(tier, "gate-read", "Grep", input)
}

#[test]
fn grep_rooted_at_home_gets_every_credential_glob_and_no_decision() {
    let w = World::new("cp-grep-home");
    for d in [".aws", ".config", "Library"] {
        std::fs::create_dir_all(w.home.join(d)).unwrap();
    }
    for tier in tiers() {
        for path in ["~", "~/", "~/.config", "~/Library"] {
            let run = grep(&w, tier, json!({ "pattern": "token", "path": path }));
            let v = run.json();
            let out = &v["hookSpecificOutput"];
            assert!(out.get("permissionDecision").is_none(), "{path}: {v}");
            let glob = out["updatedInput"]["glob"].as_str().unwrap();
            assert!(glob.starts_with("!{"), "{glob}");
            for want in [
                "**/.ssh/**",
                "**/.aws/**",
                "**/.npmrc",
                "**/.netrc",
                "**/.git-credentials",
                "**/.docker/config.json",
                "**/.config/gh/hosts.yml",
                "**/.gnupg/**",
                "**/.kube/config",
                "**/.config/solana/**",
                "**/Library/Keychains/**",
                "**/.mozilla/firefox/**",
                "**/Local?Extension?Settings/**",
                "**/AppData/Local/Google/Chrome/User?Data/**",
                "**/*-keypair.json",
            ] {
                assert!(
                    glob.contains(&ci(want)),
                    "{path} {tier:?}: missing {want}\n{glob}"
                );
            }
            assert!(!glob.contains(' ') || glob.starts_with("!{"), "{glob}");
        }
    }
}

#[test]
fn grep_inside_a_credential_store_denies() {
    let w = World::new("cp-grep-in");
    for d in [".aws", ".ssh", ".config/solana", ".gnupg"] {
        std::fs::create_dir_all(w.home.join(d)).unwrap();
    }
    for tier in tiers() {
        for path in ["~/.aws", "~/.ssh", "~/.config/solana", "~/.gnupg"] {
            let run = grep(&w, tier, json!({ "pattern": "x", "path": path }));
            assert_eq!(decision_label(&run), "deny", "{tier:?} {path}");
        }
    }
}

#[test]
fn grep_in_a_project_keeps_the_short_exclusion_list() {
    let w = World::new("cp-grep-proj");
    std::fs::create_dir_all(w.proj.join("src")).unwrap();
    for tier in tiers() {
        let run = grep(&w, tier, json!({ "pattern": "fn", "path": "src" }));
        let v = run.json();
        let glob = v["hookSpecificOutput"]["updatedInput"]["glob"]
            .as_str()
            .unwrap();
        assert!(glob.contains(&ci("**/.env")), "{glob}");
        assert!(!glob.contains(&ci(".aws")), "{glob}");
    }
}
