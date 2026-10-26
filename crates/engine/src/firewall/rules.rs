//! The per-tier rule tables: what `firewall apply <tier>` writes.
//!
//! Ported from ai-kit `.claude/bin/firewall.sh` at `main@72aca8c` (line numbers below are that
//! file's), restricted to coverage-map items X1–X9, P14 and P21. The kit's `permissions.allow`
//! list (P20) and its other deny groups are not written: this writer only adds deny rules and
//! sandbox restrictions, and the other deny groups are hook verdicts in this engine.
//!
//! Departures from the kit, each by a decision already in force:
//! - `sandbox.enabled` is written `true` from Relaxed up and **never `false`**: at Off the key
//!   is removed instead of being set false (kit `plan()`, `"sandbox.enabled": not off`, l.1786).
//! - The Solana CLI config dir is never sandbox-read-denied, at any tier: the shared contract's
//!   `credentials.list` marks `~/.config/solana/id.json` and `~/.config/solana/` `sb=never`
//!   ("sandboxed solana/anchor must sign"), so the kit's `~/.config/solana/id.json` (in
//!   `SB_CREDENTIALS`, l.1467) and Medium's `~/.config/solana/*.json` (l.1853) are dropped from
//!   `denyRead`. `denyWrite` keeps `id.json`. High's `~/` fence still covers it (kit behaviour).
//! - `deniedDomains` comes from the shared `policy/shared/exfil-hosts.list` (seeded from the
//!   kit's `DOMAINS_*` groups, l.1638–1696) through [`crate::lists::exfil_hosts`].

use crate::policy::tier::Tier;

/// The rule-set version this engine ships. Bump whenever a tier's generated block changes in a
/// way an existing install needs; SessionStart re-applies a record below it (T6).
///
/// - 1: first rule set (X1–X9, P14, P21 from kit rule set 10).
/// - 2: the repository's `.git` write carve-out is absolute ([`MachineInputs::git_dir`]); the
///   relative `.git` anchored at the session's working directory, not the repository root.
pub const RULE_SET_VERSION: u32 = 2;

/// Entries an earlier rule set wrote that no tier writes now, per list: still owned, so a
/// record naming one removes it on the next apply.
const RETIRED: &[(&str, &str)] = &[("sandbox.filesystem.allowWrite", ".git")];

/// `DENY_BASH_C` (l.1032–1034), written at High only (the kit: Medium and High, l.1747): a
/// skill's set-up line reaches Claude Code's permission rules only, never a hook (P14).
pub const DENY_BASH_C: &[&str] = &["Bash(bash -c *)"];

/// `EXCLUDED_COMMANDS` (l.1393–1402), Relaxed and up (l.1777). Each entry is a hole kept for
/// shippability: git/gh cannot authenticate inside the sandbox, `surfpool` cannot run in it.
pub const EXCLUDED_COMMANDS: &[&str] = &[
    "surfpool *",
    "anchor test*",
    "git push *",
    "git pull *",
    "git fetch *",
    "gh pr *",
    "gh run *",
    "gh issue *",
];

/// `SB_CREDENTIALS` (l.1467–1481).
pub const SB_CREDENTIALS: &[&str] = &[
    "~/.ssh",
    "~/.gnupg",
    "~/.aws",
    "~/.config/solana/id.json",
    "~/.claude/.credentials.json",
    "~/Library/Keychains",
    "/Library/Keychains",
    "~/.local/share/keyrings",
    "~/.gnome2/keyrings",
    "~/.password-store",
    "~/.config/1Password",
    "~/.config/Bitwarden",
    "~/.config/keepassxc",
];

/// Entries the shared contract forbids in `denyRead` (`credentials.list`, `sb=never`).
const NEVER_DENY_READ: &[&str] = &["~/.config/solana/id.json"];

/// `SB_HOST_CREDENTIALS` (l.1483–1494).
pub const SB_HOST_CREDENTIALS: &[&str] = &[
    "~/.netrc",
    "~/.git-credentials",
    "~/.npmrc",
    "~/.cargo/credentials",
    "~/.cargo/credentials.toml",
    "~/.docker/config.json",
    "~/.config/gh/hosts.yml",
    "~/.kube/config",
    "~/.pypirc",
    "~/.gem/credentials",
];

/// `SB_BROWSER_STORES` (l.1496–1519).
pub const SB_BROWSER_STORES: &[&str] = &[
    "~/Library/Application Support/Google/Chrome",
    "~/Library/Application Support/BraveSoftware/Brave-Browser",
    "~/Library/Application Support/Microsoft Edge",
    "~/Library/Application Support/Firefox",
    "~/Library/Application Support/Chromium",
    "~/Library/Application Support/Vivaldi",
    "~/Library/Application Support/Arc",
    "~/Library/Application Support/com.operasoftware.Opera",
    "~/.config/google-chrome",
    "~/.config/BraveSoftware/Brave-Browser",
    "~/.config/microsoft-edge",
    "~/.mozilla/firefox",
    "~/.config/chromium",
    "~/.config/vivaldi",
    "~/.config/opera",
    "~/AppData/Local/Google/Chrome/User Data",
    "~/AppData/Local/BraveSoftware/Brave-Browser/User Data",
    "~/AppData/Local/Microsoft/Edge/User Data",
    "~/AppData/Roaming/Mozilla/Firefox",
    "~/AppData/Local/Chromium/User Data",
    "~/AppData/Local/Vivaldi/User Data",
    "~/AppData/Roaming/Opera Software",
];

/// `SB_PERSISTENCE` (l.1521–1539).
pub const SB_PERSISTENCE: &[&str] = &[
    "~/.cargo/config.toml",
    "~/.cargo/config",
    "~/.gitconfig",
    "~/.config/git/config",
    "~/.zshenv",
    "~/.zshrc",
    "~/.zprofile",
    "~/.zlogin",
    "~/.bashrc",
    "~/.bash_profile",
    "~/.profile",
    "~/.config/fish/config.fish",
    "~/.config/fish/conf.d",
    "~/Library/LaunchAgents",
    "/Library/LaunchAgents",
    "/Library/LaunchDaemons",
    "~/.config/autostart",
];

/// `SB_HISTORY` (l.1541–1552).
pub const SB_HISTORY: &[&str] = &[
    "~/.zsh_history",
    "~/.zhistory",
    "~/.bash_history",
    "~/.local/share/fish/fish_history",
    "~/.config/fish/fish_history",
    "~/.python_history",
    "~/.node_repl_history",
    "~/.psql_history",
    "~/.sqlite_history",
    "~/.lesshst",
];

/// `SB_POLICY_FILES` (l.1554–1558).
pub const SB_POLICY_FILES: &[&str] = &[
    "~/.claude/settings.json",
    "~/.claude/settings.local.json",
    "/Library/Application Support/ClaudeCode/managed-settings.json",
];

/// `SB_TOOLCHAIN_WRITE` (l.1568–1579).
pub const SB_TOOLCHAIN_WRITE: &[&str] = &[
    "~/.cargo",
    "~/.rustup",
    "~/.cache",
    "~/.cache/solana",
    "~/.local/share/solana",
    "~/.avm",
    "~/.npm",
    "~/.anchor",
    "~/.config/solana",
    "~/Library/Caches",
];

/// `SB_TEMP` (l.1584): absolute only, since a project-settings entry resolves against the root.
pub const SB_TEMP: &[&str] = &["/tmp", "/private/tmp", "/var/folders"];

/// `SB_TOOLCHAIN_READ` (l.1595–1630): each root in a glob-free and a `/**` spelling.
pub const SB_TOOLCHAIN_READ: &[&str] = &[
    "~/.cargo/registry",
    "~/.cargo/registry/**",
    "~/.cargo/git",
    "~/.cargo/git/**",
    "~/.cargo/bin",
    "~/.cargo/bin/**",
    "~/.cargo/env",
    "~/.rustup",
    "~/.rustup/**",
    "~/.cache/solana",
    "~/.cache/solana/**",
    "~/.local/share/solana",
    "~/.local/share/solana/**",
    "~/.avm",
    "~/.avm/**",
    "~/.npm",
    "~/.npm/**",
    "~/.nvm",
    "~/.nvm/**",
    "~/.bun",
    "~/.bun/**",
    "~/.local/share/pnpm",
    "~/.local/share/pnpm/**",
    "~/.anchor",
    "~/.anchor/**",
    "~/Library/Caches",
    "~/Library/Caches/**",
    "~/.config/solana/cli",
    "~/.config/solana/cli/**",
];

/// The Medium `denyRead` extras (l.1851–1858) minus `~/.config/solana/*.json` (module docs).
pub const MEDIUM_DENY_READ_EXTRA: &[&str] =
    &["~/.claude/projects/**/*.jsonl", "~/.claude/history.jsonl"];

/// High's read fence (l.1862).
pub const HIGH_FENCE: &[&str] = &["~/"];

/// The list settings this writer manages, in write order.
pub const LISTS: &[&str] = &[
    "permissions.deny",
    "sandbox.excludedCommands",
    "sandbox.network.deniedDomains",
    "sandbox.filesystem.denyRead",
    "sandbox.filesystem.allowRead",
    "sandbox.filesystem.denyWrite",
    "sandbox.filesystem.allowWrite",
];

/// The scalar settings this writer manages. Each is only ever written `true`.
pub const SCALARS: &[&str] = &[
    "sandbox.enabled",
    "sandbox.network.allowLocalBinding",
    "permissions.blockReadsOutsideWorkingDirectories",
];

/// What one tier generates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    /// `(list path, entries)` for each of [`LISTS`], in that order.
    pub lists: Vec<(&'static str, Vec<String>)>,
    /// The [`SCALARS`] this tier sets `true`; the rest it leaves unset.
    pub scalars: Vec<&'static str>,
}

impl Block {
    /// The entries generated for `path`.
    pub fn list(&self, path: &str) -> &[String] {
        self.lists
            .iter()
            .find(|(p, _)| *p == path)
            .map(|(_, v)| v.as_slice())
            .unwrap_or(&[])
    }
}

/// Machine-specific inputs to a block.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MachineInputs {
    /// The git common dir's real path when it lies outside the project (a linked worktree).
    pub git_common_outside: Option<String>,
    /// The repository's `.git` directory, absolute (a relative sandbox path anchors at the
    /// session's working directory, which may be a subdirectory of the repository).
    pub git_dir: Option<String>,
}

/// The index of `path` in [`LISTS`] (and so in [`Block::lists`]).
fn idx(path: &str) -> usize {
    LISTS.iter().position(|p| *p == path).unwrap_or(0)
}

fn push_all(out: &mut Vec<String>, items: &[&str]) {
    for item in items {
        if !out.iter().any(|e| e == item) {
            out.push((*item).to_string());
        }
    }
}

/// The block for `tier` (kit `plan()`, l.1714–1879, within this writer's items). `domains` is
/// the exfil host list for the tier ([`crate::lists::exfil_hosts`]).
pub fn plan(tier: Tier, domains: &[&str], machine: &MachineInputs) -> Block {
    let mut lists: Vec<(&'static str, Vec<String>)> =
        LISTS.iter().map(|p| (*p, Vec::new())).collect();
    if tier == Tier::Off {
        return Block {
            lists,
            scalars: Vec::new(),
        };
    }
    let medium_up = tier >= Tier::Medium;
    let high = tier == Tier::High;

    // High only (user decision 2026-10-26); the kit also denies it at Medium.
    let i = idx("permissions.deny");
    if high {
        push_all(&mut lists[i].1, DENY_BASH_C);
    }

    let i = idx("sandbox.excludedCommands");
    push_all(&mut lists[i].1, EXCLUDED_COMMANDS);

    let i = idx("sandbox.network.deniedDomains");
    push_all(&mut lists[i].1, domains);

    let i = idx("sandbox.filesystem.denyWrite");
    for group in [
        SB_CREDENTIALS,
        SB_HOST_CREDENTIALS,
        SB_BROWSER_STORES,
        SB_PERSISTENCE,
        SB_HISTORY,
        SB_POLICY_FILES,
    ] {
        push_all(&mut lists[i].1, group);
    }

    let i = idx("sandbox.filesystem.allowWrite");
    push_all(&mut lists[i].1, &["."]);
    push_all(&mut lists[i].1, SB_TEMP);
    push_all(&mut lists[i].1, SB_TOOLCHAIN_WRITE);
    if let Some(git_dir) = &machine.git_dir {
        push_all(&mut lists[i].1, &[git_dir.as_str()]);
    }
    if let Some(common) = &machine.git_common_outside {
        push_all(&mut lists[i].1, &[common.as_str()]);
    }

    let i = idx("sandbox.filesystem.denyRead");
    let creds: Vec<&str> = SB_CREDENTIALS
        .iter()
        .copied()
        .filter(|e| !NEVER_DENY_READ.contains(e))
        .collect();
    push_all(&mut lists[i].1, &creds);
    push_all(&mut lists[i].1, SB_BROWSER_STORES);
    push_all(&mut lists[i].1, SB_HISTORY);
    if medium_up {
        push_all(&mut lists[i].1, SB_HOST_CREDENTIALS);
        push_all(&mut lists[i].1, MEDIUM_DENY_READ_EXTRA);
    }
    if high {
        push_all(&mut lists[i].1, HIGH_FENCE);
        let j = idx("sandbox.filesystem.allowRead");
        push_all(&mut lists[j].1, &["."]);
        push_all(&mut lists[j].1, SB_TEMP);
        push_all(&mut lists[j].1, SB_TOOLCHAIN_READ);
    }

    let mut scalars = vec!["sandbox.enabled", "sandbox.network.allowLocalBinding"];
    if high {
        scalars.push("permissions.blockReadsOutsideWorkingDirectories");
    }
    Block { lists, scalars }
}

/// Every string some tier can write into `path` on this machine (the ownership test for a
/// recorded entry: a record names an entry, and only an entry some tier emits is removed).
pub fn emittable(path: &str, domains_high: &[&str], machine: &MachineInputs) -> Vec<String> {
    let mut out = Vec::new();
    for tier in [Tier::Relaxed, Tier::Medium, Tier::High] {
        for e in plan(tier, domains_high, machine).list(path) {
            if !out.contains(e) {
                out.push(e.clone());
            }
        }
    }
    for (p, e) in RETIRED {
        if *p == path && !out.iter().any(|o| o == e) {
            out.push((*e).to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: &[&str] = &["webhook.site"];

    #[test]
    fn off_generates_nothing() {
        let b = plan(Tier::Off, D, &MachineInputs::default());
        assert!(b.lists.iter().all(|(_, v)| v.is_empty()));
        assert!(b.scalars.is_empty());
    }

    #[test]
    fn tier_matrix() {
        let m = MachineInputs::default();
        let r = plan(Tier::Relaxed, D, &m);
        let md = plan(Tier::Medium, D, &m);
        let h = plan(Tier::High, D, &m);
        assert!(r.list("permissions.deny").is_empty());
        assert!(md.list("permissions.deny").is_empty());
        assert_eq!(h.list("permissions.deny"), ["Bash(bash -c *)"]);
        assert!(r.list("sandbox.filesystem.allowRead").is_empty());
        assert!(h
            .list("sandbox.filesystem.denyRead")
            .contains(&"~/".to_string()));
        assert!(!md
            .list("sandbox.filesystem.denyRead")
            .contains(&"~/".to_string()));
        assert!(md
            .list("sandbox.filesystem.denyRead")
            .contains(&"~/.npmrc".to_string()));
        assert!(!r
            .list("sandbox.filesystem.denyRead")
            .contains(&"~/.npmrc".to_string()));
        assert!(h
            .scalars
            .contains(&"permissions.blockReadsOutsideWorkingDirectories"));
        assert!(!md
            .scalars
            .contains(&"permissions.blockReadsOutsideWorkingDirectories"));
        for b in [&r, &md, &h] {
            let dr = b.list("sandbox.filesystem.denyRead");
            assert!(
                !dr.iter().any(|e| e.starts_with("~/.config/solana")),
                "{dr:?}"
            );
            assert!(b
                .list("sandbox.filesystem.denyWrite")
                .contains(&"~/.config/solana/id.json".to_string()));
        }
    }

    #[test]
    fn repo_git_dir_is_absolute_and_relative_git_is_retired() {
        let m = MachineInputs {
            git_common_outside: None,
            git_dir: Some("/repo/.git".into()),
        };
        let w = plan(Tier::Relaxed, D, &m);
        let w = w.list("sandbox.filesystem.allowWrite");
        assert!(w.contains(&"/repo/.git".to_string()));
        assert!(!w.contains(&".git".to_string()));
        assert!(emittable("sandbox.filesystem.allowWrite", D, &m).contains(&".git".to_string()));
        assert!(!emittable("sandbox.filesystem.denyWrite", D, &m).contains(&".git".to_string()));
    }

    #[test]
    fn git_common_dir_is_writable_when_outside() {
        let m = MachineInputs {
            git_common_outside: Some("/repo/.git".into()),
            git_dir: None,
        };
        let b = plan(Tier::Relaxed, D, &m);
        assert!(b
            .list("sandbox.filesystem.allowWrite")
            .contains(&"/repo/.git".to_string()));
    }
}
