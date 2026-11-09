//! The CLI's help. `--help`, `-h` and `help [<command>]` print the overview or one command's
//! usage on stdout and exit 0. `<command> --help|-h` prints the same usage instead of running
//! the command, so a help request never performs the action. The hook entry points read the
//! hook payload on stdin and are not offered that. The full reference is docs/cli.md.

use std::io::Write;
use std::process::ExitCode;

use safe_ai_skill::{adapt, adapt_opencode};

/// What `--help`, `-h` and `help` print.
const OVERVIEW: &str = concat!(
    "usage: safe-ai-skill <command> [args]

The plugin runs safe-ai-skill's hooks by itself; these commands are for your terminal.

commands:
  tier       show or change the firewall tier
  allow      request a time-boxed grant (it waits for your confirmation)
  revoke     drop every grant
  status     show the tier, grants, pending requests, spend and recent audit entries
  session    show session state, or create a session keypair
  firewall   write, show or check safe-ai-skill's block in .claude/settings.local.json
  env        list, set and unset keys of .env files without printing values
  verify     grade and pin the installed skill packs, or check one directory
  add        check a skill, MCP or repo source before you install it
  install    install skill packs from a local directory or tarball, graded and pinned
  registry   list or audit the project's skill registry
  doctor     check your Claude Code or Codex setup
  adapt      the hook entry point for Codex and opencode

  -h, --help print this help
  --version  print the version

Run `safe-ai-skill help <command>` or `safe-ai-skill <command> --help` for a command's usage.
A pending request takes effect when your next prompt in Claude Code is exactly
`safe-ai-skill confirm <code>`, with the code safe-ai-skill shows you; it is not a terminal
command. The other subcommands (gate-*, redact, prompt-guard, ...) are run by the hooks.

Full reference: docs/cli.md (",
    env!("CARGO_PKG_REPOSITORY"),
    "/blob/v",
    env!("CARGO_PKG_VERSION"),
    "/docs/cli.md)\n"
);

const TIER: &str = "usage:
  safe-ai-skill tier
  safe-ai-skill tier [off|relaxed|medium|high] [--env-read deny|tier] [--project]
  safe-ai-skill tier --clear [--project]

With no argument, prints the tier, its source and the sandbox state (JSON). A tier name sets
your tier for every project, or with --project for this repository only. --env-read deny denies
project .env reads at every tier; --env-read tier makes them follow the tier. --clear drops
your stored choice. Raising the tier, or --env-read deny, applies at once; lowering it, or
--env-read tier, records a pending request that you confirm. `mode` is a deprecated alias.
";

const MODE: &str = "usage: safe-ai-skill mode [<args>]

Deprecated alias of `safe-ai-skill tier`: it takes the same arguments and prints a warning.
See `safe-ai-skill tier --help`.
";

const ALLOW: &str = "usage:
  safe-ai-skill allow --scope <scope> --for <duration> [--max-tx <SOL>] [--budget <SOL>]
                      [--programs <addr,addr>] [--to <addr,addr>] [--danger]

Requests a time-boxed grant. Nothing takes effect until you confirm it.
  --scope     transfer, swap, deploy, authority or destructive (authority and destructive
              grants relax nothing: those verdicts are hard guards)
  --for       a duration such as 30m, 2h or 1d; at most 30 days
  --max-tx    per-transaction SOL limit (default 0)
  --budget    total SOL limit (default 0); give both for a transfer or swap grant
  --programs  comma-separated base58 addresses the grant is limited to
  --to        comma-separated base58 addresses the grant is limited to
  --danger    adds \"(danger)\" to the summary you confirm; it changes no decision
";

const REVOKE: &str = "usage: safe-ai-skill revoke

Drops every grant at once; it applies immediately. The agent cannot run it: run it in your
terminal.
";

const STATUS: &str = "usage: safe-ai-skill status

Prints JSON: the tier and its source, the sandbox state, live grants, pending requests (never
their codes), the spend ledger and caps, the env_read setting, recent audit entries and the
data dir it used.
";

const SESSION: &str = "usage:
  safe-ai-skill session
  safe-ai-skill session init --cap <SOL>

Shows session state (JSON). `init` generates a session keypair, writes it in plain
Solana-keypair format (mode 0600) under session/<id>.json in the data dir, and prints how to
fund it. No gate reads this state, so it relaxes nothing.
";

const FIREWALL: &str = "usage:
  safe-ai-skill firewall apply [off|relaxed|medium|high] [--project] [--dry-run|-n]
  safe-ai-skill firewall show
  safe-ai-skill firewall check

`apply` writes a safe-ai-skill-owned block of sandbox restrictions into the project's
.claude/settings.local.json (--dry-run: report, write nothing). Naming a tier also sets your
tier, as `tier <name>` does (--project: this repository only; it needs a tier name). Raising
applies at once; lowering records a pending request that you confirm. `show` prints what
safe-ai-skill owns in the file; `check` compares it with the declared tier and exits non-zero
on drift.
";

const VERIFY: &str = "usage:
  safe-ai-skill verify [session]
  safe-ai-skill verify check <dir>
  safe-ai-skill verify approve <name|dir>
  safe-ai-skill verify trust <dir>

`verify` (or `verify session`) is the sweep the SessionStart hook runs: it grades and pins the
installed packs. `check` grades one directory as the sweep would at your tier and lists every
finding; it pins nothing. `approve` re-pins a drifted pack you reviewed and `trust` trusts a
pack dir; both record a pending request that you confirm. Output is JSON.
";

const ADD: &str = "usage: safe-ai-skill add skill|mcp|repo <source> [--yes] [--force] [--offline]

Checks a source before you install it and prints the install command in the \"run\" field; it
never installs anything or writes .mcp.json. A local directory given to `add skill` or
`add repo` is graded like the session sweep, at your tier. A URL or package name gets a
provenance check only: a GitHub ref that is not a full commit, or an npm version that is not
exact, is held until --yes; an exact npm version is looked up on osv.dev unless --offline.
--force implies --yes and also takes a local pack the tier denies. Output is JSON.
";

const INSTALL: &str =
    "usage: safe-ai-skill install [--from <dir|tarball>] [--home <dir>] [--yes] [--force]

Grades each skill pack in a local directory or tarball as the session sweep would at your
tier, then copies the ones it takes into ~/.claude/skills (or <dir>/.claude/skills with
--home) with telemetry preambles removed, and pins them. It never downloads anything. With no
--from it grades and pins the project's .claude/skills in place. --yes takes packs with
warnings; --force also takes packs the tier denies. Output is JSON.
";

const REGISTRY: &str = "usage: safe-ai-skill registry [list|verify]

`list` (the default) shows the project's skill-registry.json catalog (path from
catalog.registry_path) with risk classes flagged; `verify` audits the installed entries against
it. A missing registry file is an empty catalog. Output is JSON.
";

const DOCTOR: &str = "usage:
  safe-ai-skill doctor
  safe-ai-skill doctor --codex

Checks your Claude Code settings and prints a sandbox denyRead snippet; it always exits 0.
--codex checks the Codex hook setup instead and exits 1 on a failure.
";

const VERSION: &str = "usage: safe-ai-skill --version

Prints the version.
";

/// A command's usage.
enum Usage {
    Text(&'static str),
    /// `env`'s own (`env --help`).
    Env,
}

/// The commands that print their usage for `<command> --help|-h` as well as `help <command>`.
const COMMANDS: &[(&str, Usage)] = &[
    ("tier", Usage::Text(TIER)),
    ("mode", Usage::Text(MODE)),
    ("allow", Usage::Text(ALLOW)),
    ("revoke", Usage::Text(REVOKE)),
    ("status", Usage::Text(STATUS)),
    ("session", Usage::Text(SESSION)),
    ("firewall", Usage::Text(FIREWALL)),
    ("env", Usage::Env),
    ("verify", Usage::Text(VERIFY)),
    ("add", Usage::Text(ADD)),
    ("install", Usage::Text(INSTALL)),
    ("registry", Usage::Text(REGISTRY)),
    ("doctor", Usage::Text(DOCTOR)),
];

/// The hook entry points: `help <name>` says the hooks run them; `<name> --help` runs the hook.
const HOOKS: &[&str] = &[
    "gate-bash",
    "gate-bash-secrets",
    "gate-read",
    "gate-mcp",
    "gate-webfetch",
    "gate-config",
    "gate-permission",
    "session-end",
    "gate-tamper",
    "gate-skill",
    "gate-prompt-expansion",
    "redact",
    "failure-notice",
    "prompt-guard",
    "pending-notice",
];

/// `--help`, `-h` and `help [<command>]`: the overview, or one command's usage. A name that is
/// not a subcommand is a usage error, as it is without `help`.
pub fn main(rest: &[String]) -> ExitCode {
    let Some(name) = rest.first().map(String::as_str) else {
        return print(OVERVIEW);
    };
    if let Some((_, usage)) = COMMANDS.iter().find(|(cmd, _)| *cmd == name) {
        return show(usage);
    }
    match name {
        "help" | "--help" | "-h" => print(OVERVIEW),
        "--version" => print(VERSION),
        "adapt" => print(&adapt_usage()),
        hook if HOOKS.contains(&hook) => print(&format!(
            "safe-ai-skill {hook}: a hook subcommand.\nThe plugin's hooks run it with the hook \
             payload on stdin; you do not run it yourself.\nSee the Hooks section of \
             docs/cli.md.\n"
        )),
        _ => crate::cmd_unknown(name),
    }
}

/// `<command> --help|-h`: print `sub`'s usage when `--help` or `-h` is its first argument and
/// it is one of [`COMMANDS`]. `None` lets the command run.
pub fn flag(sub: &str, rest: &[String]) -> Option<ExitCode> {
    if !matches!(rest.first().map(String::as_str), Some("--help" | "-h")) {
        return None;
    }
    COMMANDS
        .iter()
        .find(|(cmd, _)| *cmd == sub)
        .map(|(_, usage)| show(usage))
}

fn show(usage: &Usage) -> ExitCode {
    match usage {
        Usage::Text(text) => print(text),
        Usage::Env => safe_ai_skill::env::main(&["--help".to_string()]),
    }
}

/// `adapt`'s entries, from the lists it accepts.
fn adapt_usage() -> String {
    format!(
        "usage:
  safe-ai-skill adapt codex <{}|session-start|redact {}>
  safe-ai-skill adapt opencode <{}>

The Codex and opencode hook templates run this with the hook payload on stdin; you do not run
it yourself. Setup: docs/adapters.md.
",
        adapt::CODEX_GATES.join("|"),
        adapt::codex::BLOCK_WITH_REDACTION,
        adapt_opencode::GATES.join("|"),
    )
}

fn print(text: &str) -> ExitCode {
    let _ = std::io::stdout().write_all(text.as_bytes());
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every subcommand has help, and help names only real subcommands.
    #[test]
    fn help_covers_every_subcommand() {
        let documented = |name: &str| {
            COMMANDS.iter().any(|(cmd, _)| *cmd == name)
                || HOOKS.contains(&name)
                || matches!(name, "help" | "--help" | "-h" | "--version" | "adapt")
        };
        for (name, _) in crate::SUBCOMMANDS {
            assert!(documented(name), "`{name}` has no help entry");
        }
        let registered = |name: &str| crate::SUBCOMMANDS.iter().any(|(sub, _)| *sub == name);
        for name in COMMANDS
            .iter()
            .map(|(cmd, _)| *cmd)
            .chain(HOOKS.iter().copied())
        {
            assert!(registered(name), "`{name}` is not a subcommand");
        }
    }

    /// `<hook> --help` must still run the hook: a hook reads its payload, not its arguments.
    #[test]
    fn no_hook_takes_a_help_flag() {
        for name in HOOKS.iter().chain(&["adapt", "--version"]) {
            assert!(!COMMANDS.iter().any(|(cmd, _)| cmd == name), "{name}");
            assert!(flag(name, &["--help".to_string()]).is_none(), "{name}");
        }
    }

    #[test]
    fn help_flag_counts_only_as_the_first_argument() {
        let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(flag("tier", &args(&["high", "--help"])).is_none());
        assert!(flag("tier", &args(&[])).is_none());
        assert!(flag("tier", &args(&["help"])).is_none());
        assert!(flag("bogus", &args(&["--help"])).is_none());
    }

    #[test]
    fn the_text_fits_a_terminal() {
        let texts = COMMANDS
            .iter()
            .filter_map(|(_, usage)| match usage {
                Usage::Text(text) => Some(*text),
                Usage::Env => None,
            })
            .chain([OVERVIEW, VERSION]);
        for text in texts {
            for line in text.lines() {
                assert!(line.chars().count() <= 100, "{line}");
            }
        }
    }
}
