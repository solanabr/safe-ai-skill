# Command-line reference

The `safe-ai-skill` binary is both the engine the hooks call and a CLI you run yourself. This page lists every subcommand and flag in `crates/engine/src/main.rs` and the modules it dispatches to. For what the firewall decides at each tier, see [docs/tiers.md](tiers.md).

- **Help:** `safe-ai-skill --help`, `-h` and `help` print the list of commands. `safe-ai-skill help <command>`, and `safe-ai-skill <command> --help` or `-h` as the first argument after the command, print that command's usage and do not run it. They exit 0. `help` with a name that is not a command exits 3, `help confirm` included (see [Which commands need the CLI](#which-commands-need-the-cli)). `help <hook subcommand>` says the hooks run it; a hook subcommand given `--help` still runs as the hook.
- **Output:** `status`, `tier`, `firewall`, `add`, `install`, `verify`, `registry`, `allow` and `session` print JSON on stdout. `doctor`, `env` and the help print text. A request that is parked for your confirmation prints a "Pending request …" line on stderr and JSON on stdout.
- **Exit codes vary by command.** An unknown top-level subcommand exits 3, as do usage errors from `add`, `env` and `adapt`. Other usage and argument errors print a JSON error and exit 0 or 1 depending on the command (`tier`, `allow`, `firewall` and `verify check` exit 1; `install`, `registry` and other `verify` errors can exit 0), so check the JSON, not just the exit code. `add` exits 0 whatever its verdict (read `status` and `proceed`), and 1 when a local path is not a directory. `doctor` always exits 0, `doctor --codex` exits 1 on a failure, `firewall check` exits non-zero on drift, and `env keys --require` exits 3 when a key is missing.
- **Version:** `safe-ai-skill --version`.

## Which commands need the CLI

The plugin runs the hooks by itself. Install the CLI (see [Install](../README.md#install)) to run `tier`, `allow`, `revoke`, `status`, `session`, `doctor`, `firewall`, `env`, `add`, `install`, `verify`, `registry` and `adapt`.

`safe-ai-skill confirm <code>` is not a terminal command: it works only as your entire next prompt in Claude Code (see [Confirming a relaxation](#confirming-a-relaxation)). Typed in a terminal it is an unknown subcommand.

Some commands change what the firewall trusts, so the agent cannot run them: the tamper tripwire denies a Bash command that runs `confirm`, `revoke`, `verify approve`, `verify trust`, `install`, `add`, bare `verify` and `verify session`, `adapt`, or any hook subcommand, also with `--help` after it. Run those in your own terminal. `tier`, `allow`, `status`, `registry`, `doctor`, `firewall`, `env keys`, `verify check <dir>`, `verify --help`, `--help`, `-h` and `help [<command>]` stay open to the agent: `tier` can only raise the tier or create a request the agent cannot confirm, and `allow` only records a request. See [SECURITY.md](../SECURITY.md#design-guarantees).

## Where the CLI keeps state

From a terminal, the CLI reads and writes the same state as the hooks. The data dir is resolved in this order:

1. `CLAUDE_PLUGIN_DATA`, when set.
2. The plugin's dir under `~/.claude/plugins/data/` (or `$CLAUDE_CONFIG_DIR/plugins/data/`): `safe-ai-skill-safe-ai-skill` first, then `safe-ai-skill-stbr`, then the only `safe-ai-skill-*` dir. Several plugin dirs that make the choice ambiguous make the CLI exit 1.
3. Otherwise a standalone dir: `$SAFE_AI_SKILL_DATA` (an absolute path), else `safe-ai-skill-data` under `~/Library/Application Support` (macOS), `$XDG_DATA_HOME` or `~/.local/share` (other unix), or `%LOCALAPPDATA%` (Windows).

If the plugin is installed but Claude Code has not created its data dir yet (it does so on the first hook run), the CLI says to start a session once. The full order, with the Codex notes, is in [docs/adapters.md](adapters.md#state-tiers-grants-and-audit). `status` prints the dir it used.

## Tier and grants

### `tier`

```bash
safe-ai-skill tier                                       # show the tier, its source, the sandbox state, ignored hints
safe-ai-skill tier <off|relaxed|medium|high> [--project] # set the user-scope tier (--project: this repository only)
safe-ai-skill tier --env-read deny|tier [--project]      # project .env reads: deny at every tier, or follow the tier
safe-ai-skill tier --clear [--project]                   # drop your stored choice
```

A tier and `--env-read` can be given in one call (`tier high --env-read deny`). Raising the tier, or tightening `--env-read` to `deny`, applies at once. Lowering it, or loosening `--env-read` back to `tier`, records a pending request that you confirm (see [Confirming a relaxation](#confirming-a-relaxation)). `--env-read ask` was removed in 1.2.0 and is refused. `mode` is a deprecated alias of `tier` that prints a warning.

### `allow`

```bash
safe-ai-skill allow --scope <scope> --for <duration> [--max-tx <SOL>] [--budget <SOL>] \
                    [--programs <addr,addr>] [--to <addr,addr>] [--danger]
```

Requests a time-boxed grant. Nothing takes effect until you confirm it.

| Flag | Meaning |
|---|---|
| `--scope` | `transfer`, `swap` or `deploy`. Anything else is an error (exit 1). `authority`, `destructive` and `secret_read` are refused with the reason: every authority, destructive or secret-read verdict is a hard guard, which no grant relaxes |
| `--for` | Duration such as `30m`, `2h` or `1d`; at most 30 days |
| `--max-tx`, `--budget` | Per-transaction and total SOL limits. Both default to 0, which covers no positive SOL amount, so give both for a `transfer` or `swap` grant. They never cover `spl-token` or MCP token transfers, which are token units |
| `--programs`, `--to` | Comma-separated base58 addresses the grant is limited to |
| `--danger` | Adds "(danger)" to the summary you confirm; it changes no decision |

A command line that chains two or more gated on-chain actions, or holds any hard-guard ask, is never covered by a grant.

1.3.0 accepted `authority` and `destructive` grants, which relaxed nothing. One it stored stays in `grants.json` until it expires or you run `revoke`, and still relaxes nothing: the session notice prints it as `inert grant …, relaxes nothing (…)` and `status` marks it `"inert": true`. A pending request for one fails at confirmation with the reason, and no grant is stored.

### `revoke`

`safe-ai-skill revoke` drops every grant at once and applies immediately. The agent cannot run it; run it in your terminal.

### `status`

`safe-ai-skill status` prints JSON: the tier and its source, the `tier_line`, the sandbox state, live grants (each with `inert`, true for a grant that relaxes nothing), pending requests (id, kind, created, lapses; never the code), the spend ledger and caps (`per_tx_sol_max`, `hard_tx_sol_max`, `daily_sol_max`, `today_sol`), the `env_read` setting, recent audit entries, and the data dir it used. It does not list pins; use `verify` for those.

### `session`

`safe-ai-skill session` shows session state, as does `session` with any action other than `init`. `session init --cap <SOL>` generates a session keypair, writes it in plain Solana-keypair format (mode 0600) under `session/<id>.json` in the data dir, and prints how to fund it; a missing or unreadable `--cap` is 0. No gate reads this state, so it relaxes nothing.

## Confirming a relaxation

`allow`, a `tier` lowering, an `--env-read` loosening, `firewall apply` below the applied tier, `verify approve` and `verify trust` change nothing on their own. They record a request (`request r3fa91c`) and print no code. Claude Code shows you the code in a hook message that never enters the agent's context, and the request takes effect when your next prompt is exactly `safe-ai-skill confirm <code>`. The rules (the 10-minute window, session binding, which sessions can confirm, native Windows, lockout) are in [docs/tiers.md](tiers.md#changing-the-tier-safe-ai-skill-tier).

## Settings manager

```bash
safe-ai-skill firewall apply [off|relaxed|medium|high] [--project] [--dry-run|-n]
safe-ai-skill firewall show     # what safe-ai-skill owns in the settings file
safe-ai-skill firewall check    # drift between the declared tier and the live file (exit non-zero on drift)
```

`apply` writes a safe-ai-skill-owned block of sandbox restrictions into the project's `.claude/settings.local.json`; at High it also adds a permission deny and `permissions.blockReadsOutsideWorkingDirectories`. It writes nothing at Off except removing what it added earlier. **Naming a tier also sets the plugin tier**, as `safe-ai-skill tier <t>` does: for every project, or for this repository only with `--project` (`--project` needs a tier name). Without a tier name, `apply` uses the tier already in effect and records no tier. `--dry-run` (or `-n`) reports what it would write and writes nothing. Raising applies at once; lowering needs the confirmation code. Details and caveats: [docs/tiers.md](tiers.md#settings-manager).

## Environment files

```bash
safe-ai-skill env keys [FILE] [--json] [--require K1,K2]      # keys with masked values; --require exits 3 when a key is missing, empty or a placeholder
printf %s '<value>' | safe-ai-skill env set FILE KEY [--multiline] [--all]   # value on stdin, never in argv
safe-ai-skill env unset FILE KEY
safe-ai-skill env init-schema [FILE]                           # write a .env.schema from FILE's keys (no values copied, never overwrites)
```

`FILE` defaults to `.env`. `env --help` prints this usage. From a Claude Code session, `set` and `unset` are refused at Medium (and at High for env files other than the project's `.env`/`.env.*`); the session's hook denies them first.

Three ways to keep secrets away from the model. Pick the one that fits; each keeps working without the next:

1. **Plain `.env` plus `safe-ai-skill env`.** The agent works with keys, never values: `env keys` lists keys with masked values, and `env set` takes the value on stdin so it never appears in argv.
2. **A `.env.schema`** in the [env-spec](https://varlock.dev/env-spec/) format that varlock uses. It lists keys, types and `@sensitive`/`@required` decorators, and it is committed, so the agent can read it directly. `env init-schema` writes one from your `.env` (keys only, every key sensitive by default), and `env keys` then annotates each key and lists declared keys that are unset. safe-ai-skill parses the schema itself and never runs varlock, because loading a schema with varlock executes `$(…)` and `exec()` values and plugins.
3. **varlock** with a secret provider or `varlock("local:…")` encryption. Run tools with `varlock run -- <cmd>` and inspect with `varlock load --agent`. Commands that print resolved values (`varlock printenv`, `reveal`, `load --format json|env|shell` without `--agent`, …) are treated like `cat .env`.

A `.env.schema` that holds key material, a literal credential, is over 64 KiB or is not a regular file is denied. See [docs/tiers.md](tiers.md#project-env-files) for what the hooks allow and deny.

## Verify, add and install

These commands check skills and MCPs. They are described, with examples, in the README section [Verify skills and MCPs before you install them](../README.md#verify-skills-and-mcps-before-you-install-them).

```bash
safe-ai-skill verify                          # session sweep: grade and pin the installed packs (the SessionStart hook runs this)
safe-ai-skill verify session                  # same as bare verify
safe-ai-skill verify check <dir>              # grade one directory as the sweep would at your tier, listing every finding (INFO included); pins nothing
safe-ai-skill verify approve <name|dir>       # re-pin a drifted pack after you reviewed it (needs your confirmation)
safe-ai-skill verify trust <dir>              # trust a pack dir; follows the content to other worktrees (needs your confirmation)

safe-ai-skill add skill|mcp|repo <source> [--yes] [--force] [--offline]
safe-ai-skill install [--from <dir|tarball>] [--home <dir>] [--yes] [--force]
safe-ai-skill registry list|verify
```

### What `add` does

`add` checks a source before you install it and prints the command that installs it, for you to run. It never runs that command, never writes `.mcp.json` and writes no pin or lockfile entry: `install` and `verify approve` are what pin packs.

**Arguments.** The kind and the source are the first two arguments that are not flags; `--yes`, `--force` and `--offline` may come anywhere. These are usage errors: a missing kind or source, a kind other than `skill`, `mcp` or `repo`, an unknown flag, an extra argument, a source that starts with `-`, a source with whitespace at either end or a control character anywhere, and whitespace inside a package name, URL or repository (a local directory may hold spaces; write it as `./name`). The problem and the usage line go to stderr, the JSON has `"status": "error"`, and `add` exits 3. A local path that is not a directory is an error with exit 1 (`no such local directory`, or `not a directory` for a file), for every kind. A bare name that is a directory here (`demo`, not `./demo`) is graded as that directory, and `"source_note"` says so; run `add` from another directory to check a package or repository of that name.

**What kind of source it is.** The JSON's `source_kind` is one of:

| `source_kind` | Sources |
|---|---|
| `local` | `.`, `..`, `~`, `~/x`, `./x`, `../x`, an absolute path, a Windows drive or UNC path, and any other name that is a directory here |
| `github` | A URL whose host is exactly `github.com` or `www.github.com` (`https`, `http`, `git+https`, `git://`, `ssh://`, `git+ssh`, a schemeless `github.com/o/r` or `git@github.com:o/r`), with an optional `/tree/<ref>[/<path>]` or `/commit/<sha>`; or the shorthand `owner/repo[/<path>]` or `github:owner/repo`. The rest follows the skills CLI (`skills@1.7.6`): `#<ref>` or `#<ref>@<skill>` names a ref (a `tree/<ref>` in the URL wins over it), and `owner/repo@<name>` always names a skill, never a ref, so `owner/repo@<sha>` pins nothing. A repository named `.git` is refused |
| `npm` | A valid package name, optionally scoped (`@scope/pkg`), prefixed `npm:` or given as an `npmjs.com/package/…` URL, with an optional `@<version>` |
| `other` | Anything else: a URL on another host (GitLab, a tarball, a remote MCP server), including one that only mentions `github.com` in its path, and a URL whose authority holds a `%` or is cut short by a `?`, `#` or `\` before the host |

**What it checks.**

- **A local directory**, for every kind (`add mcp` included), is graded by the same rule engine as the SessionStart sweep, at your tier (see [Install grading](#install-grading---yes-and---force)).
**Only a source you pinned exactly can pass**: a full 40-hex commit or an exact npm `x.y.z` version that you wrote. Anything that moves is held (`warn_hold`) until you pass `--yes`, even when `add` could resolve it.

- **A GitHub source** passes when it names a full 40-hex commit (`owner/repo#<sha>`, `…/tree/<sha>`, `…/commit/<sha>`). Any other ref, the default branch included, is a MEDIUM `unpinned_ref` finding and holds. Online, `add` asks the GitHub API (`api.github.com`, unauthenticated, so GitHub allows about 60 lookups an hour) for the commit the ref names now and puts it in `"pin"` and in the printed command, so `--yes` installs exactly the commit that was checked; the finding says what it resolved to. When the lookup fails or is rate-limited, or under `--offline`, the printed command is your source as given.
- **An npm source** passes when it names an exact `major.minor.patch` version (`pkg@1.2.3`; `pkg@1` and `pkg@1.2` are not exact, and no whitespace is allowed). No version or a dist-tag (`latest`, `next`) is a MEDIUM `unpinned_version` finding and holds; online, `add` asks the npm registry for the exact version it serves now, grades that version, and prints it. A range (`^1.0.0`, `1.x`) is not resolved: it holds and gets no CVE lookup. A name within edit distance 2 of a popular package is a HIGH `typosquat` finding, which blocks; `--yes` and `--force` do not override it.
- **The exact npm version**, the one you named or the one the registry resolved, is looked up on osv.dev, and that is the version `run` installs. A known advisory is graded by its severity (a numeric CVSS score of 7 or more, or a HIGH or CRITICAL label, is HIGH and blocks; 4 to 7 or MODERATE is MEDIUM and is held until `--yes`; below 4 is LOW; an advisory with no severity counts as HIGH). `add` follows osv.dev's `next_page_token` for up to 5 pages. When osv.dev cannot answer (an HTTP error, unreachable or timed out after 4 s, a reply that is not `{}` or an object with a `vulns` array) or the answer is still unfinished after 5 pages, `add` records a MEDIUM `osv_unavailable` finding and holds until `--yes`.
- **Any other source** is a MEDIUM `unrecognised_source` finding, held until `--yes`: nothing about it was checked. A remote `http(s)` MCP server gets its own message, since its code runs on someone else's machine.
- **The project catalog** (`skill-registry.json`, path from `catalog.registry_path`) is checked first, with no network and under `--offline` too. A source matches an entry by the entry's id, or by what it names: the npm package in any spelling (any version, `npm:` or an npmjs.com URL, any case) or the GitHub `owner/repo` in any URL or shorthand form. An entry in a high-risk class (`wallet_signing`, `key_custody`, `installer_script`) is held as `high_risk_ask` until you pass `--yes`, and none of the other checks run until then (the three shipped classes all `ask`; a repo cannot change catalog classes, so no shipped path reaches `high_risk_deny`). A catalog id, such as `add mcp phantom-mcp`, is graded and printed as its entry's own source, never as an npm package of that name. The JSON names the entry: `entry_id` and `catalog_source` on a `high_risk_*` result, `catalog_entry` and `catalog_source` otherwise.

`--offline` turns off every network step: the GitHub and npm lookups and osv.dev. A full commit or an exact npm version still passes (npm with a LOW `osv_skipped` finding); a moving source stays held.

**The install command.** When the add proceeds (it passed, or you passed `--yes` or `--force`), `"run"` holds the command; `"pin"` is the commit or version that was graded and that the command installs (null when there is none; it is there on a held result too), and `"run_note"` says why `run` is null, or that the command is not pinned. Parts that come from your source are single-quoted when the shell would read them specially.

| Kind | GitHub | npm | Local directory | Other |
|---|---|---|---|---|
| `skill` | `npx skills add o/r#<sha>`, with a skill `npx skills add o/r#<sha>@<skill>`; a sub-directory as `npx skills add https://github.com/o/r/tree/<sha>/<path>`, with ` --skill <skill>` for a skill. A `…/commit/<sha>` URL prints as `o/r#<sha>`; your own `o/r#<sha>` prints as you typed it | none: the skills CLI does not install npm packages | `npx skills add ./<path>` | `npx skills add <source>` |
| `mcp` | none: clone it, then `claude mcp add <name> -- <the command that starts it>` | `claude mcp add <name> -- npx -y <pkg>@<version>` | none, for the same reason | `claude mcp add --transport http <name> <url>` for an `http(s)` URL; otherwise none |
| `repo` | `git clone <url> <repo> && git -C <repo> checkout --detach <sha>` | none | `git clone <path>` | `git clone <source>` |

The server `<name>` is the package name without its scope, or the URL's host without `www.` and with dots turned into dashes.

These are the forms the skills CLI `skills@1.7.6` reads as a pin; it reads `o/r@<x>` as the skill `x`, never a commit. A GitHub or npm source that could not be pinned (offline, or a failed lookup), taken with `--yes`, prints your source as given (for example `npx skills add o/r`, `git clone --branch main https://github.com/o/r.git` or `claude mcp add <name> -- npx -y <pkg>`), with a `run_note` saying it installs whatever the source points to when you run it.

The `status` field of the result is `pass`, `warn_hold`, `warn_proceed`, `blocked`, `force_proceed`, `high_risk_ask` or `high_risk_deny`.

### Install grading: `--yes` and `--force`

`install` and `add` (for a local directory) grade each pack the way the SessionStart sweep would at your tier:

| Result of grading | Taken when |
|---|---|
| Clean | Always |
| Warnings, or an unreviewed HIGH finding below tier High | You pass `--yes` (the pack is pinned as unreviewed, so the sweep keeps reporting it) |
| The tier denies it (a combination BLOCK, a `packs.lock` mismatch, an unreviewed HIGH at High, a pack too large to scan), or a combination BLOCK at any tier, Off included | You pass `--force`; the gates still deny such a pack in place once it is swept |

`--force` implies `--yes`.

`install` never downloads anything: `--from` takes a local directory or tarball (extracted with `tar`), so fetch a hub yourself (for example with `git clone`) and point `--from` at it. It neutralizes telemetry preambles and pins each pack it takes. `--home <dir>` (or `SAFE_AI_SKILL_HOME`) installs into `<dir>/.claude/skills` instead of `~/.claude/skills`. With no `--from`, `install` verifies the current project's `.claude/skills` in place (scan, pin, no copy) and rewrites a `SKILL.md` there to remove a telemetry preamble it finds, unless the project's `.safe-ai-skill/packs.lock` pins that pack (the output lists it under `not_neutralized`). It does not widen `~/.claude/settings.json` permissions.

### `registry`

`registry list` (or `registry` alone) shows the project's `skill-registry.json` catalog (path from `catalog.registry_path`) with risk classes flagged. `registry verify` audits installed entries against it. A missing registry file is an empty catalog.

## Health checks and adapters

```bash
safe-ai-skill doctor            # checks your Claude Code settings; prints a sandbox denyRead snippet; always exits 0
safe-ai-skill doctor --codex    # checks the Codex hook setup; exits 1 on a failure

safe-ai-skill adapt codex <gate-bash|gate-bash-secrets|gate-tamper|gate-mcp|session-start|redact --block-with-redaction>
safe-ai-skill adapt opencode <gate>
```

`adapt` is what the Codex and opencode hook templates call. Setup is in [docs/adapters.md](adapters.md).

## Hooks

The plugin registers these hooks (`plugins/safe-ai-skill/hooks/hooks.json`). Each is `safe-ai-skill <subcommand>` run through the shim. `onFailure: block` means Claude Code blocks the call when the hook fails (it cannot start, exits with a code other than 0 or 2, times out or prints invalid output; for `PermissionRequest` it denies); `continue` lets the call proceed (fail open).

| Event | Matcher | Subcommand | `onFailure` |
|---|---|---|---|
| PreToolUse | Bash | `gate-bash` | block |
| PreToolUse | Bash | `gate-bash-secrets` | continue |
| PreToolUse | Write, Edit, MultiEdit, NotebookEdit | `gate-tamper` | continue |
| PreToolUse | Read, Grep, Glob | `gate-read` | continue |
| PreToolUse | WebFetch | `gate-webfetch` | continue |
| PreToolUse | `mcp__.*` | `gate-mcp` | continue |
| PreToolUse | Skill | `gate-skill` | block |
| PostToolUse | Bash, Read, Grep, `mcp__.*` | `redact` | continue |
| PostToolUse | Bash | `pending-notice` | continue |
| PostToolUseFailure | Bash, Read, Grep, `mcp__.*` | `failure-notice` | continue |
| PermissionRequest | Bash, file tools, WebFetch, `mcp__.*` | `gate-permission` | block |
| SessionEnd | all | `session-end` | continue |
| ConfigChange | user, project and local settings | `gate-config` | continue |
| UserPromptSubmit | all | `prompt-guard`, `gate-prompt-expansion` | continue |
| UserPromptExpansion | all | `gate-prompt-expansion` | continue |
| SessionStart | startup, resume, clear, compact | `verify session` | continue |

`onFailure` is only part of the failure behaviour. An engine crash blocks `gate-bash`, `gate-mcp` and `gate-skill` (exit 2) whatever their `onFailure` says, and a binary that cannot run on the platform fails open with a notice while Solana CLI commands still ask. The rules are in [SECURITY.md](../SECURITY.md#design-guarantees).

Other hooks' jobs: `prompt-guard` blocks a prompt that holds a pasted keypair byte array, base58 secret key or checksummed BIP-39 phrase (the blocked text still reaches the session transcript); `gate-prompt-expansion` blocks a typed `/name` slash command whose skill pack is blocked; `pending-notice` shows you the confirmation code; `failure-notice` warns when a failed tool call's raw output held a secret; `session-end` writes the [session report](tiers.md#session-report).

## Environment variables

| Variable | Effect |
|---|---|
| `SAFE_AI_SKILL_DISABLE=1` | The shim turns the hooks off. Ignored (the hooks keep running) in strict mode, or when the project's committed `.claude/settings.json` mentions it or cannot be read. SessionStart reports it. This is not the tier `off` |
| `SAFE_AI_SKILL_STRICT=1` | If the engine cannot run, block instead of failing open |
| `SAFE_AI_SKILL_TIER` | Raise the tier for this process; it can never lower it. `SAFE_AI_SKILL_PROFILE` is the old name |
| `SAFE_AI_SKILL_SHIM_CACHE=0` | Turn off the shim's verified-hash cache, so every hook call hashes the engine binary again |
| `SAFE_AI_SKILL_DATA` | Absolute path of the standalone data dir (used when the plugin's dir is not in play) |
| `SAFE_AI_SKILL_BIN_DIR` | Where `install.sh` puts the binary (default `~/.local/bin`) |
| `SAFE_AI_SKILL_VERSION` | Release `install.sh` downloads (default: the version it ships with) |
| `SAFE_AI_SKILL_PLUGIN` | `0`: `install.sh` installs the CLI only, without the Claude Code plugin that runs the hooks |
| `SAFE_AI_SKILL_HOME` | Install root for `install --from`, like `--home` |
| `SAFE_AI_SKILL_HEADLESS`, `KIT_FIREWALL_HEADLESS` | `1` or `true` makes the run headless: every `ask` becomes a `deny` (CI variables do the same; see below) |
| `SAFE_AI_SKILL_DEADLINE_MS` | Shortens the 8 s per-gate deadline after which a gate answers `ask`; it cannot lengthen it, and the floor is 2 s |
| `SAFE_AI_SKILL_ENGINE` | Engine path for the opencode plugin |
| `CLAUDE_PLUGIN_DATA`, `CLAUDE_CONFIG_DIR`, `CLAUDE_PROJECT_DIR` | Set by Claude Code; the CLI reads them to find the same state and project |

The headless rule (which variables turn it on, and that nothing turns it off) is in [docs/tiers.md](tiers.md#headless). `claude -p` on its own does not turn headless on, though no confirmation code is shown or accepted there.
