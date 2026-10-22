<p align="center">
  <img src="assets/banner.png" alt="Safe AI Skill — security firewall and supply-chain verifier for Claude Code skills and MCPs" width="100%" />
</p>

<p align="center">
  <a href="https://github.com/solanabr/safe-ai-skill/actions/workflows/ci.yml"><img src="https://github.com/solanabr/safe-ai-skill/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/version-1.0.1-blue" alt="Version">
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="License">
  <img src="https://img.shields.io/badge/Rust-1.82+-orange?logo=rust" alt="Rust">
  <img src="https://img.shields.io/badge/Claude_Code-plugin-purple" alt="Claude Code plugin">
</p>

# safe-ai-skill

safe-ai-skill is a Claude Code security plugin — a Rust hook-based firewall and registry-free supply-chain verifier that works with **any skills, MCPs, or agents** to add a policy-driven security layer. It was built with `solanabr/solana-ai-kit` as the reference integration (gating Solana transactions and deploys, verifying its `ext/` submodules and `skill-registry.json` catalog), but the gates, guards, and verifier are general-purpose and protect any Claude Code setup.

At `PreToolUse` it intercepts commands, MCP calls, and secret-file reads before they execute. At `SessionStart` it walks every installed skill and MCP submodule, pins content to git SHAs, and reports anything that drifted. Hard guards — mainnet deploys, authority changes, account closes, secret reads — are never relaxed by any profile, grant or flag.

## Install

safe-ai-skill has two layers. The **plugin** is the always-on runtime firewall (SessionStart verifier + PreToolUse gates). The **CLI** is the `safe-ai-skill` binary that powers the Tier 1/2 commands (`registry`, `add skill`, `add mcp`, `install`, `verify`, `status`). Most users want the plugin; install the CLI too if you want to gate skill/MCP installs before they run.

### Plugin (runtime firewall)

Requires Claude Code 2.1.295 or newer. Older versions still run the hooks but ignore their `onFailure` setting, so a hook that can't start never blocks anything. The prebuilt engine covers macOS (arm64, x64) and Linux (x64, arm64). The Linux builds are static (musl), so they run on any distribution, Alpine included.

```bash
claude plugin marketplace add solanabr/safe-ai-skill
claude plugin install safe-ai-skill@safe-ai-skill
```

Every Claude Code session is protected automatically from that point. No per-project configuration required.

**Dev install:** `claude plugin marketplace add .` from the repo root, then `claude plugin install safe-ai-skill@safe-ai-skill`.

**solana-ai-kit users: do nothing.** The kit's `stbr` marketplace already installs safe-ai-skill for you. Don't add this marketplace as well: with two copies installed, only one copy's hooks register, and you can't tell which one.

#### Moving from `safe-ai-skill@stbr`

Between 1.0.0 and 1.0.1 this README said to install `safe-ai-skill@stbr`. The solana-ai-kit marketplace is also named `stbr`, and removing it uninstalls the kit and deletes its data. Check what your `stbr` is before you remove anything:

```bash
claude plugin marketplace list
```

- If `stbr` comes from anything other than `solanabr/safe-ai-skill` (for example `solanabr/solana-ai-kit`), stop. You have the kit's copy and there is nothing to move.
- If `stbr` comes from `solanabr/safe-ai-skill`, switch to the new name:

  ```bash
  # only if 'marketplace list' shows stbr → solanabr/safe-ai-skill
  claude plugin uninstall safe-ai-skill@stbr --keep-data
  claude plugin marketplace remove stbr
  claude plugin marketplace add solanabr/safe-ai-skill
  claude plugin install safe-ai-skill@safe-ai-skill
  ```

The plugin keeps its pins, grants and audit log in a directory named after `plugin@marketplace`, so the new install starts empty, and its first session pins whatever is on disk at that moment. To keep your existing pins, copy the old state across before you start a session:

```bash
mkdir -p ~/.claude/plugins/data/safe-ai-skill-safe-ai-skill
cp -R ~/.claude/plugins/data/safe-ai-skill-stbr/. ~/.claude/plugins/data/safe-ai-skill-safe-ai-skill/
```

### CLI (`safe-ai-skill` command)

The plugin runs the firewall; the Tier 1/2 commands need the `safe-ai-skill` binary on your `PATH`. Pick one:

**npm**

```bash
npm install -g @stbr/safe-ai-skill           # installs the CLI globally (command: safe-ai-skill)
npx @stbr/safe-ai-skill add skill <name|url>  # or run without installing
```

`safe-ai-skill add skill <name|url>` is the headline command — it runs the full verification pipeline on the fetched content before any install touches your machine (see [Usage tiers](#usage-tiers)).

**Standalone script** (no npm or cargo)

```bash
curl -fsSL https://raw.githubusercontent.com/solanabr/safe-ai-skill/main/install.sh | sh
```

Downloads the prebuilt binary for your platform and verifies its SHA-256 against the release's published `SHA256SUMS` before installing — checksum-pinned, not an opaque pipe. Set `SAFE_AI_SKILL_BIN_DIR` to override the install location (default `~/.local/bin`).

**cargo** (any platform with a Rust toolchain)

```bash
cargo install safe-ai-skill
```

The npm and standalone paths download the binary matching their release tag and abort on any checksum mismatch.

## What it protects

**Runtime (PreToolUse firewall)**

- CLI commands: any `solana`, `spl-token`, `anchor`, or arbitrary shell command matching policy
- MCP calls: value-moving and authority-changing verbs (`send*`, `stake*`, `delegate*`, `mint*`, `bridge*`, `lend*`, `borrow*`) across any connected MCP
- Secret reads: `.env` and other env files, keypair files (by name and by content), private keys, credential paths — on Read, Grep and MCP path arguments, matched case-insensitively and through symlinks (see [Secrets and `.env`](#secrets-and-env)). A [varlock](https://varlock.dev) `.env.schema` stays readable but is denied when it holds key material (a keypair, a private-key block, an API token, or a literal value on a secret-named key; `varlock(...)` calls, `$VAR` references and placeholders don't count), is over 64 KiB, or is not a regular `.env.schema` file. safe-ai-skill never runs `varlock`.
- Interactive gate breakage: replaces broken `read -r` prompts (no TTY in hook context) with a functioning `ask` decision

**Supply-chain (SessionStart verifier)**

- Skill packs: sweeps the project's `.claude/skills`; `~/.claude/skills` only when a project's `.safe-ai-skill/policy.yaml` adds it to `supply_chain.verify_skills_dirs` (the only dir outside the project a project may add), plus packs installed there with `install --from`
- Per-submodule pinning: walks each `ext/` submodule independently; pins first-seen git SHA (TOFU); reports drift without moving anything. A drifted pack is reported every session until you run `safe-ai-skill verify approve <name>`, which re-pins it in place
- Catalog gating: classifies `skill-registry.json` entries by risk class (`wallet_signing`, `key_custody`, `installer_script`, `standard`); blocks installation of denied classes
- `curl | bash` detection: flags installer-script patterns before they execute
- MCP version tracking: flags `@latest` entries as informational — does not silently rewrite them
- CVE lookup: `add` queries osv.dev for an exact, non-local npm source such as `add mcp`'s resolved `pkg@version` (no API key required). The session sweep makes no network calls
- Heuristic scan: outbound POST in preambles, keypair/`.env` references, base58-encoded secrets, prompt injection, `eval`/download-and-exec

**Hard guards (never relaxable)**

`mainnet_deploy` · `set_authority` · `account_close` · `secret_read`

No profile, grant, flag or repo policy relaxes them. Mainnet deploys, authority changes and account closes always ask you (a mainnet `--final` deploy is denied), and secret reads are denied. Non-final deploys to other clusters are not hard guards, so a grant or profile can relax them.

## Secrets and `.env`

Raw reads of env files (`.env`, `.env.*`, `*.env`, `.envrc`, `.dev.vars`, `~/.config/solana/cli/config.yml`) are denied, and the deny message gives the commands to use instead. Keypair files, private keys, `~/.ssh/id_*` and the Solana config tree are never readable. `.env.example|.sample|.template|.dist` and `.env.schema` stay readable. A Grep over a directory has env and key files excluded from its results (this also hides `.env.example` and `.env.schema` from directory searches; read them directly), and a Grep over `$HOME` or another directory containing `~/.ssh` or `~/.config/solana` is denied; Glob only lists names and is not gated. Tool output that still contains a value from a project env file is shown as `«redacted:KEY»`.

Three tiers, pick the one that fits; each keeps working without the next:

1. **Plain `.env` + `safe-ai-skill env`.** The agent works with keys, never values:

   ```bash
   safe-ai-skill env keys .env                              # keys with masked values
   printf %s '<value>' | safe-ai-skill env set .env KEY     # value on stdin, never in argv
   safe-ai-skill env unset .env KEY
   ```

2. **Add a `.env.schema`** ([env-spec](https://varlock.dev/env-spec/), the format varlock uses). It lists keys, types and `@sensitive`/`@required` decorators and is committed, so the agent can read it directly. `safe-ai-skill env init-schema` writes one from your `.env` (keys only, every key sensitive by default), and `env keys` then annotates each key and lists declared keys that are unset. safe-ai-skill parses the schema itself: it never runs varlock, because loading a schema with varlock executes `$(…)`/`exec()` values and plugins.
3. **varlock** with a secret provider or `varlock("local:…")` encryption. Run tools with `varlock run -- <cmd>` and inspect with `varlock load --agent`. Commands that print resolved values (`varlock printenv`, `reveal`, `load --format json|env|shell` without `--agent`, …) are treated like `cat .env`.

Opt in to prompted raw reads with `secrets.env_read: ask` in the plugin's `policy/default.policy.yaml` (a project policy can't loosen it). The hooks stop a careless or prompt-injected model; for a hard boundary enable Claude Code's sandbox with `sandbox.filesystem.denyRead` — `safe-ai-skill doctor` checks your settings and prints the globs to add.

## Threat model

safe-ai-skill protects against a careless model and prompt-injected instructions. It is not a sandbox. Code that runs unsandboxed as your user can rewrite any user-space state, including the plugin's grants, pins and settings, so the Claude Code sandbox is the hard boundary. A tamper tripwire denies agent tool calls that would loosen the firewall from the inside, but encoded commands, variable indirection and scripts written now and run later can get past it. Run `allow`, `mode <profile>` and `verify approve` yourself in a terminal.

If the engine can't run on a platform (no prebuilt binary, wrong executable format, exit 126/127), the hooks fail open with a one-line notice and SessionStart reports the firewall INACTIVE, but `solana`, `spl-token` and `anchor` commands still get `ask`. `SAFE_AI_SKILL_STRICT=1` blocks instead. `SAFE_AI_SKILL_DISABLE=1` switches the hooks off, and is ignored (the hooks keep running) in strict mode, or when the project's committed `.claude/settings.json` mentions it or can't be read. See [SECURITY.md](SECURITY.md) for details.

## Known limitations in 1.0.1 (fixed in 1.1.0)

- A directory-wide Grep can still return `.env*` contents. Until 1.1.0, rely on Read-level protection and the Claude Code sandbox `denyRead`.
- A Solana command wrapped in another command or prefixed with environment assignments may not be gated. Keep the sandbox on.
- There is no SessionStart notice yet for Claude Code older than 2.1.295.
- Deleting a parent of the plugin data directory (for example `~/.claude/plugins/data`) resets the daily spend ledger, along with grants and pins. The tripwire doesn't cover removing an ancestor. 1.1.0 fixes this with authenticated state.

**Runtime threats** — agentic workflows drive CLI commands and value-moving MCP calls with no gating. Interactive `read -r` prompts silently fail in hook context (no TTY). safe-ai-skill intercepts every such action before execution.

**Supply-chain threats** — skill hubs ship external submodules from third-party sources. Each submodule is its own supply-chain unit and can contain telemetry preambles, `curl | bash` installer scripts, or unpinned MCP packages. Opt-in skill catalogs include high-risk entry classes that can execute privileged code. safe-ai-skill catches all of this at session start, before any skill or MCP is active.

## Usage tiers

### Tier 0 — install and go

Install once. Every session is protected automatically. No configuration required.

### Tier 1 — gate installs before they run

```bash
safe-ai-skill registry list          # list catalog entries with risk classification
safe-ai-skill registry verify        # audit installed entries against registry
safe-ai-skill add skill <name|url>   # catalog entry or any GitHub URL, verified before install
safe-ai-skill add mcp <id|pkg|url>   # any MCP; verified before writing .mcp.json
safe-ai-skill verify                 # on-demand audit of all installed skills and MCPs
safe-ai-skill verify check <dir>     # scan one skill directory and list every finding
safe-ai-skill verify approve <name>  # re-pin a drifted pack after you reviewed it
safe-ai-skill status                 # pins, active profile, live grants, spend, recent decisions
safe-ai-skill mode <profile>         # strict (default) | paranoid | autopilot (needs confirmation)
safe-ai-skill allow --scope transfer --for 30m --max-tx 1 --budget 5 [--to <addr>]
                                     # request a time-boxed grant (needs confirmation)
safe-ai-skill revoke                 # drop every grant at once
safe-ai-skill session                # show active session state
```

`verify approve`, `install` and `add` change what the firewall pins, so the agent can't run them: the tamper tripwire denies them, and bare `verify` / `verify session` too, which only the SessionStart hook runs. Run them in your own terminal; `verify check <dir>` stays open to the agent because it pins nothing. The agent may run `allow` and `mode`: they only create a request it cannot confirm. From a terminal the CLI uses the same state as the hooks: `$CLAUDE_PLUGIN_DATA` if set, otherwise the plugin's dir under `~/.claude/plugins/data/` (or `$CLAUDE_CONFIG_DIR/plugins/data/`, which replaces `~/.claude`), `safe-ai-skill-safe-ai-skill` first, then `safe-ai-skill-stbr`, then the only `safe-ai-skill-*` dir. If none of these resolves it exits 1 and asks you to set `CLAUDE_PLUGIN_DATA`. `status` prints the dir it used.

**Relaxations need your confirmation in the prompt.** `allow` and `mode autopilot` change
nothing on their own: they record a request (`request r3fa91c`) and print no code. Claude Code
then shows **you** a confirmation code in a hook message (right after the command, or at your
next prompt or session start) that is never put in the agent's context. The request takes
effect only when your next prompt is exactly `safe-ai-skill confirm <code>`, on its own
(within 10 minutes, once); Claude Code then shows what you approved. A confirm line inside
pasted text is refused, and three wrong codes cancel every pending request. The agent may run
`allow` itself: it only creates a request it cannot confirm. In headless `claude -p`, where
hook messages aren't shown, nothing can be confirmed. A stricter `mode` and `revoke` apply at
once. Grant scopes are `transfer`, `swap`, `deploy`, `authority` and `destructive`; anything
else is an error.

**Profiles.** `strict` is the default. `paranoid` asks for every Solana CLI command and
disables every automatic allow, grants included (it does not add prompts for MCP tools or file
reads that otherwise have no opinion). `autopilot` raises the per-transaction cap
to 2 SOL and applies only through a confirmed `safe-ai-skill mode autopilot`.
`SAFE_AI_SKILL_PROFILE` can only pick a stricter profile. To turn the hooks off, set
`SAFE_AI_SKILL_DISABLE=1`.

**State is authenticated.** Grants, the mode, the daily spend ledger and session metadata are
signed with a per-install key in the plugin data directory, and each file carries a
generation, so a hand-edited file or an older copy put back is ignored, and a deleted or edited
spend ledger counts as today's budget spent. This is tamper-evident, not tamper-proof: code
running as you outside the Claude Code sandbox can read the key, run the hook commands itself
or restore a snapshot of the whole directory. The sandbox is the hard boundary. At the first
1.1.0 session, unexpired 1.0 grants and an `autopilot` mode become pending requests you can
confirm with the codes shown then; the 1.0 spend ledger becomes today's exhausted budget. Every session start
lists what is currently loosened: a profile env var, a non-default mode, live grants, ignored
repo policy, state that failed authentication, and a Claude Code sandbox that is off.

Each `add` command runs the intrinsic verification pipeline on the actual fetched content before executing the underlying install. `registry list` shows the full catalog with risk classes flagged. High-risk entries (`wallet_signing`, `key_custody`, `installer_script`) require explicit approval.

### Tier 2 — verified hub install

```bash
safe-ai-skill install                        # verify the project's .claude/skills in place (scan, pin, no copy)
safe-ai-skill install --from <dir|tarball>   # verified install from a local skill directory or tarball
safe-ai-skill install --home ~               # install into <dir>/.claude/skills (default: ~)
```

`install` never downloads anything: `--from` takes a local directory or tarball, so fetch a hub yourself (for example `git clone`) and point `--from` at it. It runs the verification pipeline on every skill, neutralizes telemetry preambles, pins each pack, and holds a skill with a High finding, always. A skill with only Medium findings is held unless you pass `--yes`. With no `--from` it verifies the current project's `.claude/skills` in place, and rewrites a `SKILL.md` there to remove a telemetry preamble it finds. It does not auto-widen `~/.claude/settings.json` permissions.

## Registry-free verification model

Trust is based on the artifact itself, not a hash allowlist to maintain:

1. **Static heuristics** — scan SKILL.md, scripts, and package.json for outbound POST in preambles, keypair/`.env` references, base58-encoded secrets, prompt injection, `eval`/download-and-exec, and `curl | bash` patterns. Generic patterns — they do not grow per-package.
2. **Per-submodule pinning** — each `ext/` submodule is walked independently. The first-seen git commit SHA is recorded as the TOFU pin. On subsequent sessions, drift from that SHA is reported in every session (High findings listed at `path:line`) until you run `verify approve <name>`. Nothing is moved, so the working tree stays clean.
3. **Catalog gating** — entries are classified by risk class. High-risk classes require explicit policy approval; safe-ai-skill blocks installation of denied classes without prompting.
4. **Provenance pinning** — GitHub URLs resolve to immutable commit SHAs (moving refs are rejected). npm packages pin to `pkg@x.y.z` plus `dist.shasum`. `@latest` entries are flagged informational.
5. **CVE lookup** — `add` queries osv.dev for an exact, non-local npm source (for example `add mcp`'s resolved `pkg@version`). No API key required. This is the only network step; the session sweep and gates make no network calls.
6. **Local TOFU lockfile** — pin the content hash on first install; any later change is reported as drift until you approve it.

Block on high-severity heuristic match or known CVE. Warn and `ask` on medium. Pass and pin on clean.

## Integration model

Install any skill hub (e.g. `solanabr/solana-ai-kit`) alongside safe-ai-skill as a plugin. No `settings.json` merge is needed — Claude Code merges plugin hooks with project hooks automatically. safe-ai-skill's `deny` decisions survive `enableAllProjectMcpServers: true` and `bypassPermissions`.

safe-ai-skill is standalone — it can be installed independently of any particular skill hub. It adds a security and control layer over whatever skills, MCPs, and agents you already have.

## Security

See [SECURITY.md](SECURITY.md) for the full threat model, guarantees, out-of-scope items, and vulnerability reporting.

## License

MIT
