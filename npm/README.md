# safe-ai-skill

A hook-based security firewall and supply-chain verifier for Claude Code skills,
MCPs and agents. Before a tool call runs, its hooks check the call's text against
a policy: destructive git commands, secret and credential reads, data leaving for
known exfiltration hosts, download-and-run, tampering with its own settings, and,
for Solana work, irreversible or value-moving on-chain actions (irreversible ones
such as `--final`, `program close` and `spl-token close|burn` are denied on
mainnet or any cluster not identified as localnet, devnet or testnet). Credential
stores and keypairs are read-denied at every tier; project `.env` reads follow the
tier (denied at High; `.env.production` is denied from Relaxed). The firewall
takes a tier (`off < relaxed < medium < high`) as an input. A supply-chain
verifier runs at every session start: it grades and pins the project's skill
packs, and blocks a pack that drifted (in place, never moved) until you approve
it.

> **Warning: the firewall is hook-level string analysis, and it has known holes.**
> Every gate reads the text of a tool call; none watches what the call does once
> it runs, so a determined or prompt-injected model can get past it (encoded or
> runtime-built commands, scripts written in one call and run in another, code
> running as you outside the sandbox, values already in context). A Claude Code
> plugin can't ship `sandbox` or `permissions` settings, so it can't close these
> holes itself. The [solana-ai-kit](https://github.com/solanabr/ai-kit)
> implementation (OS sandbox plus permission rules) closes most of them: run
> both, or turn on Claude Code's own sandbox with the `denyRead` and
> `deniedDomains` entries in
> [SECURITY.md](https://github.com/solanabr/safe-ai-skill/blob/main/SECURITY.md#recommended-setup).
> The full list of holes is in
> [SECURITY.md](https://github.com/solanabr/safe-ai-skill/blob/main/SECURITY.md#known-holes).
> The scope split between the two projects is proposed in
> [ai-kit#264](https://github.com/solanabr/ai-kit/issues/264) and
> [ai-kit#265](https://github.com/solanabr/ai-kit/issues/265).

This npm package installs the `safe-ai-skill` CLI binary (the same binary that backs
the Claude Code plugin). The Claude Code plugin is installed separately.

## Install

```bash
npm install -g @stbr/safe-ai-skill
# or
npx @stbr/safe-ai-skill <command>
```

The package is scoped (`@stbr/safe-ai-skill`); the installed CLI command is `safe-ai-skill`.

## Quick start

```bash
# Check a source before you install it: installs nothing, and prints an install
# command pinned to the commit or version it checked where it can (see the
# project README for what is and isn't checked)
safe-ai-skill add skill <owner/repo|url|dir>
safe-ai-skill add mcp <pkg|url|dir>
safe-ai-skill add repo <owner/repo|url|dir>

# List the commands, or print one command's usage
safe-ai-skill --help
safe-ai-skill help add

# Run the session sweep now: grade and pin the installed packs
safe-ai-skill verify

# Request approval of a blocked (drifted) pack after you reviewed it; confirm with
# the code safe-ai-skill shows you in Claude Code
safe-ai-skill verify approve <name>

# Show status: tier, live grants, spend, recent decisions
safe-ai-skill status

# Show or change the firewall tier (lowering needs your confirmation in Claude Code)
safe-ai-skill tier
safe-ai-skill tier high [--project]

# Verified install from a local skill directory or tarball (no network)
safe-ai-skill install --from <dir|tarball>
```

## Claude Code plugin

The Claude Code plugin provides the runtime firewall (hooks into every Claude
Code session) and requires Claude Code 2.1.295 or newer. Install it separately:

```bash
claude plugin marketplace add solanabr/safe-ai-skill
claude plugin install safe-ai-skill@safe-ai-skill
```

Once installed, the hooks run in every session — no per-skill configuration
required (see the warning above for what they cannot catch). solana-ai-kit users already have the plugin through the
kit and should not add it again. If you installed `safe-ai-skill@stbr`, follow
the migration steps in [docs/upgrading.md](https://github.com/solanabr/safe-ai-skill/blob/main/docs/upgrading.md#moving-from-safe-ai-skillstbr)
before removing anything: the solana-ai-kit marketplace is also named `stbr`.

## How this package works

`postinstall` downloads the prebuilt `safe-ai-skill-<platform>` binary for your OS and
architecture from the GitHub Release matching this package version, verifies
its SHA-256 against the published `SHA256SUMS` file, and marks it executable.
The install fails loudly if the download or checksum verification fails — this
is a security tool; a broken silent install is unacceptable.

Supported platforms: macOS arm64, macOS x64, Linux x64, Linux arm64, Windows x64
(also used on ARM). The Linux binaries are static (musl), so they run on any
distribution, Alpine included.

For unsupported platforms, install the same release from crates.io, where every
release from 1.3.1 on is published (the install error prints this command with
the package's version filled in):
```bash
cargo install safe-ai-skill --version <version> --locked
```

Or build from the matching release tag:
```bash
git clone --branch v1.3.1 https://github.com/solanabr/safe-ai-skill && cd safe-ai-skill
cargo install --locked --path crates/engine
```

## Further reading

- [GitHub repository](https://github.com/solanabr/safe-ai-skill)
- [README](https://github.com/solanabr/safe-ai-skill/blob/main/README.md)
- [Security policy](https://github.com/solanabr/safe-ai-skill/blob/main/SECURITY.md)
- [Firewall tiers](https://github.com/solanabr/safe-ai-skill/blob/main/docs/tiers.md)
