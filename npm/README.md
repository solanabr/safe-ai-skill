# safe-ai-skill

Security firewall and supply-chain verifier for Solana AI development in Claude
Code. Its hooks read Solana CLI, SPL Token and Anchor commands and value-moving
MCP calls before they run: mainnet deploys, authority changes and over-cap
transfers ask for your approval, and irreversible actions (`--final`,
`program close` (program or buffer), `spl-token close|burn`, …) are denied on
mainnet or any cluster not identified as localnet or devnet. Credential stores
and keypairs are read-denied at every tier; project `.env` reads follow the tier
(denied at High; `.env.production` is denied from Relaxed). The firewall takes a tier
(`off < relaxed < medium < high`) as an input. A supply-chain verifier runs at
every session start: it scans skills and MCPs, flags telemetry preambles and
plaintext JWTs, pins content hashes, and blocks a pack that drifted (in place,
never moved) until you approve it.

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
# Check a source before you install it: prints the install command, pins and
# installs nothing (see the project README for what is and isn't checked)
safe-ai-skill add skill <name|url|dir>
safe-ai-skill add mcp <id|pkg|url>
safe-ai-skill add repo <url|dir>

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

For unsupported platforms or offline installs, build from the matching release tag (crates.io carries only 1.0.0):
```bash
git clone --branch v1.3.0 https://github.com/solanabr/safe-ai-skill && cd safe-ai-skill
cargo install --locked --path crates/engine
```

## Further reading

- [GitHub repository](https://github.com/solanabr/safe-ai-skill)
- [README](https://github.com/solanabr/safe-ai-skill/blob/main/README.md)
- [Security policy](https://github.com/solanabr/safe-ai-skill/blob/main/SECURITY.md)
- [Firewall tiers](https://github.com/solanabr/safe-ai-skill/blob/main/docs/tiers.md)
