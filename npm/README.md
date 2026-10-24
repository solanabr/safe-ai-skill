# safe-ai-skill

Security firewall and supply-chain verifier for Solana AI development. Gates
every Solana CLI command, SPL Token operation, Anchor invocation, and
value-moving MCP call — requiring explicit approval for mainnet deploys,
authority changes, and over-cap transfers. Runs a supply-chain verifier at
every session start that scans skills and MCPs, flags telemetry preambles and
plaintext JWTs, pins content hashes, and reports anything that drifted. It
reports and never moves a skill.

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
# Gate installs before they run
safe-ai-skill add skill <name|url>    # any GitHub skill URL or catalog entry
safe-ai-skill add mcp <id|pkg|url>    # any MCP; pins exact version before writing .mcp.json
safe-ai-skill add repo <url>          # any clonable repo; pins to commit SHA

# Audit what is already installed
safe-ai-skill verify

# Re-pin a drifted pack after you reviewed it (reported every session until then)
safe-ai-skill verify approve <name>

# Show status: active profile, live grants, spend, recent decisions
safe-ai-skill status

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

Once installed, the firewall is live in every session — no per-skill
configuration required. solana-ai-kit users already have the plugin through the
kit and should not add it again. If you installed `safe-ai-skill@stbr`, follow
the migration steps in the [README](https://github.com/solanabr/safe-ai-skill/blob/main/README.md#install)
before removing anything: the solana-ai-kit marketplace is also named `stbr`.

## How this package works

`postinstall` downloads the prebuilt `safe-ai-skill-<platform>` binary for your OS and
architecture from the GitHub Release matching this package version, verifies
its SHA-256 against the published `SHA256SUMS` file, and marks it executable.
The install fails loudly if the download or checksum verification fails — this
is a security tool; a broken silent install is unacceptable.

Supported platforms: macOS arm64, macOS x64, Linux x64, Linux arm64. The Linux
binaries are static (musl), so they run on any distribution, Alpine included.

For unsupported platforms or offline installs:
```bash
cargo install safe-ai-skill
```

## Further reading

- [GitHub repository](https://github.com/solanabr/safe-ai-skill)
- [README](https://github.com/solanabr/safe-ai-skill/blob/main/README.md)
- [Security policy](https://github.com/solanabr/safe-ai-skill/blob/main/SECURITY.md)
