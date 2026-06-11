# safe-solana-ai

Security firewall and supply-chain verifier for Solana AI development. Gates
every Solana CLI command, SPL Token operation, Anchor invocation, and
value-moving MCP call — requiring explicit approval for mainnet deploys,
authority changes, and over-cap transfers. Runs a supply-chain verifier at
every session start that scans skills and MCPs, flags telemetry preambles and
plaintext JWTs, pins content hashes, and quarantines anything that drifted.

This npm package installs the `ssai` CLI binary (the same binary that backs
the Claude Code plugin). The Claude Code plugin is installed separately.

## Install

```bash
npm install -g safe-solana-ai
# or
npx safe-solana-ai <command>
```

Both `safe-solana-ai` and `ssai` are registered as bin aliases.

## Quick start

```bash
# Gate installs before they run
ssai add skill <name|url>    # any GitHub skill URL or solana-new catalog entry
ssai add mcp <id|pkg|url>    # any MCP; pins exact version before writing .mcp.json
ssai add repo <url>          # any clonable repo; pins to commit SHA

# Audit what is already installed
ssai verify

# Show status: pins, quarantine list, active profile, live grants, recent decisions
ssai status

# Secure drop-in for: curl solana.new/setup.sh | bash
ssai bootstrap
```

## Claude Code plugin

The Claude Code plugin provides the runtime firewall (hooks into every Claude
Code session). Install it separately:

```bash
claude plugin marketplace add solanabr/safe-solana-ai
claude plugin install safe-solana-ai@safe-solana-ai
```

Once installed, the firewall is live in every session — no per-skill
configuration required.

## How this package works

`postinstall` downloads the prebuilt `ssai-<platform>` binary for your OS and
architecture from the GitHub Release matching this package version, verifies
its SHA-256 against the published `SHA256SUMS` file, and marks it executable.
The install fails loudly if the download or checksum verification fails — this
is a security tool; a broken silent install is unacceptable.

Supported platforms: macOS arm64, macOS x64, Linux x64, Linux arm64.

For unsupported platforms or offline installs:
```bash
cargo install safe-solana-ai
```

## Further reading

- [GitHub repository](https://github.com/solanabr/safe-solana-ai)
- [Architecture](https://github.com/solanabr/safe-solana-ai/blob/main/docs/architecture.md)
- [Usage reference](https://github.com/solanabr/safe-solana-ai/blob/main/docs/usage.md)
- [Security policy](https://github.com/solanabr/safe-solana-ai/blob/main/SECURITY.md)
