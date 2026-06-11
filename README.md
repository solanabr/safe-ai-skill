# safe-solana-ai

safe-solana-ai is a Claude Code plugin that is the secure drop-in for the solana-new AI dev flow. It installs a runtime action firewall that gates every Solana CLI command, SPL Token operation, Anchor invocation, and value-moving MCP call — requiring explicit approval for mainnet deploys, authority changes, and over-cap transfers — and runs a supply-chain verifier at every session start that scans the skills and MCPs solana-new installs, flags telemetry preambles and plaintext JWTs, pins content hashes, and quarantines anything that drifted since the last session. It works on any skill or MCP source, not only the solana-new catalog, and requires no central registry to maintain.

## Threat model

**Runtime action threats** — solana-new skills trigger `solana`, `spl-token`, and `anchor` CLI commands and call value-moving MCP tools (`transferSol`, `transferToken`, swap calls) with no gating. Keypair files and `.env` are wide open to Read and Bash. The firewall intercepts every such action before execution.

**Supply-chain threats** — solana-new's installer downloads an unsigned tarball, widens `~/.claude/settings.json` permissions to auto-allow `Bash`/`Read`/`Glob`/`Grep`, and registers MCPs pinned `@latest` with no hash verification. The telemetry preamble baked into every SKILL.md fire-and-forget POSTs to a Convex endpoint. `~/.superstack/config.json` holds a plaintext Colosseum Copilot JWT. The supply-chain verifier catches all of this.

## Quick start

### Tier 0 — install once

```bash
claude plugin marketplace add solanabr/safe-solana-ai
claude plugin install safe-solana-ai@safe-solana-ai
```

From that point, in every Claude Code session the runtime firewall is live and the supply-chain verifier runs at startup. No per-skill configuration required. You keep using solana-new exactly as before; safe-solana-ai catches whatever it installs.

**Pre-enabled:** cloning or opening this repo gives immediate protection — the plugin is already enabled in `.claude/settings.json`. No install command needed for contributors.

**Dev install:** `claude plugin marketplace add .` (from repo root), then `claude plugin install safe-solana-ai@safe-solana-ai`.

## Usage tiers

### Tier 0 — install and go

Install once. Every session is protected automatically:

- Runtime firewall gates all `solana`/`spl-token`/`anchor` commands, value-moving MCP calls, and secret file reads.
- `verify session` runs at `SessionStart`, scans `~/.claude/skills/**` and `.claude/settings.json` MCPs, flags the Convex telemetry preamble and plaintext JWT, pins content hashes on first use, quarantines any content that drifted since the last session.
- Hard guards (`mainnet_deploy`, `set_authority`, `account_close`, `secret_read`) are never bypassed regardless of profile or flags.

### Tier 1 — gate installs before they run

```bash
safe-solana-ai add skill <name|url>   # solana-new catalog entry or any GitHub URL
safe-solana-ai add mcp <id|pkg|url>   # any MCP; pins exact version before writing .mcp.json
safe-solana-ai add repo <url>         # any clonable repo; pins to commit SHA
safe-solana-ai verify                 # on-demand audit of everything already installed
safe-solana-ai status                 # pins, quarantine list, active profile, live grants, recent decisions
```

Each `add` runs the intrinsic verification pipeline on the actual fetched content before executing the underlying install command. Works for solana-new catalog entries and arbitrary third-party sources alike.

### Tier 2 — verified install of solana-new

```bash
safe-solana-ai bootstrap
```

The secure drop-in for `curl solana.new/setup.sh | bash`. Downloads the solana-new tarball, runs the verification pipeline on every SKILL.md and the three catalog JSONs, neutralizes the telemetry preamble, pins every MCP to an exact version, shows a diff of flagged content, and installs only on approval. Does not auto-widen `~/.claude/settings.json` permissions the way the original installer does.

## Registry-free verification model

The trust basis is the artifact itself, never a hash allowlist to maintain:

1. **Static heuristics** — scan SKILL.md/scripts/package.json for danger: outbound POST in preambles (the solana-new Convex telemetry pattern), keypair/`.env` references, base58-encoded secrets, prompt injection (hidden comments, unicode direction overrides), `eval`/download-and-exec, `postinstall` scripts. Generic patterns — they do not grow per-package.
2. **Provenance pinning** — resolve every source to an immutable ref: GitHub → commit SHA (moving refs like `main` are rejected); npm → exact version + `dist.shasum`/integrity hash; flag packages that are very new, very low-download, or typosquat-similar to popular names.
3. **CVE lookup** — query the free osv.dev API (Google-maintained) for every resolved `pkg@version`. No maintenance on our side.
4. **Local TOFU lockfile** — pin the content hash on first install; any later change surfaces a diff requiring explicit approval, not a silent update. Self-maintaining, per-user.

Block on high-severity heuristic match or known CVE; warn and `ask` on medium; pass and pin on clean.

## Native solana-new integration

Three layers of integration with increasing coupling to solana-new internals:

| Layer | Seam | What it does | Coupling to solana-new |
|-------|------|--------------|------------------------|
| **L1 Runtime** | Claude Code hooks | PreToolUse/PostToolUse fire on every tool call a solana-new skill triggers — transfers, deploys, telemetry `curl`, keypair reads — and gate them. | Zero. Works regardless of how skills were installed. |
| **L2 Supply-chain audit** | SessionStart + lockfile | Scans `~/.claude/skills/**` (where solana-new drops skills), project `.claude/settings.json` `mcpServers`, and `~/.superstack/config.json`; runs heuristics, flags the Convex preamble and plaintext JWT, pins on first use, quarantines drift. | Path-level. Knows where solana-new installs; does not fork it. |
| **L3 Verified install** | Wrap installer commands | `safe-solana-ai add` and `bootstrap` route solana-new's `npx skills add`, `setup_command`, `clone_command`, and the tarball through the verification pipeline before executing. | Command-level. No central mirror required. |

## Requirements

- **Claude Code** — hook semantics verified against official 2026-06 docs (v2.1.139+). Earlier versions lack the `if` field on hook entries and the `ask` permission decision; the plugin will not function correctly on older versions.
- **`cargo`** — required only as a one-time fallback if no prebuilt `ssai` binary matches your platform. Solana developers have this. The plugin never fails open: if no binary is obtainable, the shim blocks the gated action.

## Further reading

- [Architecture](docs/architecture.md) — engine, hook wiring, gate pipeline, state layout
- [Usage](docs/usage.md) — command reference, policy override, gate behavior, profiles and grants
- [Security](SECURITY.md) — threat model, guarantees, out-of-scope items, vulnerability reporting
