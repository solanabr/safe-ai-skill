# safe-ai-skill

safe-ai-skill is a Claude Code security plugin that sits as the firewall over `solanabr/solana-ai-kit` — the Solana AI skill and MCP hub. It installs a runtime action firewall that gates every Solana CLI command, SPL token operation, Anchor invocation, and value-moving MCP call before execution, and runs a supply-chain verifier at every session start that walks each of the kit's 18 `ext/` git submodules independently, flags telemetry preambles and plaintext secrets, pins content to git SHAs, gates opt-in catalog entries by risk class, and quarantines anything that drifted since the last session. It requires no central registry and works with any skill or MCP source.

## Threat model

**Runtime action threats** — solana-ai-kit agents drive `solana`, `spl-token`, and `anchor` CLI commands and call value-moving MCP tools (`heliusWrite.sendSol`, `heliusWrite.sendToken`, swap calls, staking mutations) with no gating. The kit's mainnet-deploy hook uses a `read -r` interactive prompt that silently fails in hook context (no TTY). The safe-ai-skill firewall intercepts every such action before execution and replaces the broken gate with a functioning `ask` decision.

**Supply-chain threats** — solana-ai-kit ships 18 `ext/` git submodules from third-party sources. Each submodule is its own supply-chain unit: it can contain telemetry preambles, `curl | bash` installer scripts, or unpinned MCP packages. The kit's 7 MCP servers are all `@latest` — a moving target that silently pulls whatever is newest on each install. The kit's opt-in `skill-registry.json` catalog includes high-risk entry classes (`phantom-mcp` wallet signing, `x402-proxy-mcp` BIP-39 key custody, `ghostsecurity` installer scripts) that can execute privileged code. The supply-chain verifier catches all of this at session start, before any skill or MCP is active.

## Quick start

### Tier 0 — install once

```bash
claude plugin marketplace add solanabr/safe-ai-skill
claude plugin install safe-ai-skill@safe-ai-skill
```

From that point, every Claude Code session over solana-ai-kit is protected automatically. No per-skill configuration required.

**Pre-enabled for contributors:** cloning this repo gives immediate protection — the plugin is already enabled in `.claude/settings.json`.

**Dev install:** `claude plugin marketplace add .` (from repo root), then `claude plugin install safe-ai-skill@safe-ai-skill`.

## Integration model

Install `solanabr/solana-ai-kit` (the config hub: agents, commands, rules, skills, catalog) and enable safe-ai-skill as a plugin (the hooks-only security layer). No `settings.json` merge is needed — Claude Code merges plugin hooks with project hooks automatically, and safe-ai-skill's `deny` decisions survive even `enableAllProjectMcpServers: true` and `bypassPermissions`. The kit's broken `read -r` mainnet gate is superseded by safe-ai-skill's `ask` gate without any modification to the kit's settings.

safe-ai-skill is standalone — anyone can install it independently of solana-ai-kit. Bundling safe-ai-skill into the `stbr` marketplace is a future release.

## Usage tiers

### Tier 0 — install and go

Install once. Every session is protected automatically:

- Runtime firewall gates all `solana`/`spl-token`/`anchor` commands, value-moving and authority-changing MCP calls (`send*`/`stake*`/`delegate*`/`mint*`/`bridge*`/`lend*`/`borrow*`), and secret file reads.
- `verify session` runs at `SessionStart`, walks each `ext/` submodule independently, checks git SHA pins, flags telemetry preambles and `curl | bash` installer patterns, quarantines any submodule that drifted since last session.
- Hard guards (`mainnet_deploy`, `set_authority`, `account_close`, `secret_read`) are never bypassed regardless of profile or flags.

### Tier 1 — gate installs before they run

```bash
safe-ai-skill registry list          # list catalog entries with risk classification
safe-ai-skill registry verify        # audit installed entries against registry
safe-ai-skill add skill <name|url>   # catalog entry or any GitHub URL, verified before install
safe-ai-skill add mcp <id|pkg|url>   # any MCP; verified before writing .mcp.json
safe-ai-skill verify                 # on-demand audit of all installed skills and MCPs
safe-ai-skill status                 # pins, quarantine list, active profile, live grants, recent decisions
```

Each `add` runs the intrinsic verification pipeline on the actual fetched content before executing the underlying install command. `registry list` shows the full 39-entry opt-in catalog with high-risk classes flagged. High-risk entries (`wallet_signing`, `key_custody`, `installer_script`) require explicit approval; safe-ai-skill blocks installation of denied classes and gates execution of approved ones at runtime.

### Tier 2 — verified hub install

```bash
safe-ai-skill install                        # hub-agnostic verified install of solana-ai-kit
safe-ai-skill install --from <url>           # install from a specific source URL or GitHub ref
safe-ai-skill install --home ~/.claude       # override install destination
```

The `install` subcommand is the secure drop-in for `curl https://aikit.superteam.codes | bash`. It downloads solana-ai-kit, runs the verification pipeline on every SKILL.md and catalog entry, walks each `ext/` submodule individually, pins each to its current git SHA, flags `@latest` MCP entries as informational, shows a diff of flagged content, and installs only on approval. It does not auto-widen `~/.claude/settings.json` permissions.

## Registry-free verification model

The trust basis is the artifact itself, not a hash allowlist to maintain:

1. **Static heuristics** — scan SKILL.md/scripts/package.json for danger: outbound POST in preambles, keypair/`.env` references, base58-encoded secrets, prompt injection, `eval`/download-and-exec, `curl | bash` patterns. Generic patterns — they do not grow per-package.
2. **Per-`ext`-submodule pinning** — each of the 18 `ext/` submodules is walked independently. The first-seen git commit SHA is recorded as the TOFU pin. On subsequent sessions, drift from that SHA triggers a quarantine and diff for review.
3. **Catalog gating** — entries in `skill-registry.json` are classified by risk class (`wallet_signing`, `key_custody`, `installer_script`, `standard`). High-risk classes require explicit policy approval; safe-ai-skill blocks installation of denied classes without prompting.
4. **Provenance pinning** — GitHub URLs are resolved to immutable commit SHAs (moving refs are rejected). npm packages are pinned to `pkg@x.y.z` + `dist.shasum`. `@latest` MCP entries are flagged informational — safe-ai-skill does not silently rewrite them.
5. **CVE lookup** — query osv.dev (Google-maintained, free, no key required) for every resolved `pkg@version`.
6. **Local TOFU lockfile** — pin the content hash on first install; any later change surfaces a diff requiring explicit approval.

Block on high-severity heuristic match or known CVE; warn and `ask` on medium; pass and pin on clean.

## Requirements

- **Claude Code** — hook semantics verified against official 2026-06 docs (v2.1.139+). Earlier versions lack the `if` field on hook entries and the `ask` permission decision; the plugin will not function correctly on older versions.
- **`cargo`** — required only as a one-time fallback if no prebuilt `safe-ai-skill` binary matches your platform. Solana developers have this. The plugin never fails open: if no binary is obtainable, the shim blocks the gated action.

## Version

**v1.0.0** — Targets solana-ai-kit v2.0.0. Engine, firewall, and supply-chain verifier are complete. All five P0 compatibility items are built: `install` subcommand, registry catalog gating, per-`ext`-submodule verification, expanded MCP verb coverage, and policy schema sync.

## Further reading

- [Architecture](docs/architecture.md) — engine, hook wiring, gate pipeline, supply-chain verifier, state layout
- [Usage](docs/usage.md) — command reference, policy override, gate behavior, profiles and grants
- [Security](SECURITY.md) — threat model, guarantees, out-of-scope items, vulnerability reporting
- [solana-new security audit](docs/solana-new-security.md) — 14 findings in the `ext/solana-new` submodule (reference; solana-new is no longer the install target)
