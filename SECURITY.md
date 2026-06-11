# Security

## What is protected

**Transactions and deploys.** Every `solana`, `spl-token`, and `anchor` CLI command that moves value, changes program authority, deploys or upgrades a program, or closes an account is intercepted before execution by the `gate-bash` PreToolUse hook. Value-moving and authority-changing MCP tool calls (`transferSol`, `transferToken`, swap calls, and anything matching the sensitive name pattern) are intercepted by `gate-mcp`. Hard guards require explicit user approval; they are never bypassed.

**Secret files.** Keypair files, `.env` files, `.pem` files, `~/.config/solana/**`, and `~/.superstack/config.json` (which holds the plaintext Colosseum Copilot JWT in a standard solana-new install) are read-denied by `gate-read` for Read/Grep/Glob tool calls and by `gate-bash-secrets` for Bash commands (`cat`, `less`, redirection, base64 encode, curl upload). PostToolUse `redact` strips any secret material that reaches tool output — 64-byte base58 private keys, JSON keypair arrays, BIP39 seed phrases, and API key patterns — replacing matches in `updatedToolOutput`.

**Prompt content.** `prompt-guard` (UserPromptSubmit hook) blocks prompts that contain raw private keys or seed phrases before they reach the model. Claude Code does not provide a prompt-rewrite mechanism; blocking with a reason message is the only available response.

**Supply chain.** Every session start runs `verify session` over the skills directories and MCP entries. The telemetry preamble baked into solana-new SKILL.md files — a fire-and-forget `curl -s -X POST` to a Convex endpoint read from `~/.superstack/config.json` — is flagged at this stage and caught at runtime by `gate-bash-secrets`. Unpinned `@latest` MCP entries are flagged. Content that drifts from its pinned hash is quarantined before skills are loaded.

## Threat model

### TOCTOU and simulation spoofing

A transaction can pass simulation while the on-chain execution differs (e.g., due to account state changes between simulation and confirmation, or a maliciously constructed instruction sequence that looks benign in simulation). safe-solana-ai gates the *execution command* — the `anchor deploy`, `solana transfer`, or MCP call — not the simulation. This does not fully mitigate sophisticated TOCTOU attacks but ensures that at minimum the execution requires user awareness and approval for high-risk actions, regardless of simulation results.

### Over-permissioned agents

solana-new's installer widens `~/.claude/settings.json` to auto-allow `Bash`, `Read`, `Glob`, and `Grep` for all Claude Code sessions. This means any skill or agent operating in that environment can read keypair files and execute arbitrary shell commands without prompting. safe-solana-ai's `deny` decisions hold even when a session is running with `bypassPermissions` (yolo mode). This is a verified property of the Claude Code hook system: `permissionDecision: "deny"` from a PreToolUse hook is not overridable by session flags. The hard guards (`mainnet_deploy`, `set_authority`, `account_close`, `secret_read`) are implemented as `deny` and enforced unconditionally by the engine, independent of policy configuration, profiles, or grants.

### Secret exfiltration

Multiple exfiltration vectors exist in a standard solana-new install:

- **Keypair file reads** — `Read` tool calls on `~/.config/solana/id.json` or project keypair files; Bash `cat` commands; `solana-keygen` commands that print key material.
- **Environment variable leakage** — `printenv`, `env`, commands that expand `$ANCHOR_WALLET` or `$SOLANA_KEYPAIR` into arguments logged in `audit.jsonl` or tool output.
- **Telemetry preamble** — every SKILL.md in the solana-new tarball contains a bash block that POSTs to a Convex URL read from `~/.superstack/config.json`. This fires on every skill invocation.
- **Convex JWT** — `~/.superstack/config.json` holds a plaintext Colosseum Copilot JWT. Reading this file is denied by both `gate-read` and `gate-bash-secrets`.

`gate-bash-secrets` catches exfiltration patterns including `curl -X POST <convex-url>/api/mutation` specifically, outbound `curl|wget|fetch` with POST bodies referencing local files, and base64-encode-then-POST patterns. It runs unconditionally on every Bash call (no `if` filter) in microseconds.

### PII in prompts

Users occasionally paste private key material, seed phrases, or other sensitive data directly into prompts when troubleshooting. `prompt-guard` matches against these patterns at UserPromptSubmit and blocks the prompt with a reason message before it reaches the model. This protects against accidental leakage into model context and potentially into logs or telemetry.

### MCP CVEs

MCP package vulnerabilities are a concrete, documented risk category. The solana-new catalog registers 41 MCP servers, all pinned `@latest` with no hash verification. safe-solana-ai addresses this in two ways: `safe-solana-ai add mcp` and `bootstrap` query osv.dev (the Google-maintained, free CVE database) for every resolved `pkg@version` before installation; and `safe-solana-ai verify` re-checks pinned versions periodically. The osv.dev API requires no authentication and is maintained externally — no safe-solana-ai maintenance burden.

### Tool poisoning and prompt injection

Malicious skills can embed instructions targeting the language model in SKILL.md content: hidden HTML comments, "ignore previous instructions" text, unicode bidirectional control characters that make visible text differ from actual content, and lookalike unicode substitutions. `heuristics.rs` scans for these patterns before any skill content is pinned to the lockfile. Skills with high-severity injection findings are refused; medium findings produce a diff for review.

### Rug-pull skills

Skills distributed through the solana-new catalog or third-party sources can contain code designed to drain funds: explicit keypair reads followed by transfer commands, base58-encoded private keys embedded in script content, or POST requests to attacker-controlled endpoints. `heuristics.rs` applies pattern matching for all of these. High-severity matches block installation. For swap operations at runtime, `gate-mcp` queries rugcheck.xyz for the input mint's risk score before allowing the swap to proceed; scores above `rugcheck_max_score` (default: 40) result in a `deny`.

## Design guarantees

**Hard guards are unconditional.** The four hard guards — `mainnet_deploy`, `set_authority`, `account_close`, `secret_read` — are enforced by the engine binary regardless of the active profile, any time-boxed grant, or any project policy override. There is no flag or configuration that relaxes them in v1. This is not a default that can be changed; it is a property of the engine.

**Never fails open.** If the `ssai` binary cannot be obtained (no matching prebuilt, no `cargo`), the `bin/ssai` shim exits with code 2, which Claude Code interprets as a block on the gated action. There is no code path that allows a gated action to proceed when the gate process cannot run.

**Fail-closed policy.** If `policy.yaml` cannot be parsed, `policy.rs` falls back to treating all gated actions as `ask`. The session is not left without gates because of a config file error.

**External API timeouts do not allow.** Rugcheck and osv.dev are external network calls. On timeout or API unavailability, the decision is `ask` (not `allow`, not `deny`). This trades some friction for correctness: the user is informed and must approve, rather than being silently allowed through or silently blocked.

**`deny` survives `bypassPermissions`.** Verified against Claude Code official docs (2026-06). Sessions running with `bypassPermissions` cannot override hook `deny` decisions.

## Out of scope for v1

### Lighthouse assertions

Lighthouse is a Solana program (`L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95`, deployed mainnet and devnet, used by Phantom) that allows embedding verifiable assertions as instructions in a transaction. The assertion is checked on-chain at execution time, not in simulation.

Retrofitting Lighthouse assertions onto a transaction already built by `solana-cli` or `anchor deploy` requires re-signing the transaction. safe-solana-ai gates commands at the CLI/MCP layer, after the transaction has been constructed and before it is submitted. Inserting Lighthouse assertions at this stage without owning the tx-construction path is not possible.

This is deferred to a future "guarded signer" component: an MCP tool that exposes `signAndSend`, holds session-key access, and can simulate, append Lighthouse assertions, and sign in a single controlled step before submission. This is a natural Phase 4 extension if agent-driven DeFi via MCP becomes the primary interaction model. It pairs with the Phase 3 session keypairs.

### Turnkey

Turnkey is a SaaS wallet-as-a-service product. It would allow the agent to hold keys without them being present on disk. It was evaluated and skipped for v1 for the following reasons: the free tier is 25 total signatures across all operations (not per day), after which the cost is $0.10 per signature; it requires account creation, API key management, and SDK integration. Phase 3 session keypairs achieve the same spend-cap-by-construction guarantee with zero external dependencies: the agent can spend at most the session keypair's funded balance, the master key stays read-denied throughout, and no third-party service is involved.

## Vulnerability reporting

To report a security vulnerability in safe-solana-ai, send email to **security@superteam.com.br** with subject line `[safe-solana-ai] vulnerability report`.

Include in your report:

- A description of the vulnerability and the affected component
- Reproduction steps (include relevant hook payloads, commands, or policy configurations)
- An assessment of the impact and any attack conditions

We will acknowledge receipt within 48 hours. Please allow reasonable time for assessment before public disclosure.
