# Security

## What is protected

**Transactions and deploys.** Every `solana`, `spl-token`, and `anchor` CLI command that moves value, changes program authority, deploys or upgrades a program, or closes an account is intercepted before execution by the `gate-bash` PreToolUse hook. Value-moving, authority-changing, and staking MCP tool calls (names matching `transfer|sign|swap|send|withdraw|burn|pay|upgrade|stake|delegate|mint|bridge|lend|borrow`) are intercepted by `gate-mcp`. Hard guards require explicit user approval; they are never bypassed.

**Secret files.** Keypair files, `.env` files, `.pem` files, and `~/.config/solana/**` are read-denied by `gate-read` for Read/Grep/Glob tool calls and by `gate-bash-secrets` for Bash commands. PostToolUse `redact` strips any secret material that reaches tool output — 64-byte base58 private keys, JSON keypair arrays, BIP39 seed phrases, and API key patterns.

**Prompt content.** `prompt-guard` (UserPromptSubmit hook) blocks prompts that contain raw private keys or seed phrases before they reach the model.

**Supply chain.** Every session start runs `verify session` over the installed skills directories, each `ext/` git submodule independently, MCP server entries in `.claude/settings.json`, and all registry-installed catalog entries. The `@latest` MCP posture is flagged as INFORMATIONAL; safe-ai-skill does not treat it as an error when a hub keeps its MCPs `@latest` by design. Content that drifts from its pinned hash or git SHA is quarantined before skills are loaded.

**Install-script execution.** Runtime `curl|bash`, `wget|bash`, and `curl|sh` patterns are intercepted by `gate-bash-secrets` (unconditional, microsecond matching) before the pipe executes. The default policy is `exec_install_scripts: ask` — the user sees the URL and script preview before approval.

## Threat model

### `ext/` submodule supply chain

safe-ai-skill is general-purpose: it verifies whatever `ext/` submodules, skills, and MCPs a given setup ships — any hub, any count, or none. The walkthrough below uses `solanabr/solana-ai-kit` as a concrete worked example because it ships a large, heterogeneous set of submodules; the same verification applies unchanged to any other configuration.

solana-ai-kit, for example, ships 18 third-party `ext/` git submodules: third-party security tools, DeFi protocol SDKs, NFT tooling, and infrastructure integrations (including `ext/ghostsecurity`, `ext/trailofbits`, `ext/jupiter`, `ext/metaplex`, `ext/helius`, `ext/sendai`, `ext/vercel`, and others). Each is an independent supply-chain unit with a different origin, maintainer, and risk profile.

**What can go wrong per submodule:**
- Telemetry preambles in SKILL.md files that POST skill-invocation metadata to third-party endpoints.
- `curl|bash` installer patterns embedded in skill content (e.g., `ext/ghostsecurity`).
- Prompt injection in SKILL.md content (hidden HTML comments, Unicode bidirectional control characters, lookalike substitutions).
- Dependency changes in a submodule's npm/Cargo manifests that introduce CVEs.
- Compromised upstream repository — a submodule commit SHA can change on any `git submodule update`.

**safe-ai-skill's response:** each submodule is walked by `ext_verify.rs` at `SessionStart`. The git SHA is pinned on first seen (TOFU). On any subsequent session where the SHA has changed — whether from an explicit `resync.sh` update or a stealth mutation — the submodule is quarantined and the diff is surfaced in `additionalContext`. The user must explicitly re-pin with `safe-ai-skill verify approve <name>` after reviewing the diff.

**No special-casing:** some submodules carry known supply-chain risks — attacker-mutable telemetry endpoints, unsigned tarball installers, and global Bash/Read permission grant patterns. safe-ai-skill treats every `ext/` submodule identically: telemetry preambles and installer patterns are flagged and neutralized generically by `heuristics.rs`; no submodule is special-cased.

### `@latest` MCP posture

solana-ai-kit configures all 7 MCP servers with `@latest` versions in `.mcp.json`. safe-ai-skill flags these as INFORMATIONAL (LOW) — not as errors — because this is a deliberate posture choice by the kit maintainers, not an oversight. The risk is concrete: an `@latest` entry silently pulls whatever is newest on each install, creating a rug-pull vector where a compromised new release is auto-applied.

safe-ai-skill's response: flag at session start and at `install` time. Offer `safe-ai-skill pin-mcps` as an opt-in rewrite to exact versions — never silent auto-rewrite. The user decides when to pin.

**What safe-ai-skill does NOT do:** safe-ai-skill does not gate MCP calls solely on the basis of `@latest` pinning. The runtime `gate-mcp` hook gates by tool name and payload. An `@latest` entry that calls a safe read-only tool is allowed; an entry that calls a sensitive tool is gated regardless of whether it is pinned.

### High-risk catalog classes

solana-ai-kit's `skill-registry.json` includes entries classified by safe-ai-skill as high risk:

| Class | Representative entries | Risk |
|-------|----------------------|------|
| `wallet_signing` | `phantom-mcp` | Requests Phantom wallet to sign arbitrary transactions on behalf of the agent. If the agent is compromised or manipulated, this class of tool can drain the connected wallet. |
| `key_custody` | `x402-proxy-mcp` | Holds BIP-39 mnemonic or derived keys for x402 payment channel operations. Key material is exposed to the MCP process boundary. |
| `installer_script` | `ghostsecurity`, others with `curl\|bash` setup | The `setup_command` or installer invokes a network fetch piped to a shell. The fetched content is not verifiable at catalog-entry-audit time; it can change between audit and execution. |

Entries in `wallet_signing` and `key_custody` are denied by default policy (configurable in `.safe-ai-skill/policy.yaml`). Entries in `installer_script` trigger the `exec_install_scripts` policy gate. At runtime, tools from approved `wallet_signing` entries are gated by `gate-mcp` with a risk-class header in the approval prompt — the user is reminded of the class on every invocation.

### TOCTOU and simulation spoofing

A transaction can pass simulation while the on-chain execution differs (e.g., due to account state changes between simulation and confirmation, or a maliciously constructed instruction sequence that looks benign in simulation). safe-ai-skill gates the *execution command* — the `anchor deploy`, `solana transfer`, or MCP call — not the simulation. This does not fully mitigate sophisticated TOCTOU attacks but ensures that at minimum the execution requires user awareness and approval for high-risk actions, regardless of simulation results.

### Over-permissioned agents

solana-ai-kit sets `enableAllProjectMcpServers: true`, which pre-approves all project MCP tools. safe-ai-skill's `deny` decisions from PreToolUse hooks hold even when `enableAllProjectMcpServers: true` is set — this is a verified property of the Claude Code hook execution order: PreToolUse runs before the permission check, and `permissionDecision: "deny"` is not overridable by project settings. The hard guards (`mainnet_deploy`, `set_authority`, `account_close`, `secret_read`) are enforced unconditionally.

### Secret exfiltration

Exfiltration vectors in a typical solana-ai-kit session:

- **Keypair file reads** — `Read` tool calls on `~/.config/solana/id.json` or project keypair files; Bash `cat` commands.
- **Telemetry preambles** — SKILL.md files in `ext/` submodules can contain bash blocks that POST to third-party endpoints on skill invocation. `gate-bash-secrets` catches all outbound POST patterns with known telemetry signatures (Convex `/api/mutation`, and config-driven additional endpoint patterns).
- **Environment variable leakage** — `printenv`, `env`, commands that expand `$ANCHOR_WALLET` or `$SOLANA_KEYPAIR` into arguments.
- **`curl|bash` runtime execution** — an agent instructed to run a setup script could fetch and execute arbitrary code. `gate-bash-secrets` intercepts these before the pipe executes.

### PII in prompts

Users occasionally paste private key material, seed phrases, or other sensitive data into prompts when troubleshooting. `prompt-guard` matches against these patterns at UserPromptSubmit and blocks the prompt with a reason message before it reaches the model.

### MCP CVEs

MCP package vulnerabilities are a concrete, documented risk. safe-ai-skill addresses this in two ways: `safe-ai-skill add mcp` and `install` query osv.dev for every resolved `pkg@version` before installation; and `safe-ai-skill verify` re-checks pinned versions on demand. The osv.dev API requires no authentication.

### Tool poisoning and prompt injection

Malicious skills can embed instructions targeting the language model in SKILL.md content: hidden HTML comments, "ignore previous instructions" text, Unicode bidirectional control characters, and lookalike unicode substitutions. `heuristics.rs` scans for these patterns before any skill content is pinned to the lockfile. Skills with high-severity injection findings are refused; medium findings produce a diff for review.

## Design guarantees

**Hard guards are unconditional.** The four hard guards — `mainnet_deploy`, `set_authority`, `account_close`, `secret_read` — are enforced by the engine binary regardless of the active profile, any time-boxed grant, or any project policy override. There is no flag or configuration that relaxes them in v1.

**Never fails open.** If the `safe-ai-skill` binary cannot be obtained (no matching prebuilt, no `cargo`), the `bin/safe-ai-skill` shim exits with code 2, which Claude Code interprets as a block on the gated action.

**Fail-closed policy.** If `policy.yaml` cannot be parsed, `policy.rs` falls back to treating all gated actions as `ask`. The session is not left without gates because of a config file error.

**External API timeouts do not allow.** Rugcheck and osv.dev are external network calls. On timeout or API unavailability, the decision is `ask` (not `allow`, not `deny`). The user is informed and must approve.

**`deny` survives `bypassPermissions`.** Verified against Claude Code official docs (2026-06). Sessions running with `bypassPermissions` cannot override hook `deny` decisions.

**`deny` survives `enableAllProjectMcpServers`.** Verified against Claude Code hook execution order. MCP pre-approval in project settings does not bypass `gate-mcp` PreToolUse decisions.

## Out of scope for v1

### Lighthouse assertions

Lighthouse is a Solana program (`L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95`, deployed mainnet and devnet) that allows embedding verifiable assertions as instructions in a transaction. The assertion is checked on-chain at execution time, not in simulation.

Retrofitting Lighthouse assertions onto a transaction already built by `solana-cli` or `anchor deploy` requires re-signing the transaction. safe-ai-skill gates commands at the CLI/MCP layer, after the transaction has been constructed and before it is submitted. Inserting Lighthouse assertions at this stage without owning the tx-construction path is not possible.

This is deferred to a future "guarded signer" component: an MCP tool that exposes `signAndSend`, holds session-key access, and can simulate, append Lighthouse assertions, and sign in a single controlled step before submission.

### Turnkey

Turnkey is a SaaS wallet-as-a-service product evaluated and skipped for v1. The free tier is 25 total signatures (not per day); beyond that, $0.10 per signature. Phase 3 session keypairs achieve the same spend-cap-by-construction guarantee with zero external dependencies.

### `safe-ai-skill doctor` (dual-install detection)

When safe-ai-skill is installed as both a Claude Code plugin and as part of a full solana-ai-kit config-repo install, both `SessionStart` hooks fire. `safe-ai-skill doctor` — detecting coexistence, reporting which gates are active vs. superseded, and diagnosing `settings.json` overlap — is a P2 item deferred to a future release.

## Vulnerability reporting

To report a security vulnerability in safe-ai-skill, send email to **security@superteam.com.br** with subject line `[safe-ai-skill] vulnerability report`.

Include in your report:

- A description of the vulnerability and the affected component
- Reproduction steps (include relevant hook payloads, commands, or policy configurations)
- An assessment of the impact and any attack conditions

We will acknowledge receipt within 48 hours. Please allow reasonable time for assessment before public disclosure.
