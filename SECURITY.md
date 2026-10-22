# Security

## What is protected

**Transactions and deploys.** Every `solana`, `spl-token`, and `anchor` CLI command that moves value, changes program authority, deploys or upgrades a program, or closes an account is intercepted before execution by the `gate-bash` PreToolUse hook. Value-moving, authority-changing, and staking MCP tool calls (names matching `transfer|sign|swap|send|withdraw|burn|pay|upgrade|stake|delegate|mint|bridge|lend|borrow`) are intercepted by `gate-mcp`. Hard guards are never relaxed: mainnet deploys, authority changes and account closes always ask for user approval (a mainnet `--final` deploy is denied), and secret reads are denied.

**Secret files.** Keypair files, `.env` files, `.pem` files, and `~/.config/solana/**` are read-denied by `gate-read` for Read/Grep/Glob tool calls and by `gate-bash-secrets` for Bash commands. A [varlock](https://varlock.dev) `.env.schema` and `.env.example` stay readable, but a Read (or Grep with a file path) of a schema that holds key material or a literal credential value, is over 64 KiB or is not a regular file is denied; Bash `cat` and Grep with a directory plus glob are not content-checked. A project's `.safe-ai-skill/policy.yaml` can remove either allow. Details are in the README. Output redaction is not active in 1.0.1 (fixed in 1.1.0): the PostToolUse `redact` hook is wired but does not read the tool output field Claude Code sends, does not use the response format Claude Code expects, and does not match MCP tools, so no tool output is scrubbed.

**Prompt content.** `prompt-guard` (UserPromptSubmit hook) blocks prompts that contain raw private keys or seed phrases before they reach the model.

**Supply chain.** Every session start runs `verify session` over the installed skills directories, each `ext/` git submodule independently, and the project's `.mcp.json`. It makes no network calls, and it does not read `.claude/settings.json` or the catalog (`registry verify` audits the catalog on demand). The `@latest` MCP posture is flagged as INFORMATIONAL; safe-ai-skill does not treat it as an error when a hub keeps its MCPs `@latest` by design. Content that drifts from its pinned hash or git SHA is reported at session start, every session until you review it and run `safe-ai-skill verify approve <name>`, which re-pins it in place. Since 1.0.1 nothing is moved or disabled, so a drifted pack still loads: read the report. The sweep covers the project's `.claude/skills`; `~/.claude/skills` only when a project's `.safe-ai-skill/policy.yaml` adds it to `supply_chain.verify_skills_dirs` (the only dir outside the project a project may add), apart from packs installed there with `install --from`.

**Install-script execution.** Runtime `curl|bash`, `wget|bash`, and `curl|sh` patterns are intercepted by `gate-bash-secrets` (unconditional, microsecond matching) before the pipe executes. The default policy is `exec_install_scripts: ask` — the user sees the URL and script preview before approval.

## Threat model

safe-ai-skill protects against a careless model and prompt-injected instructions. It is not a sandbox: code that runs unsandboxed as your user can rewrite any user-space state, including grants, pins, the mode file and the plugin's own files. The Claude Code sandbox is the hard boundary, so run Claude Code with it on if you need one. The self-grant tripwire (below) and the gates make tampering by the agent deny or ask, never allow, but they are not a defence against a process that is already running arbitrary code.

### `ext/` submodule supply chain

safe-ai-skill is general-purpose: it verifies whatever `ext/` submodules, skills, and MCPs a given setup ships — any hub, any count, or none. The walkthrough below uses `solanabr/solana-ai-kit` as a concrete worked example because it ships a large, heterogeneous set of submodules; the same verification applies unchanged to any other configuration.

solana-ai-kit, for example, ships 18 third-party `ext/` git submodules: third-party security tools, DeFi protocol SDKs, NFT tooling, and infrastructure integrations (including `ext/ghostsecurity`, `ext/trailofbits`, `ext/jupiter`, `ext/metaplex`, `ext/helius`, `ext/sendai`, `ext/vercel`, and others). Each is an independent supply-chain unit with a different origin, maintainer, and risk profile.

**What can go wrong per submodule:**
- Telemetry preambles in SKILL.md files that POST skill-invocation metadata to third-party endpoints.
- `curl|bash` installer patterns embedded in skill content (e.g., `ext/ghostsecurity`).
- Prompt injection in SKILL.md content (hidden HTML comments, Unicode bidirectional control characters, lookalike substitutions).
- Dependency changes in a submodule's npm/Cargo manifests that introduce CVEs.
- Compromised upstream repository — a submodule commit SHA can change on any `git submodule update`.

**safe-ai-skill's response:** each submodule is walked individually by the `verify session` sweep at `SessionStart`. The git SHA is pinned on first seen (TOFU). On any subsequent session where the SHA has changed — whether from an explicit `resync.sh` update or a stealth mutation — the drift is reported in the session (High findings at `path:line`), and the submodule stays where it is. The report repeats every session until the user re-pins with `safe-ai-skill verify approve <name>` after reviewing the changes.

**No special-casing:** some submodules carry known supply-chain risks — attacker-mutable telemetry endpoints, unsigned tarball installers, and global Bash/Read permission grant patterns. safe-ai-skill treats every `ext/` submodule identically: telemetry preambles and installer patterns are flagged and neutralized generically by `heuristics.rs`; no submodule is special-cased.

### `@latest` MCP posture

solana-ai-kit configures all 7 MCP servers with `@latest` versions in `.mcp.json`. safe-ai-skill flags these as INFORMATIONAL (LOW) — not as errors — because this is a deliberate posture choice by the kit maintainers, not an oversight. The risk is concrete: an `@latest` entry silently pulls whatever is newest on each install, creating a rug-pull vector where a compromised new release is auto-applied.

safe-ai-skill's response: flag at session start, listing each unpinned server at its `.mcp.json` line. It never rewrites `.mcp.json` silently; `safe-ai-skill add mcp` writes exact versions for the entries it adds, and the user decides when to pin the rest.

**What safe-ai-skill does NOT do:** safe-ai-skill does not gate MCP calls solely on the basis of `@latest` pinning. The runtime `gate-mcp` hook gates by tool name and payload. An `@latest` entry that calls a safe read-only tool is allowed; an entry that calls a sensitive tool is gated regardless of whether it is pinned.

### High-risk catalog classes

solana-ai-kit's `skill-registry.json` includes entries classified by safe-ai-skill as high risk:

| Class | Representative entries | Risk |
|-------|----------------------|------|
| `wallet_signing` | `phantom-mcp` | Requests Phantom wallet to sign arbitrary transactions on behalf of the agent. If the agent is compromised or manipulated, this class of tool can drain the connected wallet. |
| `key_custody` | `x402-proxy-mcp` | Holds BIP-39 mnemonic or derived keys for x402 payment channel operations. Key material is exposed to the MCP process boundary. |
| `installer_script` | `ghostsecurity`, others with `curl\|bash` setup | The `setup_command` or installer invokes a network fetch piped to a shell. The fetched content is not verifiable at catalog-entry-audit time; it can change between audit and execution. |

Entries in `wallet_signing` and `key_custody` force `ask` under the default policy (the class decisions live in the plugin's `default.policy.yaml`; a project's `.safe-ai-skill/policy.yaml` cannot change the catalog). Entries in `installer_script` trigger the `exec_install_scripts` policy gate, which a project policy can only move toward `deny`. At runtime, tools from approved `wallet_signing` entries are gated by `gate-mcp` with a risk-class header in the approval prompt — the user is reminded of the class on every invocation.

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

MCP package vulnerabilities are a concrete, documented risk. safe-ai-skill addresses this at install time: `safe-ai-skill add` queries osv.dev for an exact, non-local npm source (for example `add mcp`'s resolved `pkg@version`) before installation (skip with `--offline`). The session sweep and `verify` make no network calls. The osv.dev API requires no authentication.

### Tool poisoning and prompt injection

Malicious skills can embed instructions targeting the language model in SKILL.md content: hidden HTML comments, "ignore previous instructions" text, Unicode bidirectional control characters, and lookalike unicode substitutions. `heuristics.rs` scans for these patterns before any skill content is pinned to the lockfile. A skill with high-severity findings is reported at session start and held at `install`; medium findings are reported for review.

## Design guarantees

**Hard guards are unconditional while the firewall runs.** The four hard guards — `mainnet_deploy`, `set_authority`, `account_close`, `secret_read` — are enforced by the engine binary regardless of the active profile, any time-boxed grant, or any project policy override; no engine flag or configuration relaxes them. In practice: mainnet deploys, authority changes and account closes always ask (a mainnet `--final` deploy is denied), secret reads are denied, and non-final deploys to other clusters are not hard guards. They stop applying only when the firewall itself is off: when the user sets `SAFE_AI_SKILL_DISABLE=1`, or when the engine cannot run on the platform (below; Solana CLI commands still ask). SessionStart reports both.

**Fails open only when the engine cannot run, never past a broken gate.** If no engine runs on this platform (no matching prebuilt, not an executable for this OS, exec failure 126/127), the `bin/safe-ai-skill` shim keeps the Solana CLI hooks at `ask`, reports the firewall INACTIVE at SessionStart, and lets the other hooks continue with a one-line notice. An engine crash blocks `gate-bash` and `gate-mcp` (exit 2) and is reported at SessionStart. `SAFE_AI_SKILL_STRICT=1` turns every one of these cases into exit 2 (block). `SAFE_AI_SKILL_DISABLE=1` turns the hooks off unless strict mode is set or the committed `.claude/settings.json` mentions it or can't be read (a repo can't disable the firewall); SessionStart reports it either way. The shim never builds from source and never runs a binary outside its own directory. The Solana hooks set `onFailure: block`, the others `onFailure: continue` (honoured from Claude Code 2.1.295).

**Residual risk: a repo's settings env is trusted code.** Claude Code applies the `env` of a project's `.claude/settings.json` to every hook. That file can already set `PATH`, `DYLD_*` or `LD_PRELOAD` and so run its own code in place of any hook, so the shim cannot defend against it. The `SAFE_AI_SKILL_DISABLE` check is a plain-text match on that file, which stops the obvious case, not a determined repo. Only open repositories you trust with your Claude Code session, and review `.claude/settings.json` in unfamiliar ones.

**Self-grant tripwire.** The agent can't loosen the firewall through its own tools. `gate-bash-secrets` denies Bash commands that run `safe-ai-skill allow|grant|revoke|confirm`, `mode <profile>`, `verify approve|trust`, `install` or `add` (which pin or re-pin packs), or the hook-only bare `verify` / `verify session` (it pins packs it has not seen before), or that reference protected state, and `gate-tamper` (`Write|Edit|MultiEdit|NotebookEdit`) denies writes to it. Protected state is the plugin data dir (grants, mode, spend ledger, audit log), the legacy `~/.safe-ai-skill` dir, the installed plugin and its `hooks.json`, and the state files of a project `.safe-ai-skill/` dir; a project's `policy.yaml` stays editable because it can only tighten. A command or payload too large or complex to scan asks instead of passing. Run those commands yourself in a terminal. This is a tripwire, not a sandbox: encoded commands, variable indirection or scripts written now and run later can get past it.

**Residual risk: `SAFE_AI_SKILL_DISABLE` in `.claude/settings.local.json` is honoured.** The shim ignores `SAFE_AI_SKILL_DISABLE=1` only when the committed `.claude/settings.json` mentions it (any `SAFE_AI_SKILL` text or `\u` escape). `.claude/settings.local.json` is the user's own, gitignored file, so a value there switches the firewall off, and SessionStart reports it. A repo that commits a `settings.local.json` anyway, or a tool that writes one into the project, turns the firewall off the same way. Check that `settings.local.json` is ignored by git, and treat a committed one as hostile.

**Residual risk: the shim is the trust anchor.** The shim checks the engine binary against sha256 constants stamped at release and never runs a mismatch. Anything that can write the plugin's `bin/` directory can rewrite the shim and its constants just as easily, and could swap the binary between the hash and the exec. Both are out of reach of the agent through the write tripwire on `~/.claude/plugins`; neither is defended against a local process running as the user.

**Fail-closed policy.** If the plugin's `default.policy.yaml` cannot be parsed, `policy.rs` falls back to treating all gated actions as `ask`. A project's `.safe-ai-skill/policy.yaml` can only tighten the policy: a setting that would loosen it is ignored and listed at SessionStart, invalid YAML is ignored, and ill-typed values fail closed. The session is not left without gates because of a config file error.

**External API timeouts do not allow.** osv.dev is an external network call. On timeout or API unavailability, the decision is `ask` (not `allow`, not `deny`). The user is informed and must approve. The rugcheck swap check is not wired in 1.0.1 (see below): MCP swaps always `ask`.

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
