# solana-old: Preservation Spec for solanabr/solana-claude Engineering Content

**Purpose of this document**: A structured inventory of the high-engineering-depth material in `solanabr/solana-claude-config` (the `.claude/` tree in this repo) that is absent from `sendaifun/solana-new` (the "superstack"). When the migration off solana-claude completes, nothing in this document should be silently lost — each item is assigned a disposition: bundle into safe-ai-skill, contribute upstream to solana-new, or keep as an optional add-on.

---

## 1. Purpose

`solana-new` is an idea-to-launch flow: 24 skills oriented around product scaffolding, hackathon submission, pitch decks, and launch mechanics. Its agent definitions are minimal stubs (four fields, no model spec, no tool routing). It has no coding-standard rules, no specialized subagent teams, and no security or performance commands.

`solana-claude-config` built up the opposite: deep engineering infrastructure — 15 specialized subagents running opus-class models, 24 slash commands including a security audit pipeline, 5 exhaustive coding-standard files (~2,500 lines), and three security-focused skill submodules (Trail of Bits scanner, Frank Castle's safe-solana-builder with ~70 secure-codegen rules, and QEDGen Lean 4 formal verification). None of this has an equivalent in solana-new.

This spec captures what to preserve, why, and how to route it into the new stack.

---

## 2. Inventory by Category

### 2.1 Specialized Subagents

Located in `.claude/agents/`. All 15 run `model: opus` except `mobile-engineer`, `devops-engineer`, `solana-guide`, `solana-researcher`, and `unity-engineer` which run `model: sonnet`.

solana-new comparison: its 24 skills each have an `agents/openai.yaml` stub with four display fields and no prompt, model, tool, or routing definition. These are UI labels, not engineering agents.

| Agent | Role | Distinctiveness |
|---|---|---|
| `anchor-engineer` | Anchor 0.31+ program development — macros, IDL, constraints, account validation | High — wired to anchor.md rules + safe-solana-builder |
| `pinocchio-engineer` | Zero-copy Pinocchio programs, 80-95% CU reduction | Very high — no analog anywhere in solana-new |
| `solana-qa-engineer` | Owns all test frameworks: Mollusk, LiteSVM, Surfpool, Trident, fuzz, CU profiling | Very high — full QA role, formal-verification link to qedgen |
| `defi-engineer` | Protocol composition: Jupiter, Drift, Kamino, Raydium, Orca, Meteora, Marginfi, Sanctum, Pyth | High — uses sendai skills as reference library; no routing equivalent in solana-new |
| `token-engineer` | Token-2022 extensions: transfer hooks, confidential transfers, metadata, launch + liquidity strategy | High — Token-2022 specifics are absent from solana-new's token content |
| `solana-architect` | System design, PDA schemes, account architecture, cross-program composability, security review | High — design phase before implementation; opus-class reasoning on architecture |
| `rust-backend-engineer` | Async Rust services (Axum/Tokio), indexers, webhook APIs for Solana | Medium — niche but useful for off-chain work |
| `solana-frontend-engineer` | React/Next.js dApp UI with @solana/kit, wallet UX, WCAG 2.2 AA accessibility | Medium — solana-new scaffold-project covers basic setup but not deep frontend rules |
| `game-architect` | On-chain game design, Unity/C# architecture, PlaySolana/PSG1 compatibility | Medium — only relevant to game projects |
| `unity-engineer` | Unity C# implementation: Solana.Unity-SDK, NFT loading, transaction signing | Medium — game projects only |
| `mobile-engineer` | React Native/Expo, Mobile Wallet Adapter 2.0, deep linking | Medium — overlaps with solana-new build-mobile |
| `devops-engineer` | CI/CD (GitHub Actions), Docker, RPC management, monitoring, Cloudflare Workers | Medium — solana-new has no DevOps content |
| `solana-guide` | Educational — explains concepts, creates tutorials, progressive learning paths | Low — replaceable; solana-new has solana-beginner |
| `solana-researcher` | Ecosystem research: protocols, SDK capabilities, pattern comparison | Low — solana-new has colosseum-copilot and competitive-landscape |
| `tech-docs-writer` | Technical documentation: READMEs, API docs, integration guides, architecture diagrams | Low-medium — useful but not unique |

**Must-keep agents** (no equivalent in solana-new): `anchor-engineer`, `pinocchio-engineer`, `solana-qa-engineer`, `defi-engineer`, `token-engineer`, `solana-architect`.

---

### 2.2 Slash Commands

Located in `.claude/commands/`. Grouped by function.

#### Build commands

| Command | What it does | Unique vs. replaceable |
|---|---|---|
| `build-program` | Runs anchor build / cargo build-sbf, enforces fmt + clippy, reports errors | Unique — no build command in solana-new |
| `build-app` | Scaffolds/builds Next.js or Vite frontend for dApps | Replaceable by solana-new scaffold-project |
| `build-unity` | Unity C# build with dotnet test integration | Unique — no Unity tooling in solana-new |
| `scaffold` | Project scaffold from template (Anchor/native/Pinocchio) | Partially overlaps solana-new scaffold-project |

#### Quality / security commands

| Command | What it does | Unique vs. replaceable |
|---|---|---|
| `audit-solana` | Full security audit: cargo audit, cargo geiger, manual vulnerability checklist (owner/signer checks, arithmetic, PDA bumps, CPI validation), links Trail of Bits scanner | Very unique — no security tooling in solana-new |
| `profile-cu` | Per-instruction CU measurement via LiteSVM/Mollusk, identifies bottlenecks | Very unique — no CU tooling in solana-new |
| `benchmark` | CU baseline storage + regression detection across commits | Very unique |
| `diff-review` | AI-powered branch diff review for Solana-specific security issues and anti-patterns; wires Trail of Bits solana-vulnerability-scanner | Very unique |
| `test-rust` | Rust test runner with LiteSVM/Mollusk/Trident harness selection, coverage report | Unique |
| `test-ts` | TypeScript test runner (Vitest/Mocha/Jest), Anchor integration tests | Unique |
| `test-dotnet` | .NET/Unity test runner with NUnit/MSTest support | Unique |
| `test-and-fix` | Run tests, parse failures, attempt auto-fix, re-run loop | Unique |

#### Lifecycle commands

| Command | What it does | Unique vs. replaceable |
|---|---|---|
| `deploy` | Structured deploy: devnet-first gate, simulation check, verifiable build, explicit mainnet confirmation | Partially overlaps solana-new deploy-to-mainnet but more rigorous |
| `generate-idl-client` | Detects IDL source (Anchor/Shank), runs Codama pipeline, verifies TypeScript output compiles | Unique — no IDL-to-client tooling in solana-new |
| `migrate-web3` | File-by-file migration from @solana/web3.js 1.x to @solana/kit with verification | Unique |
| `setup-ci-cd` | GitHub Actions workflow: verifiable builds, test automation, security audits, formatting checks | Unique |

#### Meta / planning commands

| Command | What it does | Unique vs. replaceable |
|---|---|---|
| `plan-feature` | Technical implementation plan for Solana features with architecture notes | Partially overlaps solana-new plan-feature (if present) |
| `explain-code` | Code explanation with Solana-specific context | Low uniqueness — general LLM capability |
| `write-docs` | Generates README/API docs from code | Partially overlaps; this agent handles write-docs |
| `cleanup` | Removes dead code, unused imports, AI-generated slop per diff-review output | Useful, not unique |
| `quick-commit` | Conventional commit helper with branch naming | Not unique |
| `resync` | Re-pull config from upstream solana-claude, merge CLAUDE.md | Solana-old specific — becomes irrelevant after migration |
| `update` | Updates solana-claude-config in-place (backs up CLAUDE.md, shows diff) | Solana-old specific |
| `setup-mcp` | Configures MCP server API keys in .env | Overlaps solana-new setup patterns |

---

### 2.3 Deep Coding Rules

Located in `.claude/rules/`. These are injected into every session and govern all code Claude produces. solana-new has no equivalent — it ships zero rules files.

| File | Size / scope | Summary |
|---|---|---|
| `anchor.md` | ~450 lines | Comprehensive Anchor 0.31+ reference: account type selection, every constraint form (`init`, `seeds`, `has_one`, `realloc`, `close`), discriminator semantics, PDA canonical-bump enforcement with storage requirement, checked arithmetic (every operation), CPI construction and the mandatory `.reload()` after CPI, Token / Token-2022 interface patterns, event emission, zero-copy accounts, LazyAccount, remaining accounts, anti-pattern table, per-instruction security checklist |
| `rust.md` | ~300 lines | Solana Rust standards: never `unwrap()`/`expect()` in program code, always `checked_add`/`checked_sub`/`try_into()`, avoid unsafe unless documented, naming conventions, public API doc requirements, testing with `Result` types, performance (appropriate data structures, avoid allocations), Solana-type usage, minimal logging, input validation patterns, workspace dependency management |
| `pinocchio.md` | ~500 lines | Full Pinocchio zero-copy reference: lazy vs standard entrypoint, single-byte discriminators, `#[repr(C)]` struct layout with field-ordering rules for padding minimization, zero-copy account read/write patterns, field-by-field serialization alternative, `TryFrom` account validation pattern, PDA manual validation, CPI (basic and PDA-signed), Token/Token2022 validation, error handling without std, account creation, secure account closing (revival-attack prevention), performance optimization (stack allocation, const sizes, feature-gated debug, bitwise flags), batch instruction processing, unsafe anti-patterns to avoid, Mollusk test patterns |
| `typescript.md` | ~400 lines | dApp TypeScript standards: web3.js 1.x vs @solana/kit guidance, no `any` types, explicit return types, simulate-before-send pattern with CU buffer, BigInt for u64, type-safe account fetching, async/await (never .then()), batched RPC calls, React patterns with React Query, custom error types, user-friendly error message mapping, wallet adapter setup, performance (lazy loading, debounce), JSDoc standards, import organization |
| `dotnet.md` | ~400 lines | Unity/C# standards: .NET 9 target, naming conventions (PascalCase/camelCase/_camelCase/s_camelCase), boolean naming (IsX/HasX/CanX), Unity serialized fields, file organization order, async/await ConfigureAwait patterns, null handling, event patterns, transaction building, blockchain error handling, account deserialization, test naming and AAA structure, Unity test attributes, modern C# 12/13 features, XML documentation, performance (caching, object pooling, update-loop allocation avoidance) |

The rules files are the most immediately transferable content. They are language-/framework-scoped (not project-scoped), load automatically via the `.claude/` directory convention, and have no equivalent in solana-new.

---

### 2.4 Security and Audit Skills

Located in `.claude/skills/ext/`. These are git submodules.

#### safe-solana-builder (ext/safe-solana-builder/)

Author: Frank Castle. A coding-methodology skill that activates whenever Solana program code is the deliverable.

Structure: `SKILL.md` (orchestration) + `references/shared-base.md`, `anchor.md`, `native-rust.md`, `pinocchio.md`, `litesvm.md` (framework-specific rule sets) + `examples/`.

Coverage: ~70 security rules derived from real protocol audits:
- Protocol-specific: oracle manipulation, fee bypass, slippage, LP preprocessing gaps
- Logic flaws: dust DoS, time-unit mismatches, type narrowing, pre/post-fee inconsistencies
- Access control: missing signer checks, frontrunnable initialization, post-expiry flows
- State management: coupled-field resets, counter drift, vested/unvested separation, rollback safety
- PDA issues: zombie accounts, seed collisions, canonical bump enforcement, lifecycle closure
- Reward accounting: rounding in partial unstake, dual-path reward debt bypass, retroactive rate, dead share price, inflation/first-depositor attack, fee-on-transfer delta, rewards sourced from principal
- Vault architecture: missing withdrawal paths on PDA-controlled vaults
- Token-2022: PermanentDelegate, FreezeAuthority, TransferHook CPI forwarding, ConfidentialTransfer compatibility
- Admin key: two-step rotation, timelock recommendations
- BPF limits: 4096-byte stack frame DoS, `Box<>` mitigation

This skill pairs naturally with safe-ai-skill's security mandate. It is a prerequisite check before the audit command runs.

#### trailofbits/ (ext/trailofbits/)

Trail of Bits skills marketplace (submodule). The specifically relevant plugin for Solana work is `plugins/building-secure-contracts/skills/solana-vulnerability-scanner/`.

The scanner is invoked by `/diff-review` and `/audit-solana`. It provides automated static analysis patterns from Trail of Bits' Solana audit experience.

#### qedgen/ (ext/qedgen/)

Formal verification skill: Claude writes Lean 4 proofs for Solana program properties; Leanstral (Mistral theorem prover) fills hard sub-goals via `qedgen fill-sorry`.

Architecture: Claude reads source, writes `SPEC.md`, writes Lean 4 models/theorems, iterates on `lake build` errors, calls `qedgen fill-sorry` for hard sub-goals. Trust boundary: SPL Token, Solana runtime, CPI mechanics are axiomized; program logic (authorization, conservation, state machines, arithmetic safety, CPI correctness) is verified.

Lean support library: `QEDGen/Solana/Account.lean`, `Token.lean` (conservation axioms), `Authority.lean`, `State.lean` (lifecycle).

The `qedgen` binary is a Rust CLI with `generate`, `fill-sorry`, `spec`, `consolidate`, `setup` subcommands. First Mathlib build: 15-45 minutes. Requires `MISTRAL_API_KEY`.

This is the most specialized item in the entire inventory. It is directly aligned with safe-ai-skill's security goals (mathematical guarantees about program properties) and has no equivalent anywhere in the ecosystem.

---

### 2.5 Workflow and Infrastructure

#### Mandatory build workflow (CLAUDE.md)

Every program change must complete: `anchor build` or `cargo build-sbf` → `cargo fmt` → `cargo clippy -- -W clippy::all` → unit + integration + fuzz tests → devnet deploy before mainnet.

The "Done Checklist" is explicit: build passes, no lint warnings, all tests pass, diff-review run (AI slop removed), security audit passed, CU profiled, verifiable build for deployment.

This workflow is encoded in CLAUDE.md and enforced by the agent team through the commands.

#### Mainnet deployment rituals

`/deploy` requires explicit user confirmation for mainnet. The `CLAUDE.md` directive "NEVER deploy to mainnet without explicit user confirmation" is referenced by all build-focused agents. `/setup-ci-cd` bakes this gate into CI.

The migration plan (`plans/`) identifies that the current settings.json mainnet gate using `when.command_matches` is non-functional (not a real Claude Code feature). The real gate is the `/deploy` command's interactive prompt plus safe-ai-skill's runtime firewall (Phase 1 of the plan).

#### Agent team patterns

`settings.json` enables `CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1` and `CLAUDE_CODE_COORDINATOR_MODE=1`. The CLAUDE.md documents six named patterns: `program-ship` (architect + anchor-engineer + qa-engineer), `full-stack` (architect + anchor + frontend + backend), `audit-and-fix` (qa-engineer + audit-solana), `game-ship` (game-architect + unity-engineer + anchor-engineer), `research-and-build` (researcher + architect + engineer), `defi-compose` (defi-engineer + anchor-engineer + qa-engineer), `token-launch` (token-engineer + anchor-engineer + frontend).

#### bin/ update tooling

Three scripts: `update.sh` (in-place update from `solanabr/solana-claude-config` upstream, backs up CLAUDE.md, shows diff, dry-run support), `resync.sh` (pulls submodule updates), `_env_merge.sh` (merges .env changes without overwriting secrets).

After migration to safe-ai-skill as the primary config, `update.sh` and `resync.sh` target the wrong upstream and become dead. The update mechanism should be replaced by safe-ai-skill's own versioning.

#### settings.json permissions allowlist

The current settings.json contains a comprehensive pre-approved command allowlist (anchor, cargo, solana, spl-token, npm/yarn/pnpm/bun, git, gh, docker, unity, etc.) that was assembled over time. This is independent of the runtime firewall — it is the baseline that avoids per-command prompts during development.

The plan notes the allowlist is currently too permissive in places (wide-open `Read(*)`, `Bash(cat *)`) and needs narrowing — but the structure and breadth are valuable and should be carried into safe-ai-skill's policy layer.

---

## 3. Recommended Disposition

| Item | Disposition | Priority |
|---|---|---|
| **anchor-engineer agent** | Bundle into safe-ai-skill | Must-keep |
| **pinocchio-engineer agent** | Bundle into safe-ai-skill | Must-keep |
| **solana-qa-engineer agent** | Bundle into safe-ai-skill | Must-keep |
| **solana-architect agent** | Bundle into safe-ai-skill | Must-keep |
| **defi-engineer agent** | Bundle into safe-ai-skill | Must-keep |
| **token-engineer agent** | Bundle into safe-ai-skill | Must-keep |
| **anchor.md rules** | Bundle into safe-ai-skill | Must-keep |
| **rust.md rules** | Bundle into safe-ai-skill | Must-keep |
| **pinocchio.md rules** | Bundle into safe-ai-skill | Must-keep |
| **typescript.md rules** | Bundle into safe-ai-skill | Must-keep |
| **safe-solana-builder skill** | Bundle into safe-ai-skill | Must-keep |
| **qedgen skill** | Keep as optional add-on (requires MISTRAL_API_KEY + 15-45 min Mathlib setup) | Must-keep (opt-in) |
| **trailofbits scanner** | Bundle into safe-ai-skill | Must-keep |
| **/audit-solana command** | Bundle into safe-ai-skill | Must-keep |
| **/profile-cu command** | Bundle into safe-ai-skill | Must-keep |
| **/benchmark command** | Bundle into safe-ai-skill | Must-keep |
| **/diff-review command** | Bundle into safe-ai-skill | Must-keep |
| **/test-rust command** | Bundle into safe-ai-skill | Must-keep |
| **/test-ts command** | Bundle into safe-ai-skill | Must-keep |
| **/generate-idl-client command** | Bundle into safe-ai-skill | Must-keep |
| **/setup-ci-cd command** | Bundle into safe-ai-skill | Must-keep |
| **/migrate-web3 command** | Bundle into safe-ai-skill | Must-keep |
| **Mandatory build workflow** | Bundle into safe-ai-skill (CLAUDE.md) | Must-keep |
| **Agent team patterns** | Bundle into safe-ai-skill (CLAUDE.md + settings) | Must-keep |
| **dotnet.md rules** | Bundle into safe-ai-skill | Nice-to-have |
| **rust-backend-engineer agent** | Bundle into safe-ai-skill | Nice-to-have |
| **solana-frontend-engineer agent** | Bundle into safe-ai-skill | Nice-to-have |
| **devops-engineer agent** | Bundle into safe-ai-skill | Nice-to-have |
| **game-architect + unity-engineer agents** | Keep as optional add-on (game projects only) | Nice-to-have |
| **mobile-engineer agent** | Contribute to solana-new build-mobile | Nice-to-have |
| **/deploy command** | Merge improvements into solana-new deploy-to-mainnet | Nice-to-have |
| **/build-program command** | Contribute to solana-new scaffold-project | Nice-to-have |
| **/test-dotnet command** | Bundle into safe-ai-skill (Unity projects) | Nice-to-have |
| **settings.json allowlist** | Carry into safe-ai-skill policy layer (with narrowing) | Must-keep (reworked) |
| **solana-guide agent** | Contribute to solana-new solana-beginner | Drop / contribute |
| **solana-researcher agent** | Drop (covered by solana-new colosseum-copilot + competitive-landscape) | Drop |
| **tech-docs-writer agent** | Drop or keep as optional | Low |
| **bin/update.sh + resync.sh** | Drop (solana-claude upstream no longer relevant post-migration) | Drop |
| **plan-feature command** | Contribute to solana-new (if absent there) | Low |
| **quick-commit, cleanup, explain-code** | Drop (general-purpose, not Solana-specific) | Drop |
| **write-docs command** | Keep as optional | Low |
| **setup-mcp command** | Merge into safe-ai-skill bootstrap flow | Low |

---

## 4. Migration Notes

### End state

The user runs three things simultaneously:

1. **solana-new** (superstack) — installed at `~/.claude/skills/` via `curl solana.new/setup.sh | bash`. Provides idea-to-launch flow: scaffold, build-defi, launch-token, deploy-to-mainnet, submit-to-hackathon, etc.

2. **safe-ai-skill** — installed as a Claude Code plugin (`claude plugin install safe-ai-skill@safe-ai-skill`). Provides: runtime firewall (gates deploys, transfers, keypair reads, telemetry curl), supply-chain verification of whatever solana-new installs, and — after this migration — all the engineering-depth content from solana-claude.

3. **solana-claude-config** — this repo's `.claude/` subtree — is decommissioned or frozen. Its engineering content lives inside safe-ai-skill.

### What safe-ai-skill gains from this migration

The engineering-depth content (agents, commands, rules, security skills) moves from the `.claude/` project-local config into the safe-ai-skill plugin. This means:

- The 15 specialized agents are available in any project that has the plugin installed, not just this repo.
- The 5 rules files are injected globally, not just in this working directory.
- `/audit-solana`, `/profile-cu`, `/diff-review`, `/test-rust`, `/test-ts`, `/generate-idl-client`, `/setup-ci-cd`, `/migrate-web3` become globally available plugin commands.
- safe-solana-builder and qedgen travel with the plugin as bundled submodules.

### What becomes redundant

- `bin/update.sh` and `bin/resync.sh` — targeted at solanabr/solana-claude-config upstream; both dead post-migration.
- The `resync` and `update` slash commands — same reason.
- The project-local `.claude/settings.json` permissions allowlist — superseded by the plugin's `policy/default.policy.yaml`.
- `CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1` in project settings — moves to the plugin's own settings or kept in global `~/.claude/settings.json`.

### What solana-new users get without any extra action

With safe-ai-skill installed, a user who runs the solana-new installer and then opens any Solana project gets:
- Engineering agents available in every session (no per-project setup)
- Security rules injected automatically
- Runtime firewall active on every solana/anchor/spl-token command
- Supply-chain audit of the solana-new skills at SessionStart

The solana-new skills continue to work exactly as before; the engineering layer sits underneath them.

### Overlap to resolve

| Overlap | Resolution |
|---|---|
| solana-new `scaffold-project` vs solana-claude `/scaffold` | Keep solana-new's (better UX for new users); solana-claude's adds security scaffolding, merge that in |
| solana-new `deploy-to-mainnet` vs solana-claude `/deploy` | Merge solana-claude's devnet-first gate and verifiable build enforcement into solana-new's deploy skill |
| solana-new `build-defi-protocol` vs solana-claude `defi-engineer` agent | Complementary: solana-new orchestrates the build flow; defi-engineer provides deep protocol integration knowledge. No merge needed |
| solana-new `debug-program` skill vs solana-claude `solana-qa-engineer` agent | Complementary: debug-program is a basic stub; qa-engineer brings full test infrastructure. No conflict |
| solana-new `solana-beginner` vs solana-claude `solana-guide` agent | Drop solana-guide; solana-beginner is sufficient |

---

*Last updated: 2026-06-11. Source inventory from solanabr/solana-claude-config v1.3.0 at `/Users/azrael/Developer/GigaClaude/safe-ai-skill/.claude/`.*
