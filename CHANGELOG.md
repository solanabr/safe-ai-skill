# Changelog

All notable changes are documented in this file. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [1.0.0] — 2026-06-26

### Summary

First stable release. Ships the safe-ai-skill engine, runtime action firewall, and supply-chain verifier as a standalone, general-purpose Claude Code plugin — it secures any skills, MCPs, and agents. `solanabr/solana-ai-kit` v2.0.0 is the reference integration used to exercise and document the gates, not a requirement.

### Engine

- Static Rust binary (`safe-ai-skill` / `safe-ai-skill`) with synchronous I/O; no runtime dependency. Prebuilt for `darwin-arm64`, `darwin-x64`, `linux-x64`, `linux-arm64` with `SHA256SUMS`. Falls back to `cargo build --release` if no prebuilt matches; shim exits code 2 (block) if neither path is available — never fails open.
- Hook wiring: `gate-bash` (solana/spl-token/anchor CLI), `gate-bash-secrets` (unconditional secret and exfiltration patterns), `gate-read` (secret file globs), `gate-mcp` (value-moving MCP tools), `redact` (PostToolUse secret scrub), `prompt-guard` (UserPromptSubmit private key/seed block).
- Append-only audit log (`audit.jsonl`), TOFU lockfile (`lockfile.json`), daily spend ledger (`spend.json`), time-boxed grant store (`grants.json`), session keypair dir (mode 0600).
- Policy DSL (`default.policy.yaml`): full schema synced on-disk including `catalog`, `ext`, and `exec_install_scripts` fields. Deep-merge over project `.safe-ai-skill/policy.yaml`. Fail-closed on parse error.
- Four profiles: `strict` (default), `autopilot`, `paranoid`, `off`. Profiles adjust soft-gate thresholds; hard guards are unaffected by all profiles, grants, and flags.
- Hard guards (`mainnet_deploy`, `set_authority`, `account_close`, `secret_read`) enforced unconditionally — not present in the policy DSL, not relaxable by any configuration.

### Runtime firewall

- `gate-bash` classifies commands into `transfer`, `deploy`, `authority`, `destructive`, `install_script`, `readonly`. Mainnet + non-readonly → `ask`. Spend caps → allow/ask/deny. `install_script` (curl/wget piped to bash/sh) → `exec_install_scripts` policy value (`allow|ask|deny`; default `ask`).
- `gate-mcp` sensitive name pattern extended to cover `stake|delegate|mint|bridge|lend|borrow` in addition to the prior `transfer|sign|swap|send|withdraw|burn|pay|upgrade` — catches `heliusWrite.stakeSOL`, `heliusWrite.delegateStake`, and equivalent staking/DeFi verbs from solana-ai-kit's `heliusWrite` MCP.
- `gate-mcp` enforces catalog risk classes at runtime: tools from `wallet_signing` entries show a risk-class header on every approval prompt; `key_custody` entries are gated independently of name-pattern matching.
- Rugcheck swap gate: mint score above `rugcheck_max_score` (default 40) → `deny`; API timeout → `ask` (never allow).
- `deny` verified to survive both `bypassPermissions` and `enableAllProjectMcpServers: true` (Claude Code hook execution order).
- Supersedes the solana-ai-kit mainnet-deploy hook, which uses `read -r` in hook context (no TTY — silently fails open).

### Supply-chain verifier

- `install` subcommand: hub-agnostic secure install flow. Accepts `--from <url|ref>` and `--home <dir>`. Runs verification pipeline, shows diff of all flagged content, prompts for approval before writing. Does not auto-widen `~/.claude/settings.json` permissions. Replaces the retired `bootstrap` subcommand (which was hard-coded to a remote `skills.tar.gz` tarball and is no longer applicable).
- Per-`ext`-submodule verification (`ext_verify.rs`): each of solana-ai-kit's 18 `ext/` git submodules is walked independently at `SessionStart`. Git SHA pinned on first seen (TOFU). SHA drift triggers quarantine + diff in `additionalContext` + `reloadSkills: true`. `safe-ai-skill verify approve ext/<name>` re-pins after user review.
- `registry.rs`: parses `skill-registry.json` (39 opt-in entries, `default_installed: false`). Classifies entries by risk class (`wallet_signing`, `key_custody`, `installer_script`, `standard`). High-risk classes gate installation and runtime tool invocation per policy.
- `registry list` and `registry verify` subcommands: list catalog with risk classes and install status; audit installed entries against pinned catalog state.
- `add skill <name>` resolves catalog entries, checks risk class against policy before running verification pipeline. High-risk entries show risk summary; denied classes refuse install.
- `add mcp <id>` resolves catalog MCP entries, pins to exact `pkg@version` + `dist.shasum`, writes to `.mcp.json`. `@latest` entries in existing `.mcp.json` are flagged INFORMATIONAL — not auto-rewritten. `safe-ai-skill pin-mcps` offered as opt-in rewrite.
- Static heuristics (`heuristics.rs`): telemetry curl patterns, `curl|bash` installer patterns, keypair references, prompt injection markers (Unicode bidi, hidden comments), unpinned npx. All patterns are generic; no package-specific allowlists to maintain.
- osv.dev CVE lookup for all resolved `pkg@version` entries. No auth required.
- Every `ext/` submodule treated identically — telemetry preambles flagged and neutralized generically by `heuristics.rs`. No special-casing; known supply-chain risks are addressed through the generic per-submodule pipeline, not custom code.

### MCP posture

- solana-ai-kit ships all 7 MCP servers at `@latest`. safe-ai-skill flags these INFORMATIONAL (LOW) at `install` time and `SessionStart` by design — the kit's `@latest` posture is intentional, and safe-ai-skill does not nag or auto-pin. Runtime gating by tool name and payload operates independently of pin status.

### Relaxation model

- Time-boxed grants (`safe-ai-skill allow`): relax soft gates for a bounded scope and duration. Stored in `grants.json`; expire automatically. `safe-ai-skill revoke` cancels early.
- Hard guards bypass no grant, profile, or flag in v1. This is an engine property, not a default.

### Distribution

- **Plugin** (always-on firewall): `claude plugin marketplace add solanabr/safe-ai-skill` → `claude plugin install safe-ai-skill@stbr`. Ships committed platform binaries; the shim resolves the native prebuilt, else builds from `crates/engine`, else fails closed.
- **CLI** (`safe-ai-skill` Tier 1/2 commands) via three paths, all checksum-verified against the release `SHA256SUMS`:
  - npm — `npm install -g @stbr/safe-ai-skill` / `npx @stbr/safe-ai-skill` (CLI command: `safe-ai-skill`). `postinstall.js` downloads the platform binary from the matching GitHub Release tag and aborts on checksum mismatch (no silent install).
  - Standalone — `curl -fsSL …/install.sh | sh`. Downloads + verifies the binary before installing to `~/.local/bin` (overridable via `SAFE_AI_SKILL_BIN_DIR`); fails loud, installs nothing on mismatch.
  - cargo — `cargo install safe-ai-skill` (builds from source on any Rust-capable platform).
- README Install section separates the always-on plugin (firewall) from the `safe-ai-skill` CLI.

### Tooling & CI

- `release.yml` builds all four platform binaries (`darwin-arm64`, `darwin-x64`, `linux-x64`, `linux-arm64`) and regenerates `SHA256SUMS` on every `v*` tag.
- `ci.yml`: lint (fmt + clippy), native build+test matrix with an npm-launcher smoke, a build-only cross-build job covering `darwin-x64` + `linux-arm64`, committed-binary checksum verification, and a `package-checks` job (`node --check` on the npm wrapper, `shellcheck`/`sh -n` on shell scripts, and `scripts/check-versions.sh` asserting npm/Cargo/plugin/marketplace/README versions agree).
- `npm-e2e.yml` (release/schedule/dispatch): packs, installs, checksum-verifies, and execs the published CLI end to end.
- Repo hygiene: `.claude/` (local dogfooding config) is gitignored and the shipped plugin lives in `plugins/`; `.DS_Store`, OS/editor clutter, and install-time-downloaded `npm/bin/safe-ai-skill-*` binaries are ignored.
- Folding safe-ai-skill into the `stbr` solana-ai-kit marketplace is deferred to a future release.

### Out of scope (deferred)

- Lighthouse on-chain assertion insertion (requires owning the tx-construction path).
- Turnkey SaaS wallet integration (skipped in favor of session keypairs).
- `safe-ai-skill doctor` dual-install/coexistence detection (P2).
- Config-driven telemetry endpoint detection beyond Convex pattern (P1).
