# Architecture

## Engine

The core of safe-solana-ai is `ssai`, a single static Rust binary. The user-facing CLI command `safe-solana-ai` is the same binary (symlink or alias); `ssai` is the terse name used on the hot path.

**Why Rust.** PreToolUse fires on every Bash, Read, Grep, Glob, and MCP tool call — hundreds of invocations per session. Rust runs the gate logic in ~2–5ms; a Node.js spawn costs ~40–80ms. More importantly, a gate that requires a runtime (Node, Python) fails open if that runtime is absent. `ssai` has no runtime dependency. The binary is auditable as a single artifact. The CLI contract — stdin JSON in, stdout JSON out — is language-agnostic, so the language choice does not ripple into hook wiring or tooling.

**Crate dependencies** are intentionally minimal: `serde`/`serde_json`, `serde_yaml`, `sha2`, `ureq`, `glob`. No tokio. All I/O is synchronous; the 10–60s hook timeouts are more than sufficient.

**Source layout** (in `crates/engine/src/`):

| File | Responsibility |
|------|---------------|
| `main.rs` | Subcommand dispatch |
| `io.rs` | Hook JSON parse; decision emitters (`deny`/`ask`/`allow`/`defer` + reason); exit codes |
| `policy.rs` | YAML load + deep-merge (defaults then project override); `policy.effective()` applies active profile; fails closed on parse error |
| `context.rs` | Network detection: env flags → Anchor.toml → cached `solana config get` (60s cache) |
| `gates/bash.rs` | Tokenize → classify → network resolve → policy → decide |
| `gates/mcp.rs` | MCP tool name + payload inspection; rugcheck swap gate; high-risk MCP class enforcement |
| `gates/read.rs` | Secret-glob deny for Read/Grep/Glob |
| `redact.rs` | Secret patterns → `updatedToolOutput` / `updatedMCPToolOutput` |
| `spend.rs` | Daily spend ledger: `${CLAUDE_PLUGIN_DATA}/spend.json` |
| `audit.rs` | Append-only JSONL: `${CLAUDE_PLUGIN_DATA}/audit.jsonl` |
| `lockfile.rs` | sha256 dir-tree hashing; git SHA pinning for `ext/` submodules; `${CLAUDE_PLUGIN_DATA}/lockfile.json`; quarantine logic |
| `heuristics.rs` | Skill/MCP static scan (telemetry curl, keypair refs, injection patterns, `curl|bash`, unpinned npx) |
| `verify/mod.rs` | Intrinsic pipeline orchestrator: heuristics + provenance + osv.dev + TOFU |
| `registry.rs` | `skill-registry.json` parser; risk-class classification; high-risk gating |
| `verify/mod.rs` | Per-`ext`-submodule walker (`ext_submodules`, `run_session` integration): drift detection, quarantine, telemetry neutralization |
| `verify/lockfile.rs` | `ExtPin` pinning + git SHA resolution (`resolve_git_sha` / `resolve_ext_identity`) for `ext/` submodules |
| `main.rs` | `install` subcommand (`cmd_install`): hub-agnostic install flow — download → verify → diff → approve → write |
| `provenance.rs` | Resolve to immutable ref (GitHub SHA / npm exact+shasum); typosquat/new-pkg flags |
| `osv.rs` | osv.dev CVE lookup for resolved `pkg@version` |
| `rugcheck.rs` | `GET api.rugcheck.xyz/v1/tokens/{mint}/report`; timeout → `ask` |
| `relax.rs` | Time-boxed grant application; session-keypair autopilot logic |
| `squads.rs` | Upgrade-authority advisory: `getAccountInfo` on programdata (Phase 3) |

## Binary distribution

Prebuilt binaries are committed at `plugins/safe-solana-ai/bin/`:

```
bin/
├── ssai                  # shell shim — platform selector
├── ssai-darwin-arm64
├── ssai-darwin-x64
├── ssai-linux-x64
└── SHA256SUMS
```

The `ssai` shim selects the matching platform binary and execs it. If no match is found it performs a one-time `cargo build --release` into `${CLAUDE_PLUGIN_DATA}/bin` and records the path. CI rebuilds all three binaries and regenerates `SHA256SUMS` on every release tag.

**Never fails open.** If no prebuilt binary matches and `cargo` is unavailable, the shim exits with code 2. Claude Code interprets a non-zero exit from a PreToolUse hook as a block on the gated action. There is no code path that allows a gated action to proceed when `ssai` cannot run.

## Hook wiring

Hooks are declared in `plugins/safe-solana-ai/hooks/hooks.json` and wired by Claude Code when the plugin is enabled. All hooks invoke `ssai` subcommands via `${CLAUDE_PLUGIN_ROOT}/bin/ssai`.

### PreToolUse

**Bash — CLI command gates**

Three entries with `if` field (content filter, the correct content-matching mechanism):

```
gate-bash   if: "Bash(solana *)"     timeout: 20s
gate-bash   if: "Bash(spl-token *)"  timeout: 20s
gate-bash   if: "Bash(anchor *)"     timeout: 20s
```

One unconditional entry (no `if`) — fires on every Bash call:

```
gate-bash-secrets   timeout: 10s
```

`gate-bash-secrets` does pure string checks in microseconds: `cat ~/.config/solana/id.json`, `cat .env`, base64/exfil of keypair files, outbound `curl -X POST` to Convex-pattern endpoints, and `curl|bash`/`wget|bash` install-script patterns. It does not need to parse the full command; matching any of these patterns is sufficient for a `deny`.

**Read/Grep/Glob — secret file gate**

```
gate-read   matcher: "Read|Grep|Glob"   timeout: 10s
```

Checks the path argument against `secrets.deny_read_globs` in policy. Matches are `deny`; `allow_read_globs` entries (e.g. `.env.example`) are allowed explicitly before the deny list is checked.

**MCP — value-moving tool gate**

```
gate-mcp   matcher: "mcp__.*"   timeout: 15s
```

Fast-allows any MCP tool whose name does not match the sensitive name pattern (`transfer|sign|swap|send|withdraw|burn|pay|upgrade|stake|delegate|mint|bridge|lend|borrow`). For sensitive names, inspects the payload (amounts, destination addresses, mint addresses) and applies policy. High-risk MCP classes (`wallet_signing`, `key_custody`) are enforced via `registry.rs` independently of the name pattern. Delegates mint risk to `rugcheck.rs` for swap calls.

### PostToolUse

```
redact   matcher: "Bash|Read|Grep"   timeout: 10s
```

Scans tool output for secret patterns: 64-byte base58 private keys, JSON keypair arrays (`[n, n, n, ...]` of length 64), BIP39 seed phrases, and API key patterns. Replaces matches in `updatedToolOutput` / `updatedMCPToolOutput`.

### UserPromptSubmit

```
prompt-guard   timeout: 10s
```

Scans the user's prompt text for raw private keys or seed phrases. Claude Code does not support rewriting user prompts, so the only available response to a match is a block with a reason message.

### SessionStart

```
verify session   matcher: "startup|resume"   timeout: 60s
```

Runs the supply-chain audit on every session start and resume. Scans `~/.claude/skills/**` and `.claude/skills/**` (configurable via `supply_chain.verify_skills_dirs`), all MCP server entries in `.claude/settings.json`, and — critically — **each `ext/` submodule independently** via `verify/mod.rs` (`ext_submodules` + `run_session`).

**SessionStart cannot block session startup.** The response mechanism is:

1. Drifted or unverified submodules are moved to `${CLAUDE_PLUGIN_DATA}/quarantine/<name>`.
2. `additionalContext` is injected into the session with a warning listing what was quarantined and why.
3. `reloadSkills: true` is emitted so Claude Code reloads the (now reduced) skill set.
4. The session starts normally with the quarantined content absent.
5. The user can inspect with `safe-solana-ai status` and restore with `ssai verify approve <name>`.

## Per-`ext`-submodule verification

solana-ai-kit installs 18 third-party `ext/` submodules into `.claude/skills/ext/`. Each submodule is its own supply-chain unit — different origin, different maintainer, different risk profile. ssai treats them individually, not as a single blob.

**First-seen (TOFU) pin.** On first `verify session`, `verify/mod.rs` walks `.claude/skills/ext/` and reads the git submodule SHA for each entry (`git rev-parse HEAD` inside the submodule directory, or from `.gitmodules`). That SHA is recorded in `lockfile.json` as the canonical pin for that submodule.

**Drift detection.** On subsequent sessions, the current git SHA is compared to the pinned SHA. Any difference is drift. Drift triggers:
- The submodule is moved to quarantine before skills load.
- The drift is shown as a diff in `additionalContext`.
- `ssai verify approve <name>` re-pins after the user reviews the diff.

**Per-submodule heuristics.** `heuristics.rs` runs the same static scan on each submodule's content: telemetry curl patterns, `curl|bash` installer patterns, keypair references, prompt injection markers. The `ext/solana-new` submodule is treated the same as any other — its telemetry preamble is flagged and neutralized generically; there is no special-casing.

**`resync.sh` integration.** When solana-ai-kit's `resync.sh` updates submodules (pulling new commits), ssai detects the SHA changes on the next `SessionStart` and quarantines the updated submodules until the user reviews and re-pins. This prevents silent code updates from taking effect without user awareness.

## Catalog awareness and registry gating

solana-ai-kit ships a `skill-registry.json` with 39 opt-in entries (`default_installed: false`). ssai's `registry.rs` parses this catalog and classifies each entry by risk class.

**Risk classes:**

| Class | Example entries | Default gate |
|-------|----------------|--------------|
| `wallet_signing` | `phantom-mcp` (signs arbitrary transactions via Phantom) | `deny` unless explicitly approved in policy |
| `key_custody` | `x402-proxy-mcp` (BIP-39 key custody for x402 payments) | `deny` unless explicitly approved in policy |
| `installer_script` | `ghostsecurity` (installs via `curl\|bash`) | `ask` — shows installer content before execution |
| `standard` | All other entries | Standard verification pipeline |

**`ssai registry list`** shows all 39 entries with their risk class, install status, and policy gate. **`ssai registry verify`** audits installed entries against the registry — checking that installed content matches the pinned catalog version and that no high-risk entries were installed without approval.

**`ssai add skill <name>`** resolves a catalog entry name, checks its risk class against policy, runs the full verification pipeline, and installs on approval. High-risk entries show a risk summary and require explicit confirmation even if the general policy permits `standard` installs.

## `curl|bash` install-script gate

The runtime `gate-bash-secrets` hook intercepts `curl ... | bash`, `curl ... | sh`, `wget ... | bash`, and equivalent patterns at PreToolUse — before the pipe executes. The default policy is `exec_install_scripts: ask`: the user is shown the full URL and the beginning of the script content before being asked to approve. The policy can be set to `deny` to block all install-script execution, or `allow` to permit it (not recommended).

This gate fires unconditionally (no `if` filter) — it is part of `gate-bash-secrets`, which runs on every Bash call. The latency cost is microseconds (pure string matching, no subprocess).

## Verified hook semantics

Three properties of the Claude Code hook system (verified against official 2026-06 docs, v2.1.139+) that are load-bearing for safe-solana-ai's guarantees:

**`deny` survives `bypassPermissions`.** A `permissionDecision: "deny"` response from a PreToolUse hook blocks the action even when the session is running with `bypassPermissions` (yolo mode). The hard guards (`mainnet_deploy`, `set_authority`, `account_close`, `secret_read`) use this and cannot be overridden by any profile, grant, or session flag.

**`deny` survives `enableAllProjectMcpServers: true`.** solana-ai-kit enables all project MCPs in its `settings.json`. ssai's `gate-mcp` hook fires via PreToolUse, which runs before the MCP permission check. MCP pre-approval does not bypass `gate-mcp`. This is a verified property of the hook execution order.

**No TTY in hook context.** Hooks do not have a TTY attached. The prior approach of using `read -r` inside a hook for interactive confirmation is silently broken — it exits immediately, failing open. `ask` (`permissionDecision: "ask"`) is the correct mechanism. This is why ssai supersedes the kit's broken mainnet gate without requiring any change to the kit's settings.

**Hooks run in parallel; most-restrictive-wins.** When multiple hook entries match the same tool call, all run concurrently. The most restrictive response wins: `deny` > `ask` > `allow`. ssai composes safely with any existing project or user hooks — including the kit's own hook entries.

## Policy DSL

The default policy ships at `plugins/safe-solana-ai/policy/default.policy.yaml`. Projects override it by placing a file at `<project>/.safe-solana-ai/policy.yaml`, which is deep-merged over the defaults.

**Top-level keys:**

| Key | Purpose |
|-----|---------|
| `version` | Schema version (currently `1`) |
| `network.default` | Assumed network when detection is ambiguous |
| `network.mainnet` | Decision for any mainnet-touching action (`ask` or `deny`) |
| `spend.per_tx_sol_max` | SOL per transaction above which → `ask` |
| `spend.hard_tx_sol_max` | SOL per transaction above which → `deny` |
| `spend.daily_sol_max` | Cumulative SOL today above which → `ask` |
| `gates` | Actions always requiring `ask` regardless of spend caps |
| `mcp.sensitive_name_pattern` | Regex matched against MCP tool names to trigger inspection |
| `swap.rugcheck` | Enable rugcheck.xyz mint risk check |
| `swap.rugcheck_max_score` | Score above which → `deny` |
| `swap.rugcheck_timeout_ms` | On timeout or API unavailability → `ask` (never hard-block) |
| `swap.trusted_mints` | Mints that skip rugcheck (SOL, USDC by default) |
| `secrets.deny_read_globs` | Path globs that `gate-read` and `gate-bash-secrets` deny |
| `secrets.allow_read_globs` | Exceptions to the deny list (e.g. `.env.example`) |
| `redact.enabled` | Enable PostToolUse secret redaction |
| `audit.enabled` | Enable append-only audit log |
| `supply_chain.verify_skills_dirs` | Directories scanned at SessionStart |
| `supply_chain.flag_unpinned_mcp` | Informational: flag `@latest` MCP entries (does not auto-pin) |
| `supply_chain.flag_telemetry_curl` | Flag Convex-pattern telemetry in scanned content |
| `catalog.high_risk_classes` | Risk classes requiring explicit policy approval (`wallet_signing`, `key_custody`) |
| `catalog.denied_classes` | Risk classes blocked regardless of approval (`installer_script` by default in `paranoid` profile) |
| `ext.pin_on_first_seen` | TOFU pin each `ext/` submodule git SHA on first session |
| `ext.quarantine_on_drift` | Quarantine submodules whose SHA changed since last pin |
| `exec_install_scripts` | `allow`, `ask`, or `deny` for `curl|bash`/`wget|bash` patterns |

**Fail-closed.** If `policy.yaml` cannot be parsed, `policy.rs` falls back to a minimal safe configuration: all gated actions become `ask`. The session is never left without a gate because of a config error.

## Profiles and time-boxed grants

**Profiles** are named presets that adjust the policy's soft thresholds before gate evaluation. The active profile is set via `ssai mode <profile>` and applied in `policy.effective()`.

| Profile | Behavior |
|---------|----------|
| `strict` | Default. All gates active. Spend caps at policy values. `exec_install_scripts: ask`. |
| `autopilot` | Raises spend caps; reduces `ask` to `allow` for routine devnet operations. Hard guards remain. |
| `paranoid` | Lowers spend caps; all transfers require `ask`; `exec_install_scripts: deny`; `installer_script` catalog class denied. |
| `off` | Disables soft gates entirely. Hard guards remain and cannot be disabled. |

**Time-boxed grants** allow specific soft-gate relaxations for a bounded scope and duration, applied in `relax::apply` after `policy.effective()`. Grants are created with `ssai allow` and revoked with `ssai revoke`.

Hard guards (`mainnet_deploy`, `set_authority`, `account_close`, `secret_read`) are not affected by profiles or grants. The engine enforces this unconditionally.

## Gate pipeline

Step-by-step for `gate-bash` (the most complex gate; others follow a subset of these steps):

1. **Decode** — parse hook JSON from stdin; extract tool name, command string, and session context.
2. **Tokenize** — split command on `&&`, `;`, and `|` into segments. Each segment is gated independently. If any segment would be denied or asked, the whole pipeline gets the most restrictive decision.
3. **Classify** — categorize each segment:
   - `transfer`: `solana transfer`, `spl-token transfer`
   - `deploy`: `solana program deploy|write-buffer|upgrade`, `anchor deploy|upgrade|migrate`
   - `authority`: `solana program set-upgrade-authority`, `spl-token authorize`
   - `destructive`: `solana close`, `spl-token burn|close`
   - `install_script`: `curl|bash`, `wget|bash`, `curl|sh` patterns
   - `readonly`: everything else → fast-allow
4. **Network resolve** via `context.rs`: check env flags first, then `Anchor.toml` provider, then run `solana config get` (result cached for 60s to avoid repeated spawns on rapid commands).
5. **Apply policy** via `policy.effective()` (profile applied): mainnet + deploy/authority/destructive → `ask` with reason; transfer amount → spend-ledger check → allow/ask/deny based on caps; `install_script` → `exec_install_scripts` policy value.
6. **Relax** via `relax::apply`: check for active time-boxed grants that cover this action; apply if present. Hard guards pass through unchanged.
7. **Audit** — append decision record to `${CLAUDE_PLUGIN_DATA}/audit.jsonl`.
8. **Emit** — write `hookSpecificOutput.permissionDecision` + `permissionDecisionReason` JSON to stdout via `io.rs`.

## `${CLAUDE_PLUGIN_DATA}` state layout

`${CLAUDE_PLUGIN_DATA}` is the per-plugin data directory provided by Claude Code at runtime (not `${CLAUDE_PLUGIN_ROOT}`, which is the install location).

```
${CLAUDE_PLUGIN_DATA}/
├── audit.jsonl          # append-only gate decision log (one JSON object per line)
├── lockfile.json        # TOFU pins: skill dir sha256 trees + ext/ submodule git SHAs + MCP pkg@version+shasum
├── spend.json           # daily SOL spend ledger; resets at UTC midnight
├── grants.json          # active time-boxed grant records (written by ssai allow)
├── session/             # ephemeral keypair files; mode 0600
│   └── <id>.json
└── quarantine/          # drifted or unverified skill dirs and ext/ submodules moved here at SessionStart
    └── <skill-name>/
```

**`lockfile.json` structure:** keyed by skill dir path, `ext/<submodule-name>`, or MCP package ID. Values include:

| Field | Content |
|-------|---------|
| `sha256` | sha256 of sorted file tree (skill dirs and non-git content) |
| `git_sha` | git commit SHA (for `ext/` submodules pinned by git ref) |
| `pinned_at` | ISO 8601 timestamp of first-seen pin |
| `source` | GitHub commit SHA, npm `pkg@version`, or `ext/<name>@<sha>` |
| `shasum` | npm `dist.shasum` where applicable |
| `risk_class` | catalog risk class if installed via registry |

**`audit.jsonl` record fields:** `ts` (ISO 8601), `hook` (e.g. `gate-bash`), `decision` (`allow`/`ask`/`deny`), `reason` (string), `tool` (tool name), `input` (sanitized command or MCP tool name), `network` (resolved network), `profile`, `grant`.
