# Architecture

## Engine

The core of safe-solana-ai is `ssai`, a single static Rust binary. The user-facing CLI command `safe-solana-ai` is the same binary (symlink or alias); `ssai` is the terse name used on the hot path.

**Why Rust.** PreToolUse fires on every Bash, Read, Grep, Glob, and MCP tool call — hundreds of invocations per session. Rust runs the gate logic in ~2–5ms; a Node.js spawn costs ~40–80ms. More importantly, a gate that requires a runtime (Node, Python) fails open if that runtime is absent. `ssai` has no runtime dependency. Phases 2 and 3 of the roadmap (sha256 dir-tree hashing, programdata account inspection, future Lighthouse tx construction) are Rust-native. The binary is auditable as a single artifact. The CLI contract — stdin JSON in, stdout JSON out — is language-agnostic, so the language choice does not ripple into hook wiring or tooling.

**Crate dependencies** are intentionally minimal: `serde`/`serde_json`, `serde_yaml`, `sha2`, `ureq`, `glob`. No tokio. All I/O is synchronous; the 10–60s hook timeouts are more than sufficient.

**Source layout** (in `crates/engine/src/`):

| File | Responsibility |
|------|---------------|
| `main.rs` | Subcommand dispatch |
| `io.rs` | Hook JSON parse; decision emitters (`deny`/`ask`/`allow`/`defer` + reason); exit codes |
| `policy.rs` | YAML load + deep-merge (defaults then project override); `policy.effective()` applies active profile; fails closed on parse error |
| `context.rs` | Network detection: env flags → Anchor.toml → cached `solana config get` (60s cache) |
| `gates/bash.rs` | Tokenize → classify → network resolve → policy → decide |
| `gates/mcp.rs` | MCP tool name + payload inspection; rugcheck swap gate |
| `gates/read.rs` | Secret-glob deny for Read/Grep/Glob |
| `redact.rs` | Secret patterns → `updatedToolOutput` / `updatedMCPToolOutput` |
| `spend.rs` | Daily spend ledger: `${CLAUDE_PLUGIN_DATA}/spend.json` |
| `audit.rs` | Append-only JSONL: `${CLAUDE_PLUGIN_DATA}/audit.jsonl` |
| `lockfile.rs` | sha256 dir-tree hashing; `${CLAUDE_PLUGIN_DATA}/lockfile.json`; quarantine logic |
| `heuristics.rs` | Skill/MCP static scan (telemetry curl, keypair refs, injection patterns, unpinned npx) |
| `verify.rs` | Intrinsic pipeline orchestrator: heuristics + provenance + osv.dev + TOFU |
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

`gate-bash-secrets` does pure string checks in microseconds: `cat ~/.config/solana/id.json`, `cat .env`, base64/exfil of keypair files, and outbound `curl -X POST` to Convex-pattern endpoints (the solana-new telemetry pattern). It does not need to parse the full command; matching any of these patterns is sufficient for a `deny`.

**Read/Grep/Glob — secret file gate**

```
gate-read   matcher: "Read|Grep|Glob"   timeout: 10s
```

Checks the path argument against `secrets.deny_read_globs` in policy. Matches are `deny`; `allow_read_globs` entries (e.g. `.env.example`) are allowed explicitly before the deny list is checked.

**MCP — value-moving tool gate**

```
gate-mcp   matcher: "mcp__.*"   timeout: 15s
```

Fast-allows any MCP tool whose name does not match the sensitive name pattern (`transfer|sign|swap|send|withdraw|burn|pay|upgrade`). For sensitive names, inspects the payload (amounts, destination addresses, mint addresses) and applies policy. Delegates mint risk to `rugcheck.rs` for swap calls (Phase 2).

### PostToolUse

```
redact   matcher: "Bash|Read|Grep"   timeout: 10s
```

Scans tool output for secret patterns: 64-byte base58 private keys, JSON keypair arrays (`[n, n, n, ...]` of length 64), BIP39 seed phrases, and API key patterns. Replaces matches in `updatedToolOutput` / `updatedMCPToolOutput`. Runs after the tool completes, so it is a defense-in-depth measure — the PreToolUse `gate-read` and `gate-bash-secrets` prevent most secret exposure before it reaches output.

### UserPromptSubmit

```
prompt-guard   timeout: 10s
```

Scans the user's prompt text for raw private keys or seed phrases. Claude Code does not support rewriting user prompts, so the only available response to a match is a block with a reason message. The user is shown the reason and can resubmit without the secret material.

### SessionStart

```
verify session   matcher: "startup|resume"   timeout: 60s
```

Runs the supply-chain audit on every session start and resume. Scans `~/.claude/skills/**` and `.claude/skills/**` (configurable via `supply_chain.verify_skills_dirs`), and all MCP server entries in `.claude/settings.json`. Checks each against the TOFU lockfile.

**SessionStart cannot block session startup.** This is a verified constraint of the Claude Code hook system. The response mechanism is:

1. Drifted or unverified skill directories are moved to `${CLAUDE_PLUGIN_DATA}/quarantine/<name>`.
2. `additionalContext` is injected into the session with a warning listing what was quarantined and why.
3. `reloadSkills: true` is emitted so Claude Code reloads the (now reduced) skill set.
4. The session starts normally with the quarantined content absent.
5. The user can inspect with `safe-solana-ai status` and restore with `ssai verify approve <name>`.

## Verified hook semantics

Three properties of the Claude Code hook system (verified against official 2026-06 docs, v2.1.139+) that are load-bearing for safe-solana-ai's guarantees:

**`deny` survives `bypassPermissions`.** A `permissionDecision: "deny"` response from a PreToolUse hook blocks the action even when the session is running with `bypassPermissions` (yolo mode). The hard guards (`mainnet_deploy`, `set_authority`, `account_close`, `secret_read`) use this and cannot be overridden by any profile, grant, or session flag.

**No TTY in hook context.** Since Claude Code v2.1.139+, hooks do not have a TTY attached. The prior approach of using `read -r` inside a hook for interactive confirmation is silently broken — it exits immediately, failing open. `ask` (`permissionDecision: "ask"`) is the correct mechanism: Claude Code surfaces an approval prompt to the user in the UI. This is what replaced the dead `when.command_matches` + `read -r` mainnet gate that existed in the repo's original `.claude/settings.json`.

**Hooks run in parallel; most-restrictive-wins.** When multiple hook entries match the same tool call, all run concurrently. The most restrictive response wins: `deny` > `ask` > `allow`. safe-solana-ai composes safely with any existing project or user hooks.

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
| `supply_chain.flag_unpinned_mcp` | Warn on `@latest` MCP entries |
| `supply_chain.flag_telemetry_curl` | Flag solana-new Convex preamble pattern |

**Fail-closed.** If `policy.yaml` cannot be parsed (YAML syntax error, unknown key with `deny_unknown_fields`), `policy.rs` falls back to a minimal safe configuration: all gated actions become `ask`. The session is never left without a gate because of a config error.

## Profiles and time-boxed grants

**Profiles** are named presets that adjust the policy's soft thresholds before gate evaluation. The active profile is set via `ssai mode <profile>` and applied in `policy.effective()`.

| Profile | Behavior |
|---------|----------|
| `strict` | Default. All gates active. Spend caps at policy values. |
| `autopilot` | Raises spend caps; reduces `ask` to `allow` for routine devnet operations. Hard guards remain. |
| `paranoid` | Lowers spend caps; adds `ask` for all transfers regardless of amount. |
| `off` | Disables soft gates entirely. Hard guards remain and cannot be disabled. |

**Time-boxed grants** allow specific soft-gate relaxations for a bounded scope and duration, applied in `relax::apply` after `policy.effective()`. Grants are created with `ssai allow` and revoked with `ssai revoke`.

Hard guards (`mainnet_deploy`, `set_authority`, `account_close`, `secret_read`) are not affected by profiles or grants. The engine returns them unchanged regardless of any relaxation. This is a hard guarantee, not a default.

## Gate pipeline

Step-by-step for `gate-bash` (the most complex gate; others follow a subset of these steps):

1. **Decode** — parse hook JSON from stdin; extract tool name, command string, and session context.
2. **Tokenize** — split command on `&&`, `;`, and `|` into segments. Each segment is gated independently. If any segment would be denied or asked, the whole pipeline gets the most restrictive decision.
3. **Classify** — categorize each segment:
   - `transfer`: `solana transfer`, `spl-token transfer`
   - `deploy`: `solana program deploy|write-buffer|upgrade`, `anchor deploy|upgrade|migrate`
   - `authority`: `solana program set-upgrade-authority`, `spl-token authorize`
   - `destructive`: `solana close`, `spl-token burn|close`
   - `readonly`: everything else → fast-allow
4. **Network resolve** via `context.rs`: check env flags first, then `Anchor.toml` provider, then run `solana config get` (result cached for 60s to avoid repeated spawns on rapid commands).
5. **Apply policy** via `policy.effective()` (profile applied): mainnet + deploy/authority/destructive → `ask` with reason; transfer amount → spend-ledger check → allow/ask/deny based on caps.
6. **Relax** via `relax::apply`: check for active time-boxed grants that cover this action; apply if present. Hard guards pass through unchanged.
7. **Audit** — append decision record to `${CLAUDE_PLUGIN_DATA}/audit.jsonl`.
8. **Emit** — write `hookSpecificOutput.permissionDecision` + `permissionDecisionReason` JSON to stdout via `io.rs`.

## `${CLAUDE_PLUGIN_DATA}` state layout

`${CLAUDE_PLUGIN_DATA}` is the per-plugin data directory provided by Claude Code at runtime (not `${CLAUDE_PLUGIN_ROOT}`, which is the install location).

```
${CLAUDE_PLUGIN_DATA}/
├── audit.jsonl          # append-only gate decision log (one JSON object per line)
├── lockfile.json        # TOFU pins: skill dir sha256 trees + MCP pkg@version+shasum
├── spend.json           # daily SOL spend ledger; resets at UTC midnight
├── grants.json          # active time-boxed grant records (written by ssai allow)
├── session/             # ephemeral keypair files; mode 0600
│   └── <id>.json
└── quarantine/          # drifted or unverified skill dirs moved here at SessionStart
    └── <skill-name>/
```

**`audit.jsonl` record fields:** `ts` (ISO 8601), `hook` (e.g. `gate-bash`), `decision` (`allow`/`ask`/`deny`), `reason` (string), `tool` (tool name), `input` (sanitized command or MCP tool name), `network` (resolved network).

**`lockfile.json` structure:** keyed by skill dir path or MCP package ID; values include `sha256` (of sorted file tree), `pinned_at` (timestamp), `source` (GitHub SHA or npm `pkg@version`), `shasum` (npm `dist.shasum` where applicable).
