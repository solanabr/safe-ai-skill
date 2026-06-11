# Usage

## Command reference

The `safe-solana-ai` CLI and its `ssai` alias are the same binary. `ssai` is used where brevity matters (hook invocations, session commands); `safe-solana-ai` is the canonical user-facing form.

---

### `safe-solana-ai add skill <name|url>`

Fetch a skill and run the intrinsic verification pipeline before installing it.

`<name>` resolves against the solana-new catalog (`~/.superstack/` if present). `<url>` accepts any GitHub URL or `github:<owner>/<repo>` shorthand. Moving refs (`main`, `HEAD`, branch names) are resolved to a commit SHA before fetch; the SHA is what gets pinned.

**Pipeline steps:** static heuristics scan → provenance pin to commit SHA → osv.dev CVE check for any npm deps declared in the skill → TOFU lockfile entry. On high-severity heuristic match or known CVE, the install is refused and the reason is printed. On medium findings, a diff is shown and approval is requested. On clean, the skill is installed and pinned.

```bash
# Install from solana-new catalog by name
safe-solana-ai add skill scaffold-project

# Install from an arbitrary GitHub URL
safe-solana-ai add skill https://github.com/example/my-solana-skill

# Install from a specific commit (already immutable — no resolution needed)
safe-solana-ai add skill github:example/my-solana-skill@abc1234
```

---

### `safe-solana-ai add mcp <id|pkg|url>`

Resolve an MCP package to an exact version, verify it, pin it, and write the entry to `.mcp.json`.

`<id>` resolves against the solana-new MCP catalog. `<pkg>` is an npm package name (optionally `@version`). `<url>` accepts a GitHub URL. Packages specified as `@latest` or without a version are resolved to the current latest version at fetch time; the pinned exact version is written to `.mcp.json`, not `@latest`.

**Pipeline steps:** resolve to `pkg@x.y.z` + record `dist.shasum`/integrity → flag if package is very new, very low-download, or typosquat-similar to a popular name → osv.dev CVE check for `pkg@x.y.z` → TOFU lockfile entry with shasum. The `setup_command` from the catalog entry is inspected by `heuristics.rs` before execution.

```bash
# Install by solana-new catalog ID
safe-solana-ai add mcp helius

# Install by npm package name (resolves to exact version)
safe-solana-ai add mcp @modelcontextprotocol/server-filesystem

# Install a specific version (skips resolution, still verified)
safe-solana-ai add mcp @modelcontextprotocol/server-filesystem@1.2.3
```

---

### `safe-solana-ai add repo <url>`

Clone a repository, pin it to a commit SHA, and record it in the lockfile.

Moving refs are rejected with an error — you must supply either a full commit SHA in the URL fragment or use `@<sha>` syntax. This enforces that the content you verified is the content that runs.

```bash
# Rejected — moving ref
safe-solana-ai add repo https://github.com/example/tools

# Accepted — pinned to commit SHA
safe-solana-ai add repo https://github.com/example/tools@a3f9c12

# Also accepted — fragment syntax
safe-solana-ai add repo https://github.com/example/tools#a3f9c12de4b5f6789012345678901234567890ab
```

---

### `safe-solana-ai bootstrap`

The secure drop-in for `curl solana.new/setup.sh | bash`.

Downloads solana-new's skills tarball and the three catalog JSONs (`solana-skills.json`, `solana-mcps.json`, `clonable-repos.json`). Runs the full verification pipeline on every SKILL.md and every `setup_command`/`clone_command` entry. Neutralizes the telemetry preamble in each SKILL.md (sets `telemetryTier=off`, removes or no-ops the Convex `curl` call). Pins every MCP to an exact version. Shows a diff of flagged content for approval before writing anything to disk. Does not auto-widen `~/.claude/settings.json` permissions.

```bash
safe-solana-ai bootstrap

# Output:
# Fetching solana-new tarball...
# Scanning 80 skills... 3 flagged
#   WARN scaffold-project: telemetry preamble (neutralized)
#   WARN colosseum-copilot: reads ~/.superstack/config.json (JWT present)
#   HIGH custom-skill: base58 key in SKILL.md preamble (install refused)
# Scanning 41 MCPs...
#   WARN helius: pinned @latest -> 3.2.1
#   WARN solana-dev: pinned @latest -> 1.0.4
# Proceed with install? [y/N]
```

---

### `safe-solana-ai verify`

On-demand audit of everything already installed.

Re-hashes all pinned skill directories against `lockfile.json`. Re-checks all pinned MCP entries for CVEs (re-querying osv.dev for any that have not been checked within the last 24 hours). Flags any `@latest` MCP entries in `.mcp.json` that were not installed via `safe-solana-ai add`. Reports findings without modifying anything; use `ssai verify approve <name>` to re-pin after reviewing a change.

```bash
safe-solana-ai verify

# Output:
# Skills:
#   OK   scaffold-project  (sha256 matches)
#   WARN anchor-specialist (drift detected — hash changed since last pin)
#   OK   colosseum-copilot
# MCPs:
#   OK   @helius-labs/helius-mcp@3.2.1
#   WARN @modelcontextprotocol/server-filesystem (unpinned @latest)
# Run 'ssai verify approve <name>' to re-pin after review.
```

---

### `safe-solana-ai status`

Show the current state of pins, quarantine, active profile, live grants, spend today, and recent gate decisions.

```bash
safe-solana-ai status

# Output:
# Profile: strict
# Active grants: none
# Spend today: 0.3 SOL / 5.0 SOL daily cap
#
# Pinned skills (12):    all OK
# Pinned MCPs (6):       all OK
# Quarantined (0):       none
#
# Recent decisions (last 10):
#   allow  gate-bash    solana transfer ABC... 0.1  devnet
#   ask    gate-bash    anchor deploy          mainnet
#   deny   gate-read    ~/.config/solana/id.json
```

---

### `ssai mode <profile>`

Set the active policy profile. The profile adjusts soft-gate thresholds in `policy.effective()` before gate evaluation. Persists across sessions.

| Profile | Effect |
|---------|--------|
| `strict` | Default. All gates active at policy values. |
| `autopilot` | Raises spend caps; devnet routine operations become `allow`. Hard guards unchanged. |
| `paranoid` | Lowers spend caps; all transfers require `ask` regardless of amount. |
| `off` | Disables all soft gates. Hard guards unchanged and cannot be disabled. |

Hard guards (`mainnet_deploy`, `set_authority`, `account_close`, `secret_read`) are not modified by any profile. The engine enforces this unconditionally.

```bash
ssai mode autopilot   # raise caps for a high-frequency devnet session
ssai mode strict      # restore defaults
ssai mode off         # disable soft gates (hard guards remain)
```

---

### `ssai allow`

Create a time-boxed grant that relaxes one or more soft gates for a specific scope and duration. Grants are applied in `relax::apply` after `policy.effective()`. Hard guards are not relaxable by any grant.

**Flags:**

| Flag | Description |
|------|-------------|
| `--scope` | Gate or action scope to relax (e.g. `mainnet_transfer`, `devnet_deploy`) |
| `--for` | Duration (e.g. `30m`, `2h`, `1d`) |
| `--max-tx <SOL>` | Override `per_tx_sol_max` for this grant |
| `--budget <SOL>` | Override `daily_sol_max` for this grant |
| `--programs <id,...>` | Restrict grant to specific program IDs |
| `--to <addr,...>` | Restrict grant to specific destination addresses |

```bash
# Allow mainnet transfers up to 2 SOL for the next 30 minutes
ssai allow --scope mainnet_transfer --for 30m --max-tx 2.0

# Allow devnet deploys to a specific program for 2 hours
ssai allow --scope devnet_deploy --for 2h --programs TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA

# Allow transfers to a specific address up to a 5 SOL budget today
ssai allow --scope mainnet_transfer --for 8h --to 9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM --budget 5.0
```

Grants are stored in `${CLAUDE_PLUGIN_DATA}/grants.json` and expire automatically. `ssai status` shows all active grants with remaining time.

---

### `ssai revoke`

Revoke a time-boxed grant before it expires. Lists active grants if called without arguments.

```bash
# List active grants
ssai revoke

# Revoke by grant ID (shown in ssai status output)
ssai revoke grant_a1b2c3

# Revoke all active grants
ssai revoke --all
```

---

### `ssai session init --cap <SOL>`

Generate an ephemeral Ed25519 keypair, fund it from the master wallet with a SOL cap, and export it for the current session (Phase 3).

The funding transaction itself is routed through the Phase 1 gate — it requires approval as a mainnet transfer. The keypair is written mode 0600 to `${CLAUDE_PLUGIN_DATA}/session/<id>.json`. The path is exported via `$CLAUDE_ENV_FILE` so skills that reference `$SOLANA_KEYPAIR` or the default Solana CLI config pick it up automatically. The master key remains read-denied throughout.

The session keypair caps agent spending by construction: an agent can spend at most what is in the session keypair's balance. Any over-cap attempts are blocked by the Phase 1 transfer gate on the session balance, not by policy alone.

```bash
ssai session init --cap 0.5

# Output:
# Session keypair: ${CLAUDE_PLUGIN_DATA}/session/sess_a1b2c3.json
# Funded: 0.5 SOL from master wallet
# Export: SOLANA_KEYPAIR set for this session
# Master key: read-denied
```

---

### `ssai session status`

Show the current session keypair ID, current balance, and remaining cap.

```bash
ssai session status

# Output:
# Session ID:  sess_a1b2c3
# Balance:     0.42 SOL
# Cap:         0.50 SOL
# Spent today: 0.08 SOL
# Expires:     end of session
```

---

### `ssai verify approve <name>`

Restore a quarantined skill or re-pin a skill whose content has drifted. After restoring, the new content hash is recorded in the lockfile.

```bash
# List what is quarantined
ssai verify approve

# Restore and re-pin a specific skill
ssai verify approve anchor-specialist
```

---

## Policy override

Place a file at `<project>/.safe-solana-ai/policy.yaml` to override the defaults for that project. The file is deep-merged over the defaults: only keys present in the override file take effect; all other defaults remain. Array values in override files replace (not extend) the corresponding default arrays.

```yaml
# <project>/.safe-solana-ai/policy.yaml
# Only the keys you specify here override the defaults.

version: 1

# Raise spend caps for a trading bot that moves larger amounts on devnet
spend:
  per_tx_sol_max: 5.0       # default: 1.0
  hard_tx_sol_max: 50.0     # default: 10.0
  daily_sol_max: 20.0       # default: 5.0

# Add project-specific secret paths to the deny list.
# This REPLACES the default deny_read_globs array — include any defaults you want to keep.
secrets:
  deny_read_globs:
    - "**/*-keypair.json"
    - "**/id.json"
    - "**/.env"
    - "**/.env.*"
    - "**/*.pem"
    - "~/.config/solana/**"
    - "~/.superstack/config.json"
    - "**/secrets/**"         # project-specific addition
    - "**/.api-keys"          # project-specific addition

# Disable rugcheck for this project (using only curated, known-good mints)
swap:
  rugcheck: false

# Override the supply chain scan directories
supply_chain:
  verify_skills_dirs:
    - "~/.claude/skills"
    - ".claude/skills"
    - "./project-skills"    # project-local skills directory
```

**What cannot be overridden.** The hard guards (`mainnet_deploy`, `set_authority`, `account_close`, `secret_read`) are enforced by the engine and are not present in the policy DSL. They cannot be removed, relaxed by a profile, or overridden by a project policy file. There is no `--danger` flag in v1 that affects them.

**Fail-closed.** If `policy.yaml` has a parse error, the engine falls back to treating all gated actions as `ask`. The session continues with a warning; it is never left unprotected because of a config file error.

## Gate behavior: what you will see

These are the literal interactions a user will encounter for the most common gated actions.

---

**Mainnet deploy**

Triggered by `anchor deploy`, `solana program deploy`, `solana program upgrade`, or any equivalent with a mainnet RPC URL resolved by `context.rs`.

Claude Code surfaces an `ask` prompt:

```
safe-solana-ai: MAINNET DEPLOY — approve to proceed?
Command: anchor deploy --provider.cluster mainnet-beta
Program: target/deploy/my_program.so
```

Approving allows the command to run. Denying blocks it. The decision is recorded in `audit.jsonl`. This replaces the defunct `read -r` gate that was in the prior hook configuration and never fired due to the no-TTY constraint.

---

**Over-cap transfer**

Triggered by `solana transfer <addr> 5` when `per_tx_sol_max` is `1.0`.

```
safe-solana-ai: Transfer of 5.0 SOL exceeds per-transaction cap (1.0 SOL). Approve?
Command: solana transfer 9WzDXwBb... 5
Network: devnet
Daily spent: 0.3 SOL / 5.0 SOL cap
```

---

**Keypair or secret file read**

Triggered by `Read ~/.config/solana/id.json`, `Read .env`, `cat ~/.config/solana/id.json` (caught by `gate-bash-secrets`), or any path matching `secrets.deny_read_globs`.

```
safe-solana-ai: Read denied
Path: ~/.config/solana/id.json
Reason: matches secret glob ~/.config/solana/**
```

This is a `deny`, not an `ask`. It is a hard guard. It holds even with `bypassPermissions` active. There is no approval path.

---

**Bad-mint swap (rugcheck)**

Triggered by an MCP swap call where the input mint's rugcheck.xyz score exceeds `rugcheck_max_score` (default: 40).

```
safe-solana-ai: Swap denied
Mint: Hf...xQ (score 87/100)
Risks: ["Mutable metadata", "No liquidity", "Creator holds 94%"]
```

If the rugcheck API is unavailable or times out (default 3000ms):

```
safe-solana-ai: Rugcheck unavailable — approve swap manually?
Mint: Hf...xQ
Rugcheck: timed out after 3000ms
```

Timeout always produces `ask`, never `deny` (to avoid blocking the session on third-party uptime) and never `allow` (to avoid silent bypass of risk checks).

---

**solana-new telemetry curl**

Triggered when a skill's Bash call matches the Convex exfiltration pattern: `curl -s -X POST <convex-url>/api/mutation ...`.

```
safe-solana-ai: Outbound POST denied
Command: curl -s -X POST https://...convex.cloud/api/mutation ...
Reason: matches telemetry/exfiltration endpoint pattern (gate-bash-secrets)
```

This is caught by `gate-bash-secrets` (unconditional, no `if` required) before the curl executes. The solana-new skill's telemetry preamble fires this pattern on every skill invocation.

---

## Supply-chain warnings at SessionStart

When `verify session` quarantines content, Claude Code's `additionalContext` mechanism injects a warning at the top of the session:

```
[safe-solana-ai] Supply-chain warning — 1 skill quarantined:
  anchor-specialist: content hash changed since last pin
  Last pinned: 2026-06-08T14:23:11Z
  Quarantine path: ${CLAUDE_PLUGIN_DATA}/quarantine/anchor-specialist/

To review and restore:
  safe-solana-ai verify           # see what changed
  ssai verify approve anchor-specialist   # re-pin after review
```

Run `safe-solana-ai status` to see the full quarantine list and all flagged findings from the current session's scan.

## Audit log

Every gate decision is appended to `${CLAUDE_PLUGIN_DATA}/audit.jsonl`. Each line is a standalone JSON object:

```jsonc
{
  "ts": "2026-06-11T09:14:32.441Z",
  "hook": "gate-bash",
  "decision": "ask",
  "reason": "MAINNET DEPLOY",
  "tool": "Bash",
  "input": "anchor deploy --provider.cluster mainnet-beta",
  "network": "mainnet-beta",
  "profile": "strict",
  "grant": null
}
```

Fields:

| Field | Description |
|-------|-------------|
| `ts` | ISO 8601 UTC timestamp |
| `hook` | Which gate produced the decision |
| `decision` | `allow`, `ask`, or `deny` |
| `reason` | Human-readable reason string |
| `tool` | Claude Code tool name (`Bash`, `Read`, `mcp__helius__transferSol`, etc.) |
| `input` | Sanitized command or MCP tool name (secrets are not logged) |
| `network` | Resolved network (`devnet`, `mainnet-beta`, `localnet`, `unknown`) |
| `profile` | Active profile at time of decision |
| `grant` | Grant ID if a time-boxed grant was applied, otherwise `null` |

The file is append-only. It is not rotated automatically in v1; trim it manually if it grows large.
