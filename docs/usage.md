# Usage

## Command reference

The `safe-solana-ai` CLI and its `ssai` alias are the same binary. `ssai` is used where brevity matters (hook invocations, session commands); `safe-solana-ai` is the canonical user-facing form.

---

### `safe-solana-ai install`

Download and verified-install `solanabr/solana-ai-kit` into the project `.claude/` directory. This is the secure drop-in for `curl https://aikit.superteam.codes | bash`.

```bash
# Install solana-ai-kit from the default source
safe-solana-ai install

# Install from a specific source URL or GitHub ref
safe-solana-ai install --from https://github.com/solanabr/solana-ai-kit@a3c3d23

# Override the install destination (default: ./.claude)
safe-solana-ai install --home ~/.claude
```

**What install does, in order:**

1. Downloads the hub source (clone or tarball, depending on `--from`).
2. Runs `heuristics.rs` on every SKILL.md and catalog entry.
3. Walks all `ext/` submodules individually; pins each to its current git SHA in `lockfile.json`.
4. Parses `skill-registry.json` and flags any high-risk catalog entries.
5. Flags all `@latest` MCP entries in `.mcp.json` as INFORMATIONAL (LOW) — does not auto-rewrite.
6. Shows a diff of all flagged content.
7. Prompts for approval before writing anything to disk.
8. Does not auto-widen `~/.claude/settings.json` permissions.

```
# Example output
Fetching solanabr/solana-ai-kit@a3c3d23...
Scanning 15 agents... OK
Scanning 18 ext/ submodules...
  INFO  ext/solana-new:          git SHA a1b2c3d — telemetry preamble detected (neutralized)
  WARN  ext/ghostsecurity:       curl|bash installer in SKILL.md — HIGH
  OK    ext/jupiter:             pinned 4f9e2a1
  OK    ext/metaplex:            pinned 8c3b5d2
  [14 more OK]
Scanning skill-registry.json (39 entries)...
  HIGH  phantom-mcp:             class=wallet_signing — policy requires approval
  HIGH  x402-proxy-mcp:          class=key_custody — policy requires approval
  INFO  ghostsecurity:           class=installer_script — will gate at exec_install_scripts policy
Scanning .mcp.json (7 MCPs)...
  INFO  helius-mcp:              @latest (informational — use 'ssai pin-mcps' to pin)
  INFO  solana-dev:              @latest
  [5 more @latest]
Proceed with install? [y/N]
```

---

### `safe-solana-ai registry list`

List all entries in `skill-registry.json` with their risk classification and install status.

```bash
safe-solana-ai registry list

# Output:
# NAME                  CLASS             DEFAULT    INSTALLED  GATE
# anchor-specialist     standard          false      yes        standard
# phantom-mcp           wallet_signing    false      no         DENY (policy)
# x402-proxy-mcp        key_custody       false      no         DENY (policy)
# ghostsecurity         installer_script  false      no         ASK (exec_install_scripts)
# jupiter               standard          false      yes        standard
# [35 more entries]
```

**Flags:**

| Flag | Description |
|------|-------------|
| `--class <class>` | Filter by risk class (`standard`, `wallet_signing`, `key_custody`, `installer_script`) |
| `--installed` | Show only installed entries |
| `--high-risk` | Show only `wallet_signing` and `key_custody` entries |

---

### `safe-solana-ai registry verify`

Audit all installed registry entries against the pinned catalog state. Reports drift, missing pins, and entries installed outside the registry pipeline.

```bash
safe-solana-ai registry verify

# Output:
# Registry entries installed (6):
#   OK    anchor-specialist  git SHA 4f9e2a1 matches lockfile
#   OK    jupiter            git SHA 8c3b5d2 matches lockfile
#   WARN  colosseum-copilot  git SHA changed: 8c3b5d2 → c1d2e3f (quarantine? y/N)
# Entries installed outside registry (1):
#   WARN  custom-skill       not in registry; no catalog risk classification
```

---

### `safe-solana-ai add skill <name|url>`

Fetch a skill and run the intrinsic verification pipeline before installing it.

`<name>` resolves against the installed `skill-registry.json`. `<url>` accepts any GitHub URL or `github:<owner>/<repo>` shorthand. Moving refs (`main`, `HEAD`, branch names) are resolved to a commit SHA before fetch; the SHA is what gets pinned.

**High-risk entry gating.** If `<name>` resolves to a `wallet_signing` or `key_custody` catalog entry, ssai shows a risk summary and requires explicit confirmation — regardless of the general policy setting — before proceeding:

```
safe-solana-ai add skill phantom-mcp

# Output:
# RISK: phantom-mcp is class=wallet_signing
# This skill requests signing permissions over arbitrary transactions via Phantom wallet.
# Approving allows the agent to initiate wallet signing requests without further confirmation.
# Policy: DENY (catalog.high_risk_classes includes wallet_signing)
# To allow, update .safe-solana-ai/policy.yaml:
#   catalog:
#     high_risk_classes: []   # or remove wallet_signing from the list
# Install refused.
```

**Pipeline steps:** static heuristics scan → risk-class check → provenance pin to commit SHA → osv.dev CVE check → TOFU lockfile entry. On high-severity match or known CVE, install is refused. On medium findings, a diff is shown and approval is requested. On clean, the skill is installed and pinned.

```bash
# Install from the registry by name
safe-solana-ai add skill anchor-specialist

# Install from an arbitrary GitHub URL
safe-solana-ai add skill https://github.com/example/my-solana-skill

# Install from a specific commit (already immutable)
safe-solana-ai add skill github:example/my-solana-skill@abc1234
```

---

### `safe-solana-ai add mcp <id|pkg|url>`

Resolve an MCP package to an exact version, verify it, pin it, and write the entry to `.mcp.json`.

`<id>` resolves against the installed `skill-registry.json` MCP catalog. `<pkg>` is an npm package name (optionally `@version`). Packages specified as `@latest` or without a version are resolved to the current latest version at fetch time; the pinned exact version is written to `.mcp.json`, not `@latest`.

`@latest` entries already in `.mcp.json` (from a kit install) are **not** auto-rewritten. ssai flags them as INFORMATIONAL and offers `ssai pin-mcps` as an opt-in rewrite.

**High-risk MCP gating.** If `<id>` resolves to a `wallet_signing` or `key_custody` catalog entry, the same risk-summary gate applies as for `add skill`:

```
safe-solana-ai add mcp x402-proxy-mcp

# Output:
# RISK: x402-proxy-mcp is class=key_custody
# This MCP holds BIP-39 key custody for x402 payment channel operations.
# Approving grants the MCP access to derive and store payment keys.
# Policy: DENY (catalog.high_risk_classes includes key_custody)
# Install refused.
```

```bash
# Install by registry ID (verifies and pins to exact version)
safe-solana-ai add mcp helius

# Install by npm package name (resolves to exact version)
safe-solana-ai add mcp @modelcontextprotocol/server-filesystem

# Install a specific version (still fully verified)
safe-solana-ai add mcp @modelcontextprotocol/server-filesystem@1.2.3
```

---

### `safe-solana-ai add repo <url>`

Clone a repository, pin it to a commit SHA, and record it in the lockfile.

Moving refs are rejected — you must supply either a full commit SHA in the URL fragment or use `@<sha>` syntax.

```bash
# Rejected — moving ref
safe-solana-ai add repo https://github.com/example/tools

# Accepted — pinned to commit SHA
safe-solana-ai add repo https://github.com/example/tools@a3f9c12

# Also accepted — fragment syntax
safe-solana-ai add repo https://github.com/example/tools#a3f9c12de4b5f6789012345678901234567890ab
```

---

### `safe-solana-ai verify`

On-demand audit of everything already installed.

Re-hashes all pinned skill directories against `lockfile.json`. Re-checks all pinned `ext/` submodule git SHAs against their current state. Re-checks all pinned MCP entries for CVEs (re-querying osv.dev for any not checked within the last 24 hours). Flags any `@latest` MCP entries in `.mcp.json` that were not installed via `safe-solana-ai add`. Reports findings without modifying anything.

```bash
safe-solana-ai verify

# Output:
# ext/ submodules (18):
#   OK   ext/jupiter            git SHA 4f9e2a1 matches lockfile
#   OK   ext/metaplex           git SHA 8c3b5d2 matches lockfile
#   WARN ext/solana-new         git SHA changed: a1b2c3d → d4e5f6g
#   [15 more OK]
# Skills (3 installed outside ext/):
#   OK   anchor-specialist  (sha256 matches)
#   WARN custom-skill       (drift — hash changed since last pin)
# MCPs:
#   INFO @helius-labs/helius-mcp  @latest (informational; use 'ssai pin-mcps' to pin)
#   OK   @modelcontextprotocol/server-filesystem@1.2.3
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
# ext/ submodules (18):  17 OK, 1 quarantined
# Pinned skills (3):     all OK
# Pinned MCPs (7):       7 @latest (informational)
# Quarantined (1):       ext/solana-new (SHA drift)
#
# Recent decisions (last 10):
#   allow  gate-bash    solana transfer ABC... 0.1  devnet
#   ask    gate-bash    anchor deploy          mainnet
#   deny   gate-read    ~/.config/solana/id.json
#   ask    gate-mcp     mcp__helius__heliusWrite.sendSol
```

---

### `ssai mode <profile>`

Set the active policy profile. Persists across sessions.

| Profile | Effect |
|---------|--------|
| `strict` | Default. All gates active at policy values. `exec_install_scripts: ask`. |
| `autopilot` | Raises spend caps; devnet routine operations become `allow`. Hard guards unchanged. |
| `paranoid` | Lowers spend caps; all transfers require `ask`; `exec_install_scripts: deny`; `installer_script` catalog class denied. |
| `off` | Disables all soft gates. Hard guards unchanged and cannot be disabled. |

Hard guards (`mainnet_deploy`, `set_authority`, `account_close`, `secret_read`) are not modified by any profile.

```bash
ssai mode autopilot   # raise caps for a high-frequency devnet session
ssai mode strict      # restore defaults
ssai mode off         # disable soft gates (hard guards remain)
```

---

### `ssai allow`

Create a time-boxed grant that relaxes one or more soft gates for a specific scope and duration. Hard guards are not relaxable by any grant.

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

Generate an ephemeral Ed25519 keypair, fund it from the master wallet with a SOL cap, and export it for the current session.

The funding transaction is routed through the Phase 1 gate — it requires approval as a mainnet transfer. The keypair is written mode 0600 to `${CLAUDE_PLUGIN_DATA}/session/<id>.json`. The path is exported via `$CLAUDE_ENV_FILE` so skills that reference `$SOLANA_KEYPAIR` pick it up automatically. The master key remains read-denied throughout.

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

Show the current session keypair ID, balance, and remaining cap.

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

Restore a quarantined skill or `ext/` submodule, or re-pin content whose hash drifted. After restoring, the new content hash or git SHA is recorded in the lockfile.

```bash
# List what is quarantined
ssai verify approve

# Restore and re-pin a specific ext/ submodule after reviewing the diff
ssai verify approve ext/solana-new

# Restore a skill dir
ssai verify approve anchor-specialist
```

---

## Policy override

Place a file at `<project>/.safe-solana-ai/policy.yaml` to override the defaults for that project. The file is deep-merged over the defaults: only keys present in the override file take effect. Array values replace (not extend) the corresponding default arrays.

```yaml
# <project>/.safe-solana-ai/policy.yaml

version: 1

# Raise spend caps for a trading bot on devnet
spend:
  per_tx_sol_max: 5.0       # default: 1.0
  hard_tx_sol_max: 50.0     # default: 10.0
  daily_sol_max: 20.0       # default: 5.0

# Add project-specific secret paths.
# This REPLACES the default deny_read_globs array.
secrets:
  deny_read_globs:
    - "**/*-keypair.json"
    - "**/id.json"
    - "**/.env"
    - "**/.env.*"
    - "**/*.pem"
    - "~/.config/solana/**"
    - "**/secrets/**"
    - "**/.api-keys"

# Allow install-script execution in this project (not recommended globally)
exec_install_scripts: ask   # default: ask; options: allow | ask | deny

# Catalog risk class gates for this project
catalog:
  # Remove key_custody from the denied set to allow x402-proxy-mcp (use carefully)
  high_risk_classes:
    - wallet_signing
  denied_classes: []

# Per-ext-submodule supply chain settings
ext:
  pin_on_first_seen: true
  quarantine_on_drift: true

# Disable rugcheck for this project (using only curated, known-good mints)
swap:
  rugcheck: false

# Override the supply chain scan directories
supply_chain:
  verify_skills_dirs:
    - "~/.claude/skills"
    - ".claude/skills"
    - "./project-skills"
```

**What cannot be overridden.** The hard guards (`mainnet_deploy`, `set_authority`, `account_close`, `secret_read`) are enforced by the engine and are not present in the policy DSL. There is no `--danger` flag in v1 that affects them.

**Fail-closed.** If `policy.yaml` has a parse error, the engine falls back to treating all gated actions as `ask`. The session is never left unprotected because of a config error.

---

## Gate behavior: what you will see

These are the literal interactions a user encounters for the most common gated actions.

---

**Mainnet deploy**

Triggered by `anchor deploy`, `solana program deploy`, `solana program upgrade`, or any equivalent with a mainnet RPC URL resolved by `context.rs`.

```
safe-solana-ai: MAINNET DEPLOY — approve to proceed?
Command: anchor deploy --provider.cluster mainnet-beta
Program: target/deploy/my_program.so
```

This replaces the kit's broken `read -r` gate, which exits immediately in hook context (no TTY) and always fails open.

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

**Value-moving MCP call**

Triggered by `mcp__helius__heliusWrite.sendSol`, `mcp__helius__heliusWrite.stakeSOL`, or any tool name matching `send|stake|delegate|mint|bridge|lend|borrow`.

```
safe-solana-ai: MCP value-moving call — approve?
Tool: mcp__helius__heliusWrite.sendSol
Payload: { "to": "9WzDXwBb...", "amount": 1.0 }
Network: mainnet-beta
```

---

**High-risk catalog entry execution**

Triggered when the agent invokes a tool from a `wallet_signing` MCP entry that was approved at install time but gated at runtime.

```
safe-solana-ai: HIGH-RISK MCP — wallet_signing class. Approve?
Tool: mcp__phantom__signTransaction
Entry: phantom-mcp (class=wallet_signing, approved at install)
This action requests Phantom wallet to sign a transaction.
```

---

**`curl|bash` install script**

Triggered by `curl https://example.com/install.sh | bash` or equivalent (caught by `gate-bash-secrets`, unconditional).

```
safe-solana-ai: Install script detected — approve execution?
Pattern: curl ... | bash
URL: https://example.com/install.sh
Policy: exec_install_scripts=ask
(First 20 lines of script shown)
```

With `exec_install_scripts: deny`:

```
safe-solana-ai: Install script execution denied
Pattern: curl ... | bash
Policy: exec_install_scripts=deny
```

---

**Keypair or secret file read**

Triggered by `Read ~/.config/solana/id.json`, `Read .env`, or any path matching `secrets.deny_read_globs`.

```
safe-solana-ai: Read denied
Path: ~/.config/solana/id.json
Reason: matches secret glob ~/.config/solana/**
```

This is a hard guard — `deny`, not `ask`. It holds with `bypassPermissions` active. There is no approval path.

---

**Bad-mint swap (rugcheck)**

Triggered by an MCP swap call where the input mint's rugcheck.xyz score exceeds `rugcheck_max_score` (default: 40).

```
safe-solana-ai: Swap denied
Mint: Hf...xQ (score 87/100)
Risks: ["Mutable metadata", "No liquidity", "Creator holds 94%"]
```

On rugcheck timeout:

```
safe-solana-ai: Rugcheck unavailable — approve swap manually?
Mint: Hf...xQ
Rugcheck: timed out after 3000ms
```

Timeout always produces `ask`, never `deny` and never `allow`.

---

**Telemetry preamble blocked**

Triggered when a skill's Bash call matches the Convex exfiltration pattern or any config-driven telemetry endpoint pattern (caught by `gate-bash-secrets`).

```
safe-solana-ai: Outbound POST denied
Command: curl -s -X POST https://...convex.cloud/api/mutation ...
Reason: matches telemetry/exfiltration endpoint pattern (gate-bash-secrets)
```

---

## Supply-chain warnings at SessionStart

When `verify session` quarantines content, Claude Code's `additionalContext` mechanism injects a warning at the top of the session:

```
[safe-solana-ai] Supply-chain warning — 1 ext/ submodule quarantined:
  ext/solana-new: git SHA changed from a1b2c3d to d4e5f6g
  Last pinned: 2026-06-14T10:23:11Z
  Quarantine path: ${CLAUDE_PLUGIN_DATA}/quarantine/ext-solana-new/

To review and restore:
  safe-solana-ai verify           # see what changed
  ssai verify approve ext/solana-new   # re-pin after review
```

Run `safe-solana-ai status` to see the full quarantine list and all flagged findings from the current session's scan.

---

## Audit log

Every gate decision is appended to `${CLAUDE_PLUGIN_DATA}/audit.jsonl`. Each line is a standalone JSON object:

```jsonc
{
  "ts": "2026-06-16T09:14:32.441Z",
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

| Field | Description |
|-------|-------------|
| `ts` | ISO 8601 UTC timestamp |
| `hook` | Which gate produced the decision |
| `decision` | `allow`, `ask`, or `deny` |
| `reason` | Human-readable reason string |
| `tool` | Claude Code tool name (`Bash`, `Read`, `mcp__helius__heliusWrite.sendSol`, etc.) |
| `input` | Sanitized command or MCP tool name (secrets are not logged) |
| `network` | Resolved network (`devnet`, `mainnet-beta`, `localnet`, `unknown`) |
| `profile` | Active profile at time of decision |
| `grant` | Grant ID if a time-boxed grant was applied, otherwise `null` |

The file is append-only and not rotated automatically in v1.
