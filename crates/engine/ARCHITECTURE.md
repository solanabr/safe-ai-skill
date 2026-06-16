# ssai engine — architecture & round-2 contract

`ssai` is the Rust security engine behind the **safe-solana-ai** Claude Code plugin. It is
a single binary (hot path: gates fire on every Bash/Read/MCP call) plus a thin library so
tests and the binary share one module tree.

This document is the **contract** the round-2 parallel agents build against. The public
type signatures below are FROZEN — consume them, do not change them.

---

## Build / verify

```
cd crates/engine
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```
All four are green: `cargo test` = **314 passed** as of the solana-ai-kit foundation pass
(`cargo clippy --all-targets -- -D warnings` clean, `cargo fmt --check` clean).

Dependencies (resolved, FROZEN in `Cargo.toml`): `serde 1`, `serde_json 1`, `serde_yaml
0.9`, `sha2 0.10`, `glob 0.3`, `walkdir 2`, `bs58 0.5`, `ed25519-dalek 2` (`rand_core`),
`ureq 2` (`default-features = false, features = ["tls"]` → rustls). No tokio, no async.

---

## Round-2 rules for parallel agents

1. **Cargo.toml is FROZEN.** Every dependency the four agents need is already present. If an
   agent believes it needs a new crate, it must **STOP and flag it for human review** — it
   must NOT add a dependency itself (a silent dep add breaks the lean-binary guarantee and
   can conflict with another agent's parallel work).
2. **`main.rs` and `lib.rs` are COMPLETE and OFF-LIMITS.** All `mod` / `pub mod`
   declarations and the subcommand dispatch are finished. No agent edits these two files.
   New public items are exposed by filling existing stub bodies, not by re-declaring modules.
3. **Each agent edits ONLY its assigned module file(s) + that module's `#[cfg(test)]`
   tests.** No cross-module edits. The shared contracts below are FROZEN type signatures —
   consume them, never change them:
   - `io::{HookInput, Decision}` and the `render_*` / `emit_*` functions
   - `policy::Policy` (and sub-structs, `ProfileOverlay`)
   - `context::{Network, Context}`
   - `gate::{Scope, GateMeta}`
   - `audit::AuditEntry`
   - `verify::{Report, Finding, Severity}`
   - `grants::{Grant, Grants}`
4. **Gate purity.** Gates return a decision (+ metadata); they do NOT read stdin, load
   policy, audit, emit, or apply relaxation. `main.rs` owns all of that.

### Ownership table

| File(s) | Round-2 owner |
|---|---|
| `gates/bash.rs` | bash-gate agent |
| `gates/secrets.rs`, `gates/read.rs`, `redact.rs`, `promptguard.rs` | secrets/read/redact agent |
| `gates/mcp.rs`, `rugcheck.rs`, `spend.rs` | mcp/swap/spend agent |
| `grants.rs`, `mode.rs`, `relax.rs` | **grants/mode/relax agent (the relaxation trio — ONE agent)** |
| `verify/{heuristics,provenance,osv,lockfile}.rs`, `squads.rs`, `session.rs` | supply-chain/session agent |
| `io.rs`, `policy.rs`, `context.rs`, `audit.rs`, `error.rs`, `gate.rs`, `main.rs`, `lib.rs`, `Cargo.toml` | **FROZEN — foundation, do not edit** |

(The orchestrator may re-bucket agent→file groupings, but the FROZEN row is absolute and the
relaxation trio must stay with one agent.)

### Round-2 ownership table — solana-ai-kit compatibility milestone (P0)

This milestone's foundation pass (THIS pass) froze the policy schema, the `install` subcommand,
the `registry` module signatures, and the `verify::ext_submodules` extension point. The three
round-2 agents fill the stubs below. **Each agent edits ONLY its assigned file(s) + that file's
`#[cfg(test)]` tests.** No cross-module edits. Consume the FROZEN signatures, never change them.

| Agent | Owns | Task |
|---|---|---|
| **A** | `src/registry.rs` | Full impl + tests: `parse` (tolerant JSON), `Registry::load`, `Registry::high_risk` (classify against `policy.catalog.high_risk_classes` by id + keyword over safety/description/tags). |
| **B** | `src/verify/mod.rs` (`ext_submodules` + `run_session` integration), `src/verify/lockfile.rs` | Per-`ext`-submodule verify + git-SHA pin/drift; make `run_session` iterate `ext_submodules(...)` as individual units; `@latest` flagging downgraded to LOW (informational, not Warn). |
| **C** | `src/gates/mcp.rs`, `src/gates/bash.rs` | Use the expanded `mcp.sensitive_name_pattern` verbs (already in policy); high-risk MCP/class gating (phantom/x402 → `ask`/`deny`); runtime `curl … | sh/bash` gate honoring `supply_chain.exec_install_scripts`. |

**FROZEN this milestone (foundation-owned — round-2 does NOT touch):** `Cargo.toml` (flag a
needed dep, don't add it), `src/main.rs`, `src/lib.rs`, `src/policy.rs`. The `RegistryEntry` /
`Registry` / `CatalogPolicy` / `HighRiskClass` / `SupplyChainPolicy` shapes and the
`ext_submodules` / `Registry::{parse,load,high_risk}` signatures are FROZEN — consume them.

---

## Request flow (owned by `main.rs`)

For a PreToolUse gate (`gate-bash` / `gate-bash-secrets` / `gate-read` / `gate-mcp`):

```
stdin → HookInput::parse
      → Policy::load(cwd) → .effective()           # active-profile overlay applied
      → Context::build(command, cwd)               # network resolution
      → gate::decide(...) -> (Decision, GateMeta)  # PURE
      → relax::apply(decision, meta, effective, plugin_data)  # may upgrade Ask→Allow
      → audit::append(...)                          # when policy.audit.enabled
      → io::emit_pretooluse(final_decision)         # authoritative JSON; exit 0
```

`Defer` from a gate is emitted as `permissionDecision: "defer"` (let the default stand).
Unknown/missing subcommand → `emit_pretooluse(Allow)` (never block a hook on dispatch error).
Hard guards (`GateMeta::hard_guard == true`) are passed through `relax::apply` unchanged.

---

## Decision → JSON shapes

- **PreToolUse**:
  `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow|ask|deny|defer"[,"permissionDecisionReason":"…"]}}`
  (reason key omitted for `allow`/`defer`).
- **PostToolUse redact**: `{}` (no change) or `{"updatedToolOutput":"…"}` /
  `{"updatedMCPToolOutput":"…"}` (mcp tools).
- **UserPromptSubmit**: `{}` (allow) or `{"decision":"block","reason":"…"}`.
- **SessionStart**:
  `{"hookSpecificOutput":{"hookEventName":"SessionStart","reloadSkills":bool[,"additionalContext":"…"]}}`.

---

## State files (under `${CLAUDE_PLUGIN_DATA}`, fallback `~/.safe-solana-ai`)

| File | Producer | Purpose |
|---|---|---|
| `audit.jsonl` | `audit::append` | append-only decision log |
| `netcache.json` | `context` | cached `solana config get` RPC URL (60s TTL) |
| `spend.json` | `spend` (round-2) | daily spend ledger |
| `grants.json` | `grants` (round-2) | active scoped grants |
| `mode.json` | `mode` (round-2) | runtime active-profile override |
| `lockfile.json` | `verify::lockfile` (round-2) | TOFU content pins |
| `quarantine/<name>` | `verify` (round-2) | drifted/unverified skill dirs |
| `session/<id>.json` | `session` (round-2) | ephemeral session keypairs (0600) |

---

## Public API (FROZEN signatures)

### `error`
```rust
pub enum Error { Io(std::io::Error), Parse(String), Network(String), Other(String) }
pub type Result<T> = std::result::Result<T, Error>;
// From<std::io::Error>, Display, std::error::Error impls
```

### `io`
```rust
pub struct HookInput {
    pub session_id: Option<String>, pub cwd: Option<String>,
    pub permission_mode: Option<String>, pub hook_event_name: Option<String>,
    pub tool_name: Option<String>, pub tool_input: Option<serde_json::Value>,
    pub tool_output: Option<serde_json::Value>, pub prompt: Option<String>,
    pub source: Option<String>,
}
impl HookInput {
    pub fn from_stdin() -> Self;
    pub fn parse(raw: &str) -> Self;
    pub fn bash_command(&self) -> Option<&str>;
    pub fn read_path(&self) -> Option<&str>;
    pub fn mcp_payload(&self) -> Option<&serde_json::Value>;
}

pub enum Decision { Allow, Ask { reason: String }, Deny { reason: String }, Defer }
impl Decision { pub fn label(&self) -> &'static str; pub fn reason(&self) -> &str; }

pub fn render_pretooluse(d: &Decision) -> serde_json::Value;
pub fn emit_pretooluse(d: &Decision) -> std::io::Result<()>;
pub fn render_posttooluse_redact(updated: Option<String>, mcp: bool) -> serde_json::Value;
pub fn emit_posttooluse_redact(updated: Option<String>, mcp: bool) -> std::io::Result<()>;
pub fn render_userpromptsubmit(block: Option<&str>) -> serde_json::Value;
pub fn emit_userpromptsubmit(block: Option<&str>) -> std::io::Result<()>;
pub fn render_sessionstart(additional_context: Option<&str>, reload_skills: bool) -> serde_json::Value;
pub fn emit_sessionstart(additional_context: Option<&str>, reload_skills: bool) -> std::io::Result<()>;
```
> The `render_*` functions are the pure JSON builders the `emit_*` functions wrap; tests
> assert against `render_*` so stdout never needs capturing.

### `policy`
```rust
pub const DEFAULT_POLICY_YAML: &str;     // embedded default (literal; crate is standalone)
pub const PROFILE_ENV: &str;             // "SAFE_SOLANA_AI_PROFILE"

pub struct Policy {
    pub version: u32, pub active_profile: String,
    pub network: NetworkPolicy, pub spend: SpendPolicy,
    pub gates: Vec<String>, pub hard_guards: Vec<String>,
    pub mcp: McpPolicy, pub swap: SwapPolicy, pub secrets: SecretsPolicy,
    pub redact: TogglePolicy, pub audit: TogglePolicy,
    pub catalog: CatalogPolicy,             // NEW (solana-ai-kit milestone)
    pub supply_chain: SupplyChainPolicy,
    pub profiles: std::collections::BTreeMap<String, ProfileOverlay>,
}
pub struct NetworkPolicy { pub default: String, pub mainnet: String }
pub struct SpendPolicy { pub per_tx_sol_max: f64, pub hard_tx_sol_max: f64, pub daily_sol_max: f64 }
pub struct McpPolicy { pub sensitive_name_pattern: String }   // verbs expanded (see below)
pub struct SwapPolicy { pub rugcheck: bool, pub rugcheck_max_score: u32, pub rugcheck_timeout_ms: u64, pub trusted_mints: Vec<String> }
pub struct SecretsPolicy { pub deny_read_globs: Vec<String>, pub allow_read_globs: Vec<String> }
pub struct TogglePolicy { pub enabled: bool }
pub struct SupplyChainPolicy {
    pub verify_skills_dirs: Vec<String>,
    pub flag_unpinned_mcp: bool,            // @latest detection: INFORMATIONAL/LOW (MCPs kept @latest), not blocking
    pub flag_telemetry_curl: bool,
    pub verify_ext_submodules: bool,        // NEW — walk ext/<name> as individual units (serde default true)
    pub ext_dir: String,                    // NEW — ".claude/skills/ext" (serde default)
    pub exec_install_scripts: String,       // NEW — runtime curl|bash gate: "allow"|"ask"|"deny" (serde default "ask")
}
// NEW — opt-in skill-registry catalog gating.
pub struct CatalogPolicy {
    pub registry_path: String,              // ".claude/skills/skill-registry.json"
    pub high_risk_classes: Vec<HighRiskClass>,
}
pub struct HighRiskClass {
    pub kind: String,                       // "wallet_signing" | "key_custody" | "installer_script" | …
    pub decision: String,                   // forced decision on match: "ask" | "deny"
    pub keywords: Vec<String>,              // case-insensitive substrings of safety/description/tags
    pub ids: Vec<String>,                   // exact entry ids that always belong to the class
}
pub struct ProfileOverlay {
    pub relax_transfer: bool, pub relax_swap: bool, pub ask_all: bool,
    pub disabled: bool, pub per_tx_sol_max: Option<f64>,
}

impl Policy {
    pub fn load(cwd: &Path) -> Policy;          // deep-merge + fail-closed + env profile override
    pub fn fail_closed() -> Policy;             // conservative; every soft gate → ask
    pub fn is_fail_closed(&self) -> bool;
    pub fn is_hard_guard(&self, scope_label: &str) -> bool;
    pub fn effective(&self) -> Policy;          // apply active profile overlay
    pub fn active_overlay(&self) -> ProfileOverlay;
}
```
**Fail-closed guarantee:** any unrecoverable parse error in `load` returns `fail_closed()`
(caps zero, mainnet `ask`, profile `strict`, all hard guards present). A malformed *project
override* is ignored (base default still applies).

**Profiles:** `strict` (no-op), `autopilot` (relax_transfer/swap + per_tx cap 2.0),
`paranoid` (ask_all), `off` (disabled). `effective()` applies cap overrides; the boolean
flags are consumed by gates / `relax`. Hard guards are never relaxed.

**On-disk ⇄ embedded equivalence (FROZEN invariant).** The on-disk
`plugins/safe-solana-ai/policy/default.policy.yaml` is now the **full schema** (incl.
`active_profile`, `hard_guards`, `profiles`, `catalog`, and the new `supply_chain` fields) and
MUST parse to the same `Policy` as the embedded `DEFAULT_POLICY_YAML` const. The
`policy::tests::ondisk_policy_equivalent_to_embedded` test enforces this field-by-field — edit
both together.

**solana-ai-kit milestone field deltas:**
- `mcp.sensitive_name_pattern` expanded to
  `transfer|sign|swap|send|withdraw|burn|pay|upgrade|stake|delegate|mint|bridge|lend|borrow`
  (adds the value-moving verbs `stake delegate mint bridge lend borrow`).
- `catalog` (`CatalogPolicy`) — registry path + `high_risk_classes` (built-in classes:
  `wallet_signing`→`phantom-mcp`, `key_custody`→`x402-proxy-mcp`, `installer_script`→curl|bash).
  Classification is consumed by the round-2 catalog gate and `registry verify`.
- `supply_chain.verify_ext_submodules` / `ext_dir` / `exec_install_scripts` — per-`ext/`
  submodule verification toggle + dir + the runtime `curl … | sh/bash` gate setting.
- Every new field has a serde default so older/partial policy files still parse
  (`policy::tests::older_policy_without_new_fields_still_parses`). `Policy::load` fail-closed
  behavior is unchanged.

### `context`
```rust
pub enum Network { Mainnet, Devnet, Testnet, Localnet, Unknown }
impl Network { pub fn label(&self) -> &'static str; }

pub struct Context { pub network: Network, pub plugin_data: PathBuf, pub project_dir: PathBuf }
impl Context { pub fn build(command: &str, cwd: &Path) -> Context; }

pub fn resolve_network(command: &str, cwd: &Path) -> Network;  // flag>env>Anchor.toml>cached solana config
pub fn plugin_data_dir() -> PathBuf;                            // ${CLAUDE_PLUGIN_DATA} | ~/.safe-solana-ai
pub fn project_dir(cwd: &Path) -> PathBuf;
```
Fully implemented (not a stub). Never panics; `Unknown` on failure.

### `gate`
```rust
pub enum Scope { Transfer, Swap, Deploy, Authority, Destructive, SecretRead, Other }
impl Scope { pub fn label(&self) -> &'static str; pub fn from_label(s: &str) -> Scope; }

pub struct GateMeta {
    pub scope: Scope, pub amount_sol: Option<f64>,
    pub program: Option<String>, pub destination: Option<String>,
    pub hard_guard: bool,
}
impl GateMeta {
    pub fn new(scope: Scope, hard_guard: bool) -> Self;
    pub fn unknown() -> Self;   // Scope::Other, not a hard guard
}
```

### `audit`
```rust
pub struct AuditEntry {
    pub ts: u64, pub session_id: String, pub tool: String,
    pub classification: String, pub decision: String,
    pub reason: String, pub input_sha256: String,
}
impl AuditEntry { pub fn new(session_id, tool, classification, decision, reason, input_sha256) -> Self; }
pub fn sha256_hex(bytes: &[u8]) -> String;
pub fn append(entry: &AuditEntry, plugin_data: &Path) -> std::io::Result<()>;
```

### `gates` (STUBS — return safe defaults)
```rust
pub fn gates::bash::decide(command: &str, ctx: &Context, policy: &Policy) -> (Decision, GateMeta);   // (Defer, unknown)
pub fn gates::secrets::decide(command: &str, policy: &Policy) -> Decision;                            // Defer
pub fn gates::read::decide(path: &str, policy: &Policy) -> Decision;                                  // Defer
pub fn gates::mcp::decide(tool_name: &str, payload: Option<&serde_json::Value>, ctx: &Context, policy: &Policy) -> (Decision, GateMeta); // (Defer, unknown)
```
> `secrets`/`read` return only `Decision`; `main.rs` wraps them in a `GateMeta` with
> `scope = SecretRead, hard_guard = true`.

### `redact` / `promptguard` (STUBS)
```rust
pub fn redact::scrub(text: &str) -> Option<String>;       // None
pub fn promptguard::check(prompt: &str) -> Option<String>; // None
```

### `spend` / `rugcheck` (STUBS)
```rust
pub struct spend::SpendLedger { pub day: u64, pub total_sol: f64 }
pub fn spend::record_and_check(plugin_data: &Path, sol_amount: f64, policy: &Policy) -> Decision;  // Defer
pub fn rugcheck::check_mint(mint: &str, policy: &Policy) -> Decision;                              // Defer
```

### Relaxation trio (STUBS — one round-2 agent)
```rust
// grants
pub struct grants::Grant {
    pub id: String, pub scope: Scope, pub programs: Vec<String>, pub to: Vec<String>,
    pub max_tx_sol: f64, pub budget_sol: f64, pub spent_sol: f64,
    pub expires_at: u64, pub danger: bool,
}
pub struct grants::Grants { pub grants: Vec<Grant> }
pub fn grants::load(plugin_data: &Path) -> Grants;
pub fn grants::save(plugin_data: &Path, grants: &Grants) -> std::io::Result<()>;
pub fn grants::find_match<'a>(grants: &'a Grants, meta: &GateMeta) -> Option<&'a Grant>;
pub fn grants::debit(plugin_data: &Path, grant_id: &str, sol_amount: f64) -> std::io::Result<()>;
pub fn grants::cleanup_expired(plugin_data: &Path) -> usize;

// mode
pub fn mode::get(plugin_data: &Path) -> Option<String>;
pub fn mode::set(plugin_data: &Path, profile: &str) -> std::io::Result<()>;

// relax  (called by main.rs after every gate)
pub fn relax::apply(natural: Decision, meta: &GateMeta, policy: &Policy, plugin_data: &Path) -> Decision;
```
`relax::apply` contract: if `natural` is not `Ask`, or `meta.hard_guard` is true, return it
unchanged; otherwise consult active grants and (on a match within budget/`max_tx_sol`) debit
and return `Allow`. `policy` is the EFFECTIVE policy (profile overlay already applied).

### `verify` (`Report`/`Finding`/`Severity` FROZEN; scan fns STUBS)
```rust
pub enum Severity { Low, Medium, High }            // Ord: High > Medium > Low
pub struct Finding { pub severity: Severity, pub kind: String, pub detail: String }
impl Finding { pub fn new(severity, kind, detail) -> Self; }
pub struct Report { pub findings: Vec<Finding> }
impl Report { pub fn max_severity(&self) -> Option<Severity>; pub fn merge(&mut self, other: Report); }

pub fn verify::heuristics::scan(path: &Path) -> Report;        // empty
pub fn verify::provenance::resolve(source: &str) -> Report;    // empty
pub fn verify::osv::query(pkg: &str, version: &str) -> Report; // empty
pub fn verify::lockfile::hash_tree(path: &Path) -> String;     // ""

// NEW — per-ext-submodule discovery (STUB; round-2 Agent B implements + integrates).
// Returns each `ext/<name>` dir under `skills_dir` as an individual verifiable unit. STUB
// returns an empty vec; `run_session` behavior is UNCHANGED (still treats ext/ as one unit)
// until Agent B wires this in (per-submodule git-SHA pin/drift).
pub fn verify::ext_submodules(skills_dir: &Path, policy: &Policy) -> Vec<PathBuf>;  // []
```

### `registry` (NEW — opt-in catalog; STUBS, round-2 Agent A)
```rust
pub struct RegistryEntry {
    pub id: String, pub title: String, pub source: String, pub category: String,
    pub default_installed: bool,
    pub safety: Option<String>, pub description: Option<String>, pub tags: Vec<String>,
    pub risk_class: Option<String>,   // DERIVED (not on disk); set by Registry::high_risk
}
pub struct Registry { pub entries: Vec<RegistryEntry> }
pub fn registry::parse(json: &str) -> Result<Registry>;                          // Ok(empty)
pub fn registry::Registry::load(path: &Path) -> Result<Registry>;               // Ok(empty)
pub fn registry::Registry::high_risk(entry: &RegistryEntry, policy: &Policy) -> Option<String>; // None
```
The on-disk catalog shape is `{ version, updated, entries: [ … ] }`; each entry carries
`id`/`name`/`type`/`domain`/`description`/`source`/`install`/`license`/`maintainer`/`signal`/
`default_installed`/`safety`/`tags`. `RegistryEntry` keeps the subset ssai gates on (JSON
`name`→`title`, `type`→`category`); unknown fields are tolerated. `high_risk` classifies an
entry against `policy.catalog.high_risk_classes` (id match or case-insensitive keyword match
against safety/description/tags) and returns the matching class `kind`. `risk_class` is `None`
until classified. Round-2 Agent A fills the three stub bodies + tests.

### `squads` / `session` (STUBS)
```rust
pub fn squads::upgrade_authority_advisory(program: &str, ctx: &Context) -> Option<String>;  // None
pub fn session::init(cap_sol: f64, plugin_data: &Path) -> error::Result<String>;            // Ok("")
pub fn session::status(plugin_data: &Path) -> error::Result<String>;                        // Ok("no active session")
```

---

## Subcommands (`main.rs`, complete)

`gate-bash` · `gate-bash-secrets` · `gate-read` · `gate-mcp` · `redact` · `prompt-guard` ·
`verify session|check|approve` · `add skill|mcp|repo <source>` ·
`install [--from <dir|tarball>] [--home <dir>] [--yes]` · `registry verify|list` ·
`session init [--cap <SOL>]|status` · `allow --scope --for --max-tx --budget --programs --to [--danger]` ·
`mode [<profile>]` · `revoke` · `status`.

Gate subcommands emit the authoritative PreToolUse decision; the rest print a JSON result line.
Unknown subcommand → `emit_pretooluse(Allow)`.

**`install` (replaces `bootstrap`; solana-new tarball path REMOVED).** Hub-agnostic, LOCAL
source only — there is no hardcoded download URL (`solana.new/skills.tar.gz` + the
`curl … | tar` network path are gone). `--from <dir|tarball>` verifies + neutralizes +
installs each skill dir (a local tarball is extracted via `tar`); `--home <dir>` /
`SAFE_SOLANA_AI_HOME` redirects the install root to `<dir>/.claude/skills` (sandboxable). With
**no `--from`**, `install` runs **verify-in-place** over the current project's `.claude/skills`
(scan + telemetry-neutralize + TOFU-pin, no copy) — the post-`install.sh` audit path. Never
widens `settings.json`; a High finding holds the skill unless `--yes`.

**`registry verify|list`.** Loads the project `skill-registry.json` (path from
`policy.catalog.registry_path`) via `registry::Registry::load` and lists/audits entries with
`high_risk` classification. STUB now (the parser is a round-2 Agent A stub) → reports an empty
catalog until filled in.
