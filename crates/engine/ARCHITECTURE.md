# safe-ai-skill engine — architecture & round-2 contract

`safe-ai-skill` is the Rust security engine behind the **safe-ai-skill** Claude Code plugin. It is
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
stdin → io::read_payload                           # bytes (≤ 1 MiB + 1) + parse or Unreadable
      → Policy::load(cwd) → .effective()           # active-profile overlay applied
      → Context::build(command, cwd)               # network resolution
      → gate::decide(...) -> (Decision, GateMeta)  # PURE
      → relax::apply(decision, meta, effective, plugin_data)  # may upgrade Ask→Allow
      → audit::append(...)                          # when policy.audit.enabled
      → io::emit_pretooluse(final_decision)         # authoritative JSON; exit 0
```

`Defer` from a gate emits nothing (empty stdout, exit 0): no opinion leaves Claude Code's normal
permission flow in charge. It is never emitted as `permissionDecision: "defer"`, which Claude Code
treats as "stop this tool call".
A payload the engine cannot read is an `ask` on every PreToolUse gate (`gate-read`,
`gate-bash-secrets`, `gate-mcp`, `gate-bash`): the model shapes `tool_input`, so it can force
either kind. `Unreadable::Oversized` is over 1 MiB and never parsed. `Unreadable::Malformed` is
bad JSON or UTF-8, a lone surrogate escape (`"\ud800"`, as `JSON.stringify` emits it), or nesting
past serde's recursion limit (about 128 levels, a few hundred bytes). Only `Unreadable::Empty`
(whitespace-only stdin, which Claude Code never sends) is no opinion on the broad gates; `gate-bash`
(the Solana surface) asks on it too, and when the payload has no `tool_input.command`. These asks
run under the hard-guard `GateMeta::unreadable()`, so no grant relaxes them, and are audited with
classification `unreadable` and the sha256 of the bytes received (the first 1 MiB + 1 when
oversized). `redact` and `prompt-guard` have no opinion on any unreadable payload.
Unknown/missing subcommand → empty stdout, error on stderr, exit 3. `--version` prints
`safe-ai-skill <version>` (no hook JSON).
Hard guards (`GateMeta::hard_guard == true`) are passed through `relax::apply` unchanged.

---

## Decision → JSON shapes

- **PreToolUse**:
  `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow|ask|deny"[,"permissionDecisionReason":"…"]}}`
  (reason key omitted for `allow`); `Defer` → no output.
- **PostToolUse redact**: no output (no change) or `{"updatedToolOutput":"…"}` /
  `{"updatedMCPToolOutput":"…"}` (mcp tools).
- **UserPromptSubmit**: no output (allow) or `{"decision":"block","reason":"…"}`.
- **SessionStart** (`verify::SessionResult::hook_output`, report-only): no output when there is
  nothing to report, else `{["systemMessage":"…",]["hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"…"}]}`
  (each part only when non-empty).

---

## State files (under `${CLAUDE_PLUGIN_DATA}`, fallback `~/.safe-ai-skill`)

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
    pub fn from_stdin() -> Self;                 // bounded; unreadable → default
    pub fn parse(raw: &str) -> Self;
    pub fn bash_command(&self) -> Option<&str>;
    pub fn read_path(&self) -> Option<&str>;
    pub fn mcp_payload(&self) -> Option<&serde_json::Value>;
}

pub const MAX_STDIN_BYTES: usize;                // 1 MiB
pub enum Unreadable { Empty, Oversized, Malformed }
pub fn read_payload(reader: impl std::io::Read) -> (Vec<u8>, Result<HookInput, Unreadable>);

pub enum Decision { Allow, Ask { reason: String }, Deny { reason: String }, Defer }
impl Decision { pub fn label(&self) -> &'static str; pub fn reason(&self) -> &str; }

pub fn render_pretooluse(d: &Decision) -> Option<serde_json::Value>;  // Defer → None
pub fn emit_pretooluse(d: &Decision) -> std::io::Result<()>;
pub fn render_posttooluse_redact(updated: Option<String>, mcp: bool) -> Option<serde_json::Value>;  // no change → None
pub fn emit_posttooluse_redact(updated: Option<String>, mcp: bool) -> std::io::Result<()>;
pub fn render_userpromptsubmit(block: Option<&str>) -> Option<serde_json::Value>;  // pass → None
pub fn emit_userpromptsubmit(block: Option<&str>) -> std::io::Result<()>;
```
> The `render_*` functions are the pure JSON builders the `emit_*` functions wrap; tests
> assert against `render_*` so stdout never needs capturing.

### `policy`
```rust
pub const DEFAULT_POLICY_YAML: &str;     // embedded default (literal; crate is standalone)
pub const PROFILE_ENV: &str;             // "SAFE_AI_SKILL_PROFILE" — may only pick a stricter profile

pub struct Policy {
    pub version: u32, pub active_profile: String,
    pub network: NetworkPolicy, pub spend: SpendPolicy,
    pub gates: Vec<String>, pub hard_guards: Vec<String>,
    pub mcp: McpPolicy, pub swap: SwapPolicy, pub secrets: SecretsPolicy,
    pub redact: TogglePolicy, pub audit: TogglePolicy,
    pub catalog: CatalogPolicy,             // NEW (solana-ai-kit milestone)
    pub supply_chain: SupplyChainPolicy,
    pub profiles: std::collections::BTreeMap<String, ProfileOverlay>,
    pub ignored_overrides: Vec<String>,     // refused project/env overrides (serde-skipped)
    // private, serde-skipped: caps the project lowered; scan dirs it added
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
    pub fn load(cwd: &Path) -> Policy;          // load_with_mode(cwd, None)
    // Reads the plugin default, <cwd>/.safe-ai-skill/policy.yaml and PROFILE_ENV, calls
    // from_sources, then keeps project-added scan dirs only if they resolve on disk inside cwd.
    pub fn load_with_mode(cwd: &Path, persisted_profile: Option<&str>) -> Policy;
    // Pure (no env, no fs): base + ratcheted project overlay + profile resolution. Project scan
    // dirs get the text check only; on-disk confinement happens in load_with_mode alone.
    pub fn from_sources(base_src: &str, project_src: Option<&str>,
                        persisted_profile: Option<&str>, env_profile: Option<&str>) -> Policy;
    pub fn fail_closed() -> Policy;             // conservative; every soft gate → ask
    pub fn is_fail_closed(&self) -> bool;
    pub fn is_hard_guard(&self, scope_label: &str) -> bool;
    pub fn effective(&self) -> Policy;          // apply active profile overlay, then re-clamp project caps
    pub fn active_overlay(&self) -> ProfileOverlay;
    pub fn ignored_notice(&self) -> Option<String>; // SessionStart block listing ignored_overrides
}
```
**Fail-closed guarantee:** an unparsable plugin default returns `fail_closed()` (caps zero,
mainnet `ask`, profile `strict`, all hard guards present). A *project override* that is not
valid YAML (or not a mapping) is ignored; one with ill-typed values fails closed through the
ratchet, so no other field ends up looser than the base. Either way it is noted.

**Project ratchet (D1.10).** `.safe-ai-skill/policy.yaml` is repo-controlled, so it may only
tighten the base, field by field: caps take the lower value (and still bind under any
profile); `network.mainnet` / `exec_install_scripts` move only toward `deny`;
`network.default` only to mainnet; deny-lists (`secrets.deny_read_globs`, `gates`,
`hard_guards`, `mcp.sensitive_name_pattern` alternatives) add entries; allow-lists
(`secrets.allow_read_globs`, `swap.trusted_mints`) drop them; toggles can only turn on;
`verify_skills_dirs` keeps every base dir and may add dirs strictly inside the project
(lexically in `from_sources`, then canonicalized on disk in `load_with_mode`). Fields with no
safe direction stay fixed: `catalog`, `swap.rugcheck_timeout_ms`, `supply_chain.ext_dir`,
`supply_chain.verify_ext_submodules`. `active_profile` / `profiles` are ignored. Every refused
change lands in `ignored_overrides`, which `verify session` appends to the SessionStart
`additionalContext`; the notes never echo repo text.

**Profiles:** `strict` (no-op), `autopilot` (relax_transfer/swap + per_tx cap 2.0),
`paranoid` (ask_all), `off` (disabled). The active profile is the `safe-ai-skill mode` choice
(`mode.json`) if set, else the plugin default's; `PROFILE_ENV` may then only pick a stricter
one (`off` < `autopilot` < `strict` < `paranoid`). `effective()` applies cap overrides; the
boolean flags are consumed by gates / `relax`. Hard guards are never relaxed.

**On-disk ⇄ embedded equivalence (FROZEN invariant).** The on-disk
`plugins/safe-ai-skill/policy/default.policy.yaml` is now the **full schema** (incl.
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
pub fn plugin_data_dir() -> PathBuf;                            // ${CLAUDE_PLUGIN_DATA} | ~/.safe-ai-skill
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
    pub fn unreadable() -> Self;   // Scope::Other, hard guard (unreadable-payload asks)
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
pub fn mode::get(plugin_data: &Path) -> Option<String>;        // env-if-known, else mode.json (raw read)
pub fn mode::persisted(plugin_data: &Path) -> Option<String>;  // mode.json only; what load_with_mode takes
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
`default_installed`/`safety`/`tags`. `RegistryEntry` keeps the subset safe-ai-skill gates on (JSON
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
`mode [<profile>]` · `revoke` · `status` · `--version`.

Gate subcommands emit the authoritative PreToolUse decision (nothing for no opinion); the rest
print a JSON result line. Unknown or missing subcommand → empty stdout, stderr message, exit 3.

**`install` (replaces `bootstrap`; remote tarball path REMOVED).** Hub-agnostic, LOCAL
source only — there is no hardcoded download URL (the remote `skills.tar.gz` + the
`curl … | tar` network path are gone). `--from <dir|tarball>` verifies + neutralizes +
installs each skill dir (a local tarball is extracted via `tar`); `--home <dir>` /
`SAFE_AI_SKILL_HOME` redirects the install root to `<dir>/.claude/skills` (sandboxable). With
**no `--from`**, `install` runs **verify-in-place** over the current project's `.claude/skills`
(scan + telemetry-neutralize + TOFU-pin, no copy) — the post-`install.sh` audit path. Never
widens `settings.json`; a High finding holds the skill unless `--yes`.

**`registry verify|list`.** Loads the project `skill-registry.json` (path from
`policy.catalog.registry_path`) via `registry::Registry::load` and lists/audits entries with
`high_risk` classification. STUB now (the parser is a round-2 Agent A stub) → reports an empty
catalog until filled in.
