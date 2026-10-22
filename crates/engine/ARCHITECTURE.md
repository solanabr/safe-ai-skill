# safe-ai-skill engine — architecture

`safe-ai-skill` is the Rust security engine behind the **safe-ai-skill** Claude Code plugin. It is
a single binary (hot path: gates fire on every Bash/Read/MCP call) plus a thin library so
tests and the binary share one module tree.

This document maps the modules, the hook contract and the state they share. Signatures below
are the public surface as of 1.1.0.

---

## Build / verify

```
cd crates/engine
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```
All four must be green before a commit (`cargo clippy --all-targets -- -D warnings` and
`cargo fmt --check` clean, `cargo test` passing).

Dependencies (`Cargo.toml`): `serde 1`, `serde_json 1` (`float_roundtrip`), `serde_yaml 0.9`,
`sha2 0.10`, `glob 0.3`, `walkdir 2`, `bs58 0.5`, `ed25519-dalek 2` (`rand_core`), `rand_core
0.6` (`getrandom`), `ureq 2` (`default-features = false, features = ["tls"]` → rustls), and
`libc` on unix. No tokio, no async. A new dependency needs review (binary size, supply chain).

---

## Module rules

- **Gate purity.** Gates return a decision (+ metadata); they do NOT read stdin, load policy,
  audit, emit, or apply relaxation. `main.rs` owns all of that.
- **Subcommands** are registered in `main.rs`'s `SUBCOMMANDS` table; the PreToolUse gates run
  under `DEADLINE_GATES` (8 s, `ask` past it) and `PANIC_ASK_GATES` (a panic writes a hard-guard
  `ask` before the abort).
- **State** goes through `statefile` (authenticated envelopes) in the data dir `datadir`
  resolves; hooks resolve it with the payload `cwd` (`data_dir_with_cwd`).

---

## Request flow (owned by `main.rs`)

For a PreToolUse gate (`gate-bash` / `gate-bash-secrets` / `gate-read` / `gate-mcp` / `gate-skill`):

```
stdin → io::read_payload                           # bytes (≤ 1 MiB + 1) + parse or Unreadable
      → Policy::load(cwd) → .effective()           # policy overlays applied
      → policy::tier::resolve(root, dir, env)      # (tier, env_read, notes): max(user tier.json, raise-only hints)
      → Context::build(command, cwd)               # network resolution
      → gate::decide(...) -> (Decision, GateMeta)  # PURE
      → relax::apply(decision, meta, effective, plugin_data)  # may upgrade Ask→Allow (never at High)
      → headless post-processor                      # Ask→Deny when headless (grants confirmed earlier still allow)
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

## Platform shim (`plugins/safe-ai-skill/bin/safe-ai-skill`)

`hooks.json` runs the POSIX sh shim, which execs the prebuilt `safe-ai-skill-<plat>` beside it
(never `cargo build`, never a binary outside its own directory) and maps failures onto the hook
contract:

- **Environment failure** (no prebuilt for the platform, not an executable here, no sha256 tool,
  exit 126/127): fail open with a notice. `gate-bash` and `gate-skill` answer `ask`, SessionStart
  reports the firewall INACTIVE, every other hook exits 0 with one stderr line.
- **Tamper** (the prebuilt's sha256 differs from the constant `scripts/stamp-shim.sh` stamped at
  release): the prebuilt never runs; `gate-bash`, `gate-mcp` and `gate-skill` exit 2, the other
  PreToolUse gates ask, non-PreToolUse hooks exit 0 with a stderr line.
- **Engine crash** (signal, or exit not in {0, 2, 3}): `gate-bash`, `gate-mcp` and `gate-skill`
  exit 2 (block); the rest exit 0 with a stderr line.
- `SAFE_AI_SKILL_STRICT=1` turns every unusable case into exit 2. `SAFE_AI_SKILL_DISABLE=1`
  turns the hooks off, but is ignored in strict mode or when the committed project
  `.claude/settings.json` mentions it; SessionStart reports either way.
- The Solana `gate-bash` entries and the `Skill` matcher set `onFailure: block`, the others
  `continue`. `onFailure`
  needs Claude Code 2.1.295 or newer; older versions ignore it, so a hook that can't start
  never blocks.

CLI subcommands (not hooks) run the engine with live output and keep its exit status; an environment failure exits 1 (2 under `SAFE_AI_SKILL_STRICT`).

---

## Decision → JSON shapes

- **PreToolUse**:
  `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow|ask|deny"[,"permissionDecisionReason":"…"]}}`
  (reason key omitted for `allow`); `Defer` → no output.
- **PostToolUse redact**: no output (no change) or
  `{"hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":…}}` in the tool's own
  response shape (Read, Bash, Grep, MCP).
- **PostToolUse pending-notice** (Bash): no output, or `{"systemMessage":"…"}` with confirmation
  codes (user only).
- **PreToolUse Read/Grep rewrite**: `{"hookSpecificOutput":{"hookEventName":"PreToolUse","updatedInput":…}}`
  (no permission decision) for a directory Grep whose `glob` gets the env/key exclusions.
- **UserPromptSubmit / UserPromptExpansion**: no output (allow), `{"decision":"block","reason":"…"}`
  (a raw secret, a blocked pack's `/name`), or a confirmation outcome (`systemMessage` +
  `additionalContext`, never a code).
- **SessionStart** (`verify::SessionResult::hook_output`, report-only): no output when there is
  nothing to report, else `{["systemMessage":"…",]["hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"…"}]}`
  (each part only when non-empty).

---

## State files (in the data dir: `datadir::data_dir()`)

`datadir::data_dir()` resolves `CLAUDE_PLUGIN_DATA`, else the preferred `safe-ai-skill-*` dir
under `$CLAUDE_CONFIG_DIR/plugins/data` / `~/.claude/plugins/data`; never a relative path.
`DataDir::trusted` holds only inside `<passwd home>/.claude/plugins/data`, or inside
`$CLAUDE_CONFIG_DIR/plugins/data` when that config dir is under the passwd home and neither
it nor the data dir is inside the project or hook cwd (see `datadir` docs). Hooks resolve with `data_dir_with_cwd(Some(cwd))`. Authenticated files go through `statefile` (`{v, mac, body}`, HMAC-SHA256, key in
`key`). The CLI resolves the same dir from a terminal; state is never written to
`~/.safe-ai-skill` or the cwd.

| File | Producer | Purpose |
|---|---|---|
| `audit.jsonl` | `audit::append` | append-only decision log |
| `netcache.json` | `context` | cached `solana config get` RPC URL (60s TTL, authenticated state file, bound to the CLI config's size+mtime; future `ts` ignored) |
| `spend.json` | `spend` | daily spend ledger (authenticated; missing after the key exists, or tampered → today exhausted) |
| `grants.json` | `grants` | scoped grants (authenticated; created only by a confirmed prompt nonce) |
| `tier.json` | `tierstate` | user-scope tier `{global?, projects[root]}` with optional `env_read` (authenticated; a lowering or an `env_read` loosening needs a confirmed nonce). Replaces the pre-tier `mode.json`, which `migrate` converts once |
| `sessions.json` | `session` | session-key metadata and the active-session pointer (authenticated) |
| `lockfile.json` | `verify::lockfile` | v1 name-keyed pins; read for the state-v2 carry-over, still written by `add`/`install` |
| `state.json` | `verify::state` | state v2: per-pack pin, grade, findings, names, fingerprint (authenticated) |
| `trust.json` | `verify::trust` | user trust by content hash (authenticated) |
| `quarantine/<name>` | 1.0.0 `verify` (legacy) | skill dirs 1.0.0 moved; 1.0.1+ never writes here. `verify approve <name>` restores one, `verify session` lists leftovers |
| `session/<id>.json` | `session` | ephemeral session keypairs (0600, Solana CLI format, plain) |
| `key` | `statefile` | 32-byte HMAC key for authenticated state (0600) |
| `generations.json` | `statefile` | authenticated `{file: generation}` index; an envelope below its generation is tampered |
| `pending.json` | `confirm` | pending requests: id, payload, code **hash** once announced, failure count (authenticated) |
| `migrated.json` | `migrate` | authenticated marker: 1.0 state was converted |
| `*.lock` | `statefile::FileLock` | `state.lock` (stores), `pending.lock`, `grants.lock` |

---

## Tiers, sandbox state, headless and shared lists

The firewall takes a tier as an **input**; solana-ai-kit owns the sandbox, permission rules and tier selection UX. User-facing behaviour is in `docs/tiers.md` and the README table; this section maps the modules. Signatures are in the source (rustdoc).

| Module | Role |
|---|---|
| `policy/tier.rs` | `Tier {Off, Relaxed, Medium, High}` (`Ord`; aliases `strict`, `paranoid`, `autopilot`), `TierSource`, and `resolve(root, &DataDir, env) -> (Tier, EnvRead, Vec<Note>)`: `base` (`relaxed`), then the user value from `tier.json` (`projects[root]`, else `global`), then `max()` with the raise-only hints (kit `.claude/security.json` `tier`/`declared.tier`/`enforced.tier`, repo `policy.yaml` `tier`, env `SAFE_AI_SKILL_TIER`). A lower hint is ignored with a note. The table in the README is checked against the table in this file. |
| `tierstate.rs` | The authenticated `tier.json` v1 under the statefile MAC and generation index; the writer behind `safe-ai-skill tier`. A raise applies at once; a lowering or an `env_read` loosening (`deny` < `ask` < `tier`) becomes a `confirm::PendingKind::Tier` request. `mode.rs` stays as a deprecated alias. |
| `sandbox.rs` | `state(root) -> {On, Off, Unknown}` from the first `sandbox.enabled` in managed, project-local, project, then user settings (passwd home, never env `HOME`; `$CLAUDE_CONFIG_DIR`). `On` also needs macOS or Linux with `bwrap` on a fixed path, never native Windows. Declared configuration, not a runtime proof. A test override exists only under `test-hooks`. |
| `headless.rs` | `is_headless(env)`: any of `SAFE_AI_SKILL_HEADLESS`/`KIT_FIREWALL_HEADLESS` (`1`/`true`), a CI variable not `0`/`false`, or no readable `/dev/tty`. Any signal turns it on, nothing turns it off. `main.rs` post-processes every PreToolUse verdict: `ask` becomes `deny`; a grant confirmed earlier still allows below High. |
| `lists.rs` | Parses the embedded `policy/shared/{credentials,exfil-hosts,onchain-verbs}.list` (`include_str!`, `OnceLock`) and checks `MANIFEST` counts and sha256. Accessors for credentials, exfil hosts per tier, `irreversible()` and `recoverable()`. A parse failure is `ListsUnavailable`: the dependent gates answer a hard-guard `ask`. User or repo `secrets.exfil_hosts_extra` and `secrets.key_material_extra_globs` union in; nothing removes an entry. |
| `gates/credpaths.rs`, `gates/creddump.rs` | Credential path classification and directory-Grep exclusion globs from `credentials.list`; the command-form readers (`gh auth token`, `git credential fill`, `security … -w`, `op read`, …). Deny at every tier. |
| `gates/envread.rs`, `gates/envwrite.rs` | The raw project-env read verdict from `(tier, env_read, sandbox)`; the Write/Edit/MultiEdit and agent `env set\|unset` verdict (deny from Medium). The opt-in applies only with the sandbox `On`. |
| `gates/wallet.rs`, `gates/bash.rs` | Default-wallet destruction (deny at every tier); irreversible actions (Class U in docs/tiers.md; `irreversible` rows: deny on mainnet, Unknown or testnet, ask on identified localnet/devnet, never grantable) and value-moving actions (Class C; caps, grants, mainnet/Unknown ask, High deny). |
| `gates/exfil.rs` | The naive-exfil tripwire in `gate-bash-secrets` and `gate-mcp`: secret operand to a network-capable command, or a listed host, per the tier's list size. |
| `verify/` (`tier_action`, `gittracked.rs`) | Per-tier supply-chain action (report at Off, deny in place from Relaxed, HIGH heuristic denies at High); `on_block: move` never moves a git-tracked pack or submodule path (reads `.gitmodules` and `.git/index`, never runs git). |

**Invariants the tests pin:** every `deny` row holds at Off; no repo file, kit file or env variable lowers a tier or loosens `env_read`; a lowering is pending until a whole-prompt confirm; raising never prompts; High emits no `allow`; no tier emits `defer`; nothing moves by default; the exfil lists never shrink below the shared file; the embedded lists equal `policy/shared/*` byte for byte; headless never yields `ask`; the kit's `.safe-ai-skill/policy.yaml` loads unchanged. The conformance corpus is `policy/shared/corpus/*.jsonl`, run by `tests/shared_corpus.rs`.

---

## Public API

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
> The signatures below predate tiers: the profile fields, `PROFILE_ENV`, `load_with_mode` and `active_overlay` are being replaced by the tier resolution described above. See rustdoc for the current surface.

```rust
pub const DEFAULT_POLICY_YAML: &str;     // embedded default (literal; crate is standalone)
pub const PROFILE_ENV: &str;             // "SAFE_AI_SKILL_PROFILE" — may only pick a stricter profile

pub struct Policy {
    pub version: u32, pub active_profile: String,
    pub network: NetworkPolicy, pub spend: SpendPolicy,
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
pub struct ProfileOverlay { pub ask_all: bool, pub per_tx_sol_max: Option<f64> }

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
    pub fn effective(&self) -> Policy;          // apply active profile overlay, then re-clamp project caps
    pub fn active_overlay(&self) -> ProfileOverlay;
    pub fn ignored_notice(&self) -> Option<String>; // SessionStart block listing ignored_overrides
}
```
**Fail-closed guarantee:** an unparsable plugin default returns `fail_closed()` (caps zero,
mainnet `ask`, profile `strict`). A *project override* that is not
valid YAML (or not a mapping) is ignored; one with ill-typed values fails closed through the
ratchet, so no other field ends up looser than the base. Either way it is noted.

**Project ratchet.** `.safe-ai-skill/policy.yaml` is repo-controlled, so it may only
tighten the base, field by field: caps take the lower value (and still bind under any
profile); `network.mainnet` / `exec_install_scripts` move only toward `deny`;
`network.default` only to mainnet; deny-lists (`secrets.deny_read_globs`,
`mcp.sensitive_name_pattern` alternatives) add entries; allow-lists
(`secrets.allow_read_globs`, `swap.trusted_mints`) drop them; toggles can only turn on;
`verify_skills_dirs` keeps every base dir and may add dirs strictly inside the project
(lexically in `from_sources`, then canonicalized on disk in `load_with_mode`). Fields with no
safe direction stay fixed: `catalog`, `swap.rugcheck_timeout_ms`, `supply_chain.ext_dir`,
`supply_chain.verify_ext_submodules`. A repo `tier` (or the legacy `active_profile`) is a raise-only tier hint, and `profiles:` is ignored. Every refused
change lands in `ignored_overrides`, which `verify session` appends to the SessionStart
`additionalContext`; the notes never echo repo text.

**Profiles are gone.** `strict`, `paranoid` and `autopilot` are input aliases for the tiers `relaxed`, `high` and `relaxed` (`migrate.rs`, `policy::tier`); `profiles:`, `ask_all`, the autopilot cap, `KNOWN_PROFILES`, the `off` profile, `relax_transfer`, `relax_swap`, `disabled` and the never-read `gates`/`hard_guards` lists load as ignored notes. See "Tiers, sandbox state, headless and shared lists" below. Hard guards are set by the gates (`GateMeta::hard_guard`) and never relaxed.

**On-disk ⇄ embedded equivalence (invariant).** The on-disk
`plugins/safe-ai-skill/policy/default.policy.yaml` is now the **full schema** (incl.
`active_profile`, `profiles`, `catalog`, and the new `supply_chain` fields) and
MUST parse to the same `Policy` as the embedded `DEFAULT_POLICY_YAML` const. The
`policy::tests::ondisk_policy_equivalent_to_embedded` test enforces this field-by-field — edit
both together.

**solana-ai-kit milestone field deltas:**
- `mcp.sensitive_name_pattern` expanded to
  `transfer|sign|swap|send|withdraw|burn|pay|upgrade|stake|delegate|mint|bridge|lend|borrow`
  (adds the value-moving verbs `stake delegate mint bridge lend borrow`).
- `catalog` (`CatalogPolicy`) — registry path + `high_risk_classes` (built-in classes:
  `wallet_signing`→`phantom-mcp`, `key_custody`→`x402-proxy-mcp`, `installer_script`→curl|bash).
  Classification is consumed by the catalog gate and `registry verify`.
- `supply_chain.verify_ext_submodules` / `ext_dir` / `exec_install_scripts` — per-`ext/`
  submodule verification toggle + dir + the runtime `curl … | sh/bash` gate setting.
- Every new field has a serde default so older/partial policy files still parse
  (`policy::tests::older_policy_without_new_fields_still_parses`). `Policy::load` fail-closed
  behavior is unchanged.

### `context`
```rust
pub enum Network { Mainnet, Devnet, Testnet, Localnet, Unknown }
impl Network { pub fn label(&self) -> &'static str; }

pub struct Context {
    pub network: Network,         // default for solana/spl-token: CLI config
    pub anchor_network: Network,  // default for anchor: Anchor.toml (upward), else CLI config
    pub plugin_data: PathBuf, pub project_dir: PathBuf,
}
impl Context { pub fn build(command: &str, cwd: &Path) -> Context; } // lazy: resolves only what the command needs

pub fn resolve_network(command: &str, cwd: &Path) -> Network;   // first solana-family command
pub fn explicit_network(argv: &Argv, base: Option<&Path>) -> Option<Network>; // -u/--url, -C file
pub fn cli_network(cwd: &Path) -> Network;                      // `solana config get`, 2 s timeout
pub fn anchor_network(cwd: &Path, cli: impl FnOnce() -> Network) -> Network; // ANCHOR_PROVIDER_URL only tightens
pub mod shell;  // parse(): quote-aware split, prefix/wrapper strip, recursion
pub fn plugin_data_dir() -> PathBuf;                            // datadir::data_dir().path
pub fn project_dir(cwd: &Path) -> PathBuf;
```
Never panics; `Unknown` on failure.

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

### `gates`
```rust
pub fn gates::bash::decide(command: &str, ctx: &Context, policy: &Policy) -> (Decision, GateMeta);
pub fn gates::bash::with_indirection_prefilter(decision, meta, command, cwd, policy) -> (Decision, GateMeta);
pub fn gates::secrets::decide(command: &str, cwd: &Path, policy: &Policy) -> Decision;
pub fn gates::read::decide_tool(tool: &str, input: Option<&Value>, cwd: &Path, policy: &Policy) -> ReadVerdict; // Decide | Rewrite
pub fn gates::read::decide_mcp_args(input: Option<&Value>, cwd: &Path, policy: &Policy) -> Decision;
pub fn gates::skill::decide(tool_input: Option<&Value>, cwd: &Path, dir: &DataDir, policy: &Policy) -> Verdict;
pub fn gates::tamper::decide_nested_claude(command: &str) -> Decision;                              // Deny | Ask | Defer
pub fn gates::mcp::decide(tool_name: &str, payload: Option<&serde_json::Value>, ctx: &Context, policy: &Policy) -> (Decision, GateMeta);
pub fn gates::tamper::decide_bash(command: &str, protected: &Protected) -> Decision;                  // Deny | Ask | Defer
pub fn gates::tamper::decide_bash_within(command: &str, protected: &Protected, budget: &mut Budget) -> Decision; // Deny | Ask | Defer
pub fn gates::tamper::decide_file(tool_input: Option<&serde_json::Value>, cwd: &Path, protected: &Protected) -> Decision; // Deny | Defer
```
> `secrets`/`read` return only `Decision`; `main.rs` wraps them in a `GateMeta` with
> `scope = SecretRead, hard_guard = true`.
> `tamper` is the self-grant tripwire: `secrets::decide` runs `decide_bash_within`
> first (with the hook payload's `cwd` as the session directory), sharing one work `Budget`
> (units plus a 2 s deadline) with its own scan; exhausting it asks ("command too complex to
> inspect"), never no opinion. `gate-tamper`
> (`Write|Edit|MultiEdit|NotebookEdit`) runs `decide_file`, audits as `tamper`, and skips
> `relax::apply`.

### `redact` / `promptguard`
```rust
pub fn redact::scrub(text: &str) -> Option<String>;
pub fn redact::scrub_response(response: &Value, values: &[KnownValue]) -> Option<Value>;
pub fn promptguard::check(prompt: &str) -> Option<String>;
```

`cmd_redact` reads `tool_response` (up to `redact::MAX_SCAN_BYTES`, larger passes unchanged),
scrubs literal values from the project's env files (`env::values`) and the pattern classes, and
answers in the tool's own shape. `redact::contains_key_material` (the `.env.schema` guard) and
`is_secret_key_name` (value scrub) share one key-name table (`names_secret_value`).

### `spend` / `rugcheck`
```rust
pub struct spend::SpendLedger { pub day: u64, pub total_sol: f64 }
pub fn spend::record_and_check(plugin_data: &Path, sol_amount: f64, policy: &Policy) -> Decision;
pub fn rugcheck::check_mint(mint: &str, policy: &Policy) -> Decision;
```

`rugcheck::check_mint` (trusted mints, score threshold) is implemented but has no callers yet: `gate-mcp`
records the mint, and swap tool calls get `ask`. `swap.rugcheck*` and `swap.trusted_mints` have no effect yet.

### Relaxation
```rust
// grants — grants.json is a statefile envelope
pub struct grants::Grant { pub id, pub scope: Scope, pub programs, pub to, pub max_tx_sol, pub budget_sol,
                           pub spent_sol, pub expires_at: u64, pub danger: bool }
pub struct grants::Grants { pub grants: Vec<Grant> }
pub struct grants::GrantRequest { pub scope, pub for_secs, pub max_tx_sol, pub budget_sol, pub programs, pub to, pub danger }
pub const grants::GRANTABLE_SCOPES: [Scope; 5];   // transfer swap deploy authority destructive
pub fn grants::grantable_scope(label: &str) -> Result<Scope, String>;   // `other`/unknown → Err
pub fn grants::load(dir: &DataDir) -> Loaded<Grants>;
pub fn grants::live(dir: &DataDir) -> Grants;       // Valid AND dir.trusted, else empty
pub fn grants::save(dir: &DataDir, grants: &Grants) -> Result<(), EngineError>;
pub fn grants::add(dir: &DataDir, grant: Grant, now: u64) -> Result<bool, EngineError>;
pub fn grants::find_match<'a>(grants: &'a Grants, meta: &GateMeta) -> Option<&'a Grant>;
pub fn grants::debit(dir: &DataDir, grant_id: &str, sol_amount: f64) -> Result<(), EngineError>;

// tierstate — tier.json is a statefile envelope (see "Tiers, sandbox state, headless and shared lists");
// `mode` is a deprecated alias shim over it, and the pre-tier mode.json is converted once by migrate

// relax — called by main.rs after every gate, and by prompt-guard
pub fn relax::apply(natural: Decision, meta: &GateMeta, policy: &Policy, dir: &DataDir) -> Decision;
pub fn relax::confirm_prompt(dir: &DataDir, prompt: &str, now: u64) -> Option<ConfirmOutcome>;

// spend — spend.json is a statefile envelope; SpendLedger::load repairs a deleted/tampered one
pub fn spend::ledger_state(plugin_data: &Path) -> LedgerState;  // Valid | Fresh | Deleted | Tampered

// migrate / notice — SessionStart
pub fn migrate::run(dir: &DataDir, now: u64) -> Vec<String>;      // 1.0 → envelopes, once
pub fn notice::loosenings(inputs: &notice::Inputs) -> Option<String>;
```
`relax::apply` contract: at the tier High the engine never emits `Allow` (no grant is consulted,
and a within-cap allow falls back to no opinion, so Claude Code's own flow decides); otherwise if
`natural` is not `Ask`, or `meta.hard_guard` is true, return it unchanged; otherwise the first live grant matching within budget/`max_tx_sol`
is debited (a failed debit keeps the ask) and the result is `Allow`.

**Confirmation flow.** `allow` and a tier lowering (`tier <lower>`, or an `env_read` loosening) call
`confirm::create_pending`, which stores an entry with a public id and **no code**; the CLI
prints the id and summary only. `confirm::announce_pending` (via `relax::announce`) runs in the
PostToolUse `pending-notice` hook (Bash), in `prompt-guard` and in `verify session`: it draws
an 8-digit code per unannounced entry, stores `sha256(code‖id‖HMAC(key,label))`, and the hook
puts the code in `systemMessage` only. `prompt-guard` passes `confirm::user_prompt` to
`relax::confirm_prompt` → `confirm::confirm_attempt`: only a whole-prompt single line
(`confirm::classify`, one whitespace rule) can confirm; a wrong code counts, and the third
cancels every entry (audited `state_tamper`/`confirm_lockout`). A confirmed entry's payload is
re-validated, stored, audited and echoed (no code). `verify trust|approve` kinds are not
handled here. The tripwire denies Bash invocations of the hook subcommands and
`confirm`.

### `verify`
```rust
pub enum Severity { Low, Medium, High }            // v1 report severities (add / install / verify check)
pub struct Finding { pub severity, pub kind, pub detail, pub path, pub line }
pub struct Report { pub findings: Vec<Finding> }

pub mod verify::rules;      // rule engine: scan_pack, scan_pack_until(deadline), grade, PackReport, ScanBudget
pub mod verify::grading;    // re-exports the rules types the state machine reads
pub mod verify::heuristics; // v1 compatibility view of rules (Report) for add / install / verify check
pub mod verify::state;      // state v2: PackEntry, PackStatus {Clean, Warned, Unreviewed, Blocked}, tree_hash, stat_fingerprint
pub mod verify::trust;      // trust.json by content hash
pub mod verify::enforce;    // gate-time checks: skill_verdict, read_verdict, bash_verdict
pub type verify::Scanner = fn(&Path, Option<Instant>) -> grading::PackReport;

pub fn verify::run_session(dir: &DataDir, project_dir: &Path, policy: &Policy) -> SessionResult;
pub fn verify::request_approve(dir, cwd, target, policy) -> Result<PendingRequest, EngineError>; // id only
pub fn verify::request_trust(dir, path) -> Result<PendingRequest, EngineError>;
pub fn verify::apply_confirmed(dir: &DataDir, c: &confirm::Confirmed) -> Result<String, EngineError>;
```

**`verify session` (state v2).** `run_session` sweeps each root in
`supply_chain.verify_skills_dirs` (project `.claude/skills`; `~/.claude/skills` only when a
project overlay opts in, plus packs `install --from` put there) and each `ext/<name>` submodule,
and the project `.mcp.json`. Per pack, the content hash runs first, then the scan (bounded by the
pack allowance, the sweep budget and the hook deadline); `state::decide` moves the entry:
first-seen clean → `clean`; doc-only findings → `warned`; a code HIGH → `unreviewed` (warned, not
denied); a combination rule, drift from the pin, or a `packs.lock` mismatch → `blocked`. A pack
not fully scanned in time is recorded unscanned (`unreviewed` + `scan_budget_exceeded`) and
denied like a blocked one until a sweep scans it. Gates never move packs; only
`supply_chain.on_block: move` does, at the sweep. v1 lockfile pins are carried over on first
sight. `verify approve|trust` create pending requests; `relax::confirm_prompt` performs them via
`apply_confirmed`, which never clears a combination rule (a combo-blocked pack moved to
quarantine is refused at request time).

**Gate-time enforcement (`enforce`).** The Skill tool and a typed `/name` map the name to the
packs providing it; a pack whose stat fingerprint changed since it was verified is re-hashed and
re-graded on the spot within 5 s, and any blocked, unscanned or unverifiable provider denies. A
pack whose stat walk is cut makes every unresolved non-plugin name deny. Read/Grep/Glob and Bash
deny access inside blocked or unscanned packs from the stored state only (no hashing).

### `registry` (opt-in catalog)
```rust
pub struct RegistryEntry {
    pub id: String, pub title: String, pub source: String, pub category: String,
    pub default_installed: bool,
    pub safety: Option<String>, pub description: Option<String>, pub tags: Vec<String>,
    pub risk_class: Option<String>,   // DERIVED (not on disk); set by Registry::high_risk
}
pub struct Registry { pub entries: Vec<RegistryEntry> }
pub fn registry::parse(json: &str) -> Result<Registry>;
pub fn registry::Registry::load(path: &Path) -> Result<Registry>;
pub fn registry::Registry::high_risk(entry: &RegistryEntry, policy: &Policy) -> Option<String>;
```
The on-disk catalog shape is `{ version, updated, entries: [ … ] }`; each entry carries
`id`/`name`/`type`/`domain`/`description`/`source`/`install`/`license`/`maintainer`/`signal`/
`default_installed`/`safety`/`tags`. `RegistryEntry` keeps the subset safe-ai-skill gates on (JSON
`name`→`title`, `type`→`category`); unknown fields are tolerated. `high_risk` classifies an
entry against `policy.catalog.high_risk_classes` (id match or case-insensitive keyword match
against safety/description/tags) and returns the matching class `kind`. `risk_class` is `None`
until classified.

### `squads` / `session`
```rust
pub fn squads::upgrade_authority_advisory(program: &str, ctx: &Context) -> Option<String>;
pub fn session::init(cap_sol: f64, dir: &DataDir) -> error::Result<String>;
pub fn session::status(dir: &DataDir) -> error::Result<String>;
```

`squads::upgrade_authority_advisory` has no callers yet; no Squads routing happens. `session init
--cap` records metadata only: no gate reads it, so it relaxes nothing.

---

## Subcommands (`main.rs`, complete)

`gate-bash` · `gate-bash-secrets` · `gate-read` · `gate-mcp` · `gate-tamper` · `gate-skill` ·
`gate-prompt-expansion` · `redact` · `prompt-guard` · `pending-notice` ·
`verify session|check|approve|trust` · `env keys|set|unset|init-schema` · `doctor` · `add skill|mcp|repo <source>` ·
`install [--from <dir|tarball>] [--home <dir>] [--yes]` · `registry verify|list` ·
`session init [--cap <SOL>]|status` · `allow --scope --for --max-tx --budget --programs --to [--danger]` ·
`tier [<name>] [--project] [--env-read deny|ask|tier] | --clear` (`mode` is a deprecated alias) · `revoke` · `status` · `--version`. `allow`, a tier lowering and
`verify approve|trust` only park a pending request (prompt-nonce confirmation) and print its id;
an argument error exits 1.

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
`high_risk` classification.
