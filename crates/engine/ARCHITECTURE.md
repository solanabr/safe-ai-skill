# safe-ai-skill engine — architecture

`safe-ai-skill` is the Rust security engine behind the **safe-ai-skill** Claude Code plugin. It is
a single binary (hot path: gates fire on every Bash/Read/MCP call) plus a thin library so
tests and the binary share one module tree.

This document maps the modules, the hook contract and the state they share. Signatures below
describe the tree on this branch (unreleased changes included); the source and rustdoc are authoritative.

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
0.6` (`getrandom`), `ureq 2` (`default-features = false, features = ["tls"]` → rustls),
`miniz_oxide 0.8` (`with-alloc` only: zlib inflate for the git object reader), and `libc` on
unix. No tokio, no async. A new dependency needs review (binary size, supply chain).

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

For a PreToolUse gate (`gate-bash` / `gate-bash-secrets` / `gate-read` / `gate-mcp` / `gate-webfetch` / `gate-tamper` / `gate-skill`):

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
  exit 126/127): fail open with a notice. `gate-skill` answers `ask`, `gate-bash` answers `ask`
  when the payload names `solana`, `spl-token`, `anchor` or `keygen` (or holds `$'…'`) and
  nothing otherwise, SessionStart reports the firewall INACTIVE, every other hook exits 0 with
  one stderr line.
- **Tamper** (the prebuilt's sha256 differs from the constant `scripts/stamp-shim.sh` stamped at
  release): the prebuilt never runs; `gate-bash`, `gate-mcp` and `gate-skill` exit 2, the other
  PreToolUse gates ask, non-PreToolUse hooks exit 0 with a stderr line.
- **Engine crash** (signal, or exit not in {0, 2, 3}): `gate-bash`, `gate-mcp` and `gate-skill`
  exit 2 (block); the rest exit 0 with a stderr line.
- **Contracts by event.** Three entries are not PreToolUse gates and answer in their own channel:
  - `gate-permission` (`PermissionRequest`, which ignores exit 2): a tamper, crash or strict case is
    `{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny",…}}}`
    with exit 0; when the engine cannot run it prints nothing, so Claude Code shows its own prompt.
  - `gate-config` (`ConfigChange`): a tamper or crash is `{"decision":"block","reason":…}` with
    exit 0, the answer that event honours; when the engine cannot run it continues (strict mode
    exits 2, which that event also honours).
  - `session-end` (`SessionEnd`): informational, always continues.
- **Verified-hash cache.** After a full sha256 match the shim records the binary's fingerprint (device, inode, size, mtime, ctime from `stat` at a fixed system path) beside the stamped hash in `$CLAUDE_PLUGIN_DATA/shim-verified-<platform>` (0600, owned by the binary's owner, not a symlink). A later call skips the hash and the executable-format probe only when that line equals the stamped hash plus the current fingerprint; anything else is a full check and only a pass is cached. A binary whose ctime does not predate the check is never cached. Off on Windows and when `CLAUDE_PLUGIN_DATA` is unset, relative or unwritable; `SAFE_AI_SKILL_SHIM_CACHE=0` turns it off from any source. See SECURITY.md for the residual.
- **Tools come from fixed system directories.** `fixed_tool` resolves `uname`, `grep`, `od`, `tr`, `cut`, `stat` and `date` (and the sha256 tool) from `/usr/bin`, `/bin` and `/run/current-system/sw/bin`, never from `PATH`, which a repository's settings `env` can set. Under the test seam (a `.sha-tools-from-path` file beside the shim) they come from `PATH`. A host with no `uname` there is an environment failure (reported as `no uname in …`), not an unsupported-platform fail-open; a missing `grep`, `od`, `tr` or `cut` degrades only the helper that used it.
- `SAFE_AI_SKILL_STRICT=1` turns every unusable case into exit 2. `SAFE_AI_SKILL_DISABLE=1`
  turns the hooks off, but is ignored in strict mode or when the committed project
  `.claude/settings.json` mentions it; SessionStart reports either way.
- The single unconditional `Bash` `gate-bash` entry, the `Skill` matcher and `gate-permission`
  set `onFailure: block`, the others `continue`; so a crashing engine blocks every Bash call.
  `PermissionRequest` ignores exit 2, so the shim answers a crash, tamper or strict case there
  with a deny JSON (exit 0); `session-end` is informational and always continues.
  `gate-bash` has a fast path (`bash::may_concern`) that answers no opinion before loading
  policy, lists or state for a command that cannot concern it. `onFailure`
  needs Claude Code 2.1.295 or newer; older versions ignore it, so a hook that can't start
  never blocks.

`hooks.json` entries (matcher, subcommand, `onFailure`): `Bash` → `gate-bash` (block), `gate-bash-secrets`; `Write|Edit|MultiEdit|NotebookEdit` → `gate-tamper`; `Read|Grep|Glob` → `gate-read`; `WebFetch` → `gate-webfetch`; `mcp__.*` → `gate-mcp`; ConfigChange (`user_settings|project_settings|local_settings`) → `gate-config`; `Skill` → `gate-skill` (block); PermissionRequest → `gate-permission` (block); SessionEnd → `session-end`; PostToolUse `Bash|Read|Grep|mcp__.*` → `redact`, `Bash` → `pending-notice`; PostToolUseFailure → `failure-notice`; UserPromptSubmit → `prompt-guard` and `gate-prompt-expansion`; UserPromptExpansion → `gate-prompt-expansion`; SessionStart → `verify session`. Every entry other than `gate-bash`, `gate-skill` and `gate-permission` is `continue`. The Codex template (`adapters/codex/hooks.json`) wires `gate-bash`, `gate-bash-secrets`, `gate-tamper` (on `apply_patch`) and `gate-mcp` only; the opencode plugin wires those plus `gate-read`. Neither has `gate-webfetch`.

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
- **PostToolUseFailure failure-notice** (Bash, Read, Grep, MCP): no output, or, when the error
  text holds what `redact` would scrub, `{"systemMessage":"…","hookSpecificOutput":{"hookEventName":"PostToolUseFailure","additionalContext":"…"}}`
  (a warning, never a value; the event cannot replace the output).
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
under `$CLAUDE_CONFIG_DIR/plugins/data` / `~/.claude/plugins/data`, else (no Claude Code plugin)
the standalone dir: `$SAFE_AI_SKILL_DATA`, else `safe-ai-skill-data` under the platform data
root; never a relative path. `DataDir::trusted` holds only inside
`<passwd home>/.claude/plugins/data`, for the standalone default under the passwd home, or for
an env-placed dir (`$CLAUDE_CONFIG_DIR/plugins/data/*`, `$SAFE_AI_SKILL_DATA`, …) under the
passwd home and not inside the project or hook cwd (see `datadir` docs). Hooks resolve with `data_dir_with_cwd(Some(cwd))`. Authenticated files go through `statefile` (`{v, mac, body}`, HMAC-SHA256, key in
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
| `reports/<sid>.json`, `reports/<sid>.start.json`, `reports/last-<project hash>.json` | `report` | session report written at SessionEnd, start marker written at SessionStart (time, project hash, spend and grant-budget snapshot), and the per-project pointer the next recap reads. The project is stored as a hash, never a path. Newest 200 reports kept, markers pruned after 30 days. Informational: nothing reads them to decide |
| `*.lock` | `statefile::FileLock` | `state.lock` (stores), `pending.lock`, `grants.lock` |

---

## Tiers, sandbox state, headless and shared lists

The firewall takes a tier as an **input**; solana-ai-kit owns the sandbox, permission rules and tier selection UX. User-facing behaviour is in `docs/tiers.md` and the README table; this section maps the modules. Signatures are in the source (rustdoc).

| Module | Role |
|---|---|
| `policy/tier.rs` | `Tier {Off, Relaxed, Medium, High}` (`Ord`; aliases `strict`, `paranoid`, `autopilot`), `TierSource`, and `resolve(root, &DataDir, env) -> (Tier, EnvRead, Vec<Note>)`: `base` (`relaxed`), then the user value from `tier.json` (`projects[root]`, else `global`), then `max()` with the raise-only hints (kit `.claude/security.json` `tier`/`declared.tier`/`enforced.tier`, repo `policy.yaml` `tier`, env `SAFE_AI_SKILL_TIER`). A lower hint is ignored with a note. The table in the README is checked against the table in this file. |
| `tierstate.rs` | The authenticated `tier.json` v1 under the statefile MAC and generation index; the writer behind `safe-ai-skill tier`. A raise applies at once; a lowering or an `env_read` loosening (`deny` < `tier`; a stored 1.1.0 `ask` loads as `tier` and is rewritten at SessionStart) becomes a `confirm::PendingKind::Tier` request. `mode.rs` stays as a deprecated alias. |
| `sandbox.rs` | `state(root) -> {On, Off, Unknown}` from the first `sandbox.enabled` in managed, project-local, project, then user settings (passwd home, never env `HOME`; `$CLAUDE_CONFIG_DIR`). `On` also needs macOS or Linux with `bwrap` on a fixed path, never native Windows. Declared configuration, not a runtime proof. A test override exists only under `test-hooks`. |
| `headless.rs` | `is_headless(env)`: any of `SAFE_AI_SKILL_HEADLESS`/`KIT_FIREWALL_HEADLESS` (`1`/`true`) or a CI variable not `0`/`false`. The shared rule's `/dev/tty` signal is not wired (hook processes never have a terminal, so it would deny every interactive ask). Any signal turns it on, nothing turns it off. `main.rs` post-processes every PreToolUse verdict: `ask` becomes `deny`; a grant confirmed earlier still allows below High. |
| `lists.rs` | Parses the embedded `policy/shared/{credentials,exfil-hosts,onchain-verbs}.list` (`include_str!`, `OnceLock`) and checks `MANIFEST` counts and sha256. Accessors for credentials, exfil hosts per tier, `irreversible()` and `recoverable()`. A parse failure is `ListsUnavailable`: the dependent gates answer a hard-guard `ask`. User or repo `secrets.exfil_hosts_extra` and `secrets.key_material_extra_globs` union in; nothing removes an entry. |
| `gates/credpaths.rs`, `gates/creddump.rs` | Credential path classification and directory-Grep exclusion globs from `credentials.list`; the command-form readers (`gh auth token`, `git credential fill`, `security … -w`, `op read`, …) and any Bash word or `NAME=` prefix value naming a store (metadata-only programs excepted; an `ssh`/`scp`/`sftp` identity and `ssh-keygen -y -f` exempt). Deny at every tier. |
| `gates/envread.rs`, `gates/envwrite.rs` | Project env files (`.env`/`.env.*` inside the project root, by name and resolved path) by tier, as solana-ai-kit: raw reads `(tier, env_read, project)` open at Off/Relaxed/Medium and denied at High (`env_read: deny` denies at every tier; other env files always deny); writes (Write/Edit/MultiEdit, agent `env set\|unset`, the Bash writes `creddump` recognises) denied at Medium (other env files Medium and High). A command line that reads an env file and runs a network program or network code denies at every tier. |
| `gates/wallet.rs`, `gates/bash.rs` | Default-wallet destruction (deny at every tier); irreversible actions (Class U in docs/tiers.md; `irreversible` rows: deny on mainnet or Unknown, hard-guard ask on identified localnet/devnet/testnet, never grantable; `class_u` in `bash.rs`) and `spl-token transfer` amounts (token units, no opinion on identified devnet/testnet/localnet, ask elsewhere) and value-moving actions (Class C; caps, grants, mainnet/Unknown ask, High deny). A line joining two or more gated actions, or any hard-guard ask, is never grantable; a command over 256 KiB or with more than 2048 expansions asks unparsed. |
| `gates/exfil.rs` | The exfil tripwire (#19): `decide_bash` (called from `gate-bash-secrets`), `decide_mcp` (`gate-mcp`) and `decide_webfetch` (`gate-webfetch`). Host list per tier from `exfil-hosts.list`, secret-shaped data and blobs to non-developer hosts, `git push` to a same-line remote, browser scripts. Secret uploads by path are denied by `gates/secrets.rs`; an env read beside a network command by `gates/creddump.rs` (`envread::to_network`). |
| `gates/tamper.rs` | The self-grant tripwire (protected paths: `decide_bash`, `decide_file`, `decide_nested_claude`) and the content-aware checks (`decide_file_content`, `decide_bash_writes`): settings, hooks, git config, `.mcp.json`, lifecycle scripts, kit tier. `gate-tamper` covers Write/Edit/MultiEdit/NotebookEdit; `gate-bash-secrets` the Bash forms. |
| `gates/fetchexec.rs` | Download-and-run (`decide`): a download then run, a downloaded script piped to an interpreter, undeclared one-shot runners, `cargo install --git` outside the allowlist, mainnet Node scripts. Called from `gate-bash-secrets`. |
| `gates/shellcmd.rs` | The one list of gates a shell command text goes through, shared by `gate-bash-secrets` (`tier_verdict`), `gate-bash` (`encoded_verdict`), `PermissionRequest` (`flat_verdict`, its caller walks nested commands) and the MCP command runners (`mcpexec`, `tier_verdict`). `inner_verdict` judges a text found inside another (a decoded payload, a `git submodule foreach` or `rebase --exec` string) through `bash::decide`, `secrets::decide` and the whole list; `strictest` picks the verdict (deny over ask, the later on a tie). A gate added to the list reaches every entry. |
| `gates/encoded.rs` | Encoded payloads: `expand` returns decoded texts (depth 3, 64 KiB), including payloads that reach a shell behind a wrapper, `source`, a process substitution, a command word or a subshell or group, and `decide` asks on an undecodable one. `shellcmd::encoded_verdict` runs each decoded text through `shellcmd::inner_verdict` and takes the strictest verdict. |
| `gates/envread.rs` (env dumps) | `decide_bash`: `/proc/*/environ`, `ps e`, printing a secret-named variable (deny) and a dump piped away or written to a file (ask). The names come from `redact::is_secret_env_name`; the matching value blanking is `redact::scrub_env_lines`. |
| `gates/mcp.rs`, `gates/mcpexec.rs` | MCP name/action classification (`mcp.sensitive_name_pattern`, routed actions, staking and token transfers as hard guards) and the Bash checks for shell code run through an MCP executor: a blocked pack, a nested `claude`, and `shellcmd::tier_verdict`, with gate state in the caller's data dir. |
| `verify/` (`tier_action`, `gittracked.rs`) | Per-tier supply-chain action (report at Off, deny in place from Relaxed, HIGH heuristic denies at High); `on_block: move` never moves a git-tracked pack or submodule path (reads `.gitmodules` and `.git/index`, never runs git). |
| `verify/gitobj.rs`, `verify/history.rs` | Read-only git object reader (loose objects, `.idx` v1/v2 + `.pack` v2/v3, OFS/REF deltas; no git process, `gitdir:`/`commondir` confined to the pack or its submodule dir, FIFO-safe opens) under a time/byte/object `Budget` that every tree walk charges, and the history scan `verify::check::check_dir` (`verify add|check`, `install`, once per directory via `check_dir_with`; never the sweep) runs over it: every blob through `rules::scan_blob` under each distinct name, docs-described commits that touch code (`docs_commit_code` report-only, combo `docs_commit_sink` on added lines), and `history_unscanned` for anything left unread. |

**Invariants the tests pin:** every `deny` row holds at Off; no repo file, kit file or env variable lowers a tier or loosens `env_read`; a lowering is pending until a whole-prompt confirm; raising never prompts; High emits no `allow`; no tier emits `defer`; nothing moves by default; the exfil host list never shrinks below the shared file; the embedded lists equal `policy/shared/*` byte for byte; headless never yields `ask`; the kit's `.safe-ai-skill/policy.yaml` loads unchanged. The conformance corpus is `policy/shared/corpus/*.jsonl`, run by `tests/shared_corpus.rs` (plugin column under `--features test-hooks`; rows the shipped engine answers differently from the end state carry `interim.plugin` and a reason). `tests/tiers_matrix.rs` runs the per-tier brief rows through the `hooks.json` entries, and `tests/readme_tier_table.rs` pins the README table to `GATE_TABLE`.

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
    pub tool_response: Option<serde_json::Value>, pub prompt: Option<String>,
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

```rust
pub const DEFAULT_POLICY_YAML: &str;     // embedded default (literal; crate is standalone)
// policy::tier: TIER_ENV = "SAFE_AI_SKILL_TIER", PROFILE_ENV = "SAFE_AI_SKILL_PROFILE" (alias);
// both are raise-only tier hints.

pub struct Policy {
    pub version: u32,
    pub network: NetworkPolicy, pub spend: SpendPolicy,
    pub mcp: McpPolicy, pub swap: SwapPolicy, pub secrets: SecretsPolicy,
    pub redact: TogglePolicy, pub audit: TogglePolicy,
    pub catalog: CatalogPolicy,
    pub supply_chain: SupplyChainPolicy,
    // serde-skipped:
    pub ignored_overrides: Vec<String>,     // refused project/env overrides and removed settings
    pub base_tier: Tier,                    // the base policy's `tier` (legacy `active_profile` alias)
    pub repo_tier_hints: Vec<RawHint>,      // the project overlay's `tier`/`active_profile`: raise-only
    pub repo_env_read: Option<EnvRead>,     // the project overlay's `secrets.env_read`: tighten-only
    pub runtime: TierContext,               // resolved tier, source, env_read, sandbox, headless
    // private: scan dirs the project added (confined on disk by `load`)
}
pub struct NetworkPolicy { pub default: String, pub mainnet: String }
pub struct SpendPolicy { pub per_tx_sol_max: f64, pub hard_tx_sol_max: f64, pub daily_sol_max: f64 }
pub struct McpPolicy { pub sensitive_name_pattern: String }   // verbs expanded (see below)
pub struct SwapPolicy { pub rugcheck: bool, pub rugcheck_max_score: u32, pub rugcheck_timeout_ms: u64, pub trusted_mints: Vec<String> }
pub struct SecretsPolicy {
    pub env_read: String,                   // `tier` (default) or `deny`; a project can only tighten; the user's choice is tier.json
    pub deny_read_globs: Vec<String>, pub allow_read_globs: Vec<String>,
    pub key_material_extra_globs: Vec<String>, // union with credentials.list
    pub exfil_hosts_extra: Vec<String>,     // union with exfil-hosts.list (read by the exfil tripwire; ignored at Off)
}
pub struct TogglePolicy { pub enabled: bool }
pub struct SupplyChainPolicy {
    pub verify_skills_dirs: Vec<String>,
    pub flag_unpinned_mcp: bool,            // @latest detection: INFORMATIONAL/LOW (MCPs kept @latest), not blocking
    pub flag_telemetry_curl: bool,
    pub verify_ext_submodules: bool,        // walk ext/<name> as individual units (serde default true)
    pub ext_dir: String,                    // ".claude/skills/ext" (serde default)
    pub exec_install_scripts: String,       // runtime curl|bash gate: "allow"|"ask"|"deny" (serde default "ask")
    pub on_block: String,                   // "deny" (default) | "move" (user scope only)
}
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

// Load the policy and resolve its tier context (tier::resolve against the project root).
pub fn load_runtime(cwd: &Path, dir: &DataDir, env: &dyn Fn(&str) -> Option<String>,
                    sandbox: SandboxState, headless: bool) -> (Policy, tier::Resolution);
pub fn base() -> Policy;                    // the plugin default alone, no project overlay

impl Policy {
    // The plugin default (or the embedded one), then <cwd>/.safe-ai-skill/policy.yaml ratcheted
    // over it; project scan dirs are kept only if they resolve on disk inside cwd.
    pub fn load(cwd: &Path) -> Policy;
    // Pure (no env, no fs): base + ratcheted project overlay. Project scan dirs get the text
    // check only; on-disk confinement happens in `load`.
    pub fn from_sources(base_src: &str, project_src: Option<&str>) -> Policy;
    pub fn fail_closed() -> Policy;             // conservative; every soft gate → ask
    pub fn is_fail_closed(&self) -> bool;
    pub fn tier(&self) -> Tier;                 // runtime.tier
    pub fn ignored_notice(&self) -> Option<String>; // SessionStart block listing ignored_overrides
}
```
**Fail-closed guarantee:** an unparsable plugin default returns `fail_closed()` (caps zero,
mainnet `ask`, base tier `relaxed`). A *project override* that is not
valid YAML (or not a mapping) is ignored; one with ill-typed values fails closed through the
ratchet, so no other field ends up looser than the base. Either way it is noted.

**Project ratchet.** `.safe-ai-skill/policy.yaml` is repo-controlled, so it may only
tighten the base, field by field: caps take the lower value (and still bind at any
tier); `network.mainnet` / `exec_install_scripts` move only toward `deny`;
`network.default` only to mainnet; deny-lists (`secrets.deny_read_globs`,
`mcp.sensitive_name_pattern` alternatives) add entries; allow-lists
(`secrets.allow_read_globs`, `swap.trusted_mints`) drop them; toggles can only turn on;
`verify_skills_dirs` keeps every base dir and may add dirs strictly inside the project
(lexically in `from_sources`, then canonicalized on disk in `load`). Fields with no
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
pub fn gates::tamper::decide_bash_writes(command: &str, cwd: &Path, policy: &Policy, tier: Tier) -> Option<Verdict>;   // content-aware Bash writes
pub fn gates::exfil::decide_bash(command: &str, cwd: &Path, policy: &Policy, tier: Tier) -> Option<Verdict>;
pub fn gates::exfil::decide_mcp(tool: &str, payload: Option<&Value>, cwd: &Path, policy: &Policy, tier: Tier) -> Option<Verdict>;
pub fn gates::exfil::decide_webfetch(url: &str, prompt: &str, policy: &Policy, tier: Tier) -> Option<Verdict>;
pub fn gates::fetchexec::decide(command: &str, cwd: &Path, policy: &Policy, tier: Tier) -> Option<Verdict>;
pub fn gates::gitguard::decide(command: &str, cwd: &Path, policy: &Policy, tier: Tier) -> Option<Verdict>;     // git and gh, run by gate-bash-secrets
pub fn gates::gitguard::decide_git_config_risk(command: &str, tier: Tier) -> Option<Verdict>;                  // exec-capable config keys (tamper shares it)
pub fn gates::gitguard::inner_commands(command: &str) -> Vec<String>;      // `submodule foreach` / `rebase --exec` strings, re-judged by every Bash gate
pub fn gates::mcp::decide_name(tool_name: &str, tier: Tier) -> Option<Verdict>;   // NAME_RULES: refuse a tool by name from a tier up, before its arguments
pub fn gates::tamper::decide_nested_claude_flags(command: &str, tier: Tier) -> Option<Verdict>; // weakening flags, `claude mcp add`, `setup-token`, `plugin disable`
pub fn gates::configchange::decide(input: &Value) -> Option<Verdict>;      // ConfigChange: Deny only when the file adds a disabling switch its snapshot lacks
pub fn gates::configchange::record_baseline(cwd: Option<&Path>, homes: &ConfigHomes, dir: &DataDir); // SessionStart: snapshot the switches the settings files hold
pub fn gates::shellcmd::tier_verdict(command: &str, cwd: &Path, policy: &Policy, dir: &DataDir) -> Option<Verdict>; // the shared Bash-command gate list
pub fn gates::encoded::expand(command: &str) -> Vec<String>;      // decoded payload texts
pub fn gates::encoded::decide(command: &str) -> Option<Verdict>;  // undecodable payload → Ask
pub fn gates::envread::decide_bash(command: &str) -> Option<Verdict>;   // env dumps
pub fn gates::containers::decide(command: &str, cwd: &Path, policy: &Policy, tier: Tier) -> Option<Verdict>; // container privilege guard, run by gate-bash-secrets
pub fn gates::keyfiles::decide_bash(command: &str, cwd: &Path, tier: Tier) -> Option<Verdict>;         // git add / commit -a / stash -u|-a of a key file, via shellcmd
pub fn gates::keyfiles::session_notice(cwd: &Path, plugin_data: &Path) -> Option<SessionNotice>;       // SessionStart notice (bounded sweep), once per project and finding set
pub fn gates::permreq::decide(tool: &str, tool_input: Option<&Value>, permission_mode: Option<&str>, cwd: &Path, policy: &Policy, dir: &DataDir) -> Option<Value>; // PermissionRequest answer
pub fn report::session_start(dir: &DataDir, session_id: &str, cwd: &Path, now: u64) -> Option<String>; // start marker + recap line
pub fn report::session_end(dir: &DataDir, raw: &[u8], now: u64) -> Option<SessionReport>;              // writes reports/<sid>.json
```
> `secrets`/`read` return only `Decision`; `main.rs` wraps them in a `GateMeta` with
> `scope = SecretRead, hard_guard = true`.
> `gitguard` is in the `shellcmd` list, so `gate-bash-secrets`' tier verdict runs it, and its
> `inner_commands` strings go back through `shellcmd::inner_verdict`, the same path decoded
> payloads take. Off acts as Relaxed. `mcp::decide_name` runs first in `gate-mcp`, as a hard
> guard. `tamper` also owns the `Surface` table (code-on-next-build files, managed settings,
> a project's `.safe-ai-skill/`, and at High the user-scope `~/.claude` policy surface), applied
> by `decide_file_content_at` and `decide_bash_writes` with the tier. `gate-config` reads
> the settings file named by the `ConfigChange` payload and compares the switches
> `tamper::settings_disable_reasons` finds in it with a snapshot (`configchange.json`, MAC'd,
> trusted data dir only, at most 64 paths) of what it held when a change was last let through;
> it answers `{"decision":"block","reason":…}` only for a switch the snapshot lacks. The
> snapshot is written on a let-through and by `configchange::record_baseline`, called from
> `verify session` before the agent acts, and never on a block; with no snapshot every switch
> is new. It has no previous text, so it cannot see a removal. `fetchexec` reads
> `Cargo.toml`/`Cargo.lock`, `go.mod` and the Python manifests for its High rules. `credpaths`
> adds the stores that environment variables move (`ENV_STORES`, rebuilt only when one of
> those variables changes) and a hard-link check by device and inode.
> `containers` and `keyfiles::decide_bash` are two more entries of the `shellcmd` list
> (run on inner commands too, and by `PermissionRequest` and the MCP runners), so they inherit its
> headless post-processor and its Codex and opencode reach. `containers` reads compose files
> (512 KiB cap) and judges services as it judges flags. `keyfiles` never runs git: it reads the
> index through `verify::gittracked`; its SessionStart sweep is capped at depth 8, 20,000
> entries, 64 content sniffs and 250 ms (the tracked-file pass shares that budget, then judges
> by bare name), and `session_notice(cwd, plugin_data)` returns a `SessionNotice { user, model }`
> reported once per project and finding set (`tips/keyfiles-<project hash>`); `verify session`
> prints only `user`. `DOMAIN_PACKS` is the (empty) slot a domain pack
> fills with its own key-file patterns.
> `permreq` is the `PermissionRequest` gate (`gate-permission`, `onFailure: block`). It does not
> go through `gate::decide` or `relax::apply`: it calls the PreToolUse gates' decision functions
> itself, keeps only hard-guard results (a deny, or an ask whose `GateMeta` is not grantable),
> and answers `hookSpecificOutput.decision.behavior = "deny"` when the session is unattended
> (headless, `dontAsk`, unknown mode) or a gate denies in `auto`/`acceptEdits`/`bypassPermissions`,
> else a `systemMessage` warning or nothing. It never emits `allow`. Its gate `Context` is built
> with `Context::build_in` in the data dir the hook resolved, so a test with an unresolved dir
> stores nothing. Its denies are audited as
> `permission_request`.
> `report` runs on the SessionStart and SessionEnd hooks only, never on a gate path. `session-end`
> prints nothing (Claude Code discards SessionEnd output and allows it 1.5 s) and always exits 0;
> the SessionStart recap travels in `systemMessage` only.
> `tamper` is the self-grant tripwire: `secrets::decide` runs `decide_bash_within`
> first (with the hook payload's `cwd` as the session directory), sharing one work `Budget`
> (units plus a 2 s deadline) with its own scan; exhausting it asks ("command too complex to
> inspect"), never no opinion. `gate-tamper`
> (`Write|Edit|MultiEdit|NotebookEdit`) runs `decide_file`, audits as `tamper`, and skips
> `relax::apply`.

### `firewall`
```rust
pub fn firewall::run(cmd: &Command, ctx: &Ctx) -> Outcome;          // Ok | Drift | Park | Error
pub fn firewall::parse_args(rest: &[String]) -> Result<Command, String>;
pub fn firewall::session_note(ctx: &Ctx) -> Option<String>;          // SessionStart drift line (T3)
pub fn firewall::session_resync(ctx: &Ctx) -> Option<String>;        // re-apply an older rule set or a lower enforced tier (T6); never lowers
```
`safe-ai-skill firewall apply|show|check` writes the sandbox block and permission denies a
plugin cannot ship into the project's `.claude/settings.local.json` (`target.rs` finds it, at the
main checkout's root for a linked worktree). `rules.rs` holds the per-tier tables
(`RULE_SET_VERSION`) ported from the kit; `merge.rs` adds and removes only the entries the record
names and keeps user rules; `json.rs` edits the file preserving key order and indentation.
It never writes `sandbox.enabled: false` (Off removes the key), writes atomically, and refuses a
symlinked `.claude` or settings file. The record (tier, rule-set version, entries, scalars) is the
MAC'd state file `firewall.json` in the data dir, never a key in the settings file. Raising applies
at once; lowering parks a `PendingKind::Firewall` request for the confirmation code. Rule set 2
writes the project root and the repository's `.git` as absolute paths (`MachineInputs`,
`Target::git_dir`) and retires the relative `.git` entry (`RETIRED`, still owned until removed).
`json.rs` reads a repeated key as its last occurrence, as Claude Code does; `apply` refuses a file
that repeats a managed key (`duplicate_keys`) and `check` reports `duplicate-key` drift. `check`
exits non-zero on drift. At High the output carries a caveat: Claude Code ignores repository
`allowRead`/`allowWrite`, and counts `settings.local.json` as repository settings outside git or
when tracked.

### `redact` / `promptguard`
```rust
pub fn redact::scrub(text: &str) -> Option<String>;
pub fn redact::scrub_response(response: &Value, values: &[KnownValue]) -> Option<Value>;
pub fn redact::scrub_env_lines(text: &str) -> Option<String>;   // env-dump value blanking (Bash output)
pub fn redact::is_secret_env_name(name: &str) -> bool;          // shared with gates::envread
pub fn promptguard::check(prompt: &str) -> Option<String>;
```

Seed phrases are found by `seedphrase::find` (behind `redact::find_seed_phrases`, shared with
`promptguard`), which uses `bip39`: the embedded official English wordlist
(`src/bip39_english.txt`), the mnemonic checksum, and the published test vectors that
`promptguard` lets through.

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
pub enum Severity { Low, Medium, High }            // provenance / osv.dev / .mcp.json report severities
pub struct Finding { pub severity, pub kind, pub detail, pub path, pub line }
pub struct Report { pub findings: Vec<Finding> }

pub mod verify::rules;      // rule engine: scan_pack, scan_pack_until(deadline), grade, PackReport, ScanBudget
pub mod verify::grading;    // re-exports the rules types the state machine reads
pub mod verify::check;      // check_dir: one dir graded as the sweep's first sight + tier_action (verify check / add / install)
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

`gate-bash` · `gate-bash-secrets` · `gate-read` · `gate-mcp` · `gate-webfetch` · `gate-tamper` · `gate-skill` · `gate-config` ·
`gate-prompt-expansion` · `gate-permission` · `session-end` · `redact` · `failure-notice` · `prompt-guard` · `pending-notice` ·
`verify session|check|approve|trust` · `env keys|set|unset|init-schema` · `doctor` · `add skill|mcp|repo <source>` ·
`install [--from <dir|tarball>] [--home <dir>] [--yes|--force]` · `registry verify|list` ·
`session init [--cap <SOL>]|status` · `allow --scope --for --max-tx --budget --programs --to [--danger]` ·
`tier [<name>] [--project] [--env-read deny|tier] | --clear` (`mode` is a deprecated alias) · `firewall apply [<tier>] [--project] [--dry-run] | show | check` · `revoke` · `status` · `--version`. `allow`, a tier lowering and
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
widens `settings.json`. Each skill dir goes through `verify::check::check_dir` (the sweep's
first-sight grading at the current tier): clean is taken, warned (or unreviewed below High)
needs `--yes`, and a pack the tier denies or any combination BLOCK (Off included) needs
`--force`. A pack the project's `packs.lock` pins is not neutralized (`not_neutralized`).

**`registry verify|list`.** Loads the project `skill-registry.json` (path from
`policy.catalog.registry_path`) via `registry::Registry::load` and lists/audits entries with
`high_risk` classification.
