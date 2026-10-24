# Shared conformance corpus

One JSON object per line, eight topic files. The plugin's engine runner
(`crates/engine/tests/shared_corpus.rs`) and the kit's runner both read these files; changing an
`expect` needs both owners. Version: the contract's (see `../MANIFEST`).

| File | Topic |
|---|---|
| `cluster.jsonl` | cluster resolution precedence, Class C (recoverable) actions, grants, caps |
| `wrappers.jsonl` | wrapper and tokenizer normalisation: `env`, `timeout`, `bash -c`, path-qualified binaries, variable indirection, quoting |
| `irreversible.jsonl` | Class U (14 shapes x mainnet, testnet, Unknown, localnet, devnet, wrapped), default-wallet destruction |
| `credentials.jsonl` | home credential stores, command-form readers, Solana config |
| `exfil.jsonl` | secret-to-network, exfil hosts, JSON-RPC quiet rows |
| `env.jsonl` | project `.env` reads by tier, `env_read: deny`, other env files, writes, `.env.schema` |
| `tier.jsonl` | tier selection inputs: raise-only hints, pending lowering |
| `headless.jsonl` | the headless rule (every `ask` becomes `deny`) |

## Row

```json
{"id":"CL-2","rows":[13],"tool":"Bash","input":{"command":"anchor deploy"},"cwd":"proj","env":{},
 "files":{"proj/Anchor.toml":"[provider]\ncluster = \"mainnet\"\n"},
 "ctx":{"sandbox":"unset","headless":false,"user_policy":{},"repo_policy":{},"user_tier":null,"repo_tier":null},
 "expect":{"plugin":"AAAD","kit":"----","combined":"AAAD","owner":"plugin","interim":{"kit":"-AAD","combined":"AAAD"}}}
```

- `id`: unique across all files. Contract seed ids (`DEV-1`, `CL-2`, `MN-1`, `IR-1`, ...) keep their
  names; derived rows use `CC-`, `WR-`, `U<nn>-<c>`, `UW<nn>-<w>`, `WL-`, `CRD-`, `XF-`, `EV`, `TI-`, `HL-`.
- `rows`: the F4 overlap-matrix row numbers the case exercises (empty when none applies).
- `tool`, `input`: the PreToolUse payload (`Bash`, `Read`, `Grep`, `Write`, `Edit`, `MultiEdit`,
  `mcp__*`). In `input` string values and in `files` contents, `{HOME}` is the runner's temporary HOME
  and `{CWD}` the project directory (tool path fields are absolute, as in Claude Code). Bash command
  strings keep a literal `~`/`$HOME` (shell semantics).
- `cwd`: project directory name under the runner's temp root. `files`: path (relative to that root, or
  `~/...` = temp HOME) to content. A content starting `@symlink:<path>` creates a symlink to that
  path instead. No network: cluster comes from files and flags only.
- `env`: process environment for the hook. Runners own `HOME`, `PATH`, `CLAUDE_PLUGIN_*` and
  `CLAUDE_CONFIG_DIR`; a row cannot set them. `PATH` holds nothing, except, when the row writes
  `~/.config/solana/cli/config.yml`, a stub `solana` that answers `solana config get` from that file
  (as the real CLI does). Nothing else runs.
- `ctx`:
  - `sandbox`: `on | off | unset` (declared Claude Code sandbox).
  - `headless`: contract section 3.3; a headless row has no `A` anywhere.
  - `user_policy`: user-scope policy. `secrets.env_read` is the user's tier.json choice; other keys
    (for example `network.mainnet`, `secrets.exfil_hosts_extra`) form the base policy.
  - `repo_policy`: the repo's `.safe-ai-skill/policy.yaml` (raise-only; may carry a `tier` hint).
  - `user_tier`: `null` = the column tier is the user's selection (the four expect characters are the
    four selections). `"default"` = no user selection at all. A tier name = that fixed selection. In
    the last two forms the column is not swept, so `plugin` and `kit` must be four equal characters.
  - `repo_tier`: a raise-only hint, as the kit's `.claude/security.json`.
  - Additive, not in contract 1.0.0: `grants` (`[{"scope","max_tx_sol","budget_sol","danger"}]`, a
    confirmed grant already in the data dir, never expiring) and `pre_cli` (argument arrays of
    `safe-ai-skill` CLI calls to run first, for example an unconfirmed `tier off --project`).
- `os` (optional, additive): runners skip the row on other operating systems.
- `expect`: four characters for Off Relaxed Medium High: `D` deny, `A` ask, `L` allow, `-` no opinion.
  - `plugin` is the end state this engine must give; `kit` the end state of the kit's own layers;
    `combined = max(plugin, kit)` with `D > A > L > -`; `owner` the engine whose reason text shows.
  - `interim` (optional): the state before the end state. May carry `kit` (before the kit's M5) and
    `plugin` (the shipped engine differs from its end state); the other side defaults to the end
    state; `combined` is recomputed. End-state invariants are not checked on a row that has
    `interim`'s kit value, only on the end state.
    - Additive: `reason` (required with `interim.plugin`): why the shipped engine differs, for
      example `exfil tripwire deferred (#19)`. The engine runner asserts `interim.plugin` on such a
      row.
    - Additive: `until_feature`: a cargo feature that already gives the end state; a build with
      it is held to `plugin`, a build without it to `interim.plugin`. No feature is known since
      1.2.0 retired `env-read-opt-in`.
  - Additive: `updated_input: true` (the gate must emit `updatedInput`, no decision), `note`.
- **`?` (kit and interim columns only, additive):** the kit's verdict at that tier is not asserted
  (unknown from reading its source, or dependent on a kit choice not made yet). `combined` is then
  `D` where the plugin denies and `?` elsewhere; runners and the diff script skip a `?` tier. It never
  appears in `plugin`.

Invariants (contract section 2.2): never `plugin=A` and `kit=A`; never `plugin=L` and `kit=A`; no `A`
in a headless row. The schema test checks them on the end-state columns of every row; the engine runner
checks them again on its actual verdicts for rows without `interim`.

## Where the verdicts come from

- `plugin`: the F0 to F4 task briefs (the tables in `.superpowers/sdd/.../F1..F5-brief.md`) and the
  contract's section 2.4 seed. Class U denies on mainnet, testnet and Unknown, asks on identified
  localnet/devnet, and is never grantable.
- `kit`: read from solanabr/solana-ai-kit `42755ab` (`onchain-guard.sh`, `secrets-guard.awk`,
  `egress-guard.sh`, `firewall.sh` deny lists), nothing executed. The pin is `42755ab`; the permanent
  wrapper denies below were re-checked at kit HEAD `edf0cb5` (same entries, different line numbers).
  The end-state kit value assumes M3 to M7 as the contract describes them: its `onchain-guard` no
  longer resolves clusters, so Class U and Class C rows are `----` and the plugin carries them;
  `interim` records what the kit does today. **Exception:** the kit keeps `Bash(env *)`,
  `Bash(sh -c *)`, `Bash(bash -c *)` and `Bash(sudo *)` in its unconditional deny list (M5 only removes
  `DENY_IRREVERSIBLE_ONCHAIN` entries), so every `env`, `sh -c`, `bash -c` (also behind `timeout`) and
  `sudo` row has kit `DDDD` at every tier in the end state, and its `combined` is `DDDD`; those rows
  only verify the engine. Rows where a wrapper might defeat a kit deny glob are `?`. A kit owner should
  review the whole column.
- Seed ambiguities, resolved here: IR-1 and the other `--final` rows give the kit an end-state `----`
  (the contract's "both layers" is read as the interim state); DEV-3 uses 5 SOL, because the contract's
  50 SOL exceeds `hard_tx_sol_max` and denies (kept as DEV-3B); MN-3 and MN-4 get interim kit values.
- P2 is open: no row freezes the precedence between `ANCHOR_PROVIDER_URL` and `Anchor.toml` for
  `anchor *`; CL-3, CL-3B and CL-8 cover only the `solana`-side and flag cases.
- Not covered here: supply chain (F5, needs pack fixtures) and PostToolUse redaction, which are not
  PreToolUse verdicts.

## Known limits

- **Hook wiring.** The runner calls `gate-bash` for every Bash row, matching `hooks.json`'s single
  unconditional `gate-bash` entry.
- **Interim rows.** The exfil tripwire is deferred (#19): its host-list and quiet JSON-RPC rows hold
  the shipped verdicts in `interim.plugin`.
- **Sandbox.** `sandbox: unset` and `off` both map to the engine's "off" override under `test-hooks`,
  so Unset-versus-Off and "Linux without bwrap" are not distinguishable here. Covered by F2's tests.
- **Not in the corpus:** supply chain (needs pack fixtures) and PostToolUse redaction.
- **MANIFEST.** The corpus is not hash-pinned in `../MANIFEST`; versioning follows the contract.

## Running

```sh
cd crates/engine
cargo test --test shared_corpus                      # schema test + runner smoke test
cargo test --features test-hooks --test shared_corpus                  # the full plugin-column run
SHARED_CORPUS_FILTER=U01,CL- SHARED_CORPUS_RESULTS=/tmp/plugin.jsonl \
  cargo test --features test-hooks --test shared_corpus
sh scripts/conformance-diff.sh --column plugin /tmp/plugin.jsonl
sh scripts/conformance-diff.sh <kit-results.jsonl>   # kit runner output, compared to expect.kit
```

The full plugin run is ignored without `--features test-hooks`, and **fails** when forced (`-- --ignored`), because it would otherwise
skip every Off column, `env_read: deny`, grant and `pre_cli` row. `SHARED_CORPUS_ALLOW_SKIP=1` accepts
that gap explicitly. A filter that matches no cell also fails. `conformance-diff.sh` exits 1 on empty or
garbage input, rows missing from the results (`--allow-missing` for a partial run), duplicate or
value-less ids and unknown ids, so a crashed runner cannot pass.

The runner drives each row through the hook entry the plugin wires for the tool (`gate-bash` and
`gate-bash-secrets`, `gate-read`, `gate-tamper`, `gate-mcp`) and takes the strictest verdict, like
Claude Code's merge. Rows needing Off, `env_read: deny`, a
grant or `pre_cli` need the `test-hooks` build (an authenticated tier.json in a trusted data dir). A
no-opinion cell must print nothing (or, at most, a decision-less `systemMessage`/`updatedInput`).
