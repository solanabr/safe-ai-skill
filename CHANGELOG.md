# Changelog

All notable changes are documented in this file. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [1.1.0] — Unreleased

### Behaviour changes

- **The CLI uses the hooks' data directory.** `safe-ai-skill allow`, `mode`, `status` and the other commands now find state where the hooks keep it: `CLAUDE_PLUGIN_DATA`, else the `safe-ai-skill-*` directory under `~/.claude/plugins/data` (or `$CLAUDE_CONFIG_DIR/plugins/data`). The `~/.safe-ai-skill` and `./.safe-ai-skill` fallbacks are gone; state written there by 1.0.x was never read by the hooks.
- **New hooks:** PreToolUse `Skill`, `UserPromptExpansion`, and SessionStart on `clear` and `compact`. All fail open (`onFailure: continue`).
- **Bash commands are parsed like a shell parses them.** `gate-bash` splits on newlines, `;`, `&`, `&&`, `||` and `|` outside quotes, strips `FOO=1` prefixes and wrappers (`env`, `sudo`, `nohup`, `time`, `command`, `exec`, `xargs`, zsh `noglob`/`nocorrect`/`repeat`/`=cmd`, …), and follows `$(…)`, backticks, `(…)`, `bash -c '…'`, `eval`, here-documents fed to a shell and launchers such as `find -exec`, `watch`, `tmux`, `nix-shell --run` and `sandbox-exec`. A shell expansion that could turn into flags or extra arguments (`$X`, `$(…)`, `*`) makes a transfer ask instead of allow. (#13)
- **Solana commands are gated however they are spelled.** The always-on Bash hook leaves to the `if`-filtered `gate-bash` only commands whose every `solana`, `spl-token` or `anchor` command is spelled exactly that way at top level. Any other solana command it finds, behind a wrapper, in a script string, after a pipe, in any case, as a path or `.exe`, gets the gate's own decision, resolved and relaxable exactly as in `gate-bash`. A solana name inside code the parser can't read (`bash -c "solana $X"`, `eval`, `python -c`, a pipe into `sh`, unparseable text) or a program spelled as an expansion asks as a hard guard, as does a value-moving solana command written to a script that is then run. A path-qualified program inside such code (`./solana`, `~/.local/share/solana/…/bin/solana`) counts. So does a script written to a file by `echo`, `printf` (with its `%s` arguments filled in), or a here-document or here-string fed to `cat` or `tee`. It counts when that script runs a value-moving solana command, or runs an expansion that may be one (`X=solana; $X transfer …`), and the same command line then runs a file or stdin (`… > x.sh; cat x.sh | bash`). Command output written to a file (`grep solana … > f`, `anchor build | tee log`) and prose (`echo "anchor build failed" > notes.md`) don't count. An expansion run as a program asks only when it could spell a solana program (`$(echo sol)ana`, `X=solana; $X`) or is followed by a solana verb (`$X transfer`), so `$EDITOR close-notes.md` gets no opinion. Mentions in data arguments (`git commit -m`, `grep` patterns, `echo` text) get no opinion. A gate that crashes answers `ask`. **Known limitations:** writing a script in one Bash call and running it in a later one isn't linked, because the second call's `bash x.sh` reveals nothing to parse. Script text the command line doesn't spell out, such as `base64 -d <<< … > x.sh` or a `curl` download, isn't seen either. (#13)
- **Network resolution follows the CLI.** `-C/--config <file>` is read for its `json_rpc_url`. `solana` and `spl-token` use the CLI config, and only `anchor` reads `Anchor.toml` (the nearest one, in any of its `provider.cluster` forms; unreadable or unparseable is unknown). `ANCHOR_PROVIDER_URL` can only make an anchor command riskier. Only exact hosts count as devnet, testnet or localnet (`devnet.attacker.example` is unknown). `solana config get` is given 2 s, after which the network counts as unknown, and its cache is an authenticated state file invalidated by `solana config set`. Policy `network.mainnet: deny` now denies mainnet transfers, deploys and other mainnet asks. (#13)
- **Amounts are plain decimals.** `1e3`, `0x10`, `+1`, `inf` and overlong amounts ask instead of being parsed. (#13)
- **Every PreToolUse gate answers within 8 s.** A gate still running at 8 s, or one that crashes, emits `ask` (a deny it already reached stays a deny). `SAFE_AI_SKILL_DEADLINE_MS` can shorten the deadline to no less than 2 s, never lengthen it.

---

## [1.0.1] — Unreleased

### Summary

Security hotfix for #5–#13. Several defaults change; each change is listed below. Design and evidence: `docs/superpowers/specs/2026-10-21-open-issues-design.md`.

### Behaviour changes

- **No opinion means no output.** A gate with nothing to say prints nothing and exits 0. 1.0.0 printed `defer` on every benign call, and `defer` stops the tool call under `claude -p`. Unknown subcommands exit 3, and `--version` prints the version. (#13)
- **Skill packs are reported, not quarantined.** SessionStart findings and pin drift are reported in the session, and a drifted pack is reported every session until you run `verify approve <name>`, which re-pins it in place. Nothing is moved, so `git status` stays clean, and a clean sweep prints nothing. `~/.claude/skills` is scanned only when policy lists it, except for packs installed there with `install --from`. `verify approve` still restores packs that 1.0.0 moved into `quarantine/`, and never overwrites an existing directory. (#5, #9)
- **Unsupported platforms fail open with a notice; Solana commands still ask.** If the engine can't run (no binary for the platform, exit 126/127, a broken interpreter), hooks exit 0 with one stderr line and SessionStart reports the firewall INACTIVE, while `solana`, `spl-token` and `anchor` commands get `ask`. `SAFE_AI_SKILL_STRICT=1` blocks instead, and `SAFE_AI_SKILL_DISABLE=1` switches the hooks off. The shim no longer falls back to `cargo build` or runs a binary from the plugin data directory. (#6)
- **Irreversible flags and unknown networks ask.** `--final` deploys and upgrades, upgrade-authority changes, `program close`, `spl-token authorize … --disable`, `spl-token close|close-mint`, `anchor idl erase-authority|set-authority|close` and `solana close-vote-account` ask on every cluster, and mainnet `--final` is denied. A command whose cluster can't be identified asks instead of passing. Transfer amounts are read from positional arguments only. (#13)
- **The agent can't grant itself permissions.** When the agent runs `safe-ai-skill allow`, `mode`, `verify approve` and similar commands, or writes the plugin's state files (`grants.json`, `mode.json`, …), the call is denied. Run those commands yourself in a terminal.
- **Repo policy can only tighten.** A project's `.safe-ai-skill/policy.yaml` can lower caps and add checks, but it can no longer raise caps, shrink the scanned skill directories or change the profile. `SAFE_AI_SKILL_PROFILE` can only select a stricter profile than the one in effect. Ignored keys are listed at SessionStart.
- **The marketplace is named `safe-ai-skill` again.** Install `safe-ai-skill@safe-ai-skill`, as in 1.0.0. If you installed `safe-ai-skill@stbr`, follow the README migration and don't remove `stbr` without checking it first: the solana-ai-kit marketplace has the same name. solana-ai-kit users don't need to do anything. (#8)
- **Linux binaries are static (musl).** 1.0.0's `linux-x64` needed glibc 2.39, so it failed on Ubuntu 22.04 and Debian 12 and the firewall was silently off. File names are unchanged. (#6)
- **Claude Code 2.1.295 or newer is required** for the hooks' `onFailure` setting. Older versions still run the hooks, but a hook that can't start never blocks.

### Release process

- Release tags now point at a commit that contains the binaries. `v1.0.0` predates the commit that vendored its binaries (a8d20f8), so anything that resolved the tag got a plugin without them. `release.yml` now builds on manual dispatch from `main` only, attests each binary's build provenance and opens a PR that commits the binaries. The maintainer tags that commit `vX.Y.Z` and `safe-ai-skill--vX.Y.Z` (the form plugin dependency version ranges resolve), and the tag push publishes the GitHub Release from the committed binaries once their checksums check out and their attestations prove they were built by `release.yml` on `main`. Steps, including the one-off `safe-ai-skill--v1.0.0` tag on a8d20f8, are in `docs/RELEASING.md`.
- Release builds use a pinned toolchain (1.98.1, the same pin as CI), `--locked`, explicit macOS minimums (11.0 on arm64, 10.12 on x64), no build cache and no third-party actions. The unused cosign stub is gone.
- CI builds the musl binaries, checks that they're static and run on alpine, debian:11 and ubuntu:20.04, and verifies the provenance attestation of every committed binary. The npm e2e also runs in alpine and Debian 11 containers on x64 and arm64, and `release.yml` runs it after each publish.
- `scripts/check-versions.sh` also checks `Cargo.lock` and `install.sh`, and accepts an expected version.

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

- **Plugin** (always-on firewall): `claude plugin marketplace add solanabr/safe-ai-skill` → `claude plugin install safe-ai-skill@safe-ai-skill`. Ships committed platform binaries; the shim resolves the native prebuilt, else builds from `crates/engine`, else fails closed.
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
