# Upgrading

- [From 1.3.2 to 1.3.3](#from-132-to-133)
- [From 1.3.1 to 1.3.2](#from-131-to-132)
- [From 1.3.0 to 1.3.1](#from-130-to-131)
- [From 1.0.x to 1.3.0](#from-10x-to-130)
- [Notes carried over from 1.2.0](#upgrading-to-120-read-before-upgrading)
- [Notes carried over from 1.1.0](#upgrading-to-110-read-before-upgrading)
- [Moving from `safe-ai-skill@stbr`](#moving-from-safe-ai-skillstbr)

The complete list of changes is in the [CHANGELOG](../CHANGELOG.md).

## From 1.3.2 to 1.3.3

Fewer prompts in the Solana dev loop, and a stricter read of shell code that a command hands to a shell. Nothing to migrate.

1. **The Solana dev loop asks less.** `anchor run`, `anchor codama`, the local and read-only `anchor idl` commands, and `solana config set` to an identified localnet, devnet or testnet no longer ask, so CI no longer denies them. Mainnet and unidentified clusters still ask, and `anchor idl init|upgrade` are judged like a deploy.
2. **Transaction signatures are no longer treated as private keys.** A prompt that holds a signature gets through, and command output keeps its signatures. Keypairs, and 64-byte values after a key name, are still blocked and redacted.
3. **Shell code a command hands a shell is judged like the same code typed directly.** This covers a producer's output that a shell or `source` runs, and a dynamic `-c`, `eval`, here-string, launcher or `su -c` script. A few more commands ask or deny, and a command holding more than 64 such scripts asks as too large to check.
4. **`gate-permission` answers within the 8-second gate deadline**, instead of running until its 15-second hook timeout.
5. **A local `source <(…)` followed by an unrelated `curl` no longer asks** as a download-and-run installer.

## From 1.3.1 to 1.3.2

A security hotfix. Two gates deny or ask in a few more cases; nothing else changes.

1. **Secret reads and uploads inside a dynamic shell script are now seen.** A read or upload wrapped in a script whose body holds an expansion (`$PWD`, `$HOME`) — a double-quoted `sh -c`/`eval`, a here-string (`sh <<< "…$VAR…"`), a launcher command line (`watch`/`tmux …`), or `su -c "…$VAR…"` — used to pass the secrets gate silently; it is now re-parsed and the upload/read is denied. Benign dynamic scripts are unaffected.
2. **Shell nesting past the parser's depth limit is no longer silent.** A value-moving or irreversible Solana command whose program name comes from an expansion, nested deeper than the parser follows (8 levels), is now treated as unreadable regardless of what it names: ask at Medium, deny at High. Deeply nested commands are rare in normal use.

## From 1.3.0 to 1.3.1

Read these before you upgrade if you script `add` or use `allow`:

1. **`allow --scope authority|destructive` is refused** (exit 1, with the reason): every authority or destructive verdict is a hard guard, so these grants never relaxed anything. Grant scopes are `transfer`, `swap` and `deploy`. A grant of either scope that 1.3.0 stored stays until it expires or you run `safe-ai-skill revoke`, and still relaxes nothing; the session notice lists it as `inert grant …` and `status` marks it `"inert": true`. A pending request for one fails when you confirm it.
2. **`add` usage errors exit 3**, not 0: a missing or unknown kind, a missing source, an unknown flag, an extra argument, a source starting with `-`, a source with whitespace at either end or a control character, and whitespace inside a package, URL or repository (write a local directory with spaces as `./name`). Flags may now come anywhere (`add --yes skill <source>`). A local path that is not a directory exits 1, for `add mcp` too.
3. **`add` holds in more cases** until you pass `--yes`: a source that is not GitHub, npm or a local directory (`unrecognised_source`; 1.3.0 passed it with no finding), an osv.dev lookup that fails or comes back incomplete (`osv_unavailable` is MEDIUM; it was LOW and passed), and an npm version short of `major.minor.patch` (`pkg@1`, `pkg@1.2`). A URL that only mentions `github.com` is no longer GitHub. A high-risk catalog entry is now matched under any spelling of its package or repository, offline too.
4. **`add` prints a pinned command; a moving source still holds.** Only a commit or exact version you name can pass. Online, a branch, tag or missing version is resolved to the commit or exact version it names now and is still held, and with `--yes` the printed command installs exactly that (`npx skills add o/r#<sha>`, `claude mcp add <name> -- npx -y <pkg>@<version>`, `git clone … && git -C … checkout --detach <sha>`). Pin a skill with `owner/repo#<sha>`: as in the skills CLI, `owner/repo@<x>` names the skill `x` and pins nothing. `run` is null, with a `run_note`, where no correct command exists, and the JSON gains `source_kind`, `pin`, `run_note`, `source_note`, `catalog_entry` and `catalog_source`. `add mcp <dir>` now scans the directory, and a bare name that is a directory here is graded as that directory. Details: [cli.md](cli.md#what-add-does).
5. **`--help` no longer runs the command.** `revoke --help` used to clear every grant and `install --help` checked and pinned `.claude/skills`; `<command> --help` now prints the usage. See [cli.md](cli.md#command-line-reference).
6. **Every release from 1.3.1 on is published to crates.io:** `cargo install safe-ai-skill --version <version> --locked` (crates.io had only 1.0.0 before). The npm package works as before; it now publishes only its own two scripts and README.

## From 1.0.x to 1.3.0

1.3.0 is the first release since 1.0.0. 1.0.1, 1.1.0 and 1.2.0 were never released on their own, so upgrading from 1.0.x brings the changes of all four. Migrations run at the first session on the new engine, which for a 1.0.x user is the first 1.3.0 session.

Update the plugin, then start a session and read the SessionStart lines. This is what you will notice:

1. **Profiles became tiers.** `strict` and `autopilot` become `relaxed`, `paranoid` becomes `high`. A 1.0 `off` is never migrated (see [1.1.0](#upgrading-to-110-read-before-upgrading)).
2. **Relaxations need a code only you see.** Unexpired 1.0 grants become pending requests, and the 1.0 spend ledger counts as spent for the rest of that UTC day. Lowering the tier needs the same confirmation. See [Confirming a relaxation](cli.md#confirming-a-relaxation).
3. **Project `.env` follows the tier.** The agent can read `.env` and `.env.*` at Off, Relaxed and Medium, and High denies the reads. `safe-ai-skill tier --env-read deny` keeps the 1.1.0 behaviour of denying at every tier. `.env.production` and `.env.prod*` are denied from Relaxed up. dotenvx private keys (`.env.keys`) are denied at every tier.
4. **New denies.** At every tier: `git clean`, `git reset --hard`, `git checkout -- <path>` and other commands that discard work; printing a secret-named variable (`echo $HELIUS_API_KEY`); writes to shell startup files, `~/.gitconfig` and cargo config. From Relaxed up: a request to a host on the request-bin and tunnel list (such as `webhook.site`). Details: [Git and gh guard](tiers.md#git-and-gh-guard), [Tamper](tiers.md#tamper-settings-hooks-and-config-content), [Exfiltration tripwire](tiers.md#exfiltration-tripwire).
5. **Undeclared one-shot packages ask.** `npx`, `pnpm dlx`, `bunx`, `uvx` and similar run a package the project does not declare: ask, and a deny in CI and at High. See [Download and run](tiers.md#download-and-run).
6. **Irreversible actions and clusters.** `--final`, `program close` and `spl-token close|burn` deny on mainnet or an unidentified cluster and ask on an identified localnet, devnet or testnet. Testnet is treated like devnet. More authority changes (stake, vote, nonce, `spl-token approve`) are hard guards.
7. **Token amounts are token units.** SOL spend caps and grants never cover `spl-token` or MCP token transfers.
8. **`gate-bash` runs for every Bash call and fails closed**, and the Skill and `PermissionRequest` hooks fail closed too.
9. **Skill-pack drift is a BLOCK** until you run `safe-ai-skill verify approve <name>` in a terminal.
10. **Headless asks become denies.** In CI or with a headless switch set, every `ask` is a `deny`. See [Headless](tiers.md#headless).
11. **The CLI works without the plugin.** It uses the plugin's data dir when there is one and a standalone dir otherwise ([cli.md](cli.md#where-the-cli-keeps-state)).
12. **New in 1.3.0:** the exfil tripwire and `gate-webfetch`, content-aware tamper checks and a `ConfigChange` guard, the download-and-run and encoded-command gates, the container privilege guard, key-file hygiene, `PermissionRequest` hardening, the session report, MCP tool-name denies, and the `firewall` settings manager.

If you use the plugin through solana-ai-kit, the kit pins a specific plugin commit (1.0.0 as of kit 2.4.0), so a release here reaches you when the kit moves its pin.

## Upgrading to 1.2.0 (read before upgrading)

- **The project `.env` is readable below High.** The project's `.env` and `.env.*` now follow solana-ai-kit's tiers: the agent can read them at Off, Relaxed and Medium, writes are denied at Medium only, and High denies reads. `.env.production` and `.env.prod*` are denied from Relaxed (1.3.0). To keep the 1.1.0 behaviour (reads denied at every tier), run `safe-ai-skill tier --env-read deny`. Installs from before 1.2.0 that never chose `env_read` get a one-time SessionStart line about this, and a stored `env_read: ask` becomes `tier` with a notice. See [Project `.env` files](tiers.md#project-env-files).
- **dotenvx private keys are key material.** `.env.keys` (and `.env.keys.*`, `.env.*.keys`) is denied, read and write, at every tier.
- **Env data sent to the network denies at every tier**, Off included (`cat .env | nc …`, `dotenv -e .env -- curl …`).
- **Codex users: change your `hooks.json`.** The `safe-ai-skill-codex` wrapper is gone; the template runs `safe-ai-skill adapt codex <entry>` through the shim. Replace each `safe-ai-skill-codex <gate>` with `safe-ai-skill adapt codex <gate>`, re-approve with `/hooks` and run `safe-ai-skill doctor --codex` ([docs/adapters.md](adapters.md)). This applies only if you set Codex up from an unreleased checkout: the Codex adapter and its wrapper were added in the unreleased 1.1.0 and the wrapper was removed in 1.2.0 ([CHANGELOG](../CHANGELOG.md)), so no 1.0.x release had it.

**`env_read` since 1.2.0.** The 1.1.0 opt-in (`--env-read ask|tier`, behind the `env-read-opt-in` cargo feature and the sandbox) is gone: `tier` (the default) follows the tier, `deny` denies at every tier, and `--env-read ask` is refused. A stored `env_read: ask` is rewritten as `tier` at the first session on the new engine, with a one-time notice; a stored `deny` is kept.

## Upgrading to 1.1.0 (read before upgrading)

- **Relaxations need a code only you see.** Unexpired 1.0 grants become pending requests at your first session on the new engine; confirm each as described in [Confirming a relaxation](cli.md#confirming-a-relaxation), or re-create it. The 1.0 spend ledger counts as spent for the rest of that UTC day. Lowering the tier needs the same confirmation, and nothing can be confirmed in headless `claude -p`.
- **Profiles became tiers.** `strict` (the 1.0 default) becomes `relaxed`, `paranoid` becomes `high`, and `autopilot` becomes `relaxed` (the notice names `safe-ai-skill allow --scope transfer` for what autopilot's higher cap did). A tier below `relaxed` is never migrated: a 1.0 `off` is set aside with a hint to run `safe-ai-skill tier off` (confirmed) or set `SAFE_AI_SKILL_DISABLE=1`. Your first session prints one line about it. Raw `.env` reads stay denied for everyone after this step (1.2.0 changes this; see above).
- **What `relaxed` now denies.** Irreversible actions (`--final`, `program close` (program or buffer), `spl-token close-mint|close|burn`, `authorize --disable`, IDL erase/close, `close-vote-account`) deny on mainnet and any cluster that isn't positively identified as localnet, devnet or testnet (an RPC host without an `http(s)://` scheme identifies nothing), and ask on an identified localnet, devnet or testnet (testnet is treated like devnet; see the [CHANGELOG](../CHANGELOG.md)). Credential stores beyond `~/.ssh/id_*` (`~/.aws`, `~/.gnupg`, `~/.netrc`, `~/.npmrc`, cloud CLI tokens, keychains, browser and wallet-extension data, and more) are read-denied at every tier, by path and by any Bash command naming them. An inline `curl`/`wget` POST body to a non-localhost host still asks at every tier (a deny under `claude -p`), except an inline body to a known Solana RPC host, which has no opinion below High.
- **`gate-bash` runs for every Bash call and fails closed.** It used to run only for commands starting with `solana`, `spl-token` or `anchor`, so wrapped forms (`env FOO=1 …`, `bash -c '…'`, `timeout 5 …`) and `solana-keygen` never reached it. A fast path keeps ordinary commands cheap. If the engine crashes, Bash calls are blocked until it is fixed; if it cannot run on your platform at all, only commands naming the Solana CLIs ask.
- **Headless asks become denies.** In CI or with a headless switch set (see [Headless](tiers.md#headless)), every `ask` is a `deny`; only a grant you confirmed interactively beforehand passes. `CONFIRM_MAINNET`-style env variables are ignored, and no setting turns headless off. The plugin does not detect `claude -p` by itself; Claude Code denies a prompt it cannot show.
- **Skill-pack drift is a BLOCK.** A pinned pack whose content changes is denied (the Skill tool, `/name`, reads and Bash access inside it) until you run `safe-ai-skill verify approve <name>` in a terminal and confirm it. A pack the SessionStart sweep could not fully scan in its time budget is denied the same way until a later sweep scans it; `safe-ai-skill verify check <dir>` scans it without a budget.
- **The agent can't read Claude Code transcripts (`~/.claude/projects`) or the plugin's state key**, through Read, Grep or Bash. `safe-ai-skill doctor` recommends matching sandbox `denyRead` entries.
- **The Skill hook fails closed**: a broken engine blocks the Skill tool until it is fixed.
- **The CLI uses the plugin's data dir, or a standalone one.** From a terminal it uses `$CLAUDE_PLUGIN_DATA`, else the plugin's data dir. Since 1.2.0 it falls back to a standalone dir when there is no plugin (see [cli.md](cli.md#where-the-cli-keeps-state)); in 1.1.0 it exited 1 asking for `CLAUDE_PLUGIN_DATA`.

## Moving from `safe-ai-skill@stbr`

Between 1.0.0 and 1.0.1 the README said to install `safe-ai-skill@stbr`. The solana-ai-kit marketplace is also named `stbr`, and removing it uninstalls the kit and deletes its data. Check what your `stbr` is before you remove anything:

```bash
claude plugin marketplace list
```

- If `stbr` comes from anything other than `solanabr/safe-ai-skill` (for example `solanabr/ai-kit`, formerly `solanabr/solana-ai-kit`), stop. You have the kit's copy and there is nothing to move.
- If `stbr` comes from `solanabr/safe-ai-skill`, switch to the new name:

  ```bash
  # only if 'marketplace list' shows stbr → solanabr/safe-ai-skill
  claude plugin uninstall safe-ai-skill@stbr --keep-data
  claude plugin marketplace remove stbr
  claude plugin marketplace add solanabr/safe-ai-skill
  claude plugin install safe-ai-skill@safe-ai-skill
  ```

The plugin keeps its pins, grants and audit log in a directory named after `plugin@marketplace`, so the new install starts empty, and its first session pins whatever is on disk at that moment. To keep your existing pins, copy the old state across before you start a session:

```bash
mkdir -p ~/.claude/plugins/data/safe-ai-skill-safe-ai-skill
cp -R ~/.claude/plugins/data/safe-ai-skill-stbr/. ~/.claude/plugins/data/safe-ai-skill-safe-ai-skill/
```
