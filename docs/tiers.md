# Firewall tiers

safe-ai-skill takes a **tier** as an input and varies its gates with it. The tier is a posture, not a sandbox: the plugin is hook-level string analysis, and [what it cannot protect on its own](../README.md#read-this-first-what-this-plugin-cannot-protect-on-its-own) applies at every tier. Last updated for 1.1.0.

## Who owns what

solana-ai-kit ([ai-kit#264](https://github.com/solanabr/ai-kit/issues/264)) and this plugin split the firewall by what each can structurally enforce.

| Owner | Owns |
|---|---|
| solana-ai-kit | The OS sandbox (filesystem denies, `deniedDomains` at the syscall), permission rules, tier selection and regeneration (`/firewall`, `.claude/security.json`), git/publish/fetch-and-execute/`gh` gates, MCP tool-name denies |
| safe-ai-skill | Solana-semantic gates (cluster, amounts, irreversible and authority actions, mainnet, grants); secrets for plugin-only users (key material and home stores hard-denied, `.env` through the `env` CLI, varlock and redaction, an opt-in raw read); supply chain (scan, pins, Skill/slash deny, no moves); a labelled best-effort exfil tripwire; the tier as an **input** |
| Shared | Versioned list files in `policy/shared/` (`credentials.list`, `exfil-hosts.list`, `onchain-verbs.list`), a conformance corpus and one headless rule |

Defence in depth is kept only where the mechanisms differ (a hook against a syscall, a Rust parser against an awk one). The plugin does not reimplement sandbox semantics and does not promise what only a sandbox can do.

## Names, order, and Off

`off < relaxed < medium < high`. The default is `relaxed`. The old names are input aliases through 1.x: `strict` is `relaxed`, `paranoid` is `high`, `autopilot` is `relaxed` (see [Migration from profiles](#migration-from-profiles)).

**Off is not `SAFE_AI_SKILL_DISABLE=1`.** At Off every `deny` row of the table in the [README](../README.md#firewall-tiers) still holds: key material and credential stores, key material sent to the network, raw project `.env` reads by default, irreversible on-chain actions on mainnet or an unidentified cluster, default-wallet destruction, the tamper tripwire, the prompt guard and redaction. Off differs from Relaxed in exactly three rows: the exfil tripwire for project env files and for known exfil hosts (no opinion; key material to the network still denies), and the supply-chain deny for combination, drift, `lock_mismatch` and unscanned packs (reported instead). `SAFE_AI_SKILL_DISABLE=1` stays the only switch that turns the hooks off, and the shim ignores it in strict mode and when the project's committed `.claude/settings.json` mentions it.

No tier, grant, repo setting or env variable relaxes a `deny` row.

### How the tier is chosen

Per hook call, with the project root as the canonical git toplevel of the payload's `cwd`:

1. **Base:** `relaxed`.
2. **User scope:** the authenticated `tier.json` in the plugin's trusted data directory: `projects[<root>]` if present, else `global`, else base. This is the **only** channel that can select a tier below base.
3. **Raise-only hints,** `effective = max(user, hints…)`. Each hint that is lower than the current value is ignored, with a note in the SessionStart summary:
   - solana-ai-kit's `.claude/security.json`: the highest of top-level `tier`, `declared.tier` and `enforced.tier` (a regular file up to 256 KiB; a malformed one is ignored with a note). The plugin never reads it as a lowering.
   - a repo's `.safe-ai-skill/policy.yaml` `tier` (or the legacy `active_profile`);
   - the env variable `SAFE_AI_SKILL_TIER` (alias `SAFE_AI_SKILL_PROFILE`). A repo's `.claude/settings.json` `env` block can set it, which is why it can only raise.
4. **Floors always apply.** To get less than a repo's or the kit's floor, change the floor (for example through the kit's `/firewall`), not the plugin.

A forged or hand-edited `tier.json` fails its MAC and is ignored with a note, as is one in an untrusted data directory.

SessionStart and `safe-ai-skill status` print `tier: <t> (<source>); sandbox: <state>` and each ignored hint. When the sandbox isn't `On` the label reads `relaxed (hooks only)`.

### Changing the tier: `safe-ai-skill tier`

```bash
safe-ai-skill tier                      # show tier, source, sandbox state, ignored hints
safe-ai-skill tier <name> [--project]   # off | relaxed | medium | high
safe-ai-skill tier --env-read deny|ask|tier [--project]
safe-ai-skill tier --clear [--project]
```

- **Raising** the tier, or tightening `--env-read` (it loosens in the order `deny`, `ask`, `tier`), applies at once.
- **Lowering** the user value, or loosening `--env-read`, creates a pending request. Claude Code shows **you** an 8-digit code in a hook message (right after the command, or at your next prompt or session start), never in the agent's context. The request takes effect when your next prompt is exactly `safe-ai-skill confirm <code>`, on its own line, within 10 minutes, once. The payload is re-validated and the change audited. A confirm line inside pasted text is refused; three wrong codes cancel every pending request.
- The agent may run `safe-ai-skill tier` (it can only raise, or create a request it cannot confirm). The tamper tripwire keeps denying a Bash-invoked `confirm` and the hook subcommands.
- Headless `claude -p` shows no hook messages, so nothing can be confirmed there.
- `mode` is a deprecated alias for `tier`.
- solana-ai-kit's `/firewall` reaches this only by running `safe-ai-skill tier <t> --project` (a proposed kit change, see [the kit draft](drafts/aikit-firewall-split.md)); there is no other handoff file. Until the kit change lands, `/firewall` does not run it; run `safe-ai-skill tier <t> --project` yourself.

### Sandbox detection

`sandbox::state(root)` reports `On`, `Off` or `Unknown` from the first `sandbox.enabled` found in Claude Code's settings precedence: managed, project local, project, then the user settings under `$CLAUDE_CONFIG_DIR` or the passwd home (never the `HOME` environment variable, which a repo can set). `On` also needs a supported platform: macOS, or Linux with `bwrap` at a fixed system path; never native Windows.

This is **declared configuration, not a runtime proof.** The plugin cannot see that a given process is actually sandboxed, and commands the kit lists in `excludedCommands` run unsandboxed whatever the setting says. The state has two effects, and only these:

- the user-scope raw `.env` opt-in (below) works only while the state is `On`; otherwise reads are denied;
- the tier label, and the snippet `safe-ai-skill doctor` prints (the `denyRead` and `deniedDomains` entries to add).

## Behaviour per gate

The full table is in the [README](../README.md#firewall-tiers). It is the table the code is checked against; this page explains it. `n/o` is no opinion: empty stdout, and the call continues into Claude Code's own permission flow. `deny` rows are never relaxed by a grant, tier, repo setting or env variable. At High the engine never emits `allow`, and no tier emits `defer`.

### Project `.env` files

- **Default (`env_read: deny`):** a raw read of `.env`, `.env.*`, `*.env`, `.envrc` or `.dev.vars` (Read, Grep with a file path, MCP path argument, Bash readers such as `cat`, `grep`, `source`, `git show REV:.env`) is denied at every tier. The message names `safe-ai-skill env keys|set|unset` and, when the project has a `.env.schema` or varlock, `varlock load --agent` and `varlock run -- <cmd>`.
- **varlock value printers** (`varlock printenv`, `reveal`, `load --format json|env|shell` without `--agent`) follow the raw-read row.
- **`.env.schema` and templates** (`.env.example|.sample|.template|.dist`) are readable, subject to the content guard: a schema holding key material, a literal credential, over 64 KiB or not a regular file is denied.
- **Opt-in:** `safe-ai-skill tier --env-read ask|tier`, user scope only, only while the sandbox is `On`. `tier` follows the tier (no opinion at Off and Relaxed, deny at Medium and High); `ask` prompts at Off, Relaxed and Medium and denies at High. With the sandbox `Unknown`, `Off`, on Windows or on Linux without `bwrap` the opt-in is suspended and reads stay denied ("opt-in suspended: sandbox not on"). A repo's `policy.yaml` `env_read`, a kit file or an env variable can only tighten it. The response to an opted-in raw read isn't value-scrubbed.
- **Writes:** Write, Edit and MultiEdit to a project env file, and an agent-run `env set|unset`, are allowed at Off and Relaxed and denied at Medium and High. A write through Bash (`sed -i`, `perl -pi`, `python3 -c`) is not covered at any tier (see [Known holes](#known-holes)). `env keys` is always open.
- **Redaction** of key, seed, PEM and vendor-token patterns, and the **value scrub** (literal values from the project's env files replaced with `«redacted:KEY»`), run at every tier. The one exception is the response of an opted-in raw read, so a read-then-Edit round trip keeps the real values in the file.

## On-chain: unrecoverable vs counterparty

The axis is whether an action destroys a capability **even for its rightful owner** (Class U) or moves value or capability to a counterparty (Class C). Only Class U can be judged without knowing the counterparty. Class C is controlled by spend caps, grants and unrelaxable hard-guard asks, and denied at High.

### Class U: unrecoverable actions

Defined by the `irreversible` rows of `onchain-verbs.list`:

- `--final` on `program deploy|write-buffer|upgrade|set-upgrade-authority` (`solana`, `anchor program`, `anchor deploy -- --final`), any `program-v4` subcommand with `--final`, `program-v4 finalize`;
- `program close <program-id>` and `--bypass-warning` (closing a buffer is Class C);
- `spl-token authorize … --disable` (any authority), `spl-token close-mint`, `close`, `burn`; `anchor idl erase-authority`, `anchor idl close`; `close-vote-account`.

The verdict is keyed on the resolved cluster (flag, then a `-C` config file, then for `anchor` the nearest `Anchor.toml`, then the CLI config; `ANCHOR_PROVIDER_URL` can only make an anchor command riskier). **Mainnet, Unknown, or any cluster not positively identified as localnet or devnet (testnet included) is a deny**, with the exact command echoed ("run it yourself"). **A positively identified localnet or devnet is a hard-guard ask.** Only exact hosts count (`devnet.attacker.example` is Unknown). No grant, tier, repo setting or env variable relaxes either verdict, and Class U is not grantable.

**Wallet destruction (cluster-independent, deny at every tier):** `solana-keygen new|recover` with `--force`/`-f` and no `-o`, or an output resolving to `~/.config/solana/id.json` or the CLI config's `keypair_path`; Write, Edit and NotebookEdit to that file; Bash `rm`, `mv`, `cp`, `tee`, `dd of=` or `>` targeting it.

### Class C: value or capability to a counterparty

Transfers (`solana`, `spl-token`), deploy, upgrade, write-buffer, extend, buffer close, `set-upgrade-authority` and `spl-token authorize` to a new key, `anchor idl set-authority`, stake/vote/nonce withdraws, `spl-token gc`.

- On mainnet or an Unknown cluster: ask at Off, Relaxed and Medium; deny at High. A confirmed grant that covers it (grantable scopes only) allows below High and never at High. Policy `network.mainnet: deny` forces a deny at every tier.
- On an identified test cluster: deploy and upgrade have no opinion; a transfer within the spend caps is allowed below High (no opinion at High); an authority change or a recoverable close asks at every tier.
- The hard guards `set_authority` and `account_close` stay unrelaxable.

A Solana command the parser can't read (a name inside `bash -c "solana $X"`, `eval`, a pipe into `sh`, a program spelled as an expansion) asks as a hard guard, and denies at High. An MCP tool that moves value or signs asks, and denies at High.

### Escapes

Only from user scope, by a confirmed grant where one applies. Repo or env escapes (`CONFIRM_MAINNET`-style) are ignored. Class U has no escape.

## Key material and home credential stores

One shared list, `credentials.list`, with the classes `key_material`, `host_token`, `vault`, `browser_store` and `wallet_ext`. All of them hard-deny at **every tier**: this is deliberately not the kit's split that leaves host tokens readable below Medium, because a hook only sees agent reads, so subprocess `npm` and `gh` keep working.

- **Surfaces:** Read, file Grep, directory Grep, MCP path arguments, Bash readers, and the network sinks of the [exfil tripwire](#naive-exfil-tripwire-best-effort). Glob lists names only and stays ungated.
- **Directory Grep:** exclusion globs for every credential class are appended to its `glob`. A Grep rooted at or above `$HOME` gets all of them (this closes the 1.0.1 leak where a directory-wide Grep could return `.env*` contents). A Grep rooted inside a credential store is denied.
- **Command-form readers** (plugin-internal, not path globs): `gh auth token`, `git credential fill`, `security find-generic-password -w` and `find-internet-password -w`, `aws configure get *secret*` and `export-credentials`, `npm config get *_authToken`, `docker-credential-* get`, `secret-tool lookup`, `pass show`, `op read`, `bw get`.
- **`~/.ssh/**`:** `config`, `known_hosts` and `*.pub` are readable; private keys and `authorized_keys` stay denied.
- **Transcripts:** `~/.claude/projects/**` (and `$CLAUDE_CONFIG_DIR/projects`) and the plugin's state key are read-denied, through Read, Grep and Bash. **This also stops the agent reading its own auto-memory files** (`~/.claude/projects/<project>/memory/…`) with its tools. That is deliberate: the deny covers the whole `~/.claude/projects/**` tree, which also holds the transcripts that record hook messages, and there is no carve-out for the memory subdirectory. Open those files yourself.
- `~` means the passwd home and `$HOME` (`%USERPROFILE%` on Windows), and matching is case-insensitive on macOS and Windows, on both the path as typed and the symlink-resolved path.
- **Residual** (printed by `doctor`): subprocess, compiled or encoded reads. Only the sandbox closes them.

## Naive-exfil tripwire (best-effort)

In `gate-bash-secrets` and in `gate-mcp` executor payloads. **Deny** when, in one statement or pipeline, a network-capable command (curl, wget, nc/ncat/socat, scp/sftp/rsync/ssh, ftp/telnet, httpie/xh, aria2c, `openssl s_client`, dig/nslookup/host, `git push` or `git remote add <url>`, `/dev/tcp|udp`, or an interpreter one-liner naming a URL, socket or HTTP module):

- **(a)** takes a secret path as an operand, `@file`, `-T/--upload-file`, `-F k=@`, `--data*-@`, `< file` or a piped reader: key material at every tier, project env files from Relaxed; or
- **(b)** targets a host on the tier's list (`exfil-hosts.list`: 70 hosts at Relaxed, 79 at Medium, 84 at High; `*.x` matches subdomains of `x` only; lowercased, trailing dot stripped).

Parsing includes operand-taking wrappers (`timeout 5`, `nice -n 5`, `env -u X`, `xargs -n 1`, `stdbuf -o0`). Inline bodies to unlisted hosts are not touched below High, where an inline `curl`/`wget` POST body to a non-localhost host asks (JSON-RPC calls to a devnet RPC are quiet below High). `git push` to an existing remote, `gh pr create` and `anchor deploy` are not tripped.

You can add hosts (`secrets.exfil_hosts_extra`, a union with the shared list); nothing removes one. A dev tunnel to your own ngrok host hits the list at Relaxed and above; only a user-scope tier of `off` makes the host rule no-opinion.

It stops accidental and naive exfiltration. It does **not** stop values already in context, raw IP literals, redirects, DNS, cross-call indirection, or unlisted hosts.

## Supply chain

Grading, state v2, pins, `packs.lock`, trust and approve are unchanged; only the action varies by tier (the README table). **Deny** means the Skill tool, `/slash` expansion and Read, Grep and Bash access under the pack are refused in place. **Report** means SessionStart output naming the pack, the rule, `path:line` and the approve command.

- Combination BLOCKs, drift, `lock_mismatch` and unscanned packs: report at Off, deny in place from Relaxed. A combination BLOCK is never clearable by approve or trust.
- A HIGH heuristic (`unreviewed`): report at Off, Relaxed and Medium; deny in place at High until `verify trust` or `verify approve` (user scope). A repo's `packs.lock` cannot clear it. On an ai-kit checkout at High, SessionStart prints one `verify trust` line listing them.
- **Nothing is moved by default at any tier.** `supply_chain.on_block: move` is opt-in, never touches a git-tracked pack or a submodule path (it reads `.gitmodules` and `.git/index` and never runs git), and prints the origin and the restore command.

## Headless

One rule, shared with the kit.

1. Headless is on when any of these holds: `SAFE_AI_SKILL_HEADLESS` or `KIT_FIREWALL_HEADLESS` is `1` or `true`; any of `CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, `BUILDKITE`, `JENKINS_URL` is set and not `0` or `false`; `/dev/tty` cannot be opened for reading. Any signal turns it on; **nothing turns it off**, because a repo's settings `env` can set these signals.
2. When headless, **every `ask` becomes a `deny`** (irreversible actions on a devnet, value-moving actions on mainnet, hard-guard asks, opaque commands, MCP asks), with the reason "approve interactively, or run it yourself".
3. The only thing that passes is a grant you confirmed interactively beforehand, for grantable Class C scopes, below High.
4. Env escapes (`CONFIRM_MAINNET`, `CONFIRM_*`, anything repo-settable) are ignored. No `defer`, ever. Nothing can be confirmed in a headless session.
5. Asks that would fail ordinary CI runs were removed rather than silenced (the `curl` POST ask below High), so a Relaxed localnet deploy passes headless.

## Known holes

The list of what this layer cannot close, and which of them the kit's sandbox and permission rules close, is in [SECURITY.md](../SECURITY.md#known-holes). One cost is deliberate and not a hole: the agent cannot read its own auto-memory with its tools (see [Key material and home credential stores](#key-material-and-home-credential-stores)).

## Migration from profiles

| 1.0 / pre-tier value | Becomes | Applied |
|---|---|---|
| `strict` (the 1.0 default) | `relaxed` | Silently equal, plus one SessionStart line: "curl POST no longer asks below High; mainnet `--final`/close/burn now deny" |
| `paranoid` | `high` | A raise, immediate |
| `autopilot` | `relaxed` | Tighter than autopilot, so immediate; the notice names `safe-ai-skill allow --scope transfer` |
| 1.0 `off` | not migrated | Set aside with "`safe-ai-skill tier off` (confirm) or `SAFE_AI_SKILL_DISABLE=1`" |
| the pre-tier `mode.json` | `tier.json` v1 | In `migrate.rs`; never to a tier below `relaxed` |

`profiles:`, `ask_all`, the autopilot cap and the profile names as policy keys are removed; a policy that still has them loads, and SessionStart lists them as ignored. Raw `.env` reads stay denied for everyone after the upgrade, so no confidentiality loosening occurs.

## Shared lists

Three line-oriented files at the root of this repository in `policy/shared/`, plus a `MANIFEST`:

| File | Records | Owner |
|---|---|---|
| `credentials.list` | `class os sb glob`; a leading `!` marks an exception (readable) | joint; the `sb` column (the lowest kit tier whose sandbox `denyRead` carries the entry) is the kit's |
| `exfil-hosts.list` | `tier host`; 70 / 79 / 84 cumulative by tier | kit (curation), seeded from `firewall.sh` |
| `onchain-verbs.list` | `class cluster argv…` (`irreversible` or `recoverable`; `any` or `net`) | plugin |

- **Provenance:** seeded once from the kit's `firewall.sh` at ai-kit `42755ab` (rule set 7) plus this plugin's lists. From then on `policy/shared/` is the source and the kit vendors it.
- **Integrity:** `MANIFEST` carries the contract version and a count and sha256 per file. The engine embeds the lists at build (`include_str!`), so the embedded bytes equal `policy/shared/*`; CI checks that. A list that fails to parse at runtime makes the gates that depend on it hard-guard `ask` (fail closed).
- **Extension:** you can union entries in (`secrets.exfil_hosts_extra`, `secrets.key_material_extra_globs` in user or repo policy); nothing removes an entry.
- **Versioning:** MAJOR when an entry is removed or semantics loosen, MINOR when entries are added, PATCH for comments. The kit vendors the files at a pinned commit (the same commit as its plugin pin) and diffs them in CI. SessionStart prints `contract <version> <manifest sha[:12]>` and, when the kit's vendored `PIN` is present, reports a mismatch (informational, never a policy input).
- **Corpus:** `policy/shared/corpus/*.jsonl` holds the conformance cases both parsers run; changing an expectation needs both owners.

## See also

- [README: Read this first](../README.md#read-this-first-what-this-plugin-cannot-protect-on-its-own) and the tier table
- [SECURITY.md](../SECURITY.md#recommended-setup): recommended setup, known holes by layer
- [docs/drafts/aikit-firewall-split.md](drafts/aikit-firewall-split.md): the proposed kit-side changes
- [ai-kit#264](https://github.com/solanabr/ai-kit/issues/264) (firewall scope) and [ai-kit#265](https://github.com/solanabr/ai-kit/issues/265) (docs)
