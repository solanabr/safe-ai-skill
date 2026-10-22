<!--
DRAFT. A proposed solanabr/ai-kit PR (code and docs). Not opened, not posted. Do not paste this file into an issue.
The two issues it follows from are posted:
  https://github.com/solanabr/ai-kit/issues/264  (firewall scope: what the kit keeps, what moves, kit fixes)
  https://github.com/solanabr/ai-kit/issues/265  (docs: say which layer enforces each rule)
Evidence: ai-kit at 42755ab (kit 2.4.0, rule set 7), read with `git show 42755ab:<file>` and by generating all four tiers.
Line numbers are for 42755ab and may have moved on main.
Plugin side: safe-ai-skill 1.1.0 (unreleased when this was written). The kit pins safe-ai-skill 1.0.0 (2997280e).
Tags: [V] verified in source or by running a generated tier, [I] inferred, not tested, [U] unverified or disputed.
-->

# Proposed kit PR: split the firewall with safe-ai-skill 1.1.0

Relates to [ai-kit#264](https://github.com/solanabr/ai-kit/issues/264) and [ai-kit#265](https://github.com/solanabr/ai-kit/issues/265). Contract: `policy/shared/` and the shared-contract notes in the [safe-ai-skill repo](https://github.com/solanabr/safe-ai-skill); tier semantics: [docs/tiers.md](../tiers.md).

**Depends on:** safe-ai-skill 1.1.0 released, and the kit's plugin pin moved to its SHA (migration steps M3 to M8 in the contract). Nothing here asks the kit to drop a protection before the plugin has demonstrably replaced it: the retirement steps (A6) are gated on a green cross-stack corpus run.

**Split.** The kit owns the OS sandbox, permission rules, tier selection and regeneration (`/firewall`, `security.json`), and the git, publish, fetch-and-execute, `gh` and MCP tool-name gates. safe-ai-skill owns the Solana-semantic gates, secrets for plugin-only users, supply chain, a labelled best-effort exfil tripwire, and takes the tier as an input. Shared: versioned list files, a conformance corpus, one headless rule.

---

## Part A: code

### A1. Vendor the shared lists and diff them in CI

Add `scripts/vendor-shared.sh <sha>`: copies `policy/shared/{credentials,exfil-hosts,onchain-verbs}.list`, `MANIFEST` and `corpus/` from the plugin repo at `<sha>` into `.claude/policy/shared/` and writes `.claude/policy/shared/PIN` (`repo commit contract manifest_sha256`). Run it in the same PR that bumps the plugin pin in `.claude-plugin/marketplace.json`.

`firewall.sh apply` reads the vendored lists at apply time instead of the hand-kept arrays, and the `DOMAINS_*` and `SB_*` arrays are deleted once the output matches:

| Kit array today | Becomes |
|---|---|
| `SB_CREDENTIALS` (13), `SB_HOST_CREDENTIALS` (10, Medium), `SB_BROWSER_STORES` (22), `DENY_CREDENTIALS`, `DENY_BROWSER_STORES` | `credentials.list`: each row projects to a `Read(<glob>)` deny at every tier and to sandbox `denyRead` from the row's `sb` tier |
| `DOMAINS_EXFIL_SINKS`, `DOMAINS_TUNNELS`, `DOMAINS_PASTE_AND_DROPS` (70 / 79 / 84) | `exfil-hosts.list`: `deniedDomains` by tier |
| `DENY_IRREVERSIBLE_ONCHAIN` capability-destroying shapes | `onchain-verbs.list` `irreversible` rows (see A6) |

Intended diffs in the generated tiers, and only these: `~/.config/solana/id.json` gets `sb=never` (a sandboxed `solana` and `anchor` must be able to sign; agent reads stay denied by `Read()` and by the plugin); `~/.aws` stays `sb=relaxed`; `~/.config/solana/**` (except `cli/config.yml`) gains a `Read()` deny; `~/.ssh/config`, `known_hosts` and `*.pub` stay readable. Safari and Bitwarden's macOS path are added where the list covers them and the kit did not [V].

**CI (kit):**
- vendored bytes match `PIN`, and `PIN.commit` equals the plugin SHA in `marketplace.json`;
- generated settings for all four tiers equal the list projection (`denyRead`, `Read()` denies, `deniedDomains` counts 70 / 79 / 84);
- a nightly job diffs `MANIFEST` against upstream at that SHA;
- the shared corpus runs (`tests/test_shared_corpus.py`): for each tier, `firewall.sh apply <tier>` into a scratch settings copy, evaluate the generated `permissions.deny` against the call, pipe the PreToolUse JSON through the four hooks, and merge into the `kit` verdict. A sampled subset re-runs live through `scripts/cc-conformance.sh`;
- a cross job runs both stacks (the pinned plugin binaries are available in the kit's CI) and asserts the `combined` column and the end-state invariants: never kit `ask` with plugin `ask`, never plugin `allow` with kit `ask`, no `ask` in any headless row.

### A2. Hooks read `enforced`, and `security.json` is protected (#264 task 3)

- `lib-headless.sh:273-277` reads `enforced.tier`, not the declared tier. Decide whether to keep `KIT_FIREWALL_TIER` (`:271`).
- Add `Edit()` deny and sandbox `denyWrite` for `.claude/security.json` and `.claude/bin/**` at every tier. Today self-protection exists at High only (`firewall.sh:425`), and one in-repo edit can silence the on-chain, egress and fetch-exec hooks mid-session [V, static reading; the live edit was not run].
- Decide whether `bash .claude/bin/firewall.sh apply <looser>` run by the model should be denied; today it prompts in default mode and runs unasked under bypass [V].

safe-ai-skill reads `.claude/security.json` (`tier`, `declared.tier`, `enforced.tier`; a regular file up to 256 KiB) only as a **raise-only hint**: it can raise the plugin's tier, never lower it, so the kit's file being rewritten by an agent can't loosen the plugin.

### A3. One headless rule, and no repo-settable escapes (#264 task 5)

`kit_is_headless()` (`lib-headless.sh:301-311`) honours `KIT_FIREWALL_HEADLESS`, `CI` and `GITHUB_ACTIONS`, and `CONFIRM_MAINNET=1` turns the headless mainnet deny into a pass. A repo's committed settings `env` probably reaches these [I, high confidence: a repo `env` block delivered a disable switch to safe-ai-skill in an earlier review]. Adopt the shared rule (contract section 3.3), identical on both sides:

1. Headless is on when `SAFE_AI_SKILL_HEADLESS` or `KIT_FIREWALL_HEADLESS` is `1`/`true`, when any of `CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, `BUILDKITE`, `JENKINS_URL` is set and not `0`/`false`, or when `/dev/tty` can't be opened for reading. Any signal turns it on; **nothing turns it off** (`KIT_FIREWALL_HEADLESS=0` and `CI=0` don't un-headless).
2. When headless, every `ask` becomes a `deny`, with the reason naming the interactive route. Retire the kit's "silent when headless" for recoverable asks: the asks it silenced (devnet value moves, curl POST at Relaxed) no longer exist in the end state.
3. Ignore `CONFIRM_MAINNET` and every `CONFIRM_*` for on-chain actions (user-scope grants made interactively are the only escape, and they live in the plugin). `CONFIRM_PUBLISH` stays a kit-only matter for npm and cargo publish.

Test: a repo-scope `env` that sets `CI=0`, `KIT_FIREWALL_HEADLESS=0` or `CONFIRM_MAINNET=1` cannot turn headless off or satisfy an on-chain escape.

### A4. The `.env` rows: implement them, or remove them from the docs (#264 task 1)

`README.md:173-174` and FIREWALL-SPEC section 3 and 3.1 claim a Medium write-deny and a High read-deny. The generator has no `.env` rule at any tier, and `secrets-guard` passes `cat .env` and `sed -i … .env` at Medium and High [V, tested]. Pick one:

- **Implement** (preferred for Medium and above): sandbox `denyWrite` for `**/.env`, `**/.env.local` at Medium and `denyRead` at High (only the sandbox holds against `sed -i`, `perl -pi`, `python3 -c`), plus an `Edit()` deny. Note that `denyRead` on `.env` also stops sandboxed tools that load it themselves (a test run with dotenv); decide whether High accepts that.
- **Remove** the rows from README, FIREWALL-SPEC and `security.json` (B2 to B4 already carry the corrected text).

Either way safe-ai-skill keeps denying raw agent reads of project `.env` at every tier. Its opt-in raw read (`safe-ai-skill tier --env-read ask|tier`) is user scope only and works only while the sandbox is declared on. Bash writes to `.env` are not covered by the plugin at any tier, so the sandbox rows are the only thing that can close them.

### A5. `/firewall` lowers through the plugin's confirmation (Q6)

Proposed change to `.claude/commands/firewall.md` (exact current text not re-read for this draft [U]): after `firewall.sh apply <tier>` succeeds, run

```bash
safe-ai-skill tier <tier> --project
```

when the `safe-ai-skill` binary is on `PATH` or resolvable from the plugin's `bin/`; otherwise print that command for the user to run. A raise applies at once. A lowering creates a pending request in the plugin: Claude Code shows the user a code in a hook message, and the lowering takes effect when the user's next prompt is exactly `safe-ai-skill confirm <code>`. The kit must not try to confirm it, and must not write any handoff file: the plugin's authenticated `tier.json` is the only user-scope tier store. Until this lands, the kit's hint stays raise-only and `/firewall` prints the command.

SessionStart and `/doctor` show `tier: <t> (<source>); sandbox: <state>` from the plugin next to the kit's own tier line, so a mismatch is visible.

### A6. The irreversible set, and a fail-closed fallback hook (#264 item 8, contract M5 and M7)

After the corpus passes on the plugin:

- Remove `solana transfer|close|authorize|withdraw-from-nonce-account` and `spl-token burn|close` from `DENY_IRREVERSIBLE_ONCHAIN`: the irreversible set now comes from `onchain-verbs.list`, and the counterparty verbs are gated by the plugin's cluster resolution, caps and grants (ask on mainnet or Unknown, deny at High).
- Semantics, identical on both sides: **deny on mainnet or an Unknown cluster** (anything not positively identified as localnet or devnet, testnet included); **ask on a positively identified localnet or devnet**; never relaxable by a grant, tier, repo or env. Default-wallet `solana-keygen new|recover --force` stays a deny on every cluster.
- Drop the devnet ask and `CONFIRM_MAINNET`; retire `onchain-guard`'s cluster parser and mainnet/devnet logic.
- Keep one minimal hook, **fail-closed**: while safe-ai-skill is not enabled it denies every `irreversible` row from the vendored list on every cluster (it has no resolver, so every cluster is Unknown). While the plugin is enabled it defers `irreversible net` rows to the plugin (so an identified devnet asks) and still denies `irreversible any`. The Class U plain-form deny globs move into this hook, because a glob can't be conditional. SessionStart warns when the plugin is disabled that mainnet gating is off.
- Open: how the hook knows the plugin is enabled, including when the plugin's engine can't run on the platform (PowerShell-only Windows, no prebuilt binary). Treat an unreadable `enabledPlugins` as disabled; consider a liveness signal.

### A7. Hooks fail closed; smaller kit fixes (#264 tasks 4 to 8)

- A missing hook script exits 0 (`settings.json:703-744`), awk errors exit 0 (`secrets-guard.sh:34-39`, `egress-guard.sh:229-234`, `fetch-exec-guard.sh:63-68`), and an unknown or unparseable tier falls back to relaxed (`lib-headless.sh:280-283`). At minimum the A6 hook should fail closed, and an unknown tier should resolve to the strictest tier.
- `excludedCommands`: cut the 8 entries to FIREWALL-SPEC section 7.1's set, or justify each in the docs. An excluded command lifts the sandbox for the whole command line (`git push -h; curl https://webhook.site/…`), and `anchor test*` and `surfpool *` run unsandboxed with access to the home credential stores [V].
- `WebFetch(*)` is in `allow` (`firewall.sh:343`). Test whether `deniedDomains` governs WebFetch [I, likely not]; if not, generate `WebFetch(domain:…)` denies from the exfil list or narrow the allow.
- `README` says `~/.aws` stays open at Relaxed but `firewall.sh` denies it; says the Solana config dir stays readable but `id.json` is in Relaxed `denyRead` [V]. Run a sandboxed `solana address` and a deploy at Relaxed [U] and fix whichever side is wrong (`sb=never` for `id.json` is the proposed fix).
- `security.json:13` says three PreToolUse hooks; there are four. Remove the stale `TODO(T1)` at `firewall.sh:1357`. README says writes outside the repo are allowed at Relaxed; `firewall.sh:1466-1474` fences them at every sandboxed tier.
- Open checks: do the hooks and rules apply inside subagents (`Agent(*)` is allowed) [U]? Does `kit_vault_re` cover host tokens for Bash at Relaxed [U]?

---

## Part B: docs (#265)

`tests/test_doc_gates.sh` parses the existing gate table's "Where" column. Put the new table under its own heading and either exclude it from the parser or extend the test so every kit cell resolves to a rule string in a generated tier or a pattern in the named guard. The safe-ai-skill column can't be checked from the kit; it is checked by the corpus.

### B1. `docs/firewall.md`: add "Who enforces what" after line 5

````markdown
## Who enforces what

The firewall has four enforcement layers. Three ship in this kit. The fourth is the [safe-ai-skill](https://github.com/solanabr/safe-ai-skill) plugin, which the full install and the plugin install both enable.

- **Kit sandbox.** Claude Code's OS sandbox (`sandbox.*`). On at Relaxed, Medium and High; off at Off. It applies to every process a sandboxed Bash command starts, whatever the command looks like. It doesn't apply to the file tools, to MCP server processes, or to a command line led by one of the eight `excludedCommands`.
- **Kit permission rule.** `permissions.deny` globs. They match the literal command or tool form at every permission mode, including `bypassPermissions`. A wrapper, a variable, or a path-qualified binary does not match.
- **Kit hook.** `secrets-guard.sh`, `onchain-guard.sh`, `egress-guard.sh` and `fetch-exec-guard.sh`. Matcher: `Bash|mcp__context-mode__.*`. They parse the command and decide per statement. They fail open if a script is missing or awk fails.
- **safe-ai-skill.** The plugin's own PreToolUse, PostToolUse, UserPromptSubmit and SessionStart hooks. Active only while the plugin is installed and enabled. String and semantic analysis like the kit hooks, in a separate engine; they cover Read/Grep/Glob, Write/Edit, every `mcp__*` server and every Bash call. The plugin's tier (`relaxed` by default) is an input: this kit's `security.json` can raise it, never lower it.

R/M/H = Relaxed/Medium/High. "all" = every tier, Off included. "—" = this layer does nothing for the rule. The safe-ai-skill column describes 1.1.0 at the default tier unless a tier is named. See safe-ai-skill's `docs/tiers.md` for the full per-tier table.

| Rule | Kit sandbox | Kit permission rule | Kit hook | safe-ai-skill 1.1.0 |
|---|---|---|---|---|
| SSH, GPG, keychains, password managers, `~/.claude/.credentials.json` | `denyRead` R/M/H | `Read()` deny, all | `secrets-guard`, all | read denied (Read, Grep, MCP path args, Bash readers), all; `~/.ssh/config`, `known_hosts`, `*.pub` readable |
| Browser profiles, wallet-extension stores | `denyRead` R/M/H | `Read()` deny, all | `secrets-guard` pattern list, all (partial) | read denied, all |
| `~/.aws`, host tokens (`~/.npmrc`, `~/.netrc`, `~/.git-credentials`, `gh/hosts.yml`, kube, docker, `~/.pypirc`, gem, cargo) | `denyRead` R/M/H for `~/.aws`; host tokens M/H only | `Read()` deny, all | `secrets-guard`: coverage at R not established | agent reads denied, all; command forms (`gh auth token`, `git credential fill`, `aws configure get *secret*`, …) denied |
| Default wallet `~/.config/solana/id.json` | `denyRead` R (`id.json`) and M/H (`*.json`; `cli/config.yml` readable); `sb=never` proposed | `Read()` deny and `Bash(cat *id.json)`-style globs, all | `secrets-guard`, all | read denied; overwrite, delete and `keygen --force` denied on every cluster, all |
| Project keypairs (`target/deploy/*-keypair.json`) | — | `Bash(cat *keypair*.json)` only; the Read tool is allowed by design | — | read denied, all |
| Project `.env` **read** | — | — | — (`egress-guard` blocks *sending* it, R/M/H) | denied by default, all; opt-in raw read is user scope only, with the sandbox declared on; `.env.example` and `.env.schema` readable |
| Project `.env` **write** | — | — | — | Write/Edit/MultiEdit and agent `env set\|unset` denied M/H; Bash writes (`sed -i`, `python3 -c`) not covered |
| Class U: `--final`, `program close`, `program-v4 finalize`, `spl-token authorize … --disable`, `close-mint`/`close`/`burn`, `anchor idl erase-authority`/`close`, `close-vote-account` | — | deny glob, all (plain form) | `onchain-guard` deny, all (wrapped forms) | deny on mainnet, Unknown and testnet; ask on an identified localnet or devnet; never grantable, all |
| Class C: transfer, deploy, upgrade, buffer write/close, `extend`, authority change | — | deny glob for some plain forms | `onchain-guard`: Off silent; R/M ask on every cluster; H mainnet denied | mainnet or Unknown: ask, deny at High; a covering confirmed grant allows below High; within-cap devnet transfer allowed below High; `set_authority`, `account_close` never relaxable |
| `solana-keygen new`/`recover --force` without `-o` | — | — | `secrets-guard`, all | deny, all |
| Spend caps, time-boxed grants | — | — | — | yes (state authenticated, lowering needs a typed confirmation) |
| Value-moving calls on any MCP server | — | tool-name denies for `context-mode`, Cloudflare, Playwright executors (M/H) | `context-mode` only | every `mcp__*` server, by verb and payload: ask, deny at High |
| A secret file sent to the network (`curl -d @.env`, `--upload-file`, pipe into `nc`) | `deniedDomains` (known sinks only), R/M/H | — | `egress-guard` deny, R/M/H | deny: key material at every tier, project env files from R (best-effort tripwire) |
| Known exfil, tunnel and paste hosts | `deniedDomains` 70/79/84, Bash subprocesses only | — | `context-mode` URLs only | deny from R, list sized 70/79/84 by tier |
| Inline `curl` POST body to an unlisted host | — | — | — | ask at High only |
| WebFetch to any host | not established whether `deniedDomains` applies | `WebFetch(*)` is in `allow` | — | — |
| Fetch-and-execute of an undeclared package | — | — | `fetch-exec-guard`: Off silent; R/M note; H deny | `curl … \| sh` asks |
| Publish, force push, history rewrite, destructive git, `git config` exec keys, `gh api` | — | destructive git denied, all; `gh api` M/H | `egress-guard`, R/M/H | — |
| Skill and `ext/` supply chain | — | — | — (CI review and submodule pins) | SessionStart pin and drift; deny in place from R; HIGH heuristic denies at H; nothing moved by default |
| Output redaction of secrets in tool output | — | — | — | all tiers |
| A private key or seed phrase pasted into a prompt | — | — | — | blocked |
| Kit configuration (`settings.json`, `security.json`, `.mcp.json`) | — | `Edit()` deny, H only; guard hooks: all | — | — |
| safe-ai-skill policy and state | Bash writes outside `allowWrite` fenced, R/M/H | `Edit(/.safe-ai-skill/**)`, all | — | tamper tripwire on its data dir and CLI |
| Bash writes outside the repo | fenced outside `allowWrite`, R/M/H | — | — | — |

### What lives only in safe-ai-skill

Active only while `safe-ai-skill@stbr` is installed and enabled:

- blocking agent reads of the project's `.env` files and project keypairs;
- cluster-aware on-chain gating at Off, where the kit's `onchain-guard` asks nothing;
- spend caps and grants;
- gating value-moving calls on MCP servers other than `context-mode`;
- the runtime skill and `ext/` supply-chain check;
- the pasted-key prompt guard and output redaction.

**If you disable it** (`"safe-ai-skill@stbr": false` under `enabledPlugins`), you keep every kit column and lose every rule above. In particular, no kit tier blocks agent reads of the project's `.env`.

### What safe-ai-skill cannot do without the kit's sandbox

A Claude Code plugin cannot ship `sandbox` or `permissions`. The plugin is a pattern layer, and without the sandbox under it none of these are stopped:

- a script written in one call and run in the next;
- base64 or variable-built paths, and `python3 -c` or `node -e` one-liners;
- a compiled helper, or any subprocess, reading a credential file;
- network egress to a host no hook recognises;
- Bash writes to `.env`;
- code running as your user rewriting the plugin's own state.

The kit's sandbox (Relaxed and up) closes those for sandboxed Bash commands. It doesn't close them for MCP server processes, or for command lines led by an excluded command (`surfpool`, `anchor test`, `git push/pull/fetch`, `gh pr/run/issue`). Values already in the model's context are closed by nothing.
````

Replace the safe-ai-skill row at `docs/firewall.md:32` with: `| [safe-ai-skill](../README.md#security-firewall-safe-ai-skill) | The plugin's own hooks, active only while it is installed and enabled | The only layer that blocks agent reads of the project's `.env` and of project keypairs through the Read tool; `/setup-mcp` relies on it. Also gates secrets and on-chain writes, so some commands pass two checks. See [Who enforces what](#who-enforces-what) |`.

Correct "Blocked at every tier" at `docs/firewall.md:25-27` to "Blocked at Relaxed, Medium and High. At Off `egress-guard.sh` does not run; the deny globs in the rows above still apply" (`egress-guard.sh:64-65` exits at Off). Replace the `.env` row at `:76` and the "What Relaxed actually guarantees" paragraph at `:119` with text that says no kit layer has a `.env` rule at any tier unless A4 implements one, that safe-ai-skill blocks direct agent reads while installed, and that a value already read has reached the model provider.

### B2. `README.md`

**Replace `### Security firewall: safe-ai-skill` (lines 147-159)** with:

````markdown
### Security firewall: safe-ai-skill

Part of the kit's firewall is a separate Claude Code plugin, [safe-ai-skill](https://github.com/solanabr/safe-ai-skill). The kit enforces its sandbox, its permission rules and its four guard hooks. safe-ai-skill enforces the Solana-semantic gates (cluster-aware mainnet, value-moving and irreversible actions, spend caps and grants), blocking of agent reads of keypairs, credential stores and project `.env` files, output redaction, the session-start skill supply-chain check, a pasted-key prompt guard and a best-effort exfil tripwire. It takes the kit's tier as an input: `.claude/security.json` can raise the plugin's tier, never lower it.

**Those rules are active only while the plugin is installed and enabled.** Which layer enforces each rule is tabulated in [docs/firewall.md](docs/firewall.md#who-enforces-what).

- **Plugin install:** `solana-ai-kit@stbr` depends on `safe-ai-skill@stbr`, so installing the kit installs it.
- **Full install:** `.claude/settings.json` registers the `stbr` marketplace and enables `safe-ai-skill@stbr`. After you trust the folder, run `claude plugin install safe-ai-skill@stbr --scope project` once.
- **`--agents` install (Codex, opencode):** the hooks are Claude Code only. Vet add-ons with `npx @stbr/safe-ai-skill add skill|mcp <source>`.
- **Version:** the `stbr` marketplace pins safe-ai-skill **<1.1.0 SHA once released>**. A plugin fix reaches you when the kit moves that pin.

**Without the plugin** (`"safe-ai-skill@stbr": false`) you keep everything the kit enforces and lose `.env` and project-keypair read blocking, on-chain gating at Off, spend caps, gating of value-moving calls on MCP servers other than `context-mode`, redaction and the supply-chain check.

**Without the kit's sandbox** the plugin is hook-level string analysis with known holes (cross-call scripts, encoded paths, subprocess reads, Bash writes to `.env`, egress to unlisted hosts). Keep a sandboxed tier (Relaxed or above) when you rely on it. Run both.
````

**Tier table cells** (README lines 171-174):

- **Off, "On-chain and destructive".** Replace with: Two kit hooks still run. `secrets-guard` blocks credential reads and `solana-keygen new --force` over your default wallet. `onchain-guard` refuses the irreversible set (until A6 retires it in favour of the shared list). **The kit does not ask about mainnet or authority writes at Off**, and the egress and fetch-and-execute hooks do not run; with safe-ai-skill enabled, mainnet and Unknown-cluster writes still ask, and Class U denies. The deny rules apply here too: the git transport overrides, `gh issue delete`, `gh repo delete`, `git config alias.<name>`, `git --config-env`, `git reflog delete` and `git reflog drop` included.
- **Relaxed, "Readable".** Leaves open to commands: `~/.config/solana/cli/config.yml`, the project's `.env` (safe-ai-skill blocks direct agent reads of it while installed), project keypairs, and registry and git-host tokens; the file tools are denied those token files at every tier. Denies the never-allowed set: SSH and GPG keys, `~/.aws`, `~/.config/solana/id.json`, keychains and keyrings, browser profiles and wallet extension stores, shell startup files, shell and REPL history, `~/.cargo/config.toml` and `~/.cargo/credentials*`, `~/.gitconfig`. A sandboxed command that loads the default wallet from `id.json` may fail at this tier [U]; point `wallet =` or `--keypair` at a file outside the denied set, or run it yourself (A1 proposes `sb=never`).
- **Relaxed, "Writable".** Replace "Writes outside the repo are allowed." with "Shell writes outside these paths are refused by the sandbox."
- **Medium, "Writable".** Replace the `.env` sentence with "Shell writes outside these paths are refused by the sandbox, as at Relaxed. [If A4 implements it: `.env` is `denyWrite`. Otherwise: no kit rule covers the project's `.env` at this tier.]"
- **High, "Readable" and "Writable".** Same pattern: state what A4 decided; remove "the model can no longer read it back" if `.env` read-deny is not implemented.

### B3. `FIREWALL-SPEC.md`

- **Section 3 table, `.env` row:** `read+write — write deny not implemented in rule set 7 (see 3.1)` at Medium, `read+write — read deny not implemented in rule set 7; blocked for the agent only by safe-ai-skill` at High (or the implemented rows, per A4).
- **Section 3.1:** prepend "**Status (rule set 7):** not implemented. `firewall.sh` emits no `.env` rule at any tier, and `secrets-guard` lets `cat .env` and `sed -i … .env` through at Medium and High. The intended mechanism, if implemented, is sandbox `denyWrite` (Medium) and `denyRead` (High), because only the sandbox holds against `sed -i`, `perl -pi` and `python3 -c`."
- **New section 3.7 "Rules owned by safe-ai-skill":** the kit does not implement these; they hold only while the plugin is installed and enabled: project `.env` and keypair and credential-store read blocking, cluster-aware on-chain gating at Off, spend caps and grants, value-moving MCP verbs on servers other than `context-mode`, the runtime skill supply-chain sweep, the pasted-key prompt guard and output redaction. The plugin takes the tier as an input; both sides consume the shared lists and corpus. Full matrix: `docs/firewall.md`, *Who enforces what*.
- **Section 5 item 6:** append "The conflict exists because the kit's own `.env` rows were never implemented, so the plugin's `secret_read` hard guard is the only `.env` control kit users have."

### B4. `.claude/security.json` comment strings

The generator rewrites this file, so the strings probably live in `firewall.sh` or `install.sh` [U where emitted].

- `_tiers.relaxed`: "Project .env and keypairs stay readable to the kit; safe-ai-skill, when installed, blocks direct agent reads of both."
- `_tiers.medium`: remove ".env writes denied," (unless A4 implements it). "… No .env rule. Hard-fails headless by design."
- `_tiers.off`: append "The on-chain approval prompt, the egress hook and the fetch-and-execute hook do not run at this level."
- `_scope`: "four PreToolUse hooks"; replace "it deliberately leaves the project .env readable" with "no level has a .env rule; safe-ai-skill blocks direct agent reads of .env when installed"; append "Solana-semantic gates, .env tooling and redaction, and the skill supply-chain check live in the safe-ai-skill plugin and apply only while it is enabled."

---

## Acceptance checklist

- [ ] The shared lists are vendored with a `PIN`, and the kit's generator and hooks consume them; CI diffs the vendored bytes, the generated tiers (70 / 79 / 84 hosts) and `PIN.commit` against `marketplace.json`.
- [ ] The kit runs the shared conformance corpus in CI, and a cross job asserts `combined` from the real verdicts of both stacks. `onchain-guard.sh` cluster logic is removed only after the plugin passes it.
- [ ] The agent cannot change the effective tier mid-session through `security.json`, by Edit or Bash, at any tier. The hooks read `enforced`. An unknown tier, or a missing or broken irreversible hook, results in deny.
- [ ] Repo-scope `env` cannot turn headless off or satisfy `CONFIRM_*` for on-chain actions; headless asks become denies. A test proves it.
- [ ] `/firewall` runs (or prints) `safe-ai-skill tier <t> --project`, and a lowering waits for the plugin's typed confirmation.
- [ ] With safe-ai-skill disabled, the irreversible set and default-wallet `keygen --force` are still denied at every tier and on every cluster, Off included. With it enabled, the combined verdict is deny on mainnet or an Unknown cluster and ask on a positively identified localnet or devnet.
- [ ] Either `.env` sandbox rows exist and are tested, or no doc or JSON comment claims one (grep the four generated tiers for `.env`).
- [ ] `docs/firewall.md` has "Who enforces what" with the four columns; README, `docs/firewall.md` and FIREWALL-SPEC each say part of the firewall is the plugin, active only while installed and enabled, and link the install command. The README names the pinned plugin version and SHA, and a test or release checklist item fails when they disagree.
- [ ] README Off row and `docs/firewall.md:25-27` match `onchain-guard.sh:71-72`, `egress-guard.sh:64-65` and `fetch-exec-guard.sh:73-74`; `~/.aws` and `id.json` are described the same way in the README, `docs/firewall.md` and `firewall.sh`; `security.json` `_scope` says four hooks.
- [ ] WebFetch to a listed exfil host is denied, or the docs state it is not and why. `excludedCommands` is cut to the FIREWALL-SPEC section 7.1 set, or each remaining entry is justified.
- [ ] These stay marked unverified until someone tests them: whether `deniedDomains` governs WebFetch, whether `secrets-guard` covers host tokens at Relaxed, how Claude Code merges two hook decisions (deny > ask > allow), whether a sandboxed `solana address` fails at Relaxed, and whether hooks and rules apply inside subagents.
