# Codex CLI adapter (experimental)

> **Experimental.** Not part of the support contract yet. The mapping follows Codex's hook code
> at tag `rust-v0.164.0` (commit `6aaac69`, the installed Codex CLI 0.164.0). Codex itself says
> tool hooks are "a useful guardrail, not a complete enforcement boundary". That applies here
> too: read [Not covered](#not-covered) before relying on it.

`safe-ai-skill adapt codex <entry>` runs one of safe-ai-skill's hooks on a Codex CLI hook
payload and answers only in forms Codex honours. Codex runs it through the plugin's POSIX shim
(`safe-ai-skill`), the same entry point Claude Code uses: the shim finds the engine, checks its
sha256, and turns any engine failure into a block. Tracking issues: #23, #26.

## Install

1. Install the shim and the engine:
   - `install.sh` from 1.2.0 puts the shim at `~/.local/bin/safe-ai-skill` and the engine
     beside it as `safe-ai-skill-<platform>` (macOS and Linux).
   - Don't point the hooks at the Claude Code plugin's copy: its path carries the plugin
     version and disappears on the next update.
   - The npm package's `safe-ai-skill` is a Node launcher, not the shim, and `cargo install`
     builds the bare engine. Neither turns an engine crash into a block, so don't wire Codex
     hooks to them.
2. Copy [`adapters/codex/hooks.json`](../adapters/codex/hooks.json) to `<repo>/.codex/hooks.json`
   (project) or `~/.codex/hooks.json` (user). If the file already exists, merge the groups into
   it. Codex runs each hook command with `$SHELL -lc`, so `safe-ai-skill` must be on the `PATH`
   of a login shell. Otherwise, replace it in the commands with the shim's absolute path.
3. Start Codex and approve the hooks with `/hooks`. Codex skips untrusted hooks, and skips a
   hook again after it changes, until you re-approve it. Project `.codex/` layers load only in
   trusted projects.
4. Run `safe-ai-skill doctor --codex`, and run it again after every safe-ai-skill or Codex
   update. It runs each configured safe-ai-skill hook the way Codex does, with a payload that
   must be denied (and, for the gates, one that must pass). It fails (exit 1) on a hook that
   cannot start, times out, answers wrongly or is not the shim.

**When the hook command itself can't start, Codex runs the call.** Exit 127 from the login
shell (the shim is not on its `PATH`, a path an update removed, a typo in the program name)
marks the hook failed, and Codex runs the tool call unchecked; the shim never gets the chance
to deny. The template therefore ends every PreToolUse command with `|| printf …`, which prints
a deny when the `safe-ai-skill` command fails to run. That fallback is plain shell: it does not
help if `$SHELL` itself is broken, and it is only in the template's PreToolUse commands. A typo
after `adapt` (`adapt codx gate-bash`) reaches the shim, which denies every call until the entry
is fixed.

**Migrating from 1.1.0.** The `safe-ai-skill-codex` wrapper is gone. Its fail-closed checks are
now in the shim. Replace `safe-ai-skill-codex <gate>` with `safe-ai-skill adapt codex <gate>` in
your `hooks.json`, add the `SessionStart` group, re-approve with `/hooks`, then delete the
wrapper. Until then, an old wrapper next to the new shim keeps working, because it calls the
shim and accepts its answers.

## What it gates

| Codex call | Entry | Notes |
|---|---|---|
| `Bash` (shell and `exec_command`) | `gate-bash`, `gate-bash-secrets` | Same input as Claude Code (`tool_input.command`). A `tool_input.workdir`, if present, is where relative paths resolve. |
| `apply_patch` tool | `gate-tamper` | Every file the patch adds, updates, deletes or moves to is checked. A patch touching more than 1000 files is denied unread. |
| `apply_patch` run through the shell (heredoc, quoted argument, `$'…'`, piped) | `gate-bash-secrets` | Codex intercepts these and applies them as patches, so they get the same per-file checks. |
| `mcp__<server>__<tool>` | `gate-mcp` | Receives the raw MCP arguments. |
| Session start (`startup`, `resume`, `clear`, `compact`, `fork`) | `session-start` | The tier and state report, as `systemMessage` (shown to you) and `additionalContext` (given to the model). The supply-chain sweep is not run: it reads Claude Code's skill dirs and `.mcp.json`, which Codex does not load. Codex skills (`.agents/skills`, `$CODEX_HOME/skills`) and the MCP servers in Codex's `config.toml` are not scanned, and the report says so. |
| Tool results (opt-in) | `redact --block-with-redaction` | See [Redaction](#redaction-opt-in). |

**Which firewall checks reach Codex.** `gate-bash-secrets` carries the exfil tripwire, the tamper-content write checks, the download-and-run gate, the env-dump checks (`/proc/*/environ`, printing a secret-named variable, a dump piped elsewhere) and the encoded-command gate for Bash, and `gate-bash` the on-chain gates, so these run under Codex like under Claude Code (every `ask` is a `deny`). `gate-mcp` carries the MCP exfil, staking and token-transfer checks and, from Medium, the refusal of context-mode, Playwright and Cloudflare tools by name ([MCP calls](tiers.md#mcp-calls)). `gate-bash-secrets` also carries the [git and `gh` guard](tiers.md#git-and-gh-guard), the nested-`claude` checks and the High download-and-run rules, so they run under Codex with every `ask` a `deny`. The `ConfigChange` guard (`gate-config`) is a Claude Code hook event only: neither adapter has it, and Claude Code's settings are protected there by the write-time denies instead. There is **no `gate-webfetch` entry** (`CODEX_GATES` is `gate-bash`, `gate-bash-secrets`, `gate-tamper`, `gate-mcp`): Codex runs no hooks for its hosted tools (web search), so the `WebFetch` exfil check has nothing to attach to. A bare `printenv`/`env` dump passes with its secret values visible to the model unless the opt-in `redact` hook is on, because the value blanking is a redaction (PostToolUse) step.

### Self-protection

Under Codex, these targets are also denied, through `apply_patch` and through shell writes.
Shell writes are read with the default-wallet gate's scanner:

- deletes, moves and overwrites of the file, or of a directory holding it;
- globs, and relative paths after `cd`;
- `find -delete`, and `find -exec` with any command except a plain reader (`grep`, `cat`,
  `ls`, …);
- `chmod`/`chown`, and output redirections;
- work-tree-rewriting `git` subcommands: `checkout`, `restore`, `rm`, `mv`, `reset`, `switch`,
  and `clean` / `stash -u` (below).

Literal paths inside interpreter code (`python3 -c "os.remove('…')"`) count too. The targets:

- Codex hook config: `.codex/hooks.json`, `.codex/config.toml`, and `$CODEX_HOME/…`. Symlinks
  are resolved first.
- Claude Code settings: `.claude/settings.json`, `.claude/settings.local.json`, the user's and
  `$CLAUDE_CONFIG_DIR`'s. Claude Code guards these in its own sessions, but nothing does under
  Codex.
- The shim, the per-platform engines beside it and the old wrapper: next to the running engine
  and on `PATH`.
- safe-ai-skill's data dir ([below](#state-tiers-grants-and-audit)), and, for recursive
  removes and moves, the directories above it (`rm -rf ~/.local/share`).
- Shell startup files ([shared with opencode](#shell-startup-files)), because Codex runs its
  hooks through `$SHELL -lc`.
- A relative path naming a state file or a wallet (`tier.json`, `grants.json`, `spend.json`,
  `audit.jsonl`, `id.json`, …). Codex's `exec_command` can run in a `workdir` the hook payload
  does not carry (`exec_command.rs` `pre_tool_use_payload` sends only `command`), so the hook
  cannot tell where such a write lands.

How the broad commands are judged:

- **`find … -delete`, and `find -exec` with anything but a plain reader** (`grep`, `cat`,
  `ls`, `wc`, … with no option that names a program, such as `--pre`): denied when a start dir
  is, or holds, a protected file, whatever the `-name`/`-path` tests say. The gate does not
  evaluate `find` expressions (glob escapes, `~` and `$HOME` expansion and `-o` would all have
  to match `find` exactly), so `find . -name '*.tmp' -delete` in a project with a `.codex/` dir
  is denied. Narrow the start dir (`find src -name '*.tmp' -delete`), or run it yourself.
- **Path-less `git clean` and `git stash -u|-a`**: denied when a protected file exists under the
  tree, tracked or not and dry run (`-n`) or not. Option arguments (`clean -e PAT`,
  `stash -m MSG`) are not paths, and `--pathspec-from-file` counts as path-less.
- **A bare `config.toml` / `hooks.json`** given to `rm`, `unlink`, `shred` or `truncate`. This
  is denied only when a Codex config it could be exists: a `hooks.json` in a Codex home or in a
  `.codex/` at or above the working dir, or a `config.toml` there that defines hooks
  (`[hooks…]`, `hooks.…`, which includes the hook approval state). Removing a `config.toml`
  that defines no hooks cannot turn a gate off. Writing one still can
  (`[features] hooks = false`), so any other writing command given a bare `config.toml` is
  still denied.

### Interactive sessions are denied

Codex runs no hook for `write_stdin` (`handlers/unified_exec/write_stdin.rs`:
`pre_tool_use_payload` returns `None`). Anything the model starts that reads commands from its
terminal would therefore run unchecked whatever is typed into it later. These are denied:

- A shell with no `-c` script and no script file, or whose stdin is the terminal: `bash`,
  `sh -i`, `bash -s`, `bash /dev/stdin`, `bash < /dev/tty`.
- A shell fed by a pipe that only relays the terminal: `cat | bash`, `tee log | sh`,
  `cat | grep -v '#' | bash`.
- A REPL (`python3`, `node`, `irb`, `deno`, `python3 -`, `python3 /dev/stdin`, `-i` anywhere),
  a debugger (`gdb`, `lldb`), `expect`, and a database shell without a command (`psql mydb`,
  `sqlite3 my.db`).
- A loop that runs what it reads: `while read l; do eval "$l"; done`, `read c; $c`,
  `while read l; do sh -c "$l"; done`.
- `xargs` reading the terminal into a shell, interpreter or `eval` (`xargs -I{} sh -c {}`).
- Interpreters that execute their input: `perl -ne 'system $_'`, `ruby -ne …`,
  `awk '{system($0)}'`, `python3 -c 'exec(sys.stdin.read())'`, GNU `sed e`.
- Terminal multiplexers and pty wrappers: `tmux`, `screen`, `zellij`, `byobu`, `dtach`,
  `abduco` (except read-only `ls`/`list-*`/`has-session`), and `script` without a command.
- Remote and switched-user shells: `ssh host` with no remote command (and no `-N`/`-W`),
  `mosh host`, `telnet`, `su` without `-c`, `sudo -i`, `sudo -s`, `chroot dir`.
- Interactive containers: `docker`/`podman`/`kubectl` `exec`, `run` or `attach` with `-i`/`-it`
  and the terminal as input, and `docker compose exec|run` without `-T`/`-d`.
- A command or process substitution of a terminal reader: `bash -c "$(cat)"`, `eval "$(cat)"`,
  `bash <(cat)`.
- The same programs behind a version suffix (`python3.12`), `busybox <applet>`, a runner
  (`uv run`, `poetry run`, `pipx run`, `npx`, `mise exec`, `npm exec`, `rlwrap`), `env -S`, or
  `find -exec`; `nix-shell` / `nix develop` without a command; `socat … EXEC:`; and other REPLs
  (`ipython`, `jshell`, `iex`, …).

The same commands with their input given as arguments, a file or a pipe from a command that
produces it (`echo ls | bash`, `cat script.sh | bash`, `ssh host uptime`,
`find … | xargs sh -c '…' _`) pass.

### `ask` becomes `deny`

Codex PreToolUse honours only `deny`. `permissionDecision: "ask"`, and `allow` without
`updatedInput`, are logged as unsupported and the call runs anyway (`output_parser.rs`
`unsupported_pre_tool_use_hook_specific_output`). So every `ask` reaches Codex as a `deny`, and
the reason says how to go ahead: run the command yourself, approve it in Claude Code, or confirm
a grant there first. An `allow` produces no output. A grant you confirmed earlier still allows
the call (below the High tier), as in a headless session. Claude Code's sandbox counts as off,
because it does not wrap Codex.

### Failures deny

Codex runs the call when a hook exits with anything but 0 or 2, is killed, or prints JSON it
cannot parse (`events/pre_tool_use.rs` `parse_completed`). So the shim turns each of these into
Codex's deny JSON, printed with exit 0:

- no engine for the platform;
- an engine that is not executable, or not an executable for this machine;
- an engine that fails its sha256 check, which is then never run;
- an engine that exits non-zero, aborts or is killed;
- an answer other than nothing or a single deny line.

`SAFE_AI_SKILL_DISABLE` does not apply to the Codex hooks: their environment comes from the
login shell, whose startup files an agent could write. To turn safe-ai-skill off under Codex,
remove its groups from `hooks.json`. `SAFE_AI_SKILL_STRICT=1` still answers Codex with a deny.
A misconfigured entry (the engine's usage error) is denied with a reason saying so. The engine
also exits 0 after a panic under Codex.

### Shell startup files

Both adapters (Codex and opencode) share one guard for the shell startup files of `$HOME`
and of your passwd home:

- **Login-shell files**: `~/.zshenv`, `~/.zprofile`, `~/.zlogin` (also under `$ZDOTDIR`),
  `~/.bash_profile`, `~/.bash_login`, `~/.profile`, `~/.config/fish/config.fish` and
  `~/.config/fish/conf.d/*`. Any write is denied: a line there could set an environment
  variable or shadow `safe-ai-skill` on `PATH` for the next session.
- **Interactive rc files**: `~/.zshrc`, `~/.bashrc` and `$ZDOTDIR/.zshrc`. A write whose text
  sets `PATH` (also zsh's `path` array and fish's `fish_add_path`) or names
  `SAFE_AI_SKILL_*`, `KIT_FIREWALL_*`, `CODEX_HOME` or `OPENCODE_CONFIG*` is denied, through
  file tools, patches and the shell, and so is a copy, move, link or download onto one (its
  content can't be seen). **Since the full-coverage work, the tamper gate (`gate-tamper` and
  `gate-bash-secrets`) also denies every agent write to these rc files, an alias or prompt edit
  included, at every tier**, because they run code on the next shell. This guard's finer
  PATH-and-variable rule therefore only decides which reason text you see; edit these files
  yourself.

Reading or sourcing these files passes. Not seen: other files they `source`, a `PATH` line
built so none of those words appear, terminal or launcher configs, and a directory another
tool puts ahead on `PATH`.

## State: tiers, grants and audit

The data dir is resolved in this order:

1. `CLAUDE_PLUGIN_DATA`, when set.
2. The Claude Code plugin's dir, when it exists (`~/.claude/plugins/data/safe-ai-skill-*`, or
   under `$CLAUDE_CONFIG_DIR`). With both clients installed there is one set of state. If the
   plugin is installed but Claude Code has not created its dir yet, the CLI says to start a
   Claude Code session once, and puts nothing elsewhere meanwhile.
3. Otherwise, the standalone dir:
   - `$SAFE_AI_SKILL_DATA` (an absolute path), else `safe-ai-skill-data` under the platform's
     data root:
     - macOS: `~/Library/Application Support`
     - other unix: `$XDG_DATA_HOME`, else `~/.local/share`
     - Windows: `%LOCALAPPDATA%`
   - It is created on first use, mode 0700.
   - `~` is your account's home from the user database when the dir already exists there,
     otherwise `$HOME`.

The CLI (`safe-ai-skill tier`, `status`, `revoke`, …) resolves it the same way, so `tier high`
in a terminal applies to the Codex hooks. The trust rules are unchanged:

- State relaxes anything only in a trusted dir.
- The standalone dir, whether the default or placed by `SAFE_AI_SKILL_DATA`, `XDG_DATA_HOME`,
  `LOCALAPPDATA` or a different `$HOME`, is trusted only when all of these hold:
  - it is strictly inside your passwd home;
  - no component of its path below the home is a symlink;
  - it is not inside a git repository below the home (a dotfiles repo at the home itself does
    not count);
  - it is not inside the project or the hook's working dir (a session started in the home
    does not count).

  Otherwise its state can only tighten.
- State files keep their MAC under the dir's key.

If you install the Claude Code plugin later, its dir takes over. `session-start` and `status`
(`other_state_dirs`) then name any other dir that still holds state (a `key`), so it is not
dropped silently. The same happens when two launchers resolve different standalone dirs. Copy
the whole old dir (key included) over the one in use to keep your tier, grants and spend
ledger, or delete it.

**Confirmations are not possible under Codex.** Lowering the tier, `allow` grants, `verify
trust` and `verify approve` each wait for a code that only a Claude Code hook shows (in a
`systemMessage`) and accepts (a `UserPromptSubmit` prompt). The process-ancestry check that
guards them looks for an interactive Claude Code CLI, and a Codex hook runs in a new session
without a terminal (`engine/command_runner.rs`). So under Codex no code is announced (the
`session-start` entry skips it, leaving the request for a Claude Code session), and none can be
confirmed. With only Codex installed you can raise the tier and read `status` and the audit
log. Relaxing anything needs a Claude Code session on the same data dir.

## Redaction (opt-in)

Codex PostToolUse cannot rewrite a tool result: `updatedMCPToolOutput` is rejected, and no
`updatedToolOutput` exists (`output_parser.rs`). A hook can only block it:
`{"decision":"block","reason":…}` makes Codex hand the model the reason in place of the result,
as an error (`core/src/tools/registry.rs`). `adapt codex redact --block-with-redaction` uses
that. When a result holds secrets (the patterns and known `.env` values of the Claude Code
`redact` hook), it blocks the result and puts the redacted text in the reason. A result without
secrets passes untouched. To turn it on, add this group to your `hooks.json`:

```json
"PostToolUse": [
  {
    "matcher": "^(Bash|mcp__.*)$",
    "hooks": [
      { "type": "command", "command": "safe-ai-skill adapt codex redact --block-with-redaction || printf '%s\\n' '{\"decision\":\"block\",\"reason\":\"safe-ai-skill: the redaction hook could not run; result withheld.\"}'", "timeout": 10 }
    ]
  }
]
```

The cost:

- The model sees every redacted result as a failed call, with the output in the error text.
  Some models retry, or work around a "failure" that did not happen.
- The command has already run. Redaction hides its output from the model; it does not undo its
  effects.
- Codex sends no PostToolUse for a command still running (an `exec_command` that returns a
  process id; `core/src/tools/context.rs`). So output read later through `write_stdin` polls
  that never complete is not scanned.
- If the engine fails, or the result is too large to scan (over 8 MiB), the result is withheld
  (blocked with a short reason), not passed. A scan that outlives the hook's `timeout` is
  killed by Codex, and the result then passes.
  Without the flag the entry is a usage error, so this hook blocks every result until the
  config is fixed.
- `redact.enabled: false` in the policy turns it off, as for Claude Code.

## Not covered

- **The Codex hook timeout.** If Codex kills the shim at its `timeout`, Codex runs the call. The
  engine answers within 8 seconds, and the template's timeouts (10–20 s) leave room for that.
- **A hook command that cannot start.** Covered by the template's `|| printf` fallback and by
  `doctor --codex` ([above](#install)), not by the shim.
- **Codex skills and MCP servers.** The session start does not scan `.agents/skills`,
  `$CODEX_HOME/skills` or the MCP servers in `config.toml`.
- **Hooks wired to something other than the shim.** The npm launcher, a `cargo install`
  binary or the engine binary called directly lose the failure handling above.
- **Native Windows.** Codex runs hooks with `cmd.exe /C` there, and the shim is POSIX `sh`. Use
  WSL.
- **Real approval prompts.** Codex has no hook `ask`, and grants cannot be confirmed under Codex
  ([above](#state-tiers-grants-and-audit)).
- **`gate-read`, `gate-skill`, prompt guards.** Codex has no Read, Grep, Glob or Skill tool.
  Reads go through the shell, which `gate-bash-secrets` covers. The `UserPromptSubmit` prompt
  guard is not mapped.
- **`write_stdin` into anything else still running.** Starting the shells, REPLs and
  multiplexers listed above is denied. But any other long-running process the model started can
  still be fed input with no gate seeing it: a program of its own that reads commands from stdin,
  a TUI, or a form the list above misses, such as a script file that runs `bash`, or a command
  word the gate cannot expand. Every Bash gate and all of the self-protection is skipped for that
  input.
- **Hosted tools (web search).** Codex does not run hooks for them.
- **Shell writes are judged on their words; nothing is run.** These are not seen:
  - a write whose path is computed (variables the gate cannot expand, string building in
    interpreter code);
  - a write behind `eval` of generated text;
  - a script file the command runs;
  - a path-less `git reset --hard`, `git stash` or `git checkout <branch>` that rewrites a
    tracked protected file.

  Literal paths in `sh -c '…'` and in `-c`/`-e` interpreter code are seen.
- **False positives.**
  - A heredoc body is read as commands, so a heredoc whose text mentions `rm tier.json` can be
    denied.
  - A bare `hooks.json` given to a writing command is denied whenever a Codex `hooks.json`
    exists (a user-scope install always has one). A bare `config.toml` given to a writing
    command other than a removal is always denied. The working dir is unknown in both cases.
  - Destructive `find` and path-less `git clean` / `git stash -u` whose root holds Codex hook
    config, Claude Code settings or a login-shell startup file are denied whatever their tests
    or flags. `find ~ … -delete` is always denied. Each deny gives its reason. Run such a
    command yourself, or narrow its root (for example `find src -name '*.tmp' -delete`).
- **Codex plugin hook files.** A plugin-bundled `hooks/hooks.json` is not protected.
- **Captured payloads.** The tests use payloads built from Codex's source and its own test
  suite (`core/tests/suite/hooks.rs`), not captured from a live session.

# opencode plugin (experimental)

> **Experimental.** Not part of the support contract. The mapping follows opencode's source
> at `anomalyco/opencode@v1.19.4` (the latest release, 2026-10-22) and its plugin docs
> (<https://opencode.ai/docs/plugins/>). It has not been run inside a real opencode session
> yet: the tests feed the engine payloads built from that source, and run the plugin under
> Node with fake engines. Read [Not covered](#not-covered-opencode) before relying on it.
> Tracking issue: #26.

[`adapters/opencode/safe-ai-skill.js`](../adapters/opencode/safe-ai-skill.js) is an opencode
plugin: one file, no dependencies. In opencode's `tool.execute.before` hook it runs
`safe-ai-skill adapt opencode <gate>` with the call on stdin, and throws to block the call.
opencode awaits each plugin hook before it runs the tool, and a hook that throws stops the
call (`packages/opencode/src/plugin/index.ts` `trigger`, `src/session/tools.ts`).

## Install

1. Install the standalone CLI (`install.sh`, or `npm i -g @stbr/safe-ai-skill`; see the
   README).
2. Copy `adapters/opencode/safe-ai-skill.js` to `~/.config/opencode/plugins/` (all projects,
   recommended) or to `<repo>/.opencode/plugins/` (one project). opencode loads every
   `.js`/`.ts` file there at startup.
3. The plugin runs `safe-ai-skill` from `PATH`. To use another binary, set
   `SAFE_AI_SKILL_ENGINE`, or load the plugin from `opencode.json` with an option instead of
   step 2:
   `"plugin": [["file:///abs/path/safe-ai-skill.js", { "engine": "/abs/path/safe-ai-skill" }]]`.
   The plugin resolves the engine to an absolute path once, when opencode starts. If the
   `PATH` lookup later finds another file, or the file changes, every gated call is blocked
   until opencode restarts (restart after upgrading safe-ai-skill).

   With `install.sh` on macOS and Linux, `safe-ai-skill` on `PATH` is the shim: it checks the
   engine's sha256 and turns any engine failure or unusable answer into a deny, as for Codex.
   Pinning the shim's path is fine.

   **Recommended: pin the engine.** An absolute `engine` option in `opencode.json` is used as
   is, with no `PATH` lookup, and the agent cannot change opencode config. Without a pin, the
   engine is whatever `safe-ai-skill` comes first on `PATH` when opencode starts (see
   [Not covered](#not-covered-opencode)).
4. Check it: ask the agent to run `cat ~/.config/solana/id.json`. The call must fail with a
   `safe-ai-skill:` message. If it runs, the plugin is not loaded (see below).

## What it gates

| opencode tool | Gates | Mapping |
|---|---|---|
| `bash` `{command, workdir?}` | `gate-bash`, `gate-bash-secrets` | `workdir` (relative to the project dir) is where relative paths resolve; the project for the `.env` rules stays opencode's project dir. |
| `read` `{filePath}` | `gate-read` | `filePath` → `file_path`. |
| `grep` `{pattern, path?, include?}` | `gate-read` | `include` → `glob`; a file `path` is judged as its directory. See [Grep](#grep-under-opencode). |
| `glob` `{pattern, path?}` | `gate-read` | Lists names only: no opinion, as in Claude Code. |
| `write` `{filePath, content}`, `edit` `{filePath, oldString, newString}` | `gate-tamper` | camelCase → `file_path`, `content`, `old_string`, `new_string`. |
| `apply_patch` `{patchText}` | `gate-tamper` | Every file the patch adds, updates, deletes or moves to is checked; over 1000 files is denied unread. |
| MCP tools `<server>_<tool>`, plugin and custom tools | `gate-mcp` | See [MCP names](#mcp-names). |
| `read_mcp_resource` `{server, uri}` | `gate-mcp` | As `mcp__<server>__read_mcp_resource`; a path-like `uri` gets the read check. |
| `task`, `todowrite`, `question`, `webfetch`, `websearch`, `skill`, `lsp`, `plan_exit`, `execute`, `list_mcp_resources`, `list_mcp_resource_templates`, `invalid` | none | |

**Which firewall checks reach opencode.** The `bash` gates are `gate-bash` and `gate-bash-secrets`, so the exfil tripwire, tamper-content write checks, download-and-run, env-dump and encoded-command checks run on `bash` commands, and `gate-mcp` runs the MCP checks, as under Codex (`GATES` in `adapt_opencode.rs`). opencode's `webfetch` tool is **ungated** and there is no `gate-webfetch` entry, so a `WebFetch` URL to an exfil host is not seen (a `curl` through `bash` is). opencode has no output redaction, so a bare `printenv`/`env` dump reaches the model with its values. The [git and `gh` guard](tiers.md#git-and-gh-guard) and the nested-`claude` checks ride on `gate-bash-secrets`, and the MCP tool-name refusals on `gate-mcp`; `gate-config` (Claude Code's `ConfigChange` event) has no opencode counterpart.

**`ask` becomes a block.** opencode's `tool.execute.before` either throws or returns; there is
no ask. So every `ask` reaches opencode as a deny, and the reason says how to go ahead: run it
yourself, approve it in Claude Code, or confirm a grant there first. The engine never prints
an `allow`; a grant you confirmed earlier still lets the call run (below the High tier), as in
a headless session. Claude Code's sandbox counts as off. opencode's `permission.ask` plugin
hook is declared in its types, but nothing in v1.19.4 calls it, so it is not used.

**No interactive-shell hole.** opencode starts `bash` commands with stdin closed
(`src/tool/shell.ts`), so the Codex `write_stdin` gap does not apply.

**Failures block.** The plugin throws when the engine is missing or cannot start, exits
non-zero or is killed, takes longer than 15 seconds (option `timeoutMs`), prints more than
one line, or prints anything other than nothing, a deny, or a `gate-read` rewrite. The engine
answers within 8 seconds, exits 0 after a panic, and denies a payload it cannot read or a
tool sent to the wrong gate.

### Grep under opencode

opencode resolves the grep's `path` with `realpath` (`packages/core/src/fs-util.ts`), then
runs ripgrep with `--hidden` in it when it is a directory, and in its parent directory
otherwise (`src/tool/grep.ts`): a `path` naming a file, a symlink to a file, or a path that does
not exist searches the whole directory around it (for a link, the target's directory). The
engine resolves it the same way and judges that directory. It
passes the `include` to ripgrep as a single `--glob` (`packages/core/src/ripgrep.ts`), so it
cannot carry both an include and safe-ai-skill's credential-file exclusion.

- No `include`: the exclusion (`!{…}`) becomes the `include`. The engine prints only
  `include`, and the plugin writes it into the call's `args` in place, which opencode then
  passes to the tool. ripgrep searches every file the negated glob does not match.
- An `include` naming code files only (`*.ts`, `**/*.{ts,tsx}`, `*.rs`; not `*.md`), searched
  outside `$HOME` and the directories above it (`/` included, compared after resolving
  symlinks): the call runs unchanged. The one credential
  name it can still reach is an `.env.<ext>` file (`.env.local.ts`, matched by `**/.env.*`).
- Any other `include` (`*.json`, `*`, `config/**`, or any `include` over `$HOME`, where
  `--hidden` reaches excluded directories such as `~/.claude/projects`): denied with a reason.
  Search without `include`, or narrow `path`.

### MCP names

opencode names an MCP tool `sanitize(server) + "_" + sanitize(tool)`
(`src/mcp/catalog.ts`), and both parts may contain `_`. The engine splits the name after a
configured server name. It takes the server names from the opencode config files it can
read (the global config dir's `config.json`/`opencode.json(c)`, `$OPENCODE_CONFIG`,
`opencode.json(c)` and `.opencode/opencode.json(c)` in the project dir and every directory
above it, `$OPENCODE_CONFIG_DIR`, `$OPENCODE_CONFIG_CONTENT`; JSONC comments are allowed),
plus the names opencode hands the plugin's `config` hook. When exactly one server name
prefixes the tool name, the split is used. When none or several do, the server is unknown and
the whole name stands in for both the server and the tool, so the high-risk and value-moving
word checks see every part of it.

### What guards the guard

opencode loads plugins, custom tools and config from `.opencode/`, `opencode.json(c)`, its
config dirs and its npm cache with no trust check, and runs plugin hooks one after another. A
file the agent writes there could remove this plugin, or run after it and change the args it
checked. These writes are denied through `write`, `edit`, `apply_patch` and the shell:

- anything in a `.opencode` directory, anywhere (including `~/.opencode`);
- any file named `opencode.json` or `opencode.jsonc`;
- anything in the global config dir (`$XDG_CONFIG_HOME/opencode`, else
  `~/.config/opencode`), in `$OPENCODE_CONFIG_DIR` and in opencode's cache
  (`$XDG_CACHE_HOME/opencode`, else `~/.cache/opencode`, where npm plugins are installed),
  and the `$OPENCODE_CONFIG` file;
- this plugin's own file, wherever it is loaded from, and every path plugin the opencode
  config names (`"plugin": ["./x.ts", "file:///…"]`, resolved against the declaring file);
- the engine: the running `safe-ai-skill`, and `safe-ai-skill` in every `PATH` directory,
  whether or not it exists there yet;
- Claude Code's settings (`.claude/settings.json`, `.claude/settings.local.json`, the user's
  and `$CLAUDE_CONFIG_DIR`'s) and its plugins dir (`~/.claude/plugins`,
  `$CLAUDE_CONFIG_DIR/plugins`), as under Codex;
- safe-ai-skill's data dir (as under Codex);
- the shell startup files, as under Codex ([Shell startup files](#shell-startup-files)).

In the shell, deletes, moves and overwrites of an existing protected file or a directory
holding it are read with the default-wallet gate's scanner (globs, `cd`, `find -delete`,
`git checkout|restore|clean|…`). On top of that, quotes and backslashes are dropped
(`.o''pencode`, `.o\pencode`), and a command that names `.opencode`, `opencode.json`,
`.config/opencode` or one of the paths above, or holds a glob that can match one of them
(`.o?encode`, `~/.local/bin/*`), is denied unless every command in it only reads (`cat`, `ls`,
`grep`, `jq`, `find` without an action, `git status|diff|log|show`, …) and nothing is
redirected to a file. A command that writes a file named `safe-ai-skill` by a bare name
(`rm safe-ai-skill`, `> safe-ai-skill`) is denied too.

## Not covered (opencode)

- **A plugin that fails to load is skipped silently.** opencode logs the error and starts
  without it. `--pure` / `OPENCODE_PURE` skips external plugins, and
  `OPENCODE_DISABLE_PROJECT_CONFIG` skips project `.opencode/` plugins (prefer the global
  install). Run the check in [Install](#install-1) after every change.
- **Other plugins, and untrusted repositories.** Hooks run in load order (global config,
  project config, global plugin dir, project plugin dir). A plugin that was already installed,
  and runs after this one, can change a call's args after the check; only new writes by the
  agent are blocked. A repository you clone can ship its own `.opencode/plugins/`, tools or
  `opencode.json` `plugin` entries, and opencode runs that code in-process at startup, before
  any gate exists. Start opencode with `OPENCODE_DISABLE_PROJECT_CONFIG=1` in a repository you
  do not trust.
- **An engine planted for the next start, without a pin.** Writes to `safe-ai-skill` in the
  current `PATH` directories are denied, and so are the shell startup file writes in
  [Shell startup files](#shell-startup-files). Other ways of changing the next session's
  `PATH` are not seen: files those startup files `source`, a `PATH` line built so the word
  `PATH` never appears, a terminal or launcher config, or a new directory placed ahead on
  `PATH` by some other tool. A `safe-ai-skill` planted there is the engine the next unpinned
  opencode start uses. Pin the engine (above).
- **The shell is the user's.** opencode runs `bash` commands in the user's shell, and accepts
  `pwsh` on Unix through `$SHELL` or the config's `shell` key. The gates parse POSIX shell
  syntax only.
- **Real approval prompts.** None; asks block.
- **Output redaction (`redact`).** Not mapped. opencode's `tool.execute.after` could rewrite
  tool output, but that is untested.
- **`gate-skill`, prompt guards, the SessionStart supply-chain sweep.** Not mapped. The
  `skill`, `task`, `webfetch`, `websearch` and `lsp` tools run ungated; the code-mode
  `execute` tool runs ungated, but each MCP call it makes is gated.
- **`read_mcp_resource`.** opencode reads its arguments before the hook runs, so a rewrite
  would not reach it (none is made today; a deny still blocks it).
- **Subagents.** `task` sessions build their tools through the same code path, so their
  calls should be gated too. Not tested.
- **Shell writes are judged on their words; nothing is run.** A computed path, `eval` of
  generated text or a script file that writes to a protected place is not seen.
- **False positives.**
  - Any command that names `.opencode` or `opencode.json` and is not read-only is denied:
    `git add opencode.json`, `git commit -m "… .opencode …"`, `npm run x -- .opencode`.
  - In a project with `.opencode/` files, `find . … -delete` and `git clean -fd` are denied.
  - A grep `include` that is not code-only, or any `include` over `$HOME`, is denied (above).
  - A writing command whose glob can match a protected file is denied (`chmod +x
    ~/.local/bin/*` when `~/.local/bin` is on `PATH`). A bare `dir/*` does not count as naming
    `.opencode` or `opencode.json`.
  - Any write to a login-shell startup file is denied, and so is any non-read command that
    names `~/.zshrc` or `~/.bashrc` and contains `PATH` or a safe-ai-skill variable (`grep
    PATH ~/.zshrc > out.txt`). This applies under Codex too.
  - An unknown or ambiguous MCP name can match a high-risk or value-moving word across the
    server/tool boundary.
- **MCP servers from config the engine cannot read.** Remote (`.well-known/opencode`),
  account, and managed (`/Library/Application Support/opencode`, MDM) configs reach the engine
  only through the plugin's `config` hook. Without them, the name is judged as unknown.
- **Windows.** Untested.
- **State.** As under Codex ([State](#state-tiers-grants-and-audit)): the Claude Code plugin's
  data dir when it exists, else the standalone dir. Confirmations need a Claude Code session.
