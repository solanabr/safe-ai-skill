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
- Login-shell startup files, because Codex runs its hooks through `$SHELL -lc`: `~/.zshenv`,
  `~/.zprofile`, `~/.zlogin` (also under `$ZDOTDIR`), `~/.bash_profile`, `~/.bash_login`,
  `~/.profile`, `~/.config/fish/config.fish` and `~/.config/fish/conf.d/*`. Any write is
  denied: a line there could set an environment variable or shadow `safe-ai-skill` on `PATH`.
  Reading or sourcing them passes. `~/.zshrc` and `~/.bashrc` (not read by a non-interactive
  login shell) are not covered.
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
