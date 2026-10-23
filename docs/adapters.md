# Codex CLI adapter (experimental)

> **Experimental.** Not part of the 1.1.0 support contract. The payload mapping follows Codex's
> hook code at `openai/codex@8531184` (Codex CLI 0.155.1). Codex itself says tool hooks are "a
> useful guardrail, not a complete enforcement boundary". That applies here too: read
> [Not covered](#not-covered) before relying on it.

`safe-ai-skill adapt codex <gate>` runs one of safe-ai-skill's PreToolUse gates on a Codex CLI
hook payload. It answers only in forms Codex honours. Codex hooks run it through the
`safe-ai-skill-codex` wrapper. Tracking issue: #23.

## Install

1. Install the standalone CLI (`install.sh`, or `npm i -g @stbr/safe-ai-skill`; see the
   README).
2. Copy [`adapters/codex/safe-ai-skill-codex`](../adapters/codex/safe-ai-skill-codex) next to
   the `safe-ai-skill` binary, for example into `~/.local/bin/`, and make it executable. The
   wrapper uses the engine next to it, otherwise the one on `PATH`.
3. Copy [`adapters/codex/hooks.json`](../adapters/codex/hooks.json) to `<repo>/.codex/hooks.json`
   (project) or `~/.codex/hooks.json` (user). If the file already exists, merge the
   `PreToolUse` groups into it.
4. Start Codex and approve the hooks with `/hooks`. Codex skips untrusted hooks, and skips a
   hook again after it changes, until you re-approve it. Project `.codex/` layers load only in
   trusted projects.

## What it gates

| Codex call | Gates | Notes |
|---|---|---|
| `Bash` (shell and `exec_command`) | `gate-bash`, `gate-bash-secrets` | Same input as Claude Code (`tool_input.command`). A `tool_input.workdir`, if present, is where relative paths resolve. |
| `apply_patch` tool | `gate-tamper` | Every file the patch adds, updates, deletes or moves to is checked. A patch touching more than 1000 files is denied unread. |
| `apply_patch` run through the shell (heredoc, quoted argument, `$'…'`, piped) | `gate-bash-secrets` | Codex intercepts these and applies them as patches, so they get the same per-file checks. |
| `mcp__<server>__<tool>` | `gate-mcp` | Receives the raw MCP arguments. |

Under Codex, these targets are also denied, through `apply_patch` and through shell writes.
Shell writes are read with the default-wallet gate's scanner: deletes, moves and overwrites of
the file or of a directory holding it, globs, relative paths after `cd`, `find -delete|-exec`,
`chmod`/`chown`, output redirections, and work-tree-rewriting `git` subcommands (`checkout`,
`restore`, `rm`, `mv`, `reset`, `switch`, and `clean` / `stash -u` when a protected file exists
in the tree). Literal paths inside interpreter code (`python3 -c "os.remove('…')"`) count too.
The targets:

- Codex hook config: `.codex/hooks.json`, `.codex/config.toml`, and `$CODEX_HOME/…`. Symlinks
  are resolved first.
- Claude Code settings: `.claude/settings.json`, `.claude/settings.local.json`, the user's and
  `$CLAUDE_CONFIG_DIR`'s. Claude Code guards these in its own sessions, but nothing does under
  Codex.
- The `safe-ai-skill` engine and the wrapper: next to the running engine and on `PATH`.
- safe-ai-skill's data dir. Without `CLAUDE_PLUGIN_DATA` this is the Claude Code plugin's dir,
  which safe-ai-skill finds on its own.
- A relative path naming a state file or a wallet (`tier.json`, `grants.json`, `spend.json`,
  `audit.jsonl`, `id.json`, …). Codex's `exec_command` can run in a `workdir` the hook payload
  does not carry, so the hook cannot tell where such a write lands.

**Interactive sessions are denied.** A shell with no `-c` script, no script file and no
redirected or piped input (`bash`, `sh -i`, `zsh`), a REPL (`python3`, `node`, `irb`, `deno`,
`-i` anywhere), and a database shell without a command (`psql mydb`, `sqlite3 my.db`) are
denied. Codex's `write_stdin` types into such a session without running any hook, so nothing
typed there would be checked.

**`ask` becomes `deny`.** Codex PreToolUse honours only `deny`. On `ask` or a bare `allow`, it
logs an unsupported output and runs the call anyway. So every `ask` reaches Codex as a `deny`,
and the reason says how to go ahead: run the command yourself, approve it in Claude Code, or
confirm a grant there first. An `allow` produces no output. Grants work as in a headless session:
a grant you confirmed earlier still allows the call (below the High tier). Claude Code's sandbox
counts as off, because it does not wrap Codex.

**Failures deny.** If the engine is missing, is not executable, exits non-zero, aborts or
panics, or prints anything other than nothing or a single deny line, the wrapper prints a deny
with exit 0.
The engine also exits 0 after a panic under Codex.

## Not covered

- **The engine's direct output.** Codex hooks that call `safe-ai-skill adapt codex …` directly,
  without the wrapper, lose the failure handling above. Use the template.
- **The Codex hook timeout.** If Codex kills the wrapper at its `timeout`, Codex runs the call.
  The engine answers within 8 seconds, and the template's timeouts (10–20 s) leave room for that.
- **Real approval prompts.** Codex has no hook `ask`.
- **Output redaction (`redact`).** Codex PostToolUse cannot rewrite tool output.
- **`gate-read`, `gate-skill`.** Codex has no Read, Grep, Glob or Skill tool. Reads go through
  the shell, which `gate-bash-secrets` covers.
- **Prompt guards and the SessionStart supply-chain sweep.** Not mapped yet.
- **`write_stdin` into anything still running.** Codex runs no hook for `write_stdin`. Starting
  an interactive shell or REPL is denied (above). But any long-running process the model
  started can still be fed input with no gate seeing it: a program that reads commands from
  stdin, a TUI, or an `ssh` session. Every Bash gate and all of the self-protection is skipped
  for that input.
- **Shells started in other forms are not denied.** Only a bare interactive start is caught
  (`bash`, `python3`, `psql mydb`, …). These forms also read the model's `write_stdin` input as
  commands, and they pass:
  - `cat | bash`
  - `bash /dev/stdin`, `python3 /dev/stdin`
  - `bash < /dev/tty`
  - `script -q /dev/null`
  - `while read l; do eval "$l"; done`
  - `xargs -I{} sh -c {}`
  - `perl -ne 'system $_'`
  - `tmux`, `screen`
  - `ssh host` with no remote command

  Treat this as an open hole in the experimental adapter. Once one of these is running, nothing
  sent to it is gated.
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
  - Bare `hooks.json`/`config.toml` given to a writing command are denied wherever the command
    runs, because the working dir is unknown.
  - In a project with a `.codex/` dir (the project-scope install), three ordinary commands are
    denied:
    - `find . … -delete` (or `-exec`): it starts at a directory that holds `.codex/hooks.json`.
    - `git clean -fd`: a path-less clean sweeps the tree, and the scan does not check whether
      `.codex/` is tracked.
    - A bare `rm config.toml`: the hook cannot tell it apart from `.codex/config.toml`.

    Each deny gives its reason. Run such a command yourself, or narrow its path (for example
    `find src -name '*.tmp' -delete`).
- **Codex plugin hook files.** A plugin-bundled `hooks/hooks.json` is not protected.
- **State.** Grants, the tier and the audit log come from the Claude Code plugin's data dir. If
  the plugin is not installed, nothing can be relaxed and nothing is audited. The gates still
  deny, and ask-denies, at the default tier.
