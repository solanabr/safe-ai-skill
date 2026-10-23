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

Under Codex, these targets are also denied, through `apply_patch` and through shell writes (an
output redirection, or an argument of a writing command such as `rm`, `mv`, `cp`, `tee`, `sed`,
`truncate`):

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

**`ask` becomes `deny`.** Codex PreToolUse honours only `deny`. On `ask` or a bare `allow`, it
logs an unsupported output and runs the call anyway. So every `ask` reaches Codex as a `deny`,
and the reason says how to go ahead: run the command yourself, approve it in Claude Code, or
confirm a grant there first. An `allow` produces no output. Grants work as in a headless session:
a grant you confirmed earlier still allows the call (below the High tier). Claude Code's sandbox
counts as off, because it does not wrap Codex.

**Failures deny.** If the engine is missing, is not executable, exits non-zero, aborts or
panics, or prints anything other than nothing or a deny, the wrapper prints a deny with exit 0.
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
- **Hosted tools (web search) and `write_stdin`.** Codex does not run hooks for them.
- **Shell writes are judged on words, not run.** A write hidden behind variables, `eval`,
  generated scripts or an interpreter program (`python -c "open(...)"` with a computed path) is
  not seen. Literal paths in a quoted `sh -c '…'` are.
- **Heredoc bodies are read as commands.** A heredoc that writes text mentioning
  `rm tier.json` can be denied by mistake.
- **Codex plugin hook files.** A plugin-bundled `hooks/hooks.json` is not protected.
- **State.** Grants, the tier and the audit log come from the Claude Code plugin's data dir. If
  the plugin is not installed, nothing can be relaxed and nothing is audited. The gates still
  deny, and ask-denies, at the default tier.
