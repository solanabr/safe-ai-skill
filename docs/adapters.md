# Codex CLI adapter (experimental)

> **Experimental.** Not part of the 1.1.0 support contract. The payload mapping follows Codex's
> hook code as of `openai/codex@8531184` (Codex CLI 0.155.1). Codex states that tool hooks are "a
> useful guardrail, not a complete enforcement boundary". The same holds here.

`safe-ai-skill adapt codex <gate>` runs one of safe-ai-skill's PreToolUse gates on a Codex CLI hook
payload and answers in a form Codex understands. Tracking issue: #23.

## Install

1. Install the standalone CLI so that `safe-ai-skill` is on `PATH`: `install.sh`, or
   `npm i -g @stbr/safe-ai-skill`. See the README.
2. Copy [`adapters/codex/hooks.json`](../adapters/codex/hooks.json) to `<repo>/.codex/hooks.json`
   (project scope) or `~/.codex/hooks.json` (user scope). If that file already exists, merge the
   `PreToolUse` groups into it.
3. Start Codex and approve the hooks with `/hooks`. Codex skips hooks that are not trusted, and
   it skips hooks again after they change, until you re-approve them. It loads a project
   `.codex/` layer only when the project is trusted.

## What it gates

| Codex tool (`tool_name`) | Gates | Notes |
|---|---|---|
| `Bash` (shell and `exec_command`) | `gate-bash`, `gate-bash-secrets` | Same input as Claude Code: `tool_input.command`. |
| `apply_patch` | `gate-tamper` | Every file the patch adds, updates, deletes or moves to is checked. Patches to `.codex/hooks.json` or `.codex/config.toml` are denied. |
| `mcp__<server>__<tool>` | `gate-mcp` | The raw MCP arguments. |

**`ask` becomes `deny`.** Codex PreToolUse honours only `deny`. When a hook returns `ask` or a bare
`allow`, Codex logs it as an unsupported output and runs the tool call anyway. So every `ask`
reaches Codex as a `deny`, and its reason says how to proceed: run the command yourself, approve
it in Claude Code, or confirm a grant there first. An `allow` produces no output. Grants work as
in a headless session: a grant you confirmed earlier still allows the call (below the High tier).

## Not covered

- **Output redaction** (`redact`). Codex PostToolUse cannot rewrite tool output; it can only block
  the result.
- **`gate-read` and `gate-skill`.** Codex has no Read, Grep, Glob or Skill tool. It reads files
  through the shell, which `gate-bash-secrets` covers.
- **Prompt guards and the SessionStart supply-chain sweep.** These have not been mapped yet.
- **Hosted tools** such as web search. Codex does not run hooks for them.
- **Failures fail open.** If the hook times out, crashes, or exits with any status other than 0
  or 2, Codex marks the hook as failed and runs the call. The engine answers within 8 seconds.
- **State.** Grants, the tier and the audit log come from the Claude Code plugin's data directory
  (`~/.claude/plugins/data/safe-ai-skill-*`). If the plugin is not installed, nothing can be
  relaxed and nothing is audited. Gates still deny and block-on-ask at the default tier.
- **Writes through the shell** to `.codex/hooks.json` are not detected. Only `apply_patch` writes
  to that file are checked.
