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

   **Recommended: pin the engine.** An absolute `engine` option in `opencode.json` is used as
   is, with no `PATH` lookup, and the agent cannot change opencode config. Without a pin, the
   engine is whatever `safe-ai-skill` comes first on `PATH` when opencode starts (see
   [Not covered](#not-covered-opencode)).
4. Check it: ask the agent to run `cat ~/.config/solana/id.json`. The call must fail with a
   `safe-ai-skill:` message. If it runs, the plugin is not loaded (see below).

## What it gates

| opencode tool | Gates | Mapping |
|---|---|---|
| `bash` `{command, workdir?}` | `gate-bash`, `gate-bash-secrets` | `workdir` (relative to the project dir) is where relative paths resolve. |
| `read` `{filePath}` | `gate-read` | `filePath` → `file_path`. |
| `grep` `{pattern, path?, include?}` | `gate-read` | `include` → `glob`; a file `path` is judged as its directory. See [Grep](#grep-under-opencode). |
| `glob` `{pattern, path?}` | `gate-read` | Lists names only: no opinion, as in Claude Code. |
| `write` `{filePath, content}`, `edit` `{filePath, oldString, newString}` | `gate-tamper` | camelCase → `file_path`, `content`, `old_string`, `new_string`. |
| `apply_patch` `{patchText}` | `gate-tamper` | Every file the patch adds, updates, deletes or moves to is checked; over 1000 files is denied unread. |
| MCP tools `<server>_<tool>`, plugin and custom tools | `gate-mcp` | See [MCP names](#mcp-names). |
| `read_mcp_resource` `{server, uri}` | `gate-mcp` | As `mcp__<server>__read_mcp_resource`; a path-like `uri` gets the read check. |
| `task`, `todowrite`, `question`, `webfetch`, `websearch`, `skill`, `lsp`, `plan_exit`, `execute`, `list_mcp_resources`, `list_mcp_resource_templates`, `invalid` | none | |

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
- safe-ai-skill's data dir (as under Codex).

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
  current `PATH` directories are denied, and so are writes that put a `PATH` line into a shell
  startup file in `$HOME` (`.zshrc`, `.zshenv`, `.zprofile`, `.zlogin`, `.bashrc`,
  `.bash_profile`, `.bash_login`, `.profile`, `.config/fish/config.fish`, through the file
  tools, patches and the shell). Other ways of changing the next session's `PATH` are not seen:
  `$ZDOTDIR` or other startup files, a `PATH` line built so the word `PATH` never appears, a
  terminal or launcher config, or a new directory placed ahead on `PATH` by some other tool. A
  `safe-ai-skill` planted there is the engine the next unpinned opencode start uses. Pin the
  engine (above).
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
  - Writing a `PATH` line to a shell startup file in `$HOME` is denied, as is any non-read
    command that names such a file and contains `PATH`.
  - An unknown or ambiguous MCP name can match a high-risk or value-moving word across the
    server/tool boundary.
- **MCP servers from config the engine cannot read.** Remote (`.well-known/opencode`),
  account, and managed (`/Library/Application Support/opencode`, MDM) configs reach the engine
  only through the plugin's `config` hook. Without them, the name is judged as unknown.
- **Windows.** Untested.
- **State.** As under Codex: grants, the tier and the audit log come from the Claude Code
  plugin's data dir. Without it, nothing is relaxed and nothing is audited.
