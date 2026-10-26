# Live smoke test

`scripts/live/run.sh` runs real headless Claude Code sessions with **this checkout's engine** loaded as a plugin. It checks what actually executed, not just what a hook printed.

```sh
scripts/live/run.sh                          # all cases in cases.tsv
scripts/live/run.sh --only git-clean         # one case
scripts/live/run.sh --kit ~/src/ai-kit       # also install ai-kit into the test project
scripts/live/run.sh --keep                   # keep the temp dir (transcripts in runs/)
```

## What you need

- the `claude` CLI, logged in;
- a Rust toolchain;
- `python3`.

Each case is one `claude -p` call, so a full run is billed like any other session.

## What it does

1. Builds the engine in release mode and copies `plugins/safe-ai-skill` into a temp dir with that build, re-stamping the shim. Each session loads it with `--plugin-dir`; your installed plugins and `~/.claude` settings are untouched.
2. Replaces `solana`, `anchor`, `spl-token`, `solana-keygen`, `curl`, `wget`, `npm`, `npx`, `gh` and `docker` with stubs that only log their arguments. A first session checks that Claude's shell resolves them to the stubs. **The run stops if it doesn't.**
3. Creates a throwaway git project with a fake `.env`. If you pass `--kit`, it installs ai-kit there without ai-kit's own copy of safe-ai-skill.
4. Runs each case in `cases.tsv`. Claude Code's own approval step is pre-approved for the core tools (`--allowedTools`), so only the plugin's hooks decide. Each case is graded:

   | Expect | Passes when |
   |---|---|
   | `runs` | the session finishes |
   | `blocked` | no stub logged the command, and for `cmd` cases the plugin's hooks, replayed directly, ask or deny it (so a model refusal alone never passes) |
   | `redacted` | the fake secret value never appears in the transcript |
   | `unchanged` | `.claude/settings.local.json` is byte-identical afterwards |
   | `kept` | the untracked `.env` still exists afterwards |

5. Checks the settings manager directly: `firewall apply medium --project` in a temp git project must write the sandbox block and never `sandbox.enabled: false`.

The table's HOOK column is that direct replay; MODEL says whether the session tried the call or declined it. The script exits non-zero if any case fails.

## Adding cases

Add a tab-separated line to `cases.tsv`: name, mode (`default` or `bypass`), expect, kind (`cmd` or `prompt`), text. Only ever point `blocked` cases at stubbed programs or at the temp project. Never use a real wallet, key or network send.
