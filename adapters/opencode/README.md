# safe-ai-skill for opencode (experimental)

`safe-ai-skill.js` is an opencode plugin. Before each tool call it runs
`safe-ai-skill adapt opencode <gate>` and blocks the call when safe-ai-skill denies it, would
ask (opencode plugins cannot ask), or cannot answer (missing engine, crash, timeout, unusable
output). One file, no dependencies; it runs under Bun (opencode) or Node.

Install the `safe-ai-skill` CLI, then copy the plugin:

```sh
mkdir -p ~/.config/opencode/plugins
cp safe-ai-skill.js ~/.config/opencode/plugins/
```

Use `<repo>/.opencode/plugins/` instead for one project. To run an engine that is not on
`PATH`, set `SAFE_AI_SKILL_ENGINE`, or load the plugin from `opencode.json`:

```json
{ "plugin": [["file:///abs/path/safe-ai-skill.js", { "engine": "/abs/path/safe-ai-skill" }]] }
```

The engine is resolved to an absolute path when opencode starts. If it changes later (an
upgrade, or another `safe-ai-skill` placed earlier on `PATH`), every gated call is blocked
until opencode restarts.

Check it by asking the agent to run `cat ~/.config/solana/id.json`: the call must fail with a
`safe-ai-skill:` message.

What is gated, what is not, and why: [docs/adapters.md](../../docs/adapters.md#opencode-plugin-experimental).

Tests: `node --test adapters/opencode/test/plugin.test.mjs` (Node 22+). Set
`SAFE_AI_SKILL_TEST_ENGINE=/path/to/safe-ai-skill` to also run the real engine end to end.
