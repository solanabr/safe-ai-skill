// Fail-closed tests for adapters/opencode/safe-ai-skill.js. Fake engines (POSIX sh scripts)
// stand in for each engine outcome; no network, no opencode install. With
// SAFE_AI_SKILL_TEST_ENGINE set (the Rust test `adapt_opencode_plugin` sets it), the real engine
// is also run end to end. Run: node --test adapters/opencode/test/plugin.test.mjs

import { test } from "node:test"
import assert from "node:assert/strict"
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, renameSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { fileURLToPath } from "node:url"

import { SafeAiSkill } from "../safe-ai-skill.js"

const work = mkdtempSync(join(tmpdir(), "oc-plugin-"))
const DENY = '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"safe-ai-skill: nope"}}'

function fake(name, body) {
  const path = join(work, name)
  writeFileSync(path, `#!/bin/sh\n${body}\n`)
  chmodSync(path, 0o755)
  return path
}

async function hooks(engine, extra = {}) {
  return SafeAiSkill({ directory: work, worktree: work }, { engine, timeoutMs: 2000, ...extra })
}

async function call(h, tool, args) {
  const output = { args }
  await h["tool.execute.before"]({ tool, sessionID: "ses_1", callID: "call_1" }, output)
  return output
}

const blocked = async (h, tool, args, pattern) =>
  assert.rejects(call(h, tool, args), (e) => e instanceof Error && pattern.test(e.message))

test("no output lets the call run", async () => {
  const h = await hooks(fake("silent", "cat >/dev/null; exit 0"))
  const out = await call(h, "bash", { command: "ls" })
  assert.deepEqual(out.args, { command: "ls" })
})

test("a deny blocks with its reason", async () => {
  const h = await hooks(fake("deny", `cat >/dev/null; printf '%s' '${DENY}'`))
  await blocked(h, "bash", { command: "rm -rf /" }, /^safe-ai-skill: nope$/)
})

test("a missing engine blocks", async () => {
  const h = await hooks(join(work, "does-not-exist"))
  await blocked(h, "read", { filePath: "a.txt" }, /^safe-ai-skill: .*not found/)
  const odd = await hooks(123)
  await blocked(odd, "read", { filePath: "a.txt" }, /^safe-ai-skill: .*not found/)
})

test("an engine replaced after load blocks", async () => {
  const engine = fake("replaced", "cat >/dev/null; exit 0")
  const h = await hooks(engine)
  await call(h, "bash", { command: "ls" })
  const swap = fake("replacement", "cat >/dev/null; exit 0 # a different file")
  renameSync(swap, engine)
  await blocked(h, "bash", { command: "ls" }, /engine changed/)
})

test("an engine planted earlier on PATH blocks", async () => {
  const late = join(work, "late-bin")
  const early = join(work, "early-bin")
  mkdirSync(late, { recursive: true })
  mkdirSync(early, { recursive: true })
  writeFileSync(join(late, "safe-ai-skill"), "#!/bin/sh\ncat >/dev/null; exit 0\n")
  chmodSync(join(late, "safe-ai-skill"), 0o755)
  const saved = process.env.PATH
  process.env.PATH = `${early}:${late}:${saved}`
  try {
    const h = await SafeAiSkill({ directory: work, worktree: work }, { timeoutMs: 2000 })
    await call(h, "bash", { command: "ls" })
    writeFileSync(join(early, "safe-ai-skill"), "#!/bin/sh\nexit 0\n")
    chmodSync(join(early, "safe-ai-skill"), 0o755)
    await blocked(h, "bash", { command: "ls" }, /engine changed/)
  } finally {
    process.env.PATH = saved
  }
})

test("inherited object keys are ordinary tool ids", async () => {
  const h = await hooks(fake("silent2", "cat >/dev/null; exit 0"))
  for (const tool of ["constructor", "toString", "__proto__"]) await call(h, tool, {})
})

test("a non-zero exit blocks", async () => {
  const h = await hooks(fake("crash", "cat >/dev/null; exit 1"))
  await blocked(h, "write", { filePath: "a.txt", content: "x" }, /exit 1/)
})

test("a signal kill blocks", async () => {
  const h = await hooks(fake("killed", "cat >/dev/null; kill -9 $$"))
  await blocked(h, "bash", { command: "ls" }, /SIGKILL/)
})

test("a timeout blocks", async () => {
  const h = await hooks(fake("slow", "cat >/dev/null; sleep 5"), { timeoutMs: 300 })
  await blocked(h, "bash", { command: "ls" }, /did not answer/)
})

test("ask, allow, garbage and two lines all block", async () => {
  for (const [name, text] of [
    ["ask", '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"r"}}'],
    ["allow", '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'],
    ["garbage", "not json"],
    ["two", `${DENY}\n${DENY}`],
    ["empty-object", "{}"],
  ]) {
    const h = await hooks(fake(`out-${name}`, `cat >/dev/null; printf '%s' '${text}'`))
    await blocked(h, "bash", { command: "ls" }, /cannot use/)
  }
})

test("a gate-read rewrite changes the args object in place", async () => {
  const rewrite = '{"hookSpecificOutput":{"hookEventName":"PreToolUse","updatedInput":{"pattern":"x","include":"!{**/.env}"}}}'
  const h = await hooks(fake("rewrite", `cat >/dev/null; printf '%s' '${rewrite}'`))
  const args = { pattern: "x" }
  const out = await call(h, "grep", args)
  assert.equal(out.args, args)
  assert.equal(args.include, "!{**/.env}")
})

test("a rewrite from any other gate blocks", async () => {
  const rewrite = '{"hookSpecificOutput":{"hookEventName":"PreToolUse","updatedInput":{"command":"ls"}}}'
  const h = await hooks(fake("rewrite-bash", `cat >/dev/null; printf '%s' '${rewrite}'`))
  await blocked(h, "bash", { command: "rm x" }, /cannot use/)
})

test("tools route to their gates; MCP calls carry the configured servers", async () => {
  const log = join(work, "calls.log")
  const h = await hooks(fake("logger", `printf '%s ' "$3" >> '${log}'; cat >> '${log}'; echo >> '${log}'`))
  await h.config({ mcp: { helius: {}, "solana-dev": {} } })
  await call(h, "bash", { command: "ls" })
  await call(h, "apply_patch", { patchText: "*** Begin Patch\n*** End Patch" })
  await call(h, "helius_getBalance", { address: "x" })
  await call(h, "task", { prompt: "p" })
  const lines = readFileSync(log, "utf8").trim().split("\n")
  assert.deepEqual(
    lines.map((l) => l.split(" ")[0]),
    ["gate-bash", "gate-bash-secrets", "gate-tamper", "gate-mcp"],
  )
  const mcp = JSON.parse(lines[3].slice("gate-mcp ".length))
  assert.equal(mcp.tool, "helius_getBalance")
  assert.equal(mcp.sessionID, "ses_1")
  assert.equal(mcp.directory, work)
  assert.deepEqual(mcp.mcpServers, ["helius", "solana-dev"])
  assert.match(mcp.pluginPath, /safe-ai-skill\.js$/)
})

test("the first blocking gate stops the call", async () => {
  const log = join(work, "stop.log")
  const h = await hooks(fake("first-denies", `printf '%s\\n' "$3" >> '${log}'; cat >/dev/null; printf '%s' '${DENY}'`))
  await blocked(h, "bash", { command: "ls" }, /nope/)
  assert.deepEqual(readFileSync(log, "utf8").trim().split("\n"), ["gate-bash"])
})

const real = process.env.SAFE_AI_SKILL_TEST_ENGINE
test("the real engine: denies, rewrites, passes", { skip: !real && "SAFE_AI_SKILL_TEST_ENGINE not set" }, async () => {
  const proj = join(work, "proj")
  mkdirSync(proj, { recursive: true })
  const h = await SafeAiSkill({ directory: proj, worktree: proj }, { engine: real })
  await blocked(h, "bash", { command: "cat ~/.config/solana/id.json" }, /blocked/)
  await blocked(h, "write", { filePath: ".opencode/plugins/evil.js", content: "x" }, /opencode config/)
  await blocked(h, "bash", { command: "solana program deploy x.so --url mainnet-beta" }, /cannot ask for approval/)
  const args = { pattern: "x", path: "README.md" }
  await call(h, "grep", args)
  assert.match(args.include, /^!\{/)
  assert.equal(args.path, "README.md")
  const self = fileURLToPath(new URL("../safe-ai-skill.js", import.meta.url))
  await blocked(h, "write", { filePath: self, content: "" }, /opencode plugin/)
  await call(h, "bash", { command: "ls -la" })
  await call(h, "read", { filePath: "README.md" })
})
