// safe-ai-skill opencode plugin (experimental, issue #26).
//
// In opencode's `tool.execute.before` hook, runs `safe-ai-skill adapt opencode <gate>` with the
// call on stdin and blocks the call by throwing. It fails closed: a missing engine, a non-zero
// exit, a timeout, or any answer other than nothing, a deny, or a Grep rewrite blocks the call.
//
// Engine: the plugin option `engine` (`"plugin": [["file:///…/safe-ai-skill.js",
// {"engine": "/abs/path/safe-ai-skill"}]]`), else $SAFE_AI_SKILL_ENGINE, else `safe-ai-skill`
// on PATH. No dependencies; runs under Bun or Node.

import { spawn } from "node:child_process"

const GATES = {
  bash: ["gate-bash", "gate-bash-secrets"],
  read: ["gate-read"],
  grep: ["gate-read"],
  glob: ["gate-read"],
  write: ["gate-tamper"],
  edit: ["gate-tamper"],
  apply_patch: ["gate-tamper"],
}

// Built-in tools no gate reads. Every other tool id (MCP `<server>_<tool>`, plugin and
// custom tools, `read_mcp_resource`) goes to gate-mcp.
const UNGATED = new Set([
  "task", "todowrite", "todoread", "question", "webfetch", "websearch", "plan_exit",
  "plan_enter", "invalid", "skill", "lsp", "execute", "list_mcp_resources",
  "list_mcp_resource_templates",
])

const TIMEOUT_MS = 15000
const MAX_OUTPUT = 1 << 20
const DENY_PREFIX = '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",'

function runEngine(engine, gate, payload, timeoutMs) {
  return new Promise((resolve) => {
    let stdout = ""
    let settled = false
    const done = (result) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve(result)
    }
    let child
    try {
      child = spawn(engine, ["adapt", "opencode", gate], { stdio: ["pipe", "pipe", "ignore"] })
    } catch (e) {
      return done({ error: `could not start ${engine}: ${e.message}` })
    }
    const timer = setTimeout(() => {
      child.kill("SIGKILL")
      done({ error: `the engine did not answer within ${timeoutMs} ms` })
    }, timeoutMs)
    child.on("error", (e) => done({ error: `could not run ${engine}: ${e.message}` }))
    child.stdout.on("data", (chunk) => {
      stdout += chunk
      if (stdout.length > MAX_OUTPUT) {
        child.kill("SIGKILL")
        done({ error: "the engine printed too much" })
      }
    })
    child.on("close", (code, signal) => {
      if (code !== 0) return done({ error: `the engine failed (${signal ?? `exit ${code}`})` })
      done({ stdout })
    })
    child.stdin.on("error", () => {})
    child.stdin.end(payload)
  })
}

// What the engine's answer means: {} to proceed, {args} to proceed with rewritten args, or
// {block} with the reason.
function verdict(gate, result) {
  if (result.error) return { block: result.error }
  const out = result.stdout
  if (out === "") return {}
  if (out.includes("\n")) return { block: "the engine gave an answer the plugin cannot use" }
  let parsed
  try {
    parsed = JSON.parse(out)
  } catch {
    return { block: "the engine gave an answer the plugin cannot use" }
  }
  const hso = parsed?.hookSpecificOutput
  if (out.startsWith(DENY_PREFIX) && typeof hso?.permissionDecisionReason === "string") {
    return { block: hso.permissionDecisionReason }
  }
  const updated = hso?.updatedInput
  if (
    gate === "gate-read" &&
    hso?.permissionDecision === undefined &&
    updated !== null &&
    typeof updated === "object" &&
    !Array.isArray(updated)
  ) {
    return { args: updated }
  }
  return { block: "the engine gave an answer the plugin cannot use" }
}

export const SafeAiSkill = async ({ directory, worktree }, options) => {
  const engine = options?.engine || process.env.SAFE_AI_SKILL_ENGINE || "safe-ai-skill"
  const timeoutMs = Number(options?.timeoutMs) > 0 ? Number(options.timeoutMs) : TIMEOUT_MS
  let mcpServers = []
  return {
    config: async (cfg) => {
      mcpServers = Object.keys(cfg?.mcp ?? {})
    },
    "tool.execute.before": async (input, output) => {
      const tool = input?.tool
      const gates = GATES[tool] ?? (UNGATED.has(tool) ? [] : ["gate-mcp"])
      for (const gate of gates) {
        const payload = JSON.stringify({
          tool,
          sessionID: input.sessionID,
          callID: input.callID,
          args: output?.args,
          directory,
          worktree,
          mcpServers,
        })
        const v = verdict(gate, await runEngine(engine, gate, payload, timeoutMs))
        if (v.block !== undefined) throw new Error(`safe-ai-skill: ${v.block.replace(/^safe-ai-skill: /, "")}`)
        // opencode passes this same args object to the tool, so change it in place.
        if (v.args) Object.assign(output.args, v.args)
      }
    },
  }
}
