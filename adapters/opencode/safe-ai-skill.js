// safe-ai-skill opencode plugin (experimental, issue #26).
//
// In opencode's `tool.execute.before` hook, runs `safe-ai-skill adapt opencode <gate>` with the
// call on stdin and blocks the call by throwing. It fails closed: a missing engine, a non-zero
// exit, a timeout, or any answer other than nothing, a deny, or a Grep rewrite blocks the call.
//
// Engine: the plugin option `engine` (`"plugin": [["file:///…/safe-ai-skill.js",
// {"engine": "/abs/path/safe-ai-skill"}]]`), else $SAFE_AI_SKILL_ENGINE, else `safe-ai-skill`
// on PATH. It is resolved to an absolute, symlink-free path once, when opencode loads the
// plugin; if that resolution or the file later changes, every call is blocked until opencode
// restarts. No dependencies; runs under Bun or Node.

import { spawn } from "node:child_process"
import { accessSync, constants, realpathSync, statSync } from "node:fs"
import { delimiter, isAbsolute, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const GATES = {
  bash: ["gate-bash", "gate-bash-secrets"],
  read: ["gate-read"],
  grep: ["gate-read"],
  glob: ["gate-read"],
  write: ["gate-tamper"],
  edit: ["gate-tamper"],
  apply_patch: ["gate-tamper"],
}

// Built-in tools no gate reads (the engine keeps the same list; a tool sent to the wrong gate
// is denied there, so drift fails closed). Every other tool id (MCP `<server>_<tool>`, plugin and
// custom tools, `read_mcp_resource`) goes to gate-mcp.
const UNGATED = new Set([
  "task", "todowrite", "todoread", "question", "webfetch", "websearch", "plan_exit",
  "plan_enter", "invalid", "skill", "lsp", "execute", "list_mcp_resources",
  "list_mcp_resource_templates",
])

const TIMEOUT_MS = 15000
const MAX_OUTPUT = 1 << 20
const DENY_PREFIX = '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",'

// The engine as an absolute, symlink-free path with the file's identity, or {error}.
function locate(engine) {
  const name = String(engine)
  let candidates
  if (name.includes("/") || name.includes("\\")) {
    candidates = [resolve(name)]
  } else {
    const dirs = (process.env.PATH ?? "").split(delimiter).filter((d) => isAbsolute(d))
    const names = process.platform === "win32" ? [`${name}.exe`, name] : [name]
    candidates = dirs.flatMap((d) => names.map((n) => join(d, n)))
  }
  for (const candidate of candidates) {
    try {
      accessSync(candidate, constants.X_OK)
      const path = realpathSync(candidate)
      const st = statSync(path)
      if (!st.isFile()) continue
      return { path, id: `${st.dev}:${st.ino}:${st.size}:${st.mtimeMs}:${st.ctimeMs}` }
    } catch {}
  }
  return { error: `the safe-ai-skill engine (${name}) was not found` }
}

function runEngine(engine, gate, payload, timeoutMs) {
  return new Promise((done_) => {
    let stdout = ""
    let settled = false
    let timer
    const done = (result) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      done_(result)
    }
    let child
    try {
      child = spawn(engine, ["adapt", "opencode", gate], { stdio: ["pipe", "pipe", "ignore"] })
    } catch (e) {
      return done({ error: `could not start ${engine}: ${e.message}` })
    }
    timer = setTimeout(() => {
      child.kill("SIGKILL")
      done({ error: `the engine did not answer within ${timeoutMs} ms` })
    }, timeoutMs)
    child.on("error", (e) => done({ error: `could not run ${engine}: ${e.message}` }))
    child.stdout.setEncoding("utf8")
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
  const name = options?.engine || process.env.SAFE_AI_SKILL_ENGINE || "safe-ai-skill"
  const engine = locate(name)
  const pluginPath = fileURLToPath(import.meta.url)
  const timeoutMs = Number(options?.timeoutMs) > 0 ? Number(options.timeoutMs) : TIMEOUT_MS
  let mcpServers = []
  return {
    config: async (cfg) => {
      mcpServers = Object.keys(cfg?.mcp ?? {})
    },
    "tool.execute.before": async (input, output) => {
      const tool = input?.tool
      const gates = Object.hasOwn(GATES, tool) ? GATES[tool] : UNGATED.has(tool) ? [] : ["gate-mcp"]
      if (gates.length === 0) return
      if (engine.error) throw new Error(`safe-ai-skill: ${engine.error}; blocked until it is installed and opencode restarts.`)
      const now = locate(name)
      if (now.path !== engine.path || now.id !== engine.id) {
        throw new Error("safe-ai-skill: the safe-ai-skill engine changed since opencode started; blocked until opencode restarts.")
      }
      for (const gate of gates) {
        const payload = JSON.stringify({
          tool,
          sessionID: input.sessionID,
          callID: input.callID,
          args: output?.args,
          directory,
          worktree,
          mcpServers,
          pluginPath,
        })
        const v = verdict(gate, await runEngine(engine.path, gate, payload, timeoutMs))
        if (v.block !== undefined) throw new Error(`safe-ai-skill: ${v.block.replace(/^safe-ai-skill: /, "")}`)
        // opencode passes this same args object to the tool, so change it in place.
        if (v.args) Object.assign(output.args, v.args)
      }
    },
  }
}
