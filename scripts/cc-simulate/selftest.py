#!/usr/bin/env python3
"""Self-test of ccsim's Claude Code model, with throwaway shell hooks and no engine: matcher
forms, exit codes, onFailure, timeouts, decision precedence, permission rules, -p asks and
prompt blocking, each against the doc sentence ccsim cites. Exit 1 on any failure."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ccsim  # noqa: E402

FAILS = []


def check(name, cond, detail=""):
    print("%s %s %s" % ("ok  " if cond else "FAIL", name, detail))
    if not cond:
        FAILS.append(name)


def pre(decision, reason="r"):
    return ("printf '%%s' '{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\","
            "\"permissionDecision\":\"%s\",\"permissionDecisionReason\":\"%s\"}}'"
            % (decision, reason))


def with_hooks(sim, hooks, perms=None):
    os.makedirs(os.path.join(sim.proj, ".claude"), exist_ok=True)
    data = {"hooks": hooks}
    if perms:
        data["permissions"] = perms
    with open(os.path.join(sim.proj, ".claude", "settings.json"), "w") as f:
        json.dump(data, f)


def bash_hooks(*handlers, matcher="Bash"):
    return {"PreToolUse": [{"matcher": matcher, "hooks": [
        dict({"type": "command"}, **h) for h in handlers]}]}


def main():
    check("matcher exact", ccsim.matcher_matches("Bash", "Bash") and
          not ccsim.matcher_matches("Bash", "BashOutput"))
    check("matcher list", ccsim.matcher_matches("Read|Grep|Glob", "Grep") and
          ccsim.matcher_matches("Edit, Write", "Write"))
    check("matcher regex", ccsim.matcher_matches("mcp__.*", "mcp__x__y") and
          not ccsim.matcher_matches("mcp__.*", "Bash"))
    check("matcher all", ccsim.matcher_matches("*", "x") and ccsim.matcher_matches(None, "x"))
    check("stdout forms", ccsim.parse_stdout('{"a":1}')[0] == "json" and
          ccsim.parse_stdout("{bad}")[0] == "parse_error" and
          ccsim.parse_stdout("[1]")[0] == "text" and ccsim.parse_stdout("")[0] == "empty")

    s = ccsim.Sim(None)
    try:
        cases = [
            ("deny beats ask and allow", [pre("allow"), pre("ask"), pre("deny", "no")], "deny"),
            ("ask beats allow", [pre("allow"), pre("ask", "why")], "ask->declined"),
            ("allow alone runs", [pre("allow")], "allow"),
            ("exit 2 blocks", ["echo nope >&2; exit 2"], "deny"),
            ("exit 2 beats a JSON allow", [pre("allow") + "; exit 2"], "deny"),
            ("exit 1 + JSON allow: fields decide", [pre("allow") + "; exit 1"], "allow"),
        ]
        for name, cmds, want in cases:
            with_hooks(s, bash_hooks(*[{"command": c} for c in cmds]))
            o = s.tool_call("Bash", {"command": "true"})
            check(name, o.decision == want, o.decision)
        with_hooks(s, bash_hooks({"command": pre("allow") + "; exit 1", "onFailure": "block"}))
        o = s.tool_call("Bash", {"command": "true"})
        check("onFailure block: exit 1 with JSON blocks", o.decision == "deny", o.decision)
        with_hooks(s, bash_hooks({"command": "exit 1", "onFailure": "block"}))
        check("onFailure block: exit 1 blocks",
              s.tool_call("Bash", {"command": "true"}).decision == "deny")
        with_hooks(s, bash_hooks({"command": "echo '{bad}'", "onFailure": "block"}))
        check("onFailure block: invalid JSON blocks",
              s.tool_call("Bash", {"command": "true"}).decision == "deny")
        with_hooks(s, bash_hooks({"command": "sleep 5; " + pre("deny"), "timeout": 1}))
        s.ask_answer = "yes"
        o = s.tool_call("Bash", {"command": "true"})
        check("timeout without onFailure: no decision, normal flow", o.decision == "allow",
              o.decision)
        with_hooks(s, bash_hooks({"command": "sleep 5", "timeout": 1, "onFailure": "block"}))
        check("timeout with onFailure block: blocks",
              s.tool_call("Bash", {"command": "true"}).decision == "deny")
        s.ask_answer = "no"
        with_hooks(s, bash_hooks({"command": pre("allow")}),
                   {"deny": ["Bash(rm *)"], "ask": ["Bash(git push *)"]})
        check("deny rule beats a hook allow",
              s.tool_call("Bash", {"command": "rm -rf x"}).decision == "deny")
        check("ask rule beats a hook allow",
              s.tool_call("Bash", {"command": "git push"}).decision == "ask->declined")
        with_hooks(s, bash_hooks({"command": pre("ask", "because")}))
        s.headless = True
        o = s.tool_call("Bash", {"command": "true"})
        check("-p: ask is denied and the reason reaches the model",
              o.decision == "ask->denied(-p)" and "because" in o.model_text() and
              o.permission_denied_event)
        s.headless = False
        o = s.tool_call("Bash", {"command": "true"})
        check("interactive: ask reason goes to the user, not the model",
              "because" in o.user_text() and "because" not in o.model_text())
        with_hooks(s, bash_hooks({"command": pre("deny", "denied-why")}))
        o = s.tool_call("Bash", {"command": "true"})
        check("deny reason reaches the model", "denied-why" in o.model_text())
        with_hooks(s, bash_hooks({"command": pre("allow", "allow-why")}))
        o = s.tool_call("Bash", {"command": "true"})
        check("allow reason: debug log only", "allow-why" not in o.model_text() +
              o.user_text() and any("allow-why" in t for _, t in o.debug))
        with_hooks(s, {"UserPromptSubmit": [{"hooks": [{"type": "command", "command":
                       "printf '%s' '{\"decision\":\"block\",\"reason\":\"rr\"}'"}]}]})
        o = s.user_prompt("secret-prompt")
        check("prompt block: reason to user, Original prompt in transcript, nothing to model",
              o.decision == "block" and "Original prompt: secret-prompt" in o.user_text()
              and "secret-prompt" not in o.model_text()
              and any("secret-prompt" in t for _, t in o.transcript))
        with_hooks(s, {"UserPromptSubmit": [{"hooks": [{"type": "command", "command":
                       "printf '%s' '{\"systemMessage\":\"sm\",\"hookSpecificOutput\":"
                       "{\"hookEventName\":\"UserPromptSubmit\",\"additionalContext\":\"ac\"}}'"
                       }]}]})
        o = s.user_prompt("hi")
        check("systemMessage to user only, additionalContext to model and transcript",
              "sm" in o.user_text() and "sm" not in o.model_text() and "ac" in o.model_text()
              and any(t == "ac" for _, t in o.transcript))
        with_hooks(s, {"SessionStart": [{"matcher": "resume", "hooks": [
            {"type": "command", "command": "echo plain"}]}]})
        check("SessionStart matcher on source",
              not s.session_start("startup").model and
              s.session_start("resume").model_text() == "plain")
        with_hooks(s, {"SessionStart": [{"hooks": [
            {"type": "command", "command": "echo x", "if": "Bash(*)"}]}]})
        check("`if` on a non-tool event: hook never runs", not s.session_start("startup").hooks)
    finally:
        s.cleanup()
    print("selftest: %d failed" % len(FAILS))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
