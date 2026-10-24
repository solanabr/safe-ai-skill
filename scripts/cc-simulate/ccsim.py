#!/usr/bin/env python3
"""ccsim: an offline model of Claude Code's hook runtime, for the safe-ai-skill plugin.

It reads the real plugins/safe-ai-skill/hooks/hooks.json (and any project settings hooks,
such as the kit's), picks the hooks Claude Code would run for an event, runs each one through
the real POSIX shim and engine with the environment Claude Code gives hooks, applies
`timeout` and `onFailure`, merges the answers by the documented rules and reports what
Claude Code would do, what the MODEL would see and what the USER would see.

Contract source: the Claude Code docs (code.claude.com/docs/en/hooks, plugins-reference,
headless, tools-reference), pinned against Claude Code 2.1.304. Each rule below names the
doc it comes from; `DOCS-SILENT` marks a choice the docs do not settle, and the report says
so wherever one of those choices decided an outcome.

What it is not: Claude Code. The model is not simulated (each scenario names the tool call
it makes), the transcript file Claude Code writes is modelled from the docs only, and the
permission-rule matcher is a small subset of Claude Code's. The parts that need the real
CLI are listed in the report under each check.

Safety: everything lives in a fresh temp dir (HOME, CLAUDE_CONFIG_DIR, project). Stub
solana / anchor / spl-token / solana-keygen scripts sit first on PATH and only echo. The
real ~/.claude is never written; nothing here uses the network.
"""

import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PLUGIN_SRC = os.path.join(REPO, "plugins", "safe-ai-skill")
PLUGIN_NAME = "safe-ai-skill"
MARKETPLACE = "safe-ai-skill"
PLUGIN_VERSION = "1.1.0"
STUBS = ("solana", "anchor", "spl-token", "solana-keygen")

# hooks: default per-hook timeout in seconds, by event ("Common fields" -> timeout).
DEFAULT_TIMEOUT = {"UserPromptSubmit": 30}
DEFAULT_TIMEOUT_OTHER = 600

# hooks: "When multiple PreToolUse hooks return different decisions, precedence is
# deny > defer > ask > allow."
RANK = {"allow": 1, "ask": 2, "defer": 3, "deny": 4}

# hooks "Matcher patterns": only these characters means an exact name or a `|`/`,` list.
EXACT_MATCHER = re.compile(r"^[A-Za-z0-9_\-\s,|]*$")


def plat_name():
    s, m = platform.system(), platform.machine().lower()
    arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "x64", "amd64": "x64"}.get(m, m)
    return {"Darwin": "darwin", "Linux": "linux"}.get(s, s.lower()) + "-" + arch


def ps_available():
    """Whether this machine lets a process read the process table the way the engine's
    ancestry check does (`/proc`, or `/bin/ps`); a sandboxed run usually cannot."""
    if os.path.exists("/proc/self/stat"):
        return True
    for ps in ("/bin/ps", "/usr/bin/ps"):
        if os.path.isfile(ps):
            try:
                r = subprocess.run([ps, "-A", "-o", "pid="], capture_output=True, timeout=5)
                return r.returncode == 0 and bool(r.stdout.strip())
            except (OSError, subprocess.SubprocessError):
                return False
    return False


def matcher_matches(matcher, value):
    """hooks "Matcher patterns": `*`, empty or omitted matches all; letters, digits, `_`, `-`,
    spaces, `,` and `|` only is an exact string or list; anything else is an unanchored
    JavaScript regex (Python `re.search` agrees with JS on every matcher used here)."""
    if matcher is None or matcher in ("", "*"):
        return True
    if value is None:
        return True
    if EXACT_MATCHER.match(matcher):
        return value in [p.strip() for p in re.split(r"[|,]", matcher) if p.strip()]
    return re.search(matcher, value) is not None


def matcher_value(event, payload):
    """What an event's matcher is compared against (hooks reference, per event). The docs list
    no matcher for UserPromptSubmit, so every group runs there."""
    if event in ("PreToolUse", "PostToolUse"):
        return payload.get("tool_name")
    if event == "SessionStart":
        return payload.get("source")
    if event == "UserPromptExpansion":
        return payload.get("command_name")
    return None


def parse_stdout(out):
    """hooks "Invalid stdout on exit 0": stdout is JSON output only when it is one object with
    nothing around it but whitespace; text that starts with `{` and ends with `}` but is not
    valid JSON is a parse failure; anything else is plain text."""
    s = out.strip()
    if not s:
        return "empty", None
    if s.startswith("{") and s.endswith("}"):
        try:
            v = json.loads(s)
        except ValueError:
            return "parse_error", None
        if isinstance(v, dict):
            return "json", v
        return "parse_error", None
    return "text", s


class HookResult:
    def __init__(self, handler, source):
        self.handler = handler
        self.source = source  # "plugin:safe-ai-skill" or "settings"
        self.exit = None
        self.stdout = ""
        self.stderr = ""
        self.timed_out = False
        self.kind = None  # empty|text|json|parse_error
        self.fields = {}
        self.plain = None
        self.blocking = False  # acts like exit 2 on this event
        self.block_reason = ""
        self.nonblocking_error = None  # notice text for the user
        self.failed = False

    def name(self):
        return self.handler.get("command", "")[:80]


class Outcome:
    """What one event did: the merged decision plus who saw what."""

    def __init__(self, event):
        self.event = event
        self.decision = None
        self.reasons = []
        self.model = []  # (channel, text): reaches the model's context
        self.user = []  # (channel, text): shown to the user
        self.transcript = []  # (channel, text): docs say it is written to the transcript
        self.unknown_transcript = []  # (channel, text): docs silent on transcript storage
        self.debug = []  # (channel, text): debug log only
        self.notes = []  # DOCS-SILENT or modelling notes that decided something
        self.hooks = []
        self.updated_input = None
        self.updated_output = None
        self.tool_result = None  # what the tool returned (before PostToolUse)
        self.ran = False
        self.permission_denied_event = False

    def model_text(self):
        return "\n".join(t for _, t in self.model)

    def user_text(self):
        return "\n".join(t for _, t in self.user)

    def summary(self):
        return {
            "event": self.event,
            "decision": self.decision,
            "ran": self.ran,
            "reasons": self.reasons,
            "model": self.model,
            "user": self.user,
            "transcript": self.transcript,
            "transcript_docs_silent": self.unknown_transcript,
            "debug": self.debug,
            "notes": self.notes,
            "permission_denied_event": self.permission_denied_event,
            "hooks": [
                {"cmd": h.name(), "source": h.source, "exit": h.exit, "kind": h.kind,
                 "timed_out": h.timed_out, "stdout": h.stdout[:2000], "stderr": h.stderr[:500]}
                for h in self.hooks
            ],
        }


def rule_match(rule, tool, tool_input, home, cwd):
    """A small subset of permission-rule syntax: `Tool`, `Bash(<glob>)` against each
    `&&`/`||`/`;`/`|` part of the command, `Read(<path glob>)` with `~`, `//` and `/`
    anchors. Good enough for the kit's rules and the scenarios here; not Claude Code's
    parser (no wrapper stripping, no `$()` handling)."""
    m = re.match(r"^([A-Za-z_]+)(?:\((.*)\))?$", rule)
    if not m:
        return False
    rtool, spec = m.group(1), m.group(2)
    tools = {"Read": ("Read", "Grep", "Glob"), "Edit": ("Edit", "Write", "MultiEdit")}
    if tool not in tools.get(rtool, (rtool,)):
        return False
    if spec is None:
        return True
    if tool == "Bash":
        cmd = (tool_input or {}).get("command", "")
        parts = [p.strip() for p in re.split(r"&&|\|\||;|\|", cmd) if p.strip()]
        # headless docs: "The trailing ` *` enables prefix matching"; taken here to match the
        # bare prefix too (`ls *` matches `ls`).
        if spec.endswith(" *"):
            pat = re.escape(spec[:-2]).replace(r"\*", ".*") + "(\\s.*)?"
        else:
            pat = re.escape(spec).replace(r"\*", ".*")
        return any(re.fullmatch(pat, p, re.S) for p in parts)
    path = (tool_input or {}).get("file_path") or (tool_input or {}).get("path") or ""
    if not path:
        return False
    if spec.startswith("~/"):
        spec = os.path.join(home, spec[2:])
    elif spec.startswith("//"):
        spec = spec[1:]
    elif spec.startswith("/"):
        spec = os.path.join(cwd, spec[1:])
    elif not spec.startswith("*"):
        spec = os.path.join(cwd, spec)
    path = expand_home(path, home)
    if not os.path.isabs(path):
        path = os.path.join(cwd, path)
    pat = re.escape(spec).replace(r"\*\*", "\0").replace(r"\*", "[^/]*").replace("\0", ".*")
    return re.fullmatch(pat, path) is not None or re.fullmatch(pat + "(/.*)?", path) is not None


class Sim:
    """One throwaway Claude Code install: fake HOME, CLAUDE_CONFIG_DIR, a project, stubs, and
    the plugin installed from this repo with the given engine binary."""

    def __init__(self, engine, trust_override=False, keep=False, base=None):
        self.work = tempfile.mkdtemp(prefix="ccsim.", dir=base)
        self.keep = keep
        self.home = os.path.join(self.work, "home")
        self.cfg = os.path.join(self.work, "cfg")
        self.proj = os.path.join(self.work, "proj")
        self.stub = os.path.join(self.work, "stubbin")
        self.stub_log = os.path.join(self.work, "stub.log")
        for d in (self.home, self.cfg, self.proj, self.stub):
            os.makedirs(d)
        # plugins-reference: CLAUDE_PLUGIN_DATA is ~/.claude/plugins/data/<id>/ with every
        # character outside [A-Za-z0-9_-] of the plugin identifier replaced by `-`; with
        # CLAUDE_CONFIG_DIR set, ~/.claude is that dir (settings page note).
        plugin_id = re.sub(r"[^A-Za-z0-9_-]", "-", PLUGIN_NAME + "@" + MARKETPLACE)
        self.data = os.path.join(self.cfg, "plugins", "data", plugin_id)
        self.root = os.path.join(self.cfg, "plugins", "cache", MARKETPLACE, PLUGIN_NAME,
                                 PLUGIN_VERSION)
        shutil.copytree(PLUGIN_SRC, self.root)
        bin_dir = os.path.join(self.root, "bin")
        if engine:
            shutil.copy(engine, os.path.join(bin_dir, "safe-ai-skill-" + plat_name()))
            os.chmod(os.path.join(bin_dir, "safe-ai-skill-" + plat_name()), 0o755)
            subprocess.run(["sh", os.path.join(REPO, "scripts", "stamp-shim.sh"), bin_dir],
                           check=True, stdout=subprocess.DEVNULL)
        for name in STUBS:
            p = os.path.join(self.stub, name)
            with open(p, "w") as f:
                f.write('#!/bin/sh\nprintf "%%s\\n" "ccsim stub ran: %s $*" | tee -a "%s"\n'
                        % (name, self.stub_log))
            os.chmod(p, 0o755)
        subprocess.run(["git", "init", "-q", self.proj], check=True)
        self.trust_override = trust_override
        self.session_id = str(uuid.uuid4())
        self.transcript_path = os.path.join(self.cfg, "projects", "ccsim",
                                            self.session_id + ".jsonl")
        self.extra_env = {}
        # Simulate a machine where the engine cannot read the process table (native Windows,
        # a sandboxed hook): a test-hooks engine honours this switch; a release one ignores it.
        self.no_process_table = False
        self.headless = False  # claude -p
        self.allowed_tools = []  # --allowedTools
        self.ask_answer = "no"  # what the simulated user answers in a permission dialog
        self.log = []  # every Outcome, in order
        self.model_context = []  # everything the model has been given
        self.user_screen = []
        self.transcript = []  # what the docs say Claude Code writes
        self.transcript_unknown = []
        self.with_plugin = bool(engine)
        self.rg = None

    def cleanup(self):
        if not self.keep:
            shutil.rmtree(self.work, ignore_errors=True)

    # environments

    def base_env(self):
        """The `claude` process environment: an allowlist, like `env -i`. Claude Code adds
        CLAUDECODE=1 for the processes it starts."""
        env = {
            "HOME": self.home,
            "CLAUDE_CONFIG_DIR": self.cfg,
            # The standalone data dir would prefer an existing one under the real passwd home.
            "SAFE_AI_SKILL_DATA": os.path.join(self.home, ".local", "share", "safe-ai-skill-data"),
            "PATH": self.stub + ":/usr/bin:/bin:/usr/sbin:/sbin",
            "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
            "LANG": "en_US.UTF-8",
            "USER": os.environ.get("USER", "ccsim"),
            "SHELL": "/bin/bash",
            "CLAUDECODE": "1",
            "CLAUDE_CODE_ENTRYPOINT": "sdk-cli" if self.headless else "cli",
        }
        if self.trust_override:
            env["SAFE_AI_SKILL_TEST_TRUST_DATA_DIR"] = "1"
        if self.no_process_table:
            env["SAFE_AI_SKILL_TEST_NO_PROCESS_TABLE"] = "1"
        env.update(self.extra_env)
        return {k: v for k, v in env.items() if v is not None}

    def hook_env(self, source):
        """plugins-reference "Where each variable resolves": hook commands get
        CLAUDE_PLUGIN_ROOT, CLAUDE_PLUGIN_DATA and CLAUDE_PROJECT_DIR (plugin hooks);
        hooks reference: settings hooks get CLAUDE_PROJECT_DIR."""
        env = self.base_env()
        env["CLAUDE_PROJECT_DIR"] = self.proj
        # env-vars "CLAUDE_CODE_SESSION_ID": set in hook and Bash tool subprocesses, equal to
        # the hook input's session_id (kept on resume, new on /clear).
        env["CLAUDE_CODE_SESSION_ID"] = self.session_id
        if source.startswith("plugin:"):
            env["CLAUDE_PLUGIN_ROOT"] = self.root
            env["CLAUDE_PLUGIN_DATA"] = self.data
            os.makedirs(self.data, exist_ok=True)  # "created on first reference"
        return env

    def tool_env(self):
        """plugins-reference: the plugin's bin/ is on the Bash tool's PATH; the plugin path
        variables are not in the Bash tool's environment."""
        env = self.base_env()
        env["PATH"] = os.path.join(self.root, "bin") + ":" + env["PATH"]
        env["CLAUDE_CODE_SESSION_ID"] = self.session_id
        return env

    # hook selection

    def settings_hooks(self):
        """(source, event map) for each hooks source Claude Code would load."""
        out = []
        if self.with_plugin:
            with open(os.path.join(self.root, "hooks", "hooks.json")) as f:
                out.append(("plugin:" + PLUGIN_NAME, json.load(f)["hooks"]))
        seen = set()
        for name in ("settings.json", "settings.local.json"):
            p = os.path.join(self.proj, ".claude", name)
            if os.path.isfile(p):
                with open(p) as f:
                    data = json.load(f)
                hooks = data.get("hooks") or {}
                # hooks: "If you define the same handler in more than one settings file, it
                # runs once. A plugin's or skill's copy of the same handler stays separate."
                dedup = {}
                for ev, groups in hooks.items():
                    kept = []
                    for g in groups:
                        hs = []
                        for h in g.get("hooks", []):
                            key = (ev, g.get("matcher"), json.dumps(h, sort_keys=True))
                            if key not in seen:
                                seen.add(key)
                                hs.append(h)
                        if hs:
                            kept.append(dict(g, hooks=hs))
                    dedup[ev] = kept
                out.append(("settings", dedup))
        return out

    def permission_rules(self):
        rules = {"allow": list(self.allowed_tools), "ask": [], "deny": []}
        for name in ("settings.json", "settings.local.json"):
            p = os.path.join(self.proj, ".claude", name)
            if os.path.isfile(p):
                with open(p) as f:
                    perms = json.load(f).get("permissions") or {}
                for k in rules:
                    rules[k] += perms.get(k, [])
        return rules

    def select(self, event, payload):
        value = matcher_value(event, payload)
        picked = []
        for source, hooks in self.settings_hooks():
            for group in hooks.get(event, []):
                if event != "UserPromptSubmit" and not matcher_matches(group.get("matcher"), value):
                    continue
                for h in group.get("hooks", []):
                    if h.get("if") is not None:
                        # hooks: `if` is only evaluated on tool events; elsewhere the hook
                        # never runs.
                        if event not in ("PreToolUse", "PostToolUse"):
                            continue
                        if not rule_match(h["if"], payload.get("tool_name"),
                                          payload.get("tool_input"), self.home, self.proj):
                            continue
                    picked.append((source, h))
        return picked

    # running

    def payload(self, event, **extra):
        """hooks "Common input fields"."""
        p = {
            "session_id": self.session_id,
            "transcript_path": self.transcript_path,
            "cwd": self.proj,
            "permission_mode": "default",
            "hook_event_name": event,
        }
        p.update(extra)
        return p

    def run_one(self, event, source, handler, payload):
        r = HookResult(handler, source)
        cmd = handler.get("command", "")
        if source.startswith("plugin:"):
            cmd = cmd.replace("${CLAUDE_PLUGIN_ROOT}", self.root)
            cmd = cmd.replace("${CLAUDE_PLUGIN_DATA}", self.data)
        cmd = cmd.replace("${CLAUDE_PROJECT_DIR}", self.proj)
        timeout = handler.get("timeout") or DEFAULT_TIMEOUT.get(event, DEFAULT_TIMEOUT_OTHER)
        try:
            p = subprocess.Popen(["/bin/bash", "-c", cmd], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 env=self.hook_env(source), cwd=self.proj,
                                 start_new_session=True)
        except OSError as e:
            r.failed, r.kind, r.nonblocking_error = True, "cannot_start", str(e)
            return self.apply_on_failure(event, r, "failed")
        try:
            out, err = p.communicate(json.dumps(payload).encode(), timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(p.pid, 9)
            except OSError:
                pass
            p.communicate()
            # hooks "Timeouts": the hook is cancelled and its output discarded.
            r.timed_out, r.failed, r.kind = True, True, "timeout"
            r.nonblocking_error = "%s hook error: timed out" % event
            return self.apply_on_failure(event, r, "timed out")
        r.exit, r.stdout, r.stderr = p.returncode, out.decode(errors="replace"), err.decode(
            errors="replace")
        r.kind, parsed = parse_stdout(r.stdout)
        first_err = (r.stderr.strip().splitlines() or [""])[0]
        if r.exit == 2:
            # "Blocking error. Your stderr is the reason"; JSON fields are read but can't
            # override the block.
            r.blocking, r.block_reason = True, r.stderr.strip()
            if r.kind == "json":
                r.fields = parsed
            return r
        if r.kind == "json":
            r.fields = parsed
            if r.exit != 0:
                # "Exit code other than 0 or 2: counts [as a failure] for a command hook even
                # if it printed JSON"; without onFailure the fields alone decide.
                r.failed = True
                if handler.get("onFailure") == "block":
                    return self.apply_on_failure(event, r, "failed")
            return r
        if r.kind == "parse_error":
            r.failed = True
            r.nonblocking_error = "%s hook error: invalid JSON output" % event
            return self.apply_on_failure(event, r, "failed")
        if r.kind == "text":
            r.plain = parsed
        if r.exit != 0:
            r.failed = True
            r.nonblocking_error = "%s hook error: %s" % (event, first_err)
            return self.apply_on_failure(event, r, "failed")
        return r

    def apply_on_failure(self, event, r, how):
        """hooks "Block the action when a hook fails": with onFailure "block" a failure does
        what exit 2 does on that event."""
        if r.handler.get("onFailure") == "block":
            r.blocking = True
            r.block_reason = ('%s hook error: [%s]: %s; blocking because onFailure is "block"\n%s'
                              % (event, r.handler.get("command", ""), how, r.stderr.strip()))
        return r

    def run_event(self, event, payload):
        picked = self.select(event, payload)
        # hooks: "When an event fires, its matching hooks run in parallel."
        with ThreadPoolExecutor(max_workers=max(1, len(picked))) as ex:
            futs = [ex.submit(self.run_one, event, s, h, payload) for s, h in picked]
            return [f.result() for f in futs]

    def _common(self, o, results):
        for r in results:
            o.hooks.append(r)
            sm = r.fields.get("systemMessage") if r.fields else None
            if isinstance(sm, str) and sm:
                # hooks "Universal output fields": "Warning message shown to the user. In
                # Agent SDK and --output-format stream-json output, it can arrive as an
                # SDKInformationalMessage". Transcript storage: DOCS-SILENT.
                o.user.append(("systemMessage", sm))
                o.unknown_transcript.append(("systemMessage", sm))
            if r.nonblocking_error and not r.blocking:
                o.user.append(("hook error notice", r.nonblocking_error))
                o.transcript.append(("hook error notice", r.nonblocking_error))
            if r.fields and r.fields.get("continue") is False:
                o.notes.append("a hook returned continue:false (stops Claude)")
                o.user.append(("stopReason", r.fields.get("stopReason", "")))

    def _context(self, o, results, event):
        """additionalContext (all events here) and plain stdout (UserPromptSubmit,
        UserPromptExpansion, SessionStart) reach the model as a system reminder, and "Claude
        Code saves the injected text in the session transcript"."""
        for r in results:
            if r.blocking:
                continue
            hso = r.fields.get("hookSpecificOutput") if r.fields else None
            if isinstance(hso, dict) and hso.get("additionalContext"):
                if hso.get("hookEventName") not in (None, event):
                    o.notes.append("hookEventName mismatch in %s" % r.name())
                o.model.append(("additionalContext", hso["additionalContext"]))
                o.transcript.append(("additionalContext", hso["additionalContext"]))
            if r.plain and event in ("UserPromptSubmit", "UserPromptExpansion", "SessionStart"):
                o.model.append(("plain stdout", r.plain))
                o.transcript.append(("plain stdout", r.plain))
            elif r.plain:
                o.debug.append(("stdout", r.plain))

    def record(self, o):
        self.log.append(o)
        self.model_context += [t for _, t in o.model]
        self.user_screen += [t for _, t in o.user]
        self.transcript += [t for _, t in o.transcript]
        self.transcript_unknown += [t for _, t in o.unknown_transcript]
        os.makedirs(os.path.dirname(self.transcript_path), exist_ok=True)
        with open(self.transcript_path, "a") as f:
            for ch, t in o.transcript:
                f.write(json.dumps({"event": o.event, "channel": ch, "text": t}) + "\n")
        return o

    # events

    def session_start(self, source="startup"):
        o = Outcome("SessionStart")
        res = self.run_event("SessionStart", self.payload("SessionStart", source=source))
        self._common(o, res)
        self._context(o, res, "SessionStart")
        for r in res:
            if r.blocking:  # exit 2: "Shows stderr to user only"
                o.user.append(("exit 2 stderr", r.block_reason))
        return self.record(o)

    def user_prompt(self, prompt):
        """UserPromptSubmit, then (for a typed /name) UserPromptExpansion and the skill body.
        DOCS-SILENT: the order of the two events; the engine judges a typed /name on both."""
        o = Outcome("UserPromptSubmit")
        res = self.run_event("UserPromptSubmit", self.payload("UserPromptSubmit", prompt=prompt))
        self._common(o, res)
        blocked, suppress, reasons = False, False, []
        for r in res:
            hso = r.fields.get("hookSpecificOutput") if r.fields else None
            if isinstance(hso, dict) and hso.get("suppressOriginalPrompt"):
                suppress = True
            if r.blocking:
                blocked = True
                reasons.append(r.block_reason)
            elif r.fields.get("decision") == "block":
                blocked = True
                reasons.append(r.fields.get("reason", ""))
        if blocked:
            # "reason: Shown to the user when decision is block. Not added to context";
            # "By default the block message shown to the user ends with `Original prompt:`
            # followed by the submitted text, and Claude Code writes that message to the
            # session's transcript file on disk."
            o.decision = "block"
            msg = "\n".join(reasons) + ("" if suppress else "\nOriginal prompt: " + prompt)
            o.user.append(("prompt blocked", msg))
            o.transcript.append(("prompt blocked", msg))
            o.reasons = reasons
            return self.record(o)
        o.decision = "pass"
        # The user's own prompt reaches the model and the transcript.
        o.model.append(("user prompt", prompt))
        o.transcript.append(("user prompt", prompt))
        self._context(o, res, "UserPromptSubmit")
        self.record(o)
        name = slash_name(prompt)
        if name and self.skill_dir(name):
            return self.expand(name, prompt)
        return o

    def skill_dir(self, name):
        p = os.path.join(self.proj, ".claude", "skills", name)
        return p if os.path.isfile(os.path.join(p, "SKILL.md")) else None

    def expand(self, name, prompt):
        o = Outcome("UserPromptExpansion")
        args = prompt.strip()[len(name) + 1:].strip()
        res = self.run_event("UserPromptExpansion", self.payload(
            "UserPromptExpansion", expansion_type="slash_command", command_name=name,
            command_args=args, command_source="projectSettings", prompt=prompt))
        self._common(o, res)
        reasons = [r.block_reason for r in res if r.blocking] + [
            r.fields.get("reason", "") for r in res
            if not r.blocking and r.fields.get("decision") == "block"]
        if reasons:
            o.decision = "block"  # "reason: Shown to the user"
            o.reasons = reasons
            o.user.append(("expansion blocked", "\n".join(reasons)))
            o.transcript.append(("expansion blocked", "\n".join(reasons)))
            return self.record(o)
        o.decision = "expand"
        self._context(o, res, "UserPromptExpansion")
        body = self.render_skill(name)
        o.model.append(("skill body", body))
        o.transcript.append(("skill body", body))
        o.ran = True
        return self.record(o)

    def render_skill(self, name):
        """The SKILL.md body with each !`cmd` run in the project (skills docs: injected
        commands run when the skill loads)."""
        with open(os.path.join(self.skill_dir(name), "SKILL.md")) as f:
            text = f.read()
        body = re.sub(r"\A---\n.*?\n---\n", "", text, flags=re.S)

        def run(m):
            p = subprocess.run(["/bin/bash", "-c", m.group(1)], cwd=self.proj,
                               env=self.tool_env(), capture_output=True, text=True, timeout=30)
            return p.stdout
        return re.sub(r"!`([^`]*)`", run, body)

    def tool_call(self, tool, tool_input):
        o = Outcome("PreToolUse")
        tool_use_id = "toolu_ccsim_" + uuid.uuid4().hex[:12]
        res = self.run_event("PreToolUse", self.payload(
            "PreToolUse", tool_name=tool, tool_input=tool_input, tool_use_id=tool_use_id))
        self._common(o, res)
        decisions, updated = [], []
        for r in res:
            if r.blocking:
                decisions.append(("deny", r.block_reason, r.source))
                continue
            hso = r.fields.get("hookSpecificOutput") if r.fields else None
            pd, why = None, ""
            if isinstance(hso, dict):
                pd, why = hso.get("permissionDecision"), hso.get("permissionDecisionReason", "")
                if "updatedInput" in hso:
                    updated.append((r.source, hso["updatedInput"]))
            if pd is None and r.fields.get("decision") in ("approve", "block"):
                # deprecated top-level form: approve -> allow, block -> deny
                pd = {"approve": "allow", "block": "deny"}[r.fields["decision"]]
                why = r.fields.get("reason", "")
            if pd in RANK:
                decisions.append((pd, why, r.source))
        hook_decision = max((d[0] for d in decisions), key=RANK.get, default=None)
        self._context(o, res, "PreToolUse")
        for d, why, src in decisions:
            if d in ("allow", "defer") and why:
                o.debug.append(("permissionDecisionReason (%s, %s)" % (d, src), why))
        if updated:
            if len(updated) > 1:
                o.notes.append("DOCS-SILENT: %d hooks returned updatedInput; the last one in "
                               "hook order is applied here" % len(updated))
            tool_input = updated[-1][1]
            o.updated_input = tool_input
        rules = self.permission_rules()
        rule_hit = {k: [r for r in rules[k] if rule_match(r, tool, tool_input, self.home,
                                                          self.proj)] for k in rules}
        # hooks PreToolUse: "Deny and ask rules are still evaluated regardless of what the hook
        # returns"; a hook allow "skips the permission prompt".
        final, why = None, []
        if hook_decision == "deny":
            final, why = "deny", [w for d, w, _ in decisions if d == "deny"]
            o.model.append(("tool_result (denied by hook)", "\n".join(why)))
            o.user.append(("tool denied by hook", "\n".join(why)))
            o.transcript.append(("tool_result", "\n".join(why)))
        elif hook_decision == "defer":
            final = "defer"
            o.notes.append("defer: the turn ends (only with -p)")
        elif rule_hit["deny"]:
            final, why = "deny", ["permission rule deny: " + ", ".join(rule_hit["deny"])]
            o.model.append(("tool_result (denied by rule)", why[0]))
            o.user.append(("tool denied by rule", why[0]))
            o.transcript.append(("tool_result", why[0]))
        elif hook_decision == "ask" or rule_hit["ask"]:
            why = [w for d, w, _ in decisions if d == "ask"] or ["permission rule ask"]
            labels = sorted({s for d, _, s in decisions if d == "ask"})
            final = self._ask(o, why, labels)
        elif hook_decision == "allow":
            final = "allow"
        elif rule_hit["allow"] or not self.needs_permission(tool, tool_input):
            final = "allow"
        else:
            final = self._ask(o, ["(no rule, no hook decision: normal permission prompt)"], [])
        o.decision, o.reasons = final, why
        if final != "allow":
            return self.record(o)
        self.record(o)
        return self.execute(tool, tool_input, tool_use_id, o)

    def needs_permission(self, tool, tool_input):
        """tools-reference: Read, Grep, Glob need no permission inside the working
        directory; Bash and the writing tools do (the read-only Bash set is not modelled)."""
        if tool in ("Read", "Grep", "Glob"):
            path = (tool_input or {}).get("file_path") or (tool_input or {}).get("path") or self.proj
            path = os.path.abspath(os.path.join(self.proj, expand_home(path, self.home)))
            return not (path == self.proj or path.startswith(self.proj + os.sep))
        return tool not in ("Skill",)

    def _ask(self, o, why, labels):
        text = "\n".join(why)
        if self.headless:
            # hooks: "When Claude Code denies the call in a -p run where no one can answer
            # that prompt, Claude reads the reason in the tool result instead."; headless:
            # "denials appear as permission_denied system messages".
            o.permission_denied_event = True
            o.model.append(("tool_result (ask auto-denied under -p)", text))
            o.transcript.append(("tool_result", text))
            return "ask->denied(-p)"
        # hooks: "For ask, shown to the user in the permission prompt" with a source label.
        o.user.append(("permission dialog %s" % " ".join("[%s]" % l for l in labels), text))
        if self.ask_answer == "yes":
            return "allow"
        o.model.append(("tool_result (user declined)", "The user declined this tool call."))
        o.transcript.append(("tool_result", "The user declined this tool call."))
        return "ask->declined"

    def execute(self, tool, tool_input, tool_use_id, pre):
        response = self.run_tool(tool, tool_input)
        pre.ran = True
        pre.tool_result = response
        if tool == "Bash" and bash_failed(tool_input.get("command", ""), response):
            return self.execute_failed(tool, tool_input, tool_use_id, pre, response)
        o = Outcome("PostToolUse")
        o.ran = True
        o.tool_result = response
        res = self.run_event("PostToolUse", self.payload(
            "PostToolUse", tool_name=tool, tool_input=tool_input,
            tool_response={k: v for k, v in response.items() if k != "exit"},
            tool_use_id=tool_use_id, duration_ms=1))
        self._common(o, res)
        shown = response
        for r in res:
            hso = r.fields.get("hookSpecificOutput") if r.fields else None
            if isinstance(hso, dict):
                for k in ("updatedToolOutput", "updatedMCPToolOutput"):
                    if k in hso:
                        if o.updated_output is not None:
                            o.notes.append("DOCS-SILENT: two hooks replaced the tool output")
                        o.updated_output = hso[k]
                        shown = hso[k]
        # "updatedToolOutput replaces the tool's output ... before it is sent to Claude"
        text = render_response(tool, shown)
        o.model.append(("tool_result", text))
        o.transcript.append(("tool_result", text))
        self._context(o, res, "PostToolUse")
        for r in res:
            if r.blocking:  # exit 2: "Shows stderr to Claude; the tool already ran"
                o.model.append(("PostToolUse exit 2 stderr", r.block_reason))
            elif r.fields.get("decision") == "block":
                o.model.append(("PostToolUse block reason", r.fields.get("reason", "")))
        self.record(o)
        pre.updated_output = o.updated_output
        pre.model += o.model
        pre.user += o.user
        pre.hooks += o.hooks
        pre.notes += o.notes
        return pre

    def execute_failed(self, tool, tool_input, tool_use_id, pre, response):
        """hooks PostToolUseFailure: "Runs when a tool that started executing fails"; for Bash
        the `error` is "Exit code N" then the output, "generally the same text Claude receives
        as the failed tool's result"; its only event-specific output is additionalContext
        (no documented way to replace the text). PostToolUse does not run."""
        o = Outcome("PostToolUseFailure")
        o.ran = True
        o.tool_result = response
        error = "Exit code %d\n%s%s" % (response.get("exit", 1), response.get("stdout", ""),
                                         response.get("stderr", ""))
        res = self.run_event("PostToolUseFailure", self.payload(
            "PostToolUseFailure", tool_name=tool, tool_input=tool_input,
            tool_use_id=tool_use_id, error=error, is_interrupt=False, duration_ms=1))
        self._common(o, res)
        o.model.append(("tool_result (error)", error.rstrip("\n")))
        o.transcript.append(("tool_result (error)", error.rstrip("\n")))
        self._context(o, res, "PostToolUseFailure")
        o.notes.append("Bash exited %d: PostToolUseFailure, not PostToolUse" %
                       response.get("exit", 1))
        self.record(o)
        pre.model += o.model
        pre.user += o.user
        pre.hooks += o.hooks
        pre.notes += o.notes
        return pre

    def run_tool(self, tool, ti):
        if tool == "Bash":
            p = subprocess.run(["/bin/bash", "-c", ti.get("command", "")], cwd=self.proj,
                               env=self.tool_env(), capture_output=True, text=True, timeout=60)
            return {"stdout": p.stdout, "stderr": p.stderr, "interrupted": False,
                    "isImage": False, "exit": p.returncode}
        if tool == "Read":
            path = os.path.join(self.proj, expand_home(ti.get("file_path", ""), self.home))
            try:
                with open(path, errors="replace") as f:
                    content = f.read()
            except OSError as e:
                return {"type": "error", "error": str(e)}
            return {"type": "text", "file": {"filePath": path, "content": content,
                                             "numLines": content.count("\n"), "startLine": 1,
                                             "totalLines": content.count("\n")}}
        if tool == "Grep":
            return self.grep(ti)
        if tool == "Skill":
            name = ti.get("skill", "")
            if not self.skill_dir(name):
                return {"success": False, "commandName": name}
            return {"success": True, "commandName": name, "body": self.render_skill(name)}
        if tool in ("Write", "Edit"):
            path = os.path.join(self.proj, ti.get("file_path", ""))
            with open(path, "a" if tool == "Edit" else "w") as f:
                f.write(ti.get("content", ti.get("new_string", "")))
            return {"type": "update", "filePath": path}
        return {"note": "tool not modelled"}

    def grep(self, ti):
        """tools-reference: Grep is built on ripgrep and skips gitignored files. Claude Code's
        exact rg argument list is not documented; this runs rg (Claude Code's embedded one
        when found) with -n, --hidden, the pattern, an optional --glob and the path. The
        hidden-file default is a guess (DOCS-SILENT)."""
        rg = self.rg or find_rg()
        if not rg:
            return {"error": "no ripgrep available to the simulator"}
        exe, argv0 = rg
        args = [argv0, "-n", "--no-heading", "--hidden", "--", ti.get("pattern", "")]
        if ti.get("glob"):
            args[1:1] = ["--glob", ti["glob"]]
        path = ti.get("path")
        if path:
            args.append(expand_home(path, self.home))
        p = subprocess.run(args, executable=exe, cwd=self.proj, env=self.tool_env(),
                           capture_output=True, text=True, timeout=60)
        return {"mode": "content", "content": p.stdout, "stderr": p.stderr[:500],
                "exit": p.returncode}

    # state helpers

    def cli(self, *args, env=None):
        """`safe-ai-skill <args>` from the user's own terminal (outside Claude Code): the
        shim on the plugin path with the throwaway HOME and CLAUDE_CONFIG_DIR."""
        e = self.base_env()
        e.update(env or {})
        p = subprocess.run([os.path.join(self.root, "bin", "safe-ai-skill")] + list(args),
                           cwd=self.proj, env=e, capture_output=True, text=True, timeout=60)
        return p.returncode, p.stdout + p.stderr

    def files_containing(self, needle, roots=None):
        hits = []
        for root in roots or (self.cfg, self.proj, self.home):
            for dp, _, fns in os.walk(root):
                for fn in fns:
                    p = os.path.join(dp, fn)
                    try:
                        with open(p, "rb") as f:
                            if needle.encode() in f.read():
                                hits.append(p)
                    except OSError:
                        pass
        return hits


# tools-reference: exit 1 is a valid result only for these; "Every other command that exits 1
# counts as a failure". Any other non-zero exit is a failure.
BENIGN_EXIT1 = ("grep", "rg", "egrep", "fgrep", "find", "diff", "test", "[")


def bash_failed(command, response):
    code = response.get("exit", 0)
    if code == 0:
        return False
    if code == 1:
        words = command.strip().split()
        first = words[0] if words else ""
        if first in BENIGN_EXIT1 or words[:2] in (["git", "diff"], ["git", "grep"]):
            return False
    return True


def expand_home(path, home):
    """`~` against the simulated HOME, never the caller's (os.path.expanduser would read the
    real one)."""
    if path == "~" or path.startswith("~/"):
        return home + path[1:]
    return path


def slash_name(prompt):
    m = re.match(r"^/([A-Za-z0-9_:\-]+)(\s|$)", prompt.strip())
    return m.group(1) if m else None


def render_response(tool, resp):
    if not isinstance(resp, dict):
        return json.dumps(resp)
    if tool == "Bash":
        return (resp.get("stdout", "") + resp.get("stderr", "")).rstrip("\n")
    if tool == "Read" and isinstance(resp.get("file"), dict):
        return resp["file"].get("content", "")
    if tool == "Grep":
        return resp.get("content", "") or resp.get("error", "")
    if tool == "Skill":
        return resp.get("body", "")
    return json.dumps(resp)


_RG = []
_RG_LOCK = threading.Lock()


def find_rg():
    """Claude Code's own ripgrep (its binary run as argv0 `rg`), else a system rg."""
    with _RG_LOCK:
        if _RG:
            return _RG[0]
        found = None
        claude = os.environ.get("CCSIM_CLAUDE") or shutil.which("claude")
        if claude:
            try:
                p = subprocess.run(["rg", "--version"], executable=claude, capture_output=True,
                                   text=True, timeout=20)
                if p.returncode == 0 and "ripgrep" in p.stdout:
                    found = (claude, "rg")
            except (OSError, subprocess.SubprocessError):
                pass
        if not found:
            sys_rg = shutil.which("rg")
            if sys_rg and os.access(sys_rg, os.X_OK):
                found = (sys_rg, "rg")
        _RG.append(found)
        return found
