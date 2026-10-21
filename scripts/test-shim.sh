#!/bin/sh
# test-shim.sh — failure-contract tests for the plugin shim
# (plugins/safe-ai-skill/bin/safe-ai-skill, spec D6.1) and the onFailure wiring in
# plugins/safe-ai-skill/hooks/hooks.json (D6.2).
#
# Self-contained: each case copies the shim into a temp plugin layout beside fake engine
# binaries, with a fake `uname` first on PATH, so no real engine runs. The matrix repeats
# under every POSIX shell installed (sh, dash, bash --posix, busybox sh) and once through
# the shim's own shebang. Needs python3 for the JSON checks. Exits 1 if any check fails.

set -u

cd "$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)" || exit 1
shim_src=$PWD/plugins/safe-ai-skill/bin/safe-ai-skill
hooks_json=$PWD/plugins/safe-ai-skill/hooks/hooks.json

py=$(python3 -I -c 'import sys; print(sys.executable)' 2>/dev/null) || {
  echo "test-shim: python3 is required for the JSON checks" >&2
  exit 1
}

work=$(mktemp -d "${TMPDIR:-/tmp}/test-shim.XXXXXX") || exit 1
trap 'rm -rf "$work"' EXIT
trap 'exit 1' HUP INT TERM

# The shim and the fakes read these; the caller's own values must not leak into the cases.
unset SAFE_AI_SKILL_STRICT SAFE_AI_SKILL_DISABLE CLAUDE_PLUGIN_OPTION_STRICT \
  FAKE_UNAME_S FAKE_UNAME_M FAKE_MARKS

ALLOW='{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'
payload=$work/payload
printf '%s\n' '{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"README.md"}}' >"$payload"
payload_text=$(cat "$payload")

fakebin=$work/fakebin
mkdir "$fakebin"
cat >"$fakebin/uname" <<'EOF'
#!/bin/sh
# Fake uname: answers from FAKE_UNAME_S / FAKE_UNAME_M and fails for an unset one.
case "${1:-}" in
  -s) [ -n "${FAKE_UNAME_S+set}" ] && printf '%s\n' "$FAKE_UNAME_S" ;;
  -m) [ -n "${FAKE_UNAME_M+set}" ] && printf '%s\n' "$FAKE_UNAME_M" ;;
  *) false ;;
esac
EOF
cat >"$fakebin/cargo" <<'EOF'
#!/bin/sh
: >"$FAKE_MARKS/cargo"
exit 1
EOF
chmod +x "$fakebin/uname" "$fakebin/cargo"

# mk <path> <body>: write an executable fake engine that records it ran, then runs <body>.
# The fakes' $-expressions are meant to expand when they run, not here.
# shellcheck disable=SC2016
mk() {
  printf '#!/bin/sh\n: >"$FAKE_MARKS/${0##*/}"\n%s\n' "$2" >"$1"
  chmod +x "$1"
}

# engine <path> <behaviour>: write one fake engine variant.
# shellcheck disable=SC2016
engine() {
  case $2 in
    ok) mk "$1" 'printf "ran=%s args=%s stdin=%s" "${0##*/}" "$*" "$(cat)"' ;;
    bytes) mk "$1" "printf 'line1\\n\\nline3\\n\\n'" ;;
    planted) mk "$1" "printf '%s' '$ALLOW'" ;;
    exit:*) mk "$1" "printf '%s' '$ALLOW'; echo 'engine stderr' >&2; exit ${2#exit:}" ;;
    kill) mk "$1" "printf '%s' '$ALLOW'; kill -s KILL \$\$" ;;
    badinterp) printf '#!/nonexistent/interpreter\necho ran\n' >"$1" && chmod +x "$1" ;;
    # No shebang and no binary magic: execve fails with ENOEXEC, and a shell that falls
    # back to running it as a script prints an allow verdict.
    garbage) printf '\001\002\003\004\necho %s\n' "'$ALLOW'" >"$1" && chmod +x "$1" ;;
    empty) : >"$1" && chmod +x "$1" ;;
    noexec) mk "$1" 'echo ran' && chmod -x "$1" ;;
  esac
}

# fresh [<suffix>]: a new plugin layout with a planted data-dir engine and a crates/engine
# dir (so a cargo fallback, if any, would fire). Resets the case environment to
# Linux/x86_64.
n=0
fresh() {
  n=$((n + 1))
  case_dir=$work/case$n${1:-}
  bin_dir=$case_dir/plugins/safe-ai-skill/bin
  data_dir=$case_dir/data
  marks=$case_dir/marks
  mkdir -p "$bin_dir" "$data_dir/bin" "$marks" "$case_dir/crates/engine"
  : >"$case_dir/crates/engine/Cargo.toml"
  cp "$shim_src" "$bin_dir/safe-ai-skill"
  chmod +x "$bin_dir/safe-ai-skill"
  engine "$data_dir/bin/safe-ai-skill" planted
  u_s=Linux
  u_m=x86_64
  u_fail=
  e_strict=
  e_disable=
  e_opt=
  bare=
}

# run <args...>: run the case's shim under $sh_cmd with the hook payload on stdin (by bare
# name from its own directory when $bare is set). Sets rc; stdout and stderr land in
# $case_dir/out and $case_dir/err. The outer 2>/dev/null only swallows this shell's own
# "Killed" job notices.
run() {
  (
    (
      PATH=$fakebin:$PATH
      FAKE_MARKS=$marks
      CLAUDE_PLUGIN_DATA=$data_dir
      FAKE_UNAME_M=$u_m
      export PATH FAKE_MARKS CLAUDE_PLUGIN_DATA FAKE_UNAME_M
      if [ -z "$u_fail" ]; then FAKE_UNAME_S=$u_s && export FAKE_UNAME_S; fi
      if [ -n "$e_strict" ]; then SAFE_AI_SKILL_STRICT=$e_strict && export SAFE_AI_SKILL_STRICT; fi
      if [ -n "$e_disable" ]; then SAFE_AI_SKILL_DISABLE=$e_disable && export SAFE_AI_SKILL_DISABLE; fi
      if [ -n "$e_opt" ]; then CLAUDE_PLUGIN_OPTION_STRICT=$e_opt && export CLAUDE_PLUGIN_OPTION_STRICT; fi
      if [ "$sh_cmd" = direct ]; then exec "$bin_dir/safe-ai-skill" "$@"; fi
      if [ -n "$bare" ]; then cd "$bin_dir" && exec $sh_cmd safe-ai-skill "$@"; fi
      exec $sh_cmd "$bin_dir/safe-ai-skill" "$@"
    ) <"$payload" >"$case_dir/out" 2>"$case_dir/err"
    exit $?
  ) 2>/dev/null
  rc=$?
}

checks=0
fails=0
t() { tname=$1; }
check() { checks=$((checks + 1)); }
fail() {
  fails=$((fails + 1))
  printf 'not ok - [%s] %s: %s\n' "$sh_name" "$tname" "$1"
}
snippet() { head -c 400 "$1" | tr '\n' '|'; }

expect_rc() {
  check
  [ "$rc" = "$1" ] || fail "exit $rc, want $1; stderr <$(snippet "$case_dir/err")>"
}
expect_rc_nonzero() {
  check
  [ "$rc" != 0 ] || fail "exit 0, want non-zero"
}
expect_out() {
  check
  [ "$(cat "$case_dir/out")" = "$1" ] || fail "stdout <$(snippet "$case_dir/out")>, want <$1>"
}
expect_no_out() {
  check
  [ ! -s "$case_dir/out" ] || fail "stdout <$(snippet "$case_dir/out")>, want nothing"
}
expect_no_err() {
  check
  [ ! -s "$case_dir/err" ] || fail "stderr <$(snippet "$case_dir/err")>, want nothing"
}
expect_err_lines() {
  check
  lines=$(wc -l <"$case_dir/err" | tr -d ' ')
  [ "$lines" = "$1" ] || fail "$lines stderr lines, want $1: <$(snippet "$case_dir/err")>"
}
expect_err_has() {
  check
  grep -q -- "$1" "$case_dir/err" || fail "stderr <$(snippet "$case_dir/err")> lacks '$1'"
}
expect_ran() {
  check
  [ -e "$marks/$1" ] || fail "$1 did not run"
}
expect_not_ran() {
  check
  [ ! -e "$marks/$1" ] || fail "$1 ran"
}
expect_ask() {
  check
  "$py" -I -c '
import json, sys
d = json.load(open(sys.argv[1]))
h = d["hookSpecificOutput"]
assert list(d) == ["hookSpecificOutput"], d
assert h["hookEventName"] == "PreToolUse" and h["permissionDecision"] == "ask", h
assert "inactive" in h["permissionDecisionReason"], h
' "$case_dir/out" </dev/null 2>/dev/null ||
    fail "stdout <$(snippet "$case_dir/out")> is not a PreToolUse ask"
}
expect_notice() {
  check
  "$py" -I -c '
import json, sys
d = json.load(open(sys.argv[1]))
needle = sys.argv[2]
h = d["hookSpecificOutput"]
assert needle in d["systemMessage"], d
assert h["hookEventName"] == "SessionStart" and needle in h["additionalContext"], h
' "$case_dir/out" "$1" </dev/null 2>/dev/null ||
    fail "stdout <$(snippet "$case_dir/out")> is not a SessionStart notice with '$1'"
}

# env_case <scenario>: a fresh case where the engine can't run. Decoy prebuilts for other
# platforms are present and must never run.
env_case() {
  fresh
  target=$bin_dir/safe-ai-skill-linux-x64
  decoys='darwin-arm64 darwin-x64 linux-arm64'
  case $1 in
    mingw) u_s=MINGW64_NT-10.0-22631 ;;
    msys) u_s=MSYS_NT-10.0-22631 ;;
    cygwin) u_s=CYGWIN_NT-10.0-22631 ;;
    sunos) u_s=SunOS && u_m=sun4v ;;
    riscv) u_m=riscv64 ;;
    nouname) u_fail=1 ;;
    missing) ;;
    exit127) engine "$target" exit:127 ;;
    exit126) engine "$target" exit:126 ;;
    *) engine "$target" "$1" ;;
  esac
  case $1 in
    mingw | msys | cygwin | sunos | riscv | nouname) decoys="$decoys linux-x64" ;;
  esac
  for p in $decoys; do engine "$bin_dir/safe-ai-skill-$p" ok; done
}

matrix() {
  # Dispatch: each platform runs its own prebuilt, with args and stdin intact.
  for spec in Darwin/arm64/darwin-arm64 Darwin/x86_64/darwin-x64 Linux/x86_64/linux-x64 \
    Linux/aarch64/linux-arm64 Linux/arm64/linux-arm64 \
    MINGW64_NT-10.0-22631/x86_64/windows-x64.exe MSYS_NT-10.0-22631/x86_64/windows-x64.exe \
    CYGWIN_NT-10.0-22631/x86_64/windows-x64.exe MINGW64_NT-10.0-22631/aarch64/windows-x64.exe; do
    fresh
    u_s=${spec%%/*}
    rest=${spec#*/}
    u_m=${rest%%/*}
    want=${rest#*/}
    for p in darwin-arm64 darwin-x64 linux-x64 linux-arm64 windows-x64.exe; do
      engine "$bin_dir/safe-ai-skill-$p" ok
    done
    t "dispatch $u_s/$u_m runs safe-ai-skill-$want"
    run gate-read 'two words'
    expect_rc 0
    expect_out "ran=safe-ai-skill-$want args=gate-read two words stdin=$payload_text"
  done

  # Engine verdicts (exit 0/2/3) pass through untouched.
  fresh
  engine "$bin_dir/safe-ai-skill-linux-x64" bytes
  t "exit 0 passes stdout through byte for byte"
  run gate-read
  expect_rc 0
  check
  printf 'line1\n\nline3\n\n' | cmp -s - "$case_dir/out" ||
    fail "stdout <$(snippet "$case_dir/out")> is not byte-identical"
  for code in 2 3; do
    fresh
    engine "$bin_dir/safe-ai-skill-linux-x64" "exit:$code"
    t "exit $code passes stdout, stderr and status through"
    run gate-read
    expect_rc "$code"
    expect_out "$ALLOW"
    expect_err_has 'engine stderr'
    run gate-bash
    expect_rc "$code"
    expect_out "$ALLOW"
  done

  # Environment failure: fail open with a notice, but the Solana surface stays at ask.
  for sc in mingw msys cygwin sunos riscv nouname missing exit127 exit126 badinterp garbage \
    empty noexec; do
    env_case "$sc"
    t "$sc: gate-read fails open with one stderr line"
    run gate-read
    expect_rc 0
    expect_no_out
    expect_err_lines 1
    t "$sc: gate-mcp fails open with one stderr line"
    run gate-mcp
    expect_rc 0
    expect_no_out
    expect_err_lines 1
    t "$sc: redact fails open with one stderr line"
    run redact
    expect_rc 0
    expect_no_out
    expect_err_lines 1
    t "$sc: gate-bash answers ask"
    run gate-bash
    expect_rc 0
    expect_ask
    expect_err_lines 1
    t "$sc: SessionStart reports the firewall INACTIVE"
    run verify session
    expect_rc 0
    expect_notice INACTIVE
    expect_err_lines 1
    t "$sc: a CLI command reports the failure"
    run status
    expect_rc_nonzero
    t "$sc: SAFE_AI_SKILL_STRICT=1 fails closed"
    e_strict=1
    for args in gate-read gate-bash gate-mcp 'verify session'; do
      run $args
      expect_rc 2
      expect_no_out
    done
    e_strict=
    t "$sc: userConfig strict fails closed"
    e_opt=true
    run gate-read
    expect_rc 2
    expect_no_out
    e_opt=
    t "$sc: no planted engine, cargo build or other platform's binary runs"
    expect_not_ran safe-ai-skill
    expect_not_ran cargo
    for p in $decoys; do expect_not_ran "safe-ai-skill-$p"; done
  done

  # Engine crash (signal, or exit not in {0,2,3}): the Solana and MCP gates block.
  for sc in exit:1 exit:101 exit:139 kill; do
    fresh
    engine "$bin_dir/safe-ai-skill-linux-x64" "$sc"
    t "crash $sc: gate-bash blocks"
    run gate-bash
    expect_rc 2
    expect_no_out
    expect_err_has crashed
    t "crash $sc: gate-mcp blocks"
    run gate-mcp
    expect_rc 2
    expect_no_out
    expect_err_has crashed
    t "crash $sc: gate-read continues and drops the engine's stdout"
    run gate-read
    expect_rc 0
    expect_no_out
    expect_err_has crashed
    t "crash $sc: redact and SessionStart continue"
    run redact
    expect_rc 0
    expect_no_out
    run verify session
    expect_rc 0
    expect_no_out
    expect_err_has 'verify session skipped'
    t "crash $sc: SAFE_AI_SKILL_STRICT=1 fails closed"
    e_strict=1
    run gate-read
    expect_rc 2
    expect_no_out
    e_strict=
    t "crash $sc: a CLI command keeps the engine's status"
    case $sc in
      exit:*) want=${sc#exit:} ;;
      *) want=137 ;;
    esac
    run status
    expect_rc "$want"
  done

  # SAFE_AI_SKILL_DISABLE=1 (exact) turns the hooks off; SessionStart says so.
  fresh
  engine "$bin_dir/safe-ai-skill-linux-x64" ok
  e_disable=1
  t "SAFE_AI_SKILL_DISABLE=1 silences every gate"
  for args in gate-read gate-bash gate-mcp gate-bash-secrets redact prompt-guard; do
    run $args
    expect_rc 0
    expect_no_out
    expect_no_err
  done
  t "SAFE_AI_SKILL_DISABLE=1 is reported at SessionStart"
  run verify session
  expect_rc 0
  expect_notice INACTIVE
  expect_notice SAFE_AI_SKILL_DISABLE
  expect_not_ran safe-ai-skill-linux-x64
  t "SAFE_AI_SKILL_DISABLE=1 leaves CLI commands working"
  run status
  expect_rc 0
  expect_ran safe-ai-skill-linux-x64
  fresh
  u_s=SunOS
  e_disable=1
  t "SAFE_AI_SKILL_DISABLE=1 is silent on an unsupported platform too"
  run gate-read
  expect_rc 0
  expect_no_out
  expect_no_err
  for v in 0 true yes ' 1' '1 '; do
    fresh
    engine "$bin_dir/safe-ai-skill-linux-x64" ok
    e_disable=$v
    t "SAFE_AI_SKILL_DISABLE='$v' does not disable"
    run gate-read
    expect_rc 0
    expect_ran safe-ai-skill-linux-x64
  done
  fresh
  engine "$bin_dir/safe-ai-skill-linux-x64" ok
  e_disable=1
  e_strict=1
  t "SAFE_AI_SKILL_STRICT=1 overrides SAFE_AI_SKILL_DISABLE=1"
  run gate-read
  expect_rc 0
  expect_ran safe-ai-skill-linux-x64

  # uname output lands in JSON; hostile characters must not break it.
  fresh
  u_s='Evil"OS'\\
  u_m='x"86'\\
  t "a hostile uname still yields valid JSON"
  run gate-bash
  expect_rc 0
  expect_ask
  run verify session
  expect_rc 0
  expect_notice INACTIVE

  fresh ' with spaces'
  engine "$bin_dir/safe-ai-skill-linux-x64" ok
  t "a plugin path with spaces still dispatches"
  run gate-read
  expect_rc 0
  expect_ran safe-ai-skill-linux-x64
  fresh
  engine "$bin_dir/safe-ai-skill-linux-x64" ok
  bare=1
  t "the shim finds its prebuilt when run by bare name"
  run gate-read
  expect_rc 0
  expect_ran safe-ai-skill-linux-x64

  fresh
  t "a failed probe is not cached: the next run sees a newly installed prebuilt"
  run gate-read
  expect_rc 0
  expect_err_lines 1
  engine "$bin_dir/safe-ai-skill-linux-x64" ok
  run gate-read
  expect_rc 0
  expect_ran safe-ai-skill-linux-x64

  fresh
  engine "$bin_dir/safe-ai-skill-linux-x64" ok
  t "the prebuilt runs, never the data-dir engine"
  run gate-read
  expect_rc 0
  expect_ran safe-ai-skill-linux-x64
  expect_not_ran safe-ai-skill

  # Every subcommand hooks.json wires up gets hook semantics, not CLI semantics.
  while IFS= read -r args; do
    fresh
    u_s=SunOS
    t "hooks.json '$args' fails open on an unsupported platform"
    run $args
    expect_rc 0
    case $args in
      gate-bash) expect_ask ;;
      'verify session') expect_notice INACTIVE ;;
      *) expect_no_out ;;
    esac
  done <"$work/hook-commands"
}

sh_name=hooks.json
t "hooks.json wires onFailure: block on the Solana entries, continue elsewhere"
check
"$py" -I - "$hooks_json" "$work/hook-commands" <<'EOF' || fail "see above"
import json, re, sys

cfg = json.load(open(sys.argv[1]))
prefix = '"${CLAUDE_PLUGIN_ROOT}"/bin/safe-ai-skill '
solana = re.compile(r"Bash\((solana|spl-token|anchor) \*\)")
problems, commands, blocking = [], set(), 0
for event, groups in cfg["hooks"].items():
    for group in groups:
        for hook in group["hooks"]:
            cmd = hook["command"]
            if not cmd.startswith(prefix):
                problems.append(f"{event}: unexpected command {cmd!r}")
                continue
            commands.add(cmd[len(prefix):])
            want = "block" if solana.fullmatch(hook.get("if", "")) else "continue"
            blocking += want == "block"
            if want == "block" and cmd[len(prefix):] != "gate-bash":
                problems.append(f"{event}: {hook['if']} must run gate-bash, runs {cmd!r}")
            if hook.get("onFailure") != want:
                problems.append(
                    f"{event} {cmd[len(prefix):]!r} if={hook.get('if')!r}: "
                    f"onFailure={hook.get('onFailure')!r}, want {want!r}"
                )
if blocking != 3:
    problems.append(f"{blocking} Solana entries, want 3")
with open(sys.argv[2], "w") as out:
    out.write("".join(c + "\n" for c in sorted(commands)))
for p in problems:
    print("  " + p)
sys.exit(1 if problems else 0)
EOF

for sh_name in sh dash bash busybox; do
  if ! command -v "$sh_name" >/dev/null 2>&1; then
    echo "skip: $sh_name not installed"
    continue
  fi
  case $sh_name in
    bash) sh_cmd='bash --posix' ;;
    busybox) sh_cmd='busybox sh' ;;
    *) sh_cmd=$sh_name ;;
  esac
  before=$fails
  matrix
  echo "$sh_cmd: $((fails - before)) failed"
done

sh_name=direct
sh_cmd=direct
fresh
engine "$bin_dir/safe-ai-skill-linux-x64" ok
t "the shim runs through its own shebang"
run gate-read
expect_rc 0
expect_ran safe-ai-skill-linux-x64
fresh
u_s=SunOS
t "the shebang path fails open with ask too"
run gate-bash
expect_rc 0
expect_ask

echo "test-shim: $checks checks, $fails failed"
[ "$fails" -eq 0 ] || exit 1
