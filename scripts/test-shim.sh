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
stamp_src=$PWD/scripts/stamp-shim.sh
hooks_json=$PWD/plugins/safe-ai-skill/hooks/hooks.json

py=$(python3 -I -c 'import sys; print(sys.executable)' 2>/dev/null) || {
  echo "test-shim: python3 is required for the JSON checks" >&2
  exit 1
}

work=$(mktemp -d "${TMPDIR:-/tmp}/test-shim.XXXXXX") || exit 1
trap 'rm -rf "$work"' EXIT
trap 'exit 1' HUP INT TERM

# The shim and the fakes read these; the caller's own values must not leak into the cases.
unset SAFE_AI_SKILL_STRICT SAFE_AI_SKILL_DISABLE SAFE_AI_SKILL_SHIM_CACHE CLAUDE_PROJECT_DIR \
  FAKE_UNAME_S FAKE_UNAME_M FAKE_MARKS FAKE_REAL_SHA

# The real platform, for the cases that run a native executable as the engine.
host_s=$(uname -s)
host_m=$(uname -m)
case $host_s/$host_m in
  Darwin/arm64) host_plat=darwin-arm64 ;;
  Darwin/x86_64) host_plat=darwin-x64 ;;
  Linux/x86_64) host_plat=linux-x64 ;;
  Linux/aarch64 | Linux/arm64) host_plat=linux-arm64 ;;
  *) host_plat= ;;
esac
native_true=
for d in /usr/bin /bin; do
  if [ -z "$native_true" ] && [ -f "$d/true" ]; then native_true=$d/true; fi
done

ALLOW='{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}'
DENY='{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"mainnet deploy"}}'
SESSION='{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"engine context"}}'
SESSION_MSG='{"systemMessage":"engine notice","hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"engine context"}}'
BLOCK='{"decision":"block","reason":"redacted text"}'
REWRITE='{"hookSpecificOutput":{"hookEventName":"PreToolUse","updatedInput":{"include":"!{**/.env}"}}}'
payload=$work/payload
printf '%s\n' '{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"README.md"}}' >"$payload"
payload_text=$(cat "$payload")
solana_payload=$work/solana-payload
printf '%s\n' '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"solana transfer X 1 -um"}}' >"$solana_payload"
big_in=$work/big-in
dd if=/dev/zero bs=1024 count=200 2>/dev/null | tr '\000' x >"$big_in"
nul_in=$work/nul-in
printf '{"a":"\000"}\n' >"$nul_in"
big_out=$work/big-out
dd if=/dev/zero bs=1024 count=200 2>/dev/null | tr '\000' y >"$big_out"

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

# PATH dirs for the sha256-tool cases: the tools the shim needs except any sha256 tool, a
# shasum that records it ran (and hashes with the host's tool), and a sha256sum that fails.
minbin=$work/minbin
mkdir "$minbin"
for tool in od mktemp rm cat grep sleep; do
  tool_path=$(command -v "$tool") && ln -s "$tool_path" "$minbin/$tool"
done
if command -v sha256sum >/dev/null 2>&1; then
  FAKE_REAL_SHA="$(command -v sha256sum)"
else
  FAKE_REAL_SHA="$(command -v shasum) -a 256"
fi
export FAKE_REAL_SHA
shasum_dir=$work/shasum-only
broken_sha_dir=$work/broken-sha
mkdir "$shasum_dir" "$broken_sha_dir"
# shellcheck disable=SC2016 # expands when the fake runs
printf '#!/bin/sh\n: >"$FAKE_MARKS/shasum"\n[ "$*" = "-a 256" ] || exit 1\nexec $FAKE_REAL_SHA\n' \
  >"$shasum_dir/shasum"
printf '#!/bin/sh\nexit 1\n' >"$broken_sha_dir/sha256sum"
# A sha256sum that records it ran, for the verified-hash cache cases (PATH keeps the host's
# stat and date).
rec_sha_dir=$work/rec-sha
mkdir "$rec_sha_dir"
# shellcheck disable=SC2016 # expands when the fake runs
printf '#!/bin/sh\n: >"$FAKE_MARKS/sha"\nexec $FAKE_REAL_SHA\n' >"$rec_sha_dir/sha256sum"
chmod +x "$shasum_dir/shasum" "$broken_sha_dir/sha256sum" "$rec_sha_dir/sha256sum"

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
  stale=1
  case $2 in
    ok) mk "$1" 'printf "ran=%s args=%s stdin=%s" "${0##*/}" "$*" "$(cat)"' ;;
    silent) mk "$1" ':' ;;
    session) mk "$1" "printf '%s' '$SESSION'" ;;
    sessionmsg) mk "$1" "printf '%s' '$SESSION_MSG'" ;;
    bytes) mk "$1" "printf 'line1\\n\\nline3\\n\\n'" ;;
    cksum) mk "$1" 'cksum' ;;
    bigout) mk "$1" "cat '$big_out'" ;;
    planted) mk "$1" "printf '%s' '$ALLOW'" ;;
    exit:*) mk "$1" "printf '%s' '$ALLOW'; echo 'engine stderr' >&2; exit ${2#exit:}" ;;
    kill) mk "$1" "printf '%s' '$ALLOW'; kill -s KILL \$\$" ;;
    badinterp) printf '#!/nonexistent/interpreter\necho ran\n' >"$1" && chmod +x "$1" ;;
    # No shebang and no binary magic: execve fails with ENOEXEC, and a shell that falls
    # back to running it as a script prints an allow verdict.
    garbage) printf '\001\002\003\004\necho %s\n' "'$ALLOW'" >"$1" && chmod +x "$1" ;;
    empty) : >"$1" && chmod +x "$1" ;;
    noexec) mk "$1" 'echo ran' && chmod -x "$1" ;;
    deny) mk "$1" "printf '%s\\n' '$DENY'" ;;
    deny2) mk "$1" "printf '%s\\n%s\\n' '$DENY' '$ALLOW'" ;;
    block) mk "$1" "printf '%s\\n' '$BLOCK'" ;;
    rewrite) mk "$1" "printf '%s\\n' '$REWRITE'" ;;
    # An ELF header, elf:<EI_CLASS>:<e_machine lo>:<e_machine hi> in octal, whose body, if a
    # shell ever ran the file as a script, would leave a mark.
    elf:*)
      IFS=: read -r _ cls m1 m2 <<EOT
$2
EOT
      # shellcheck disable=SC2059 # the format carries the header bytes
      printf "\\177ELF\\$cls\\001\\001\\000\\000\\000\\000\\000\\000\\000\\000\\000\\002\\000\\$m1\\$m2\\001\\000\\000\\000\\n" >"$1"
      printf '%s\n' ': >"$FAKE_MARKS/${0##*/}"' >>"$1"
      chmod +x "$1"
      ;;
  esac
}

# stamp: write the case's prebuilt hashes into its shim, as release.yml does.
stamp() {
  sh "$stamp_src" "$bin_dir" >/dev/null || fail "stamp-shim.sh failed"
  stale=
}

# fresh [<suffix>]: a new plugin layout with a planted data-dir engine, a crates/engine dir
# (so a cargo fallback, if any, would fire) and an empty project dir. Resets the case
# environment to Linux/x86_64 with the default hook payload.
n=0
fresh() {
  n=$((n + 1))
  case_dir=$work/case$n${1:-}
  bin_dir=$case_dir/plugins/safe-ai-skill/bin
  data_dir=$case_dir/data
  project_dir=$case_dir/project
  marks=$case_dir/marks
  mkdir -p "$bin_dir" "$data_dir/bin" "$project_dir/.claude" "$marks" "$case_dir/crates/engine"
  : >"$case_dir/crates/engine/Cargo.toml"
  cp "$shim_src" "$bin_dir/safe-ai-skill"
  # The test seam: the shim takes uname, od, grep and its sha256 tool from PATH, so the
  # fakes below apply. A case that tests the fixed system paths removes it.
  : >"$bin_dir/.sha-tools-from-path"
  chmod +x "$bin_dir/safe-ai-skill"
  engine "$data_dir/bin/safe-ai-skill" planted
  u_s=Linux
  u_m=x86_64
  u_fail=
  e_strict=
  e_disable=
  bare=
  payload_f=$payload
  no_stamp=
  e_path=
  e_tmpdir=
  e_nofake=
  e_cache=
  e_data=$data_dir
  stale=1
}

# launch <args...>: exec the case's shim under $sh_cmd in the case environment (by bare name
# from its own directory when $bare is set). Called in a subshell.
launch() {
  if [ -n "$e_nofake" ]; then PATH=${e_path:-$PATH}; else PATH=$fakebin:${e_path:-$PATH}; fi
  FAKE_MARKS=$marks
  CLAUDE_PLUGIN_DATA=$e_data
  CLAUDE_PROJECT_DIR=$project_dir
  FAKE_UNAME_M=$u_m
  export PATH FAKE_MARKS CLAUDE_PLUGIN_DATA CLAUDE_PROJECT_DIR FAKE_UNAME_M
  if [ -z "$u_fail" ]; then FAKE_UNAME_S=$u_s && export FAKE_UNAME_S; fi
  if [ -n "$e_strict" ]; then SAFE_AI_SKILL_STRICT=$e_strict && export SAFE_AI_SKILL_STRICT; fi
  if [ -n "$e_disable" ]; then SAFE_AI_SKILL_DISABLE=$e_disable && export SAFE_AI_SKILL_DISABLE; fi
  if [ -n "$e_tmpdir" ]; then TMPDIR=$e_tmpdir && export TMPDIR; fi
  if [ -n "$e_cache" ]; then SAFE_AI_SKILL_SHIM_CACHE=$e_cache && export SAFE_AI_SKILL_SHIM_CACHE; fi
  if [ -z "$e_data" ]; then unset CLAUDE_PLUGIN_DATA; fi
  if [ "$sh_cmd" = direct ]; then exec "$bin_dir/safe-ai-skill" "$@"; fi
  # shellcheck disable=SC2086 # sh_cmd is one shell or two words, e.g. "bash --posix"
  if [ -n "$bare" ]; then cd "$bin_dir" && exec $sh_cmd safe-ai-skill "$@"; fi
  # shellcheck disable=SC2086 # as above
  exec $sh_cmd "$bin_dir/safe-ai-skill" "$@"
}

# run <args...>: run the case's shim with $payload_f on stdin, stamping it first unless
# $no_stamp. Sets rc; stdout and stderr land in $case_dir/out and $case_dir/err. The outer
# 2>/dev/null only swallows this shell's own "Killed" job notices.
run() {
  if [ -n "$stale" ] && [ -z "$no_stamp" ]; then stamp; fi
  (
    (launch "$@") <"$payload_f" >"$case_dir/out" 2>"$case_dir/err"
    exit $?
  ) 2>/dev/null
  rc=$?
}

# run_solana <args...>: run with a Bash payload naming solana (the Solana surface).
run_solana() {
  saved_payload=$payload_f
  payload_f=$solana_payload
  run "$@"
  payload_f=$saved_payload
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
expect_out() {
  check
  [ "$(cat "$case_dir/out")" = "$1" ] || fail "stdout <$(snippet "$case_dir/out")>, want <$1>"
}
expect_out_file() {
  check
  cmp -s "$1" "$case_dir/out" || fail "stdout <$(snippet "$case_dir/out")> differs from $1"
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
# expect_json <python expression>: stdout is one JSON value `d` for which it holds.
expect_json() {
  check
  "$py" -I -c '
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
assert eval("(" + sys.argv[2] + ")"), d
' "$case_dir/out" "$1" </dev/null 2>/dev/null ||
    fail "stdout <$(snippet "$case_dir/out")> fails: $(printf '%s' "$1" | tr -s '\n ' '  ')"
}
expect_ask() {
  expect_json 'list(d) == ["hookSpecificOutput"]
    and d["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    and d["hookSpecificOutput"]["permissionDecision"] == "ask"
    and "inactive" in d["hookSpecificOutput"]["permissionDecisionReason"]'
}
# expect_permission_deny <needle>: a PermissionRequest deny whose message contains <needle>.
expect_permission_deny() {
  expect_json 'list(d) == ["hookSpecificOutput"]
    and d["hookSpecificOutput"]["hookEventName"] == "PermissionRequest"
    and d["hookSpecificOutput"]["decision"]["behavior"] == "deny"
    and "'"$1"'" in d["hookSpecificOutput"]["decision"]["message"]'
}
# expect_config_block <needle>: a ConfigChange block whose reason contains <needle>.
expect_config_block() {
  expect_json 'list(d) == ["decision", "reason"]
    and d["decision"] == "block"
    and "'"$1"'" in d["reason"]'
}
# expect_notice <needle>: a SessionStart notice whose two texts both contain <needle>.
expect_notice() {
  expect_json "'$1' in d['systemMessage']
    and d['hookSpecificOutput']['hookEventName'] == 'SessionStart'
    and '$1' in d['hookSpecificOutput']['additionalContext']"
}
# expect_unique_keys: stdout is JSON with no key repeated in any object.
expect_unique_keys() {
  check
  "$py" -I -c '
import json, sys
def pairs(kv):
    keys = [k for k, _ in kv]
    assert len(keys) == len(set(keys)), keys
    return dict(kv)
json.load(open(sys.argv[1], encoding="utf-8"), object_pairs_hook=pairs)
' "$case_dir/out" </dev/null 2>/dev/null || fail "stdout <$(snippet "$case_dir/out")> repeats a key"
}
expect_tamper_ask() {
  expect_json 'list(d) == ["hookSpecificOutput"]
    and d["hookSpecificOutput"]["permissionDecision"] == "ask"
    and "sha256" in d["hookSpecificOutput"]["permissionDecisionReason"]'
}
expect_repo_note() {
  expect_json '"SAFE_AI_SKILL_DISABLE set by project settings" in d["systemMessage"]
    and "ignored" in d["systemMessage"]'
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
  # shellcheck disable=SC2086 # one word per platform
  for p in $decoys; do engine "$bin_dir/safe-ai-skill-$p" ok; done
}

expect_codex_deny() {
  expect_json 'list(d) == ["hookSpecificOutput"]
    and d["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    and d["hookSpecificOutput"]["permissionDecision"] == "deny"
    and d["hookSpecificOutput"]["permissionDecisionReason"].strip() != ""'
}
expect_codex_block() {
  expect_json 'sorted(d) == ["decision", "reason"] and d["decision"] == "block"
    and d["reason"].strip() != ""'
}

# Codex hooks (`adapt codex …`): Codex runs a call whose hook fails, so every failure is a
# deny (PreToolUse) or a block (the opt-in redaction), printed with exit 0.
codex_matrix() {
  for b in deny silent; do
    fresh
    engine "$bin_dir/safe-ai-skill-linux-x64" "$b"
    t "codex: an engine $b answer passes through"
    run adapt codex gate-bash
    expect_rc 0
    case $b in
      deny) expect_out "$DENY" ;;
      silent) expect_no_out ;;
    esac
    expect_ran safe-ai-skill-linux-x64
  done
  for b in ok planted deny2 garbage exit:1 exit:2 exit:3 exit:134 kill; do
    fresh
    engine "$bin_dir/safe-ai-skill-linux-x64" "$b"
    t "codex: engine $b denies with exit 0"
    run adapt codex gate-bash-secrets
    expect_rc 0
    expect_codex_deny
    fresh
    engine "$bin_dir/safe-ai-skill-linux-x64" "$b"
    t "codex redact: engine $b blocks with exit 0"
    run adapt codex redact --block-with-redaction
    expect_rc 0
    expect_codex_block
  done
  fresh
  engine "$bin_dir/safe-ai-skill-linux-x64" block
  t "codex redact: an engine block passes through"
  run adapt codex redact --block-with-redaction
  expect_rc 0
  expect_out "$BLOCK"
  for sc in missing sunos nouname exit127 noexec; do
    env_case "$sc"
    t "codex: $sc denies with exit 0"
    run adapt codex gate-mcp
    expect_rc 0
    expect_codex_deny
    t "codex session-start: $sc reports INACTIVE with the Codex effect"
    run adapt codex session-start
    expect_rc 0
    expect_notice INACTIVE
    expect_notice 'Codex hooks check is blocked'
  done
  fresh
  engine "$bin_dir/safe-ai-skill-linux-x64" deny
  stamp
  engine "$bin_dir/safe-ai-skill-linux-x64" planted
  no_stamp=1
  t "codex: a tampered engine never runs and denies"
  run adapt codex gate-tamper
  expect_rc 0
  expect_codex_deny
  expect_not_ran safe-ai-skill-linux-x64
  fresh
  engine "$bin_dir/safe-ai-skill-linux-x64" deny
  e_disable=1
  t "codex: SAFE_AI_SKILL_DISABLE=1 does not turn the Codex hooks off"
  run adapt codex gate-bash
  expect_rc 0
  expect_out "$DENY"
  expect_ran safe-ai-skill-linux-x64
  fresh
  engine "$bin_dir/safe-ai-skill-linux-x64" ok
  t "codex: a mistyped adapt entry denies"
  run adapt codx gate-bash
  expect_rc 0
  expect_codex_deny
  fresh
  engine "$bin_dir/safe-ai-skill-linux-x64" exit:3
  t "codex: a usage error says the hook entry is misconfigured"
  run adapt codex gate-bash
  expect_rc 0
  expect_json '"misconfigured" in d["hookSpecificOutput"]["permissionDecisionReason"]'
  env_case missing
  e_strict=1
  t "codex: strict still answers Codex with a deny"
  run adapt codex gate-bash
  expect_rc 0
  expect_codex_deny
}

# opencode hooks (`adapt opencode …`, run by the opencode plugin): the same deny JSON on
# every failure; nothing, one deny line or a gate-read rewrite passes through.
opencode_matrix() {
  for b in deny silent rewrite; do
    fresh
    engine "$bin_dir/safe-ai-skill-linux-x64" "$b"
    t "opencode: an engine $b answer passes through"
    run adapt opencode gate-read
    expect_rc 0
    case $b in
      deny) expect_out "$DENY" ;;
      silent) expect_no_out ;;
      rewrite) expect_out "$REWRITE" ;;
    esac
  done
  for b in ok planted deny2 garbage exit:1 exit:2 exit:3 exit:134 kill block; do
    fresh
    engine "$bin_dir/safe-ai-skill-linux-x64" "$b"
    t "opencode: engine $b denies with exit 0"
    run adapt opencode gate-bash
    expect_rc 0
    expect_codex_deny
  done
  env_case missing
  t "opencode: a missing engine denies with exit 0"
  run adapt opencode gate-tamper
  expect_rc 0
  expect_codex_deny
  fresh
  engine "$bin_dir/safe-ai-skill-linux-x64" deny
  e_disable=1
  t "opencode: SAFE_AI_SKILL_DISABLE=1 does not turn the opencode hooks off"
  run adapt opencode gate-bash
  expect_rc 0
  expect_out "$DENY"
}

# The verified-hash cache: a binary whose sha256 matched once is not rehashed while its
# fingerprint (dev, inode, size, mtime, ctime) and the stamped hash stay the same. Only a
# binary whose ctime predates the check is cached, so these cases age their engines first.
cache_matrix() {
  fresh
  engine "$bin_dir/safe-ai-skill-linux-x64" ok
  engine "$bin_dir/safe-ai-skill-windows-x64.exe" ok
  stamp
  : >"$bin_dir/.sha-tools-from-path"
  e_path=$rec_sha_dir:$PATH
  cache=$data_dir/shim-verified-linux-x64
  sleep 2

  t "cache: a first run hashes the prebuilt and records it, mode 0600"
  run gate-read
  expect_rc 0
  expect_ran sha
  expect_ran safe-ai-skill-linux-x64
  check
  if [ ! -f "$cache" ] || [ -L "$cache" ]; then fail "no cache file at $cache"; fi
  check
  mode=$(stat -c %A "$cache" 2>/dev/null || stat -f %Sp "$cache" 2>/dev/null)
  case $mode in
    -rw-------) ;;
    *) fail "cache mode is $mode, want -rw-------" ;;
  esac
  check
  [ -z "$(find "$data_dir" -name '.shim-verified-*')" ] || fail "a temp file was left behind"

  rm -f "$marks"/*
  t "cache: a second run skips the hash"
  run gate-read
  expect_rc 0
  expect_out "ran=safe-ai-skill-linux-x64 args=gate-read stdin=$payload_text"
  expect_not_ran sha
  expect_ran safe-ai-skill-linux-x64

  for off in 0 envset; do
    rm -f "$marks"/*
    if [ "$off" = 0 ]; then e_cache=0; else e_data=; fi
    t "cache: off ($off) hashes on every call"
    run gate-read
    expect_rc 0
    expect_ran sha
    expect_ran safe-ai-skill-linux-x64
    e_cache=
    e_data=$data_dir
  done

  good=$(cat "$cache")
  for bad in hash perm symlink garbage empty; do
    case $bad in
      hash) printf '%s\n' "$good" | sed 's/ [0-9a-f]\{64\} / 0000000000000000000000000000000000000000000000000000000000000000 /' >"$cache" ;;
      perm) chmod 644 "$cache" ;;
      symlink) rm -f "$cache" && printf '%s\n' "$good" >"$cache.real" &&
        chmod 600 "$cache.real" && ln -s "$cache.real" "$cache" ;;
      garbage) printf 'v1 junk\n' >"$cache" ;;
      empty) : >"$cache" ;;
    esac
    rm -f "$marks"/*
    t "cache: a $bad cache is not trusted"
    run gate-read
    expect_rc 0
    expect_ran sha
    expect_ran safe-ai-skill-linux-x64
    check
    if [ "$bad" = symlink ]; then
      [ -L "$cache" ] || fail "the symlinked cache was replaced"
      rm -f "$cache" "$cache.real"
      run gate-read
    else
      [ "$(cat "$cache")" = "$good" ] || fail "the cache was not rewritten after the rehash"
    fi
    check
    case $(ls -l "$cache" 2>/dev/null) in
      -rw-------*) ;;
      *) fail "cache mode after rewrite is not -rw-------" ;;
    esac
  done

  t "cache: a rewritten prebuilt is rehashed and caught despite the cache"
  no_stamp=1
  cp -p "$bin_dir/safe-ai-skill-linux-x64" "$case_dir/ref"
  engine "$bin_dir/safe-ai-skill-linux-x64" planted
  touch -r "$case_dir/ref" "$bin_dir/safe-ai-skill-linux-x64"
  rm -f "$marks"/*
  run gate-bash
  expect_rc 2
  expect_ran sha
  expect_not_ran safe-ai-skill-linux-x64
  check
  [ "$(cat "$cache")" = "$good" ] || fail "a failed check changed the cache"

  t "cache: a prebuilt swapped in by rename is rehashed and caught"
  cp -p "$case_dir/ref" "$bin_dir/safe-ai-skill-linux-x64"
  run gate-read
  expect_rc 0
  cp -p "$bin_dir/safe-ai-skill-linux-x64" "$case_dir/swap"
  engine "$case_dir/swap" planted
  touch -r "$case_dir/ref" "$case_dir/swap"
  mv -f "$case_dir/swap" "$bin_dir/safe-ai-skill-linux-x64"
  rm -f "$marks"/*
  run gate-bash
  expect_rc 2
  expect_ran sha
  expect_not_ran safe-ai-skill-linux-x64

  # Deterministic only when the rewrite and the run share one wall-clock second.
  t "cache: a prebuilt changed within the check's second is not cached"
  same=
  for _ in 1 2 3 4 5; do
    s0=$(date +%s)
    engine "$bin_dir/safe-ai-skill-linux-x64" ok
    rm -f "$cache"
    run gate-read
    if [ "$s0" = "$(date +%s)" ]; then
      same=1
      break
    fi
  done
  if [ -n "$same" ]; then
    expect_rc 0
    check
    [ ! -e "$cache" ] || fail "a just-changed prebuilt was cached"
  else
    echo "skip: could not run the shim within one second of rewriting the prebuilt"
  fi

  t "cache: Windows never caches (a user process can set ctime there)"
  u_s=MINGW64_NT-10.0-22631
  rm -f "$marks"/*
  run gate-read
  expect_rc 0
  expect_ran safe-ai-skill-windows-x64.exe
  check
  [ -z "$(find "$data_dir" -name 'shim-verified-windows*')" ] || fail "a Windows cache was written"
}

matrix() {
  codex_matrix
  opencode_matrix
  cache_matrix

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

  # A real native executable, so the ELF / Mach-O checks run and not only "#!".
  if [ -n "$native_true" ]; then
    fresh
    u_s=$host_s
    u_m=$host_m
    for p in darwin-arm64 darwin-x64 linux-x64 linux-arm64; do
      cp "$native_true" "$bin_dir/safe-ai-skill-$p"
    done
    stale=1
    t "a native $host_s/$host_m executable passes the format check and runs"
    check
    case $(od -A n -t x1 -N 2 "$native_true") in
      *23*21*) fail "$native_true is a script, not a native executable" ;;
    esac
    run gate-bash
    expect_rc 0
    expect_no_out
    expect_no_err
  else
    echo "skip: no native true to run as the engine"
  fi

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

  # Big and binary payloads cross the shim intact in both directions.
  fresh
  engine "$bin_dir/safe-ai-skill-linux-x64" cksum
  payload_f=$big_in
  t "a 200 KiB stdin reaches the engine byte for byte"
  run gate-read
  expect_rc 0
  expect_out "$(cksum <"$big_in")"
  payload_f=$nul_in
  t "a stdin with a NUL byte reaches the engine byte for byte"
  run gate-read
  expect_rc 0
  expect_out "$(cksum <"$nul_in")"
  fresh
  engine "$bin_dir/safe-ai-skill-linux-x64" bigout
  t "a 200 KiB engine stdout comes back byte for byte"
  run redact
  expect_rc 0
  expect_out_file "$big_out"

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
    t "$sc: gate-bash answers ask for a Solana command"
    run_solana gate-bash
    expect_rc 0
    expect_ask
    expect_err_lines 1
    t "$sc: gate-bash fails open for any other call"
    run gate-bash
    expect_rc 0
    expect_no_out
    expect_err_lines 1
    t "$sc: gate-skill answers ask"
    run gate-skill
    expect_rc 0
    expect_ask
    expect_err_lines 1
    t "$sc: gate-permission leaves the prompt to Claude Code"
    run_solana gate-permission
    expect_rc 0
    expect_no_out
    expect_err_lines 1
    t "$sc: session-end continues with one stderr line"
    run session-end
    expect_rc 0
    expect_no_out
    expect_err_lines 1
    t "$sc: gate-config lets the settings change through with one stderr line"
    run gate-config
    expect_rc 0
    expect_no_out
    expect_err_lines 1
    t "$sc: SessionStart reports the firewall INACTIVE"
    run verify session
    expect_rc 0
    expect_notice INACTIVE
    expect_err_lines 1
    case $sc in
      exit127 | exit126)
        t "$sc: SessionStart shows the start error to the user"
        expect_json "'could not start (exit ${sc#exit}) (engine stderr)' in d['systemMessage']"
        ;;
    esac
    # CLI output is live, so only the status and the notice are checked.
    t "$sc: a CLI command exits 1"
    run status
    expect_rc 1
    expect_err_has 'firewall inactive'
    t "$sc: SAFE_AI_SKILL_STRICT=1 fails closed"
    e_strict=1
    for args in gate-read gate-bash gate-mcp gate-config 'verify session'; do
      # shellcheck disable=SC2086 # 'verify session' is two arguments
      run $args
      expect_rc 2
      expect_no_out
    done
    t "$sc: SAFE_AI_SKILL_STRICT=1 denies a PermissionRequest (exit 2 is not honoured there)"
    run gate-permission
    expect_rc 0
    expect_permission_deny STRICT
    t "$sc: SAFE_AI_SKILL_STRICT=1 makes a CLI command exit 2"
    run status
    expect_rc 2
    expect_err_has 'firewall inactive'
    e_strict=
    t "$sc: no planted engine, cargo build or other platform's binary runs"
    expect_not_ran safe-ai-skill
    expect_not_ran cargo
    # shellcheck disable=SC2086 # one word per platform
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
    t "crash $sc: gate-skill blocks"
    run gate-skill
    expect_rc 2
    expect_no_out
    expect_err_has crashed
    t "crash $sc: gate-permission denies with exit 0"
    run gate-permission
    expect_rc 0
    expect_permission_deny crashed
    expect_err_has 'denied this request'
    t "crash $sc: gate-config blocks the settings change with exit 0"
    run gate-config
    expect_rc 0
    expect_config_block crashed
    expect_err_has 'blocked this settings change'
    t "crash $sc: session-end continues"
    run session-end
    expect_rc 0
    expect_no_out
    expect_err_has crashed
    t "crash $sc: gate-read continues and drops the engine's stdout"
    run gate-read
    expect_rc 0
    expect_no_out
    expect_err_has crashed
    t "crash $sc: redact continues"
    run redact
    expect_rc 0
    expect_no_out
    t "crash $sc: SessionStart reports the firewall INACTIVE"
    run verify session
    expect_rc 0
    expect_notice INACTIVE
    expect_err_has 'verify session skipped'
    t "crash $sc: SAFE_AI_SKILL_STRICT=1 fails closed"
    e_strict=1
    run gate-read
    expect_rc 2
    expect_no_out
    run verify session
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

  # SAFE_AI_SKILL_DISABLE=1 (exact) from the user turns the hooks off; SessionStart says so.
  fresh
  engine "$bin_dir/safe-ai-skill-linux-x64" ok
  e_disable=1
  t "SAFE_AI_SKILL_DISABLE=1 silences every gate"
  for args in gate-read gate-bash gate-mcp gate-bash-secrets redact prompt-guard; do
    run "$args"
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

  # A repo can't disable the firewall: DISABLE is ignored when the committed project
  # settings mention it, and honoured from the user's own settings.local.json.
  fresh
  engine "$bin_dir/safe-ai-skill-linux-x64" session
  e_disable=1
  printf '{"env":{"SAFE_AI_SKILL_DISABLE":"1"}}\n' >"$project_dir/.claude/settings.json"
  t "SAFE_AI_SKILL_DISABLE from the committed project settings is ignored"
  for args in gate-read gate-bash gate-mcp redact prompt-guard; do
    rm -f "$marks/safe-ai-skill-linux-x64"
    run "$args"
    expect_rc 0
    expect_ran safe-ai-skill-linux-x64
  done
  t "SessionStart adds the ignored-DISABLE notice to the engine's output"
  run verify session
  expect_rc 0
  expect_repo_note
  expect_json 'd["hookSpecificOutput"]["additionalContext"] == "engine context"'
  fresh
  engine "$bin_dir/safe-ai-skill-linux-x64" silent
  e_disable=1
  printf '{"env":{"SAFE_AI_SKILL_DISABLE":"1"}}\n' >"$project_dir/.claude/settings.json"
  t "SessionStart merges the ignored-DISABLE notice into the engine's systemMessage"
  engine "$bin_dir/safe-ai-skill-linux-x64" sessionmsg
  run verify session
  expect_rc 0
  expect_unique_keys
  expect_repo_note
  expect_json 'd["systemMessage"].startswith("safe-ai-skill: SAFE_AI_SKILL_DISABLE")
    and d["systemMessage"].endswith("engine notice")
    and d["hookSpecificOutput"]["additionalContext"] == "engine context"'
  for code in 2 3; do
    t "SessionStart names the ignored DISABLE on stderr when the engine exits $code"
    engine "$bin_dir/safe-ai-skill-linux-x64" "exit:$code"
    run verify session
    expect_rc "$code"
    expect_err_has 'SAFE_AI_SKILL_DISABLE set by project settings'
    expect_err_has 'engine stderr'
  done
  engine "$bin_dir/safe-ai-skill-linux-x64" silent
  t "SessionStart prints the ignored-DISABLE notice on its own when the engine is silent"
  run verify session
  expect_rc 0
  expect_repo_note
  expect_json 'd["hookSpecificOutput"]["hookEventName"] == "SessionStart"'
  fresh
  e_disable=1
  printf '{"env":{"SAFE_AI_SKILL_DISABLE":"1"}}\n' >"$project_dir/.claude/settings.json"
  t "an environment failure still names the ignored DISABLE at SessionStart"
  run verify session
  expect_rc 0
  expect_notice INACTIVE
  expect_repo_note
  fresh
  engine "$bin_dir/safe-ai-skill-linux-x64" ok
  e_disable=1
  printf '{"permissions":{"allow":[]}}\n' >"$project_dir/.claude/settings.json"
  printf '{"env":{"SAFE_AI_SKILL_DISABLE":"1"}}\n' >"$project_dir/.claude/settings.local.json"
  t "SAFE_AI_SKILL_DISABLE from the user's settings.local.json is honoured"
  run gate-read
  expect_rc 0
  expect_no_out
  expect_no_err
  run verify session
  expect_rc 0
  expect_notice INACTIVE
  expect_not_ran safe-ai-skill-linux-x64

  # uname output lands in JSON; hostile characters must not break it.
  fresh
  u_s='Evil"OS'\\
  u_m='x"86'\\
  t "a hostile uname still yields valid JSON"
  run_solana gate-bash
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

  # The prebuilt must match the sha256 stamped into the shim at release (D6.1). A mismatch
  # is tamper: the Solana and MCP gates block, PreToolUse gates ask, the rest continue.
  fresh
  engine "$bin_dir/safe-ai-skill-linux-x64" ok
  stamp
  engine "$bin_dir/safe-ai-skill-linux-x64" planted
  no_stamp=1
  t "tamper: gate-bash blocks a prebuilt that fails its sha256 check"
  run gate-bash
  expect_rc 2
  expect_no_out
  expect_err_has sha256
  t "tamper: gate-mcp blocks"
  run gate-mcp
  expect_rc 2
  expect_no_out
  t "tamper: gate-skill blocks"
  run gate-skill
  expect_rc 2
  expect_no_out
  t "tamper: gate-permission denies with exit 0"
  run gate-permission
  expect_rc 0
  expect_permission_deny sha256
  t "tamper: gate-config blocks the settings change with exit 0"
  run gate-config
  expect_rc 0
  expect_config_block sha256
  t "tamper: the other PreToolUse gates ask"
  for args in gate-read gate-bash-secrets; do
    run "$args"
    expect_rc 0
    expect_tamper_ask
  done
  t "tamper: non-PreToolUse hooks continue with one stderr line"
  for args in redact prompt-guard gate-prompt-expansion session-end; do
    run "$args"
    expect_rc 0
    expect_no_out
    expect_err_lines 1
  done
  t "tamper: SessionStart reports the firewall TAMPERED"
  run verify session
  expect_rc 0
  expect_notice TAMPERED
  t "tamper: a CLI command refuses to run"
  run status
  expect_rc 2
  expect_err_has sha256
  t "tamper: SAFE_AI_SKILL_STRICT=1 blocks every hook"
  e_strict=1
  for args in gate-read redact 'verify session'; do
    # shellcheck disable=SC2086 # 'verify session' is two arguments
    run $args
    expect_rc 2
    expect_no_out
  done
  e_strict=
  t "tamper: the mismatched prebuilt never runs"
  expect_not_ran safe-ai-skill-linux-x64

  fresh
  stamp
  engine "$bin_dir/safe-ai-skill-linux-x64" ok
  no_stamp=1
  t "a prebuilt planted where the release shipped none fails the sha256 check"
  run gate-bash
  expect_rc 2
  expect_not_ran safe-ai-skill-linux-x64

  fresh
  engine "$bin_dir/safe-ai-skill-linux-x64" ok
  : >"$bin_dir/.sha-tools-from-path"
  e_path=$shasum_dir:$minbin
  t "shasum -a 256 verifies the prebuilt when sha256sum is missing"
  run gate-read
  expect_rc 0
  expect_ran shasum
  expect_ran safe-ai-skill-linux-x64
  engine "$bin_dir/safe-ai-skill-linux-x64" planted
  no_stamp=1
  rm -f "$marks/safe-ai-skill-linux-x64"
  t "shasum also catches a mismatch"
  run gate-bash
  expect_rc 2
  expect_not_ran safe-ai-skill-linux-x64

  for tools in none broken; do
    fresh
    engine "$bin_dir/safe-ai-skill-linux-x64" ok
    : >"$bin_dir/.sha-tools-from-path"
    case $tools in
      none) e_path=$minbin ;;
      broken) e_path=$broken_sha_dir:$minbin ;;
    esac
    t "sha256 tool $tools: gate-read fails open with one stderr line"
    run gate-read
    expect_rc 0
    expect_no_out
    expect_err_lines 1
    expect_err_has sha256
    t "sha256 tool $tools: gate-bash answers ask"
    run_solana gate-bash
    expect_rc 0
    expect_ask
    t "sha256 tool $tools: SessionStart reports the firewall INACTIVE"
    run verify session
    expect_rc 0
    expect_notice INACTIVE
    t "sha256 tool $tools: SAFE_AI_SKILL_STRICT=1 fails closed"
    e_strict=1
    run gate-read
    expect_rc 2
    e_strict=
    t "sha256 tool $tools: the unverified prebuilt never runs"
    expect_not_ran safe-ai-skill-linux-x64
  done

  # A Linux prebuilt must be a 64-bit ELF for this machine (EI_CLASS 2, e_machine
  # 0x3e x86-64 / 0xb7 aarch64), else it is an environment failure.
  for spec in x86_64/linux-x64/elf:001:076:000 x86_64/linux-x64/elf:002:267:000 \
    aarch64/linux-arm64/elf:002:076:000; do
    fresh
    u_m=${spec%%/*}
    rest=${spec#*/}
    target=${rest%%/*}
    engine "$bin_dir/safe-ai-skill-$target" "${rest#*/}"
    t "$u_m: an ELF prebuilt with ${rest#*/} is an environment failure"
    run_solana gate-bash
    expect_rc 0
    expect_ask
    run gate-read
    expect_rc 0
    expect_err_lines 1
    expect_not_ran "safe-ai-skill-$target"
  done

  # Without the test seam the shim takes its sha256 tool from fixed system paths, so a PATH
  # without one still verifies the prebuilt.
  if [ -n "$host_plat" ] && { [ -x /usr/bin/sha256sum ] || [ -x /bin/sha256sum ] ||
    [ -x /sbin/sha256sum ] || [ -x /usr/bin/shasum ]; }; then
    fresh
    rm -f "$bin_dir/.sha-tools-from-path"
    engine "$bin_dir/safe-ai-skill-$host_plat" ok
    e_path=$minbin
    t "the sha256 tool comes from a fixed system path, not PATH"
    run gate-read
    expect_rc 0
    expect_ran "safe-ai-skill-$host_plat"
  fi

  # uname comes from a system dir: a PATH without uname, or with one that lies, can't pick
  # the platform or make the shim fail open.
  if [ -n "$host_plat" ] && { [ -x /usr/bin/uname ] || [ -x /bin/uname ]; }; then
    for how in missing lying; do
      fresh
      rm -f "$bin_dir/.sha-tools-from-path"
      for p in darwin-arm64 darwin-x64 linux-x64 linux-arm64; do
        engine "$bin_dir/safe-ai-skill-$p" ok
      done
      e_path=$minbin
      case $how in
        missing) e_nofake=1 ;;
        lying) u_s=SunOS && u_m=sun4v ;;
      esac
      t "a PATH with a $how uname still runs this host's prebuilt"
      run gate-read
      expect_rc 0
      expect_no_err
      expect_out "ran=safe-ai-skill-$host_plat args=gate-read stdin=$payload_text"
      run_solana gate-bash
      expect_rc 0
      expect_ran "safe-ai-skill-$host_plat"
    done
  fi

  # No uname in a system dir (simulated under the seam by a PATH without one) is an
  # environment failure under the usual contract, not a silent pass.
  fresh
  engine "$bin_dir/safe-ai-skill-linux-x64" ok
  e_nofake=1
  e_path=$minbin
  t "no uname: gate-read fails open with one stderr line naming uname"
  run gate-read
  expect_rc 0
  expect_no_out
  expect_err_lines 1
  expect_err_has uname
  t "no uname: gate-bash on the Solana surface asks"
  run_solana gate-bash
  expect_rc 0
  expect_ask
  t "no uname: gate-skill asks"
  run gate-skill
  expect_rc 0
  expect_ask
  t "no uname: gate-mcp gives no opinion"
  run gate-mcp
  expect_rc 0
  expect_no_out
  t "no uname: SessionStart reports the firewall INACTIVE"
  run verify session
  expect_rc 0
  expect_notice INACTIVE
  expect_notice uname
  t "no uname: a Codex hook denies"
  run adapt codex gate-bash
  expect_rc 0
  expect_codex_deny
  t "no uname: SAFE_AI_SKILL_STRICT=1 fails closed"
  e_strict=1
  run gate-read
  expect_rc 2
  e_strict=
  t "no uname: no prebuilt ran"
  expect_not_ran safe-ai-skill-linux-x64

  # Engine output never touches a file: a same-user process rewriting
  # $TMPDIR/safe-ai-skill.*/out can't turn a deny into an allow, and the shim creates no
  # temp files at all.
  fresh
  engine "$bin_dir/safe-ai-skill-linux-x64" deny
  e_tmpdir=$case_dir/tmp
  mkdir "$e_tmpdir"
  (
    while :; do
      for d in "$e_tmpdir"/safe-ai-skill.*; do
        if [ -d "$d" ]; then printf '%s' "$ALLOW" >"$d/out" 2>/dev/null; fi
      done
    done
  ) &
  writer=$!
  t "a background writer on \$TMPDIR/safe-ai-skill.*/out can't change the verdict"
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    run gate-bash
    expect_rc 0
    expect_out "$DENY"
  done
  kill "$writer" 2>/dev/null
  wait "$writer" 2>/dev/null
  t "the shim creates no temp files"
  for args in gate-read gate-mcp redact 'verify session'; do
    # shellcheck disable=SC2086 # 'verify session' is two arguments
    run $args
  done
  check
  leftovers=$(find "$e_tmpdir" -mindepth 1 | tr '\n' ' ')
  [ -z "$leftovers" ] || fail "temp files: $leftovers"

  # The ignored repo DISABLE is reported whatever the session check's exit code.
  fresh
  engine "$bin_dir/safe-ai-skill-linux-x64" exit:2
  e_disable=1
  printf '{"env":{"SAFE_AI_SKILL_DISABLE":"1"}}\n' >"$project_dir/.claude/settings.json"
  t "SessionStart names the ignored DISABLE on stderr when the engine exits 2"
  run verify session
  expect_rc 2
  expect_err_has 'SAFE_AI_SKILL_DISABLE set by project settings'

  # JSON escapes can spell the key without its plain text: any \u escape or SAFE_AI_SKILL
  # mention in the committed settings counts as the repo setting DISABLE.
  for body in '{"env":{"SAFE_AI_SKILL_DIS\u0041BLE":"1"}}' \
    '{"env":{"\u0053AFE_AI_SKILL_DISABLE":"1"}}' '{"env":{"SAFE_AI_SKILL_STRICT":"0"}}'; do
    fresh
    engine "$bin_dir/safe-ai-skill-linux-x64" ok
    e_disable=1
    printf '%s\n' "$body" >"$project_dir/.claude/settings.json"
    t "committed settings $body: SAFE_AI_SKILL_DISABLE is ignored"
    run gate-read
    expect_rc 0
    expect_ran safe-ai-skill-linux-x64
  done

  # Every subcommand hooks.json wires up gets hook semantics, not CLI semantics.
  while IFS= read -r args; do
    fresh
    u_s=SunOS
    t "hooks.json '$args' takes its hook contract on an unsupported platform"
    # shellcheck disable=SC2086 # 'verify session' is two arguments
    run_solana $args
    expect_rc 0
    case $args in
      gate-bash | gate-skill) expect_ask ;;
      'verify session') expect_notice INACTIVE ;;
      *) expect_no_out ;;
    esac
  done <"$work/hook-commands"
}

sh_name=hooks.json
t "hooks.json wires onFailure: block on the Bash gate-bash entry, the Skill gate and gate-permission, continue elsewhere"
check
"$py" -I - "$hooks_json" "$work/hook-commands" <<'EOF' || fail "see above"
import json, re, sys

cfg = json.load(open(sys.argv[1]))
prefix = '"${CLAUDE_PLUGIN_ROOT}"/bin/safe-ai-skill '
problems, commands, blocking = [], set(), 0
for event, groups in cfg["hooks"].items():
    for group in groups:
        for hook in group["hooks"]:
            cmd = hook["command"]
            if not cmd.startswith(prefix):
                problems.append(f"{event}: unexpected command {cmd!r}")
                continue
            commands.add(cmd[len(prefix):])
            sub = cmd[len(prefix):]
            # The Skill gate fails closed too: failing open would run a blocked pack's !`cmd`.
            skill = event == "PreToolUse" and group.get("matcher") == "Skill"
            if skill and sub != "gate-skill":
                problems.append(f"{event}: the Skill matcher must run gate-skill, runs {cmd!r}")
            # gate-bash runs for every Bash call (an `if` filter misses wrapped, quoted,
            # path-qualified, expansion and solana-keygen commands) and fails closed.
            solana_entry = sub == "gate-bash"
            # The PermissionRequest gate fails closed: a failure denies the request.
            permission = event == "PermissionRequest"
            if permission and sub != "gate-permission":
                problems.append(f"{event}: must run gate-permission, runs {cmd!r}")
            if sub == "gate-permission" and not permission:
                problems.append(f"{event}: gate-permission belongs on PermissionRequest only")
            # The shim answers gate-config with ConfigChange's own block (decision: block).
            if (sub == "gate-config") != (event == "ConfigChange"):
                problems.append(f"{event}: gate-config belongs on ConfigChange, and only it there")
            want = "block" if solana_entry or skill or permission else "continue"
            blocking += solana_entry
            if solana_entry and (group.get("matcher") != "Bash" or "if" in hook):
                problems.append(f"{event}: gate-bash must be an unconditional Bash entry")
            if hook.get("onFailure") != want:
                problems.append(
                    f"{event} {cmd[len(prefix):]!r} if={hook.get('if')!r}: "
                    f"onFailure={hook.get('onFailure')!r}, want {want!r}"
                )
if blocking != 1:
    problems.append(f"{blocking} gate-bash entries, want 1")
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
  # By absolute path: some cases run the shim with a PATH that lacks the shell.
  sh_path=$(command -v "$sh_name")
  # A busybox built with "prefer applets" runs its own uname even with PATH
  # emptied, so the mocked uname below can never take effect there.
  if [ "$sh_name" = busybox ] && busybox sh -c 'PATH=/nonexistent; uname' >/dev/null 2>&1; then
    echo "skip: busybox sh prefers its built-in applets (uname cannot be mocked)"
    continue
  fi
  case $sh_name in
    bash) sh_cmd="$sh_path --posix" ;;
    busybox) sh_cmd="$sh_path sh" ;;
    *) sh_cmd=$sh_path ;;
  esac
  before=$fails
  matrix
  echo "$sh_cmd: $((fails - before)) failed"
done

sh_name=stamp
t "the committed shim's sha256 constants match the committed prebuilts"
check
sh "$stamp_src" --check plugins/safe-ai-skill/bin >/dev/null 2>"$work/stamp-err" ||
  fail "$(cat "$work/stamp-err")"
fresh
engine "$bin_dir/safe-ai-skill-linux-x64" ok
stamp
t "stamp-shim.sh --check passes on a freshly stamped layout"
check
sh "$stamp_src" --check "$bin_dir" >/dev/null 2>&1 || fail "check failed"
engine "$bin_dir/safe-ai-skill-linux-x64" planted
t "stamp-shim.sh --check fails once a prebuilt changes"
check
if sh "$stamp_src" --check "$bin_dir" >/dev/null 2>&1; then fail "check passed"; fi

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
run_solana gate-bash
expect_rc 0
expect_ask

echo "test-shim: $checks checks, $fails failed"
[ "$fails" -eq 0 ] || exit 1
