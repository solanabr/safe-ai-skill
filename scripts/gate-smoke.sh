#!/bin/sh
# gate-smoke.sh — the engine's hard guards hold on this platform (release.yml and ci.yml
# run it on the Windows build; it works on any platform).
#
#   sh scripts/gate-smoke.sh <engine-binary>
#
# gate-bash on a mainnet `solana program deploy --final` must deny or ask, and gate-read on
# an SSH private key under an isolated home must deny (credential stores are denied at the
# default tier; a project `.env` is readable below High since 1.2.0, so it is not used).
# Exits 1 otherwise.

set -u

if [ $# -ne 1 ]; then
  echo "usage: gate-smoke.sh <engine-binary>" >&2
  exit 2
fi
bin=$1
work=$(mktemp -d "${TMPDIR:-/tmp}/gate-smoke.XXXXXX") || exit 2
trap 'rm -rf "$work"' EXIT
# Forward slashes on Windows (Git Bash), so the path is JSON-safe there too.
cwd=$(cd "$work" && { pwd -W 2>/dev/null || pwd; })
# Every state location lives under $work, in native form on Windows: the engine must not
# fall back to (and create) %LOCALAPPDATA%\safe-ai-skill-data, which later sessions and the
# engine test suite report as a stray data dir.
mkdir -p "$work/data"
CLAUDE_PLUGIN_DATA=$cwd/data
SAFE_AI_SKILL_DATA=$cwd/data
LOCALAPPDATA=$cwd/data
XDG_DATA_HOME=$cwd/data
export CLAUDE_PLUGIN_DATA SAFE_AI_SKILL_DATA LOCALAPPDATA XDG_DATA_HOME
# Isolated home (HOME for POSIX, USERPROFILE for native Windows) holding a dummy key.
mkdir -p "$work/home/.ssh"
printf '%s\n' '-----BEGIN OPENSSH PRIVATE KEY-----' 'dummy' '-----END OPENSSH PRIVATE KEY-----' \
  >"$work/home/.ssh/id_ed25519"
home=$(cd "$work/home" && { pwd -W 2>/dev/null || pwd; })
HOME=$work/home
USERPROFILE=$home
export HOME USERPROFILE
unset SAFE_AI_SKILL_PROFILE SAFE_AI_SKILL_DISABLE CLAUDE_PROJECT_DIR

fails=0
# expect <want-regex> <subcommand> <payload>
expect() {
  out=$(printf '%s' "$3" | "$bin" "$2" | tr -d '\r')
  decision=$(printf '%s' "$out" | sed -n 's/.*"permissionDecision":"\([a-z]*\)".*/\1/p')
  if printf '%s\n' "$decision" | grep -Eqx "$1"; then
    echo "ok - $2: $decision"
  else
    echo "not ok - $2: got '${decision:-no decision}', want $1; output: $out"
    fails=$((fails + 1))
  fi
}

expect 'deny|ask' gate-bash \
  '{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"'"$cwd"'","tool_input":{"command":"solana program deploy --final --url mainnet-beta target/deploy/x.so"}}'
expect 'deny' gate-read \
  '{"hook_event_name":"PreToolUse","tool_name":"Read","cwd":"'"$cwd"'","tool_input":{"file_path":"'"$home"'/.ssh/id_ed25519"}}'

[ "$fails" -eq 0 ]
