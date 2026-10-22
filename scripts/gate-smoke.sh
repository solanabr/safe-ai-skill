#!/bin/sh
# gate-smoke.sh — the engine's hard guards hold on this platform (release.yml and ci.yml
# run it on the Windows build; it works on any platform).
#
#   sh scripts/gate-smoke.sh <engine-binary>
#
# gate-bash on a mainnet `solana program deploy --final` must deny or ask, and gate-read on
# a `.env` must deny. Exits 1 otherwise.

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
CLAUDE_PLUGIN_DATA=$work/data
export CLAUDE_PLUGIN_DATA
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
  '{"hook_event_name":"PreToolUse","tool_name":"Read","cwd":"'"$cwd"'","tool_input":{"file_path":"'"$cwd"'/.env"}}'

[ "$fails" -eq 0 ]
