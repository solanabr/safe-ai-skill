#!/bin/sh
# check-binary-versions.sh — assert every committed engine binary is the version the
# manifests declare. A required CI check: new hooks.json/shim must never reach main with
# older binaries (1.0.0 answers `allow` to subcommands it doesn't know, so the 1.0.1 hooks
# would fail open on it).
#
# Usage: check-binary-versions.sh [bin-dir] [expected-version]
#   bin-dir           default plugins/safe-ai-skill/bin
#   expected-version  default the version in plugins/safe-ai-skill/.claude-plugin/plugin.json
#
# The binary this host can run must print exactly "safe-ai-skill <version>" for --version.
# The others must embed that line (the engine keeps it as one literal); a binary built
# before 1.0.1 embeds no such line and fails.

set -eu

root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
bindir="${1:-${root}/plugins/safe-ai-skill/bin}"
expected="${2:-$(grep -m1 '"version"' "${root}/plugins/safe-ai-skill/.claude-plugin/plugin.json" |
  sed 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')}"
want="safe-ai-skill ${expected}"

case "$(uname -s)/$(uname -m)" in
  Darwin/arm64 | Darwin/aarch64) host=darwin-arm64 ;;
  Darwin/x86_64) host=darwin-x64 ;;
  Linux/x86_64 | Linux/amd64) host=linux-x64 ;;
  Linux/aarch64 | Linux/arm64) host=linux-arm64 ;;
  *) host= ;;
esac

fail=0
for p in darwin-arm64 darwin-x64 linux-x64 linux-arm64; do
  f="${bindir}/safe-ai-skill-${p}"
  if [ ! -f "${f}" ]; then
    echo "check-binary-versions: ${f} is missing" >&2
    fail=1
    continue
  fi
  if [ "${p}" = "${host}" ]; then
    got="$("${f}" --version 2>/dev/null)" || got="(--version failed)"
    how="runs"
  else
    # Every "safe-ai-skill X.Y.Z" in the file; -o takes the whole number, so 1.0.10 is
    # never read as 1.0.1.
    got="$(LC_ALL=C grep -a -o 'safe-ai-skill [0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*' "${f}" |
      grep -Fx "${want}" | head -n1)" || got=""
    how="embeds"
  fi
  if [ "${got}" = "${want}" ]; then
    echo "ok   safe-ai-skill-${p} ${how} '${want}'"
  else
    echo "FAIL safe-ai-skill-${p}: wanted '${want}' (${how}), got '${got:-nothing}'" >&2
    fail=1
  fi
done

if [ "${fail}" -ne 0 ]; then
  echo "check-binary-versions: committed binaries are not ${expected}. Vendor them with release.yml on release/v${expected} (docs/RELEASING.md)." >&2
  exit 1
fi
echo "check-binary-versions: OK — all binaries at ${expected}."
