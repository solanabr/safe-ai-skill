#!/bin/sh
# check-versions.sh — assert the release version is identical across all
# distribution manifests. Run in CI and before tagging a release.
#
# Sources checked:
#   npm/package.json                              "version": "X"
#   crates/engine/Cargo.toml                      version = "X"
#   plugins/safe-ai-skill/.claude-plugin/plugin.json   "version": "X"
#   .claude-plugin/marketplace.json               "version": "X"
#   README.md                                     badge/version-X-blue
#
# Exits non-zero (and prints the offending values) if any disagree.

set -eu

cd "$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"

fail=0

# Extract the first "version" string value from a JSON file.
json_version() {
  grep -m1 '"version"' "$1" | sed 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/'
}

npm_v="$(json_version npm/package.json)"
cargo_v="$(grep -m1 '^version' crates/engine/Cargo.toml | sed 's/.*"\([^"]*\)".*/\1/')"
plugin_v="$(json_version plugins/safe-ai-skill/.claude-plugin/plugin.json)"
market_v="$(json_version .claude-plugin/marketplace.json)"
readme_v="$(grep -m1 'badge/version-' README.md | sed 's/.*badge\/version-\([0-9][^-]*\)-.*/\1/')"

printf '%-12s %s\n' "npm:"        "${npm_v}"
printf '%-12s %s\n' "cargo:"      "${cargo_v}"
printf '%-12s %s\n' "plugin:"     "${plugin_v}"
printf '%-12s %s\n' "marketplace:" "${market_v}"
printf '%-12s %s\n' "readme:"     "${readme_v}"

for v in "${cargo_v}" "${plugin_v}" "${market_v}" "${readme_v}"; do
  if [ "${v}" != "${npm_v}" ]; then
    fail=1
  fi
done

if [ -z "${npm_v}" ]; then
  echo "check-versions: could not parse npm version" >&2
  fail=1
fi

if [ "${fail}" -ne 0 ]; then
  echo "check-versions: VERSION MISMATCH — all manifests must agree." >&2
  exit 1
fi

echo "check-versions: OK — all manifests at ${npm_v}."
