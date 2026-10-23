#!/bin/sh
# Rewrite policy/shared/MANIFEST: the contract version, then one line per list file with its
# record count and the sha256 of its exact bytes (shared contract §1.4).
#
#   sh scripts/shared-manifest.sh [contract-version]
#
# The version defaults to the one already in MANIFEST. Bump it by hand: MAJOR when an entry is
# removed or semantics loosen, MINOR when entries are added, PATCH for comments/provenance.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
dir="$root/policy/shared"
files="credentials.list exfil-hosts.list onchain-verbs.list"

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# Records: every line that is not blank, a `#` comment or a `[section]` header.
records() {
  grep -cvE '^[[:space:]]*(#|\[|$)' "$1" || true
}

version=${1:-}
if [ -z "$version" ] && [ -f "$dir/MANIFEST" ]; then
  version=$(awk 'NR == 1 && $1 == "contract" { print $2 }' "$dir/MANIFEST")
fi
[ -n "$version" ] || { echo "shared-manifest: no contract version" >&2; exit 2; }

tmp="$dir/MANIFEST.tmp.$$"
{
  printf 'contract %s\n' "$version"
  for f in $files; do
    printf '%s %s sha256:%s\n' "$f" "$(records "$dir/$f")" "$(sha256 "$dir/$f")"
  done
} >"$tmp"
mv "$tmp" "$dir/MANIFEST"
cat "$dir/MANIFEST"
