#!/bin/sh
# stamp-shim.sh — write each prebuilt's sha256 into the plugin shim's `sha256_<plat>=`
# constants (spec D6.1), or with --check, fail unless they already match.
#
#   sh scripts/stamp-shim.sh [--check] <bin-dir>
#
# <bin-dir> holds the shim (safe-ai-skill) and the prebuilts (safe-ai-skill-<plat>, .exe
# on Windows). A platform without a prebuilt gets an empty constant, which the shim treats
# as "no prebuilt shipped": a binary planted there later fails the check. release.yml runs
# this after vendoring the binaries and before regenerating SHA256SUMS, which hashes the
# stamped shim. A local engine build copied into bin/ must be stamped the same way, or the
# shim refuses to run it.

set -eu

check=
if [ "${1:-}" = --check ]; then
  check=1
  shift
fi
if [ $# -ne 1 ]; then
  echo "usage: stamp-shim.sh [--check] <bin-dir>" >&2
  exit 2
fi
dir=$1
shim=$dir/safe-ai-skill
if [ ! -f "$shim" ]; then
  echo "stamp-shim: no shim at $shim" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  hash_cmd='sha256sum'
elif command -v shasum >/dev/null 2>&1; then
  hash_cmd='shasum -a 256'
else
  echo "stamp-shim: needs sha256sum or shasum" >&2
  exit 1
fi

# The sha256 of <file>, or empty when it doesn't exist.
sha_of() {
  [ -f "$1" ] || return 0
  # shellcheck disable=SC2086 # hash_cmd is a command and its flags
  h=$($hash_cmd <"$1")
  h=${h%%[!0-9a-f]*}
  if [ "${#h}" -ne 64 ]; then
    echo "stamp-shim: could not hash $1" >&2
    exit 1
  fi
  printf '%s' "$h"
}

script=
bad=0
for plat in darwin-arm64 darwin-x64 linux-x64 linux-arm64 windows-x64; do
  ext=
  case $plat in windows-*) ext=.exe ;; esac
  var=sha256_$(printf '%s' "$plat" | tr - _)
  want=$(sha_of "$dir/safe-ai-skill-$plat$ext")
  count=$(grep -c "^$var=" "$shim" || true)
  if [ "$count" != 1 ]; then
    echo "stamp-shim: $shim has $count '$var=' lines, want 1" >&2
    exit 1
  fi
  if [ -n "$check" ]; then
    have=$(sed -n "s/^$var=//p" "$shim")
    if [ "$have" != "$want" ]; then
      echo "stamp-shim: $var is '$have', the binary hashes to '$want'" >&2
      bad=1
    fi
  fi
  script="$script
s/^$var=.*/$var=$want/"
done

if [ -n "$check" ]; then
  if [ "$bad" = 0 ]; then echo "stamp-shim: $shim constants match the prebuilts"; fi
  exit "$bad"
fi

tmp=$(mktemp "${TMPDIR:-/tmp}/stamp-shim.XXXXXX")
trap 'rm -f "$tmp"' EXIT
sed "$script" "$shim" >"$tmp"
# Rewrite in place so the shim keeps its mode.
cat "$tmp" >"$shim"
