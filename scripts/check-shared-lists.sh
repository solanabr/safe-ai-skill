#!/bin/sh
# Lint policy/shared (shared contract §1.1-§1.4): records sorted (LC_ALL=C) and unique within
# each [section], valid enums, lowercase hosts without scheme/port/trailing dot, no brace or
# character-class globs, no tabs, LF only, and MANIFEST counts and hashes matching the bytes.
#
#   sh scripts/check-shared-lists.sh
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
dir="$root/policy/shared"
fail=0

err() {
  echo "check-shared-lists: $*" >&2
  fail=1
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

for f in credentials.list exfil-hosts.list onchain-verbs.list MANIFEST; do
  [ -f "$dir/$f" ] || { err "missing $f"; continue; }
  if LC_ALL=C grep -q "$(printf '\t')" "$dir/$f"; then err "$f: tab character"; fi
  if LC_ALL=C grep -q "$(printf '\r')" "$dir/$f"; then err "$f: CR line ending"; fi
done
[ "$fail" = 0 ] || exit 1

# Sorted and unique within each section: print each section's records, then compare.
check_sorted() {
  file=$1
  awk -v out="${TMPDIR:-/tmp}/shared-lint.$$" '
    /^[[:space:]]*(#|$)/ { next }
    /^\[/ { n++; next }
    { print > (out "." n + 0) }
  ' "$dir/$file"
  for part in "${TMPDIR:-/tmp}"/shared-lint.$$.*; do
    [ -f "$part" ] || continue
    LC_ALL=C sort -c -u "$part" 2>/dev/null || err "$file: records not sorted (LC_ALL=C) and unique in a section"
    rm -f "$part"
  done
}

for f in credentials.list exfil-hosts.list onchain-verbs.list; do
  check_sorted "$f"
done

# credentials.list: class os sb glob (glob = rest of line). Braces only in the one variable.
bad=$(awk '
  /^[[:space:]]*(#|$)/ { next }
  /^\[/ { if ($0 !~ /^\[[a-z]+(:[A-Z_]+)?\]$/) print NR ": bad section"; next }
  {
    class = $1; sub(/^!/, "", class)
    if (class !~ /^(key_material|host_token|vault|browser_store|wallet_ext)$/) print NR ": class " $1
    if ($2 !~ /^(any|macos|linux|windows)$/) print NR ": os " $2
    if ($3 !~ /^(relaxed|medium|high|never)$/) print NR ": sb " $3
    glob = $0; sub(/^[^ ]+ +[^ ]+ +[^ ]+ +/, "", glob)
    if (glob == "" || NF < 4) print NR ": missing glob"
    rest = glob; gsub(/\$\{CLAUDE_CONFIG_DIR:-~\/\.claude\}/, "", rest)
    if (rest ~ /[{}\[\]]/) print NR ": brace or character class in glob"
    if (rest ~ /\$/) print NR ": variable other than CLAUDE_CONFIG_DIR"
    if (glob !~ /^(~\/|\/|\*\*\/|\$\{CLAUDE_CONFIG_DIR)/) print NR ": glob not anchored (~/, /, **/ or the variable)"
  }
' "$dir/credentials.list")
[ -z "$bad" ] || err "credentials.list: $bad"

bad=$(awk '
  /^[[:space:]]*(#|$)/ { next }
  /^\[/ { print NR ": sections not used"; next }
  {
    if (NF != 2) print NR ": expected tier host"
    if ($1 !~ /^(relaxed|medium|high)$/) print NR ": tier " $1
    h = $2
    if (h != tolower(h)) print NR ": host not lowercase"
    if (h ~ /\.$/ || h ~ /[:\/]/) print NR ": host has a scheme, port, path or trailing dot"
    if (h !~ /^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/) print NR ": host syntax " h
  }
' "$dir/exfil-hosts.list")
[ -z "$bad" ] || err "exfil-hosts.list: $bad"

bad=$(awk '
  /^[[:space:]]*(#|$)/ { next }
  /^\[/ { print NR ": sections not used"; next }
  {
    if ($1 !~ /^(irreversible|recoverable)$/) print NR ": class " $1
    if ($2 !~ /^(any|net)$/) print NR ": cluster " $2
    if (NF < 4) print NR ": expected a program and a verb"
    for (i = 3; i <= NF; i++) {
      t = $i
      if (t ~ /^\[/ && t !~ /^\[-[-a-z0-9]+\]$/) print NR ": bad [--flag] token " t
      if (t !~ /^\[/ && t ~ /[{}\[\]]/) print NR ": brace or character class in " t
    }
  }
' "$dir/onchain-verbs.list")
[ -z "$bad" ] || err "onchain-verbs.list: $bad"

# MANIFEST: contract line, then one line per file with the record count and hash.
manifest="$dir/MANIFEST"
head -n 1 "$manifest" | grep -qE '^contract [0-9]+\.[0-9]+\.[0-9]+$' || err "MANIFEST: line 1 must be 'contract X.Y.Z'"
for f in credentials.list exfil-hosts.list onchain-verbs.list; do
  want_n=$(grep -cvE '^[[:space:]]*(#|\[|$)' "$dir/$f" || true)
  want="$f $want_n sha256:$(sha256 "$dir/$f")"
  grep -qxF "$want" "$manifest" || err "MANIFEST: expected '$want' (run scripts/shared-manifest.sh)"
done
lines=$(wc -l <"$manifest" | tr -d ' ')
[ "$lines" = 4 ] || err "MANIFEST: expected 4 lines, found $lines"

if [ "$fail" = 0 ]; then
  echo "check-shared-lists: OK"
fi
exit "$fail"
