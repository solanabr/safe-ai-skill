#!/bin/sh
# Compare a runner's results file against the shared conformance corpus and print the per-row
# divergences. It only reads files: it never executes the kit (or any other) code.
#
#   sh scripts/conformance-diff.sh [--column kit|plugin|combined] [--interim] [--allow-missing] \
#                                  [--show-missing] <results.jsonl>
#
# <results.jsonl> has one JSON object per line: {"id": "CL-2", "<column>": "----"} where the value
# is four verdict characters for Off Relaxed Medium High (D deny, A ask, L allow, - no opinion;
# ? = tier not asserted or not run). Other keys are ignored. The kit's runner emits the "kit"
# column, the engine runner (SHARED_CORPUS_RESULTS=<path>) emits "plugin".
#
#   --column      which corpus column to compare (default kit)
#   --interim     compare against expect.interim.<column> where a row has one (the state before
#                 the kit's M5), else the end-state column
#   --allow-missing  accept corpus rows the results file does not cover (a partial run); without
#                   it every uncovered row is a failure and is listed as MISSING
#   --show-missing  with --allow-missing, still list the uncovered rows
#
# CORPUS_DIR overrides policy/shared/corpus. A `?` on either side skips that tier.
# Exit 0: every corpus row compared, no divergence. Exit 1: any DIVERGE, UNKNOWN, MISSING (unless
# --allow-missing) or MALFORMED line (a line with no id, an id with no value for the column, a
# duplicate id), or no row compared at all (empty or garbage input). Exit 2: usage.
#
# The corpus is parsed with awk from its one-object-per-line, "expect" before "interim" layout
# (the generator and the kit runner both keep it); it is not a general JSON parser.
set -eu

column=kit
interim=0
show_missing=0
allow_missing=0
results=

while [ $# -gt 0 ]; do
  case $1 in
    --column)
      [ $# -ge 2 ] || { echo "conformance-diff: --column needs a value" >&2; exit 2; }
      column=$2
      shift 2
      ;;
    --interim)
      interim=1
      shift
      ;;
    --show-missing)
      show_missing=1
      shift
      ;;
    --allow-missing)
      allow_missing=1
      shift
      ;;
    -h | --help)
      sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    -*)
      echo "conformance-diff: unknown option $1" >&2
      exit 2
      ;;
    *)
      [ -z "$results" ] || { echo "conformance-diff: one results file only" >&2; exit 2; }
      results=$1
      shift
      ;;
  esac
done

case $column in
  kit | plugin | combined) ;;
  *) echo "conformance-diff: --column must be kit, plugin or combined" >&2; exit 2 ;;
esac
[ -n "$results" ] || { echo "usage: conformance-diff.sh [--column C] [--interim] [--allow-missing] [--show-missing] <results.jsonl>" >&2; exit 2; }
[ -f "$results" ] || { echo "conformance-diff: no such file: $results" >&2; exit 2; }

root=$(cd "$(dirname "$0")/.." && pwd)
corpus=${CORPUS_DIR:-$root/policy/shared/corpus}
[ -d "$corpus" ] || { echo "conformance-diff: no corpus directory: $corpus" >&2; exit 2; }

tmp=$(mktemp -d "${TMPDIR:-/tmp}/conformance-diff.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

# corpus -> id <TAB> expected <TAB> owner
awk -v column="$column" -v interim="$interim" '
  function field(s, key,    t) {
    if (match(s, "\"" key "\"[ \t]*:[ \t]*\"[^\"]*\"")) {
      t = substr(s, RSTART, RLENGTH)
      sub(/^[^:]*:[ \t]*"/, "", t)
      sub(/"$/, "", t)
      return t
    }
    return ""
  }
  {
    id = field($0, "id")
    if (id == "") next
    if (!match($0, "\"expect\"[ \t]*:[ \t]*\\{")) next
    body = substr($0, RSTART + RLENGTH)
    cut = index(body, "\"interim\"")
    end = (cut > 0) ? substr(body, 1, cut - 1) : body
    want = field(end, column)
    if (interim == 1 && cut > 0) {
      ibody = substr(body, cut)
      iv = field(ibody, column)
      if (iv != "") want = iv
    }
    if (want == "") next
    printf "%s\t%s\t%s\n", id, want, field(end, "owner")
  }
' "$corpus"/*.jsonl >"$tmp/corpus.tsv"

# results -> id <TAB> got; malformed lines go to malformed.txt
awk -v column="$column" -v bad="$tmp/malformed.txt" '
  function field(s, key,    t) {
    if (match(s, "\"" key "\"[ \t]*:[ \t]*\"[^\"]*\"")) {
      t = substr(s, RSTART, RLENGTH)
      sub(/^[^:]*:[ \t]*"/, "", t)
      sub(/"$/, "", t)
      return t
    }
    return ""
  }
  /^[ \t\r]*$/ { next }
  {
    id = field($0, "id")
    if (id == "") { printf "MALFORMED line %d: no id\n", NR >> bad; next }
    if (id in seen) { printf "MALFORMED %s: duplicate id (line %d)\n", id, NR >> bad; next }
    seen[id] = 1
    v = field($0, column)
    if (v == "") { printf "MALFORMED %s: no %s value (line %d)\n", id, column, NR >> bad; next }
    printf "%s\t%s\n", id, v
  }
' "$results" >"$tmp/results.tsv"
: >>"$tmp/malformed.txt"

rc=0
awk -F '\t' -v column="$column" -v show_missing="$show_missing" -v allow_missing="$allow_missing" '
  FNR == NR {
    want[$1] = $2
    owner[$1] = $3
    order[++n] = $1
    next
  }
  {
    got[$1] = $2
    seen[$1] = 1
  }
  END {
    diverge = 0; unknown = 0; missing = 0; matched = 0; skipped = 0
    for (id in seen) {
      if (!(id in want)) {
        printf "UNKNOWN %s (not in the corpus)\n", id
        unknown++
      }
    }
    for (i = 1; i <= n; i++) {
      id = order[i]
      if (!(id in seen)) {
        missing++
        if (allow_missing == 0 || show_missing == 1) printf "MISSING %s\n", id
        continue
      }
      w = want[id]; g = got[id]
      if (length(g) != 4) {
        printf "DIVERGE %s %s expected %s got \"%s\" (not four characters) owner=%s\n", id, column, w, g, owner[id]
        diverge++
        continue
      }
      bad = 0; checked = 0
      for (k = 1; k <= 4; k++) {
        a = substr(w, k, 1); b = substr(g, k, 1)
        if (a == "?" || b == "?") continue
        checked++
        if (a != b) bad = 1
      }
      if (bad) {
        printf "DIVERGE %s %s expected %s got %s owner=%s\n", id, column, w, g, owner[id]
        diverge++
      } else if (checked == 0) {
        skipped++
      } else {
        matched++
      }
    }
    printf "conformance-diff (%s): %d rows match, %d diverge, %d unknown, %d not asserted, %d missing from results\n", \
      column, matched, diverge, unknown, skipped, missing
    if (matched + diverge == 0) {
      print "conformance-diff: no corpus row was compared (empty or unusable results)"
      exit 1
    }
    exit (diverge > 0 || unknown > 0 || (missing > 0 && allow_missing == 0)) ? 1 : 0
  }
' "$tmp/corpus.tsv" "$tmp/results.tsv" || rc=$?

if [ -s "$tmp/malformed.txt" ]; then
  cat "$tmp/malformed.txt"
  rc=1
fi
exit "$rc"
