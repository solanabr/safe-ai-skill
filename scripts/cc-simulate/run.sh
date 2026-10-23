#!/bin/sh
# run.sh — build the release engine (and a test-hooks release build, for the checks that need
# a trusted data dir), then run the simulator self-test and the eight live checks against both.
#
#   sh scripts/cc-simulate/run.sh [--kit DIR] [extra live_checks.py args]
#
# Builds into $TMPDIR, never touches ~/.claude, uses no network beyond cargo's own fetch.

set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
out=${CCSIM_TARGET:-${TMPDIR:-/tmp}/ccsim-target}
manifest=$root/crates/engine/Cargo.toml

cargo build --manifest-path "$manifest" --release --locked --target-dir "$out/rel"
cargo build --manifest-path "$manifest" --release --locked --features test-hooks \
  --target-dir "$out/th"

python3 -I -B "$root/scripts/cc-simulate/selftest.py"
echo "== release build (data dir untrusted)"
python3 -I -B "$root/scripts/cc-simulate/live_checks.py" \
  --engine "$out/rel/release/safe-ai-skill" "$@"
echo "== test-hooks release build (data dir trusted)"
python3 -I -B "$root/scripts/cc-simulate/live_checks.py" \
  --engine "$out/th/release/safe-ai-skill" --trusted "$@"
