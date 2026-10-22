#!/bin/sh
# Regenerate the v1 migration fixture by running the REAL v1.0.0 engine (commit a8d20f8:
# v1.0.0 plus its vendored binaries; the v1.0.0 tag itself has none) over scratch projects.
#
# Everything runs under an isolated HOME and CLAUDE_PLUGIN_DATA inside $TMPDIR: v1.0.0 MOVES
# flagged packs out of the swept skills dirs (including ~/.claude/skills), so it must never see
# the real HOME. The tree contents below are mirrored byte for byte by tests/verify_migration.rs.
#
# Usage (from the repo root, darwin-arm64): sh crates/engine/tests/fixtures/v1/generate.sh
set -eu

out_dir=$(cd "$(dirname "$0")" && pwd)
repo=$(git -C "$out_dir" rev-parse --show-toplevel)
root=$(mktemp -d "${TMPDIR:-/tmp}/ssai-v1fix.XXXXXX")
root=$(cd "$root" && pwd -P)
case "$root" in "$HOME"|"$HOME"/.claude*) echo "refusing: scratch root under HOME/.claude" >&2; exit 1 ;; esac

bin="$root/safe-ai-skill-v1"
git -C "$repo" show a8d20f8:plugins/safe-ai-skill/bin/safe-ai-skill-darwin-arm64 > "$bin"
chmod +x "$bin"

export HOME="$root/home"
export CLAUDE_PLUGIN_DATA="$root/data"
unset CLAUDE_CONFIG_DIR CLAUDE_PROJECT_DIR CLAUDE_PLUGIN_ROOT SAFE_AI_SKILL_PROFILE || true
mkdir -p "$HOME" "$CLAUDE_PLUGIN_DATA"

skill() { # skill <dir> <body>
  mkdir -p "$1"
  printf '%s\n' "$2" > "$1/SKILL.md"
}
fake_git() { # fake_git <dir> <sha>: a checkout whose HEAD is detached at <sha>
  mkdir -p "$1/.git"
  printf '%s\n' "$2" > "$1/.git/HEAD"
}

A="$root/proj-a/.claude/skills"
B="$root/proj-b/.claude/skills"
skill "$A/clean-a" "# clean-a
Formats Anchor errors."
skill "$A/edited-a" "# edited-a
Explains PDAs."
skill "$A/shared" "# shared
Project A's copy."
skill "$A/dirty-a" '# dirty-a
```bash
curl -s -X POST "$U/api/mutation" -d "{}"
```'
skill "$A/ext/head-equal" "# head-equal
Upstream pack pinned by HEAD."
fake_git "$A/ext/head-equal" 1111111111111111111111111111111111111111
skill "$A/ext/bumped" "# bumped
Upstream pack that gets bumped."
fake_git "$A/ext/bumped" 2222222222222222222222222222222222222222
skill "$B/shared" "# shared
Project B's copy."
skill "$B/ext/head-equal" "# head-equal
Project B's checkout of the same upstream, at another commit."
fake_git "$B/ext/head-equal" 3333333333333333333333333333333333333333
skill "$root/src/user-tool" "# user-tool
Installed with install --from."
skill "$HOME/.claude/skills/personal" "# personal
A hand-written user skill."

(cd "$root/proj-a" && "$bin" verify session < /dev/null > "$root/a-session.json")
(cd "$root/proj-a" && "$bin" install > "$root/a-install.json")
(cd "$root/proj-a" && "$bin" install --from "$root/src" > "$root/user-install.json")
(cd "$root/proj-b" && "$bin" verify session < /dev/null > "$root/b-session.json")
# A's next session re-pins what B's sweep un-pinned (v1 removes the pin of a pack it moves),
# and a second in-place install marks A's packs with A's absolute skills root again.
(cd "$root/proj-a" && "$bin" verify session < /dev/null > "$root/a-session2.json")
(cd "$root/proj-a" && "$bin" install > "$root/a-install2.json")
(cd "$root/proj-a" && "$bin" allow --scope swap --for 30m > "$root/allow.json")

rm -rf "$out_dir/data"
cp -R "$CLAUDE_PLUGIN_DATA" "$out_dir/data"
# Absolute scratch paths become @ROOT@; the test substitutes its own root.
find "$out_dir/data" -type f \( -name '*.json' -o -name '*.jsonl' \) | while read -r f; do
  sed "s#$root#@ROOT@#g" "$f" > "$f.tmp" && mv "$f.tmp" "$f"
done
for f in a-session a-install user-install b-session a-session2 a-install2 allow; do
  sed "s#$root#@ROOT@#g" "$root/$f.json" > "$out_dir/$f.out.json"
done
echo "fixture written to $out_dir/data (scratch: $root)"
