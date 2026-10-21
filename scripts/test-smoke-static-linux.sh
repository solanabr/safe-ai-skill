#!/bin/sh
# test-smoke-static-linux.sh — tests for scripts/smoke-static-linux.sh. Fake
# readelf and docker go first on PATH, so this runs anywhere: no ELF tools, no
# docker daemon, no network. Run in CI by the package-checks job.
#
# Usage: test-smoke-static-linux.sh [path-to-smoke-script]

set -u

here="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
script="${1:-${here}/smoke-static-linux.sh}"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/smoke-test.XXXXXX")"
trap 'rm -rf "${tmp}"' EXIT INT TERM
stub="${tmp}/stub"
bin="${tmp}/dist/safe-ai-skill-linux-x64"
mkdir -p "${stub}" "${tmp}/dist"
: > "${bin}"
chmod +x "${bin}"

# readelf: FAKE_LINK=static|dynamic decides what -d and -V print.
cat > "${stub}/readelf" <<'EOF'
#!/bin/sh
case "$1" in
  -d)
    echo "Dynamic section at offset 0x1b0e30 contains 18 entries:"
    if [ "${FAKE_LINK}" = dynamic ]; then
      echo " 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]"
    else
      echo " 0x000000006ffffffb (FLAGS_1)            Flags: NOW PIE"
    fi ;;
  -V)
    if [ "${FAKE_LINK}" = dynamic ]; then
      echo "  0x0010:   Name: GLIBC_2.39  Flags: none  Version: 5"
    else
      echo "No version information found in this file."
    fi ;;
  *) exit 1 ;;
esac
EOF

# docker: `pull` succeeds; `run` logs its arguments, prints FAKE_OUT, exits FAKE_RC.
cat > "${stub}/docker" <<'EOF'
#!/bin/sh
case "$1" in
  pull) exit 0 ;;
  run)
    echo "$*" >> "${FAKE_LOG}"
    if [ "${FAKE_RC}" -ne 0 ]; then
      echo "version 'GLIBC_2.39' not found" >&2
    else
      printf '%s\n' "${FAKE_OUT}"
    fi
    exit "${FAKE_RC}" ;;
esac
EOF
chmod +x "${stub}/readelf" "${stub}/docker"

failures=0

fail() {
  echo "FAIL $1"
  failures=$((failures + 1))
}

# check <name> <expected exit> <link> <container stdout> <container exit> [smoke args...]
check() {
  name="$1" want="$2" link="$3" out="$4" rc="$5"
  shift 5
  : > "${tmp}/log"
  FAKE_LINK="${link}" FAKE_OUT="${out}" FAKE_RC="${rc}" FAKE_LOG="${tmp}/log" \
    PATH="${stub}:${PATH}" sh "${script}" "$@" > "${tmp}/out" 2>&1
  got=$?
  if [ "${got}" -eq "${want}" ]; then
    echo "PASS ${name}"
  else
    fail "${name}: expected exit ${want}, got ${got}"
    sed 's/^/    /' "${tmp}/out"
  fi
}

check static-and-runs 0 static "safe-ai-skill 1.0.1" 0 "${bin}" 1.0.1
grep -q -- '--network none' "${tmp}/log" || fail "containers must run with --network none"
grep -q -- ':/smoke:ro ' "${tmp}/log" || fail "the binary must be mounted read-only"
for image in alpine:3 debian:11 ubuntu:20.04; do
  grep -q " ${image} " "${tmp}/log" || fail "${image} not exercised"
done
check glibc-dynamic 1 dynamic "" 1 "${bin}" 1.0.1
check version-prints-hook-json 1 static '{"hookSpecificOutput":{"permissionDecision":"allow"}}' 0 "${bin}" 1.0.1
check wrong-version 1 static "safe-ai-skill 1.0.0" 0 "${bin}" 1.0.1
check container-exit-127 1 static "" 127 "${bin}" 1.0.1
check usage-error 2 static "" 0
check missing-binary 2 static "" 0 "${tmp}/dist/missing" 1.0.1

echo "failures=${failures}"
[ "${failures}" -eq 0 ]
