#!/bin/sh
# smoke-static-linux.sh — prove a Linux release binary is static and runs on
# other distributions. 1.0.0's linux-x64 binary needed GLIBC_2.39: on Ubuntu
# 22.04 and Debian 12 it exited 127, which Claude Code treats as a non-blocking
# hook error, so the firewall was silently off.
#
# Usage: smoke-static-linux.sh <binary> <expected-version>
#
# Fails unless:
#   1. `readelf -d` lists no NEEDED library and `readelf -V` no GLIBC_ version;
#   2. in alpine, debian:11 and ubuntu:20.04 containers (no network),
#      `<binary> --version` exits 0 and prints "safe-ai-skill <expected-version>".
#
# Needs readelf and docker (both on GitHub's Ubuntu runners). Used by ci.yml
# and release.yml.

set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <binary> <expected-version>" >&2
  exit 2
fi

bin="$1"
want="safe-ai-skill $2"
fail=0

if [ ! -f "${bin}" ] || [ ! -x "${bin}" ]; then
  echo "smoke: ${bin} is not an executable file" >&2
  exit 2
fi

dynamic="$(readelf -d "${bin}")"
case "${dynamic}" in
  *'(NEEDED)'*)
    echo "smoke: ${bin} needs shared libraries:" >&2
    printf '%s\n' "${dynamic}" | grep '(NEEDED)' >&2
    fail=1
    ;;
esac

versions="$(readelf -V "${bin}")"
case "${versions}" in
  *GLIBC_*)
    echo "smoke: ${bin} references glibc symbol versions" >&2
    fail=1
    ;;
esac

dir="$(CDPATH='' cd -- "$(dirname -- "${bin}")" && pwd)"
name="$(basename -- "${bin}")"

for image in alpine:3 debian:11 ubuntu:20.04; do
  docker pull -q "${image}" >/dev/null
  rc=0
  out="$(docker run --rm --network none -v "${dir}:/smoke:ro" "${image}" "/smoke/${name}" --version)" || rc=$?
  if [ "${rc}" -ne 0 ]; then
    echo "smoke: ${image}: ${name} --version exited ${rc}" >&2
    fail=1
  elif [ "${out}" != "${want}" ]; then
    echo "smoke: ${image}: expected '${want}', got '${out}'" >&2
    fail=1
  else
    echo "smoke: ${image}: ${out}"
  fi
done

exit "${fail}"
