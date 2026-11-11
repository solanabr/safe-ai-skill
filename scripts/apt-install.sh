#!/bin/sh
# apt-install.sh — install Ubuntu packages on a GitHub runner, and get through
# an outage of the runner's own Ubuntu mirror. On 2026-11-11 Canonical's DNS
# failed for about three hours, and with it `apt-get install musl-tools` on the
# ubuntu-24.04-arm runners, which know only ports.ubuntu.com. Every entry in
# the x64 runners' mirror list is under ubuntu.com too.
#
# Usage: sudo sh scripts/apt-install.sh <package>...
#
#   1. The runner's own sources, as they are: `apt-get update`, then
#      `apt-get install -y --no-install-recommends <package>...`.
#   2. If that install fails, the same install once more from FALLBACK below,
#      a mirror outside Canonical's domain, with the runner's sources left
#      out. Its list has a stock Ubuntu install's suites and components, so apt
#      picks the same versions. apt only trusts what the Ubuntu archive key
#      signed (signed-by), so the mirror can't change what gets installed.
#
# `apt-get update` exits 0 even when it fetched nothing, so the install's exit
# status decides. Used by ci.yml and release.yml.

set -eu

# MIT's mirror. It serves /ubuntu (amd64) and /ubuntu-ports (arm64 and the
# other ports) over https, and its DNS is not Canonical's.
FALLBACK=https://mirrors.mit.edu
KEYRING=/usr/share/keyrings/ubuntu-archive-keyring.gpg

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <package>..." >&2
  exit 2
fi
if [ "$(id -u)" -ne 0 ]; then
  echo "apt-install: run as root (sudo sh $0 $*)" >&2
  exit 2
fi

apt-get update || true
if apt-get install -y --no-install-recommends "$@"; then
  exit 0
fi

if [ ! -f "${KEYRING}" ]; then
  echo "apt-install: ${KEYRING} is missing, so the fallback mirror can't be verified" >&2
  exit 1
fi
# shellcheck source=/dev/null
codename="$(. /etc/os-release && echo "${VERSION_CODENAME}")"
case "$(dpkg --print-architecture)" in
  amd64 | i386) tree=ubuntu ;;
  *) tree=ubuntu-ports ;;
esac

echo "::warning::apt-install: the runner's Ubuntu mirror failed; installing $* from ${FALLBACK}/${tree}"
list="$(mktemp "${TMPDIR:-/tmp}/apt-install.XXXXXX")"
trap 'rm -f "${list}"' EXIT
for suite in "${codename}" "${codename}-updates" "${codename}-backports" "${codename}-security"; do
  echo "deb [signed-by=${KEYRING}] ${FALLBACK}/${tree} ${suite} main restricted universe multiverse"
done >"${list}"

# Only the fallback list (no sources.list.d), and the runner's index files stay.
fallback_apt() {
  apt-get -o "Dir::Etc::SourceList=${list}" -o Dir::Etc::SourceParts=/dev/null \
    -o APT::Get::List-Cleanup=0 "$@"
}
fallback_apt update || true
fallback_apt install -y --no-install-recommends "$@"
