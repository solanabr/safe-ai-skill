#!/bin/sh
# install.sh — standalone installer for the safe-ai-skill CLI
#
# Downloads the prebuilt safe-ai-skill binary for the current platform from the
# GitHub Release matching $SAFE_AI_SKILL_VERSION (default: latest pinned below),
# verifies its SHA-256 against the release's published SHA256SUMS, and installs
# it to $SAFE_AI_SKILL_BIN_DIR (default: ~/.local/bin).
#
# This mirrors the npm postinstall path (npm/scripts/postinstall.js). It is the
# checksum-verified alternative to `curl <url> | bash`: it FAILS LOUDLY and
# installs nothing on a checksum mismatch or download error. A broken silent
# install is worse than a loud failing one for a security tool.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/solanabr/safe-ai-skill/main/install.sh | sh
#   SAFE_AI_SKILL_BIN_DIR=/usr/local/bin sh install.sh
#   SAFE_AI_SKILL_VERSION=1.0.0 sh install.sh

set -eu

REPO="solanabr/safe-ai-skill"
# Default version — keep in sync with npm/package.json and crates/engine/Cargo.toml.
VERSION="${SAFE_AI_SKILL_VERSION:-1.0.0}"
TAG="v${VERSION}"
RELEASE_BASE="https://github.com/${REPO}/releases/download/${TAG}"
BIN_DIR="${SAFE_AI_SKILL_BIN_DIR:-${HOME}/.local/bin}"

err() {
  printf 'safe-ai-skill: %s\n' "$1" >&2
}

fatal() {
  err "INSTALL FAILED — $1"
  exit 1
}

# ── platform detection ──────────────────────────────────────────────────────

detect_platform() {
  os="$(uname -s)"
  arch="$(uname -m)"
  case "${os}" in
    Darwin)
      case "${arch}" in
        arm64) echo "darwin-arm64" ;;
        x86_64) echo "darwin-x64" ;;
        *) return 1 ;;
      esac
      ;;
    Linux)
      case "${arch}" in
        x86_64) echo "linux-x64" ;;
        aarch64 | arm64) echo "linux-arm64" ;;
        *) return 1 ;;
      esac
      ;;
    *)
      return 1
      ;;
  esac
}

# ── download (curl or wget) ─────────────────────────────────────────────────

download() {
  # download <url> <dest>
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$2" "$1"
  else
    fatal "neither curl nor wget is available."
  fi
}

# ── sha256 (sha256sum or shasum) ────────────────────────────────────────────

sha256_of() {
  # sha256_of <file> → prints lowercase hex hash
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    fatal "neither sha256sum nor shasum is available."
  fi
}

# ── main ────────────────────────────────────────────────────────────────────

plat="$(detect_platform)" || fatal "unsupported platform $(uname -s)/$(uname -m). Install via: cargo install safe-ai-skill"

binary_name="safe-ai-skill-${plat}"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT INT TERM

err "downloading ${binary_name} from release ${TAG}…"
download "${RELEASE_BASE}/${binary_name}" "${tmp_dir}/${binary_name}" \
  || fatal "could not download ${RELEASE_BASE}/${binary_name}. Verify release ${TAG} exists, or use: cargo install safe-ai-skill"
download "${RELEASE_BASE}/SHA256SUMS" "${tmp_dir}/SHA256SUMS" \
  || fatal "could not download SHA256SUMS for ${TAG}."

# Expected hash for our binary from the published SHA256SUMS.
expected="$(grep " ${binary_name}\$" "${tmp_dir}/SHA256SUMS" | awk '{print $1}' | head -n1)"
[ -n "${expected}" ] || fatal "${binary_name} not found in SHA256SUMS."

actual="$(sha256_of "${tmp_dir}/${binary_name}")"
if [ "${actual}" != "${expected}" ]; then
  err "  expected: ${expected}"
  err "  got:      ${actual}"
  fatal "checksum mismatch for ${binary_name}. Do NOT use this binary; the artifact may be tampered or the release out of date."
fi

mkdir -p "${BIN_DIR}"
install_path="${BIN_DIR}/safe-ai-skill"
cp "${tmp_dir}/${binary_name}" "${install_path}"
chmod 0755 "${install_path}"

err "installed safe-ai-skill ${VERSION} → ${install_path} (checksum verified)."

case ":${PATH}:" in
  *":${BIN_DIR}:"*) ;;
  *) err "note: ${BIN_DIR} is not on your PATH. Add it, e.g.: export PATH=\"${BIN_DIR}:\$PATH\"" ;;
esac
