#!/bin/sh
# install.sh — installer for safe-ai-skill: the Claude Code plugin and the CLI
#
# Downloads the prebuilt safe-ai-skill binary for the current platform from the
# GitHub Release matching $SAFE_AI_SKILL_VERSION (default: latest pinned below),
# verifies its SHA-256 against the release's published SHA256SUMS, and installs
# it to $SAFE_AI_SKILL_BIN_DIR (default: ~/.local/bin).
#
# Then, when `claude` is on PATH, it installs the Claude Code plugin, which is what
# runs the hooks: the same `claude plugin marketplace add` + `claude plugin install`
# a manual install runs. It leaves an already installed copy (for example
# safe-ai-skill@stbr from solana-ai-kit) alone, since two copies don't both run.
# SAFE_AI_SKILL_PLUGIN=0 installs the CLI only.
#
# From 1.3.0 a release also ships the plugin's POSIX shim (safe-ai-skill-shim). On
# macOS and Linux it is installed as `safe-ai-skill`, with the binary beside it as
# `safe-ai-skill-<platform>`: the shim checks the binary against the sha256 stamped in
# it and is the entry point Codex hooks need (it turns an engine failure into a block).
# A release without it, and Windows, get the binary alone as `safe-ai-skill`.
#
# This mirrors the npm postinstall path (npm/scripts/postinstall.js). It is the
# checksum-verified alternative to `curl <url> | bash`: it FAILS LOUDLY and
# installs nothing on a checksum mismatch or download error. A broken silent
# install is worse than a loud failing one for a security tool.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/solanabr/safe-ai-skill/main/install.sh | sh
#   SAFE_AI_SKILL_BIN_DIR=/usr/local/bin sh install.sh
#   SAFE_AI_SKILL_VERSION=1.3.2 sh install.sh
#   curl -fsSL …/install.sh | SAFE_AI_SKILL_PLUGIN=0 sh     # CLI only, no hooks

set -eu

REPO="solanabr/safe-ai-skill"
# HTTPS, so adding the marketplace doesn't need a GitHub SSH key.
MARKETPLACE_URL="https://github.com/${REPO}.git"
PLUGIN_ID="safe-ai-skill@safe-ai-skill"
# Default version — scripts/check-versions.sh keeps it equal to every manifest.
VERSION="${SAFE_AI_SKILL_VERSION:-1.3.2}"
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
    # Git Bash / MSYS2 / Cygwin. Windows on ARM runs the x64 build under emulation.
    MINGW* | MSYS* | CYGWIN*)
      case "${arch}" in
        x86_64 | amd64 | aarch64 | arm64) echo "windows-x64" ;;
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

plat="$(detect_platform)" || fatal "unsupported platform $(uname -s)/$(uname -m). Install via: cargo install safe-ai-skill --version ${VERSION} --locked"

ext=""
case "${plat}" in windows-*) ext=".exe" ;; esac
binary_name="safe-ai-skill-${plat}${ext}"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT INT TERM

err "downloading ${binary_name} from release ${TAG}…"
download "${RELEASE_BASE}/${binary_name}" "${tmp_dir}/${binary_name}" \
  || fatal "could not download ${RELEASE_BASE}/${binary_name}. Verify release ${TAG} exists, or use: cargo install safe-ai-skill --version ${VERSION} --locked"
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
install_path="${BIN_DIR}/safe-ai-skill${ext}"

# place <src> <dest>: copy to a temp file beside <dest>, make it executable, then rename it
# over <dest>. A running hook never sees a half-written file, and a signed macOS binary is
# never rewritten in place.
place() {
  tmp_file="$(dirname "$2")/.$(basename "$2").install.$$"
  cp "$1" "${tmp_file}" || fatal "could not write ${tmp_file}."
  chmod 0755 "${tmp_file}" || fatal "could not chmod ${tmp_file}."
  mv -f "${tmp_file}" "$2" || fatal "could not install $2."
}

shim_expected=""
case "${plat}" in
  windows-*) ;;
  *) shim_expected="$(grep " safe-ai-skill-shim\$" "${tmp_dir}/SHA256SUMS" | awk '{print $1}' | head -n1)" ;;
esac
if [ -n "${shim_expected}" ]; then
  download "${RELEASE_BASE}/safe-ai-skill-shim" "${tmp_dir}/safe-ai-skill-shim" \
    || fatal "could not download ${RELEASE_BASE}/safe-ai-skill-shim."
  shim_actual="$(sha256_of "${tmp_dir}/safe-ai-skill-shim")"
  [ "${shim_actual}" = "${shim_expected}" ] \
    || fatal "checksum mismatch for safe-ai-skill-shim. Do NOT use it; the artifact may be tampered."
  # The binary first, so the shim never points at a missing or older one.
  place "${tmp_dir}/${binary_name}" "${BIN_DIR}/${binary_name}"
  place "${tmp_dir}/safe-ai-skill-shim" "${install_path}"
  err "installed safe-ai-skill ${VERSION} → ${install_path} (shim) + ${BIN_DIR}/${binary_name} (checksums verified)."
else
  place "${tmp_dir}/${binary_name}" "${install_path}"
  err "installed safe-ai-skill ${VERSION} → ${install_path} (checksum verified)."
fi

case ":${PATH}:" in
  *":${BIN_DIR}:"*) ;;
  *) err "note: ${BIN_DIR} is not on your PATH. Add it, e.g.: export PATH=\"${BIN_DIR}:\$PATH\"" ;;
esac

# ── Claude Code plugin (the hooks) ──────────────────────────────────────────

plugin_commands() {
  err "  claude plugin marketplace add ${MARKETPLACE_URL}"
  err "  claude plugin install ${PLUGIN_ID}"
}

if [ "${SAFE_AI_SKILL_PLUGIN:-1}" = "0" ]; then
  err "SAFE_AI_SKILL_PLUGIN=0: the Claude Code plugin was not installed, so no hooks run."
  exit 0
fi
if ! command -v claude >/dev/null 2>&1; then
  err "the hooks are NOT installed: claude (Claude Code) is not on PATH. Install Claude Code, then run:"
  plugin_commands
  exit 0
fi

installed="$(claude plugin list --json 2>/dev/null \
  | grep -o '"id": *"safe-ai-skill@[^"]*"' | head -n1 | sed 's/.*"\(safe-ai-skill@[^"]*\)"$/\1/')" || installed=""
if [ -n "${installed}" ]; then
  err "the Claude Code plugin is already installed as ${installed}; left as it is."
  exit 0
fi

log="${tmp_dir}/plugin.log"
if claude plugin marketplace add "${MARKETPLACE_URL}" >"${log}" 2>&1 \
  && claude plugin install "${PLUGIN_ID}" >>"${log}" 2>&1; then
  err "installed the Claude Code plugin ${PLUGIN_ID}: the hooks run from your next Claude Code session."
else
  cat "${log}" >&2
  err "INSTALL FAILED — the CLI is installed, but the Claude Code plugin is not, so no hooks run. Run:"
  plugin_commands
  exit 1
fi
