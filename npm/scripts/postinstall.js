#!/usr/bin/env node
// postinstall.js — safe-solana-ai npm wrapper
//
// Downloads the ssai binary for the current platform from the GitHub Release
// that matches this package version, verifies its SHA-256 against the
// published SHA256SUMS file, marks it executable, and writes a thin
// bin/cli.js launcher stub if one is not already present.
//
// Design notes
// ─────────────────────────────────────────────────────────────────────────────
// • Zero runtime npm dependencies. Uses Node's built-in https and fs modules
//   (Node 18+ has global fetch; we use https for reliability in older CI).
// • The binary is placed at <package-root>/bin/ssai-<plat> and the launcher
//   at bin/cli.js discovers it via __dirname at exec time.
// • We FAIL LOUDLY on any download or checksum error. This is a security
//   tool; a broken silent install is worse than a loud failing install.
//
// Alternative approach (NOT used here)
// ─────────────────────────────────────────────────────────────────────────────
// The "optionalDependencies" pattern publishes per-platform sub-packages
// (e.g. safe-solana-ai-darwin-arm64) containing the prebuilt binary; npm
// installs only the matching one based on os/cpu fields in package.json.
// Pros: works offline after install, no postinstall script required.
// Cons: requires publishing N+1 packages per release, each with the binary
//       as a file asset (npm has a 250 MB limit; fine here but more setup).
// The postinstall-download pattern used here is simpler to maintain for a
// single-publisher project and avoids the multi-package release coordination.

"use strict";

const https = require("https");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { execFileSync } = require("child_process");

// ── constants ─────────────────────────────────────────────────────────────

const PKG_VERSION = require("../package.json").version;
const GITHUB_REPO = "solanabr/safe-solana-ai";
const RELEASE_TAG = `v${PKG_VERSION}`;
const RELEASE_BASE = `https://github.com/${GITHUB_REPO}/releases/download/${RELEASE_TAG}`;

const BIN_DIR = path.join(__dirname, "..", "bin");
const CHECKSUMS_FILE = path.join(BIN_DIR, "SHA256SUMS");

// ── platform detection ────────────────────────────────────────────────────

function detectPlatform() {
  const os = process.platform;
  const arch = process.arch;

  if (os === "darwin" && arch === "arm64") return "darwin-arm64";
  if (os === "darwin" && arch === "x64")  return "darwin-x64";
  if (os === "linux"  && arch === "x64")  return "linux-x64";
  if (os === "linux"  && arch === "arm64") return "linux-arm64";

  return null;
}

// ── https helpers ─────────────────────────────────────────────────────────

/**
 * Download a URL, following up to `maxRedirects` redirects.
 * Returns a Buffer on success; throws on HTTP error or timeout.
 */
function download(url, maxRedirects = 5) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { timeout: 60_000 }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        if (maxRedirects <= 0) {
          reject(new Error(`Too many redirects downloading ${url}`));
          return;
        }
        resolve(download(res.headers.location, maxRedirects - 1));
        return;
      }
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode} downloading ${url}`));
        return;
      }
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve(Buffer.concat(chunks)));
      res.on("error", reject);
    });
    req.on("timeout", () => {
      req.destroy();
      reject(new Error(`Timeout downloading ${url}`));
    });
    req.on("error", reject);
  });
}

// ── checksum verification ─────────────────────────────────────────────────

/**
 * Parse a sha256sum / shasum -a 256 output file.
 * Returns a Map<filename, expectedHex>.
 */
function parseSumsFile(content) {
  const map = new Map();
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    // Both "  " (two-space) and " " (single-space) formats accepted.
    const parts = trimmed.split(/\s+/);
    if (parts.length >= 2) {
      map.set(parts[1], parts[0].toLowerCase());
    }
  }
  return map;
}

function sha256hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

// ── main ──────────────────────────────────────────────────────────────────

async function main() {
  const plat = detectPlatform();
  if (!plat) {
    console.error(
      `safe-solana-ai: unsupported platform ${process.platform}/${process.arch}.\n` +
      `Install cargo and run: cargo install safe-solana-ai`
    );
    process.exit(1);
  }

  const binaryName = `ssai-${plat}`;
  const binaryPath = path.join(BIN_DIR, binaryName);
  const binaryUrl  = `${RELEASE_BASE}/${binaryName}`;
  const sumsUrl    = `${RELEASE_BASE}/SHA256SUMS`;

  // Skip download if binary already present (e.g. re-running npm install in CI).
  if (!fs.existsSync(binaryPath)) {
    console.log(`safe-solana-ai: downloading ${binaryName} from GitHub Release ${RELEASE_TAG}…`);

    let binaryBuf;
    let sumsBuf;

    try {
      [binaryBuf, sumsBuf] = await Promise.all([download(binaryUrl), download(sumsUrl)]);
    } catch (err) {
      console.error(
        `\nsafe-solana-ai: INSTALL FAILED — could not download release assets.\n` +
        `  URL: ${binaryUrl}\n` +
        `  Error: ${err.message}\n\n` +
        `Troubleshooting:\n` +
        `  • Check your internet connection.\n` +
        `  • Verify that release ${RELEASE_TAG} exists at\n` +
        `    https://github.com/${GITHUB_REPO}/releases\n` +
        `  • As a fallback, install via cargo: cargo install safe-solana-ai\n`
      );
      process.exit(1);
    }

    // Verify checksum before writing to disk.
    const sumsText = sumsBuf.toString("utf8");
    const expectedHex = parseSumsFile(sumsText).get(binaryName);
    if (!expectedHex) {
      console.error(
        `safe-solana-ai: INSTALL FAILED — ${binaryName} not found in SHA256SUMS.\n` +
        `SHA256SUMS content:\n${sumsText}`
      );
      process.exit(1);
    }

    const actualHex = sha256hex(binaryBuf);
    if (actualHex !== expectedHex) {
      console.error(
        `safe-solana-ai: INSTALL FAILED — checksum mismatch for ${binaryName}.\n` +
        `  Expected: ${expectedHex}\n` +
        `  Got:      ${actualHex}\n\n` +
        `The downloaded binary did not match the published checksum. This may\n` +
        `indicate a network issue, a tampered artifact, or an out-of-date release.\n` +
        `Do NOT use this binary. Re-run the install or use: cargo install safe-solana-ai`
      );
      process.exit(1);
    }

    // Write verified binary and checksums side-car.
    fs.mkdirSync(BIN_DIR, { recursive: true });
    fs.writeFileSync(binaryPath, binaryBuf, { mode: 0o755 });
    fs.writeFileSync(CHECKSUMS_FILE, sumsText, "utf8");

    console.log(`safe-solana-ai: installed ${binaryName} (checksum verified).`);
  } else {
    // Binary already present; re-verify the stored checksum.
    if (fs.existsSync(CHECKSUMS_FILE)) {
      const sumsText = fs.readFileSync(CHECKSUMS_FILE, "utf8");
      const expectedHex = parseSumsFile(sumsText).get(binaryName);
      if (expectedHex) {
        const actualHex = sha256hex(fs.readFileSync(binaryPath));
        if (actualHex !== expectedHex) {
          console.error(
            `safe-solana-ai: INTEGRITY ERROR — cached ${binaryName} checksum mismatch.\n` +
            `  Expected: ${expectedHex}\n` +
            `  Got:      ${actualHex}\n` +
            `Deleting corrupted binary; re-run npm install to re-download.`
          );
          fs.unlinkSync(binaryPath);
          process.exit(1);
        }
      }
    }
    console.log(`safe-solana-ai: ${binaryName} already present.`);
  }

  // Ensure executable bit (in case fs lost it on Windows-style FS).
  try {
    fs.chmodSync(binaryPath, 0o755);
  } catch (_) {
    // Best-effort; may be a read-only fs (e.g. in some CI caches).
  }
}

main().catch((err) => {
  console.error(`safe-solana-ai: unexpected install error: ${err.message}`);
  process.exit(1);
});
