#!/usr/bin/env node
// cli.js — safe-solana-ai / ssai launcher
//
// Thin exec wrapper. Resolves the platform binary installed by postinstall.js
// and execs it, forwarding all arguments and stdio.
//
// This file intentionally has no logic beyond binary location; all business
// logic lives in the ssai Rust binary.

"use strict";

const path = require("path");
const fs = require("fs");
const { spawnSync } = require("child_process");

const BIN_DIR = path.join(__dirname, "..");  // npm/bin → npm/
const ACTUAL_BIN_DIR = path.join(BIN_DIR, "bin");

function detectPlatform() {
  const os = process.platform;
  const arch = process.arch;
  if (os === "darwin" && arch === "arm64") return "darwin-arm64";
  if (os === "darwin" && arch === "x64")  return "darwin-x64";
  if (os === "linux"  && arch === "x64")  return "linux-x64";
  if (os === "linux"  && arch === "arm64") return "linux-arm64";
  return null;
}

const plat = detectPlatform();
const binaryPath = plat ? path.join(ACTUAL_BIN_DIR, `ssai-${plat}`) : null;

if (!binaryPath || !fs.existsSync(binaryPath)) {
  process.stderr.write(
    `safe-solana-ai: no binary found for platform ${process.platform}/${process.arch}.\n` +
    `Run: npm install safe-solana-ai  (to trigger postinstall)\n` +
    `Or:  cargo install safe-solana-ai\n`
  );
  process.exit(2);
}

const result = spawnSync(binaryPath, process.argv.slice(2), {
  stdio: "inherit",
  windowsHide: true,
});

if (result.error) {
  process.stderr.write(`safe-solana-ai: failed to exec binary: ${result.error.message}\n`);
  process.exit(2);
}

process.exit(result.status ?? 0);
