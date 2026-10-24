#!/usr/bin/env python3
"""windows-test-gate.py — run the engine suite and fail on any failure not allowlisted.

    python3 -I scripts/windows-test-gate.py [--allowlist FILE] [-- extra cargo test args]

Runs `cargo test --no-fail-fast` on crates/engine and collects each failing test as
`<test binary>::<test name>` (e.g. `gates::read_dotenv_denies`,
`safe_ai_skill::datadir::tests::the_root_itself_is_untrusted`). Fails when a test fails
that is not in the allowlist (crates/engine/tests/windows-known-failures.txt), or when
cargo fails without any test failing (a build error). An allowlisted test that now passes
is reported so its line can be deleted. Used by ci.yml's Windows job.
"""

import argparse
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = os.path.join(ROOT, "crates", "engine", "Cargo.toml")
DEFAULT_ALLOWLIST = os.path.join(ROOT, "crates", "engine", "tests", "windows-known-failures.txt")

RUNNING = re.compile(r"^\s*Running .*[/\\]deps[/\\]([A-Za-z0-9_]+)-[0-9a-f]+(?:\.exe)?\)?\s*$")
DOCTESTS = re.compile(r"^\s*Doc-tests (\S+)")
# Doc-test names contain spaces (`src/lib.rs - item (line 12)`).
RESULT = re.compile(r"^test (.+?) \.\.\. (ok|FAILED|ignored)")
SUMMARY = re.compile(r"^test result: ")
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def load_allowlist(path):
    entries = set()
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if line:
                entries.add(line)
    return entries


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--allowlist", default=DEFAULT_ALLOWLIST)
    ap.add_argument("cargo_args", nargs="*")
    args = ap.parse_args()
    allowed = load_allowlist(args.allowlist)

    cmd = ["cargo", "test", "--manifest-path", MANIFEST, "--no-fail-fast", *args.cargo_args]
    env = dict(os.environ, CARGO_TERM_COLOR="never")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            encoding="utf-8", errors="replace", env=env)
    binary = "?"
    failed, passed = set(), set()
    # Test binaries that started but never printed a `test result:` line (crashed or aborted):
    # their unreported tests are failures no allowlist entry can cover.
    started, finished = [], set()
    for line in proc.stdout:
        sys.stdout.write(line)
        line = ANSI.sub("", line)
        m = RUNNING.match(line) or DOCTESTS.match(line)
        if m:
            binary = m.group(1) if RUNNING.match(line) else "doctest"
            started.append(binary)
            continue
        if SUMMARY.match(line):
            finished.add(binary)
            continue
        m = RESULT.match(line)
        if m:
            key = f"{binary}::{m.group(1)}"
            (failed if m.group(2) == "FAILED" else passed).add(key)
    code = proc.wait()

    aborted = sorted(set(started) - finished)
    new = sorted(failed - allowed)
    stale = sorted(allowed & passed)
    print(f"\nwindows-test-gate: {len(failed)} failed ({len(failed) - len(new)} allowlisted), "
          f"{len(passed)} passed or ignored")
    for key in stale:
        print(f"::warning::{key} passes now; delete it from the allowlist")
    for key in new:
        print(f"::error::{key} fails and is not in the allowlist")
    for name in aborted:
        print(f"::error::test binary {name} ended without a result (crashed or aborted)")
    if new or aborted:
        return 1
    if code != 0 and not failed:
        print("::error::cargo test failed without a test failure (build error?)")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
