#!/usr/bin/env python3
"""latency-budget.py — the hook latency budget (spec D5, WS-E E5), run by CI.

    python3 -I scripts/latency-budget.py --engine <new build> --baseline <shipped binary>

1. Cold gate: `gate-read` through the real shim (sha256 check included), one fresh process
   and a fresh plugin data dir per call. The median of RUNS calls must stay under 50 ms.
2. Sweep: SessionStart `verify session` over a synthetic skills corpus in a scratch HOME,
   steady state (after one pinning run). The new engine's median must stay within 2x the
   baseline's, measured on the same runner, so the bound tracks the hardware.

Exits 1 when a budget is exceeded, 2 on a setup error.
"""

import argparse
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHIM = os.path.join(ROOT, "plugins", "safe-ai-skill", "bin", "safe-ai-skill")
STAMP = os.path.join(ROOT, "scripts", "stamp-shim.sh")

COLD_GATE_MS = 50.0
SWEEP_RATIO = 2.0
RUNS = 15
SWEEP_RUNS = 7
PACKS = 150

READ_PAYLOAD = json.dumps(
    {
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "README.md"},
    }
).encode()


def plat():
    system = platform.system()
    machine = platform.machine().lower()
    arch = {"x86_64": "x64", "amd64": "x64", "arm64": "arm64", "aarch64": "arm64"}.get(machine)
    family = {"Linux": "linux", "Darwin": "darwin"}.get(system)
    if not arch or not family:
        sys.exit(f"latency-budget: unsupported host {system}/{machine}")
    return f"{family}-{arch}"


def timed(cmd, env, stdin=b"", cwd=None):
    start = time.perf_counter()
    proc = subprocess.run(
        cmd, input=stdin, env=env, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    elapsed = (time.perf_counter() - start) * 1000
    if proc.returncode not in (0, 2, 3):
        sys.stderr.write(proc.stderr.decode(errors="replace"))
        print(f"latency-budget: {' '.join(cmd)} exited {proc.returncode}", file=sys.stderr)
        sys.exit(2)
    return elapsed


def base_env(home):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE", "SAFE_AI_SKILL"))}
    env["HOME"] = home
    return env


def cold_gate(engine, work):
    bindir = os.path.join(work, "plugin", "bin")
    os.makedirs(bindir)
    shutil.copy2(SHIM, os.path.join(bindir, "safe-ai-skill"))
    shutil.copy2(engine, os.path.join(bindir, f"safe-ai-skill-{plat()}"))
    subprocess.run(["sh", STAMP, bindir], check=True, stdout=subprocess.DEVNULL)
    home = os.path.join(work, "gate-home")
    os.makedirs(home)
    samples = []
    for i in range(RUNS):
        env = base_env(home)
        env["CLAUDE_PLUGIN_DATA"] = os.path.join(work, f"gate-data-{i}")
        samples.append(
            timed([os.path.join(bindir, "safe-ai-skill"), "gate-read"], env, READ_PAYLOAD, cwd=work)
        )
    return samples


def make_corpus(home):
    skills = os.path.join(home, ".claude", "skills")
    for n in range(PACKS):
        pack = os.path.join(skills, f"pack-{n:03d}")
        os.makedirs(os.path.join(pack, "references"))
        with open(os.path.join(pack, "SKILL.md"), "w") as f:
            f.write(f"---\nname: pack-{n:03d}\ndescription: Example skill {n}.\n---\n\n")
            f.write("Use this skill to format Rust code with cargo fmt.\n" * 40)
        for r in range(4):
            with open(os.path.join(pack, "references", f"ref-{r}.md"), "w") as f:
                f.write(f"# Reference {r}\n\n" + "Plain documentation text.\n" * 200)


def sweep(binary, work, tag):
    home = os.path.join(work, f"sweep-home-{tag}")
    project = os.path.join(work, f"sweep-project-{tag}")
    os.makedirs(project)
    make_corpus(home)
    env = base_env(home)
    env["CLAUDE_PLUGIN_DATA"] = os.path.join(work, f"sweep-data-{tag}")
    payload = json.dumps(
        {"hook_event_name": "SessionStart", "source": "startup", "cwd": project}
    ).encode()
    timed([binary, "verify", "session"], env, payload, cwd=project)  # pins every pack
    return [timed([binary, "verify", "session"], env, payload, cwd=project) for _ in range(SWEEP_RUNS)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", required=True, help="the engine build under test")
    ap.add_argument("--baseline", required=True, help="the last shipped binary for this host")
    args = ap.parse_args()
    for path in (args.engine, args.baseline):
        if not os.access(path, os.X_OK):
            sys.exit(f"latency-budget: {path} is not an executable")

    work = tempfile.mkdtemp(prefix="latency-budget.")
    try:
        gate = cold_gate(os.path.abspath(args.engine), work)
        new = sweep(os.path.abspath(args.engine), work, "new")
        old = sweep(os.path.abspath(args.baseline), work, "baseline")
    finally:
        shutil.rmtree(work, ignore_errors=True)

    gate_ms = statistics.median(gate)
    new_ms, old_ms = statistics.median(new), statistics.median(old)
    ratio = new_ms / old_ms if old_ms > 0 else float("inf")
    print(f"cold gate-read via shim: median {gate_ms:.1f} ms, max {max(gate):.1f} ms "
          f"(budget < {COLD_GATE_MS:.0f} ms)")
    print(f"sweep ({PACKS} packs): new {new_ms:.1f} ms, baseline {old_ms:.1f} ms, "
          f"ratio {ratio:.2f} (budget <= {SWEEP_RATIO:.1f})")
    failed = False
    if gate_ms >= COLD_GATE_MS:
        print("::error::cold gate-read is over its 50 ms budget")
        failed = True
    if ratio > SWEEP_RATIO:
        print("::error::the SessionStart sweep is more than 2x slower than the baseline")
        failed = True
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
