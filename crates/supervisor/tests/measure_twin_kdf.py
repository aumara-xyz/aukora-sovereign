#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Measure each release replay child, excluding Cargo/build memory and time."""
import os
import platform
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
label = sys.argv[1]
executable = Path(os.environ["CARGO_TARGET_DIR"]) / "release/sovereign"
results = []
for sample in range(1, 4):
    output = ROOT / f"crates/supervisor/tests/twin-kdf-{label}-{sample}.txt"
    with output.open("w") as log:
        started = time.perf_counter()
        child = subprocess.Popen([str(executable), "immune-check"], stdout=log, stderr=log)
        _, status, usage = os.wait4(child.pid, 0)
        child.returncode = os.waitstatus_to_exitcode(status)
        elapsed = time.perf_counter() - started
    peak_bytes = usage.ru_maxrss if sys.platform == "darwin" else usage.ru_maxrss * 1024
    report = output.read_text()
    if child.returncode != 0 or "antibody_pass_count 20/20" not in report:
        raise SystemExit(f"replay failed: {output}, exit {child.returncode}")
    results.append(
        f"{label} sample {sample}: 20/20; exit {child.returncode}; "
        f"wall {elapsed:.3f} s; peak RSS {peak_bytes} bytes ({peak_bytes / 1048576:.2f} MiB)"
    )
    output.unlink()
result = f"host: {platform.system()} {platform.machine()}; release immune-check\n" + "\n".join(results) + "\n"
(ROOT / f"crates/supervisor/tests/twin-kdf-{label}.txt").write_text(result)
print(result, end="")
