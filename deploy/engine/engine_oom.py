# SPDX-License-Identifier: AGPL-3.0-or-later
"""Set the actual sandbox processes' OOM priority before the engine unit becomes active.

OpenShell 0.1.4 cannot set Docker's OomScoreAdj. The engine unit's own OOMScoreAdjust applies to the CLI, not
containers created by dockerd. Pause the workload while enumerating its host PIDs so no child can miss the change;
future children inherit +500. This makes the engine expendable before the authority under host memory pressure.
"""
from __future__ import annotations

from pathlib import Path
import re
import subprocess
import sys


PROC = Path("/proc")
SCORE = "500"


def docker(*args):
    return subprocess.run(["/usr/bin/docker", *args], check=True, timeout=15, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def set_priority(container):
    if not re.fullmatch(r"[a-f0-9]{64}", container):
        raise ValueError("not a container id")
    try:
        docker("pause", container)
        lines = docker("top", container, "-eo", "pid").splitlines()
        pids = [line.strip() for line in lines[1:]]
        if not lines or lines[0].strip() != "PID" or not pids or len(pids) != len(set(pids)) \
                or any(not re.fullmatch(r"[1-9][0-9]*", pid) for pid in pids):
            raise ValueError("no trustworthy sandbox pid list")
        for pid in pids:
            path = PROC / pid / "oom_score_adj"
            path.write_text(SCORE + "\n", encoding="ascii")
            if path.read_text(encoding="ascii").strip() != SCORE:
                raise ValueError("sandbox OOM priority did not stick")
    finally:
        # Even a pause timeout can leave the container frozen after Docker processes the request.
        # Failure to unpause fails activation too; ExecStopPost removes the sandbox.
        docker("unpause", container)


def main():
    try:
        if len(sys.argv) != 2:
            raise ValueError("expected one sandbox container id")
        set_priority(sys.argv[1])
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print("engine-run: cannot set sandbox OOM priority: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
