# SPDX-License-Identifier: AGPL-3.0-or-later
"""Runs as root, as the probe unit's ExecStartPre=+ and ExecStopPost=+ (deploy/units/aukora-release-probe.template;
deploy/engine/NODE.md O20): make the throwaway user's copy of the state for the pre-swap probe of an offered release,
then record its outcome for the supervisor. Never touches the live state beyond reading it.

  release_probe.py prepare ID | finish ID"""
from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import node_release as r  # noqa: E402
from node_release import core  # noqa: E402

# The pre-swap probe (deploy/units/aukora-release-probe.template): root's copy for the throwaway user, the
# configuration copy in a root-owned folder, and the outcome the supervisor reads.
LIVE_STATE = "/var/lib/aukora"
PROBE_RUN = "/run/aukora-release-probe"
PROBE_CONFIG = "/run/aukora-release-probe-config"
PROBE_RESULTS = r.STATE + "/probe"
PROBE_IDENTITY = ("node-identity-v1", "aura-signing-key")
PROBE_FOLDERS = ("floor", "targets", "browser-sessions")


def copy_owned(source, destination, uid):
    """Regular files and folders only (links are neither followed nor copied); folders 0700, files 0600, all the
    throwaway user's."""
    info = os.lstat(source)
    if stat.S_ISDIR(info.st_mode):
        os.mkdir(destination, 0o700)
        os.chown(destination, uid, uid)
        for name in sorted(os.listdir(source)):
            copy_owned(os.path.join(source, name), os.path.join(destination, name), uid)
    elif stat.S_ISREG(info.st_mode):
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(descriptor, "wb") as target, open(source, "rb") as origin:
            shutil.copyfileobj(origin, target)
            os.fchown(target.fileno(), uid, uid)
            os.fchmod(target.fileno(), 0o600)


def results_folder():
    """Root's records, readable by the supervisor (the unit's UMask 0077 applies to the root steps too: set, not asked)."""
    os.makedirs(PROBE_RESULTS, mode=0o755, exist_ok=True)
    os.chmod(PROBE_RESULTS, 0o755)


def probe_prepare(rid):
    """ExecStartPre=+ of the probe unit: the offered, staged release only; a fresh copy of what the candidate's start
    reads, owned by the unit's throwaway user, and the configuration in a root-owned folder. Never the live state."""
    import sqlite3
    if r.link_id(r.OFFERED) != rid:
        core.refuse("node-release", "probe-not-offered")
    r.staged_digest(rid)
    results_folder()
    try:
        os.unlink(os.path.join(PROBE_RESULTS, rid + ".json"))
    except FileNotFoundError:
        pass
    run = os.path.join(PROBE_RUN, rid)
    info = os.lstat(run)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid == 0 or info.st_mode & 0o077:
        core.refuse("node-release", "probe-runtime")
    uid, state = info.st_uid, os.path.join(run, "state")
    os.mkdir(state, 0o700)
    os.chown(state, uid, uid)
    for name in PROBE_IDENTITY:
        copy_owned(os.path.join(LIVE_STATE, name), os.path.join(state, name), uid)
    for name in PROBE_FOLDERS:
        if os.path.isdir(os.path.join(LIVE_STATE, name)):
            copy_owned(os.path.join(LIVE_STATE, name), os.path.join(state, name), uid)
    ledger = os.path.join(state, "aura.sqlite3")
    source = sqlite3.connect("file:" + os.path.join(LIVE_STATE, "aura.sqlite3") + "?mode=ro", uri=True, timeout=5)
    try:
        source.execute("VACUUM INTO ?", (ledger,))
    finally:
        source.close()
    os.chown(ledger, uid, uid)
    os.chmod(ledger, 0o600)
    # The floor again, after the ledger: the state the ledger snapshot recorded.
    if os.path.isdir(os.path.join(LIVE_STATE, "floor")):
        shutil.rmtree(os.path.join(state, "floor"))
        copy_owned(os.path.join(LIVE_STATE, "floor"), os.path.join(state, "floor"), uid)
    # The unit's UMask (0077) applies to this root step too: the modes are set, not asked for.
    os.makedirs(PROBE_CONFIG, mode=0o755, exist_ok=True)
    os.chmod(PROBE_CONFIG, 0o755)
    config = os.path.join(PROBE_CONFIG, rid)
    shutil.rmtree(config, ignore_errors=True)
    os.mkdir(config, 0o755)
    os.chmod(config, 0o755)
    for name in ("node.json", "gate-targets-v1.json"):
        if not os.path.lexists(os.path.join(r.CONFIG, name)):
            continue
        raw = core.read_regular(os.path.join(r.CONFIG, name), 1 << 20, "node-release")
        if name == "node.json":
            # The configuration names files beside itself (claim, egress policy): they name the copy's folder now,
            # which holds neither (the probe never reads them).
            node = core.parse_json(raw, "node-release", 1 << 20)
            node["claim_commitment"] = os.path.join(config, "claim.sha256")
            node["egress_policy"] = os.path.join(config, "egress.json")
            raw = core.canonical(node)
        core.atomic_write(os.path.join(config, name), raw, 0o644)


def journal_lines(invocation, main_pid):
    """What this run's main process wrote (stdout and stderr both reach the journal; only the exact success line
    counts, and only if it is the one line the candidate's main process wrote to stdout)."""
    if not re.fullmatch(r"[0-9a-f]{32}", invocation) or (main_pid and not main_pid.isdigit()):
        return None
    # systemd may no longer know the main pid once it exited: then every stdout line of the run counts (the root
    # steps write nothing to stdout), which only makes the one-line rule stricter.
    match = ["_PID=" + main_pid] if main_pid else []
    try:
        done = subprocess.run(["journalctl", "--no-pager", "-o", "json", "_SYSTEMD_INVOCATION_ID=" + invocation,
                               "_TRANSPORT=stdout"] + match,
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=20, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    lines = []
    for raw in done.stdout.decode("utf-8", "replace").splitlines()[:64]:
        try:
            entry = json.loads(raw)
        except ValueError:
            return None
        message = entry.get("MESSAGE")
        if not isinstance(message, str):
            return None
        lines.append(message)
    return lines


def probe_finish(rid, environment=None):
    """ExecStopPost=+ of the probe unit: record the outcome for the supervisor (root 0644). Passed only if the unit
    succeeded, the candidate exited 0 and said exactly `probe ok <its release digest>`."""
    environment = os.environ if environment is None else environment
    digest = r.staged_digest(rid)[2]
    said = journal_lines(environment.get("INVOCATION_ID", ""), environment.get("MAINPID", ""))
    passed = (environment.get("SERVICE_RESULT") == "success" and environment.get("EXIT_CODE") == "exited"
              and environment.get("EXIT_STATUS") == "0" and said == ["probe ok " + digest])
    results_folder()
    core.atomic_write(os.path.join(PROBE_RESULTS, rid + ".json"),
                      core.canonical({"v": 1, "id": rid, "release": digest, "passed": passed,
                                      "result": str(environment.get("SERVICE_RESULT", ""))[:32],
                                      "at_ms": time.time_ns() // 1_000_000}), 0o644)
    shutil.rmtree(os.path.join(PROBE_CONFIG, rid), ignore_errors=True)
    return passed



def main(argv):
    if os.geteuid() != 0:
        core.refuse("release-probe", "root-required")
    if len(argv) != 2 or argv[0] not in ("prepare", "finish") or not r.RELEASE_ID.match(argv[1]):
        core.refuse("release-probe", "usage")
    if argv[0] == "prepare":
        probe_prepare(argv[1])
    else:
        print("release-probe: " + ("passed" if probe_finish(argv[1]) else "failed"), file=sys.stderr)
    return 0


if __name__ == "__main__":
    core.run_main("release-probe", main)
