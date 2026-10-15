# SPDX-License-Identifier: AGPL-3.0-or-later
"""Runs as root on a node (rows 80, 131): stage a verified release, switch to it with a probe and an automatic
rollback, deliver the one-time claim commitment, replace the egress policy.

A release lives in /opt/aukora/releases/<id> and is never modified after it is verified. The switch changes one
symbolic link and restarts the supervisor; it never touches node state, and a rollback restores the previous release
and never any data (Aura has no rollback, and a restored snapshot could revive a spent approval). The switch has
already been authorized by the operator's release-pointer check; this tool adds the replay guard (the pointer
sequence only rises) and refuses anything that was not verified against its manifest."""
from __future__ import annotations

import grp
import http.client
import json
import os
import pwd
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "spawn"))
import core  # noqa: E402

ROOT = "/opt/aukora"
RELEASES = ROOT + "/releases"
CURRENT = ROOT + "/current"
PREVIOUS = ROOT + "/previous"
CONFIG = "/etc/aukora"
NODE_JSON = CONFIG + "/node.json"
EGRESS = CONFIG + "/egress.json"
CLAIM = CONFIG + "/claim.sha256"
STATE = "/var/lib/aukora-release"
ACTIVE = STATE + "/active.json"
DELIVERED = STATE + "/claim-delivered"
HOSTS = "/etc/hosts"
UNIT_DIR = "/etc/systemd/system"
SERVICE = "aukora-sovereign.service"
ENABLED = ("aukora-egress.service", "aukora-egress-verify.timer", SERVICE)
SERVICE_USER = "aukora"
RELEASE_ID = re.compile(r"[0-9a-f]{12}-[0-9a-f]{12}\Z")
HOSTS_BEGIN, HOSTS_END = "# BEGIN AUKORA EGRESS\n", "# END AUKORA EGRESS\n"
PROBE_PATH = "/"
PROBE_SECONDS = 180
STABLE_SECONDS = 10


def system(argv, check=True):
    done = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if check and done.returncode != 0:
        print("node-release: " + " ".join(argv[:3]) + " exited " + str(done.returncode) + "\n"
              + done.stderr[-300:].decode("utf-8", "replace"), file=sys.stderr)
        core.refuse("node-release", "command-failed")
    return done


def release_id(manifest_bytes, manifest):
    return manifest["commit"][:12] + "-" + core.sha256_hex(manifest_bytes)[:12]


# ---- staging -------------------------------------------------------------------------------------------------

def stage(stage_dir):
    """Verify release.tar against release.json and install it as /opt/aukora/releases/<id>. Idempotent."""
    manifest_bytes = core.read_regular(os.path.join(stage_dir, "release.json"), core.MAX_MANIFEST_BYTES, "release")
    manifest = core.parse_manifest(manifest_bytes)
    rid, digest = release_id(manifest_bytes, manifest), core.sha256_hex(manifest_bytes)
    os.umask(0o022)
    os.makedirs(RELEASES, mode=0o755, exist_ok=True)
    target = os.path.join(RELEASES, rid)
    if os.path.isdir(target) and not os.path.islink(target):
        marker = core.read_regular(os.path.join(target, ".verified"), 128, "release").decode("ascii", "replace")
        if marker.strip() != digest:
            core.refuse("release", "exists-different")
        return rid, manifest
    scratch = tempfile.mkdtemp(prefix=".stage-", dir=RELEASES)
    try:
        core.extract_bundle(os.path.join(stage_dir, "release.tar"), manifest, scratch)
        for directory, _names, _files in os.walk(scratch):
            os.chmod(directory, 0o755)
        core.atomic_write(os.path.join(scratch, "release.json"), manifest_bytes, 0o644)
        core.atomic_write(os.path.join(scratch, ".verified"), (digest + "\n").encode("ascii"), 0o644)
        os.rename(scratch, target)
    except BaseException:
        if os.path.dirname(scratch) == RELEASES and os.path.basename(scratch).startswith(".stage-"):
            shutil.rmtree(scratch, ignore_errors=True)
        raise
    return rid, manifest


def verified_release(rid, digest):
    if not RELEASE_ID.match(rid) or not core.is_hex(digest, 64):
        core.refuse("node-release", "arguments")
    directory = os.path.join(RELEASES, rid)
    if os.path.islink(directory) or not os.path.isdir(directory):
        core.refuse("node-release", "not-staged")
    marker = core.read_regular(os.path.join(directory, ".verified"), 128, "release").decode("ascii", "replace")
    if marker.strip() != digest:
        core.refuse("node-release", "not-staged")
    manifest_bytes = core.read_regular(os.path.join(directory, "release.json"), core.MAX_MANIFEST_BYTES, "release")
    if core.sha256_hex(manifest_bytes) != digest or release_id(manifest_bytes, core.parse_manifest(manifest_bytes)) != rid:
        core.refuse("node-release", "not-staged")
    return directory, core.parse_manifest(manifest_bytes)


# ---- units, links, facts -------------------------------------------------------------------------------------

def sync_units(release_dir):
    """Install the release's unit files. Returns True if any changed (the caller reloads systemd)."""
    source = os.path.join(release_dir, "deploy", "units")
    changed = False
    for name in sorted(os.listdir(source)):
        if not name.endswith((".service", ".timer")):
            continue
        data = core.read_regular(os.path.join(source, name), 64 * 1024, "release")
        destination = os.path.join(UNIT_DIR, name)
        try:
            current = core.read_regular(destination, 64 * 1024, "release")
        except core.Refusal:
            current = None
        if current != data:
            core.atomic_write(destination, data, 0o644)
            changed = True
    return changed


def apply_units(release_dir):
    if sync_units(release_dir):
        system(["systemctl", "daemon-reload"])
    system(["systemctl", "enable"] + list(ENABLED))


def restart_supervisor(check=True):
    """Restart even after a crash loop: a unit that hit its start limit refuses restarts until it is reset."""
    system(["systemctl", "reset-failed", SERVICE], check=False)
    system(["systemctl", "restart", SERVICE], check=check)


def point(link, target):
    """Atomically make link a symbolic link to target (relative)."""
    temporary = link + ".new"
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
    os.symlink(target, temporary)
    os.replace(temporary, link)


def link_id(link):
    try:
        target = os.readlink(link)
    except OSError:
        return None
    name = os.path.basename(target)
    return name if RELEASE_ID.match(name) and target == "releases/" + name else None


def read_active():
    try:
        raw = core.read_regular(ACTIVE, 4096, "node-release")
    except core.Refusal:
        return None
    active = core.parse_json(raw, "node-release", 4096)
    core.exact_keys(active, ("v", "id", "commit", "release", "seq", "pointer_sha256", "activated_at_ms"),
                    "node-release", "active-invalid")
    return active


def write_active(rid, manifest, digest, seq, pointer):
    record = {"v": 1, "id": rid, "commit": manifest["commit"], "release": digest, "seq": seq,
              "pointer_sha256": pointer, "activated_at_ms": time.time_ns() // 1_000_000}
    os.makedirs(STATE, mode=0o755, exist_ok=True)
    core.atomic_write(ACTIVE, core.canonical(record), 0o644)


def node_config():
    """node.json, with the shell host name taken from its shell origin."""
    config = core.parse_json(core.read_regular(NODE_JSON, 64 * 1024, "node-release"), "node-release", 64 * 1024)
    if not isinstance(config, dict):
        core.refuse("node-release", "node-config")
    origin = config.get("shell_origin")
    if not isinstance(config.get("listen"), str) or not isinstance(origin, str) or not origin.startswith("https://"):
        core.refuse("node-release", "node-config")
    config["shell_host"] = origin[len("https://"):]
    if not core.is_hostname(config["shell_host"]) or config["listen"].count(":") != 1:
        core.refuse("node-release", "node-config")
    return config


# ---- the switch ----------------------------------------------------------------------------------------------

def show(unit):
    done = system(["systemctl", "show", "-p", "ActiveState", "-p", "SubState", "-p", "MainPID", "-p", "NRestarts", unit])
    return dict(line.split("=", 1) for line in done.stdout.decode("utf-8", "replace").splitlines() if "=" in line)


def shell_answers(config):
    host, port = config["listen"].rsplit(":", 1)
    connection = http.client.HTTPConnection(host, int(port), timeout=3)
    try:
        connection.request("GET", PROBE_PATH, headers={"Host": config["shell_host"], "X-Forwarded-Proto": "https",
                                                       "Connection": "close"})
        return connection.getresponse().status == 200
    except (OSError, http.client.HTTPException):
        return False
    finally:
        connection.close()


def probe(config, binary, binary_sha256, seconds):
    """True when the supervisor has run the new binary, without a restart, for STABLE_SECONDS while the frontdoor
    answers the shell host. The agent need not be running: a new release waits for its owner's approval first."""
    if core.sha256_file(binary) != binary_sha256:
        return False
    deadline, steady, restarts = time.monotonic() + seconds, None, None
    while time.monotonic() < deadline:
        props = show(SERVICE)
        up = props.get("ActiveState") == "active" and props.get("SubState") == "running"
        if up and restarts is not None and props.get("NRestarts") != restarts:
            steady = None
        restarts = props.get("NRestarts") if up else None
        good = False
        if up:
            try:
                good = (os.readlink("/proc/%d/exe" % int(props.get("MainPID", "0"))) == binary
                        and shell_answers(config))
            except (OSError, ValueError):
                good = False
        steady = (steady or time.monotonic()) if good else None
        if steady is not None and time.monotonic() - steady >= STABLE_SECONDS:
            return True
        time.sleep(2)
    return False


def switch(rid, digest, pointer_sha256, seq, seconds):
    directory, manifest = verified_release(rid, digest)
    if not core.is_hex(pointer_sha256, 64) or not core.is_int(seq, 1):
        core.refuse("node-release", "arguments")
    active = read_active()
    if active is None:
        core.refuse("node-release", "not-installed")
    if seq <= active["seq"]:
        core.refuse("node-release", "pointer-replayed")
    old = link_id(CURRENT)
    if old is None:
        core.refuse("node-release", "not-installed")
    config = node_config()
    binary = os.path.realpath(os.path.join(directory, "bin", "sovereign"))
    previous_before = link_id(PREVIOUS)
    flipped = old != rid
    try:
        if flipped:
            point(PREVIOUS, "releases/" + old)
            point(CURRENT, "releases/" + rid)
            apply_units(directory)
        restart_supervisor()
        healthy = probe(config, binary, manifest["files"]["bin/sovereign"]["sha256"], seconds)
    except (core.Refusal, OSError, KeyboardInterrupt):
        healthy = False  # an interrupt (SIGINT, SIGTERM, SIGHUP) takes the rollback path too
    if healthy:
        write_active(rid, manifest, digest, seq, pointer_sha256)
        return "switched"
    if not flipped:
        return "failed"
    point(CURRENT, "releases/" + old)
    if previous_before is not None:
        point(PREVIOUS, "releases/" + previous_before)
    else:
        try:
            os.unlink(PREVIOUS)
        except FileNotFoundError:
            pass
    apply_units(os.path.join(RELEASES, old))
    restart_supervisor(check=False)
    return "rolled-back"


# ---- claim and egress ----------------------------------------------------------------------------------------

def claim(digest, delivered):
    """digest: write the commitment of the one-time secret, readable by the service user only; delivered: record
    that the operator has shown the secret, after which no other commitment is accepted."""
    os.makedirs(STATE, mode=0o755, exist_ok=True)
    if delivered:
        core.atomic_write(DELIVERED, b"", 0o644)
        return
    if not core.is_hex(digest, 64):
        core.refuse("node-release", "arguments")
    if os.path.lexists(DELIVERED):
        core.refuse("node-release", "claim-delivered")
    core.atomic_write(CLAIM, (digest + "\n").encode("ascii"), 0o440, (0, grp.getgrnam(SERVICE_USER).gr_gid))
    if system(["systemctl", "is-active", "--quiet", SERVICE], check=False).returncode == 0:
        restart_supervisor()


def hosts_text(policy):
    lines = [address + " " + provider["host"] + "\n" for provider in policy["providers"] for address in provider["addresses"]]
    return HOSTS_BEGIN + "".join(lines) + HOSTS_END if lines else ""


def set_hosts(policy):
    """Provider names resolve to the pinned addresses; the firewall lets the service user open no DNS connection."""
    current = core.read_regular(HOSTS, 1 << 20, "node-release").decode("utf-8")
    if current.count(HOSTS_BEGIN) != current.count(HOSTS_END) or current.count(HOSTS_BEGIN) > 1:
        core.refuse("node-release", "hosts-markers")
    if HOSTS_BEGIN in current:
        head, rest = current.split(HOSTS_BEGIN)
        current = head + rest.split(HOSTS_END, 1)[1]
    text = current + ("" if current.endswith("\n") or not current else "\n") + hosts_text(policy)
    with open(HOSTS, "w", encoding="utf-8") as target:  # /etc/hosts can be a mount point: keep the inode
        target.write(text)


def egress(path):
    """Replace the egress policy with a newer epoch, reload the rules, and restart the supervisor."""
    policy = core.validate_policy(core.read_regular(path, 256 * 1024, "node-release"))
    before = core.read_regular(EGRESS, 256 * 1024, "node-release")
    if policy["epoch"] <= core.validate_policy(before)["epoch"]:
        core.refuse("node-release", "epoch-stale")
    hosts_before = core.read_regular(HOSTS, 1 << 20, "node-release")
    try:
        core.atomic_write(EGRESS, core.canonical(policy), 0o644)
        set_hosts(policy)
        system(["systemctl", "restart", "aukora-egress.service"])
    except (core.Refusal, OSError):
        # The supervisor requires the egress unit, so a failed reload can leave both stopped: put the old policy back.
        core.atomic_write(EGRESS, before, 0o644)
        with open(HOSTS, "wb") as target:
            target.write(hosts_before)
        system(["systemctl", "restart", "aukora-egress.service"], check=False)
        restart_supervisor(check=False)
        raise
    restart_supervisor(check=False)  # it reads the policy at start; its own health is not this tool's to judge
    os.unlink(path)


def status():
    active = read_active()
    print(json.dumps({"current": link_id(CURRENT), "previous": link_id(PREVIOUS), "active": active,
                      "claim_delivered": os.path.lexists(DELIVERED)}, sort_keys=True))


# ---- command line --------------------------------------------------------------------------------------------

def interrupted(_number, _frame):
    raise KeyboardInterrupt


def options(argv, allowed):
    found = {}
    index = 0
    while index < len(argv):
        flag = argv[index]
        if flag not in allowed or flag in found:
            core.refuse("node-release", "usage")
        if allowed[flag]:
            if index + 1 >= len(argv):
                core.refuse("node-release", "usage")
            found[flag], index = argv[index + 1], index + 2
        else:
            found[flag], index = True, index + 1
    return found


def main(argv):
    if os.geteuid() != 0:
        core.refuse("node-release", "root-required")
    if not argv:
        core.refuse("node-release", "usage")
    command, rest = argv[0], argv[1:]
    if command == "stage":
        found = options(rest, {"--stage": True})
        if "--stage" not in found:
            core.refuse("node-release", "usage")
        rid, manifest = stage(found["--stage"])
        print(json.dumps({"id": rid, "commit": manifest["commit"]}, sort_keys=True))
    elif command == "switch":
        found = options(rest, {"--id": True, "--release": True, "--pointer-sha256": True, "--seq": True,
                               "--probe-seconds": True})
        try:
            seq, seconds = int(found.get("--seq", "")), int(found.get("--probe-seconds", PROBE_SECONDS))
        except ValueError:
            core.refuse("node-release", "arguments")
        if not 10 <= seconds <= 1800:
            core.refuse("node-release", "arguments")
        for number in (signal.SIGTERM, signal.SIGHUP):
            signal.signal(number, interrupted)  # the switch rolls back on an interrupt, as it does on a failed probe
        result = switch(found.get("--id", ""), found.get("--release", ""), found.get("--pointer-sha256", ""), seq, seconds)
        print(json.dumps({"result": result}, sort_keys=True))
        return 0 if result == "switched" else 3
    elif command == "claim":
        found = options(rest, {"--digest": True, "--delivered": False})
        if ("--digest" in found) == ("--delivered" in found):
            core.refuse("node-release", "usage")
        claim(found.get("--digest"), "--delivered" in found)
    elif command == "egress":
        found = options(rest, {"--policy": True})
        if "--policy" not in found:
            core.refuse("node-release", "usage")
        egress(found["--policy"])
    elif command == "status":
        status()
    else:
        core.refuse("node-release", "usage")
    return 0


if __name__ == "__main__":
    core.run_main("node-release", main)
