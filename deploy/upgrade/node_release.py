# SPDX-License-Identifier: AGPL-3.0-or-later
"""Runs as root on a node (rows 80, 131): stage a verified release, switch to it with a probe and an automatic
rollback, deliver the one-time claim commitment, replace the egress policy.

A release lives in /opt/aukora/releases/<id> and is never modified after it is verified. The switch changes one
symbolic link and restarts the supervisor; it never touches node state, and a rollback restores the previous release
and never any data (Aura has no rollback, and a restored snapshot could revive a spent approval). Before replacing
a link it verifies the exact pointer against the node's current owner binding, installation identity and clock,
and durably spends its sequence. Failed switches and rollback do not restore spent sequences."""
from __future__ import annotations

import fcntl
import base64
import grp
import hashlib
import http.client
import json
import os
import pwd
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass

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
INSTANCE = STATE + "/instance.json"
SEQUENCE = STATE + "/sequence.json"
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
    sync_directory(os.path.dirname(link))


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


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
    if (type(active["v"]) is not int or active["v"] != 1 or not isinstance(active["id"], str)
            or RELEASE_ID.fullmatch(active["id"]) is None or not core.is_hex(active["commit"], 40)
            or not core.is_hex(active["release"], 64) or not core.is_int(active["seq"])
            or not core.is_int(active["activated_at_ms"])
            or active["id"] != active["commit"][:12] + "-" + active["release"][:12]
            or (active["pointer_sha256"] is not None if active["seq"] == 0
                else not core.is_hex(active["pointer_sha256"], 64))):
        core.refuse("node-release", "active-invalid")
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

def protected_record(path, keys):
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077 or info.st_nlink != 1:
        core.refuse("node-release", "release-state")
    raw = core.read_regular(path, 4096, "node-release")
    record = core.parse_json(raw, "node-release", 4096)
    core.exact_keys(record, keys, "node-release", "release-state")
    if core.canonical(record) != raw:
        core.refuse("node-release", "release-state")
    return record


def installation(node):
    record = protected_record(INSTANCE, ("schema", "node", "instance"))
    if (record["schema"] != "aukora-node-instance-v1" or record["node"] != node
            or not core.is_node_name(node) or not core.is_hex(record["instance"], 64)):
        core.refuse("node-release", "instance-invalid")
    return record["instance"]


def read_sequence(instance, active):
    record = protected_record(SEQUENCE, ("schema", "instance", "seq", "pointer_sha256"))
    if (record["schema"] != "aukora-release-sequence-v1" or record["instance"] != instance
            or not core.is_int(record["seq"], active["seq"])
            or (record["pointer_sha256"] is not None if record["seq"] == 0
                else not core.is_hex(record["pointer_sha256"], 64))
            or (record["seq"] == active["seq"] and record["pointer_sha256"] != active["pointer_sha256"])):
        core.refuse("node-release", "sequence-invalid")
    return record["seq"]


@contextmanager
def switch_lock():
    directory = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    lock = None
    try:
        info = os.fstat(directory)
        if info.st_uid != 0 or info.st_mode & 0o022:
            core.refuse("node-release", "release-state")
        lock = os.open("switch.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077 or info.st_nlink != 1:
            core.refuse("node-release", "release-state")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            core.refuse("node-release", "switch-busy")
        yield
    finally:
        if lock is not None:
            os.close(lock)
        os.close(directory)


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


def switch(rid, digest, pointer_path, assertion_path, seconds):
    with switch_lock():
        return authorized_switch(rid, digest, pointer_path, assertion_path, seconds)


def authorized_switch(rid, digest, pointer_path, assertion_path, seconds):
    directory, manifest = verified_release(rid, digest)
    active = read_active()
    if active is None:
        core.refuse("node-release", "not-installed")
    old = link_id(CURRENT)
    if old is None or old != active["id"]:
        core.refuse("node-release", "not-installed")
    config = node_config()
    instance = installation(config.get("node"))
    last_seq = read_sequence(instance, active)
    binary = os.path.realpath(os.path.join(directory, "bin", "sovereign"))
    previous_before = link_id(PREVIOUS)
    flipped = old != rid
    verifier = trusted_verifier(old, active)
    rollback_needed = False
    try:
        with node_authorization(verifier, pointer_path, assertion_path, config, instance) as found:
            if found.commit != manifest["commit"] or found.release != digest:
                core.refuse("node-release", "pointer-release")
            if found.seq <= last_seq:
                core.refuse("node-release", "pointer-replayed")
            require_live(found)
            record = {"schema": "aukora-release-sequence-v1", "instance": instance, "seq": found.seq,
                      "pointer_sha256": found.sha256}
            core.atomic_write(SEQUENCE, core.canonical(record), 0o600)
            rollback_needed = True
            if flipped:
                point(PREVIOUS, "releases/" + old)
                require_live(found)
                point(CURRENT, "releases/" + rid)
        if flipped:
            apply_units(directory)
        restart_supervisor()
        healthy = probe(config, binary, manifest["files"]["bin/sovereign"]["sha256"], seconds)
        if healthy:
            write_active(rid, manifest, digest, found.seq, found.sha256)
            return "switched"
    except (core.Refusal, OSError, KeyboardInterrupt, subprocess.SubprocessError):
        if not rollback_needed:
            raise
    rollback_switch(old, previous_before, active, flipped)
    return "rolled-back" if flipped else "failed"


def rollback_switch(old, previous_before, active, flipped):
    """Attempt each restoration even if another fails; the spent sequence is never restored."""
    actions = []
    if flipped:
        actions.extend((lambda: point(CURRENT, "releases/" + old), lambda: restore_previous(previous_before)))
    # ACTIVE may have been renamed before its write/fsync failed.
    actions.append(lambda: core.atomic_write(ACTIVE, core.canonical(active), 0o644))
    if flipped:
        actions.extend((lambda: apply_units(os.path.join(RELEASES, old)), restart_supervisor))
    failed = False
    for action in actions:
        try:
            action()
        except (core.Refusal, OSError, KeyboardInterrupt):
            failed = True
    if failed:
        core.refuse("node-release", "rollback-failed")


def restore_previous(previous_before):
    if previous_before is not None:
        point(PREVIOUS, "releases/" + previous_before)
    else:
        try:
            os.unlink(PREVIOUS)
        except FileNotFoundError:
            pass
        else:
            sync_directory(os.path.dirname(PREVIOUS))


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
                      "instance": installation(node_config().get("node")),
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
        found = options(rest, {"--id": True, "--release": True, "--pointer": True, "--assertion": True,
                               "--probe-seconds": True})
        try:
            seconds = int(found.get("--probe-seconds", PROBE_SECONDS))
        except ValueError:
            core.refuse("node-release", "arguments")
        if not 10 <= seconds <= 1800:
            core.refuse("node-release", "arguments")
        if not all(flag in found for flag in ("--id", "--release", "--pointer", "--assertion")):
            core.refuse("node-release", "arguments")
        for number in (signal.SIGTERM, signal.SIGHUP):
            signal.signal(number, interrupted)  # the switch rolls back on an interrupt, as it does on a failed probe
        result = switch(found["--id"], found["--release"], found["--pointer"], found["--assertion"], seconds)
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


POINTER_SCHEMA = "aukora-release-pointer-v2"
ASSERTION_SCHEMA = "aukora-release-assertion-v1"
DOMAIN = b"aukora:release-pointer:v2"
ES256, EDDSA = -7, -8
# SubjectPublicKeyInfo header of a P-256 key, followed by the 65-byte uncompressed point.
P256_SPKI = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
ED25519_SPKI = bytes.fromhex("302a300506032b6570032100")
FLAG_UP, FLAG_UV, FLAG_AT, FLAG_ED = 0x01, 0x04, 0x40, 0x80


@dataclass(frozen=True)
class Pointer:
    node: str
    instance: str
    commit: str
    release: str
    seq: int
    not_after: int
    sha256: str  # of the pointer bytes


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64url(text, reason):
    """Strict unpadded base64url that re-encodes to the same text."""
    if not isinstance(text, str) or re.fullmatch("[A-Za-z0-9_-]*", text) is None or len(text) % 4 == 1:
        core.refuse("upgrade", reason)
    try:
        data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError:
        core.refuse("upgrade", reason)
    if b64url(data) != text:
        core.refuse("upgrade", reason)
    return data


def challenge(pointer_bytes):
    return b64url(hashlib.sha256(DOMAIN + b"\x00" + pointer_bytes).digest())


def es256_verify(spki, message, signature):
    if (not spki.startswith(P256_SPKI) or len(spki) != len(P256_SPKI) + 65 or spki[len(P256_SPKI)] != 4):
        core.refuse("upgrade", "pointer-key")
    openssl = shutil.which("openssl")
    if openssl is None:
        core.refuse("upgrade", "openssl-missing")
    encoded = base64.b64encode(spki).decode("ascii")
    pem = "-----BEGIN PUBLIC KEY-----\n" + "\n".join(encoded[i:i + 64] for i in range(0, len(encoded), 64)) \
        + "\n-----END PUBLIC KEY-----\n"
    with tempfile.TemporaryDirectory(prefix="aukora-pointer-") as scratch:
        for name, data in (("key.pem", pem.encode("ascii")), ("message", message), ("signature", signature)):
            with open(os.path.join(scratch, name), "wb") as target:
                target.write(data)
        done = subprocess.run([openssl, "dgst", "-sha256", "-verify", os.path.join(scratch, "key.pem"),
                               "-signature", os.path.join(scratch, "signature"), os.path.join(scratch, "message")],
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if done.returncode != 0 or done.stdout.strip() != b"Verified OK":
        core.refuse("upgrade", "pointer-signature")


def ed25519_verify(spki, message, signature):
    if not spki.startswith(ED25519_SPKI) or len(spki) != len(ED25519_SPKI) + 32 or len(signature) != 64:
        core.refuse("upgrade", "pointer-key")
    openssl = shutil.which("openssl")
    if openssl is None:
        core.refuse("upgrade", "openssl-missing")
    with tempfile.TemporaryDirectory(prefix="aukora-pointer-") as scratch:
        for name, data in (("key.der", spki), ("message", message), ("signature", signature)):
            with open(os.path.join(scratch, name), "wb") as target:
                target.write(data)
        done = subprocess.run([openssl, "pkeyutl", "-verify", "-pubin", "-keyform", "DER",
                               "-inkey", os.path.join(scratch, "key.der"), "-rawin",
                               "-in", os.path.join(scratch, "message"),
                               "-sigfile", os.path.join(scratch, "signature")],
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if done.returncode != 0:
        core.refuse("upgrade", "pointer-signature")


def read_pointer(raw, node, instance=None):
    """Parse only the v2 outer schema; not_after is exclusive Unix milliseconds."""
    document = core.parse_json(raw, "upgrade", 4096)
    core.exact_keys(document, ("schema", "body"), "upgrade", "pointer")
    if core.canonical(document) != raw:
        core.refuse("upgrade", "pointer-not-canonical")
    body = core.exact_keys(document["body"], ("node", "instance", "commit", "release", "seq", "not_after"),
                           "upgrade", "pointer")
    if (document["schema"] != POINTER_SCHEMA or body["node"] != node or not core.is_node_name(node)
            or not core.is_hex(body["instance"], 64) or not core.is_hex(body["commit"], 40)
            or not core.is_hex(body["release"], 64) or not core.is_int(body["seq"], 1)
            or not core.is_int(body["not_after"], 1)):
        core.refuse("upgrade", "pointer")
    if instance is not None and body["instance"] != instance:
        core.refuse("upgrade", "pointer-instance")
    found = Pointer(node, body["instance"], body["commit"], body["release"], body["seq"],
                    body["not_after"], core.sha256_hex(raw))
    require_live(found)
    return found


def require_live(found):
    if time.time_ns() // 1_000_000 >= found.not_after:
        core.refuse("upgrade", "pointer-expired")


def read_assertion(assertion_path):
    assertion = core.parse_json(core.read_regular(assertion_path, 16384, "upgrade"), "upgrade", 16384)
    core.exact_keys(assertion, ("schema", "credential_id", "authenticator_data", "client_data_json", "signature"),
                    "upgrade", "pointer-assertion")
    return assertion


def client_data(raw):
    """WebAuthn JSON permits decimals; it is separate from the canonical pointer parser."""
    if len(raw) > 8192:
        core.refuse("upgrade", "pointer-client-data")

    def pairs(entries):
        result = {}
        for key, value in entries:
            if key in result:
                core.refuse("upgrade", "pointer-client-data")
            result[key] = value
        return result

    def constant(_value):
        core.refuse("upgrade", "pointer-client-data")

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        core.refuse("upgrade", "pointer-client-data")


def verify_bytes(raw, assertion, credential, node, instance=None):
    found = read_pointer(raw, node, instance)
    if assertion["schema"] != ASSERTION_SCHEMA or unb64url(assertion["credential_id"], "pointer-assertion") != credential["_id"]:
        core.refuse("upgrade", "pointer-assertion")
    authenticator = unb64url(assertion["authenticator_data"], "pointer-assertion")
    client_bytes = unb64url(assertion["client_data_json"], "pointer-assertion")
    signature = unb64url(assertion["signature"], "pointer-assertion")
    client = client_data(client_bytes)
    if not isinstance(client, dict) or client.get("type") != "webauthn.get":
        core.refuse("upgrade", "pointer-client-data")
    if client.get("challenge") != challenge(raw) or client.get("origin") != credential["origin"]:
        core.refuse("upgrade", "pointer-client-data")
    top = credential["top_origin"]
    if top is not None:
        framed = client.get("crossOrigin") is True and client.get("topOrigin") == top
    else:
        framed = ("crossOrigin" not in client or client["crossOrigin"] is False) and "topOrigin" not in client
    if not framed:
        core.refuse("upgrade", "pointer-client-data")
    if len(authenticator) != 37 or authenticator[:32] != hashlib.sha256(credential["rp_id"].encode("ascii")).digest():
        core.refuse("upgrade", "pointer-authenticator")
    flags = authenticator[32]
    if not flags & FLAG_UP or not flags & FLAG_UV or flags & (FLAG_AT | FLAG_ED):
        core.refuse("upgrade", "pointer-authenticator")
    message = authenticator + hashlib.sha256(client_bytes).digest()
    if credential["alg"] == ES256:
        es256_verify(credential["_spki"], message, signature)
    elif credential["alg"] == EDDSA:
        ed25519_verify(credential["_spki"], message, signature)
    else:
        core.refuse("upgrade", "pointer-key")
    require_live(found)
    return found


def trusted_verifier(old, active):
    """Select and hash the currently installed binary before any link changes."""
    directory, manifest = verified_release(old, active["release"])
    if manifest["commit"] != active["commit"]:
        core.refuse("node-release", "not-installed")
    binary = os.path.join(directory, "bin", "sovereign")
    info = os.lstat(binary)
    entry = manifest["files"]["bin/sovereign"]
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
            or info.st_size != entry["bytes"] or core.sha256_file(binary) != entry["sha256"]):
        core.refuse("node-release", "not-installed")
    return binary


@contextmanager
def node_authorization(binary, pointer_path, assertion_path, config, instance):
    """Keep the installed verifier's Aura reservation until the caller has spent and switched."""
    raw = core.read_regular(pointer_path, 4096, "upgrade")
    found = read_pointer(raw, config.get("node"), instance)
    expected = core.canonical(vars(found))
    process = subprocess.Popen(
        [binary, "release", "verify-pointer", "--config", NODE_JSON,
         "--pointer", pointer_path, "--assertion", assertion_path],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        ready, _, _ = select.select([process.stdout], [], [], 30)
        if not ready or process.stdout.readline(4097) != expected + b"\n" or process.poll() is not None:
            core.refuse("upgrade", "owner-binding")
        yield found
        process.stdin.write(b"release\n")
        process.stdin.flush()
        process.stdin.close()
        if process.wait(timeout=10) != 0:
            core.refuse("upgrade", "owner-binding")
    except subprocess.TimeoutExpired:
        core.refuse("upgrade", "owner-binding")
    finally:
        # EOF or termination releases the read reservation, including on interruption during cleanup.
        try:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=10)
        finally:
            process.stdin.close()
            process.stdout.close()


if __name__ == "__main__":
    core.run_main("node-release", main)
