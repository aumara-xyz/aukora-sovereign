# SPDX-License-Identifier: AGPL-3.0-or-later
"""Runs once as root on a new node (row 73): packages, the service account, the first release, the node
configuration, the units, and the first start. It refuses to touch a node that already has a configuration or a
release: an existing node changes only through deploy/upgrade.

The stage directory holds release.json, release.tar, node-input.json and egress.json, and this tool with the
modules it imports. It writes no claim: the one-time secret's commitment arrives afterwards from the operator
(node_release.py claim), and until then the node refuses every claim."""
from __future__ import annotations

import ctypes
import grp
import ipaddress
import os
import pwd
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "upgrade"))
import caddy  # noqa: E402
import core  # noqa: E402
import node_release as release  # noqa: E402

PACKAGES = ("uidmap", "nftables", "ca-certificates", "python3")
VM_PACKAGES = ("caddy", "apparmor")
LISTEN = "127.0.0.1:18080"
USER = "aukora"
SUBORDINATE_COUNT = 65536
MIN_LANDLOCK_ABI = 4
USERNS_SYSCTL = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns"
PROFILE = "/etc/apparmor.d/aukora-sovereign"
CADDYFILE = "/etc/caddy/Caddyfile"
START_WAIT_SECONDS = 40


def run(argv, environment=None):
    done = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          env=environment, check=False)
    if done.returncode != 0:
        print("install: " + " ".join(argv[:3]) + " exited " + str(done.returncode) + "\n"
              + done.stderr[-300:].decode("utf-8", "replace"), file=sys.stderr)
        core.refuse("install", "command-failed")
    return done


def landlock_abi():
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    # landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION) answers with the ABI number.
    return libc.syscall(444, ctypes.c_void_p(0), ctypes.c_size_t(0), ctypes.c_uint(1))


def load_input(stage):
    data = core.parse_json(core.read_regular(os.path.join(stage, "node-input.json"), 4096, "install"), "install", 4096)
    core.exact_keys(data, ("name", "shell_host", "owner_host", "public_ip"), "install", "node-input")
    if not core.is_node_name(data["name"]) or not core.is_hostname(data["shell_host"]):
        core.refuse("install", "node-input")
    if data["owner_host"] != "owner." + data["shell_host"] or not core.is_hostname(data["owner_host"]):
        core.refuse("install", "node-input")
    if data["public_ip"] is not None:
        try:
            if not ipaddress.IPv4Address(data["public_ip"]).is_global:
                raise ValueError
        except ValueError:
            core.refuse("install", "node-input")
    return data


def ensure_packages(packages):
    missing = []
    for package in packages:
        done = subprocess.run(["dpkg-query", "-W", "-f=${Status}", package], stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
        if done.stdout != b"install ok installed":
            missing.append(package)
    if missing:
        environment = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
        # A new machine often runs its own package updates first; wait for the package lock instead of failing.
        wait = ["-o", "DPkg::Lock::Timeout=600"]
        run(["apt-get", "update"] + wait, environment)
        run(["apt-get", "install", "-y", "--no-install-recommends"] + wait + missing, environment)


def ensure_user():
    try:
        pwd.getpwnam(USER)
    except KeyError:
        run(["useradd", "--system", "--user-group", "--home-dir", "/var/lib/aukora", "--no-create-home",
             "--shell", "/usr/sbin/nologin", USER])


def subordinate_start():
    """First id of the service user's subordinate range, added after every existing range if it has none.
    The cage runs as that id, which is never the supervisor's own."""
    starts, highest = [], 100000
    for path in ("/etc/subuid", "/etc/subgid"):
        found = None
        try:
            lines = core.read_regular(path, 1 << 20, "install").decode("ascii", "replace").splitlines()
        except core.Refusal:
            lines = []
        for line in lines:
            parts = line.split(":")
            if len(parts) == 3 and parts[1].isdigit() and parts[2].isdigit():
                if parts[0] == USER and int(parts[2]) >= SUBORDINATE_COUNT:
                    found = int(parts[1])
                highest = max(highest, int(parts[1]) + int(parts[2]))
        starts.append(found)
    if starts[0] is None and starts[1] is None:
        end = highest + SUBORDINATE_COUNT - 1
        run(["usermod", "--add-subuids", "%d-%d" % (highest, end), "--add-subgids", "%d-%d" % (highest, end), USER])
        return highest
    if starts[0] != starts[1] or starts[0] is None:
        core.refuse("install", "subordinate-ids")
    return starts[0]


def make_dir(path, mode, group=None):
    os.makedirs(path, exist_ok=True)
    os.chmod(path, mode)
    os.chown(path, 0, grp.getgrnam(group).gr_gid if group else 0)


def userns_restricted():
    """Ubuntu can refuse unprivileged user namespaces to every program that has no AppArmor profile for them."""
    try:
        return core.read_regular(USERNS_SYSCTL, 16, "install").strip() == b"1"
    except core.Refusal:
        return False


def install_userns_profile():
    """A VM gets a profile that lets the supervisor, at its release path, create namespaces."""
    text = ("abi <abi/4.0>,\n"
            "include <tunables/global>\n"
            "profile aukora-sovereign /opt/aukora/releases/*/bin/sovereign flags=(unconfined) {\n  userns,\n}\n")
    core.atomic_write(PROFILE, text.encode("ascii"), 0o644)
    run(["apparmor_parser", "-r", PROFILE])


def configure_caddy(node):
    """A VM serves one node, so its Caddyfile is exactly that node's block."""
    block = caddy.render_block(node["name"], node["shell_host"], node["owner_host"], LISTEN)
    core.atomic_write(CADDYFILE, block.encode("utf-8"), 0o644, (0, 0))
    run(["caddy", "validate", "--config", CADDYFILE, "--adapter", "caddyfile"])
    run(["systemctl", "enable", "caddy"])
    run(["systemctl", "restart", "caddy"])


def node_config(node, cage_id):
    origin = "https://" + node["shell_host"]
    return core.canonical({
        "v": 1, "kind": "aukora-node-config-v1", "node": node["name"], "listen": LISTEN,
        "shell_origin": origin, "owner_origin": "https://" + node["owner_host"], "registered_site": origin,
        "proxy_peers": ["127.0.0.1", "::1"], "public_ip": node["public_ip"],
        "state_root": "/var/lib/aukora", "approved_release_root": release.CURRENT, "cage_root": "/run/aukora/cage",
        "cage_uid": cage_id, "cage_gid": cage_id,
        "claim_commitment": release.CLAIM, "egress_policy": release.EGRESS,
        "egress_status": "/run/aukora-egress/status.json", "release_state": release.ACTIVE})


def wait_active():
    steady = None
    for _attempt in range(START_WAIT_SECONDS):
        props = release.show(release.SERVICE)
        if props.get("ActiveState") == "active" and props.get("SubState") == "running":
            steady = steady or time.monotonic()
            if time.monotonic() - steady >= 5:
                return
        else:
            steady = None
        time.sleep(1)
    core.refuse("install", "service-not-active")


def clean(stage):
    for name in os.listdir(stage):
        path = os.path.join(stage, name)
        if os.path.isfile(path) and not os.path.islink(path):
            os.unlink(path)
    try:
        os.rmdir(stage)
    except OSError:
        pass


def main(argv):
    if os.geteuid() != 0:
        core.refuse("install", "root-required")
    if len(argv) != 4 or argv[0] != "--stage" or argv[2] != "--mode" or argv[3] not in ("lxd", "vm"):
        core.refuse("install", "usage")
    stage, mode = argv[1], argv[3]
    if not os.path.isabs(stage) or not os.path.isdir(stage) or os.path.islink(stage):
        core.refuse("install", "stage")
    os.umask(0o022)
    node = load_input(stage)
    policy_raw = core.read_regular(os.path.join(stage, "egress.json"), 256 * 1024, "install")
    policy = core.validate_policy(policy_raw)
    if os.path.lexists(release.NODE_JSON) or os.path.lexists(release.CURRENT):
        core.refuse("install", "node-exists")
    if landlock_abi() < MIN_LANDLOCK_ABI:
        core.refuse("install", "landlock-abi")
    if not os.path.exists("/sys/fs/cgroup/cgroup.controllers"):
        core.refuse("install", "cgroup-v2")
    restricted = userns_restricted()
    if restricted and mode != "vm":
        core.refuse("install", "userns-policy")  # a container cannot load the profile that would allow it
    ensure_packages(PACKAGES + (VM_PACKAGES if mode == "vm" else ()))
    if restricted:
        install_userns_profile()
    ensure_user()
    cage_id = subordinate_start()
    make_dir("/opt/aukora", 0o755)
    make_dir(release.STATE, 0o755)
    make_dir(release.CONFIG, 0o750, USER)
    rid, manifest = release.stage(stage)
    release.point(release.CURRENT, "releases/" + rid)
    digest = core.sha256_hex(core.read_regular(os.path.join(stage, "release.json"), core.MAX_MANIFEST_BYTES, "install"))
    release.write_active(rid, manifest, digest, 0, None)
    gid = grp.getgrnam(USER).gr_gid
    core.atomic_write(release.EGRESS, core.canonical(policy), 0o644, (0, 0))
    release.set_hosts(policy)
    if os.path.isdir("/etc/cloud/cloud.cfg.d"):
        core.atomic_write("/etc/cloud/cloud.cfg.d/99-aukora-hosts.cfg", b"manage_etc_hosts: false\n", 0o644)
    core.atomic_write(release.NODE_JSON, node_config(node, cage_id), 0o640, (0, gid))
    release.apply_units(os.path.join(release.RELEASES, rid))
    if mode == "vm":
        configure_caddy(node)
    run(["systemctl", "start", "aukora-egress.service", "aukora-egress-verify.timer"])
    run(["systemctl", "start", release.SERVICE])
    wait_active()
    clean(stage)
    return 0


if __name__ == "__main__":
    core.run_main("install", main)
