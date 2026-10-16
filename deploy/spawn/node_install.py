# SPDX-License-Identifier: AGPL-3.0-or-later
"""Runs once as root on a new node (row 73): packages, the service account, the first release, the node
configuration, the units, and the first start. It refuses to touch a node that already has a configuration or a
release: an existing node changes only through deploy/upgrade.

The stage directory holds release.json, release.tar, node-input.json and egress.json, and this tool with the
modules it imports. An optional packages directory supplies the offline Debian packages. It writes no claim:
the one-time secret's commitment arrives afterwards from the operator
(node_release.py claim), and until then the node refuses every claim."""
from __future__ import annotations

import ctypes
from contextlib import contextmanager
import fcntl
import grp
import ipaddress
import json
import os
import pwd
import re
import secrets
import stat
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "upgrade"))
import caddy  # noqa: E402
import core  # noqa: E402
import node_release as release  # noqa: E402

PACKAGES = ("uidmap", "nftables", "ca-certificates", "python3", "openssl")
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


def missing_packages(packages):
    missing = []
    for package in packages:
        done = subprocess.run(["dpkg-query", "-W", "-f=${Status}", package], stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
        if done.returncode not in (0, 1):
            core.refuse("install", "package-query")
        if done.returncode != 0 or done.stdout != b"install ok installed":
            missing.append(package)
    return missing


def package_bundle(stage):
    directory = os.path.join(stage, "packages")
    if not os.path.lexists(directory):
        return None
    info = os.lstat(directory)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        core.refuse("install", "package-stage")
    paths, total = [], 0
    for name in sorted(os.listdir(directory)):
        path = os.path.join(directory, name)
        info = os.lstat(path)
        if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+:_%~-]*\.deb", name)
                or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                or info.st_nlink != 1 or not 0 < info.st_size <= 256 * 1024 * 1024):
            core.refuse("install", "package-stage")
        total += info.st_size
        paths.append(path)
        if len(paths) > 512 or total > 1024 * 1024 * 1024:
            core.refuse("install", "package-stage")
    return paths


def package_plan(stage, bundle):
    """Validate the host's apt operation order before changing the package database."""
    path = os.path.join(stage, "package-plan.json")
    try:
        info = os.lstat(path)
    except OSError:
        core.refuse("install", "package-plan")
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1):
        core.refuse("install", "package-plan")
    plan = core.parse_json(core.read_regular(path, 512 * 1024, "install"), "install", 512 * 1024)
    core.exact_keys(plan, ("schema", "steps"), "install", "package-plan")
    steps = plan["steps"]
    if (plan["schema"] != "aukora-package-plan-v1" or not isinstance(steps, list)
            or not 1 <= len(steps) <= 1024):
        core.refuse("install", "package-plan")
    archives, identities = {}, {}
    package_name = r"[a-z0-9][a-z0-9+.-]{1,127}"
    architecture = r"[a-z0-9][a-z0-9-]{0,63}"
    for archive in bundle:
        fields = run(["dpkg-deb", "--show", "--showformat=${Package}\t${Architecture}", archive]).stdout
        try:
            name, arch = fields.decode("ascii").split("\t")
        except (UnicodeError, ValueError):
            core.refuse("install", "package-plan")
        identity = name + ":" + arch
        if (not re.fullmatch(package_name, name) or not re.fullmatch(architecture, arch)
                or identity in identities):
            core.refuse("install", "package-plan")
        archives[os.path.basename(archive)] = (archive, identity)
        identities[identity] = name
    unpacked, operations, count = set(), [], 0
    for step in steps:
        core.exact_keys(step, ("op", "packages"), "install", "package-plan")
        action, packages = step["op"], step["packages"]
        if action not in ("unpack", "configure") or not isinstance(packages, list) or not 1 <= len(packages) <= 512:
            core.refuse("install", "package-plan")
        count += len(packages)
        if count > 2048:
            core.refuse("install", "package-plan")
        arguments = []
        for package in packages:
            if not isinstance(package, str):
                core.refuse("install", "package-plan")
            if action == "unpack":
                if package not in archives:
                    core.refuse("install", "package-plan")
                archive, identity = archives[package]
                if identity in unpacked:
                    core.refuse("install", "package-plan")
                unpacked.add(identity)
                arguments.append(archive)
                continue
            if not re.fullmatch(package_name + "(?::" + architecture + ")?", package):
                core.refuse("install", "package-plan")
            matches = [identity for identity, name in identities.items()
                       if package == identity or package == name]
            if matches:
                if len(matches) != 1 or matches[0] not in unpacked:
                    core.refuse("install", "package-plan")
            else:
                done = subprocess.run(["dpkg-query", "-W", "-f=${db:Status-Status}", package],
                                      stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, check=False)
                if done.returncode != 0 or done.stdout not in (
                        b"installed", b"unpacked", b"half-configured", b"triggers-awaited", b"triggers-pending"):
                    core.refuse("install", "package-plan")
            arguments.append(package)
        operations.append((action, arguments))
    if unpacked != set(identities):
        core.refuse("install", "package-plan")
    return operations


def network_available():
    """Require an up nonloopback interface with an address and a default route in the same family."""
    for family in ("-4", "-6"):
        values = []
        for args in (("address", "show"), ("route", "show", "default")):
            try:
                done = subprocess.run(["ip", family, "-json"] + list(args), stdin=subprocess.DEVNULL,
                                      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
                value = json.loads(done.stdout) if done.returncode == 0 else None
            except (OSError, ValueError):
                value = None
            if not isinstance(value, list):
                break
            values.append(value)
        if len(values) != 2:
            continue
        addresses, routes = values
        for interface in addresses:
            if not isinstance(interface, dict):
                continue
            flags, records = interface.get("flags"), interface.get("addr_info")
            if (not isinstance(flags, list) or "UP" not in flags or "LOOPBACK" in flags
                    or interface.get("operstate") not in ("UP", "UNKNOWN") or not isinstance(records, list)
                    or not isinstance(interface.get("ifname"), str) or interface["ifname"] == "lo"):
                continue
            for record in records:
                if (not isinstance(record, dict) or record.get("scope") != "global"
                        or not isinstance(record.get("local"), str)):
                    continue
                try:
                    address = ipaddress.ip_address(record.get("local", ""))
                except ValueError:
                    continue
                if (address.version != (4 if family == "-4" else 6) or address.is_loopback
                        or address.is_unspecified or address.is_link_local or address.is_multicast):
                    continue
                for route in routes:
                    if (isinstance(route, dict) and route.get("dst") == "default"
                            and route.get("dev") == interface.get("ifname")
                            and route.get("type", "unicast") == "unicast"
                            and isinstance(route.get("flags", []), list) and "linkdown" not in route.get("flags", [])):
                        return True
    return False


def ensure_packages(packages, stage):
    bundle = package_bundle(stage)
    missing = missing_packages(packages)
    if not missing:
        return
    environment = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    if bundle is not None:
        if not bundle:
            core.refuse("install", "packages-missing")
        operations = package_plan(stage, bundle)
        for action, arguments in operations:
            run(["dpkg", "--" + action] + arguments, environment)
        run(["dpkg", "--configure", "--pending"], environment)
    else:
        if not network_available():
            core.refuse("install", "packages-offline")
        # A new machine often runs its own package updates first; wait for the package lock instead of failing.
        wait = ["-o", "DPkg::Lock::Timeout=600"]
        run(["apt-get", "update"] + wait, environment)
        run(["apt-get", "install", "-y", "--no-install-recommends"] + wait + missing, environment)
    if missing_packages(packages):
        core.refuse("install", "packages-missing")


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


def require_unactivated_node():
    """Only an installation with no release, claim or supervisor state can resume."""
    for path in (release.NODE_JSON, release.CURRENT, release.PREVIOUS, release.ACTIVE,
                 release.DELIVERED, release.CLAIM):
        if os.path.lexists(path):
            core.refuse("install", "node-exists")
    state_root = os.path.join(os.path.dirname(release.STATE), USER)
    records = {os.path.basename(release.INSTANCE), os.path.basename(release.SEQUENCE), "install.lock"}
    for directory in (release.STATE, state_root):
        if not os.path.lexists(directory):
            continue
        info = os.lstat(directory)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            core.refuse("install", "node-exists")
        contents = set(os.listdir(directory))
        if contents - (records if directory == release.STATE else set()):
            core.refuse("install", "node-exists")


@contextmanager
def install_lock():
    """Serialize package, identity, release and configuration changes across installer processes."""
    os.makedirs(release.STATE, mode=0o755, exist_ok=True)
    directory = os.open(release.STATE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    lock = None
    try:
        info = os.fstat(directory)
        if info.st_uid != 0 or info.st_mode & 0o022:
            core.refuse("install", "node-exists")
        lock = os.open("install.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                       0o600, dir_fd=directory)
        info = os.fstat(lock)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o7777 != 0o600 or info.st_nlink != 1):
            core.refuse("install", "install-state")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            core.refuse("install", "install-busy")
        require_unactivated_node()
        yield directory
    finally:
        if lock is not None:
            os.close(lock)
        os.close(directory)


def initial_record(directory, path, keys):
    descriptor = os.open(os.path.basename(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                         dir_fd=directory)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or info.st_mode & 0o7777 != 0o600 or info.st_size > 4096):
            core.refuse("install", "install-state")
        raw = source.read(4097)
        os.fsync(source.fileno())
    record = core.parse_json(raw, "install", 4096)
    core.exact_keys(record, keys, "install", "install-state")
    if core.canonical(record) != raw:
        core.refuse("install", "install-state")
    return record


def sync_instance_directory(directory):
    os.fsync(directory)
    parent = os.open(os.path.dirname(release.STATE), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def retain_instance(directory, node):
    """A retry keeps both initial records exactly; incomplete or used records refuse."""
    entries = set(os.listdir(directory))
    retained = {os.path.basename(release.INSTANCE), os.path.basename(release.SEQUENCE)} & entries
    if retained:
        if len(retained) != 2:
            core.refuse("install", "install-state")
        identity = initial_record(directory, release.INSTANCE, ("schema", "node", "instance"))
        sequence = initial_record(directory, release.SEQUENCE, ("schema", "instance", "seq", "pointer_sha256"))
        if (identity["schema"] != "aukora-node-instance-v1" or identity["node"] != node["name"]
                or not core.is_hex(identity["instance"], 64)
                or sequence["schema"] != "aukora-release-sequence-v1"
                or sequence["instance"] != identity["instance"] or not core.is_int(sequence["seq"], 0, 0)
                or sequence["pointer_sha256"] is not None):
            core.refuse("install", "install-state")
        sync_instance_directory(directory)
        return
    instance = secrets.token_hex(32)
    records = (
        (release.INSTANCE, {"schema": "aukora-node-instance-v1", "node": node["name"], "instance": instance}),
        (release.SEQUENCE, {"schema": "aukora-release-sequence-v1", "instance": instance,
                            "seq": 0, "pointer_sha256": None}),
    )
    for path, document in records:
        descriptor = os.open(os.path.basename(path),
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=directory)
        try:
            core.write_all(descriptor, core.canonical(document))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    sync_instance_directory(directory)


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
    packages = package_bundle(stage)
    if packages is not None:
        for path in packages:
            os.unlink(path)
        os.rmdir(os.path.join(stage, "packages"))
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
    if len(argv) == 2 and argv[0] == "--missing-packages" and argv[1] in ("lxd", "vm"):
        packages = PACKAGES + (VM_PACKAGES if argv[1] == "vm" else ())
        sys.stdout.buffer.write(core.canonical(missing_packages(packages)))
        return 0
    if len(argv) != 4 or argv[0] != "--stage" or argv[2] != "--mode" or argv[3] not in ("lxd", "vm"):
        core.refuse("install", "usage")
    stage, mode = argv[1], argv[3]
    if not os.path.isabs(stage) or not os.path.isdir(stage) or os.path.islink(stage):
        core.refuse("install", "stage")
    os.umask(0o022)
    node = load_input(stage)
    policy_raw = core.read_regular(os.path.join(stage, "egress.json"), 256 * 1024, "install")
    policy = core.validate_policy(policy_raw)
    require_unactivated_node()
    if landlock_abi() < MIN_LANDLOCK_ABI:
        core.refuse("install", "landlock-abi")
    if not os.path.exists("/sys/fs/cgroup/cgroup.controllers"):
        core.refuse("install", "cgroup-v2")
    restricted = userns_restricted()
    if restricted and mode != "vm":
        core.refuse("install", "userns-policy")  # a container cannot load the profile that would allow it
    with install_lock() as directory:
        retain_instance(directory, node)
        return install_node(stage, mode, node, policy, restricted)


def install_node(stage, mode, node, policy, restricted):
    ensure_packages(PACKAGES + (VM_PACKAGES if mode == "vm" else ()), stage)
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
    # The supervisor refuses to start without an explicit gate target inventory; a new node starts with none, so the
    # gate refuses every change until a later, passkey-approved release adds targets.
    core.atomic_write(os.path.join(release.CONFIG, "gate-targets-v1.json"),
                      core.canonical({"kind": "aukora-gate-targets-v1", "node": node["name"], "targets": [], "v": 1}),
                      0o640, (0, gid))
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
