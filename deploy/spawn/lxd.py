# SPDX-License-Identifier: AGPL-3.0-or-later
"""The host-lxd backend (row 73): a container on the LXD host, run as root on that host.

The container is unprivileged with an isolated id map. Packages are downloaded on the host against the
container's package state, including when its profile supplies no network interface. The frontdoor's loopback
port is published on the host's loopback by a proxy device, and the host's Caddy block points at that port."""
from __future__ import annotations

import json
import os
import re
import socket
import stat
import time

import caddy
import core
import release

IMAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}\Z")
FRONTDOOR_PORT = 18080
READY_ATTEMPTS = 60
PACKAGE = re.compile(r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?\Z")
ARCH = re.compile(r"[a-z0-9][a-z0-9-]*\Z")
VERSION = re.compile(r"[0-9][A-Za-z0-9.+:~\-]*\Z")
PACKAGE_ROW = re.compile(r"(Inst|Conf) (\S+)(?: \[[^\]\r\n]+\])? \((\S+)(?: ([^\r\n]*))?\)(?: \[[^\r\n]*\])?\Z")
PLATFORM_QUERY = """import json, os, shlex
fields = {}
with open(os.path.join(os.sep, 'etc', 'os-release'), encoding='utf-8') as source:
    for line in source:
        key, separator, value = line.strip().partition('=')
        if separator and key in ('ID', 'VERSION_ID'):
            words = shlex.split(value)
            if key in fields or len(words) != 1:
                raise SystemExit(1)
            fields[key] = words[0]
print(json.dumps(fields))
"""


def package_platform(runner):
    raw = runner.run(["python3", "-B", "-c", PLATFORM_QUERY]).stdout
    platform = core.parse_json(raw, "spawn", 4096)
    core.exact_keys(platform, ("ID", "VERSION_ID"), "spawn", "package-platform")
    if any(not isinstance(value, str) or not value for value in platform.values()):
        core.refuse("spawn", "package-platform")
    arch = runner.run(["dpkg", "--print-architecture"]).stdout.decode("ascii", "replace").strip()
    if not ARCH.fullmatch(arch) or arch == "all":
        core.refuse("spawn", "package-platform")
    return platform, arch


def package_plan(output, arch):
    """Read APT's C-locale simulation; removals and foreign architectures are refused."""
    found, configured, steps = {}, set(), []
    for line in output.decode("utf-8", "replace").splitlines():
        if line.startswith("Remv "):
            core.refuse("spawn", "package-removal")
        if not line.startswith(("Inst ", "Conf ")):
            continue
        row = PACKAGE_ROW.fullmatch(line)
        if row is None:
            core.refuse("spawn", "package-plan")
        action, name, version, origin = row.groups()
        if not PACKAGE.fullmatch(name) or not VERSION.fullmatch(version):
            core.refuse("spawn", "package-plan")
        base, separator, qualifier = name.partition(":")
        target = re.search(r"\[([a-z0-9][a-z0-9-]*)\]\Z", origin or "")
        target = target.group(1) if target else qualifier if separator else arch
        if target not in (arch, "all") or (separator and qualifier not in (target, arch)):
            core.refuse("spawn", "package-plan")
        if action == "Inst":
            if base in found or base in configured:
                core.refuse("spawn", "package-plan")
            found[base] = (target, version)
            op, token = "unpack", base
        else:
            if base in configured or (base in found and found[base] != (target, version)):
                core.refuse("spawn", "package-plan")
            configured.add(base)
            op, token = "configure", base + (":" + target if target != "all" else "")
        if not steps or steps[-1]["op"] != op:
            steps.append({"op": op, "packages": []})
        steps[-1]["packages"].append(token)
        if len(found) > 512 or len(configured) > 512:
            core.refuse("spawn", "package-plan")
    if not set(found) <= configured:
        core.refuse("spawn", "package-plan")
    return found, steps


def stage_packages(plan, node):
    """Resolve against the container's dpkg status, download on the host, then push only that package set."""
    stage = release.NODE_STAGE
    raw = node.run(["python3", "-B", stage + "/node_install.py", "--missing-packages", "lxd"]).stdout
    missing = core.parse_json(raw, "spawn", 16 * 1024)
    if (not isinstance(missing, list) or len(missing) > 512
            or any(not isinstance(name, str) or not PACKAGE.fullmatch(name) for name in missing)
            or len(set(missing)) != len(missing)):
        core.refuse("spawn", "package-query")
    destination = stage + "/packages"
    if not missing:
        node.run(["mkdir", "-m", "0700", "--", destination])
        return
    platform, arch = package_platform(node)
    if package_platform(plan.host) != (platform, arch):
        core.refuse("spawn", "package-platform-mismatch")
    snapshot = node.run(["dpkg-query", "--status"]).stdout
    if not snapshot or len(snapshot) > 32 * 1024 * 1024:
        core.refuse("spawn", "package-query")
    status = os.path.join(plan.scratch, "dpkg-status")
    extended = os.path.join(plan.scratch, "apt-extended-states")
    core.atomic_write(status, snapshot, 0o600)
    core.atomic_write(extended, b"", 0o600)
    options = ["-o", "Dir::State::status=" + status, "-o", "Dir::State::extended_states=" + extended,
               "-o", "Dir::Cache::pkgcache=", "-o", "Dir::Cache::srcpkgcache=",
               "-o", "APT::Architecture=" + arch, "-o", "APT::Get::AllowUnauthenticated=false"]
    plan.host.run(["env", "LC_ALL=C", "apt-get", "update", "-o", "DPkg::Lock::Timeout=600"])
    solved = plan.host.run(["env", "LC_ALL=C", "apt-get"] + options
                           + ["-s", "--reinstall", "--no-remove", "--no-install-recommends", "install", "--"] + missing)
    packages, steps = package_plan(solved.stdout, arch)
    if not packages or any(name.split(":", 1)[0] not in packages for name in missing):
        core.refuse("spawn", "package-plan")
    directory = os.path.join(plan.scratch, "packages")
    os.mkdir(directory, 0o700)
    requests = [name + (":" + target if target != "all" else "") + "=" + version
                for name, (target, version) in sorted(packages.items())]
    plan.host.run(["env", "--chdir=" + directory, "LC_ALL=C", "apt-get"] + options + ["download", "--"] + requests)
    files, seen, total = [], {}, 0
    for filename in sorted(os.listdir(directory)):
        path = os.path.join(directory, filename)
        info = os.lstat(path)
        if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+:_%~-]*\.deb", filename)
                or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or not 0 < info.st_size <= 256 * 1024 * 1024):
            core.refuse("spawn", "package-download")
        total += info.st_size
        if total > 1024 * 1024 * 1024:
            core.refuse("spawn", "package-download")
        metadata = plan.host.run(["dpkg-deb", "--show", "--showformat=${Package}\\t${Architecture}\\t${Version}", path])
        fields = metadata.stdout.decode("ascii", "replace").split("\t")
        if len(fields) != 3:
            core.refuse("spawn", "package-download")
        name, target, version = fields
        wanted = packages.get(name)
        if (name in seen or wanted is None or version != wanted[1]
                or target not in (wanted[0], "all") or target not in (arch, "all")):
            core.refuse("spawn", "package-download")
        seen[name] = (filename, target)
        files.append((path, filename))
    if set(seen) != set(packages):
        core.refuse("spawn", "package-download")
    for step in steps:
        if step["op"] == "unpack":
            step["packages"] = [seen[name][0] for name in step["packages"]]
        else:
            for index, token in enumerate(step["packages"]):
                name = token.split(":", 1)[0]
                if name in seen:
                    target = seen[name][1]
                    step["packages"][index] = name + (":" + target if target != "all" else "")
    order = os.path.join(plan.scratch, "package-plan.json")
    core.atomic_write(order, core.canonical({"schema": "aukora-package-plan-v1", "steps": steps}), 0o600)
    node.run(["mkdir", "-m", "0700", "--", destination])
    for path, filename in files:
        node.push(path, destination + "/" + filename)
    node.push(order, stage + "/package-plan.json")


class Transport:
    """Run a command as root inside the node, and put a file there."""

    def __init__(self, host, instance):
        self.host, self.instance = host, instance

    def run(self, argv, check=True):
        return self.host.run(["lxc", "exec", self.instance, "--"] + list(argv), None, check)

    def push(self, local, remote):
        self.host.run(["lxc", "file", "push", local, self.instance + remote, "--mode", "0600", "--uid", "0", "--gid", "0"])


def inventory(host):
    try:
        items = json.loads(host.text(["lxc", "list", "--format", "json"]))
    except ValueError:
        core.refuse("spawn", "inventory-invalid")
    if not isinstance(items, list):
        core.refuse("spawn", "inventory-invalid")
    return items


def find(items, instance, node_id):
    """The inventory row for instance if it is ours, None if absent. A foreign container of that name is a refusal."""
    mine = [item for item in items if isinstance(item, dict) and item.get("name") == instance]
    if not mine:
        return None
    config = mine[0].get("config")
    if len(mine) != 1 or not isinstance(config, dict) or config.get("user.aukora.spawn-id") != node_id:
        core.refuse("spawn", "identity-mismatch")
    return mine[0]


def devices(host, instance):
    # lxc 5.21 shows instance config only as YAML; the instance API answers in JSON.
    try:
        return json.loads(host.text(["lxc", "query", "/1.0/instances/" + instance])).get("expanded_devices", {})
    except (ValueError, AttributeError):
        core.refuse("spawn", "inventory-invalid")


def ensure_device(host, instance, name, kind, settings):
    current = devices(host, instance).get(name)
    wanted = dict(settings, type=kind)
    if current is None:
        host.run(["lxc", "config", "device", "add", instance, name, kind] + [k + "=" + v for k, v in settings.items()])
    elif any(current.get(k) != v for k, v in wanted.items()):
        core.refuse("spawn", "device-conflict")


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def wait_ready(node):
    for _attempt in range(READY_ATTEMPTS):
        if node.run(["true"], check=False).returncode == 0:
            # 0 is done; 2 is done with a recoverable warning.
            if node.run(["cloud-init", "status", "--wait"], check=False).returncode in (0, 2):
                return
        time.sleep(2)
    core.refuse("spawn", "container-not-ready")


def provision(plan):
    """Create or resume the container and its ingress. Returns the Transport; install and claim follow."""
    host, state, instance = plan.host, plan.state, plan.instance
    if not IMAGE.match(plan.image):
        core.refuse("spawn", "image-invalid")
    caddy.preflight(plan.name, plan.shell_host, plan.owner_host)
    row = find(inventory(host), instance, plan.node_id)
    if row is None:
        if state.has("initialized"):
            core.refuse("spawn", "container-missing")
        host.run(["lxc", "init", plan.image, instance, "--config", "security.nesting=true",
                  "--config", "security.privileged=false", "--config", "security.idmap.isolated=true",
                  "--config", "security.idmap.size=262144", "--config", "user.aukora.spawn-id=" + plan.node_id])
        state.mark("initialized")
        row = {"status": "Stopped"}
    if row.get("status") != "Running":
        host.run(["lxc", "start", instance])
    node = Transport(host, instance)
    wait_ready(node)
    return node


def expose(plan):
    """Publish the frontdoor on the host's loopback and put the node's Caddy block in front of it."""
    state = plan.state
    caddy.preflight(plan.name, plan.shell_host, plan.owner_host)
    if not state.has("port"):
        state.put("port", str(free_port()))
    port = int(state.get("port"))
    if not 1024 <= port <= 65535:
        core.refuse("spawn", "state-invalid")
    ensure_device(plan.host, plan.instance, "ingress", "proxy",
                  {"bind": "host", "listen": "tcp:127.0.0.1:%d" % port, "connect": "tcp:127.0.0.1:%d" % FRONTDOOR_PORT})
    block = caddy.render_block(plan.name, plan.shell_host, plan.owner_host, "127.0.0.1:%d" % port)
    caddy.apply(plan.name, block, lambda argv: plan.host.run(argv, None, False).returncode)


def destroy(plan):
    host, instance = plan.host, plan.instance
    row = find(inventory(host), instance, plan.node_id)
    caddy.apply(plan.name, None, lambda argv: host.run(argv, None, False).returncode)
    if row is not None:
        if "ingress" in devices(host, instance):
            host.run(["lxc", "config", "device", "remove", instance, "ingress"])
        host.run(["lxc", "delete", instance, "--force"])


def transport_for(host, name, node_id):
    """For an existing node (upgrade): its Transport, after checking the container is ours and running."""
    instance = "aukora-" + name
    row = find(inventory(host), instance, node_id)
    if row is None or row.get("status") != "Running":
        core.refuse("upgrade", "node-not-running")
    return Transport(host, instance)


def require_root():
    if os.getuid() != 0:
        core.refuse("spawn", "root-required")
