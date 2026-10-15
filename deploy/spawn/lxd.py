# SPDX-License-Identifier: AGPL-3.0-or-later
"""The host-lxd backend (row 73): a container on the LXD host, run as root on that host.

The container is unprivileged with an isolated id map (live-tested settings). It keeps its network interface;
what the node's service user may reach is decided inside the node by the egress policy, not by removing the
interface. The frontdoor's loopback port is published on the host's loopback by a proxy device, and the host's
Caddy block points at that port."""
from __future__ import annotations

import json
import os
import re
import socket
import time

import caddy
import core

IMAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}\Z")
FRONTDOOR_PORT = 18080
READY_ATTEMPTS = 60


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
