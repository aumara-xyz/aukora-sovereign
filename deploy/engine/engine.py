# SPDX-License-Identifier: AGPL-3.0-or-later
"""Operator side of the engine (deploy/engine/NODE.md). Nothing here runs by itself.

  python3 -B deploy/engine/engine.py pin FILE                 # sha256 and size of a downloaded or built artifact
  python3 -B deploy/engine/engine.py install NAME --stage DIR [--on nebius-vm] [--dry-run]
  python3 -B deploy/engine/engine.py install NAME --stage-on-node [--on nebius-vm] [--dry-run]
  python3 -B deploy/engine/engine.py egress NAME [--on nebius-vm] [--dry-run]

`install` adds the engine to a node that `spawn.sh create` installed: it pushes the stage folder (engine-plugins.tar
and the operator artifacts the pins name) and runs the release's own engine_install.py as root on the node. The node
name passes the deploy guard first, with the guard's `upgrade` admission (the engine changes an existing node, as an
upgrade does): a node in deploy/EXISTING-NODES is refused before any host command, cloud call or state read. Only
Nebius VM nodes: an LXD node shares its host's Caddy and has no Docker for OpenShell.

`egress` pins the door's allowlisted web_fetch hosts (`net.hosts` in door-policy-v1.json.in) in the node's egress
policy, as `--provider` pins the model provider: the names are resolved HERE, on the operator machine (spawn's rule:
the node never resolves), a new policy epoch keeps every relay and provider and adds the hosts, and the node's
`node_release.py egress` installs it (/etc/hosts lines, the firewall set, a supervisor restart). Without it an approved
web_fetch ends `resolve-failed` (NODE.md O10). `install` does the same first, and the node's installer refuses a policy
that lacks a door host. The engine's own DNS stays sealed: the hosts file is the node's, not the sandbox's.

`--stage-on-node` is for artifacts that never pass through the operator machine (about 1 GB, built on the artifact VM
of runbook A and copied VM to VM, NODE.md section 8): the stage is already at /root/aukora-engine-stage on the node
(root, 0700). Nothing is trusted for being there: the installer checks every artifact against the release's pins,
exactly as for a pushed stage."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, os.pardir, "spawn"))
sys.path.insert(0, os.path.join(HERE, os.pardir, "upgrade"))
import core  # noqa: E402
import guard  # noqa: E402

NODE_STAGE = "/root/aukora-engine-stage"
NODE_TOOL = "/opt/aukora/current/deploy/engine/engine_install.py"
STAGE_FILES = re.compile(r"(engine-plugins\.tar|dsh-engine-[0-9a-z.-]+\.tar\.gz|openshell-[0-9.]+-linux-x64\.tar\.gz|"
                         r"openshell-sandbox-image\.tar|rust-[0-9.]+-x86_64-unknown-linux-gnu\.tar\.gz)\Z")


def pin(path):
    digest, size = hashlib.sha256(), 0
    with open(path, "rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            digest.update(block)
            size += len(block)
    print(json.dumps({"file": os.path.basename(path), "sha256": digest.hexdigest(), "bytes": size}))
    return 0


def stage_files(stage):
    if not os.path.isabs(stage) or not os.path.isdir(stage) or os.path.islink(stage):
        core.refuse("engine", "stage")
    names = sorted(os.listdir(stage))
    if "engine-plugins.tar" not in names or any(STAGE_FILES.match(name) is None for name in names):
        core.refuse("engine", "stage-contents")
    for name in names:
        if os.path.islink(os.path.join(stage, name)) or not os.path.isfile(os.path.join(stage, name)):
            core.refuse("engine", "stage-contents")
    return names


DOOR_TEMPLATE = os.path.join(HERE, "door-policy-v1.json.in")
NODE_RELEASE = "/opt/aukora/current/deploy/upgrade/node_release.py"


def door_hosts():
    """The door's allowlisted web_fetch hosts, from this release's door policy template. Only https on 443 can be
    pinned (one port per pinned name)."""
    raw = core.read_regular(DOOR_TEMPLATE, 64 * 1024, "engine").replace(b"@AUMA_UID@", b"0")
    policy = core.parse_json(raw, "engine", 64 * 1024)
    if policy.get("classes", {}).get("net") == "deny":
        return []
    net = policy.get("net") or {}
    hosts, ports = net.get("hosts", []), net.get("ports", [])
    if net.get("allow_http") or any(port != 443 for port in ports):
        core.refuse("engine", "door-port-unpinnable")
    if not isinstance(hosts, list) or any(not isinstance(h, str) or not core.is_hostname(h) for h in hosts):
        core.refuse("engine", "door-hosts")
    return hosts


def pin_door_hosts(plan, node):
    """A new egress epoch adding the door's hosts, resolved here, installed by the node's own tool. No-op when every
    door host is already pinned."""
    import egress  # noqa: E402
    hosts = door_hosts()
    current = core.validate_policy(plan.state.get("egress.json").encode("utf-8"))
    pinned = {rule["host"] for rule in current["providers"] if rule["port"] == egress.PORT}
    if all(host in pinned for host in hosts):
        return False
    names = {host: name for name, host in egress.PROVIDERS.items()}
    providers = [names[rule["host"]] for rule in current["providers"] if rule["host"] in names]
    policy = egress.build(current["epoch"] + 1, [rule["url"] for rule in current["relays"]], providers,
                          egress.pinned_hosts(current) + hosts)
    plan.state.put("egress.json", policy.decode("utf-8"))  # a retry then uses the next epoch, never this one
    scratch = tempfile.mkdtemp(prefix="aukora-egress-")
    try:
        path = os.path.join(scratch, "egress.json")
        core.atomic_write(path, policy, 0o600)
        node.push(path, "/root/egress.json.new")
        node.run(["python3", "-B", NODE_RELEASE, "egress", "--policy", "/root/egress.json.new"])
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return True


def egress_command(argv):
    if not argv or argv[0].startswith("-"):
        core.refuse("engine", "usage")
    name, rest = argv[0], argv[1:]
    admission = guard.admit("upgrade", name)  # a listed node stops here, before anything else
    backend = rest[rest.index("--on") + 1] if "--on" in rest and rest.index("--on") + 1 < len(rest) else "nebius-vm"
    if backend != "nebius-vm":
        core.refuse("engine", "vm-only")
    hosts = door_hosts()
    if "--dry-run" in rest:
        print("would: resolve %s here and add them to %s's egress policy (a new epoch), installed by %s egress"
              % (", ".join(hosts) or "no host", name, NODE_RELEASE))
        return 0
    import host  # noqa: E402  (only after the guard)
    import spawn  # noqa: E402
    import vm  # noqa: E402
    root, plan = spawn.existing_plan(admission, name, {"on": backend}, None)
    if plan is None or not plan.state.has("installed"):
        core.refuse("engine", "unknown-node")
    with host.Lock(root):
        node = vm.transport_for(plan.host, name, plan.node_id, plan.state)
        changed = pin_door_hosts(plan, node)
    print(json.dumps({"door_hosts": hosts, "egress_changed": changed}))
    return 0


def install(argv):
    if len(argv) >= 2 and argv[1] == "--stage-on-node":
        name, stage, rest = argv[0], None, argv[2:]
    elif len(argv) >= 3 and argv[1] == "--stage":
        name, stage, rest = argv[0], argv[2], argv[3:]
    else:
        core.refuse("engine", "usage")
    admission = guard.admit("upgrade", name)  # a listed node stops here, before anything else
    dry = "--dry-run" in rest
    backend = "nebius-vm"
    if "--on" in rest:
        backend = rest[rest.index("--on") + 1] if rest.index("--on") + 1 < len(rest) else ""
    if backend != "nebius-vm":
        core.refuse("engine", "vm-only")
    names = stage_files(stage) if stage is not None else None
    if dry:
        what = ("push %s to %s:%s" % (", ".join(names), name, NODE_STAGE) if names is not None
                else "use the stage already at %s:%s" % (name, NODE_STAGE))
        print("would: %s and run %s --stage %s as root" % (what, NODE_TOOL, NODE_STAGE))
        return 0
    import host  # noqa: E402  (only after the guard)
    import spawn  # noqa: E402
    import vm  # noqa: E402
    root, plan = spawn.existing_plan(admission, name, {"on": backend}, None)
    if plan is None or not plan.state.has("installed"):
        core.refuse("engine", "unknown-node")
    with host.Lock(root):
        node = vm.transport_for(plan.host, name, plan.node_id, plan.state)
        pin_door_hosts(plan, node)  # the installer refuses an egress policy without the door's hosts (O10)
        if names is not None:
            node.run(["rm", "-rf", "--", NODE_STAGE], check=False)
            node.run(["install", "-d", "-m", "0700", NODE_STAGE])
            for item in names:
                node.push(os.path.join(stage, item), NODE_STAGE + "/" + item)
        else:
            # Root's own folder, not a link, holding the plugin archive: anything else is not a stage.
            node.run(["test", "-d", NODE_STAGE, "-a", "!", "-L", NODE_STAGE, "-a", "-O", NODE_STAGE,
                      "-a", "-f", NODE_STAGE + "/engine-plugins.tar"])
            node.run(["chmod", "0700", NODE_STAGE])
        node.run(["python3", "-B", NODE_TOOL, "--stage", NODE_STAGE])
        node.run(["rm", "-rf", "--", NODE_STAGE], check=False)
    return 0


def main(argv):
    if len(argv) == 2 and argv[0] == "pin":
        return pin(argv[1])
    if argv and argv[0] == "install":
        return install(argv[1:])
    if argv and argv[0] == "egress":
        return egress_command(argv[1:])
    core.refuse("engine", "usage")


if __name__ == "__main__":
    core.run_main("engine", main)
