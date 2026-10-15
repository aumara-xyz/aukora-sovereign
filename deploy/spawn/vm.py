# SPDX-License-Identifier: AGPL-3.0-or-later
"""The nebius-vm backend (row 73): a managed VM on Nebius, driven from the operator's own machine.

Creating one spends money, so it needs --spend-ok and an hourly estimate before anything else runs. A retry
never allocates twice: the 'allocating' marker is written before the create call, and a marker without a VM in
the inventory is a refusal, not a second create. The VM has a public interface and its own Caddy; the node
installs everything over ssh as the image's default user with sudo, because the image refuses root logins."""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shlex
import sys
import time
import uuid

import core

CLI = ["--no-check-update", "--no-progress", "--retries", "1", "--format", "json"]
IMAGE_FAMILY = "ubuntu24.04-driverless"
USER = "ubuntu"
BOOT_DISK_GIB = "40"


def environment():
    """The settings a VM needs, checked before any command runs."""
    values = {}
    for key in ("AUKORA_NEBIUS_PARENT_ID", "AUKORA_NEBIUS_SUBNET_ID", "AUKORA_NEBIUS_IMAGE_PARENT_ID"):
        values[key] = os.environ.get(key, "")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", values[key]):
            core.refuse("spawn", "nebius-settings")
    key_file = os.environ.get("AUKORA_SSH_PUBLIC_KEY_FILE", "")
    if not key_file or not os.path.isfile(key_file):
        core.refuse("spawn", "ssh-public-key")
    public = core.read_regular(key_file, 8192, "spawn").decode("utf-8", "replace").strip()
    if "\n" in public or not public.startswith(("ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-")):
        core.refuse("spawn", "ssh-public-key")
    values["public_key"] = public
    family = os.environ.get("AUKORA_NEBIUS_IMAGE_FAMILY", IMAGE_FAMILY)
    if not re.fullmatch(r"[a-z0-9._-]{1,64}", family):
        core.refuse("spawn", "nebius-settings")
    values["family"] = family
    return values


def require_spend(spend_ok):
    estimate = os.environ.get("AUKORA_VM_HOURLY_ESTIMATE", "")
    if not spend_ok:
        core.refuse("spawn", "spend-required")
    if not re.fullmatch(r"[0-9]+(\.[0-9]+)?", estimate):
        core.refuse("spawn", "estimate-required")
    print("Nebius VM: operator estimate %s USD per hour, until the VM is destroyed." % estimate, file=sys.stderr)
    return estimate


def nebius(host, *args):
    try:
        return json.loads(host.text(["nebius"] + list(args) + CLI))
    except ValueError:
        core.refuse("spawn", "inventory-invalid")


def inventory(host, parent):
    listing = nebius(host, "compute", "v1", "instance", "list", "--parent-id", parent, "--all")
    items = listing.get("items", []) if isinstance(listing, dict) else None
    if not isinstance(items, list):
        core.refuse("spawn", "inventory-invalid")
    return items


def find(items, instance, node_id):
    """(instance id, or None if absent). A foreign VM of that name is a refusal."""
    mine = [i for i in items if isinstance(i, dict) and isinstance(i.get("metadata"), dict)
            and i["metadata"].get("name") == instance]
    if not mine:
        return None
    meta = mine[0]["metadata"]
    labels = meta.get("labels") if isinstance(meta.get("labels"), dict) else {}
    if len(mine) != 1 or labels.get("aukora-spawn-id") != node_id or not isinstance(meta.get("id"), str) or not meta["id"]:
        core.refuse("spawn", "identity-mismatch")
    return meta["id"]


def smallest_preset(host, parent):
    """Platform and preset of the smallest CPU-only shape with at least 2 vCPU and 8 GiB."""
    listing = nebius(host, "compute", "v1", "platform", "list", "--parent-id", parent, "--all")
    candidates = []
    for platform in listing.get("items", []) if isinstance(listing, dict) else []:
        spec = platform.get("spec", platform)
        platform_name = platform.get("metadata", {}).get("name", platform.get("name", ""))
        for preset in spec.get("presets", []):
            resources = preset.get("resources", {})
            try:
                cpu, memory = int(resources["vcpu_count"]), int(resources["memory_gibibytes"])
                gpu = int(resources.get("gpu_count", 0))
            except (KeyError, TypeError, ValueError):
                continue
            if platform_name and preset.get("name") and gpu == 0 and cpu >= 2 and memory >= 8:
                candidates.append((cpu, memory, platform_name, preset["name"]))
    if not candidates:
        core.refuse("spawn", "cpu-preset")
    return min(candidates)[2:]


def public_ip(host, instance_id):
    vm = nebius(host, "compute", "v1", "instance", "get", "--id", instance_id)
    found = []
    interfaces = vm.get("status", {}).get("network_interfaces", []) if isinstance(vm, dict) else []
    for interface in interfaces:
        text = interface.get("public_ip_address", {}).get("address", "")
        try:
            address = ipaddress.IPv4Address(str(text).split("/")[0])
        except ValueError:
            continue
        if address.is_global:
            found.append(str(address))
    if len(found) != 1:
        core.refuse("spawn", "public-ip")
    return found[0]


class Transport:
    """Run a command as root on the VM (ssh, then sudo) and put a file there (scp, then sudo install)."""

    def __init__(self, host, address, known_hosts):
        try:
            if not ipaddress.IPv4Address(address).is_global:
                raise ValueError(address)
        except ValueError:
            core.refuse("spawn", "public-ip")
        self.host, self.address = host, address
        self.options = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
                        "-o", "UserKnownHostsFile=" + known_hosts, "-o", "ConnectTimeout=10",
                        "-o", "ServerAliveInterval=15"]
        if os.environ.get("AUKORA_SSH_KEY_FILE"):
            self.options += ["-i", os.environ["AUKORA_SSH_KEY_FILE"], "-o", "IdentitiesOnly=yes"]
        self.target = USER + "@" + address

    def run(self, argv, check=True):
        return self.host.run(["ssh"] + self.options + [self.target, shlex.join(["sudo", "-n"] + list(argv))], None, check)

    def push(self, local, remote):
        scratch = "/tmp/aukora-push-" + uuid.uuid4().hex
        self.host.run(["scp", "-q"] + self.options + [local, self.target + ":" + scratch])
        try:
            self.run(["install", "-m", "0600", "-o", "root", "-g", "root", scratch, remote])
        finally:
            self.host.run(["ssh"] + self.options + [self.target, shlex.join(["rm", "-f", scratch])], None, False)

    def wait(self):
        attempts = int(os.environ.get("AUKORA_BOOT_ATTEMPTS", "60"))
        for _attempt in range(attempts):
            if self.run(["true"], check=False).returncode == 0:
                if self.run(["cloud-init", "status", "--wait"], check=False).returncode in (0, 2):
                    return
            time.sleep(5)
        core.refuse("spawn", "vm-not-ready")


def provision(plan, settings):
    """Create or resume the VM. Sets plan.public_ip and returns the Transport; install and claim follow."""
    host, state, instance = plan.host, plan.state, plan.instance
    parent = settings["AUKORA_NEBIUS_PARENT_ID"]
    instance_id = find(inventory(host, parent), instance, plan.node_id)
    if instance_id is None:
        if state.has("allocating"):
            core.refuse("spawn", "allocation-unknown")
        platform, preset = smallest_preset(host, parent)
        user_data = "#cloud-config\n" + json.dumps({"users": ["default"], "ssh_pwauth": False,
                                                    "ssh_authorized_keys": [settings["public_key"]]}, sort_keys=True) + "\n"
        interface = json.dumps([{"name": "eth0", "subnet_id": settings["AUKORA_NEBIUS_SUBNET_ID"],
                                 "ip_address": {}, "public_ip_address": {}}], separators=(",", ":"))
        state.mark("allocating")
        try:
            nebius(host, "compute", "v1", "instance", "create", "--parent-id", parent, "--name", instance,
                   "--labels", "aukora-spawn-id=" + plan.node_id, "--resources-platform", platform,
                   "--resources-preset", preset, "--boot-disk-attach-mode", "read_write",
                   "--boot-disk-managed-disk-name", instance + "-boot",
                   "--boot-disk-managed-disk-size-gibibytes", BOOT_DISK_GIB, "--boot-disk-managed-disk-type",
                   "network_ssd", "--boot-disk-managed-disk-source-image-family-image-family", settings["family"],
                   "--boot-disk-managed-disk-source-image-family-parent-id", settings["AUKORA_NEBIUS_IMAGE_PARENT_ID"],
                   "--network-interfaces", interface, "--cloud-init-user-data", user_data)
        except core.Refusal:
            # A refused create that left no VM behind may be tried again; one that may have left a VM may not.
            if find(inventory(host, parent), instance, plan.node_id) is None:
                state.unmark("allocating")
            raise
        instance_id = find(inventory(host, parent), instance, plan.node_id)
        if instance_id is None:
            core.refuse("spawn", "allocation-unknown")
    state.put("instance-id", instance_id)
    plan.public_ip = public_ip(host, instance_id)
    state.put("ip", plan.public_ip)
    node = Transport(host, plan.public_ip, os.path.join(state.path, "known_hosts"))
    node.wait()
    return node


def destroy(plan, settings):
    host, parent = plan.host, settings["AUKORA_NEBIUS_PARENT_ID"]
    instance_id = find(inventory(host, parent), plan.instance, plan.node_id)
    if (instance_id is None and plan.state.has("allocating") and not plan.state.has("instance-id")
            and not plan.force):
        core.refuse("spawn", "allocation-unknown")  # --yes-destroy accepts that no VM was created
    if instance_id is not None:
        nebius(host, "compute", "v1", "instance", "delete", "--id", instance_id)


def transport_for(host, name, node_id, state):
    """For an existing node (upgrade): its Transport, after checking the VM is ours."""
    parent = os.environ.get("AUKORA_NEBIUS_PARENT_ID", "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", parent):
        core.refuse("upgrade", "nebius-settings")
    instance_id = find(inventory(host, parent), "aukora-" + name, node_id)
    if instance_id is None:
        core.refuse("upgrade", "node-not-running")
    return Transport(host, public_ip(host, instance_id), os.path.join(state.path, "known_hosts"))
