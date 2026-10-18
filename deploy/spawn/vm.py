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
# The operator's Nebius profile signs in through the browser (auth-type federation). When its cached token has expired
# the CLI prints a sign-in link on stderr and WAITS for the browser, 15 minutes by default (--auth-timeout); the spawner
# captures stderr and has no stdin, so nobody saw the link and `engine.py egress` seemed to hang inside
# `nebius compute instance list`. So: never open a browser from here, bound every read (the CLI's own deadline for the
# sign-in, and a wall-clock timeout on the process as the last word), and say what to do. A create or delete is never
# cut short by a clock (a half-done change is worse), but it never waits on a browser either.
CLI_NO_BROWSER = ["--no-browser"]
CLI_READ = CLI_NO_BROWSER + ["--auth-timeout", "30s", "--timeout", "60s"]
READ_SECONDS = 120
SIGN_IN_HINT = ("the Nebius CLI needs you to sign in again (its token expired). Run `nebius iam whoami` in a terminal, "
                "finish the browser sign-in, then run this again. Nothing was changed.")
IMAGE_FAMILY = "ubuntu24.04-driverless"
USER = "ubuntu"
# The real node (deploy/engine/NODE.md, O1): two resident 0.6 GB models, docker with the sandbox image, the harness and
# the engine's own builds. The default is the rehearsal's 4 vCPU, 16 GiB and 80 GiB disk (cpu-d3 4vcpu-16gb).
# AUKORA_VM_VCPU, AUKORA_VM_MEMORY_GIB and AUKORA_VM_DISK_GIB choose another size, never below 2 vCPU / 8 GiB / 60 GiB:
# engine-run.sh sizes the sandbox's caps from the VM (2 vCPU / 8 GiB: 1.5 CPUs and about 5.2 GiB, NODE.md section 12
# P2), and below 60 GiB the engine disk, containerd's disk and the host-disk floor leave the engine no room to start.
MIN_VCPU = 4
MIN_MEMORY_GIB = 16
BOOT_DISK_GIB = "80"
SIZE_FLOORS = {"AUKORA_VM_VCPU": (2, 64), "AUKORA_VM_MEMORY_GIB": (8, 256), "AUKORA_VM_DISK_GIB": (60, 1024)}
# Extra labels (AUKORA_VM_LABELS="purpose=peter-node"); the spawn id and delete-after stay spawn's own.
LABEL = re.compile(r"[a-z][a-z0-9_-]{0,62}=[a-z0-9][a-z0-9_-]{0,62}\Z")
RESERVED_LABELS = ("aukora-spawn-id", "delete-after")


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
    # Optional: the VM's security group (Nebius's default group admits every port), and a delete-after label
    # (YYYY-MM-DD) for a disposable node.
    group = os.environ.get("AUKORA_NEBIUS_SECURITY_GROUP_ID", "")
    if group and not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", group):
        core.refuse("spawn", "nebius-settings")
    values["security_group"] = group
    delete_after = os.environ.get("AUKORA_VM_DELETE_AFTER", "")
    if delete_after and not re.fullmatch(r"20[0-9]{2}-[01][0-9]-[0-3][0-9]", delete_after):
        core.refuse("spawn", "nebius-settings")
    values["delete_after"] = delete_after
    defaults = {"AUKORA_VM_VCPU": MIN_VCPU, "AUKORA_VM_MEMORY_GIB": MIN_MEMORY_GIB,
                "AUKORA_VM_DISK_GIB": int(BOOT_DISK_GIB)}
    for key, (low, high) in SIZE_FLOORS.items():
        text = os.environ.get(key, "")
        if text and (not re.fullmatch(r"[1-9][0-9]{0,3}", text) or not low <= int(text) <= high):
            core.refuse("spawn", "nebius-settings")
        values[key] = int(text) if text else defaults[key]
    extra = [item for item in os.environ.get("AUKORA_VM_LABELS", "").split(",") if item]
    if len(extra) > 8 or any(LABEL.match(item) is None or item.split("=", 1)[0] in RESERVED_LABELS for item in extra):
        core.refuse("spawn", "nebius-settings")
    values["labels"] = extra
    return values


def require_spend(spend_ok):
    estimate = os.environ.get("AUKORA_VM_HOURLY_ESTIMATE", "")
    if not spend_ok:
        core.refuse("spawn", "spend-required")
    if not re.fullmatch(r"[0-9]+(\.[0-9]+)?", estimate):
        core.refuse("spawn", "estimate-required")
    print("Nebius VM: operator estimate %s USD per hour, until the VM is destroyed." % estimate, file=sys.stderr)
    return estimate


def nebius(host, *args, read=False):
    """One `nebius` call, JSON out. `read`: a list or get (bounded in time); otherwise a change (never cut short)."""
    argv = ["nebius"] + list(args) + CLI + (CLI_READ if read else CLI_NO_BROWSER)
    try:
        done = host.run(argv, None, False, READ_SECONDS if read else None)
    except core.Refusal as error:
        if str(error).endswith(":command-timeout"):
            print("nebius did not answer in %d s; it may be waiting for a sign-in. %s" % (READ_SECONDS, SIGN_IN_HINT),
                  file=sys.stderr)
            core.refuse(host.admission.action, "nebius-timeout")
        raise
    if done.returncode != 0:
        said = done.stderr.decode("utf-8", "replace")
        if "authentication process" in said or "get auth data" in said:
            print("nebius: " + SIGN_IN_HINT, file=sys.stderr)
            core.refuse(host.admission.action, "nebius-sign-in")
        if os.environ.get("AUKORA_DEPLOY_DEBUG") == "1":
            print("command failed: nebius " + " ".join(args[:3]) + "\n" + said[-400:], file=sys.stderr)
        core.refuse(host.admission.action, "command-failed")
    try:
        return json.loads(done.stdout.decode("utf-8", "replace"))
    except ValueError:
        core.refuse("spawn", "inventory-invalid")


def inventory(host, parent):
    listing = nebius(host, "compute", "v1", "instance", "list", "--parent-id", parent, "--all", read=True)
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


def smallest_preset(host, parent, min_vcpu=MIN_VCPU, min_memory=MIN_MEMORY_GIB):
    """Platform and preset of the smallest CPU-only shape with at least min_vcpu vCPU and min_memory GiB."""
    listing = nebius(host, "compute", "v1", "platform", "list", "--parent-id", parent, "--all", read=True)
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
            if platform_name and preset.get("name") and gpu == 0 and cpu >= min_vcpu and memory >= min_memory:
                candidates.append((cpu, memory, platform_name, preset["name"]))
    if not candidates:
        core.refuse("spawn", "cpu-preset")
    return min(candidates)[2:]


def public_ip(host, instance_id):
    vm = nebius(host, "compute", "v1", "instance", "get", "--id", instance_id, read=True)
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
        platform, preset = smallest_preset(host, parent, settings["AUKORA_VM_VCPU"], settings["AUKORA_VM_MEMORY_GIB"])
        print("Nebius VM: %s %s, %d GiB disk." % (platform, preset, settings["AUKORA_VM_DISK_GIB"]), file=sys.stderr)
        user_data = "#cloud-config\n" + json.dumps({"users": ["default"], "ssh_pwauth": False,
                                                    "ssh_authorized_keys": [settings["public_key"]]}, sort_keys=True) + "\n"
        nic = {"name": "eth0", "subnet_id": settings["AUKORA_NEBIUS_SUBNET_ID"], "ip_address": {}, "public_ip_address": {}}
        if settings["security_group"]:
            nic["security_groups"] = [{"id": settings["security_group"]}]
        interface = json.dumps([nic], separators=(",", ":"))
        labels = "aukora-spawn-id=" + plan.node_id
        if settings["delete_after"]:
            labels += ",delete-after=" + settings["delete_after"]
        for item in settings["labels"]:
            labels += "," + item
        state.mark("allocating")
        try:
            nebius(host, "compute", "v1", "instance", "create", "--parent-id", parent, "--name", instance,
                   "--labels", labels, "--resources-platform", platform,
                   "--resources-preset", preset, "--boot-disk-attach-mode", "read_write",
                   "--boot-disk-managed-disk-name", instance + "-boot",
                   "--boot-disk-managed-disk-size-gibibytes", str(settings["AUKORA_VM_DISK_GIB"]),
                   "--boot-disk-managed-disk-type",
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
