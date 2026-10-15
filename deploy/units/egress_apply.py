# SPDX-License-Identifier: AGPL-3.0-or-later
"""Loads the node's egress policy into the firewall (row 70) and reports whether the live rules still are the
loaded rules.

load    read the policy file, build the rules from it, replace the aukora_egress table in one transaction, record
        what was loaded
verify  compare the live table and the policy file with what load recorded; exit 1 if either differs

The rules constrain the node's service user only. That user may finish connections it already has, open new ones on
the loopback interface only to the local index and embedder ports, and open new ones elsewhere only to the addresses
a relay or provider entry pins, on that entry's port; every other new connection of that user is rejected. A name
lookup through a resolver daemon's local socket is not a connection the firewall sees. The status file carries
digests only: sha256 of the policy file (the host policy digest the relay client compares) and of the table as the
kernel lists it."""
from __future__ import annotations

import ipaddress
import os
import pwd
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "spawn"))
import core  # noqa: E402

POLICY = "/etc/aukora/egress.json"
RUN = "/run/aukora-egress"
LOADED = RUN + "/loaded.json"
STATUS = RUN + "/status.json"
TABLE = "aukora_egress"
SERVICE_USER = "aukora"
# The loopback services the node runs for its service user: OpenViking's vector index and its embedder
# (deploy/openviking). Nothing else on loopback is open to that user: not the resolver stub, not Caddy's admin API.
LOOPBACK_PORTS = (1933, 1934)


def nft(arguments, data=None):
    done = subprocess.run(["nft"] + arguments, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if done.returncode != 0:
        print("egress: nft exited " + str(done.returncode) + "\n" + done.stderr[-300:].decode("utf-8", "replace"),
              file=sys.stderr)
        core.refuse("egress", "nft-failed")
    return done.stdout


def render(policy, uid):
    """The rule text. Only validated addresses, ports and a numeric uid go into it."""
    sets, rules = [], []
    entries = [("relay", rule) for rule in policy["relays"]] + [("provider", rule) for rule in policy["providers"]]
    for index, (kind, rule) in enumerate(entries):
        for version, family, match in ((4, "ipv4_addr", "ip"), (6, "ipv6_addr", "ip6")):
            members = [a for a in rule["addresses"] if ipaddress.ip_address(a).version == version]
            if members:
                name = "%s_%d_v%d" % (kind, index, version)
                sets.append("\tset %s {\n\t\ttype %s\n\t\telements = { %s }\n\t}\n" % (name, family, ", ".join(members)))
                rules.append("\t\t%s daddr @%s tcp dport %d accept\n" % (match, name, rule["port"]))
    return ("table inet %(t)s\ndelete table inet %(t)s\ntable inet %(t)s {\n%(sets)s\tchain output {\n"
            "\t\ttype filter hook output priority 0; policy accept;\n\t\tmeta skuid != %(uid)d accept\n"
            "\t\tct state established,related accept\n\t\toifname \"lo\" tcp dport { %(lo)s } accept\n%(rules)s"
            "\t\treject\n\t}\n}\n"
            % {"t": TABLE, "uid": uid, "sets": "".join(sets), "rules": "".join(rules),
               "lo": ", ".join(str(port) for port in LOOPBACK_PORTS)})


def live_digest():
    return core.sha256_hex(nft(["list", "table", "inet", TABLE]))


def policy_file():
    raw = core.read_regular(POLICY, 256 * 1024, "egress")
    return raw, core.validate_policy(raw)


def write_status(policy, epoch, loaded_policy, loaded, live):
    """ok means the policy file is the loaded policy and the live table is the loaded table."""
    record = {"v": 1, "epoch": epoch, "policy_sha256": policy, "loaded_policy_sha256": loaded_policy,
              "loaded_ruleset_sha256": loaded, "live_ruleset_sha256": live,
              "ok": loaded != "" and loaded == live and policy == loaded_policy,
              "observed_at_ms": time.time_ns() // 1_000_000}
    core.atomic_write(STATUS, core.canonical(record), 0o644)
    return record["ok"]


def load():
    raw, policy = policy_file()
    try:
        uid = pwd.getpwnam(SERVICE_USER).pw_uid
    except KeyError:
        core.refuse("egress", "service-user")
    nft(["-f", "-"], render(policy, uid).encode("ascii"))
    digest, policy_sha256 = live_digest(), core.sha256_hex(raw)
    core.atomic_write(LOADED, core.canonical({"policy_sha256": policy_sha256, "ruleset_sha256": digest}), 0o644)
    write_status(policy_sha256, policy["epoch"], policy_sha256, digest, digest)
    return 0


def verify():
    raw, policy = policy_file()
    policy_sha256 = core.sha256_hex(raw)
    try:
        loaded = core.parse_json(core.read_regular(LOADED, 4096, "egress"), "egress", 4096)
        core.exact_keys(loaded, ("policy_sha256", "ruleset_sha256"), "egress", "loaded")
    except core.Refusal:
        write_status(policy_sha256, policy["epoch"], "", "", "")
        return 1
    try:
        live = live_digest()
    except core.Refusal:
        live = ""
    ok = write_status(policy_sha256, policy["epoch"], loaded["policy_sha256"], loaded["ruleset_sha256"], live)
    return 0 if ok else 1


def main(argv):
    if os.geteuid() != 0:
        core.refuse("egress", "root-required")
    if argv == ["load"]:
        return load()
    if argv == ["verify"]:
        return verify()
    core.refuse("egress", "usage")


if __name__ == "__main__":
    core.run_main("egress", main)
