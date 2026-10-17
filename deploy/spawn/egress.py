# SPDX-License-Identifier: AGPL-3.0-or-later
"""Operator side of the egress policy (row 70): turn relay URLs and provider names into the pinned policy file.

The node's service user may open connections only to the addresses this file pins, one entry per relay. The file
format and its validation live in core.py; the node renders and loads the firewall rules from it
(deploy/units/egress_apply.py). Names are resolved here, once, on the operator's machine; the node never resolves
a relay name."""
from __future__ import annotations

import ipaddress
import re
import socket

import core

# The broker's fixed endpoints (broker::provider::HostedProvider); a prompt cannot select another one.
PROVIDERS = {"openrouter": "openrouter.ai", "deepseek": "api.deepseek.com"}
PORT = 443


def resolve(host, port):
    """Public addresses of host, v4 before v6, at most core.MAX_ADDRESSES, or a refusal."""
    if ":" in host or re.fullmatch(r"[0-9.]+", host):
        found = {str(ipaddress.ip_address(host))}
    else:
        try:
            rows = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        except OSError:
            core.refuse("egress", "unresolved")
        found = set()
        for _family, _kind, _proto, _name, address in rows:
            found.add(str(ipaddress.ip_address(address[0].split("%", 1)[0])))
    public = sorted((ipaddress.ip_address(a) for a in found if core.public_address(a)),
                    key=lambda ip: (ip.version, ip.packed))
    if not public:
        core.refuse("egress", "no-public-address")
    return [str(ip) for ip in public[:core.MAX_ADDRESSES]]


def build(epoch, relay_urls, provider_names, hosts=()):
    """Canonical policy bytes. Each relay and provider gets its own pinned address list. `hosts` are further names
    the node's service user must reach on PORT: the engine door's allowlisted web_fetch hosts (deploy/engine/NODE.md
    O10). They are pinned exactly like a provider (an entry, /etc/hosts lines, a firewall set), so the door resolves
    them without a resolver, as the broker does the provider."""
    relays, seen = [], set()
    for url in relay_urls:
        key = core.relay_key(url)
        if key not in seen:  # the same relay named twice is pinned once
            seen.add(key)
            relays.append({"url": url, "port": key[1], "addresses": resolve(key[0], key[1])})
    providers = []
    for name in dict.fromkeys(provider_names):
        if name not in PROVIDERS:
            core.refuse("egress", "provider")
        providers.append({"host": PROVIDERS[name], "port": PORT, "addresses": resolve(PROVIDERS[name], PORT)})
    for host in dict.fromkeys(hosts):
        if not core.is_hostname(host) or host in PROVIDERS.values():
            core.refuse("egress", "host")
        providers.append({"host": host, "port": PORT, "addresses": resolve(host, PORT)})
    raw = core.canonical({"v": core.EGRESS_VERSION, "epoch": epoch, "relays": relays, "providers": providers})
    core.validate_policy(raw)
    return raw


def pinned_hosts(policy):
    """The names in a policy that are not one of the broker's providers (the door's hosts), in policy order."""
    return [rule["host"] for rule in policy["providers"] if rule["host"] not in PROVIDERS.values()]
