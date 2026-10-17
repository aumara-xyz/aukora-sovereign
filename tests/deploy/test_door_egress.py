# SPDX-License-Identifier: AGPL-3.0-or-later
"""The engine door's web_fetch hosts in the node's egress policy (deploy/engine/NODE.md O10).

  python3 -B -m unittest discover -s tests/deploy -p 'test_*.py'

Names are resolved on the operator machine (stubbed here); the door's hosts are pinned like a provider, survive a
later `spawn.sh egress`, and the release's own door policy names only hosts that can be pinned."""
from __future__ import annotations

import os
import sys
import unittest
from unittest import mock

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
sys.path.insert(0, os.path.join(ROOT, "deploy", "spawn"))
sys.path.insert(0, os.path.join(ROOT, "deploy", "engine"))
import core  # noqa: E402
import egress  # noqa: E402
import engine  # noqa: E402

ADDRESSES = {"api.deepseek.com": ["203.0.114.10"], "example.com": ["93.184.215.14"], "docs.rs": ["151.101.1.1"]}


def resolve(host, _port):
    return ADDRESSES[host]


class DoorEgress(unittest.TestCase):
    def test_door_hosts_are_pinned_beside_the_provider_and_kept_by_a_later_epoch(self):
        with mock.patch.object(egress, "resolve", resolve):
            first = core.validate_policy(egress.build(1, [], ["deepseek"], ["example.com"]))
            self.assertEqual([(p["host"], p["port"], p["addresses"]) for p in first["providers"]],
                             [("api.deepseek.com", 443, ["203.0.114.10"]), ("example.com", 443, ["93.184.215.14"])])
            self.assertEqual(egress.pinned_hosts(first), ["example.com"])
            # spawn.sh egress rebuilds from its flags plus the hosts already pinned: the door's host stays.
            later = core.validate_policy(egress.build(2, [], ["deepseek"], egress.pinned_hosts(first)))
            self.assertEqual(egress.pinned_hosts(later), ["example.com"])
            # The same name twice is pinned once; a provider's name is not a door host; nonsense is refused.
            twice = core.validate_policy(egress.build(3, [], ["deepseek"], ["example.com", "example.com"]))
            self.assertEqual(len(twice["providers"]), 2)
            for bad in (["api.deepseek.com"], ["not a host"]):
                with self.assertRaises(core.Refusal):
                    egress.build(4, [], ["deepseek"], bad)

    def test_the_release_door_policy_names_pinnable_hosts(self):
        hosts = engine.door_hosts()
        self.assertTrue(hosts)
        self.assertTrue(all(core.is_hostname(host) for host in hosts))


if __name__ == "__main__":
    unittest.main()
