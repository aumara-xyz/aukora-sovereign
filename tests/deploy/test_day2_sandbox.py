# SPDX-License-Identifier: AGPL-3.0-or-later
"""Exercise the engine script's actual Docker inspection checks without a Docker daemon."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import re
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (ROOT / "deploy/engine/engine-run.sh").read_text(encoding="utf-8")


class SandboxRestartPolicy(unittest.TestCase):
    def setUp(self):
        self.verify = re.search(
            r"/usr/bin/docker inspect \$container_ids \| python3 -I -c '\n(.*?)\n' "
            r'"\$ENGINE_MEMORY_MIB" "\$ENGINE_CPU_MILLI"', SCRIPT, re.S).group(1)
        name = "/openshell-default--auma-engine-example"
        self.containers = [
            {"Name": name, "State": {"Running": True}, "HostConfig": {
                "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
                "Memory": 5632 << 20, "NanoCpus": 1500 * 1000000, "PidsLimit": 2048,
                "Mounts": [{"Type": "tmpfs", "Target": "/tmp", "TmpfsOptions": {"SizeBytes": 1 << 30}}],
            }},
            {"Name": name + "-supervisor", "State": {"Running": True}, "HostConfig": {
                "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
            }},
        ]

    def run_verify(self, containers):
        return subprocess.run([sys.executable, "-I", "-c", self.verify, "5632", "1500"],
                              input=json.dumps(containers), text=True, capture_output=True)

    def test_checks_all_containers_including_stopped_ones(self):
        self.assertIn('docker ps -aq --filter "name=^/openshell-default--$NAME-"', SCRIPT)
        self.assertEqual(self.run_verify(self.containers).returncode, 0)
        for index in (0, 1):
            for policy in ("always", "unless-stopped", "on-failure", ""):
                with self.subTest(container=index, policy=policy):
                    containers = copy.deepcopy(self.containers)
                    containers[index]["HostConfig"]["RestartPolicy"]["Name"] = policy
                    done = self.run_verify(containers)
                    self.assertNotEqual(done.returncode, 0)
                    self.assertIn("can restart outside the supervisor", done.stderr)
            containers = copy.deepcopy(self.containers)
            del containers[index]["HostConfig"]["RestartPolicy"]
            self.assertNotEqual(self.run_verify(containers).returncode, 0)
        # A stopped companion with an unsafe policy must not hide from the check.
        self.containers[1]["State"]["Running"] = False
        self.containers[1]["HostConfig"]["RestartPolicy"]["Name"] = "always"
        self.assertNotEqual(self.run_verify(self.containers).returncode, 0)

    def test_requires_one_running_workload_and_its_companion(self):
        for containers in ([], self.containers[:1], self.containers + self.containers[:1]):
            self.assertNotEqual(self.run_verify(containers).returncode, 0)
        self.containers[0]["State"]["Running"] = False
        self.assertNotEqual(self.run_verify(self.containers).returncode, 0)

    def test_keeps_the_workload_resource_checks(self):
        for key in ("Memory", "NanoCpus", "PidsLimit", "Mounts"):
            with self.subTest(key=key):
                containers = copy.deepcopy(self.containers)
                del containers[0]["HostConfig"][key]
                done = self.run_verify(containers)
                self.assertNotEqual(done.returncode, 0)
                self.assertIn("not capped as asked", done.stderr)


if __name__ == "__main__":
    unittest.main()
