# SPDX-License-Identifier: AGPL-3.0-or-later
"""Authority OOM ordering and one consistent engine/model budget on the minimum node."""
import configparser
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]


def service(name):
    parsed = configparser.ConfigParser(strict=False, interpolation=None)
    parsed.read(ROOT / "deploy/units" / name)
    return parsed["Service"]


class MemoryBudget(unittest.TestCase):
    def test_authority_outlives_replaceable_engine_and_models(self):
        supervisor = service("aukora-sovereign.service")
        self.assertEqual(supervisor["OOMScoreAdjust"], "-900")
        self.assertEqual(supervisor["MemoryMin"], "256M")
        for name in ("aukora-kira.service", "aukora-openshell-gateway.service"):
            self.assertEqual(service(name)["OOMScoreAdjust"], "-500")
        for name in ("aukora-kira-embed.service", "aukora-kira-rerank.service"):
            model = service(name)
            self.assertEqual(model["OOMScoreAdjust"], "500")
            self.assertEqual(model["MemoryHigh"], "1G")
            self.assertEqual(model["MemoryMax"], "1536M")
            self.assertEqual(model["LimitCORE"], "0")
        engine = service("aukora-engine.service")
        self.assertEqual(engine["OOMScoreAdjust"], "500")
        # A systemd cap here would constrain the host CLI, not the Docker sandbox.
        self.assertNotIn("MemoryHigh", engine)
        self.assertNotIn("MemoryMax", engine)
        probe = service("aukora-release-probe.template")
        self.assertEqual(probe["MemoryHigh"], "384M")
        self.assertEqual(probe["MemoryMax"], "512M")
        self.assertEqual(probe["OOMScoreAdjust"], "500")

    def test_minimum_node_keeps_models_and_host_outside_the_actual_docker_cap(self):
        script = (ROOT / "deploy/engine/engine-run.sh").read_text()
        limits = re.search(r"limits\(\) \{\n.*?\n\}", script, re.S).group()
        prelude = "nproc() { echo 2; }\nawk() { echo 8388608; }\n"
        done = subprocess.run(["sh", "-c", prelude + limits +
                               '\nlimits && echo "$ENGINE_MEMORY_MIB $ENGINE_CPU_MILLI"'],
                              text=True, capture_output=True, check=True)
        engine_mib, cpu_milli = map(int, done.stdout.split())
        self.assertEqual((engine_mib, cpu_milli), (3584, 1500))
        self.assertEqual(8192 - engine_mib - 2 * 1536, 1536)  # host reserve, including 512 MiB probe
        self.assertIn('--memory "${ENGINE_MEMORY_MIB}Mi"', script)
        self.assertIn('host.get("Memory") != memory', script)  # verify the same cap after creation


if __name__ == "__main__":
    unittest.main()
