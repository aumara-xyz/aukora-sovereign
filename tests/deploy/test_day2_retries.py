# SPDX-License-Identifier: AGPL-3.0-or-later
"""Authority recovery must not bypass engine admission or restart one-shot fences."""
from __future__ import annotations

import configparser
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
UNITS = ROOT / "deploy" / "units"


def unit(name):
    parsed = configparser.ConfigParser(strict=False, interpolation=None)
    parsed.optionxform = str
    parsed.read(UNITS / name)
    return parsed


class AuthorityRetries(unittest.TestCase):
    def test_authority_services_never_hit_a_start_limit_and_back_off(self):
        services = {
            "aukora-sovereign.service": ("on-failure", "3s"),
            "aukora-egress.service": ("on-failure", "5s"),
            "aukora-kira.service": ("on-failure", "3s"),
            "aukora-kira-embed.service": ("on-failure", "5s"),
            "aukora-kira-rerank.service": ("on-failure", "5s"),
            "aukora-openshell-gateway.service": ("on-failure", "5s"),
            "aukora-engine-diskguard.service": ("always", "5s"),
        }
        for name, (restart, delay) in services.items():
            with self.subTest(unit=name):
                parsed = unit(name)
                self.assertEqual(parsed["Unit"]["StartLimitIntervalSec"], "0")
                self.assertEqual(parsed["Service"]["Restart"], restart)
                self.assertEqual(parsed["Service"]["RestartSec"], delay)
                self.assertEqual(parsed["Service"]["RestartSteps"], "6")
                self.assertEqual(parsed["Service"]["RestartMaxDelaySec"], "300s")

    def test_egress_success_requeues_authority_without_weakening_the_dependency(self):
        sovereign, egress = unit("aukora-sovereign.service"), unit("aukora-egress.service")
        self.assertIn("aukora-egress.service", sovereign["Unit"]["Requires"].split())
        self.assertIn("aukora-egress.service", sovereign["Unit"]["After"].split())
        service = egress["Service"]
        self.assertEqual(service["Type"], "oneshot")
        self.assertEqual(service["RemainAfterExit"], "yes")
        self.assertTrue(service["ExecStart"].endswith("/egress_apply.py load"))
        # ExecStartPost runs only after a successful oneshot; it must not wait on its own After dependency.
        self.assertEqual(service["ExecStartPost"],
                         "/usr/bin/systemctl --no-block start aukora-sovereign.service")
        self.assertNotIn("ExecStopPost", service)
        self.assertNotIn("User", service)  # root reaches systemd's socket within the service's AF_UNIX allowance
        self.assertIn("AF_UNIX", service["RestrictAddressFamilies"].split())

    def test_engine_still_waits_for_admission_and_uses_the_supervisors_recovery(self):
        engine = unit("aukora-engine.service")
        self.assertNotIn("Install", engine)
        self.assertEqual(engine["Unit"]["PartOf"], "aukora-sovereign.service")
        self.assertEqual(engine["Unit"]["StartLimitIntervalSec"], "300")
        self.assertEqual(engine["Unit"]["StartLimitBurst"], "5")
        service = engine["Service"]
        self.assertEqual(service["ExecCondition"], "/usr/bin/test -f /run/aukora-engine-ctl/admission.json")
        self.assertEqual(service["Restart"], "on-failure")
        self.assertEqual(service["RestartSec"], "10s")
        self.assertNotIn("RestartSteps", service)
        self.assertNotIn("RestartMaxDelaySec", service)

    def test_fences_cleanup_and_periodic_verification_keep_their_lifecycles(self):
        for name in ("aukora-engine-fence.service", "aukora-engine-cleanup.service", "aukora-egress-verify.service"):
            with self.subTest(unit=name):
                service = unit(name)["Service"]
                self.assertEqual(service["Type"], "oneshot")
                self.assertNotIn("Restart", service)
        self.assertNotIn("Install", unit("aukora-engine-cleanup.service"))
        self.assertEqual(unit("aukora-egress-verify.timer")["Timer"]["OnUnitActiveSec"], "15s")


if __name__ == "__main__":
    unittest.main()
