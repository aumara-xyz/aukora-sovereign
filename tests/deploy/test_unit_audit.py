# SPDX-License-Identifier: AGPL-3.0-or-later
"""Exercise the installed-unit auditor with fake systemd commands; no services are queried or changed."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class UnitAudit(unittest.TestCase):
    def test_a_weakened_release_probe_is_refused(self):
        with tempfile.TemporaryDirectory() as scratch:
            commands = {
                "id": "#!/bin/sh\necho 0\n",
                "systemd-analyze": "#!/bin/sh\necho 'Overall exposure level for fixture: 0.0'\n",
                "systemctl": '''#!/usr/bin/env python3
import os, sys
if sys.argv[1] != 'show':
    sys.exit(0)
prop = sys.argv[2].removeprefix('--property=')
values = {'User': 'aukora', 'UMask': '0077', 'ProtectSystem': 'strict',
          'SystemCallArchitectures': 'native', 'CapabilityBoundingSet': '', 'AmbientCapabilities': '',
          'RestrictAddressFamilies': '', 'IPAddressDeny': '::/0 0.0.0.0/0', 'TasksMax': '64',
          'MemoryHigh': '402653184', 'MemoryMax': '536870912', 'RuntimeMaxUSec': '1min 30s',
          'TimeoutStopUSec': '10s', 'KillMode': 'control-group', 'ProtectProc': 'invisible',
          'StartLimitIntervalUSec': '0', 'RestartSteps': '6', 'RestartMaxDelayUSec': '5min',
          'Restart': 'on-failure', 'MemoryMin': '268435456', 'LogRateLimitIntervalUSec': '0',
          'LogRateLimitBurst': '0', 'TimeoutStartUSec': '1min 30s'}
per_unit = {'aukora-sovereign.service': {'RestartUSec': '3s', 'OOMScoreAdjust': '-900'},
            'aukora-egress.service': {'RestartUSec': '5s'},
            'aukora-release-probe@000000000000-000000000000.service': {'OOMScoreAdjust': '500'}}
unit = sys.argv[-1]
if unit == 'aukora-release-probe@000000000000-000000000000.service' and prop == 'PrivateNetwork' and os.environ.get('WEAKEN_PROBE'):
    print('no')
else:
    print(per_unit.get(unit, {}).get(prop, values.get(prop, 'yes')))
''',
            }
            for name, body in commands.items():
                path = Path(scratch) / name
                path.write_text(body)
                path.chmod(0o755)
            env = {**os.environ, "PATH": scratch + os.pathsep + os.environ["PATH"]}
            audit = ["sh", str(ROOT / "deploy/units/check-units.sh")]
            good = subprocess.run(audit, env=env, capture_output=True, text=True)
            self.assertEqual(good.returncode, 0, good.stdout + good.stderr)
            self.assertIn("ok   aukora-release-probe@000000000000-000000000000.service", good.stdout)
            bad = subprocess.run(audit, env={**env, "WEAKEN_PROBE": "1"}, capture_output=True, text=True)
            self.assertEqual(bad.returncode, 1, bad.stdout + bad.stderr)
            self.assertIn("FAIL aukora-release-probe@000000000000-000000000000.service: PrivateNetwork", bad.stdout)
