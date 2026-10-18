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
if sys.argv[1] == 'is-enabled':
    unit = sys.argv[-1]
    if unit.startswith('aukora-release-probe@'):
        print('enabled' if os.environ.get('ENABLE_PROBE') else 'static')
    sys.exit(0)
if sys.argv[1] == 'cat':
    print('# /etc/systemd/system/aukora-release-probe@.service')
    print('[Service]')
    print('RestrictAddressFamilies=none')
    reset = os.environ.get('RESET_FAMILIES')
    if reset:
        print('# /etc/systemd/system/aukora-release-probe@.service.d/override.conf')
        print('[Service]')
        print(' RestrictAddressFamilies = ' if reset == 'spaced' else 'RestrictAddressFamilies=')
        if reset == 'sectioned':
            # systemd ignores this line outside [Service]; the audit must too.
            print('[Install]')
            print('RestrictAddressFamilies=none')
    sys.exit(0)
if sys.argv[1] == 'list-unit-files':
    if os.environ.get('ENABLE_INSTANCE'):
        print('aukora-release-probe@0123456789ab-0123456789ab.service enabled enabled')
    sys.exit(0)
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
if prop == 'IPAddressDeny' and os.environ.get('REVERSE_DENY'):
    print('0.0.0.0/0 ::/0')
elif unit == 'aukora-release-probe@000000000000-000000000000.service' and prop == 'PrivateNetwork' and os.environ.get('WEAKEN_PROBE'):
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
            # systemd 255.4 prints the deny set in either order; the same set passes.
            reversed_deny = subprocess.run(audit, env={**env, "REVERSE_DENY": "1"}, capture_output=True, text=True)
            self.assertEqual(reversed_deny.returncode, 0, reversed_deny.stdout + reversed_deny.stderr)
            # A probe enabled for boot would start unapproved release code outside the supervisor.
            enabled = subprocess.run(audit, env={**env, "ENABLE_PROBE": "1"}, capture_output=True, text=True)
            self.assertEqual(enabled.returncode, 1, enabled.stdout + enabled.stderr)
            self.assertIn("is not static", enabled.stdout)
            # A drop-in that resets the address families reads back like "none" in systemctl show; the unit files tell.
            for spelling in ("1", "spaced", "sectioned"):
                reset = subprocess.run(audit, env={**env, "RESET_FAMILIES": spelling}, capture_output=True, text=True)
                self.assertEqual(reset.returncode, 1, reset.stdout + reset.stderr)
                self.assertIn("RestrictAddressFamilies is ''", reset.stdout)
            # A real release instance enabled through a drop-in would start at boot; the placeholder stays static.
            instance = subprocess.run(audit, env={**env, "ENABLE_INSTANCE": "1"}, capture_output=True, text=True)
            self.assertEqual(instance.returncode, 1, instance.stdout + instance.stderr)
            self.assertIn("an instance is enabled for boot", instance.stdout)
            bad = subprocess.run(audit, env={**env, "WEAKEN_PROBE": "1"}, capture_output=True, text=True)
            self.assertEqual(bad.returncode, 1, bad.stdout + bad.stderr)
            self.assertIn("FAIL aukora-release-probe@000000000000-000000000000.service: PrivateNetwork", bad.stdout)
