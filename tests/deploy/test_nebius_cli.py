# SPDX-License-Identifier: AGPL-3.0-or-later
"""The spawner's `nebius` calls never hang on a browser sign-in (deploy/spawn/vm.py).

  python3 -B -m unittest discover -s tests/deploy -p 'test_*.py'

`engine.py egress` once hung inside `nebius compute instance list`: the operator's profile signs in through the browser,
its token had expired, and the CLI waited (15 minutes by default) for a callback while its sign-in link went to a stderr
the spawner captures. These tests run vm.nebius against a fake `nebius` on PATH (no cloud call is made): the arguments
carry no-browser and the bounds, a CLI that reports the sign-in failure becomes one clear refusal with a hint, a CLI that
never answers is killed at the wall-clock bound, and a change (create/delete) is never given a clock."""
from __future__ import annotations

import contextlib
import io
import os
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
sys.path.insert(0, os.path.join(ROOT, "deploy", "spawn"))
import core  # noqa: E402
import guard  # noqa: E402
import host as hostmod  # noqa: E402
import vm  # noqa: E402

LIST = ("compute", "v1", "instance", "list", "--parent-id", "project-x", "--all")


def read(path):
    with open(path, encoding="utf-8") as source:
        return source.read()


def fake(directory, body):
    path = os.path.join(directory, "nebius")
    with open(path, "w", encoding="utf-8") as out:
        out.write("#!/bin/sh\n" + body)
    os.chmod(path, stat.S_IRWXU)


class NebiusCli(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.argv = os.path.join(self.dir.name, "argv")
        patch = mock.patch.dict(os.environ, {"PATH": self.dir.name + os.pathsep + os.environ["PATH"]})
        patch.start()
        self.addCleanup(patch.stop)
        self.host = hostmod.Host(guard.Admission("upgrade", "demo"))

    def call(self, *args, **kwargs):
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            try:
                return vm.nebius(self.host, *args, **kwargs), errors.getvalue(), None
            except core.Refusal as refusal:
                return None, errors.getvalue(), str(refusal)

    def test_a_read_carries_no_browser_and_the_bounds_and_returns_json(self):
        fake(self.dir.name, 'echo "$@" > %s\necho \'{"items": []}\'\n' % self.argv)
        result, _, refused = self.call(*LIST, read=True)
        self.assertIsNone(refused)
        self.assertEqual(result, {"items": []})
        said = read(self.argv).split()
        for flag in ("--no-browser", "--auth-timeout", "30s", "--timeout", "60s", "--format", "json"):
            self.assertIn(flag, said)

    def test_an_expired_sign_in_is_one_clear_refusal_not_a_wait(self):
        fake(self.dir.name,
             'echo "To complete the authentication process, open the following link in your browser: https://x" >&2\n'
             'echo "Error: get auth data on the client: get from wrapped tokener: authorize: get code: '
             'context deadline exceeded" >&2\nexit 7\n')
        started = time.monotonic()
        result, errors, refused = self.call(*LIST, read=True)
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(refused, "upgrade:nebius-sign-in")
        self.assertIn("nebius iam whoami", errors)
        self.assertNotIn("https://x", errors, "the sign-in link is not echoed")

    def test_other_failures_stay_command_failed_and_an_unauthorized_reply_is_not_a_sign_in_problem(self):
        fake(self.dir.name, 'echo "Error: rpc error: PermissionDenied: not authorized for this parent" >&2\nexit 1\n')
        _, errors, refused = self.call(*LIST, read=True)
        self.assertEqual(refused, "upgrade:command-failed")
        self.assertNotIn("iam whoami", errors)

    def test_a_cli_that_never_answers_is_killed_at_the_wall_clock_bound(self):
        fake(self.dir.name, "sleep 30\n")
        started = time.monotonic()
        with mock.patch.object(vm, "READ_SECONDS", 1):
            _, errors, refused = self.call(*LIST, read=True)
        self.assertLess(time.monotonic() - started, 10)
        self.assertEqual(refused, "upgrade:nebius-timeout")
        self.assertIn("nebius iam whoami", errors)

    def test_a_change_never_opens_a_browser_and_is_given_no_clock(self):
        fake(self.dir.name, 'echo "$@" > %s\necho \'{}\'\n' % self.argv)
        seen = {}
        real = self.host.run

        def spy(argv, data=None, check=True, timeout=None):
            seen["timeout"] = timeout
            return real(argv, data, check, timeout)

        with mock.patch.object(self.host, "run", spy):
            self.call("compute", "v1", "instance", "delete", "--id", "i-1")
        self.assertIsNone(seen["timeout"])
        said = read(self.argv).split()
        self.assertIn("--no-browser", said)
        self.assertNotIn("--auth-timeout", said)

    def test_every_listing_in_the_spawner_is_a_bounded_read(self):
        source = read(os.path.join(ROOT, "deploy", "spawn", "vm.py"))
        for line in source.splitlines():
            if 'nebius(host, "compute", "v1", ' in line and (' "list"' in line or ' "get"' in line):
                self.assertIn("read=True", line, line)
            if 'nebius(host, "compute", "v1", ' in line and (" delete" in line or ' "delete"' in line):
                self.assertNotIn("read=True", line, line)


if __name__ == "__main__":
    unittest.main()
