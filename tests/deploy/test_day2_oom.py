# SPDX-License-Identifier: AGPL-3.0-or-later
"""The engine's host OOM adjustment freezes and covers the sandbox's actual process tree."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("engine_oom", ROOT / "deploy/engine/engine_oom.py")
OOM = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OOM)
CONTAINER = "1" * 64


class EngineOOMPriority(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="engine-oom-")
        self.addCleanup(self.scratch.cleanup)
        self.proc = Path(self.scratch.name)
        for pid in ("123", "456"):
            (self.proc / pid).mkdir()
            (self.proc / pid / "oom_score_adj").write_text("0\n", encoding="ascii")
        self.proc_patch = mock.patch.object(OOM, "PROC", self.proc)
        self.proc_patch.start()
        self.addCleanup(self.proc_patch.stop)

    def test_sets_and_checks_all_workload_pids_while_paused(self):
        with mock.patch.object(OOM, "docker", side_effect=["", "PID\n123\n456\n", ""]) as docker:
            OOM.set_priority(CONTAINER)
        self.assertEqual(docker.call_args_list, [mock.call("pause", CONTAINER),
                         mock.call("top", CONTAINER, "-eo", "pid"), mock.call("unpause", CONTAINER)])
        for pid in ("123", "456"):
            self.assertEqual((self.proc / pid / "oom_score_adj").read_text(), "500\n")

    def test_invalid_or_empty_pid_lists_fail_and_unpause_without_writes(self):
        for output in ("", "PID\n", "UID PID\n123\n", "PID\n0\n", "PID\n-1\n", "PID\n123 456\n",
                       "PID\n../123\n", "PID\n123\n123\n"):
            with self.subTest(output=output):
                with mock.patch.object(OOM, "docker", side_effect=["", output, ""]) as docker:
                    with self.assertRaises(ValueError):
                        OOM.set_priority(CONTAINER)
                self.assertEqual(docker.call_args_list[-1], mock.call("unpause", CONTAINER))
                self.assertEqual((self.proc / "123/oom_score_adj").read_text(), "0\n")

    def test_pause_and_proc_failures_still_unpause(self):
        failed = subprocess.TimeoutExpired("docker", 15)
        for results, error in (([failed, ""], subprocess.TimeoutExpired),
                               (["", "PID\n999\n", ""], FileNotFoundError)):
            with mock.patch.object(OOM, "docker", side_effect=results) as docker:
                with self.assertRaises(error):
                    OOM.set_priority(CONTAINER)
            self.assertEqual(docker.call_args_list[-1], mock.call("unpause", CONTAINER))

    def test_wrong_score_or_unpause_failure_refuses_activation(self):
        with mock.patch.object(OOM, "docker", side_effect=["", "PID\n123\n", ""]), \
                mock.patch.object(Path, "read_text", return_value="0\n"):
            with self.assertRaisesRegex(ValueError, "did not stick"):
                OOM.set_priority(CONTAINER)
        with mock.patch.object(OOM, "docker", side_effect=["", "PID\n123\n", subprocess.TimeoutExpired("docker", 15)]):
            with self.assertRaises(subprocess.TimeoutExpired):
                OOM.set_priority(CONTAINER)

    def test_rejects_untrusted_container_argument(self):
        with mock.patch.object(OOM, "docker") as docker:
            for value in ("", "--help", "short", "f" * 63, "g" * 64):
                with self.assertRaises(ValueError):
                    OOM.set_priority(value)
            docker.assert_not_called()

    def test_engine_checks_the_actual_container_before_activating(self):
        text = (ROOT / "deploy/engine/engine-run.sh").read_text(encoding="utf-8")
        self.assertIn("container=$(/usr/bin/docker inspect $container_ids", text)
        self.assertIn('print(workloads[0]["Id"])', text)
        self.assertIn('python3 -I /opt/aukora/current/deploy/engine/engine_oom.py "$container"', text)


if __name__ == "__main__":
    unittest.main()
