# SPDX-License-Identifier: AGPL-3.0-or-later
"""The VM's size and labels (deploy/spawn/vm.py): the rehearsal's 4 vCPU / 16 GiB / 80 GiB unless the operator names
another size, never below 2 vCPU / 8 GiB / 60 GiB, and extra labels never replace spawn's own. No cloud call is made.

  python3 -B -m unittest discover -s tests/deploy -p 'test_*.py'"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
sys.path.insert(0, os.path.join(ROOT, "deploy", "spawn"))
import core  # noqa: E402
import vm  # noqa: E402

PLATFORMS = {"items": [
    {"metadata": {"name": "cpu-e2"}, "spec": {"presets": [
        {"name": "2vcpu-8gb", "resources": {"vcpu_count": 2, "memory_gibibytes": 8}},
        {"name": "4vcpu-16gb", "resources": {"vcpu_count": 4, "memory_gibibytes": 16}}]}},
    {"metadata": {"name": "cpu-d3"}, "spec": {"presets": [
        {"name": "2vcpu-8gb", "resources": {"vcpu_count": 2, "memory_gibibytes": 8}},
        {"name": "4vcpu-16gb", "resources": {"vcpu_count": 4, "memory_gibibytes": 16}}]}},
    {"metadata": {"name": "gpu-h200"}, "spec": {"presets": [
        {"name": "1gpu", "resources": {"vcpu_count": 2, "memory_gibibytes": 8, "gpu_count": 1}}]}}]}


class VmSize(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        key = os.path.join(self.dir.name, "id.pub")
        with open(key, "w", encoding="utf-8") as out:
            out.write("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample operator\n")
        self.base = {"AUKORA_NEBIUS_PARENT_ID": "project-x", "AUKORA_NEBIUS_SUBNET_ID": "subnet-x",
                     "AUKORA_NEBIUS_IMAGE_PARENT_ID": "images-x", "AUKORA_SSH_PUBLIC_KEY_FILE": key}

    def settings(self, **extra):
        env = dict(self.base, **extra)
        with mock.patch.dict(os.environ, env, clear=True):
            return vm.environment()

    def refused(self, **extra):
        with self.assertRaises(core.Refusal) as caught:
            self.settings(**extra)
        return str(caught.exception)

    def test_the_default_is_the_rehearsal_size(self):
        values = self.settings()
        self.assertEqual((values["AUKORA_VM_VCPU"], values["AUKORA_VM_MEMORY_GIB"], values["AUKORA_VM_DISK_GIB"]),
                         (4, 16, 80))
        self.assertEqual(values["labels"], [])
        self.assertTrue(values["static_ip"])

    def test_a_named_size_is_taken_and_the_floors_hold(self):
        values = self.settings(AUKORA_VM_VCPU="2", AUKORA_VM_MEMORY_GIB="8", AUKORA_VM_DISK_GIB="80")
        self.assertEqual((values["AUKORA_VM_VCPU"], values["AUKORA_VM_MEMORY_GIB"]), (2, 8))
        for key, value in (("AUKORA_VM_VCPU", "1"), ("AUKORA_VM_MEMORY_GIB", "4"), ("AUKORA_VM_DISK_GIB", "40"),
                           ("AUKORA_VM_VCPU", "02"), ("AUKORA_VM_DISK_GIB", "80.5"), ("AUKORA_VM_VCPU", "x")):
            self.assertEqual(self.refused(**{key: value}), "spawn:nebius-settings", (key, value))

    def test_extra_labels_are_checked_and_never_replace_spawns_own(self):
        self.assertEqual(self.settings(AUKORA_VM_LABELS="purpose=peter-node")["labels"], ["purpose=peter-node"])
        for bad in ("aukora-spawn-id=abc", "delete-after=2026-10-18", "Purpose=x", "purpose=", "a=b c", "a"):
            self.assertEqual(self.refused(AUKORA_VM_LABELS=bad), "spawn:nebius-settings", bad)

    def test_static_address_is_default_with_an_explicit_throwaway_opt_out(self):
        self.assertTrue(self.settings()["static_ip"])
        self.assertTrue(self.settings(AUKORA_VM_STATIC_IP="")["static_ip"])
        self.assertTrue(self.settings(AUKORA_VM_STATIC_IP="1")["static_ip"])
        self.assertFalse(self.settings(AUKORA_VM_STATIC_IP="0")["static_ip"])
        self.assertEqual(self.refused(AUKORA_VM_STATIC_IP="yes"), "spawn:nebius-settings")

    def test_the_smallest_cpu_shape_at_the_named_size(self):
        with mock.patch.object(vm, "nebius", lambda *args, **kwargs: PLATFORMS):
            self.assertEqual(vm.smallest_preset(None, "project-x", 2, 8), ("cpu-d3", "2vcpu-8gb"))
            self.assertEqual(vm.smallest_preset(None, "project-x"), ("cpu-d3", "4vcpu-16gb"))


if __name__ == "__main__":
    unittest.main()
