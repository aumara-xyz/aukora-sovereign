# SPDX-License-Identifier: AGPL-3.0-or-later
"""The VM's size and labels (deploy/spawn/vm.py): the rehearsal's 4 vCPU / 16 GiB / 80 GiB unless the operator names
another size, never below 2 vCPU / 8 GiB / 60 GiB, and extra labels never replace spawn's own. No cloud call is made.

  python3 -B -m unittest discover -s tests/deploy -p 'test_*.py'"""
from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
sys.path.insert(0, os.path.join(ROOT, "deploy", "spawn"))
import core  # noqa: E402
import vm  # noqa: E402
import spawn  # noqa: E402

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
        self.assertEqual(self.settings(AUKORA_VM_LABELS="purpose=owner-node")["labels"], ["purpose=owner-node"])
        for bad in ("aukora-spawn-id=abc", "delete-after=2026-10-18", "Purpose=x", "purpose=", "a=b c", "a"):
            self.assertEqual(self.refused(AUKORA_VM_LABELS=bad), "spawn:nebius-settings", bad)

    def test_static_address_is_default_with_an_explicit_throwaway_opt_out(self):
        self.assertTrue(self.settings()["static_ip"])
        self.assertTrue(self.settings(AUKORA_VM_STATIC_IP="")["static_ip"])
        self.assertTrue(self.settings(AUKORA_VM_STATIC_IP="1")["static_ip"])
        self.assertFalse(self.settings(AUKORA_VM_STATIC_IP="0")["static_ip"])
        self.assertEqual(self.refused(AUKORA_VM_STATIC_IP="yes"), "spawn:nebius-settings")

    def test_an_existing_allocation_is_named_exactly_and_only_with_a_static_address(self):
        self.assertEqual(self.settings()["public_allocation"], "")
        self.assertEqual(self.settings(AUKORA_NEBIUS_PUBLIC_ALLOCATION_ID="vpcallocation-e00abc")["public_allocation"],
                         "vpcallocation-e00abc")
        for bad in ("e00abc", "vpcallocation-E00", "vpcallocation-a b"):
            self.assertEqual(self.refused(AUKORA_NEBIUS_PUBLIC_ALLOCATION_ID=bad), "spawn:nebius-settings", bad)
        self.assertEqual(self.refused(AUKORA_NEBIUS_PUBLIC_ALLOCATION_ID="vpcallocation-e00abc", AUKORA_VM_STATIC_IP="0"),
                         "spawn:nebius-settings")

    def test_the_smallest_cpu_shape_at_the_named_size(self):
        with mock.patch.object(vm, "nebius", lambda *args, **kwargs: PLATFORMS):
            self.assertEqual(vm.smallest_preset(None, "project-x", 2, 8), ("cpu-d3", "2vcpu-8gb"))
            self.assertEqual(vm.smallest_preset(None, "project-x"), ("cpu-d3", "4vcpu-16gb"))

    def test_dry_run_checks_vm_options_and_describes_the_selected_size(self):
        options = {"on": "nebius-vm", "dry": True, "release": "bundle", "relay": [], "provider": []}
        selected = {**self.base, "AUKORA_VM_VCPU": "2", "AUKORA_VM_MEMORY_GIB": "8",
                    "AUKORA_VM_DISK_GIB": "60", "AUKORA_VM_STATIC_IP": "0"}
        with mock.patch.dict(os.environ, selected, clear=True), mock.patch.object(spawn.release, "load"), \
                mock.patch.object(spawn.host, "Host") as host, mock.patch.object(spawn.host, "private_dir") as state:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(spawn.create(None, "test-node", options), 0)
            self.assertIn("2 vCPU and 8 GiB, 60 GiB disk; dynamic public address", output.getvalue())
            host.assert_not_called()
            state.assert_not_called()
            for key, value in (("AUKORA_VM_VCPU", "1"), ("AUKORA_VM_LABELS", "Bad=x"),
                               ("AUKORA_VM_STATIC_IP", "yes")):
                with mock.patch.dict(os.environ, {key: value}), self.assertRaises(core.Refusal):
                    spawn.create(None, "test-node", options)
            host.assert_not_called()
            state.assert_not_called()

    def test_static_address_selection_reaches_the_create_request(self):
        for static in (True, False):
            settings = self.settings(AUKORA_VM_STATIC_IP="1" if static else "0")
            plan = SimpleNamespace(host=object(), state=mock.Mock(), instance="test-node", node_id="test-spawn")
            plan.state.has.return_value = False
            plan.state.path = self.dir.name
            with mock.patch.object(vm, "inventory", return_value={}), \
                    mock.patch.object(vm, "find", side_effect=[None, "created-instance"]), \
                    mock.patch.object(vm, "smallest_preset", return_value=("cpu", "small")), \
                    mock.patch.object(vm, "nebius") as api, \
                    mock.patch.object(vm, "public_ip", return_value="public-address"), \
                    mock.patch.object(vm, "Transport") as transport:
                vm.provision(plan, settings)
                args = api.call_args.args
                nic = json.loads(args[args.index("--network-interfaces") + 1])[0]
                self.assertEqual(nic["public_ip_address"], {"static": True} if static else {})
                self.assertIn("aukora-spawn-id=test-spawn", args)
                transport.return_value.wait.assert_called_once()


if __name__ == "__main__":
    unittest.main()
