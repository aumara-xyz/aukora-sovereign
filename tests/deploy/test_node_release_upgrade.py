# SPDX-License-Identifier: AGPL-3.0-or-later
"""The owner-approved upgrade on the node (deploy/engine/NODE.md O17): `node_release.py offer` makes a staged release
the offered one and switches nothing; `follow` (the supervisor's root pre-start step) switches the current-release
link only to the staged release the owner's floor names, and otherwise leaves everything as it was.

  python3 -B -m unittest discover -s tests/deploy -p 'test_*.py'

Runs anywhere: the root-only parts (the switch lock's owner check, the installed binary's hash check, reading the
floor through the binary as the service user, systemd) are stubbed; the links, the staged-release checks and the
active record are the real code against a scratch /opt/aukora."""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
sys.path.insert(0, os.path.join(ROOT, "deploy", "upgrade"))
import node_release  # noqa: E402
import core  # noqa: E402


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class Upgrade(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.mkdtemp(prefix="node-release-")
        root = os.path.join(self.scratch, "opt-aukora")
        state = os.path.join(self.scratch, "release-state")
        os.makedirs(os.path.join(root, "releases"))
        os.makedirs(state)
        self.patches = [
            mock.patch.object(node_release, "ROOT", root),
            mock.patch.object(node_release, "RELEASES", root + "/releases"),
            mock.patch.object(node_release, "CURRENT", root + "/current"),
            mock.patch.object(node_release, "PREVIOUS", root + "/previous"),
            mock.patch.object(node_release, "OFFERED", root + "/offered"),
            mock.patch.object(node_release, "STATE", state),
            mock.patch.object(node_release, "ACTIVE", state + "/active.json"),
            mock.patch.object(node_release, "ANCHOR", state + "/anchor.json"),
            mock.patch.object(node_release, "ANCHOR_OWNER", os.getuid()),
            # Root-only checks, stubbed: the lock's ownership, the installed binary's hash, systemd.
            mock.patch.object(node_release, "switch_lock", contextlib.nullcontext),
            mock.patch.object(node_release, "trusted_verifier", lambda rid, active: "/bin/sovereign-" + rid),
            mock.patch.object(node_release, "sync_units", lambda directory: False),
        ]
        for patch in self.patches:
            patch.start()
        self.floor = None
        self.asked = []
        mock.patch.object(node_release, "approved_floor", self.read_floor).start()
        self.old = self.stage("a" * 40)
        self.new = self.stage("b" * 40)
        self.third = self.stage("c" * 40)
        node_release.point(node_release.CURRENT, "releases/" + self.old[0])
        node_release.write_active(self.old[0], self.old[1], self.old[2], 0, None)

    def tearDown(self):
        mock.patch.stopall()
        shutil.rmtree(self.scratch)

    @staticmethod
    def make_floor(release, sequence, spent, history=()):
        """An owner floor as `sovereign release floor` prints it: `spent` approvals, newest last."""
        return {"digest": release[2], "epoch": 1, "sequence": sequence, "head": format(sequence, "064x"),
                "history": [r[2] for r in history], "spent": ["1:%d:%s" % (n, "e" * 64) for n in spent]}

    def read_floor(self, binary):
        self.asked.append(binary)
        return self.floor

    def stage(self, commit):
        files = {name: {"bytes": 1, "mode": "0755" if name.startswith("bin/") else "0644", "sha256": "0" * 64}
                 for name in core.REQUIRED_FILES}
        manifest = {"schema": core.RELEASE_SCHEMA, "commit": commit, "target": "x86_64-unknown-linux-gnu",
                    "toolchain": "1.99.1", "files": files}
        raw = canonical(manifest)
        digest = hashlib.sha256(raw).hexdigest()
        rid = commit[:12] + "-" + digest[:12]
        directory = os.path.join(node_release.RELEASES, rid)
        os.makedirs(directory)
        with open(os.path.join(directory, "release.json"), "wb") as target:
            target.write(raw)
        with open(os.path.join(directory, ".verified"), "w") as target:
            target.write(digest + "\n")
        return rid, manifest, digest

    def test_offer_switches_nothing_and_follow_waits_for_the_owners_floor(self):
        self.assertEqual(node_release.offer(self.new[0]), self.new[0])
        self.assertEqual(node_release.link_id(node_release.OFFERED), self.new[0])
        self.assertEqual(node_release.link_id(node_release.CURRENT), self.old[0], "offering switches nothing")
        # The floor still names the running release (card not approved, declined, or expired): nothing moves, and
        # root anchors that floor.
        self.floor = self.make_floor(self.old, 10, [10])
        self.assertEqual(node_release.follow(), "unchanged (anchored)")
        self.assertEqual(node_release.follow(), "unchanged")
        # No owner floor yet, or it could not be read: nothing moves either.
        self.floor = None
        self.assertEqual(node_release.follow(), "unchanged")
        self.assertEqual(node_release.link_id(node_release.CURRENT), self.old[0])
        self.assertEqual(node_release.read_active()["id"], self.old[0])
        # The question is asked of the installed (current) release's binary, never the candidate's.
        self.assertTrue(all(binary.endswith(self.old[0]) for binary in self.asked))

    def test_follow_switches_to_the_release_the_owner_approved(self):
        node_release.offer(self.new[0])
        self.floor = self.make_floor(self.new, 20, [10, 20], [self.old])
        self.assertEqual(node_release.follow(), "switched to " + self.new[0])
        self.assertEqual(node_release.link_id(node_release.CURRENT), self.new[0])
        self.assertEqual(node_release.link_id(node_release.PREVIOUS), self.old[0])
        self.assertIsNone(node_release.link_id(node_release.OFFERED), "the offer is spent")
        active = node_release.read_active()
        self.assertEqual((active["id"], active["release"], active["commit"]), (self.new[0], self.new[2], "b" * 40))
        # Started again on the new release, the floor names it: nothing more to do.
        self.assertEqual(node_release.follow(), "unchanged")

    def test_an_approved_release_is_followed_even_if_the_offer_was_taken_back(self):
        node_release.offer(self.new[0])
        self.assertEqual(node_release.withdraw(), "withdrawn")
        self.floor = self.make_floor(self.new, 20, [10, 20], [self.old])
        self.assertEqual(node_release.follow(), "switched to " + self.new[0])

    def test_a_floor_naming_a_release_that_is_not_staged_switches_nothing(self):
        self.floor = {**self.make_floor(self.new, 20, [10, 20], [self.old]), "digest": "f" * 64}
        self.assertEqual(node_release.follow(), "approved-release-not-staged")
        self.assertEqual(node_release.link_id(node_release.CURRENT), self.old[0])

    def test_a_tampered_staged_release_is_never_switched_to(self):
        node_release.offer(self.new[0])
        with open(os.path.join(node_release.RELEASES, self.new[0], "release.json"), "ab") as target:
            target.write(b" ")
        self.floor = self.make_floor(self.new, 20, [10, 20], [self.old])
        self.assertEqual(node_release.follow(), "approved-release-not-staged")
        self.assertEqual(node_release.link_id(node_release.CURRENT), self.old[0])

    def test_a_restored_snapshot_of_an_older_floor_is_never_followed(self):
        # Codex review (B30): A runs, root anchors A's floor; the owner approves B and the node switches; the aukora
        # uid then restores the A-era Aura and floor (internally consistent, its approval of A valid) and restarts.
        a_floor = self.make_floor(self.old, 10, [10])
        self.floor = a_floor
        node_release.follow()
        node_release.offer(self.new[0])
        self.floor = self.make_floor(self.new, 20, [10, 20], [self.old])
        self.assertEqual(node_release.follow(), "switched to " + self.new[0])
        self.floor = a_floor
        self.assertTrue(node_release.follow().startswith("refused: the floor is behind"))
        self.assertEqual(node_release.link_id(node_release.CURRENT), self.new[0], "never rolled back to A")
        # A divergent floor (a later version that does not extend the spent approvals) is refused too.
        self.floor = self.make_floor(self.old, 30, [10, 29], [self.new])
        self.assertTrue(node_release.follow().startswith("refused"))
        self.assertEqual(node_release.link_id(node_release.CURRENT), self.new[0])
        # So is an anchor root did not write.
        os.chmod(node_release.ANCHOR, 0o666)
        with self.assertRaises(core.Refusal):
            node_release.follow()

    def test_a_then_b_then_c_and_an_owner_approved_rollback(self):
        self.floor = self.make_floor(self.old, 10, [10])
        node_release.follow()
        node_release.offer(self.new[0])
        self.floor = self.make_floor(self.new, 20, [10, 20], [self.old])
        self.assertEqual(node_release.follow(), "switched to " + self.new[0])
        node_release.offer(self.third[0])
        self.floor = self.make_floor(self.third, 30, [10, 20, 30], [self.old, self.new])
        self.assertEqual(node_release.follow(), "switched to " + self.third[0])
        # Going back to B is a new owner approval (a later floor naming B): followed like any other step.
        node_release.offer(self.new[0])
        self.floor = self.make_floor(self.new, 40, [10, 20, 30, 40], [self.old, self.third])
        self.assertEqual(node_release.follow(), "switched to " + self.new[0])
        self.assertEqual(node_release.read_active()["id"], self.new[0])
        with open(node_release.ANCHOR, "rb") as anchor:
            self.assertEqual(json.loads(anchor.read())["floor"]["sequence"], 40)

    def test_the_first_floor_root_sees_must_follow_the_running_release(self):
        # No anchor yet: a floor that names another release and did not move on from the running one is refused.
        self.floor = self.make_floor(self.new, 20, [20], [])
        self.assertTrue(node_release.follow().startswith("refused"))
        self.assertEqual(node_release.link_id(node_release.CURRENT), self.old[0])

    def test_the_current_release_cannot_be_offered(self):
        with self.assertRaises(core.Refusal):
            node_release.offer(self.old[0])
        with self.assertRaises(core.Refusal):
            node_release.offer("0" * 12 + "-" + "0" * 12)


if __name__ == "__main__":
    unittest.main()
