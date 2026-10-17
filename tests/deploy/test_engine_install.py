# SPDX-License-Identifier: AGPL-3.0-or-later
"""The engine installer's archive extraction and the pre-start home patch, against the two findings of the Codex
review of the node commit (2026-10-17):

  1. engine-prestart.sh must never open, as root, a name the engine could have planted in its home.
  2. safe_extract must never write outside its destination, whatever links an archive carries.

  python3 -B -m unittest discover -s tests/deploy -p 'test_*.py'

The extraction tests run anywhere (lchown is stubbed; nothing here needs root). The pre-start test needs GNU
coreutils (`mv -T`, `stat -c`) and is skipped elsewhere; as a non-root user it fakes only the owner check."""
from __future__ import annotations

import io
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
sys.path.insert(0, os.path.join(ROOT, "deploy", "engine"))
import engine_install  # noqa: E402
import core  # noqa: E402  (deploy/spawn, put on the path by engine_install)


def member(archive, name, kind="file", data=b"x", link="", mode=0o644):
    info = tarfile.TarInfo(name)
    info.mode = mode
    if kind == "file":
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
        return
    info.type = {"dir": tarfile.DIRTYPE, "sym": tarfile.SYMTYPE, "hard": tarfile.LNKTYPE,
                 "fifo": tarfile.FIFOTYPE, "char": tarfile.CHRTYPE}[kind]
    info.linkname = link
    if kind == "dir":
        info.mode = 0o755
    archive.addfile(info)


class Extract(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.mkdtemp(prefix="engine-install-")
        # A sibling of the destination standing in for the already-installed harness (/opt/aukora-engine/dsh), and a
        # folder standing in for /etc: neither may gain a file.
        self.dest = os.path.join(self.scratch, "engine", "plugins")
        os.makedirs(os.path.join(self.scratch, "engine", "dsh"))
        self.etc = os.path.join(self.scratch, "etc")
        os.makedirs(os.path.join(self.etc, "cron.d"))
        self.lchown = mock.patch.object(engine_install.os, "lchown", lambda *a: None)
        self.lchown.start()

    def tearDown(self):
        self.lchown.stop()
        shutil.rmtree(self.scratch)

    def tar(self, members):
        path = os.path.join(self.scratch, "a%d.tar" % len(os.listdir(self.scratch)))
        with tarfile.open(path, "w") as archive:
            for args in members:
                member(archive, *args[:1], **args[1])
        return path

    def refused(self, path, reason, **options):
        with self.assertRaises(core.Refusal) as caught:
            engine_install.safe_extract(path, self.dest, **options)
        self.assertEqual(str(caught.exception), "engine-install:" + reason)

    def nothing_escaped(self):
        self.assertEqual(os.listdir(os.path.join(self.etc, "cron.d")), [])
        self.assertEqual(os.listdir(os.path.join(self.scratch, "engine", "dsh")), [])

    def test_the_review_chain_writes_nothing_outside_with_or_without_links(self):
        etc = os.path.relpath(self.etc, os.path.join(self.dest, "a", "b", "c"))
        chain = [("a", {"kind": "dir"}), ("t", {"kind": "dir"}),
                 ("a/b", {"kind": "sym", "link": "../t"}),
                 ("a/b/c", {"kind": "sym", "link": "../../dsh"}),
                 ("a/b/c/d", {"kind": "sym", "link": etc}),
                 ("a/b/c/d/cron.d/aukora-pwn", {"data": b"* * * * * root id\n"})]
        self.refused(self.tar(chain), "archive-link")  # the plugin archive: the first link refuses
        self.nothing_escaped()
        # A pinned artifact may carry links, but nothing is ever written through one: the second link already
        # lies beneath the first and refuses.
        self.refused(self.tar(chain), "archive-path", links=True)
        self.nothing_escaped()

    def test_the_plugin_archive_takes_only_files_and_folders(self):
        for kind in ("sym", "hard"):
            self.refused(self.tar([("p/lib/index.js", {}), ("p/x", {"kind": kind, "link": "p/lib/index.js"})]),
                         "archive-link")
        for kind in ("fifo", "char"):
            self.refused(self.tar([("p/x", {"kind": kind})]), "archive-member")
        self.refused(self.tar([("../x", {})]), "archive-path")
        self.refused(self.tar([("/x", {})]), "archive-path")
        self.refused(self.tar([("p/x", {}), ("p/x", {})]), "archive-member")  # a repeated name is not overwritten
        engine_install.safe_extract(self.tar([("p", {"kind": "dir"}), ("p/lib/index.js", {"data": b"ok"}),
                                              ("p/bin/run", {"mode": 0o755})]), self.dest)
        with open(os.path.join(self.dest, "p/lib/index.js"), "rb") as handle:
            self.assertEqual(handle.read(), b"ok")
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.dest, "p/bin/run")).st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.dest, "p/lib/index.js")).st_mode), 0o644)

    def test_pinned_artifacts_keep_in_tree_links_and_refuse_the_rest(self):
        engine_install.safe_extract(self.tar([
            ("lib/node_modules/npm/bin/npm-cli.js", {"data": b"cli", "mode": 0o755}),
            ("bin/npm", {"kind": "sym", "link": "../lib/node_modules/npm/bin/npm-cli.js"}),
            ("bin/copy", {"kind": "hard", "link": "lib/node_modules/npm/bin/npm-cli.js"}),
        ]), self.dest, links=True)
        self.assertTrue(os.path.islink(os.path.join(self.dest, "bin/npm")))
        copy = os.path.join(self.dest, "bin/copy")
        self.assertFalse(os.path.islink(copy))
        self.assertNotEqual(os.stat(copy).st_ino, os.stat(os.path.join(self.dest, "bin/npm")).st_ino)
        self.refused(self.tar([("bin/x", {"kind": "sym", "link": "/etc/passwd"})]), "archive-link", links=True)
        self.refused(self.tar([("bin/x", {"kind": "sym", "link": "../../dsh"})]), "archive-link", links=True)
        # Lexically inside, really outside: a/u names dest/dsh on paper, but a/w is a link up to b, so a/u really
        # reaches the harness next door. Found when every link is resolved at the end; nothing stays.
        self.refused(self.tar([("a", {"kind": "dir"}), ("b", {"kind": "dir"}),
                               ("a/w", {"kind": "sym", "link": "../b"}),
                               ("a/u", {"kind": "sym", "link": "w/../../dsh"})]), "archive-link", links=True)
        self.assertFalse(os.path.exists(self.dest))
        # Any refusal leaves no partial tree behind.
        self.refused(self.tar([("ok", {}), ("bin/x", {"kind": "sym", "link": "/etc/passwd"})]), "archive-link",
                     links=True)
        self.assertFalse(os.path.exists(self.dest))

    def test_a_destination_that_is_a_link_refuses(self):
        os.symlink(self.etc, self.dest)
        self.refused(self.tar([("x", {})]), "archive-destination")
        self.nothing_escaped()


class BuildPlugins(unittest.TestCase):
    """deploy/engine/build_plugins.py copies only regular files, never through a link, never outside --out."""

    def setUp(self):
        sys.path.insert(0, os.path.join(ROOT, "deploy", "engine"))
        import build_plugins
        self.build = build_plugins
        self.scratch = tempfile.mkdtemp(prefix="build-plugins-")
        self.out = os.path.join(self.scratch, "out")
        os.makedirs(self.out)

    def tearDown(self):
        shutil.rmtree(self.scratch)

    def test_links_and_escaping_paths_fail_the_build(self):
        from pathlib import Path
        out = Path(self.out)
        secret = Path(self.scratch) / "secret"
        secret.write_text("host file")
        link = Path(self.scratch) / "client.js"
        link.symlink_to(secret)
        with self.assertRaises(SystemExit):
            self.build.copy_file(link, out / "p" / "lib" / "client.js", out)
        self.assertFalse((out / "p" / "lib" / "client.js").exists())
        for bad in ("/etc/x", "../aukora-door/lib/index.js", "a/../../x", "", "a//b"):
            with self.assertRaises(SystemExit):
                self.build.relative_name(bad)
        with self.assertRaises(SystemExit):
            self.build.beneath(out / ".." / "elsewhere", out)
        tree = Path(self.scratch) / "tree"
        (tree / "sub").mkdir(parents=True)
        (tree / "sub" / "x").symlink_to(secret)
        with self.assertRaises(SystemExit):
            self.build.copy_tree(tree, out / "t", out)
        plain = Path(self.scratch) / "plain.js"
        plain.write_text("ok")
        self.build.copy_file(plain, out / "p" / "lib" / "index.js", out)
        self.assertEqual((out / "p" / "lib" / "index.js").read_text(), "ok")


def home_patch_block():
    with open(os.path.join(ROOT, "deploy", "engine", "engine-prestart.sh"), encoding="utf-8") as handle:
        text = handle.read()
    start = text.index("# >>> home-patch")
    return text[start:text.index("# <<< home-patch", start)]


GNU = sys.platform.startswith("linux") and shutil.which("mktemp") is not None


@unittest.skipUnless(GNU, "needs GNU coreutils (mv -T, stat -c); runs on the node or any Linux")
class HomePatch(unittest.TestCase):
    def run_block(self, home):
        prelude = 'set -eu\nfail() { echo "engine-prestart: $1" >&2; exit 1; }\nHOME_DIR=%s\n' % home
        env = dict(os.environ)
        if os.geteuid() != 0:
            # Not root: only the ownership test of the profiles folder is answered by a stub.
            shim = tempfile.mkdtemp(prefix="shim-")
            with open(os.path.join(shim, "stat"), "w") as handle:
                handle.write('#!/bin/sh\necho 0:755\n')
            os.chmod(os.path.join(shim, "stat"), 0o755)
            env["PATH"] = shim + ":" + env["PATH"]
        return subprocess.run(["sh", "-c", prelude + home_patch_block()], env=env, capture_output=True)

    def test_a_planted_link_is_never_followed(self):
        scratch = tempfile.mkdtemp(prefix="home-patch-")
        try:
            home = os.path.join(scratch, "home")
            os.makedirs(os.path.join(home, "profiles"), mode=0o755)
            victim = os.path.join(scratch, "node.json")
            with open(victim, "w") as handle:
                handle.write('{"node":"keep"}')
            os.symlink(victim, os.path.join(home, "cordis.patch.yml.new"))
            os.symlink(victim, os.path.join(home, "cordis.patch.yml"))
            done = self.run_block(home)
            self.assertEqual(done.returncode, 0, done.stderr)
            with open(victim) as handle:
                self.assertEqual(handle.read(), '{"node":"keep"}')
            patch = os.path.join(home, "cordis.patch.yml")
            self.assertFalse(os.path.islink(patch))
            with open(patch) as handle:
                self.assertEqual(handle.read(), "[]\n")
            self.assertEqual(stat.S_IMODE(os.lstat(patch).st_mode), 0o644)
            self.assertEqual(os.listdir(os.path.join(home, "profiles")), [])
            # A folder planted at the name stops the start instead of being written into.
            os.unlink(patch)
            os.mkdir(patch)
            self.assertNotEqual(self.run_block(home).returncode, 0)
            self.assertEqual(os.listdir(patch), [])
        finally:
            shutil.rmtree(scratch)


def admission_block():
    with open(os.path.join(ROOT, "deploy", "engine", "engine-prestart.sh"), encoding="utf-8") as handle:
        text = handle.read()
    start = text.index("# >>> admission")
    return text[start:text.index("# <<< admission", start)]


@unittest.skipUnless(GNU, "needs GNU coreutils (stat -c); runs on the node or any Linux")
class AdmissionFile(unittest.TestCase):
    """The root pre-start trusts the supervisor's admission only from a folder and file the engine cannot have made:
    owner, mode, links and no symbolic link are checked, not assumed (Mistral review)."""

    def run_block(self, ctl, supervisor):
        prelude = 'set -eu\nfail() { echo "engine-prestart: $1" >&2; exit 1; }\nCTL=%s\nSUPERVISOR=%d\n' % (ctl, supervisor)
        return subprocess.run(["sh", "-c", prelude + admission_block()], capture_output=True)

    def test_only_the_supervisors_own_file_in_its_own_folder_passes(self):
        scratch = tempfile.mkdtemp(prefix="admission-")
        try:
            me = os.geteuid()
            ctl = os.path.join(scratch, "ctl")
            os.mkdir(ctl, 0o750)
            os.chmod(ctl, 0o750)
            admission = os.path.join(ctl, "admission.json")
            with open(admission, "w") as handle:
                handle.write('{"release":"%s"}' % ("a" * 64))
            os.chmod(admission, 0o600)
            self.assertEqual(self.run_block(ctl, me).returncode, 0)
            self.assertNotEqual(self.run_block(ctl, me + 1).returncode, 0, "another owner")
            for bits in (0o644, 0o660, 0o666):
                os.chmod(admission, bits)
                self.assertNotEqual(self.run_block(ctl, me).returncode, 0, oct(bits))
            os.chmod(admission, 0o640)
            self.assertEqual(self.run_block(ctl, me).returncode, 0)
            os.chmod(ctl, 0o770)
            self.assertNotEqual(self.run_block(ctl, me).returncode, 0, "group-writable folder")
            os.chmod(ctl, 0o750)
            forged = os.path.join(scratch, "forged.json")
            os.rename(admission, forged)
            os.symlink(forged, admission)
            self.assertNotEqual(self.run_block(ctl, me).returncode, 0, "a link")
            os.unlink(admission)
            os.link(forged, admission)
            self.assertNotEqual(self.run_block(ctl, me).returncode, 0, "two links")
            linked = os.path.join(scratch, "linked")
            os.symlink(ctl, linked)
            self.assertNotEqual(self.run_block(linked, me).returncode, 0, "a linked folder")
        finally:
            shutil.rmtree(scratch)


class EngineDisk(unittest.TestCase):
    """The engine's fixed-size disk (Auma's review R3): two fifths of the root filesystem within 8..40 GiB, and never
    so large that the host keeps less than 8 GiB free beside it."""

    def test_sizes_for_the_node_presets_and_the_floor(self):
        gib = engine_install.GIB
        self.assertEqual(engine_install.engine_disk_bytes(77 * gib, 62 * gib), 30 * gib)
        self.assertEqual(engine_install.engine_disk_bytes(40 * gib, 28 * gib), 16 * gib)
        self.assertEqual(engine_install.engine_disk_bytes(500 * gib, 480 * gib), 40 * gib)
        self.assertEqual(engine_install.engine_disk_bytes(10 * gib, 16 * gib), 8 * gib)
        with self.assertRaises(core.Refusal) as caught:
            engine_install.engine_disk_bytes(40 * gib, 20 * gib)
        self.assertEqual(str(caught.exception), "engine-install:disk-too-small")

    def test_containerds_disk_is_a_tenth_within_six_and_twelve_gib(self):
        gib = engine_install.GIB
        self.assertEqual(engine_install.containers_disk_bytes(77 * gib, 62 * gib), 7 * gib)
        self.assertEqual(engine_install.containers_disk_bytes(40 * gib, 30 * gib), 6 * gib)
        self.assertEqual(engine_install.containers_disk_bytes(500 * gib, 480 * gib), 12 * gib)
        with self.assertRaises(core.Refusal):
            engine_install.containers_disk_bytes(40 * gib, 10 * gib)
        with open(os.path.join(ROOT, "deploy", "engine", "aukora-containerd-disk.mount"), encoding="utf-8") as handle:
            unit = handle.read()
        self.assertIn("What=" + engine_install.CONTAINER_IMAGE + "\n", unit)
        self.assertIn("Where=" + engine_install.CONTAINER_DISK + "\n", unit)
        self.assertIn("Before=containerd.service\n", unit)
        self.assertEqual(engine_install.CONTAINER_UNIT, "var-lib-containerd.mount")

    def test_the_unit_mounts_the_image_over_the_engine_folder_without_suid_or_devices(self):
        with open(os.path.join(ROOT, "deploy", "engine", "aukora-engine-disk.mount"), encoding="utf-8") as handle:
            unit = handle.read()
        self.assertIn("What=" + engine_install.ENGINE_IMAGE + "\n", unit)
        self.assertIn("Where=" + engine_install.ENGINE_DISK + "\n", unit)
        self.assertIn("Options=loop,nosuid,nodev,noatime\n", unit)
        # systemd names a mount unit after its path: /var/lib/aukora-engine -> var-lib-aukora\x2dengine.mount
        self.assertEqual(engine_install.DISK_UNIT, "var-lib-aukora\\x2dengine.mount")


if __name__ == "__main__":
    unittest.main()
