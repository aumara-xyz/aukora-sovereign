# SPDX-License-Identifier: AGPL-3.0-or-later
"""Operator side: load a release bundle (the output of scripts/reproduce.sh) and build the small stage archive a node
receives. Nothing from a bundle is used before every file in it has been checked against release.json."""
from __future__ import annotations

import io
import os
import tarfile
from dataclasses import dataclass

import core

STAGE_DIR = "aukora-stage"
NODE_STAGE = "/root/" + STAGE_DIR
# The tools a stage carries, taken out of the verified bundle so root on the node runs the reviewed commit's code.
INSTALL_TOOLS = ("deploy/spawn/core.py", "deploy/spawn/caddy.py", "deploy/spawn/node_install.py",
                 "deploy/upgrade/node_release.py")
UPGRADE_TOOLS = ("deploy/spawn/core.py", "deploy/upgrade/node_release.py")


@dataclass(frozen=True)
class Release:
    directory: str
    manifest_bytes: bytes
    manifest: dict
    digest: str  # sha256 of release.json: the release id a pointer binds
    tar_path: str

    @property
    def commit(self):
        return self.manifest["commit"]


def load(directory):
    if not os.path.isabs(directory) or os.path.islink(directory) or not os.path.isdir(directory):
        core.refuse("spawn", "release-dir")
    raw = core.read_regular(os.path.join(directory, "release.json"), core.MAX_MANIFEST_BYTES, "release")
    manifest = core.parse_manifest(raw)
    tar_path = os.path.join(directory, "release.tar")
    if os.path.islink(tar_path) or not os.path.isfile(tar_path):
        core.refuse("release", "archive")
    core.verify_bundle(tar_path, manifest)
    return Release(directory, raw, manifest, core.sha256_hex(raw), tar_path)


def build_stage(scratch, release, tools, extra):
    """stage.tar with release.json, the tool scripts from the bundle and the extra files (name -> bytes).
    release.tar is pushed separately, into the same directory on the node."""
    files = dict(extra)
    files["release.json"] = release.manifest_bytes
    for name, data in core.read_bundle_files(release.tar_path, release.manifest, tools).items():
        files[os.path.basename(name)] = data
    path = os.path.join(scratch, "stage.tar")
    with tarfile.open(path, "w", format=tarfile.GNU_FORMAT) as archive:
        top = tarfile.TarInfo(STAGE_DIR)
        top.type, top.mode = tarfile.DIRTYPE, 0o700
        archive.addfile(top)
        for name in sorted(files):
            entry = tarfile.TarInfo(STAGE_DIR + "/" + name)
            entry.size, entry.mode = len(files[name]), 0o600
            archive.addfile(entry, io.BytesIO(files[name]))
    return path
