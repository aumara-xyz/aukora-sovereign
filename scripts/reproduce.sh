#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Row 81: rebuild a commit from a pristine export of it, and byte-compare.
#
#   reproduce.sh build COMMIT OUT_DIR [--twice]   write OUT_DIR/release.tar and OUT_DIR/release.json
#   reproduce.sh compare FILE COMMIT NAME         refuse unless FILE has exactly the bytes a pristine rebuild of COMMIT
#                                                 gives for NAME (sovereign, auma or aukora-verify)
#
# The export has no .git and no untracked file; Cargo reads no configuration outside it; every host path is mapped
# to a fixed name; the clock is the commit's. --twice builds in two different directories and refuses if any file
# differs. Linux builders only: the node's binaries are x86_64-unknown-linux-gnu.
exec python3 -B - "$0" "$@" <<'PY'
import hashlib
import io
import json
import os
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

TARGET = "x86_64-unknown-linux-gnu"
SCHEMA = "aukora-release-v1"
# (package, binary, static): the guest is the only static image; the supervisor and the verifier link normally.
BUILDS = (("supervisor", "sovereign", False), ("verifier", "aukora-verify", False), ("guest", "auma", True))
DEPLOY_FILES = ("deploy/spawn/core.py", "deploy/spawn/caddy.py", "deploy/spawn/node_install.py",
                "deploy/upgrade/node_release.py", "deploy/upgrade/release_probe.py")
UNITS = "deploy/units"
# The engine's installer, policies and in-wall scripts (deploy/engine/NODE.md): every file, so the owner's release
# approval covers what root runs and what the wall is made of.
ENGINE = "deploy/engine"
REQUIRED = ("bin/sovereign", "bin/auma", "bin/aukora-verify", "www/release-manifest.json") + DEPLOY_FILES + (
    "deploy/units/aukora-sovereign.service", "deploy/units/aukora-egress.service", "deploy/units/egress_apply.py",
    "deploy/units/aukora-egress-verify.service", "deploy/units/aukora-egress-verify.timer",
    "deploy/units/systemd-time-wait-sync.service", "deploy/units/aukora-journald.conf")
MAX_RELEASE_BYTES = 512 * 1024 * 1024


class Refusal(Exception):
    pass


def refuse(reason, detail=""):
    raise Refusal("reproduce:" + reason + (": " + detail if detail else ""))


def run(argv, reason, **kwargs):
    done = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
    if done.returncode:
        refuse(reason, done.stderr.decode("utf-8", "replace").strip()[-600:])
    return done.stdout.decode("utf-8", "replace").strip()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def static_elf(data):
    """True for a 64-bit little-endian ELF with no interpreter and no needed library."""
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return False
    phoff, phsize, phnum = (int.from_bytes(data[32:40], "little"), int.from_bytes(data[54:56], "little"),
                            int.from_bytes(data[56:58], "little"))
    dynamic = None
    for index in range(phnum):
        at = phoff + index * phsize
        kind = int.from_bytes(data[at:at + 4], "little")
        if kind == 3:
            return False
        if kind == 2:
            dynamic = (int.from_bytes(data[at + 8:at + 16], "little"), int.from_bytes(data[at + 32:at + 40], "little"))
    if dynamic:
        for at in range(dynamic[0], dynamic[0] + dynamic[1], 16):
            tag = int.from_bytes(data[at:at + 8], "little")
            if tag == 1:
                return False
            if tag == 0:
                break
    return True


def export(repo, commit, destination):
    destination.mkdir()
    archive = subprocess.run(["git", "-C", str(repo), "archive", "--format=tar", commit], stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if archive.returncode:
        refuse("archive-failed", archive.stderr.decode("utf-8", "replace").strip())
    with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as source:
        try:
            source.extractall(destination, filter="data")
        except TypeError:  # Python before the extraction filters
            source.extractall(destination)
    for ancestor in destination.parents:
        for name in ("config", "config.toml"):
            if (ancestor / ".cargo" / name).exists():
                refuse("external-cargo-config", str(ancestor / ".cargo" / name))


def rebuild(repo, commit, work):
    """One pristine build. Returns (files, toolchain): files maps each bundle path to (bytes, mode)."""
    work.mkdir()
    source = work / "source"
    export(repo, commit, source)
    cache = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo")).resolve()
    home = work / "cargo-home"
    home.mkdir()
    for name in ("registry", "git"):
        if (cache / name).exists():
            (home / name).symlink_to(cache / name, target_is_directory=True)
    target_dir, scratch = work / "target", work / "tmp"
    scratch.mkdir()
    environment = {name: os.environ[name] for name in ("PATH", "HOME", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN") if name in os.environ}
    environment.update(
        CARGO_HOME=str(home), CARGO_TARGET_DIR=str(target_dir), CARGO_INCREMENTAL="0", CARGO_NET_OFFLINE="true",
        RUSTUP_AUTO_INSTALL="0", RUSTC_WRAPPER="", RUSTC_WORKSPACE_WRAPPER="", TMPDIR=str(scratch), TZ="UTC", LC_ALL="C",
        SOURCE_DATE_EPOCH=run(["git", "-C", str(repo), "show", "-s", "--format=%ct", commit], "git-failed"),
        CARGO_PROFILE_RELEASE_CODEGEN_UNITS="1", CARGO_PROFILE_RELEASE_INCREMENTAL="false",
        CARGO_PROFILE_RELEASE_DEBUG="0", CARGO_PROFILE_RELEASE_LTO="thin", CARGO_PROFILE_RELEASE_OPT_LEVEL="3",
        CARGO_PROFILE_RELEASE_PANIC="unwind", CARGO_PROFILE_RELEASE_STRIP="none")
    rustc = run(["rustc", "-Vv"], "toolchain-failed", cwd=source, env=environment).splitlines()[0]
    sysroot = Path(run(["rustc", "--print", "sysroot"], "toolchain-failed", cwd=source, env=environment)).resolve()
    node = shutil.which("node")
    if node is None:
        refuse("node-missing")
    node_version = run([node, "--version"], "node-failed", env=environment)
    # Broader prefixes first: rustc and the C compiler use the last mapping that matches.
    remaps = [(work, "/aukora/build"), (source, "/aukora/source"), (cache, "/aukora/cargo-cache"),
              (home, "/aukora/cargo-home"), (sysroot, "/aukora/rust-toolchain")]
    flags = ["--remap-path-prefix=%s=%s" % (path, name) for path, name in remaps]
    environment["CFLAGS"] = " ".join(shlex.quote("-ffile-prefix-map=%s=%s" % (path, name)) for path, name in remaps)
    environment["CXXFLAGS"] = environment["CFLAGS"]
    environment["CC_SHELL_ESCAPED_FLAGS"] = "1"
    built = {}
    for package, binary, static in BUILDS:
        environment["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(flags + (["-C", "target-feature=+crt-static"] if static else []))
        # --target keeps these flags off build scripts and procedural macros, which must stay dynamic.
        run(["cargo", "build", "-p", package, "--bin", binary, "--target", TARGET, "--release", "--locked", "--offline"],
            "build-failed", cwd=source, env=environment)
        path = target_dir / TARGET / "release" / binary
        if not path.is_file():
            refuse("binary-missing", binary)
        data = path.read_bytes()
        for prefix, _name in remaps:
            # A prefix such as /usr (a distribution compiler's sysroot) legitimately appears in any binary.
            if len(prefix.parts) >= 3 and os.fsencode(str(prefix)) in data:
                refuse("host-path", "%s contains %s" % (binary, prefix))
        if static and not static_elf(data):
            refuse("not-static", binary)
        built["bin/" + binary] = (data, "0755")
    run([node, "app/build.mjs"], "app-build-failed", cwd=source, env=environment)
    tree = source / "app" / "release"
    for path in sorted(tree.rglob("*")):
        if path.is_symlink() or (not path.is_file() and not path.is_dir()):
            refuse("app-release-entry", str(path.relative_to(tree)))
        if path.is_file():
            built["www/" + path.relative_to(tree).as_posix()] = (path.read_bytes(), "0644")
    for name in DEPLOY_FILES:
        built[name] = ((source / name).read_bytes(), "0644")
    for path in sorted((source / UNITS).iterdir()):
        if path.is_file() and not path.is_symlink():
            built[UNITS + "/" + path.name] = (path.read_bytes(), "0755" if path.suffix == ".sh" else "0644")
    for path in sorted((source / ENGINE).rglob("*")):
        if path.is_symlink():
            refuse("engine-entry", str(path.relative_to(source)))
        if path.is_file():
            built[path.relative_to(source).as_posix()] = (path.read_bytes(), "0755" if path.suffix == ".sh" else "0644")
    for name in REQUIRED:
        if name not in built:
            refuse("file-missing", name)
    if sum(len(data) for data, _mode in built.values()) > MAX_RELEASE_BYTES:
        refuse("too-large")
    return built, rustc + "; node " + node_version


def manifest_for(commit, built, toolchain):
    files = {name: {"bytes": len(data), "mode": mode, "sha256": sha256(data)} for name, (data, mode) in sorted(built.items())}
    document = {"schema": SCHEMA, "commit": commit, "target": TARGET, "toolchain": toolchain, "files": files}
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def write_tar(path, built, epoch):
    """Sorted names, fixed times and owners, GNU format: the same files always give the same tar bytes."""
    with tarfile.open(path, "w", format=tarfile.GNU_FORMAT) as archive:
        for name in sorted(built):
            data, mode = built[name]
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode, entry.mtime = len(data), int(mode, 8), epoch
            entry.uid = entry.gid = 0
            entry.uname = entry.gname = ""
            archive.addfile(entry, io.BytesIO(data))


def pristine(repo, commit, work, twice):
    first = rebuild(repo, commit, work / "a")
    if twice:
        second = rebuild(repo, commit, work / "b")
        if first[1] != second[1]:
            refuse("toolchain-differs")
        differing = sorted(name for name in set(first[0]) | set(second[0]) if first[0].get(name) != second[0].get(name))
        if differing:
            refuse("bytes-differ", ", ".join(differing[:8]))
    return first


def main(arguments):
    twice = "--twice" in arguments
    arguments = [value for value in arguments if value != "--twice"]
    script = Path(sys.argv[1]).resolve()
    repo = Path(run(["git", "-C", str(script.parent), "rev-parse", "--show-toplevel"], "git-failed"))
    if len(arguments) == 3 and arguments[0] == "build":
        commit = run(["git", "-C", str(repo), "rev-parse", "--verify", arguments[1] + "^{commit}"], "commit-unknown")
        destination = Path(arguments[2]).resolve()
        if destination.exists():
            refuse("output-exists", str(destination))
        with tempfile.TemporaryDirectory(prefix="aukora-reproduce-") as scratch:
            built, toolchain = pristine(repo, commit, Path(scratch), twice)
            epoch = int(run(["git", "-C", str(repo), "show", "-s", "--format=%ct", commit], "git-failed"))
            manifest = manifest_for(commit, built, toolchain)
            destination.mkdir(parents=True)
            write_tar(destination / "release.tar", built, epoch)
            (destination / "release.json").write_bytes(manifest)
        print("release %s  commit %s" % (sha256(manifest), commit))
        return
    if len(arguments) == 4 and arguments[0] == "compare" and arguments[3] in ("sovereign", "auma", "aukora-verify"):
        candidate = Path(arguments[1]).resolve()
        if not candidate.is_file():
            refuse("file-missing", str(candidate))
        commit = run(["git", "-C", str(repo), "rev-parse", "--verify", arguments[2] + "^{commit}"], "commit-unknown")
        with tempfile.TemporaryDirectory(prefix="aukora-reproduce-") as scratch:
            built, _toolchain = pristine(repo, commit, Path(scratch), twice)
        expected = built["bin/" + arguments[3]][0]
        print("%s  %s" % (sha256(expected), arguments[3]))
        if candidate.read_bytes() != expected:
            refuse("bytes-differ", arguments[3])
        print("reproduce:identical")
        return
    refuse("usage", "reproduce.sh build COMMIT OUT_DIR [--twice] | reproduce.sh compare FILE COMMIT NAME")


try:
    main(sys.argv[2:])
except Refusal as error:
    print(error, file=sys.stderr)
    sys.exit(1)
except (OSError, tarfile.TarError, ValueError) as error:
    print("reproduce:failed: %s" % error, file=sys.stderr)
    sys.exit(1)
PY
