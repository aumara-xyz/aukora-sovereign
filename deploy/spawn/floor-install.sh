#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
set -eu
set +x
umask 077

exec python3 - "$@" <<'PY'
import json
import os
import pwd
import stat
import subprocess
import sys
import tempfile


def refuse(reason):
    raise SystemExit("spawn:floor-install-" + reason)


options = {
    "--config": "/etc/aukora/node.json",
    "--sovereign": "/usr/local/bin/sovereign",
    "--floor-bin": "/usr/local/bin/sovereign-floor",
    "--user": "aukora",
    "--service": "aukora-sovereign.service",
}
arguments = sys.argv[1:]
while arguments:
    if len(arguments) < 2 or arguments[0] not in options:
        refuse("arguments")
    options[arguments[0]] = arguments[1]
    arguments = arguments[2:]

if os.geteuid() != 0:
    refuse("root-required")
os.umask(0o077)
try:
    if pwd.getpwnam(options["--user"]).pw_uid == 0:
        refuse("service-user")
except KeyError:
    refuse("service-user")
for option in ("--config", "--sovereign", "--floor-bin"):
    if not os.path.isabs(options[option]):
        refuse("absolute-path")


def protected(info, directory):
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if (not expected(info.st_mode) or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) & 0o022
            or (not directory and info.st_nlink != 1)):
        refuse("config-protection")


def config_parent(path):
    parts = path.split("/")[1:]
    if any(part in ("", ".", "..") for part in parts):
        refuse("config-protection")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        protected(os.fstat(descriptor), True)
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            protected(os.fstat(descriptor), True)
        return descriptor, parts[-1]
    except BaseException:
        os.close(descriptor)
        raise


def read_config(directory, name):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        protected(info, False)
        content = source.read()
    return info, content


def command(arguments, reason):
    result = subprocess.run(arguments, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            check=False)
    if result.returncode:
        refuse(reason)
    return result.stdout


directory = None
pending = None
try:
    directory, name = config_parent(options["--config"])
    original, content = read_config(directory, name)
    config = json.loads(content)
    if not isinstance(config, dict):
        refuse("config")
    command(["systemctl", "stop", options["--service"]], "stop")
    evidence = command(["runuser", "-u", options["--user"], "--",
                        options["--sovereign"], "floor-evidence", "--config",
                        options["--config"]], "evidence")
    with tempfile.TemporaryDirectory(prefix="aukora-floor-install-") as temporary:
        evidence_file = os.path.join(temporary, "evidence.json")
        with open(evidence_file, "xb") as target:
            target.write(evidence)
        command([options["--floor-bin"], "advance", "--config",
                 options["--config"], "--evidence", evidence_file], "advance")
    current, current_content = read_config(directory, name)
    if (current.st_dev, current.st_ino, current_content) != (
            original.st_dev, original.st_ino, content):
        refuse("config-changed")
    config["release_floor"] = True
    pending = ".floor-install-" + os.urandom(16).hex()
    descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
    with os.fdopen(descriptor, "w", encoding="utf-8") as target:
        os.fchown(target.fileno(), original.st_uid, original.st_gid)
        os.fchmod(target.fileno(), stat.S_IMODE(original.st_mode))
        json.dump(config, target, sort_keys=True, separators=(",", ":"))
        target.write("\n")
        target.flush()
        os.fsync(target.fileno())
    os.replace(pending, name, src_dir_fd=directory, dst_dir_fd=directory)
    pending = None
    os.fsync(directory)
    command(["systemctl", "start", options["--service"]], "start")
except (OSError, ValueError, TypeError):
    refuse("io")
finally:
    if pending is not None:
        os.unlink(pending, dir_fd=directory)
    if directory is not None:
        os.close(directory)
PY
