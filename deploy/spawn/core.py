# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared by the operator tools and the node tools: refusals, canonical JSON, the egress policy and the release
bundle. Standard library only, so one file runs on the operator's machine and on a node. Refusal codes are
'<organ>:<reason>'."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import stat
import sys
import tarfile
import urllib.parse

MAX_SAFE_INTEGER = 2 ** 53 - 1


class Refusal(Exception):
    """The message is the stable code and nothing else."""


def refuse(organ, reason):
    raise Refusal(organ + ":" + reason)


def run_main(organ, main):
    """Run main(argv): a refusal prints its code, any other failure prints '<organ>:io'."""
    try:
        code = main(sys.argv[1:])
    except Refusal as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
    except OSError:
        print(organ + ":io", file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        raise SystemExit(130)
    raise SystemExit(code or 0)


# ---- bytes, hashes, JSON -------------------------------------------------------------------------------------

def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical(value):
    """Sorted keys, no whitespace, UTF-8, no NaN: the bytes every signed or hashed file here carries."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def parse_json(raw, organ, limit):
    """Strict parse: bounded, UTF-8, no duplicate keys, no floats, no NaN."""
    if len(raw) > limit:
        refuse(organ, "too-large")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        refuse(organ, "not-utf8")

    def pairs(items):
        seen = {}
        for key, value in items:
            if key in seen:
                refuse(organ, "duplicate-key")
            seen[key] = value
        return seen

    def reject(_text):
        refuse(organ, "invalid-json")

    try:
        return json.loads(text, object_pairs_hook=pairs, parse_float=reject, parse_constant=reject)
    except (ValueError, RecursionError):
        refuse(organ, "invalid-json")


def is_int(value, low=0, high=MAX_SAFE_INTEGER):
    return isinstance(value, int) and not isinstance(value, bool) and low <= value <= high


def is_hex(value, length):
    return isinstance(value, str) and re.fullmatch("[0-9a-f]{%d}" % length, value) is not None


def exact_keys(value, keys, organ, reason):
    if not isinstance(value, dict) or set(value) != set(keys):
        refuse(organ, reason)
    return value


# ---- names and hosts -----------------------------------------------------------------------------------------

# A hyphen must be followed by a letter: sslip.io reads the first dashed number run in a host name as the address.
NODE_NAME = re.compile(r"[a-z](?:[a-z0-9]|-(?=[a-z])){1,20}\Z")
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOST = re.compile(_LABEL + r"(?:\." + _LABEL + r")+\Z")


def is_node_name(value):
    return isinstance(value, str) and NODE_NAME.match(value) is not None


def is_hostname(value):
    return (isinstance(value, str) and len(value) <= 253 and _HOST.match(value) is not None
            and re.search("[a-z]", value.rsplit(".", 1)[1]) is not None)


# ---- files ---------------------------------------------------------------------------------------------------

def write_all(descriptor, data):
    view = memoryview(data)
    while view:
        view = view[os.write(descriptor, view):]


def read_regular(path, limit, organ):
    """Read a regular file that is not a symbolic link, at most limit bytes."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        refuse(organ, "file-unreadable")
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            refuse(organ, "file-invalid")
        return source.read(limit + 1)


def atomic_write(path, data, mode, owner=None):
    """Write beside the target, flush, then rename over it; the final component is never followed.
    owner is an optional (uid, gid) pair, applied before the rename."""
    directory = os.path.dirname(path) or "."
    temporary = os.path.join(directory, "." + os.path.basename(path) + "." + str(os.getpid()) + ".new")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open(temporary, flags, mode)
    try:
        with os.fdopen(descriptor, "wb") as target:
            os.fchmod(target.fileno(), mode)
            if owner is not None:
                os.fchown(target.fileno(), owner[0], owner[1])
            target.write(data)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    handle = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(handle)
    finally:
        os.close(handle)


# ---- egress policy (row 70) ----------------------------------------------------------------------------------
# One file per node. Its sha256 over the exact bytes is the host policy digest the relay client compares with
# (relay::egress::EgressPolicy.host_policy_digest). Fields v, epoch and relays[{url,port,addresses}] are the relay
# crate's; providers[{host,port,addresses}] are the broker's model endpoints.

EGRESS_VERSION = 1
MAX_RELAYS = 16
MAX_ADDRESSES = 16
# The model provider plus the door's web_fetch hosts (deploy/engine/door-policy-v1.json.in); the supervisor's
# config.rs holds the same bound.
MAX_PROVIDERS = 16
MAX_URL_BYTES = 2048


def public_address(address):
    """The relay crate's rule for a destination a relay may use: global unicast only."""
    ip = ipaddress.ip_address(address)
    if ip.version == 4:
        a, b, c, _ = ip.packed
        return not (a == 0 or a == 10 or (a == 100 and 64 <= b <= 127) or a == 127 or (a == 169 and b == 254)
                    or (a == 172 and 16 <= b <= 31)
                    or (a == 192 and ((b == 0 and c in (0, 2)) or (b == 88 and c == 99) or b == 168))
                    or (a == 198 and (b in (18, 19) or (b == 51 and c == 100)))
                    or (a == 203 and b == 0 and c == 113) or a >= 224)
    words = [int.from_bytes(ip.packed[i:i + 2], "big") for i in range(0, 16, 2)]
    return (words[0] & 0xE000 == 0x2000 and not (words[0] == 0x2001 and words[1] & 0xFE00 == 0)
            and not (words[0] == 0x2001 and words[1] == 0x0DB8) and words[0] != 0x2002
            and not (words[0] == 0x3FFF and words[1] & 0xF000 == 0))


def parse_relay_url(url):
    """Return (host, port) for a relay URL the relay client would accept: wss, no userinfo, no fragment."""
    if not isinstance(url, str) or not url or len(url.encode("utf-8")) > MAX_URL_BYTES:
        refuse("egress", "relay-url")
    if any(ord(c) < 33 or ord(c) == 127 for c in url) or "\\" in url or "#" in url:
        refuse("egress", "relay-url")
    if not url.startswith("wss://"):
        refuse("egress", "relay-url")
    authority = re.split("[/?]", url[len("wss://"):], 1)[0]
    if not authority or "@" in authority:
        refuse("egress", "relay-url")
    try:
        parts = urllib.parse.urlsplit(url)
        host, port = parts.hostname, (443 if parts.port is None else parts.port)
    except ValueError:
        refuse("egress", "relay-url")
    if not host or not 1 <= port <= 65535 or authority.startswith("[") != (":" in host):
        refuse("egress", "relay-url")
    if ":" in host or re.fullmatch(r"[0-9.]+", host):
        try:
            if not public_address(host):
                refuse("egress", "relay-url")
        except ValueError:
            refuse("egress", "relay-url")
    elif not is_hostname(host):
        refuse("egress", "relay-url")
    return host, port


def relay_key(url):
    """What makes two relay URLs the same relay: host, effective port, path and query (the relay crate compares
    parsed URLs, so a trailing slash, an explicit :443 or the host's case do not make another relay)."""
    host, port = parse_relay_url(url)
    parts = urllib.parse.urlsplit(url)
    return host, port, parts.path or "/", parts.query


def _addresses(value, literal):
    if (not isinstance(value, list) or not 1 <= len(value) <= MAX_ADDRESSES
            or not all(isinstance(item, str) for item in value) or len(set(value)) != len(value)):
        refuse("egress", "addresses")
    for item in value:
        try:
            ip = ipaddress.ip_address(item)
        except ValueError:
            refuse("egress", "addresses")
        if str(ip) != item or not public_address(item) or (literal is not None and item != literal):
            refuse("egress", "addresses")
    return value


def validate_policy(raw):
    """The egress policy bytes, or a refusal: canonical JSON, public pinned addresses, unique destinations."""
    policy = parse_json(raw, "egress", 256 * 1024)
    exact_keys(policy, ("v", "epoch", "relays", "providers"), "egress", "policy")
    if policy["v"] != EGRESS_VERSION or not is_int(policy["epoch"], 1) or canonical(policy) != raw:
        refuse("egress", "policy")
    relays, providers = policy["relays"], policy["providers"]
    if not isinstance(relays, list) or not isinstance(providers, list):
        refuse("egress", "policy")
    if len(relays) > MAX_RELAYS or len(providers) > MAX_PROVIDERS:
        refuse("egress", "policy")
    seen = set()
    for rule in relays:
        exact_keys(rule, ("url", "port", "addresses"), "egress", "relay")
        host, port = parse_relay_url(rule["url"])
        if rule["port"] != port or relay_key(rule["url"]) in seen:
            refuse("egress", "relay")
        seen.add(relay_key(rule["url"]))
        literal = host if (":" in host or re.fullmatch(r"[0-9.]+", host)) else None
        _addresses(rule["addresses"], str(ipaddress.ip_address(literal)) if literal else None)
    names = set()
    for rule in providers:
        exact_keys(rule, ("host", "port", "addresses"), "egress", "provider")
        if not is_hostname(rule["host"]) or rule["host"] in names or not is_int(rule["port"], 1, 65535):
            refuse("egress", "provider")
        names.add(rule["host"])
        _addresses(rule["addresses"], None)
    return policy


# ---- the release bundle (rows 80, 81) ------------------------------------------------------------------------
# release.json is canonical JSON naming every file of release.tar with its mode, size and sha256. The sha256 of
# release.json is the release id that a release pointer binds. The tar holds regular files only.

RELEASE_SCHEMA = "aukora-release-v1"
MAX_FILES = 8192
MAX_RELEASE_BYTES = 512 * 1024 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
REQUIRED_FILES = (
    "bin/sovereign", "bin/auma", "bin/aukora-verify", "www/release-manifest.json",
    "deploy/spawn/core.py", "deploy/spawn/caddy.py", "deploy/spawn/node_install.py", "deploy/upgrade/node_release.py",
    "deploy/units/aukora-sovereign.service", "deploy/units/aukora-egress.service", "deploy/units/egress_apply.py",
    "deploy/units/aukora-egress-verify.service", "deploy/units/aukora-egress-verify.timer",
)
_PATH = re.compile(r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*\Z")


def safe_member_path(path):
    return (isinstance(path, str) and len(path) <= 240 and _PATH.match(path) is not None
            and all(part not in (".", "..") for part in path.split("/")))


def parse_manifest(raw):
    """release.json bytes to a dict, or a refusal. The release id is sha256_hex(raw)."""
    manifest = parse_json(raw, "release", MAX_MANIFEST_BYTES)
    exact_keys(manifest, ("schema", "commit", "target", "toolchain", "files"), "release", "manifest")
    if (manifest["schema"] != RELEASE_SCHEMA or not is_hex(manifest["commit"], 40)
            or not isinstance(manifest["target"], str) or not isinstance(manifest["toolchain"], str)
            or len(manifest["target"]) > 64 or len(manifest["toolchain"]) > 512 or canonical(manifest) != raw):
        refuse("release", "manifest")
    files = manifest["files"]
    if not isinstance(files, dict) or not 0 < len(files) <= MAX_FILES:
        refuse("release", "manifest")
    total = 0
    for path, entry in files.items():
        exact_keys(entry, ("bytes", "mode", "sha256"), "release", "manifest")
        if (not safe_member_path(path) or not is_int(entry["bytes"], 0, MAX_RELEASE_BYTES)
                or entry["mode"] not in ("0644", "0755") or not is_hex(entry["sha256"], 64)):
            refuse("release", "manifest")
        total += entry["bytes"]
    if total > MAX_RELEASE_BYTES:
        refuse("release", "too-large")
    for required in REQUIRED_FILES:
        if required not in files:
            refuse("release", "file-missing")
    return manifest


def _members(tar_path, manifest, destination, wanted):
    """Walk release.tar once. Every regular member must be named in the manifest with its exact size and digest;
    anything else (links, devices, directories with content rules, unknown names) refuses. Returns the bytes of the
    wanted members. With a destination, every file is also written there with the manifest's mode."""
    files, seen, found = manifest["files"], set(), {}
    try:
        archive = tarfile.open(tar_path, "r:")
    except (OSError, tarfile.TarError):
        refuse("release", "archive")
    with archive:
        try:
            for member in archive:
                if member.isdir():
                    if not safe_member_path(member.name.rstrip("/")):
                        refuse("release", "archive-path")
                    continue
                entry = files.get(member.name)
                if (not member.isreg() or member.issparse() or entry is None or member.name in seen
                        or member.size != entry["bytes"]):
                    refuse("release", "archive-member")
                seen.add(member.name)
                digest, chunks = hashlib.sha256(), []
                source = archive.extractfile(member)
                target = None
                if destination is not None:
                    path = os.path.join(destination, *member.name.split("/"))
                    os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
                    target = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                try:
                    for block in iter(lambda: source.read(1 << 20), b""):
                        digest.update(block)
                        if member.name in wanted:
                            chunks.append(block)
                        if target is not None:
                            write_all(target, block)
                    if target is not None:
                        os.fchmod(target, int(entry["mode"], 8))
                finally:
                    if target is not None:
                        os.close(target)
                if digest.hexdigest() != entry["sha256"]:
                    refuse("release", "digest")
                if member.name in wanted:
                    found[member.name] = b"".join(chunks)
        except tarfile.TarError:
            refuse("release", "archive")
    if seen != set(files):
        refuse("release", "files-missing")
    return found


def verify_bundle(tar_path, manifest):
    _members(tar_path, manifest, None, ())


def extract_bundle(tar_path, manifest, destination):
    """Write the verified tree into an existing empty directory. The caller removes it on a refusal."""
    _members(tar_path, manifest, destination, ())


def read_bundle_files(tar_path, manifest, names):
    """The verified bytes of selected files (the tool scripts a stage carries)."""
    found = _members(tar_path, manifest, None, set(names))
    if set(found) != set(names):
        refuse("release", "file-missing")
    return found
