# SPDX-License-Identifier: AGPL-3.0-or-later
"""Runs once as root on a node that node_install.py already installed (deploy/engine/NODE.md): adds the engine.

  python3 -B /opt/aukora/current/deploy/engine/engine_install.py --stage /root/aukora-engine-stage

Installs, every artifact checked against deploy/engine/engine-pins.json before use:
  users       auma (the engine, inside the wall), kira (Kira 2 and its models), group kira-clients (aukora joins it)
  packages    docker.io, nftables, polkitd, curl, xz-utils, unzip
  artifacts   node, the pinned harness, OpenShell 0.1.4, the sandbox image, the read-only toolchain, llama.cpp, the two
              model files; the plugin packages from the stage (engine-plugins.tar, fingerprinted by the supervisor and
              approved by the owner before any is loaded)
  config      /etc/aukora/engine-v1.json (engine origin), door-policy-v1.json (the door inside the node),
              /etc/aukora/engine/{openshell-policy.yaml, openshell-gateway.toml, resolv.conf}, engine.env,
              docker daemon.json (the DNS posture), the polkit rule, tmpfiles
  Kira        agents: auma (the door's non-owner token, /etc/aukora/door-kira.token, aukora 0600) and owner (root's
              alone, /root/aukora-kira-owner.token); services embed, rerank, kira
  Caddy       the engine host (engine.<shell host>) beside the node's block, validated, reloaded, rolled back
It starts the fences, the gateway and Kira, and restarts the supervisor so it reads the door policy and the engine
configuration. It never starts the engine: the supervisor does, after the owner's approvals.

The stage folder holds engine-plugins.tar and the operator artifacts named `operator:<file>` in the pins. Refuses
on a node that has no engine-capable release, already has an engine, is not a VM node, or whose inventory lacks the
engine/plugin-set.json target."""
from __future__ import annotations

import grp
import json
import os
import pwd
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, os.pardir, "spawn"))
import core  # noqa: E402

RELEASE = "/opt/aukora/current"
ENGINE_ROOT = "/opt/aukora-engine"
KIRA_ROOT = "/opt/aukora-kira"
CONFIG = "/etc/aukora"
ENGINE_CONFIG = CONFIG + "/engine"
CACHE = "/var/cache/aukora-engine"
PACKAGES = ("docker.io", "nftables", "polkitd", "curl", "xz-utils", "unzip", "openssl")
ENGINE_UNITS = ("aukora-engine-fence.service", "aukora-kira-embed.service", "aukora-kira-rerank.service",
                "aukora-kira.service", "aukora-openshell-gateway.service")
ENGINE_LISTEN = "127.0.0.1:18081"
STAGE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,120}\Z")


def run(argv, data=None, env=None, check=True):
    done = subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, check=False)
    if check and done.returncode != 0:
        print("engine-install: " + " ".join(argv[:3]) + " exited " + str(done.returncode) + "\n"
              + done.stderr[-400:].decode("utf-8", "replace"), file=sys.stderr)
        core.refuse("engine-install", "command-failed")
    return done


def owned_dir(path, mode, user="root", group="root"):
    os.makedirs(path, exist_ok=True)
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode):
        core.refuse("engine-install", "not-a-directory")
    os.chown(path, pwd.getpwnam(user).pw_uid, grp.getgrnam(group).gr_gid)
    os.chmod(path, mode)


def release_file(relative):
    return os.path.join(RELEASE, "deploy", relative)


# ---- preconditions ---------------------------------------------------------------------------------------------

def preconditions():
    if os.geteuid() != 0:
        core.refuse("engine-install", "root-required")
    node = core.parse_json(core.read_regular(CONFIG + "/node.json", 64 * 1024, "engine-install"), "engine-install", 64 * 1024)
    for path in ("engine/engine-pins.json", "engine/entry.mjs", "units/aukora-engine.service"):
        if not os.path.isfile(release_file(path)):
            core.refuse("engine-install", "release-without-engine")
    if os.path.lexists(CONFIG + "/engine-v1.json"):
        core.refuse("engine-install", "engine-exists")
    inventory = core.parse_json(core.read_regular(CONFIG + "/gate-targets-v1.json", 64 * 1024, "engine-install"),
                                "engine-install", 64 * 1024)
    if not any(t.get("id") == "engine/plugin-set.json" for t in inventory.get("targets", [])):
        core.refuse("engine-install", "inventory-lacks-engine-target")  # an older node needs an owner-approved sync
    caddyfile = core.read_regular("/etc/caddy/Caddyfile", 1 << 20, "engine-install").decode("utf-8", "replace")
    if caddyfile.count("# BEGIN AUKORA SOVEREIGN ") != 1:
        core.refuse("engine-install", "not-a-vm-node")  # an LXD host's shared Caddy is not ours to extend
    shell_host = node["shell_origin"][len("https://"):]
    if not core.is_hostname(shell_host) or not core.is_hostname("engine." + shell_host):
        core.refuse("engine-install", "shell-host")
    return node, shell_host


def load_pins():
    pins = core.parse_json(core.read_regular(release_file("engine/engine-pins.json"), 64 * 1024, "engine-install"),
                           "engine-install", 64 * 1024)
    artifacts = pins["artifacts"]
    for name, item in artifacts.items():
        if not (isinstance(item.get("sha256"), str) and core.is_hex(item["sha256"], 64)):
            print("engine-install: no pin for " + name, file=sys.stderr)
            core.refuse("engine-install", "engine-pin-missing")
    # The Kira units name the model files by their pins; a pin change without the unit change refuses here.
    for kind, unit in (("embed_model", "aukora-kira-embed.service"), ("rerank_model", "aukora-kira-rerank.service")):
        text = core.read_regular(release_file("units/" + unit), 64 * 1024, "engine-install").decode("ascii")
        if artifacts[kind]["sha256"] not in text:
            core.refuse("engine-install", "model-pin-unit-mismatch")
    return artifacts


# ---- artifacts -------------------------------------------------------------------------------------------------

def fetch(name, item, stage):
    """The verified local path of one artifact: from the stage (operator:FILE) or downloaded by root over HTTPS."""
    url = item["url"]
    if url.startswith("operator:"):
        filename = url[len("operator:"):]
        if not STAGE_NAME.match(filename):
            core.refuse("engine-install", "pin-url")
        path = os.path.join(stage, filename)
    else:
        if not url.startswith("https://"):
            core.refuse("engine-install", "pin-url")
        owned_dir(CACHE, 0o700)
        path = os.path.join(CACHE, name)
        if not (os.path.isfile(path) and core.sha256_file(path) == item["sha256"]):
            run(["curl", "--fail", "--silent", "--show-error", "--location", "--proto", "=https", "--tlsv1.2",
                 "--max-time", "1800", "--output", path + ".part", url])
            os.replace(path + ".part", path)
    info = os.lstat(path) if os.path.lexists(path) else None
    if info is None or not stat.S_ISREG(info.st_mode):
        core.refuse("engine-install", "artifact-missing:" + name)
    if core.sha256_file(path) != item["sha256"]:
        core.refuse("engine-install", "artifact-digest:" + name)
    if "bytes" in item and info.st_size != item["bytes"]:
        core.refuse("engine-install", "artifact-size:" + name)
    return path


def safe_extract(archive_path, destination, strip=0):
    """Regular files, folders and in-tree links only; no absolute or parent paths; everything root-owned, not
    writable by others. A link that points outside the tree refuses."""
    if os.path.lexists(destination):
        shutil.rmtree(destination)
    os.makedirs(destination, mode=0o755)
    with tarfile.open(archive_path) as archive:
        for member in archive.getmembers():
            parts = [p for p in member.name.split("/") if p not in ("", ".")][strip:]
            if not parts:
                continue
            if any(p == ".." for p in parts) or member.name.startswith("/"):
                core.refuse("engine-install", "archive-path")
            target = os.path.join(destination, *parts)
            if member.isdir():
                os.makedirs(target, mode=0o755, exist_ok=True)
            elif member.isfile():
                os.makedirs(os.path.dirname(target), mode=0o755, exist_ok=True)
                with archive.extractfile(member) as source, open(target, "wb") as out:
                    shutil.copyfileobj(source, out)
                os.chmod(target, 0o755 if member.mode & 0o111 else 0o644)
            elif member.issym():
                link = member.linkname
                resolved = os.path.normpath(os.path.join(os.path.dirname(target), link))
                if link.startswith("/") or not resolved.startswith(destination + os.sep):
                    core.refuse("engine-install", "archive-link")
                os.makedirs(os.path.dirname(target), mode=0o755, exist_ok=True)
                os.symlink(link, target)
            else:
                core.refuse("engine-install", "archive-member")
    for root, dirs, files in os.walk(destination):
        for name in dirs + files:
            path = os.path.join(root, name)
            os.lchown(path, 0, 0)


def install_artifacts(artifacts, stage):
    owned_dir(ENGINE_ROOT, 0o755)
    owned_dir(KIRA_ROOT, 0o755)
    safe_extract(fetch("node", artifacts["node"], stage), ENGINE_ROOT + "/node", strip=1)
    safe_extract(fetch("dsh", artifacts["dsh"], stage), ENGINE_ROOT + "/dsh")
    if not os.path.isfile(ENGINE_ROOT + "/dsh/node_modules/@deepseek-ai/dsh/lib/bin.js"):
        core.refuse("engine-install", "dsh-layout")
    version = json.load(open(ENGINE_ROOT + "/dsh/node_modules/@deepseek-ai/dsh/package.json"))["version"]
    if version != "0.2.1-alpha.5":
        core.refuse("engine-install", "dsh-version")
    safe_extract(fetch("rust", artifacts["rust"], stage), "/opt/rust")
    openshell = fetch("openshell", artifacts["openshell"], stage)
    scratch = CACHE + "/openshell"
    safe_extract(openshell, scratch)
    for binary in ("openshell", "openshell-gateway"):
        found = [os.path.join(r, binary) for r, _, files in os.walk(scratch) if binary in files]
        if len(found) != 1:
            core.refuse("engine-install", "openshell-layout")
        shutil.copyfile(found[0], "/usr/local/bin/" + binary)
        os.chmod("/usr/local/bin/" + binary, 0o755)
    shutil.rmtree(scratch)
    loaded = run(["docker", "load", "--input", fetch("sandbox_image", artifacts["sandbox_image"], stage)]).stdout
    match = re.search(rb"Loaded image(?: ID)?: (\S+)", loaded)
    if match is None:
        core.refuse("engine-install", "sandbox-image")
    image = match.group(1).decode("ascii")
    llama = fetch("llama", artifacts["llama"], stage)
    target = KIRA_ROOT + "/llama"
    if os.path.lexists(target):
        shutil.rmtree(target)
    os.makedirs(target, mode=0o755)
    with zipfile.ZipFile(llama) as archive:
        for member in archive.infolist():
            name = os.path.basename(member.filename)
            if member.is_dir() or not (name == "llama-server" or name.endswith(".so")):
                continue  # only the server and its shared libraries
            with archive.open(member) as source, open(os.path.join(target, name), "wb") as out:
                shutil.copyfileobj(source, out)
            os.chmod(os.path.join(target, name), 0o755)
    if not os.path.isfile(target + "/llama-server"):
        core.refuse("engine-install", "llama-layout")
    owned_dir(KIRA_ROOT + "/models", 0o755)
    for kind, name in (("embed_model", "embed.gguf"), ("rerank_model", "rerank.gguf")):
        shutil.copyfile(fetch(kind, artifacts[kind], stage), KIRA_ROOT + "/models/" + name)
        os.chmod(KIRA_ROOT + "/models/" + name, 0o644)
        if core.sha256_file(KIRA_ROOT + "/models/" + name) != artifacts[kind]["sha256"]:
            core.refuse("engine-install", "model-copy")
    # The plugin packages: staged only. Nothing loads them until the owner approves their fingerprints.
    safe_extract(os.path.join(stage, "engine-plugins.tar"), ENGINE_ROOT + "/plugins")
    # The in-wall scripts and the authority overlay come from the release itself.
    owned_dir(ENGINE_ROOT + "/aukora", 0o755)
    for name in ("entry.mjs", "authority.patch.yml"):
        shutil.copyfile(release_file("engine/" + name), ENGINE_ROOT + "/aukora/" + name)
        os.chmod(ENGINE_ROOT + "/aukora/" + name, 0o644)
    return image


# ---- users, config, Kira, Caddy --------------------------------------------------------------------------------

def ensure_users():
    for group in ("kira-clients",):
        if run(["getent", "group", group], check=False).returncode != 0:
            run(["groupadd", "--system", group])
    for user, home in (("auma", "/var/lib/aukora-engine/work"), ("kira", "/var/lib/aukora-kira")):
        try:
            pwd.getpwnam(user)
        except KeyError:
            run(["useradd", "--system", "--user-group", "--home-dir", home, "--no-create-home",
                 "--shell", "/usr/sbin/nologin", user])
    run(["usermod", "--append", "--groups", "kira-clients", "aukora"])
    auma = pwd.getpwnam("auma")
    if auma.pw_uid in (0, pwd.getpwnam("aukora").pw_uid, pwd.getpwnam("kira").pw_uid):
        core.refuse("engine-install", "engine-uid")
    return auma.pw_uid, auma.pw_gid


def write_config(shell_host, uid, gid, image):
    owned_dir(ENGINE_CONFIG, 0o755)
    aukora_gid = grp.getgrnam("aukora").gr_gid
    policy = core.read_regular(release_file("engine/openshell-policy.yaml"), 64 * 1024, "engine-install")
    core.atomic_write(ENGINE_CONFIG + "/openshell-policy.yaml", policy.replace(b"@AUMA_UID@", str(uid).encode()), 0o644)
    for name in ("openshell-gateway.toml", "resolv.conf"):
        core.atomic_write(ENGINE_CONFIG + "/" + name, core.read_regular(release_file("engine/" + name), 64 * 1024,
                                                                         "engine-install"), 0o644)
    env = "AUMA_UID=%d\nAUMA_GID=%d\nENGINE_HOST=engine.%s\nSANDBOX_IMAGE=%s\n" % (uid, gid, shell_host, image)
    core.atomic_write(CONFIG + "/engine.env", env.encode("ascii"), 0o644)
    door = core.read_regular(release_file("engine/door-policy-v1.json.in"), 64 * 1024, "engine-install")
    door = door.replace(b"@AUMA_UID@", str(uid).encode())
    json.loads(door)
    core.atomic_write(CONFIG + "/door-policy-v1.json", door, 0o640, (0, aukora_gid))
    engine = core.canonical({
        "v": 1, "plugin_root": ENGINE_ROOT + "/plugins", "control_dir": "/run/aukora-engine-ctl",
        "web_socket": "/run/aukora-engine/io/web.sock", "launch_file": "/run/aukora-engine/io/launch-url",
        "host": "engine." + shell_host, "listen": ENGINE_LISTEN, "session_hours": 12})
    core.atomic_write(CONFIG + "/engine-v1.json", engine, 0o640, (0, aukora_gid))
    os.makedirs("/etc/polkit-1/rules.d", mode=0o755, exist_ok=True)
    core.atomic_write("/etc/polkit-1/rules.d/50-aukora-engine.rules",
                      core.read_regular(release_file("engine/aukora-engine.rules"), 4096, "engine-install"), 0o644)
    tmpfiles = core.read_regular(release_file("engine/aukora-engine.tmpfiles"), 4096, "engine-install")
    core.atomic_write("/etc/tmpfiles.d/aukora-engine.conf", tmpfiles.replace(b"@AUMA@", b"auma"), 0o644)
    run(["systemd-tmpfiles", "--create", "/etc/tmpfiles.d/aukora-engine.conf"])
    owned_dir("/var/lib/aukora-engine", 0o755)
    owned_dir("/var/lib/aukora-engine/work", 0o700, "auma", "auma")
    owned_dir("/var/lib/aukora-engine/home", 0o1770, "root", "auma")
    # The gateway's JWT keys (wall test, finding 3): root's alone.
    jwt = "/var/lib/aukora-openshell/jwt"
    owned_dir("/var/lib/aukora-openshell", 0o700)
    owned_dir(jwt, 0o700)
    if not os.path.exists(jwt + "/signing.pem"):
        run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", jwt + "/signing.pem"])
        run(["openssl", "pkey", "-in", jwt + "/signing.pem", "-pubout", "-out", jwt + "/public.pem"])
        core.atomic_write(jwt + "/kid", secrets.token_hex(8).encode("ascii"), 0o600)


def register_kira():
    """Two agents: auma (the door's, non-owner, own scope) and owner (root's alone)."""
    owned_dir("/var/lib/aukora-kira", 0o700, "kira", "kira")
    sovereign = RELEASE + "/bin/sovereign"
    scratch = "/var/lib/aukora-kira/.tokens"
    owned_dir(scratch, 0o700, "kira", "kira")
    for agent, extra, destination, owner in (
            ("auma", ["--scopes", "auma"], CONFIG + "/door-kira.token", "aukora"),
            ("owner", ["--owner"], "/root/aukora-kira-owner.token", "root")):
        if os.path.exists(destination):
            continue
        temporary = scratch + "/" + agent
        run(["runuser", "-u", "kira", "--", sovereign, "kira", "register", agent, "--state", "/var/lib/aukora-kira",
             "--token-file", temporary] + extra)
        data = core.read_regular(temporary, 4096, "engine-install")
        os.unlink(temporary)
        account = pwd.getpwnam(owner)
        core.atomic_write(destination, data, 0o600, (account.pw_uid, account.pw_gid))
    os.rmdir(scratch)


ENGINE_BLOCK = """# BEGIN AUKORA ENGINE {name}
https://{engine} {{
	header {{
		Strict-Transport-Security "max-age=31536000"
		X-Content-Type-Options "nosniff"
		Referrer-Policy "no-referrer"
		-Server
	}}
	request_body {{
		max_size 16MiB
	}}
	@launch_token query token=*
	handle @launch_token {{
		respond 404
	}}
	handle {{
		reverse_proxy {upstream} {{
			flush_interval -1
			header_up Host {{host}}
			header_up X-Forwarded-Proto https
			header_up X-Forwarded-For {{remote_host}}
			header_up -X-Forwarded-Host
			header_up -Forwarded
		}}
	}}
}}

http://{engine} {{
	@launch_token query token=*
	handle @launch_token {{
		respond 404
	}}
	handle {{
		redir https://{{host}}{{uri}} permanent
	}}
}}
# END AUKORA ENGINE {name}
"""


def configure_caddy(name, shell_host):
    path = "/etc/caddy/Caddyfile"
    before = core.read_regular(path, 1 << 20, "engine-install")
    if b"# BEGIN AUKORA ENGINE " in before:
        return
    block = ENGINE_BLOCK.format(name=name, engine="engine." + shell_host, upstream=ENGINE_LISTEN)
    core.atomic_write(path, before.rstrip(b"\n") + b"\n\n" + block.encode("utf-8"), 0o644, (0, 0))
    if (run(["caddy", "validate", "--config", path, "--adapter", "caddyfile"], check=False).returncode != 0
            or run(["systemctl", "reload", "caddy"], check=False).returncode != 0):
        core.atomic_write(path, before, 0o644, (0, 0))
        run(["systemctl", "reload", "caddy"], check=False)
        core.refuse("engine-install", "caddy")


def main(argv):
    if len(argv) != 2 or argv[0] != "--stage" or not os.path.isabs(argv[1]) or not os.path.isdir(argv[1]):
        core.refuse("engine-install", "usage")
    stage = argv[1]
    os.umask(0o022)
    node, shell_host = preconditions()
    artifacts = load_pins()
    environment = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    run(["apt-get", "update", "-o", "DPkg::Lock::Timeout=600"], env=environment)
    run(["apt-get", "install", "-y", "--no-install-recommends", "-o", "DPkg::Lock::Timeout=600"] + list(PACKAGES),
        env=environment)
    uid, gid = ensure_users()
    # The fences go up before docker takes its new settings, so no sandbox ever has a resolver.
    run(["systemctl", "enable", "--now", "aukora-engine-fence.service"])
    # Docker's own resolver forwards only into 192.0.2.53, which the fence drops (the DNS posture). Nothing else in
    # Docker's defaults changes: the wall test held on them.
    os.makedirs("/etc/docker", mode=0o755, exist_ok=True)
    core.atomic_write("/etc/docker/daemon.json",
                      core.read_regular(release_file("engine/docker-daemon.json"), 4096, "engine-install"), 0o644)
    run(["systemctl", "restart", "docker.service"])
    image = install_artifacts(artifacts, stage)
    write_config(shell_host, uid, gid, image)
    register_kira()
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", "--now"] + [u for u in ENGINE_UNITS if u != "aukora-engine-fence.service"])
    configure_caddy(node["node"], shell_host)
    # The supervisor reads the door policy and the engine configuration at start; the engine itself waits for it.
    run(["systemctl", "restart", "aukora-sovereign.service"])
    print(json.dumps({"engine_host": "engine." + shell_host, "engine_uid": uid, "sandbox_image": image,
                      "open": "https://" + shell_host + "/engine/open (after the owner approves the release and the "
                              "plugin set)"}, indent=2))
    return 0


if __name__ == "__main__":
    core.run_main("engine-install", main)
