#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Installs local, already built bytes, or uses pre-mounted runtime directories.
# It makes no network requests.
set -eu
umask 077

if [ "$(id -u)" -ne 0 ]; then
    echo 'install: run as root' >&2
    exit 1
fi
task_runtime_in_place=false
if [ "${1:-}" = --runtime-in-place ]; then
    task_runtime_in_place=true
    shift
fi
if [ "$#" -lt 6 ] || [ "$#" -gt 7 ]; then
    echo 'usage: install.sh [--runtime-in-place] BINARY NODE_DIR HARNESS_DIR BUNDLE_DIR OWNER_HOST CHAT_HOST [CONFIG_TEMPLATE]' >&2
    exit 2
fi
if "$task_runtime_in_place" && { [ "$2" != /opt/aukora/node ] || [ "$3" != /opt/aukora/harness ] || [ "$4" != /opt/aukora/sovereign ]; }; then
    echo 'install: runtime in place requires /opt/aukora/node, /opt/aukora/harness, and /opt/aukora/sovereign' >&2
    exit 1
fi
for command in python3 systemctl runuser newuidmap newgidmap; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "install: required command unavailable: $command" >&2
        exit 1
    fi
done
if [ ! -f /sys/fs/cgroup/cgroup.controllers ]; then
    echo 'install: cgroup v2 required' >&2
    exit 1
fi
if [ ! -f "$1" ] || { ! "$task_runtime_in_place" && { [ ! -d "$2" ] || [ ! -d "$3" ] || [ ! -d "$4/guest" ]; }; }; then
    echo 'install: binary, Node directory, built harness directory, and bundle/guest required' >&2
    exit 1
fi
task_deploy_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
task_template=${7:-$task_deploy_dir/node.example.json}
if [ -e /etc/aukora/node.json ] || [ -e /var/lib/aukora/node.ed25519 ]; then
    echo 'install: existing node requires an explicit upgrade; refusing to replace its configuration' >&2
    exit 1
fi
if ! id aukora >/dev/null 2>&1; then
    useradd --system --user-group --home-dir /var/lib/aukora --shell /usr/sbin/nologin aukora
fi
if "$task_runtime_in_place"; then
    # Test as the service user: mode bits alone miss ACLs and read-only mounts.
    # Safe contained package symlinks inside the runtime remain supported.
    runuser -u aukora -- python3 - "$2" "$3" "$4" <<'PY'
import os
import stat
import sys

def refuse(reason):
    raise SystemExit("install: runtime in place " + reason)

for root in sys.argv[1:]:
    path = root
    while path != "/":
        try:
            info = os.lstat(path)
        except OSError:
            refuse("path missing or inaccessible")
        if stat.S_ISLNK(info.st_mode):
            refuse("root or ancestor is a symlink")
        if not stat.S_ISDIR(info.st_mode):
            refuse("directory required")
        if os.access(path, os.W_OK):
            refuse("is writable by aukora")
        path = os.path.dirname(path)
    def walk_error(error):
        refuse("tree missing or inaccessible")
    for directory, subdirectories, files in os.walk(root, onerror=walk_error):
        for path in [directory] + [os.path.join(directory, name) for name in subdirectories + files]:
            if os.access(path, os.W_OK):
                refuse("is writable by aukora")
if not os.path.isdir(os.path.join(sys.argv[3], "guest")):
    refuse("bundle/guest required")
PY
fi
install -d -o root -g aukora -m 0750 /etc/aukora
install -d -o aukora -g aukora -m 0700 /var/lib/aukora
# The guest's workspace and sandbox root: traversable by the guest uid, never listable.
install -d -o aukora -g aukora -m 0711 /var/lib/aukora-guest
if ! "$task_runtime_in_place"; then
    install -d -o root -g root -m 0755 /opt/aukora
    for task_destination in node harness sovereign; do
        if [ -e "/opt/aukora/$task_destination" ]; then
            echo 'install: runtime destination exists; refusing an implicit replacement' >&2
            exit 1
        fi
    done
    cp -a -- "$2" /opt/aukora/node
    cp -a -- "$3" /opt/aukora/harness
    cp -a -- "$4" /opt/aukora/sovereign
    chown -R root:root /opt/aukora
    find /opt/aukora -type d -exec chmod 0755 {} +
    find /opt/aukora -type f -exec chmod a+r,go-w {} +
    find /opt/aukora -type f -perm /111 -exec chmod a+x {} +
fi
install -o root -g root -m 0755 "$1" /usr/local/bin/sovereign

# Configuration and subordinate ranges are generated without printing their contents.
python3 - "$task_template" "$5" "$6" <<'PY'
import json
import os
import re
import sys

template, owner, chat = sys.argv[1:]
hostname = re.compile(r"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$")
if not owner.startswith("owner-") or not chat.startswith("chat-") or owner == chat:
    raise SystemExit("install: distinct owner- and chat- hostnames required")
for host in (owner, chat):
    if not hostname.fullmatch(host) or len(host) > 253 or any(
        not label or len(label) > 63 or label[0] == "-" or label[-1] == "-"
        for label in host.split(".")
    ):
        raise SystemExit("install: invalid hostname")

def subordinate(path):
    try:
        with open(path, encoding="ascii") as source:
            lines = source.read().splitlines()
    except FileNotFoundError:
        lines = []
    ranges = [line.split(":") for line in lines if line and not line.startswith("#")]
    for name, start, length in ranges:
        if name == "aukora" and int(start) >= 100000 and int(length) > 0:
            return int(start)
    start = max([100000] + [int(start) + int(length) for _, start, length in ranges])
    with open(path, "a", encoding="ascii") as target:
        target.write(f"aukora:{start}:65536\n")
        target.flush()
        os.fsync(target.fileno())
    return start

with open(template, encoding="utf-8") as source:
    config = json.load(source)
config["node_id"] = os.urandom(16).hex()
config["state_dir"] = "/var/lib/aukora"
config["listen"] = "127.0.0.1:18080"
config["owner_hostname"] = owner
config["chat_hostname"] = chat
config["owner_origin"] = "https://" + owner
config["chat_origin"] = "https://" + chat
config["trusted_proxy"] = {"peers": ["127.0.0.1", "::1"]}
config["webauthn"] = {"rp_id": owner, "origin": "https://" + owner}
config["cgroup_root"] = "/sys/fs/cgroup/system.slice/aukora-sovereign.service"
config["guest"] = {
    "node_dir": "/opt/aukora/node", "harness_dir": "/opt/aukora/harness",
    "bundle_dir": "/opt/aukora/sovereign",
    "work_dir": "/var/lib/aukora-guest",
    "subordinate_uid": subordinate("/etc/subuid"),
    "subordinate_gid": subordinate("/etc/subgid"),
}
descriptor = os.open("/etc/aukora/node.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
with os.fdopen(descriptor, "w", encoding="utf-8") as target:
    json.dump(config, target, sort_keys=True, separators=(",", ":"))
    target.write("\n")
    target.flush()
    os.fsync(target.fileno())
with open("/etc/aukora/Caddyfile.snippet", "x", encoding="ascii") as target:
    target.write(f"{owner}, {chat} {{\n    reverse_proxy 127.0.0.1:18080 {{\n")
    target.write("        header_up Host {host}\n        header_up X-Forwarded-Host {host}\n")
    target.write("        header_up X-Forwarded-Proto https\n        header_up X-Forwarded-For {remote_host}\n")
    target.write("        header_up -Forwarded\n    }\n}\n")
PY
chown root:aukora /etc/aukora/node.json
chmod 0640 /etc/aukora/node.json
chmod 0644 /etc/aukora/Caddyfile.snippet
install -o root -g root -m 0644 "$task_deploy_dir/aukora-sovereign.service" /etc/systemd/system/aukora-sovereign.service
systemctl daemon-reload
systemctl enable --now aukora-sovereign.service >/dev/null
task_wait=0
while [ "$(stat -c %s /var/lib/aukora/node.ed25519 2>/dev/null || true)" != 32 ]; do
    task_wait=$((task_wait + 1))
    if [ "$task_wait" -ge 100 ]; then
        echo 'install: supervisor did not initialize its private node key' >&2
        exit 1
    fi
    sleep 0.1
done
echo 'Installed. Import /etc/aukora/Caddyfile.snippet into the host Caddy configuration.' >&2
echo 'Model calls require defensible prices in broker.prices, then owner approval of a key and grant.' >&2
# The one claim link is the only secret emitted by this installer.
exec runuser -u aukora -- /usr/local/bin/sovereign claim-link --config /etc/aukora/node.json
