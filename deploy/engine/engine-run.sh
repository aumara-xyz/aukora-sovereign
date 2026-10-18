#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Root, the engine unit's main process: run the harness INSIDE an OpenShell 0.1.4 sandbox (docker compute driver,
# enforce), with exactly the mounts below, and nothing of the host's keys, state or configuration.
#   engine-run.sh           create the sandbox and stay attached to it (systemd tracks the engine's life)
#   engine-run.sh verify    after start: the effective policy is ours, Status Effective; refuse otherwise
#   engine-run.sh delete    after stop: remove the sandbox
#   engine-run.sh gateway-clean  before gateway start: remove old containers without contacting the gateway
#   engine-run.sh guard     stop the engine when the host disk is below its floor (once; `watch`: every 5 s)
#
# Mounts (host -> sandbox; the policy's read_only/read_write lists must name each):
#   /opt/aukora-engine          -> /engine                 ro  node, pinned harness, in-wall scripts
#   /opt/rust                   -> /opt/rust               ro  pinned toolchain (wall test)
#   /var/lib/aukora-engine/work -> /work                   rw  the workspace (wall test)
#   /var/lib/aukora-engine/home -> /engine-home            rw  harness home: sticky, root-owned skeleton
#   /run/aukora-door            -> /run/aukora-door        rw  the door socket (folder 0711 aukora: not engine-writable)
#   /run/aukora-broker          -> /run/aukora-broker      rw  the model broker's socket (the same shape; NODE.md section 7)
#   /run/aukora-engine/io       -> /run/aukora-engine-io   rw  1 MiB tmpfs: web socket + launch line
#   /etc/aukora/engine/resolv.conf -> /etc/resolv.conf     ro  the DNS posture: no resolver
#   tmpfs                       -> /tmp                    rw  1 GiB, counted in the memory cap (docker: nosuid,nodev; exec, native addons load from it)
# Never mounted: /etc/aukora (except that one file), /var/lib/aukora*, the Kira socket, the docker socket, /root.
#
# The argv is the wall test's (the wall-test VM's run-sandbox.sh, 2026-10-17): `--from IMAGE`, `--policy FILE` and the
# mounts as a docker driver-config JSON (the gateway allows it: allow_driver_config, enable_bind_mounts). The CLI talks
# to the local gateway over mTLS as the registered gateway `aukora` (engine_install.py registers it; NODE.md O2/O3).
# RAN on the node rehearsal of 2026-10-17.
set -eu
. /etc/aukora/engine.env
NAME=auma-engine
POLICY=/etc/aukora/engine/openshell-policy.yaml
export OPENSHELL_TELEMETRY_ENABLED=false HOME=/var/lib/aukora-openshell OPENSHELL_GATEWAY=aukora
MOUNTS='{"docker":{"mounts":[
{"type":"bind","source":"/opt/aukora-engine","target":"/engine","read_only":true},
{"type":"bind","source":"/opt/rust","target":"/opt/rust","read_only":true},
{"type":"bind","source":"/var/lib/aukora-engine/work","target":"/work","read_only":false},
{"type":"bind","source":"/var/lib/aukora-engine/home","target":"/engine-home","read_only":false},
{"type":"bind","source":"/run/aukora-door","target":"/run/aukora-door","read_only":false},
{"type":"bind","source":"/run/aukora-broker","target":"/run/aukora-broker","read_only":false},
{"type":"bind","source":"/run/aukora-engine/io","target":"/run/aukora-engine-io","read_only":false},
{"type":"bind","source":"/etc/aukora/engine/resolv.conf","target":"/etc/resolv.conf","read_only":true},
{"type":"tmpfs","target":"/tmp","size_bytes":1073741824,"mode":1023,"options":["exec"]}]}}'

# Resource caps (Auma's review R3: a cargo build, a fork bomb or a memory hog must not take down the supervisor, Kira
# or the gateway, which share the VM). The sandbox gets three quarters of the CPUs and the memory less 2.5 GiB, so on a
# 2 vCPU / 8 GiB node it has 1.5 CPUs and about 5.2 GiB and the host keeps half a CPU and 2.5 GiB however hard the
# engine works; OpenShell 0.1.4 sets these on the sandbox container (docker NanoCpus, Memory; RAN on the rehearsal
# node) and already caps its pids at 2048. /tmp is a tmpfs inside that memory cap, not the container's layer on the
# host disk (OpenShell refuses a mount on /sandbox, its reserved workspace); /work and /engine-home live on the engine's own fixed-size filesystem
# (/var/lib/aukora-engine, a loop-mounted image: engine-prestart.sh refuses to start without it). verify holds the
# running container to all of it.
limits() {
    cpus=$(nproc) && memory_kib=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo) || return 1
    ENGINE_CPU_MILLI=$((cpus * 750))
    ENGINE_MEMORY_MIB=$((memory_kib / 1024 - 2560))
    [ "$ENGINE_MEMORY_MIB" -ge 1536 ] || { echo "engine-run: too little memory for the engine and its host" >&2; return 1; }
}

# The host's own disk, a second line behind the first. The sandbox's container layer (OpenShell's reserved /sandbox,
# which the engine can write) is on containerd's own fixed-size filesystem, bytes and inodes (engine_install.py), so a
# filler there stops at that filesystem. If anything still reaches the host's root filesystem, below its floor (15%
# of the blocks and at least 8 GiB, 10% of the inodes and at least 100,000) the engine does not start, and the guard
# (aukora-engine-diskguard.service: `engine-run.sh watch`, a check every 5 s) stops a running one. A polling floor
# reserves nothing against a fast writer: the bounded filesystems are the bound, this is the alarm that acts.
host_disk_ok() {
    set -- $(df -Pk / | awk 'NR == 2 {print $2, $4}') $(df -Pi / | awk 'NR == 2 {print $2, $4}')
    [ -n "${4:-}" ] || return 1
    floor=$(($1 * 15 / 100))
    [ "$floor" -ge 8388608 ] || floor=8388608
    inodes=$(($3 / 10))
    [ "$inodes" -ge 100000 ] || inodes=100000
    [ "$2" -ge "$floor" ] && [ "$4" -ge "$inodes" ]
}

guard() {
    host_disk_ok && return 0
    systemctl is-active --quiet aukora-engine.service || return 0
    echo "engine-run: the host disk is below its floor (blocks or inodes); stopping the engine" >&2
    systemctl stop --no-block aukora-engine.service
}

create() {
    limits || exit 1
    host_disk_ok || { echo "engine-run: the host disk is below its floor (blocks or inodes); not starting" >&2; exit 1; }
    exec /usr/local/bin/openshell sandbox create --name "$NAME" --from "$SANDBOX_IMAGE" --policy "$POLICY" \
        --driver-config-json "$MOUNTS" --no-auto-providers --no-tty \
        --cpu "${ENGINE_CPU_MILLI}m" --memory "${ENGINE_MEMORY_MIB}Mi" \
        -- /engine/node/bin/node /engine/aukora/entry.mjs "$ENGINE_HOST"
}

verify() {
    # `openshell policy get NAME --full -o json` (0.1.4, RAN on the node rehearsal): {"status": "effective",
    # "policy_source": "sandbox", "policy": {...}}; an empty network_policies map is left out of the payload. The
    # effective policy must be exactly ours: the same keys, the same path lists, Landlock enforced, the engine's uid,
    # no network policy. Anything else stops the start (Grok review of the node commit, part 5 #2).
    for _ in $(seq 1 60); do
        effective=$(/usr/local/bin/openshell policy get "$NAME" --full -o json 2>/dev/null) || effective=
        printf '%s' "$effective" | python3 -I -c 'import json,sys; sys.exit(json.load(sys.stdin).get("status") != "effective")' \
            2>/dev/null && break
        sleep 1
    done
    printf '%s' "$effective" | python3 -I -c '
import json, sys
uid, gid, policy_file = sys.argv[1], sys.argv[2], sys.argv[3]
got = json.load(sys.stdin)
def fail(why):
    print("engine-run: effective policy: " + why, file=sys.stderr)
    sys.exit(1)
if got.get("status") != "effective" or got.get("policy_source") != "sandbox":
    fail("not effective")
policy = got.get("policy") or {}
if set(policy) - {"version", "filesystem_policy", "landlock", "process", "network_policies"}:
    fail("unexpected keys " + ",".join(sorted(set(policy))))
if policy.get("network_policies") not in (None, {}):
    fail("a network policy")
if policy.get("landlock") != {"compatibility": "hard_requirement"}:
    fail("landlock is not hard_requirement")
if policy.get("process") != {"run_as_user": uid, "run_as_group": gid}:
    fail("not the engine uid and gid")
# The path lists, read from our own policy file (one "- /path" per line under read_only / read_write).
want, section = {"read_only": [], "read_write": []}, None
for line in open(policy_file, encoding="utf-8"):
    stripped = line.split("#", 1)[0].rstrip()
    if stripped.strip() in ("read_only:", "read_write:"):
        section = stripped.strip()[:-1]
    elif section and stripped.strip().startswith("- "):
        want[section].append(stripped.strip()[2:].strip())
    elif stripped and not stripped.startswith("    "):
        section = None
fs = policy.get("filesystem_policy") or {}
if fs.get("include_workdir") is not True or fs.get("read_only") != want["read_only"] or fs.get("read_write") != want["read_write"]:
    fail("filesystem lists differ from " + policy_file)
text = json.dumps(policy)
for never in ("docker.sock", "/etc/aukora", "/var/lib/aukora", "/run/aukora-kira", "/root", "best_effort"):
    if never in text:
        fail("names " + never)
' "$AUMA_UID" "$AUMA_GID" "$POLICY" || return 1
    # The caps are on the running container, not only in the argv (fail closed: no container, or no cap, is a refusal).
    # OpenShell 0.1.4 creates both the workload and its companion with Docker's default restart policy (no).
    # Check both, including stopped containers: Docker/containerd must never revive an old sandbox outside the
    # supervisor's admission. A failed check stops the unit and ExecStopPost removes the sandbox.
    limits || return 1
    container_ids=$(/usr/bin/docker ps -aq --filter "name=^/openshell-default--$NAME-") || return 1
    [ -n "$container_ids" ] || { echo "engine-run: no sandbox containers" >&2; return 1; }
    # The ids returned by Docker are intentionally separate arguments.
    /usr/bin/docker inspect $container_ids | python3 -I -c '
import json, sys
memory, nano = int(sys.argv[1]) << 20, int(sys.argv[2]) * 1000000
containers = json.load(sys.stdin)
workloads = [c for c in containers if not c.get("Name", "").endswith("-supervisor")]
if len(containers) != 2 or len(workloads) != 1 or {c.get("Name") for c in containers} != \
        {workloads[0]["Name"], workloads[0]["Name"] + "-supervisor"} or not workloads[0].get("State", {}).get("Running"):
    print("engine-run: not exactly one running sandbox and its companion", file=sys.stderr)
    sys.exit(1)
for container in containers:
    if container.get("HostConfig", {}).get("RestartPolicy", {}).get("Name") != "no":
        print("engine-run: a sandbox container can restart outside the supervisor", file=sys.stderr)
        sys.exit(1)
host = workloads[0]["HostConfig"]
tmpfs = {m.get("Target"): (m.get("TmpfsOptions") or {}).get("SizeBytes") for m in host.get("Mounts") or [] if m.get("Type") == "tmpfs"}
if host.get("Memory") != memory or host.get("NanoCpus") != nano or not 0 < (host.get("PidsLimit") or 0) <= 4096 \
        or tmpfs.get("/tmp") != 1 << 30:
    print("engine-run: the sandbox container is not capped as asked", file=sys.stderr)
    sys.exit(1)
' "$ENGINE_MEMORY_MIB" "$ENGINE_CPU_MILLI" || return 1
    # A live positive assertion, not the absence of a warning. Until it exists the Type=exec unit stays activating
    # and the supervisor serves no engine traffic. The entry watchdog kills on silence and on any disabled row.
    for _ in $(seq 1 30); do
        # >>> authority-ready (tests/deploy/test_engine_authority.py executes this check)
        if python3 -I -c '
import json, os, sys, time
try:
    path = "/run/aukora-engine/io/authority-status"
    with open(path, "rb") as f:
        raw = f.read(16385)
        age = time.time() - os.fstat(f.fileno()).st_mtime
    with open("/var/lib/aukora-engine/home/profiles/aukora/node_modules/.aukora-authority.json", "rb") as f:
        expected = json.load(f)
    value = json.loads(raw)
    assert len(raw) <= 16384 and 0 <= age < 10 and value.pop("state") == "ready" and value == expected
except (OSError, ValueError, AssertionError, KeyError, TypeError, AttributeError):
    sys.exit(1)
'; then return 0; fi
        # <<< authority-ready
        sleep 1
    done
    echo "engine-run: supervisor:authority-plugin-missing; runtime authority check refused the start" >&2
    return 1
}

# Remove the sandbox and prove it is gone (SCOUT's sweep, M10: a delete whose failure was swallowed could leave the
# old engine up after a "stop"). OpenShell 0.1.4 deletes asynchronously ("deletion accepted; cleanup is pending") and
# names the sandbox's two containers openshell-<workspace>--<name>-<id> and ...-supervisor (docker ps on the node
# rehearsal). Wait for both to go; if they do not, remove them with docker; if even that fails, exit non-zero so the
# unit is failed (the supervisor counts a failed unit as possibly running and the engine origin refuses).
# Fail closed: if docker cannot be asked, the answer is "still there".
containers() { /usr/bin/docker ps -aq --filter "name=^/openshell-default--$NAME-" 2>/dev/null || echo docker-unreachable; }
# OpenShell 0.1.4 restores persisted running intent at gateway startup, even when Docker's restart policy is no.
# The gateway uses an in-memory database, and this Docker-only sweep runs before every gateway launch: an old
# workload cannot survive a gateway crash or be rediscovered without the supervisor admitting a fresh engine.
# >>> gateway-clean (tests/deploy/test_day2_gateway.py runs this block with a stub Docker)
gateway_clean() {
    ids=$(/usr/bin/docker ps -aq --filter "name=^/openshell-default--$NAME-") || return 1
    if [ -n "$ids" ]; then
        # Docker's ids are intentionally separate arguments; remove running and stopped containers alike.
        /usr/bin/docker rm -f $ids >/dev/null || return 1
    fi
    ids=$(/usr/bin/docker ps -aq --filter "name=^/openshell-default--$NAME-") || return 1
    [ -z "$ids" ] || { echo "engine-run: the old sandbox is still present before gateway start" >&2; return 1; }
}
# <<< gateway-clean
delete() {
    /usr/local/bin/openshell sandbox delete "$NAME" >/dev/null 2>&1 || true
    # 10 s for OpenShell's own cleanup, then docker; all of it inside the unit's TimeoutStopSec (90 s, Sonnet sweep C3).
    for _ in $(seq 1 10); do
        [ -z "$(containers)" ] && return 0
        sleep 1
    done
    containers | xargs -r /usr/bin/docker rm -f >/dev/null 2>&1 || true
    [ -z "$(containers)" ] && return 0
    echo "engine-run: the sandbox $NAME is still up" >&2
    exit 1
}

case "${1:-create}" in
    create) delete; create ;;
    verify) verify ;;
    delete) delete ;;
    gateway-clean) gateway_clean ;;
    guard) guard ;;
    watch) while :; do guard || true; sleep 5; done ;;
    *) echo "usage: engine-run.sh [create|verify|delete|gateway-clean|guard|watch]" >&2; exit 2 ;;
esac
