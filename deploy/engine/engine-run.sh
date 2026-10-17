#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Root, the engine unit's main process: run the harness INSIDE an OpenShell 0.1.4 sandbox (docker compute driver,
# enforce), with exactly the mounts below, and nothing of the host's keys, state or configuration.
#   engine-run.sh           create the sandbox and stay attached to it (systemd tracks the engine's life)
#   engine-run.sh verify    after start: the effective policy is ours, Status Effective; refuse otherwise
#   engine-run.sh delete    after stop: remove the sandbox
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
{"type":"bind","source":"/etc/aukora/engine/resolv.conf","target":"/etc/resolv.conf","read_only":true}]}}'

create() {
    exec /usr/local/bin/openshell sandbox create --name "$NAME" --from "$SANDBOX_IMAGE" --policy "$POLICY" \
        --driver-config-json "$MOUNTS" --no-auto-providers --no-tty \
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
' "$AUMA_UID" "$AUMA_GID" "$POLICY"
}

# Remove the sandbox and prove it is gone (SCOUT's sweep, M10: a delete whose failure was swallowed could leave the
# old engine up after a "stop"). OpenShell 0.1.4 deletes asynchronously ("deletion accepted; cleanup is pending") and
# names the sandbox's two containers openshell-<workspace>--<name>-<id> and ...-supervisor (docker ps on the node
# rehearsal). Wait for both to go; if they do not, remove them with docker; if even that fails, exit non-zero so the
# unit is failed (the supervisor counts a failed unit as possibly running and the engine origin refuses).
# Fail closed: if docker cannot be asked, the answer is "still there".
containers() { /usr/bin/docker ps -aq --filter "name=^/openshell-default--$NAME-" 2>/dev/null || echo docker-unreachable; }
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
    *) echo "usage: engine-run.sh [create|verify|delete]" >&2; exit 2 ;;
esac
