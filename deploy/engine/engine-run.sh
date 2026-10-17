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
# [GUESS] The CLI spelling of policy, image and mounts below is not from the wall test's argv (the report records the
# policy and the gateway settings, not the command). Before the first node, copy the exact `openshell sandbox create`
# line from the wall-test VM's history into create() and keep these mounts; wall-check.sh proves the result.
set -eu
. /etc/aukora/engine.env
NAME=auma-engine
POLICY=/etc/aukora/engine/openshell-policy.yaml
export OPENSHELL_TELEMETRY_ENABLED=false HOME=/var/lib/aukora-openshell

create() {
    exec /usr/local/bin/openshell sandbox create --name "$NAME" --policy "$POLICY" --image "$SANDBOX_IMAGE" \
        --no-auto-providers --no-tty \
        --mount type=bind,source=/opt/aukora-engine,target=/engine,readonly \
        --mount type=bind,source=/opt/rust,target=/opt/rust,readonly \
        --mount type=bind,source=/var/lib/aukora-engine/work,target=/work \
        --mount type=bind,source=/var/lib/aukora-engine/home,target=/engine-home \
        --mount type=bind,source=/run/aukora-door,target=/run/aukora-door \
        --mount type=bind,source=/run/aukora-broker,target=/run/aukora-broker \
        --mount type=bind,source=/run/aukora-engine/io,target=/run/aukora-engine-io \
        --mount type=bind,source=/etc/aukora/engine/resolv.conf,target=/etc/resolv.conf,readonly \
        -- /engine/node/bin/node /engine/aukora/entry.mjs "$ENGINE_HOST"
}

verify() {
    for _ in $(seq 1 60); do
        effective=$(/usr/local/bin/openshell policy get "$NAME" 2>/dev/null) || effective=
        case "$effective" in *"Status: Effective"*) break ;; esac
        sleep 1
    done
    case "$effective" in *"Status: Effective"*) ;; *) echo "engine-run: policy not effective" >&2; exit 1 ;; esac
    # Whole lines, not substrings (Grok review of the node commit, part 5 #2): `hard_requirement: false` or a network
    # stanza beside an empty one must not pass. [GUESS] the output shape of `openshell policy get` (O2).
    for want in '[[:space:]]*compatibility:[[:space:]]*hard_requirement([[:space:]]+#.*)?' \
                "[[:space:]]*run_as_user:[[:space:]]*\"$AUMA_UID\"([[:space:]]+#.*)?" \
                "[[:space:]]*run_as_group:[[:space:]]*\"$AUMA_UID\"([[:space:]]+#.*)?" \
                '[[:space:]]*network_policies:[[:space:]]*\{\}([[:space:]]+#.*)?' \
                '[[:space:]]*-[[:space:]]*/run/aukora-door([[:space:]]+#.*)?' \
                '[[:space:]]*-[[:space:]]*/run/aukora-broker([[:space:]]+#.*)?' \
                '[[:space:]]*-[[:space:]]*/engine-home([[:space:]]+#.*)?'; do
        printf '%s\n' "$effective" | grep -qxE -- "$want" || { echo "engine-run: effective policy lacks: $want" >&2; exit 1; }
    done
    # Exactly one of each, and nothing the node never mounts or allows.
    for once in 'network_policies:' 'run_as_user:' 'compatibility:'; do
        [ "$(printf '%s\n' "$effective" | grep -cF -- "$once")" = 1 ] || { echo "engine-run: effective policy repeats: $once" >&2; exit 1; }
    done
    for never in docker.sock /etc/aukora /var/lib/aukora /run/aukora-kira /root best_effort; do
        if printf '%s\n' "$effective" | grep -qF -- "$never"; then echo "engine-run: effective policy names: $never" >&2; exit 1; fi
    done
}

case "${1:-create}" in
    create) /usr/local/bin/openshell sandbox delete "$NAME" >/dev/null 2>&1 || true; create ;;
    verify) verify ;;
    delete) /usr/local/bin/openshell sandbox delete "$NAME" >/dev/null 2>&1 || true ;;
    *) echo "usage: engine-run.sh [create|verify|delete]" >&2; exit 2 ;;
esac
