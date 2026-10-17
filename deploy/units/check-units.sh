#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Row 102, run as root on a node: audit the installed units. For each unit it checks that
#   1. the hardening properties the unit file sets are the properties in effect (a drop-in cannot weaken them quietly),
#   2. systemd-analyze security reports an overall exposure at or below the unit's ceiling, and
#   3. the units that carry an install section are enabled, so they come back after a reboot.
# Prints one line per unit and exits 1 if any check fails. The ceilings are the targets for the first qualification
# on a node; change one only together with the unit file, in the same reviewed commit.
set -eu

failed=0
fail() { printf 'FAIL %s: %s\n' "$1" "$2"; failed=1; }

# check_unit UNIT CEILING PROPERTY=VALUE...
check_unit() {
    unit=$1 ceiling=$2
    shift 2
    for expected in "$@"; do
        property=${expected%%=*}
        actual=$(systemctl show --property="$property" --value "$unit" 2>/dev/null) || actual=
        [ "$actual" = "${expected#*=}" ] || fail "$unit" "$property is '$actual', expected '${expected#*=}'"
    done
    exposure=$(systemd-analyze security --no-pager "$unit" 2>/dev/null |
        sed -n 's/.*Overall exposure level for [^:]*: *\([0-9][0-9.]*\).*/\1/p' | tail -n 1)
    if [ -z "$exposure" ]; then
        fail "$unit" "systemd-analyze security gave no overall exposure level"
    elif awk -v got="$exposure" -v max="$ceiling" 'BEGIN { exit !(got + 0 <= max + 0) }'; then
        printf 'ok   %s exposure %s (ceiling %s)\n' "$unit" "$exposure" "$ceiling"
    else
        fail "$unit" "exposure $exposure is above the ceiling $ceiling"
    fi
}

# The properties both egress units set: root keeps one capability and sees almost nothing of the host.
egress_properties="NoNewPrivileges=yes ProtectSystem=strict ProtectHome=yes PrivateTmp=yes
ProtectKernelTunables=yes ProtectKernelModules=yes ProtectControlGroups=yes ProtectClock=yes RestrictNamespaces=yes
RestrictRealtime=yes RestrictSUIDSGID=yes LockPersonality=yes MemoryDenyWriteExecute=yes"

[ "$(id -u)" = 0 ] || { echo 'check-units: run as root' >&2; exit 2; }
command -v systemd-analyze >/dev/null || { echo 'check-units: systemd-analyze is missing' >&2; exit 2; }

check_unit aukora-sovereign.service 7.5 User=aukora ProtectSystem=strict ProtectHome=yes PrivateTmp=yes \
    ProtectKernelModules=yes ProtectClock=yes LockPersonality=yes RestrictRealtime=yes RestrictSUIDSGID=yes \
    RemoveIPC=yes SystemCallArchitectures=native Delegate=yes UMask=0077
# shellcheck disable=SC2086
check_unit aukora-egress.service 5.0 $egress_properties
# shellcheck disable=SC2086
check_unit aukora-egress-verify.service 5.0 $egress_properties
for unit in aukora-sovereign.service aukora-egress.service aukora-egress-verify.timer; do
    systemctl is-enabled --quiet "$unit" || fail "$unit" "not enabled for the next boot"
done

# An engine node (deploy/engine/NODE.md): Kira and its model servers run as kira with nothing else; the engine unit is
# started only by the supervisor, so it carries no install section and is not checked for enablement.
if [ -f /etc/aukora/engine-v1.json ]; then
    # [GUESS] systemctl show's spelling of an empty bounding set and of the address families (LINUX, not run yet).
    kira_properties="User=kira NoNewPrivileges=yes ProtectSystem=strict ProtectHome=yes PrivateTmp=yes PrivateDevices=yes
RestrictNamespaces=yes MemoryDenyWriteExecute=yes IPAddressDeny=any PrivateNetwork=yes CapabilityBoundingSet="
    for unit in aukora-kira.service aukora-kira-embed.service aukora-kira-rerank.service; do
        # shellcheck disable=SC2086
        check_unit "$unit" 3.0 $kira_properties "RestrictAddressFamilies=AF_UNIX AF_INET"
    done
    check_unit aukora-openshell-gateway.service 6.0 NoNewPrivileges=yes ProtectSystem=strict ProtectHome=yes \
        PrivateTmp=yes PrivateDevices=yes RestrictNamespaces=yes IPAddressDeny=any \
        CapabilityBoundingSet=cap_net_bind_service
    for unit in aukora-kira.service aukora-kira-embed.service aukora-kira-rerank.service aukora-engine-fence.service \
        aukora-openshell-gateway.service; do
        systemctl is-enabled --quiet "$unit" || fail "$unit" "not enabled for the next boot"
    done
    systemctl is-enabled --quiet aukora-engine.service 2>/dev/null && fail aukora-engine.service "enabled: only the supervisor may start it"
fi

[ "$failed" = 0 ] && echo 'units ok'
exit "$failed"
