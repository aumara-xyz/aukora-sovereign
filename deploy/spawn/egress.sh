#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later

egress_prepare() {
    local settings
    settings=$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1:],separators=(",",":")))' "$boot_probe" "$release_floor" "$relays_json")
    if [[ -f $state_dir/settings ]]; then
        [[ $(cat -- "$state_dir/settings") == "$settings" ]] || refuse spawn:configuration-mismatch
    else
        printf '%s\n' "$settings" > "$state_dir/settings"
    fi
    local planned
    planned=$(python3 "$here/egress.py" plan "$template" "$relays_json")
    if [[ -f $state_dir/egress.json ]]; then
        [[ $(cat -- "$state_dir/egress.json") == "$planned" ]] || refuse spawn:configuration-mismatch
    else
        printf '%s\n' "$planned" > "$state_dir/egress.json"
    fi
    python3 "$here/egress.py" units "$planned" "${AUKORA_SYSTEMD_DIR:-/etc/systemd/system}"
}

egress_rows() {
    python3 -c 'import json,sys; [print(row["unit"],row["address"],row["port"],sep="\t") for row in json.load(open(sys.argv[1]))]' "$state_dir/egress.json"
}

egress_attach() {
    local unit address outbound_port
    while IFS=$'\t' read -r unit address outbound_port; do
        ensure_device "$unit" proxy bind=instance "listen=tcp:$address:443" "connect=tcp:127.0.0.1:$outbound_port"
    done < <(egress_rows)
    if [[ ! -f $state_dir/egress-helper ]]; then
        quiet lxc exec "$node" -- install -d -m 0755 /opt/aukora/deploy/spawn
        quiet lxc file push "$here/egress.py" "$node/opt/aukora/deploy/spawn/egress.py" --mode 0644
        mark egress-helper
    fi
    if [[ ! -f $state_dir/egress-hosts ]]; then
        quiet lxc exec "$node" -- python3 /opt/aukora/deploy/spawn/egress.py hosts add "$node_id" "$(cat -- "$state_dir/egress.json")"
        mark egress-hosts
    fi
}

egress_remove() {
    [[ -f $state_dir/egress.json ]] || return 0
    local unit address outbound_port
    if [[ -f $state_dir/egress-hosts ]] && python3 -c 'import json,sys; sys.exit(0 if any(v["name"]==sys.argv[1] and v.get("status")=="Running" for v in json.loads(sys.argv[2])) else 1)' "$node" "$1"; then
        quiet lxc exec "$node" -- python3 /opt/aukora/deploy/spawn/egress.py hosts remove "$node_id" "$(cat -- "$state_dir/egress.json")"
    fi
    while IFS=$'\t' read -r unit address outbound_port; do
        local device_state=0
        python3 -c 'import json,sys; sys.exit(0 if sys.argv[1] in json.loads(sys.argv[2]).get("devices",{}) else 1)' "$unit" "$2" || device_state=$?
        if [[ $device_state == 0 ]]; then
            quiet lxc config device remove "$node" "$unit"
        elif [[ $device_state != 1 ]]; then
            refuse spawn:device-conflict
        fi
    done < <(egress_rows)
    # Host forwarders are shared across nodes and retained after removal.
}
