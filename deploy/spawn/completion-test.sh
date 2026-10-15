#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
work=$(mktemp -d "$here/.completion-test.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
mkdir "$work/scripts"
cp "$here/"*.sh "$here/"*.py "$work/scripts/"
python3 - "$here" "$work" <<'PY'
from pathlib import Path
import sys
here,work=map(Path,sys.argv[1:])
mutations=[
('spawn.sh','relay-validation','relayurl','relays_json=$(python3 "$here/egress.py" relays "$relays_json")',':'),
('spawn.sh','egress-plan','egress','    egress_prepare',':'),
('spawn.sh','egress-devices','egress','    egress_attach',':'),
('spawn.sh','remove-own-egress','egress','        egress_remove "$inventory" "$config"',':'),
('spawn.sh','static-preparation','egress','sovereign_runtime=$(bash "$here/prepare-runtime.sh" --runtime "$runtime" --output "$sovereign_runtime" </dev/null)','sovereign_runtime="$runtime/sovereign"'),
('spawn.sh','runtime-reuse-check','runtimeinvalid','[[ $(cat -- "$state_dir/runtime-path") == "$sovereign_runtime" && -d $sovereign_runtime && ! -L $sovereign_runtime && -x $sovereign_runtime/guest/probe && ! -L $sovereign_runtime/guest/probe ]] || refuse spawn:runtime-inputs',':'),
('spawn.sh','boot-probe-default','host','boot_probe=true; release_floor=false;','boot_probe=false; release_floor=false;'),
('spawn.sh','vm-flags','vmflags','export AUKORA_SPAWN_BOOT_PROBE=$boot_probe AUKORA_SPAWN_RELEASE_FLOOR=$release_floor AUKORA_SPAWN_RELAYS=$relays_json',':'),
('spawn.sh','ingress-clash','egressport',"if any(row['port'] == int(sys.argv[2]) for row in json.load(open(sys.argv[1]))):",'if False:'),
('egress.sh','settings-match','configmismatch','[[ $(cat -- "$state_dir/settings") == "$settings" ]] || refuse spawn:configuration-mismatch',':'),
('egress.sh','provider-match','configmismatch','[[ $(cat -- "$state_dir/egress.json") == "$planned" ]] || refuse spawn:configuration-mismatch',':'),
('egress.sh','unit-setup','egress','python3 "$here/egress.py" units "$planned" "${AUKORA_SYSTEMD_DIR:-/etc/systemd/system}"',':'),
('egress.sh','helper-push','egress','quiet lxc file push "$here/egress.py" "$node/opt/aukora/deploy/spawn/egress.py" --mode 0644',':'),
('egress.sh','hosts-add','egress','quiet lxc exec "$node" -- python3 /opt/aukora/deploy/spawn/egress.py hosts add "$node_id" "$(cat -- "$state_dir/egress.json")"',':'),
('egress.sh','hosts-once','host','[[ ! -f $state_dir/egress-hosts ]]','true'),
('egress.sh','shared-retention','egress','    # Host forwarders are shared across nodes and retained after removal.','    quiet systemctl disable --now aukora-egress-relay-damus.socket'),
('egress.sh','partial-device','partialdestroy','if [[ $device_state == 0 ]]; then','if true; then'),
]
for filename,name,case,old,new in mutations:
    source=(here/filename).read_text(); assert old in source,name
    (work/(name+'.sh')).write_text(source.replace(old,new,1))
(work/'mutations').write_text(''.join('\t'.join([filename,name,case])+'\n' for filename,name,case,*_ in mutations))
PY
# A copied baseline must pass before mutation failures count.
SPAWN_UNDER_TEST="$work/scripts/spawn.sh" bash "$here/test.sh" --case egress > "$work/result" 2>&1 || { cat "$work/result"; exit 1; }
count=0
while IFS=$'\t' read -r filename mutation scenario; do
    cp "$here/spawn.sh" "$here/egress.sh" "$work/scripts/"
    cp "$work/$mutation.sh" "$work/scripts/$filename"
    if SPAWN_UNDER_TEST="$work/scripts/spawn.sh" bash "$here/test.sh" --case "$scenario" > "$work/result" 2>&1; then
        printf 'FAIL surviving completion mutation: %s\n' "$mutation" >&2; exit 1
    fi
    printf 'KILLED completion: %s\n' "$mutation"
    count=$((count+1))
done < "$work/mutations"
printf 'test result: ok. %s spawn completion mutations killed\n' "$count"
