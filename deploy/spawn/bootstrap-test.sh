#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
set +x

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
candidate=${AUKORA_BOOTSTRAP_CANDIDATE:-"$here/bootstrap.sh"}
real_python=${REAL_PYTHON:-$(command -v python3)}
temporary=$(mktemp -d "$here/.bootstrap-test.XXXXXX")
trap 'rm -rf -- "$temporary"' EXIT
export REAL_PYTHON="$real_python" TEST_TMP="$temporary" TEST_LOG="$temporary/commands"
mkdir -p "$temporary/bin" "$temporary/root/etc" "$temporary/root/opt/aukora/deploy" "$temporary/root/opt/aukora/debs"
cp "$here/../node.example.json" "$temporary/root/opt/aukora/deploy/node.example.json"

fail() { printf 'FAIL bootstrap: %s\n' "$1" >&2; exit 1; }

cat > "$temporary/bin/mock" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
tool=${0##*/}
if [[ $tool == python3 && $# != 1 ]]; then exec "$REAL_PYTHON" "$@"; fi
if [[ $tool != install || $# == 8 ]]; then
    printf '%s' "$tool" >> "$TEST_LOG"
    printf ' %s' "$@" >> "$TEST_LOG"
    printf '\n' >> "$TEST_LOG"
fi
case "$tool" in
    apt-get)
        [[ ${MOCK_APT_ALLOWED:-0} == 1 ]] || exit 91
        # Bounded: an idle inherited pipe must not hang the suite; real input is already there.
        if IFS= read -r -t 5 input; then exit 92; fi
        [[ ${MOCK_APT_EXIT:-0} == 0 ]] || exit "$MOCK_APT_EXIT"
        [[ $1 != update ]] || exit 0
        [[ $1 == install && $2 == -y && $3 == --no-install-recommends ]] || exit 93
        shift 3
        for package in "$@"; do
            if grep -qx "$package" "$TEST_TMP/packages"; then exit 94; fi
            printf '%s\n' "$package" >> "$TEST_TMP/packages"
        done ;;
    dpkg)
        [[ $1 == -i ]] || exit 95
        # Bounded: an idle inherited pipe must not hang the suite; real input is already there.
        if IFS= read -r -t 5 input; then exit 96; fi
        [[ ${MOCK_DPKG_EXIT:-0} == 0 ]] || exit "$MOCK_DPKG_EXIT"
        shift
        for deb in "$@"; do
            [[ -f $deb && $deb == "$TEST_TMP/root/opt/aukora/debs/"*.deb ]] || exit 97
            package=${deb##*/}
            package=${package%%_*}
            if grep -qx "$package" "$TEST_TMP/packages"; then exit 98; fi
            [[ ${MOCK_DPKG_NO_INSTALL:-0} == 1 ]] || printf '%s\n' "$package" >> "$TEST_TMP/packages"
        done
        if grep -qx uidmap "$TEST_TMP/packages" && ! grep -qx libsubid4 "$TEST_TMP/packages"; then exit 99; fi
        exit "${MOCK_DPKG_AFTER_EXIT:-0}" ;;
    dpkg-query)
        if grep -qx "${!#}" "$TEST_TMP/packages"; then printf 'install ok installed'; exit 0; fi
        exit 1 ;;
    getent) [[ -f "$TEST_TMP/user" ]] ;;
    useradd) [[ "${MOCK_USERADD_EXIT:-0}" == 0 ]] && touch "$TEST_TMP/user" ;;
    id) printf '%s\n' "${MOCK_UID:-997}" ;;
    install)
        if [[ $# == 8 ]]; then
            [[ $1 == -d && $2 == -o && $3 == root && $4 == -g && $5 == root && $6 == -m && $7 == 0755 && $8 == "$TEST_TMP/root/etc/aukora-approvals" ]] || exit 90
            mkdir -p "$8"
            chmod 0755 "$8"
        else
            exec /usr/bin/install "$@"
        fi ;;
    sysctl) printf '%s\n' "${MOCK_USERNS_RESTRICTION:-1}" ;;
    apparmor_parser) exit "${MOCK_APPARMOR_EXIT:-0}" ;;
    python3)
        if [[ $# != 1 || $1 != - ]]; then exec "$REAL_PYTHON" "$@"; fi
        exec "$REAL_PYTHON" -c '
import os, sys, types
script = sys.stdin.read()
class Call:
    def __call__(self, *args):
        assert args[0] == 444 and args[1:] == (0, 0, 1)
        return int(os.environ.get("MOCK_ABI", "5"))
sys.modules["ctypes"] = types.SimpleNamespace(
    CDLL=lambda *a, **kw: types.SimpleNamespace(syscall=Call()),
    c_long=int, c_void_p=lambda value: value, c_size_t=int, c_uint=int)
sys.modules["platform"] = types.SimpleNamespace(
    machine=lambda: os.environ.get("MOCK_ARCH", "x86_64"))
exec(compile(script, "landlock-bootstrap", "exec"))
' ;;
esac
MOCK
chmod +x "$temporary/bin/mock"
for tool in apt-get dpkg dpkg-query getent useradd id sysctl apparmor_parser python3 install; do
    ln -s mock "$temporary/bin/$tool"
done
export PATH="$temporary/bin:$PATH"

cat > "$temporary/root/opt/aukora/deploy/install.sh" <<'INSTALL'
#!/usr/bin/env bash
set -euo pipefail
template=${!#}
[[ -f $template ]] || exit 98
cp "$template" "$TEST_TMP/node.json"
set -- "${@:1:$#-1}"
printf 'install' >> "$TEST_LOG"
printf ' %s' "$@" >> "$TEST_LOG"
printf '\n' >> "$TEST_LOG"
# Bootstrap must leave subordinate allocation to the real installer.
cmp "$TEST_TMP/subuid.before" "$TEST_TMP/root/etc/subuid" || exit 99
cmp "$TEST_TMP/subgid.before" "$TEST_TMP/root/etc/subgid" || exit 99
"$REAL_PYTHON" - "$template" "$TEST_TMP/root/opt/aukora/deploy/spawn/invite.json" <<'PYINSTALL'
import json, pathlib, sys
config, invite = map(pathlib.Path, sys.argv[1:])
assert json.loads(config.read_text())['invite'] == json.loads(invite.read_text()), 'installer lost invite'
PYINSTALL
printf '%s\n' "${MOCK_CLAIM_LINK:-https://owner-s1-203-0-113-7.sslip.io/#claim=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA}"
printf 'synthetic-installer-secret\n' >&2
exit "${MOCK_INSTALL_EXIT:-0}"
INSTALL

# shellcheck source=bootstrap.sh
source "$candidate"
bootstrap_root="$temporary/root"

root_function=$(declare -f require_root)
root_function=${root_function//\$EUID/\$TEST_EUID}
eval "$root_function"
TEST_EUID=1
if require_root > "$temporary/out" 2> "$temporary/err"; then fail 'non-root accepted'; fi
[[ $(cat "$temporary/err") == spawn:root-required ]] || fail 'root refusal code'
TEST_EUID=0
require_root || fail 'root refused'
require_root() { :; }

reset_fixture() {
    : > "$TEST_LOG"
    rm -f -- "$temporary/user" "$temporary/node.json" "$bootstrap_root/etc/apparmor.d/aukora-sovereign" "$bootstrap_root/opt/aukora/debs/"*.deb
    rm -rf -- "$bootstrap_root/etc/aukora-approvals"
    printf 'ubuntu:100000:65536\n' > "$bootstrap_root/etc/subuid"
    printf 'ubuntu:100000:65536\n' > "$bootstrap_root/etc/subgid"
    cp "$bootstrap_root/etc/subuid" "$temporary/subuid.before"
    cp "$bootstrap_root/etc/subgid" "$temporary/subgid.before"
    printf 'python3\napparmor\n' > "$temporary/packages"
    mkdir -p "$bootstrap_root/opt/aukora/deploy/spawn"
    printf '{"schema":"aukora-spawn-invite-v1","event":{"id":"fixture"},"invite_event_id":"fixture","inviter_npub":"npub-fixture","claim_sha256":"fixture"}\n' > "$bootstrap_root/opt/aukora/deploy/spawn/invite.json"
    cp "$here/../node.example.json" "$bootstrap_root/opt/aukora/deploy/node.example.json"
    touch "$bootstrap_root/opt/aukora/debs/libsubid4_1_amd64.deb" "$bootstrap_root/opt/aukora/debs/uidmap_1_amd64.deb"
    unset MOCK_ABI MOCK_ARCH MOCK_APT_EXIT MOCK_APT_ALLOWED MOCK_DPKG_EXIT MOCK_DPKG_AFTER_EXIT MOCK_DPKG_NO_INSTALL MOCK_UID MOCK_USERADD_EXIT MOCK_USERNS_RESTRICTION MOCK_APPARMOR_EXIT MOCK_INSTALL_EXIT MOCK_CLAIM_LINK
}

expect_refusal() {
    local code=$1
    shift
    if bootstrap_main "$@" > "$temporary/out" 2> "$temporary/err"; then fail "$code accepted"; fi
    [[ $(cat "$temporary/err") == "$code" ]] || fail "$code output"
    [[ ! -s "$temporary/out" ]] || fail "$code public output"
    [[ ! -f $temporary/node.json ]] || fail "$code installer reached"
}

reset_fixture
bootstrap_main host s1 0123456789abcdef0123456789abcdef 203.0.113.7 > "$temporary/out" 2> "$temporary/err"
cat > "$temporary/expected" <<EXPECTED
python3 -
dpkg-query -W -f=\${Status} libsubid4
dpkg-query -W -f=\${Status} uidmap
dpkg-query -W -f=\${Status} python3
dpkg-query -W -f=\${Status} apparmor
dpkg -i $bootstrap_root/opt/aukora/debs/libsubid4_1_amd64.deb $bootstrap_root/opt/aukora/debs/uidmap_1_amd64.deb
dpkg-query -W -f=\${Status} libsubid4
dpkg-query -W -f=\${Status} uidmap
dpkg-query -W -f=\${Status} python3
dpkg-query -W -f=\${Status} apparmor
getent passwd aukora
useradd --system --create-home --home-dir /var/lib/aukora --shell /usr/sbin/nologin aukora
id -u aukora
install -d -o root -g root -m 0755 $bootstrap_root/etc/aukora-approvals
install --runtime-in-place $bootstrap_root/opt/aukora/bin/sovereign $bootstrap_root/opt/aukora/node $bootstrap_root/opt/aukora/harness $bootstrap_root/opt/aukora/sovereign owner-s1-203-0-113-7.sslip.io chat-s1-203-0-113-7.sslip.io
EXPECTED
cmp "$temporary/expected" "$TEST_LOG" || fail 'host command sequence'
[[ ! -s "$temporary/out" && ! -s "$temporary/err" ]] || fail 'installer secret leaked'
cmp "$temporary/subuid.before" "$bootstrap_root/etc/subuid" || fail 'host subordinate allocation not left to installer'
cmp "$temporary/subgid.before" "$bootstrap_root/etc/subgid" || fail 'host default user range changed'
: > "$TEST_LOG"
bootstrap_main host s1 0123456789abcdef0123456789abcdef 203.0.113.7 > "$temporary/out" 2> "$temporary/err"
cmp "$temporary/subuid.before" "$bootstrap_root/etc/subuid" || fail 'subuid rerun'
cmp "$temporary/subgid.before" "$bootstrap_root/etc/subgid" || fail 'subgid rerun'
if grep -q '^useradd ' "$TEST_LOG"; then fail 'user recreated'; fi

reset_fixture
export MOCK_APT_ALLOWED=1
bootstrap_main vm s1 0123456789abcdef0123456789abcdef 203.0.113.7 > "$temporary/out" 2> "$temporary/err"
cmp "$temporary/subuid.before" "$bootstrap_root/etc/subuid" || fail 'VM subordinate allocation not left to installer'
cmp "$temporary/subgid.before" "$bootstrap_root/etc/subgid" || fail 'VM default user range changed'
cp "$temporary/expected" "$temporary/vm.expected"
"$REAL_PYTHON" - "$temporary/vm.expected" "$bootstrap_root" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
text = path.read_text()
text = text.replace("dpkg-query -W -f=${Status} apparmor\n", "dpkg-query -W -f=${Status} apparmor\ndpkg-query -W -f=${Status} caddy\n")
text = text.replace("getent passwd aukora\n", "apt-get update\napt-get install -y --no-install-recommends caddy\ngetent passwd aukora\n")
text = text.replace("install -d -o root", "sysctl -n kernel.apparmor_restrict_unprivileged_userns\napparmor_parser -r " + sys.argv[2] + "/etc/apparmor.d/aukora-sovereign\ninstall -d -o root")
text = text.replace("install --runtime-in-place ", "install ")
for directory in ("node", "harness", "sovereign"):
    text = text.replace(sys.argv[2] + "/opt/aukora/" + directory, sys.argv[2] + "/opt/aukora/runtime/" + directory)
path.write_text(text)
PY
cmp "$temporary/vm.expected" "$TEST_LOG" || fail 'vm command sequence'
cat > "$temporary/profile.expected" <<'PROFILE'
include <tunables/global>
profile aukora-sovereign /usr/local/bin/sovereign flags=(unconfined) {
    userns,
}
PROFILE
cmp "$temporary/profile.expected" "$bootstrap_root/etc/apparmor.d/aukora-sovereign" || fail 'supervisor AppArmor profile'
[[ ! -s "$temporary/out" && ! -s "$temporary/err" ]] || fail 'vm logs leaked'
[[ ! -e "$bootstrap_root/etc/sysctl.d" ]] || fail 'global sysctl changed'

for abi in -1 0 3; do
    reset_fixture
    export MOCK_ABI=$abi
    expect_refusal spawn:landlock-abi host s1 0123456789abcdef0123456789abcdef 203.0.113.7
    [[ $(cat "$TEST_LOG") == 'python3 -' ]] || fail 'Landlock refusal was not first'
done
reset_fixture
export MOCK_ARCH=riscv64
expect_refusal spawn:landlock-abi host s1 0123456789abcdef0123456789abcdef 203.0.113.7
reset_fixture
export MOCK_ABI=4 MOCK_ARCH=aarch64
bootstrap_main host s1 0123456789abcdef0123456789abcdef 203.0.113.7 > "$temporary/out" 2> "$temporary/err"

for bad_name in a S1 -s1 'a;id' 'a/b' 'aaaaaaaaaaaaaaaaaaaaaa'; do
    reset_fixture
    expect_refusal spawn:name host "$bad_name" 0123456789abcdef0123456789abcdef 203.0.113.7
    [[ ! -s "$TEST_LOG" ]] || fail 'name refused after mutation'
done
reset_fixture
expect_refusal spawn:backend bad s1 0123456789abcdef0123456789abcdef 203.0.113.7
reset_fixture
expect_refusal spawn:node-id host s1 'BAD' 203.0.113.7
for bad_ip in '203.0.113.7;id' 203.0.113.256 203.0.113.007; do
    reset_fixture
    expect_refusal spawn:public-ip host s1 0123456789abcdef0123456789abcdef "$bad_ip"
done
reset_fixture
export MOCK_UID=0
expect_refusal spawn:user host s1 0123456789abcdef0123456789abcdef 203.0.113.7
reset_fixture
export MOCK_USERADD_EXIT=1
expect_refusal spawn:user host s1 0123456789abcdef0123456789abcdef 203.0.113.7
reset_fixture
printf 'other:100999:2\naukora:300000:65536\n' >> "$bootstrap_root/etc/subuid"
printf 'other:100999:2\naukora:300000:65536\n' >> "$bootstrap_root/etc/subgid"
cp "$bootstrap_root/etc/subuid" "$temporary/subuid.before"
cp "$bootstrap_root/etc/subgid" "$temporary/subgid.before"
bootstrap_main host s1 0123456789abcdef0123456789abcdef 203.0.113.7 > "$temporary/out" 2> "$temporary/err" || fail 'host existing subordinate ranges refused'
cmp "$temporary/subuid.before" "$bootstrap_root/etc/subuid" || fail 'host existing subuid ranges changed'
cmp "$temporary/subgid.before" "$bootstrap_root/etc/subgid" || fail 'host existing subgid ranges changed'
reset_fixture
# An image that already has every package needs no network: apt never runs.
printf 'libsubid4\nuidmap\n' >> "$temporary/packages"
bootstrap_main host s1 0123456789abcdef0123456789abcdef 203.0.113.7 > "$temporary/out" 2> "$temporary/err" || fail 'preinstalled packages refused'
if grep -Eq '^(apt-get|dpkg) ' "$TEST_LOG"; then fail 'present packages reinstalled'; fi
grep -q '^install ' "$TEST_LOG" || fail 'preinstalled packages did not reach the installer'
reset_fixture
printf 'uidmap\n' >> "$temporary/packages"
bootstrap_main host s1 0123456789abcdef0123456789abcdef 203.0.113.7 > "$temporary/out" 2> "$temporary/err" || fail 'missing libsubid4 refused'
grep -qx "dpkg -i $bootstrap_root/opt/aukora/debs/libsubid4_1_amd64.deb" "$TEST_LOG" || fail 'present uidmap reinstalled with missing libsubid4'
reset_fixture
rm -f -- "$bootstrap_root/opt/aukora/debs/"*.deb
expect_refusal spawn:packages host s1 0123456789abcdef0123456789abcdef 203.0.113.7
if grep -q '^apt-get ' "$TEST_LOG"; then fail 'host attempted apt without local debs'; fi
reset_fixture
export MOCK_DPKG_EXIT=1
expect_refusal spawn:packages host s1 0123456789abcdef0123456789abcdef 203.0.113.7
reset_fixture
export MOCK_DPKG_AFTER_EXIT=1
expect_refusal spawn:packages host s1 0123456789abcdef0123456789abcdef 203.0.113.7
reset_fixture
export MOCK_DPKG_NO_INSTALL=1
expect_refusal spawn:packages host s1 0123456789abcdef0123456789abcdef 203.0.113.7
reset_fixture
export MOCK_APT_ALLOWED=1 MOCK_APT_EXIT=1
expect_refusal spawn:packages vm s1 0123456789abcdef0123456789abcdef 203.0.113.7
reset_fixture
export MOCK_APT_ALLOWED=1
rm -f -- "$bootstrap_root/opt/aukora/debs/"*.deb
bootstrap_main vm s1 0123456789abcdef0123456789abcdef 203.0.113.7 > "$temporary/out" 2> "$temporary/err" || fail 'VM apt fallback refused'
grep -qx 'apt-get install -y --no-install-recommends libsubid4 uidmap caddy' "$TEST_LOG" || fail 'VM apt did not install only missing packages'
reset_fixture
printf 'stdin-must-not-be-consumed\n' | bootstrap_main host s1 0123456789abcdef0123456789abcdef 203.0.113.7 > "$temporary/out" 2> "$temporary/err" || fail 'local package install consumed stdin'
reset_fixture
export MOCK_APT_ALLOWED=1
printf 'stdin-must-not-be-consumed\n' | bootstrap_main vm s1 0123456789abcdef0123456789abcdef 203.0.113.7 > "$temporary/out" 2> "$temporary/err" || fail 'apt fallback consumed stdin'
reset_fixture
export MOCK_APT_ALLOWED=1 MOCK_USERNS_RESTRICTION=0
expect_refusal spawn:userns-policy vm s1 0123456789abcdef0123456789abcdef 203.0.113.7
reset_fixture
export MOCK_APT_ALLOWED=1 MOCK_APPARMOR_EXIT=1
expect_refusal spawn:apparmor-profile vm s1 0123456789abcdef0123456789abcdef 203.0.113.7
reset_fixture
export MOCK_INSTALL_EXIT=1
if bootstrap_main host s1 0123456789abcdef0123456789abcdef 203.0.113.7 > "$temporary/out" 2> "$temporary/err"; then fail 'installer failure accepted'; fi
[[ $(cat "$temporary/err") == spawn:install && ! -s "$temporary/out" ]] || fail 'installer failure leaked logs'

# The only installer stdout stays in memory until the private handoff.
reset_fixture
bootstrap_main host s1 0123456789abcdef0123456789abcdef 203.0.113.7 > "$temporary/out" 2> "$temporary/err"
[[ $claim_link == 'https://owner-s1-203-0-113-7.sslip.io/#claim=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' ]] || fail 'installer claim not captured'
for bad in 'https://attacker.invalid/#claim=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' 'https://owner-s1-203x0x113x7.sslip.io/#claim=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' 'https://owner-s1-203-0-113-7.sslip.io/#claim=short' $'https://owner-s1-203-0-113-7.sslip.io/#claim=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nextra'; do
    reset_fixture
    export MOCK_CLAIM_LINK="$bad"
    if bootstrap_main host s1 0123456789abcdef0123456789abcdef 203.0.113.7 > "$temporary/out" 2> "$temporary/err"; then fail 'invalid installer claim accepted'; fi
    [[ ! -s $temporary/out && $(cat "$temporary/err") == spawn:claim-output && -z $claim_link ]] || fail 'invalid installer claim leaked'
done

for invalid_invite in missing malformed schema; do
    reset_fixture
    case $invalid_invite in
        missing) rm "$bootstrap_root/opt/aukora/deploy/spawn/invite.json" ;;
        malformed) printf '{' > "$bootstrap_root/opt/aukora/deploy/spawn/invite.json" ;;
        schema) printf '{"schema":"old"}' > "$bootstrap_root/opt/aukora/deploy/spawn/invite.json" ;;
    esac
    expect_refusal spawn:invite-provenance host s1 0123456789abcdef0123456789abcdef 203.0.113.7
done

if [[ "${1:-}" != --check-only ]]; then
    "$REAL_PYTHON" - "$candidate" "$temporary" <<'PY'
from pathlib import Path
import sys

text = Path(sys.argv[1]).read_text()
folder = Path(sys.argv[2])
package_start = text.index('    local -a packages=')
package_end = text.index('    if ! getent passwd aukora', package_start)
legacy_packages = '''    local -a packages=(uidmap python3 apparmor) missing=()
    [[ "$mode" != vm ]] || packages+=(caddy)
    local package
    for package in "${packages[@]}"; do
        [[ $(dpkg-query -W -f='${Status}' "$package" 2>/dev/null) == 'install ok installed' ]] || missing+=("$package")
    done
    if (( ${#missing[@]} )) && {
        ! DEBIAN_FRONTEND=noninteractive apt-get update >/dev/null 2>&1 ||
        ! DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}" >/dev/null 2>&1
    }; then
        bootstrap_refuse 'spawn:packages'
        return 1
    fi
'''
legacy_subids = '''set_subids() {
    local path=$1 temporary
    [[ -e "$path" ]] || install -m 0644 /dev/null "$path"
    if ! awk -F: '
        $1 != "aukora" && NF == 3 && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ {
            if ($2 < 101000 && $2 + $3 > 100000) exit 1
        }
    ' "$path"; then
        bootstrap_refuse 'spawn:subid-conflict'
        return 1
    fi
    temporary=$(mktemp "${path}.XXXXXX")
    if ! awk -F: '$1 != "aukora" {print}' "$path" > "$temporary"; then
        rm -f -- "$temporary"
        bootstrap_refuse 'spawn:subid-write'
        return 1
    fi
    printf '%s\\n' 'aukora:100000:1000' >> "$temporary"
    chmod 0644 "$temporary"
    mv -f -- "$temporary" "$path"
}

'''
subid_call = '''    if [[ "$mode" == host ]]; then
        set_subids "${bootstrap_root}/etc/subuid" || return 1
        set_subids "${bootstrap_root}/etc/subgid" || return 1
    fi
'''
mutations = [
    ("invite-required", '    if ! invite_template "$template"; then', '    if false; then'),
    ("invite-record", "    config['invite'] = provenance", '    pass'),
    ("invite-schema", "    if provenance.get('schema') != 'aukora-spawn-invite-v1': raise ValueError()", '    pass'),
    ("root", '[[ "$EUID" -eq 0 ]]', 'true'),
    ("approvals-directory", '    install -d -o root -g root -m 0755 "${bootstrap_root}/etc/aukora-approvals"\n', ''),
    ("name", '[[ "$name" =~ ^[a-z][a-z0-9-]{1,20}$ ]]', 'true'),
    ("node-id", '[[ "$node_id" =~ ^[0-9a-f]{32}$ ]]', 'true'),
    ("backend", '[[ "$mode" == host || "$mode" == vm ]]', 'true'),
    ("ip-shape", '[[ "$public_ip" =~ ^([0-9]{1,3}\\.){3}[0-9]{1,3}$ ]]', 'true'),
    ("ip-range", '(( 10#$octet <= 255 ))', 'true'),
    ("ip-leading-zero", '[[ "$octet" == 0 || "$octet" != 0* ]]', 'true'),
    ("landlock-abi", 'if abi < 4:', 'if False:'),
    ("landlock-arch", 'if platform.machine() not in ("x86_64", "aarch64"):', 'if False:'),
    ("legacy-packages", text[package_start:package_end], legacy_packages),
    ("legacy-host-subids", '    # The installer allocates free subordinate ranges in both modes.\n', subid_call),
    ("host-subid-write", '    # The installer allocates free subordinate ranges in both modes.\n', '    printf "aukora:100000:1000\\n" >> "${bootstrap_root}/etc/subuid"\n'),
    ("local-debs", 'DEBIAN_FRONTEND=noninteractive dpkg -i "${debs[@]}" </dev/null >/dev/null 2>&1', 'true'),
    ("libsubid4-required", 'packages=(libsubid4 uidmap python3 apparmor)', 'packages=(uidmap python3 apparmor)'),
    ("missing-only", 'for package in "${missing[@]}"; do', 'for package in "${packages[@]}"; do'),
    ("installed-state", '''        missing=()
        for package in "${packages[@]}"; do
            [[ $(dpkg-query -W -f='${Status}' "$package" 2>/dev/null) == 'install ok installed' ]] || missing+=("$package")
        done
''', '        missing=()\n'),
    ("host-no-apt", '[[ "$mode" != vm ]] ||\n', 'false ||\n'),
    ("dpkg-fail", '''[[ "$mode" == vm ]] || { bootstrap_refuse 'spawn:packages'; return 1; }''', ':'),
    ("dpkg-stdin", 'dpkg -i "${debs[@]}" </dev/null', 'dpkg -i "${debs[@]}"'),
    ("apt-update-stdin", 'apt-get update </dev/null', 'apt-get update'),
    ("apt-install-stdin", 'apt-get install -y --no-install-recommends "${missing[@]}" </dev/null', 'apt-get install -y --no-install-recommends "${missing[@]}"'),
    ("supervisor-nonroot", '[[ "$supervisor_uid" =~ ^[0-9]+$ && "$supervisor_uid" != 0 ]]', 'true'),
    ("user-create", "|| { bootstrap_refuse 'spawn:user'; return 1; }\n    fi", "|| true\n    fi"),
    ("packages-fail", "            bootstrap_refuse 'spawn:packages'\n            return 1", "            :"),
    ("userns-profile", '    userns,', ''),
    ("userns-restriction", '[[ "$userns_restriction" == 1 ]]', 'true'),
    ("profile-load", 'apparmor_parser -r "$profile" >/dev/null 2>&1', 'true'),
    ("install-private", '"$owner_host" "$chat_host" "$template" 2>/dev/null', '"$owner_host" "$chat_host" "$template"'),
    ("install-copy", 'set -- --runtime-in-place', ":"),
    ("install-owner", '"$owner_host" "$chat_host" "$template" 2>/dev/null', '"$chat_host" "$owner_host" "$template" 2>/dev/null'),
    ("claim-origin", '$claim_link == "https://$owner_host/#claim="*', '1 == 1'),
    ("claim-token", '${claim_link#*#claim=} =~ ^[A-Za-z0-9_-]{43}$', '1 == 1'),
    ("install-fail", "        bootstrap_refuse 'spawn:install'", "        :"),
]
for name, before, after in mutations:
    assert text.count(before) == 1, name
    mutated = text.replace(before, after)
    if name == "legacy-host-subids":
        mutated = mutated.replace('install_userns_profile() {', legacy_subids + 'install_userns_profile() {')
    (folder / ("mutation-" + name + ".sh")).write_text(mutated)
PY
    killed=0
    for mutation in "$temporary"/mutation-*.sh; do
        if AUKORA_BOOTSTRAP_CANDIDATE="$mutation" bash "$here/bootstrap-test.sh" --check-only > "$temporary/mutation.out" 2>&1; then
            fail "surviving mutation ${mutation##*/}"
        fi
        killed=$((killed + 1))
    done
    printf 'PASS bootstrap mutation kills: %s/%s\n' "$killed" "$killed"
fi
printf 'PASS bootstrap tests: offline host packages, VM apt fallback, unchanged subordinate IDs, root, arguments, Landlock, AppArmor, private installer output\n'
