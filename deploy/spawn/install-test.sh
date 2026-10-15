#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
set +x

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
candidate=${AUKORA_INSTALL_CANDIDATE:-$here/../install.sh}
real_python=${INSTALL_TEST_PYTHON:-$(command -v python3)}
real_cp=${INSTALL_TEST_CP:-$(command -v cp)}
real_chmod=${INSTALL_TEST_CHMOD:-$(command -v chmod)}
real_find=${INSTALL_TEST_FIND:-$(command -v find)}
temporary=$(mktemp -d "$here/.install-test.XXXXXX")
trap 'if [[ ${KEEP_INSTALL_TEST:-0} == 1 ]]; then printf "fixture: %s\n" "$temporary" >&2; else rm -rf -- "$temporary"; fi' EXIT
export INSTALL_TEST_ROOT="$temporary/root" INSTALL_TEST_LOG="$temporary/commands"
export INSTALL_TEST_PYTHON="$real_python" INSTALL_TEST_CP="$real_cp"
export INSTALL_TEST_CHMOD="$real_chmod" INSTALL_TEST_FIND="$real_find"
mkdir -p "$temporary/bin"

fail() { printf 'FAIL installer: %s\n' "$1" >&2; exit 1; }
sh -n "$candidate" || fail 'shell syntax'

cat > "$temporary/bin/mock" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
tool=${0##*/}
printf '%s' "$tool" >> "$INSTALL_TEST_LOG"
printf ' <%s>' "$@" >> "$INSTALL_TEST_LOG"
printf '\n' >> "$INSTALL_TEST_LOG"
case "$tool" in
    id)
        if [[ ${1:-} == -u ]]; then printf '%s\n' "${INSTALL_TEST_UID:-0}"; fi ;;
    newuidmap|newgidmap|useradd|chown|sleep) : ;;
    cp) exec "$INSTALL_TEST_CP" "$@" ;;
    chmod) exec "$INSTALL_TEST_CHMOD" "$@" ;;
    find)
        # BSD find spells GNU find's any-executable-bit predicate +111.
        if [[ $(uname -s) == Darwin ]]; then
            adjusted=()
            for argument in "$@"; do
                [[ $argument != /111 ]] || argument=+111
                adjusted+=("$argument")
            done
            exec "$INSTALL_TEST_FIND" "${adjusted[@]}"
        fi
        exec "$INSTALL_TEST_FIND" "$@" ;;
    stat) [[ -f ${!#} ]] && printf '32\n' ;;
    install)
        is_directory=0
        mode=''
        while [[ $# -gt 0 ]]; do
            case $1 in
                -d) is_directory=1; shift ;;
                -o|-g) shift 2 ;;
                -m) mode=$2; shift 2 ;;
                *) break ;;
            esac
        done
        if [[ $is_directory == 1 ]]; then
            mkdir -p -- "$@"
            "$INSTALL_TEST_CHMOD" "$mode" "$@"
        else
            "$INSTALL_TEST_CP" "$1" "$2"
            "$INSTALL_TEST_CHMOD" "$mode" "$2"
        fi ;;
    systemctl)
        if [[ ${1:-} == enable ]]; then
            "$INSTALL_TEST_PYTHON" -c 'import os,pathlib; (pathlib.Path(os.environ["INSTALL_TEST_ROOT"])/"var/lib/aukora/node.ed25519").write_bytes(bytes(32))'
        fi ;;
    runuser)
        [[ $1 == -u && $2 == aukora && $3 == -- ]]
        shift 3
        if [[ $1 == python3 ]]; then
            export INSTALL_TEST_ACTOR=aukora
            exec "$@"
        fi
        [[ $# == 4 && $1 == "$INSTALL_TEST_ROOT/usr/local/bin/sovereign" && $2 == claim-link && $3 == --config && $4 == "$INSTALL_TEST_ROOT/etc/aukora/node.json" ]]
        printf 'https://owner-s1-203-0-113-7.sslip.io/#claim=synthetic-installer-secret\n' ;;
    python3) exec "$INSTALL_TEST_PYTHON" "$INSTALL_TEST_DRIVER" "$@" ;;
    *) exit 90 ;;
esac
MOCK
chmod +x "$temporary/bin/mock"
for tool in id newuidmap newgidmap useradd chown sleep cp chmod find stat install systemctl runuser python3; do
    ln -s mock "$temporary/bin/$tool"
done
export INSTALL_TEST_DRIVER="$temporary/python-driver.py"
cat > "$INSTALL_TEST_DRIVER" <<'PY'
import os
import stat
import sys

source = sys.stdin.read()
sys.argv = sys.argv[1:]
if os.environ.get("INSTALL_TEST_ACTOR") == "aukora":
    # The test host has no aukora account or Linux read-only LXD mounts.
    # Simulate its effective access, including owner/group permissions and ACLs.
    def access(path, mode):
        assert mode == os.W_OK
        if str(path) == os.environ.get("INSTALL_TEST_ACL_WRITE"):
            return True
        try:
            info = os.stat(path)
        except OSError:
            return False
        permission = stat.S_IWOTH
        if str(path) == os.environ.get("INSTALL_TEST_OWNER_WRITE"):
            permission = stat.S_IWUSR
        elif str(path) == os.environ.get("INSTALL_TEST_GROUP_WRITE"):
            permission = stat.S_IWGRP
        return bool(info.st_mode & permission)
    os.access = access
    original_walk = os.walk
    def walk(root, **kwargs):
        if str(root) == os.environ.get("INSTALL_TEST_WALK_ERROR"):
            if "onerror" in kwargs:
                kwargs["onerror"](PermissionError("mock unreadable runtime subtree"))
            return iter(())
        return original_walk(root, **kwargs)
    os.walk = walk
exec(compile(source, "installer-test", "exec"))
PY
export PATH="$temporary/bin:$PATH"

reset_case() {
    rm -rf -- "$INSTALL_TEST_ROOT" "$temporary/source"
    mkdir -p "$INSTALL_TEST_ROOT/opt/aukora/deploy" "$INSTALL_TEST_ROOT/etc" "$INSTALL_TEST_ROOT/var/lib" "$INSTALL_TEST_ROOT/usr/local/bin" "$INSTALL_TEST_ROOT/etc/systemd/system" "$INSTALL_TEST_ROOT/sys/fs/cgroup"
    mkdir -p "$temporary/source/node/bin" "$temporary/source/harness/package" "$temporary/source/sovereign/guest"
    printf '#!/bin/sh\nexit 0\n' > "$temporary/source/node/bin/node"
    printf '#!/bin/sh\nexit 0\n' > "$temporary/source/binary"
    printf 'runtime-fixture\n' > "$temporary/source/harness/package/entry.js"
    printf 'guest-fixture\n' > "$temporary/source/sovereign/guest/preload.mjs"
    "$real_chmod" 0755 "$temporary/source/node/bin/node" "$temporary/source/binary"
    "$real_chmod" 0644 "$temporary/source/harness/package/entry.js" "$temporary/source/sovereign/guest/preload.mjs"
    "$real_find" "$temporary/source" -type d -exec "$real_chmod" 0755 {} +
    ln -s package "$temporary/source/harness/package-link"
    : > "$INSTALL_TEST_ROOT/sys/fs/cgroup/cgroup.controllers"
    printf 'other:200000:65536\naukora:100000:1000\n' > "$INSTALL_TEST_ROOT/etc/subuid"
    printf 'other:200000:65536\naukora:100000:1000\n' > "$INSTALL_TEST_ROOT/etc/subgid"
    "$real_cp" "$here/../node.example.json" "$INSTALL_TEST_ROOT/opt/aukora/deploy/node.example.json"
    "$real_cp" "$here/../aukora-sovereign.service" "$INSTALL_TEST_ROOT/opt/aukora/deploy/aukora-sovereign.service"
    "$real_python" - "$candidate" "$INSTALL_TEST_ROOT" <<'PY'
from pathlib import Path
import sys
source, root = sys.argv[1:]
text = Path(source).read_text()
text = text.replace('while path != "/":', 'while path != ' + repr(root) + ':')
for absolute in ("/opt/aukora", "/etc/aukora", "/var/lib/aukora", "/usr/local/bin", "/etc/systemd/system", "/sys/fs/cgroup", "/etc/subuid", "/etc/subgid"):
    text = text.replace(absolute, root + absolute)
Path(root + "/opt/aukora/deploy/install.sh").write_text(text)
PY
    : > "$INSTALL_TEST_LOG"
    unset INSTALL_TEST_UID INSTALL_TEST_ACL_WRITE INSTALL_TEST_OWNER_WRITE INSTALL_TEST_GROUP_WRITE INSTALL_TEST_WALK_ERROR
}

mount_runtime() {
    local runtime
    for runtime in node harness sovereign; do
        "$real_cp" -a "$temporary/source/$runtime" "$INSTALL_TEST_ROOT/opt/aukora/$runtime"
    done
}
run_install() {
    sh "$INSTALL_TEST_ROOT/opt/aukora/deploy/install.sh" "$@" > "$temporary/out" 2> "$temporary/err"
}
run_copy() {
    run_install "$temporary/source/binary" "$temporary/source/node" "$temporary/source/harness" "$temporary/source/sovereign" owner-s1-203-0-113-7.sslip.io chat-s1-203-0-113-7.sslip.io "$@"
}
run_in_place() {
    run_install --runtime-in-place "$temporary/source/binary" "$INSTALL_TEST_ROOT/opt/aukora/node" "$INSTALL_TEST_ROOT/opt/aukora/harness" "$INSTALL_TEST_ROOT/opt/aukora/sovereign" owner-s1-203-0-113-7.sslip.io chat-s1-203-0-113-7.sslip.io "$@"
}
expect_refusal() {
    local reason=$1
    shift
    if "$@"; then fail "$reason accepted"; fi
    [[ ! -s "$temporary/out" ]] || fail "$reason claim emitted"
    [[ ! -e "$INSTALL_TEST_ROOT/etc/aukora/node.json" ]] || fail "$reason installed configuration"
}
verify_install() {
    local expected_subid=${1:-100000}
    local expected_ranges=${2:-$'other:200000:65536\naukora:100000:1000\n'}
    [[ $(cat "$temporary/out") == 'https://owner-s1-203-0-113-7.sslip.io/#claim=synthetic-installer-secret' ]] || fail 'one claim link stdout'
    [[ $(wc -l < "$temporary/out") -eq 1 ]] || fail 'unexpected installer stdout'
    ! grep -qE -- synthetic-installer-secret "$INSTALL_TEST_LOG" "$temporary/err" || fail 'claim appeared in diagnostics'
    "$real_python" - "$INSTALL_TEST_ROOT" "$expected_subid" "$expected_ranges" <<'PY'
import json
from pathlib import Path
import sys
root = Path(sys.argv[1])
subid = int(sys.argv[2])
expected_ranges = sys.argv[3]
config = json.loads((root / "etc/aukora/node.json").read_text())
assert config["listen"] == "127.0.0.1:18080"
assert config["owner_hostname"] == "owner-s1-203-0-113-7.sslip.io"
assert config["chat_hostname"] == "chat-s1-203-0-113-7.sslip.io"
assert config["webauthn"] == {"rp_id": config["owner_hostname"], "origin": "https://" + config["owner_hostname"]}
assert config["guest"] == {"node_dir": str(root) + "/opt/aukora/node", "harness_dir": str(root) + "/opt/aukora/harness", "bundle_dir": str(root) + "/opt/aukora/sovereign", "work_dir": str(root) + "/var/lib/aukora-guest", "subordinate_uid": subid, "subordinate_gid": subid}
assert (root / "etc/subuid").read_text() == expected_ranges
assert (root / "etc/subgid").read_text() == expected_ranges
assert (root / "etc/aukora/node.json").stat().st_mode & 0o777 == 0o640
commands = Path(root.parent / "commands").read_text().splitlines()
assert "systemctl <daemon-reload>" in commands
assert "systemctl <enable> <--now> <aukora-sovereign.service>" in commands
assert commands[-1] == "runuser <-u> <aukora> <--> <" + str(root) + "/usr/local/bin/sovereign> <claim-link> <--config> <" + str(root) + "/etc/aukora/node.json>"
for runtime in ("node", "harness", "sovereign"):
    assert (root / "opt/aukora" / runtime).is_dir()
assert (root / "opt/aukora/harness/package-link").is_symlink()
PY
}

reset_case
run_copy || fail 'default copy install'
verify_install
[[ $(grep -cE -- '^cp ' "$INSTALL_TEST_LOG") == 3 ]] || fail 'default runtime copies changed'
grep -qE -- '^chown <-R> <root:root>' "$INSTALL_TEST_LOG" || fail 'default runtime ownership changed'
[[ $(grep -cE -- '^find ' "$INSTALL_TEST_LOG") == 3 ]] || fail 'default runtime mode updates changed'

reset_case
printf 'ubuntu:100000:65536\n' > "$INSTALL_TEST_ROOT/etc/subuid"
printf 'ubuntu:100000:65536\n' > "$INSTALL_TEST_ROOT/etc/subgid"
run_copy || fail 'default subordinate range allocation'
verify_install 165536 $'ubuntu:100000:65536\naukora:165536:65536\n'

reset_case
mount_runtime
expect_refusal 'default existing runtime' run_copy

reset_case
mount_runtime
run_in_place || fail 'runtime in place install'
verify_install
! grep -qE -- '^(cp|find) |^chown <-R> |^install <-d> <-o> <root> <-g> <root> <-m> <0755>' "$INSTALL_TEST_LOG" || fail 'mounted runtime modified'

reset_case
mount_runtime
printf 'ubuntu:100000:65536\n' > "$INSTALL_TEST_ROOT/etc/subuid"
printf 'ubuntu:100000:65536\n' > "$INSTALL_TEST_ROOT/etc/subgid"
run_in_place || fail 'in place subordinate range allocation'
verify_install 165536 $'ubuntu:100000:65536\naukora:165536:65536\n'
! grep -qE -- '^(cp|find) |^chown <-R> |^install <-d> <-o> <root> <-g> <root> <-m> <0755>' "$INSTALL_TEST_LOG" || fail 'stock image mounted runtime modified'

reset_case
mount_runtime
"$real_cp" "$here/../node.example.json" "$temporary/custom.json"
"$real_python" - "$temporary/custom.json" <<'PYINVITE'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1]); value = json.loads(path.read_text())
value['invite'] = {'schema':'aukora-spawn-invite-v1', 'event':{'id':'a'*64}, 'invite_event_id':'a'*64, 'inviter_npub':'npub-fixture', 'claim_sha256':'b'*64}
path.write_text(json.dumps(value))
PYINVITE
run_in_place "$temporary/custom.json" || fail 'in place config template'
verify_install
"$real_python" - "$temporary/custom.json" "$INSTALL_TEST_ROOT/etc/aukora/node.json" <<'PYINVITE'
import json, pathlib, sys
original, installed = map(pathlib.Path, sys.argv[1:])
assert json.loads(installed.read_text())['invite'] == json.loads(original.read_text())['invite']
PYINVITE

reset_case
mount_runtime
"$real_cp" -a "$temporary/source/node" "$INSTALL_TEST_ROOT/opt/aukora/wrong-node"
expect_refusal 'in place exact runtime paths' run_install --runtime-in-place "$temporary/source/binary" "$INSTALL_TEST_ROOT/opt/aukora/wrong-node" "$INSTALL_TEST_ROOT/opt/aukora/harness" "$INSTALL_TEST_ROOT/opt/aukora/sovereign" owner-s1-203-0-113-7.sslip.io chat-s1-203-0-113-7.sslip.io

for runtime in node harness sovereign; do
    reset_case
    mount_runtime
    rm -rf -- "$INSTALL_TEST_ROOT/opt/aukora/$runtime"
    expect_refusal "missing $runtime" run_in_place
    reset_case
    mount_runtime
    mv "$INSTALL_TEST_ROOT/opt/aukora/$runtime" "$INSTALL_TEST_ROOT/opt/$runtime-real"
    ln -s "../$runtime-real" "$INSTALL_TEST_ROOT/opt/aukora/$runtime"
    expect_refusal "symlink $runtime" run_in_place
    reset_case
    mount_runtime
    rm -rf -- "$INSTALL_TEST_ROOT/opt/aukora/$runtime"
    : > "$INSTALL_TEST_ROOT/opt/aukora/$runtime"
    expect_refusal "nondirectory $runtime" run_in_place
    reset_case
    mount_runtime
    "$real_chmod" 0777 "$INSTALL_TEST_ROOT/opt/aukora/$runtime"
    expect_refusal "writable root $runtime" run_in_place
done

reset_case
mount_runtime
mv "$INSTALL_TEST_ROOT/opt/aukora" "$INSTALL_TEST_ROOT/opt/runtime-real"
ln -s runtime-real "$INSTALL_TEST_ROOT/opt/aukora"
expect_refusal 'symlink runtime ancestor' run_in_place

reset_case
mount_runtime
"$real_chmod" 0777 "$INSTALL_TEST_ROOT/opt/aukora"
expect_refusal 'writable runtime ancestor' run_in_place

for permission in world owner group acl; do
    reset_case
    mount_runtime
    target="$INSTALL_TEST_ROOT/opt/aukora/harness/package/entry.js"
    case "$permission" in
        world) "$real_chmod" 0666 "$target" ;;
        owner) export INSTALL_TEST_OWNER_WRITE="$target" ;;
        group) "$real_chmod" 0660 "$target"; export INSTALL_TEST_GROUP_WRITE="$target" ;;
        acl) export INSTALL_TEST_ACL_WRITE="$target" ;;
    esac
    expect_refusal "writable runtime file $permission" run_in_place
done

reset_case
mount_runtime
"$real_chmod" 0777 "$INSTALL_TEST_ROOT/opt/aukora/harness/package"
expect_refusal 'writable runtime subtree' run_in_place

reset_case
mount_runtime
export INSTALL_TEST_WALK_ERROR="$INSTALL_TEST_ROOT/opt/aukora/harness"
expect_refusal 'inaccessible runtime tree' run_in_place

reset_case
mount_runtime
rm -rf -- "$INSTALL_TEST_ROOT/opt/aukora/sovereign/guest"
expect_refusal 'in place guest absent' run_in_place

if [[ ${1:-} != --check-only ]]; then
    "$real_python" - "$candidate" "$temporary" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
folder = Path(sys.argv[2])
mutations = [
    ("invite-provenance", '    config = json.load(source)', '    config = json.load(source)\nconfig.pop("invite", None)'),
    ("exact-paths", 'if "$task_runtime_in_place" && {', 'if false && {'),
    ("missing", '        except OSError:\n            refuse("path missing or inaccessible")', '        except OSError:\n            break'),
    ("root-symlink", 'if stat.S_ISLNK(info.st_mode):', 'if False:'),
    ("directory", 'if not stat.S_ISDIR(info.st_mode):', 'if False:'),
    ("tree-inaccessible", 'os.walk(root, onerror=walk_error)', 'os.walk(root)'),
    ("root-writable", '        if os.access(path, os.W_OK):\n            refuse("is writable by aukora")', '        if False:\n            refuse("is writable by aukora")'),
    ("descendant-writable", '            if os.access(path, os.W_OK):', '            if False:'),
    ("service-user", 'runuser -u aukora -- python3 - "$2" "$3" "$4"', 'python3 - "$2" "$3" "$4"'),
    ("guest-required", 'if not os.path.isdir(os.path.join(sys.argv[3], "guest")):', 'if False:'),
    ("skip-copy", 'if ! "$task_runtime_in_place"; then\n    install -d', 'if true; then\n    install -d'),
    ("subid-allocation", 'start = max([100000] + [int(start) + int(length) for _, start, length in ranges])', 'start = 100000'),
]
for name, before, after in mutations:
    assert text.count(before) == 1, name
    mutant = text.replace(before, after)
    if name == "missing":
        mutant = mutant.replace('for root in sys.argv[1:]:', 'for root in sys.argv[1:]:\n    if not os.path.exists(root):\n        continue')
    if name == "root-symlink":
        mutant = mutant.replace('info = os.lstat(path)', 'info = os.stat(path)')
    if name == "directory":
        # os.walk also refuses a nondirectory through its error handler.
        mutant = mutant.replace('os.walk(root, onerror=walk_error)', 'os.walk(root)')
    (folder / ("mutation-" + name + ".sh")).write_text(mutant)
PY
    killed=0
    for mutation in "$temporary"/mutation-*.sh; do
        if AUKORA_INSTALL_CANDIDATE="$mutation" bash "$here/install-test.sh" --check-only > "$temporary/mutation.out" 2>&1; then
            fail "surviving mutation ${mutation##*/}"
        fi
        killed=$((killed + 1))
    done
    printf 'PASS installer mutation kills: %s/%s\n' "$killed" "$killed"
fi
printf 'PASS installer tests: shell syntax, default copy, runtime in place, stock image subordinate ranges, roots, symlinks, service-user writability, config, unit, one claim link\n'
