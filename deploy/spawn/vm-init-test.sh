#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
set +x

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
candidate=${VM_INIT_TEST_SUT:-$here/vm-init.sh}
temporary=$(mktemp -d "$here/.vm-init-test.XXXXXX")
export TMPDIR="$temporary"
trap 'rm -rf "$temporary"' EXIT
export VM_TEST_LOG="$temporary/commands" VM_TEST_FIXTURES="$temporary/fixtures"
export VM_MOCK_UID=0 VM_MOCK_LANDLOCK_EXIT=0 VM_MOCK_INSTALL_EXIT=0 VM_MOCK_CADDY_EXIT=0
export VM_MOCK_CURL_FAIL_URL='' VM_MOCK_TAMPER=''
mkdir -p "$temporary/bin" "$temporary/helpers" "$VM_TEST_FIXTURES/node/bin" "$VM_TEST_FIXTURES/harness" "$VM_TEST_FIXTURES/guest" "$VM_TEST_FIXTURES/bridge"
export PATH="$temporary/bin:$PATH"
printf 'fixture node\n' >"$VM_TEST_FIXTURES/node/bin/node"
chmod 0755 "$VM_TEST_FIXTURES/node/bin/node"
printf 'fixture harness\n' >"$VM_TEST_FIXTURES/harness/entry.js"
printf 'fixture guest\n' >"$VM_TEST_FIXTURES/guest/preload.mjs"
printf 'fixture bridge\n' >"$VM_TEST_FIXTURES/bridge/frame.mjs"
python3 "$here/vectors/probe-elf.py" "$VM_TEST_FIXTURES/guest/probe"
release=$(bash "$here/bundle.sh" --node "$VM_TEST_FIXTURES/node" --harness "$VM_TEST_FIXTURES/harness" --guest "$VM_TEST_FIXTURES/guest" --bridge "$VM_TEST_FIXTURES/bridge" --output "$VM_TEST_FIXTURES/runtime.tar.gz")
cat >"$VM_TEST_FIXTURES/sovereign" <<'BINARY'
#!/bin/bash
set -euo pipefail
printf 'unexpected-claim' >>"$VM_TEST_LOG"
exit 91
BINARY
chmod 0755 "$VM_TEST_FIXTURES/sovereign"
hash() {
    python3 - "$1" <<'PY'
import hashlib, sys
with open(sys.argv[1], "rb") as source:
    digest = hashlib.sha256()
    for chunk in iter(lambda: source.read(1024 * 1024), b""):
        digest.update(chunk)
    print(digest.hexdigest())
PY
}
runtime_hash=$(hash "$VM_TEST_FIXTURES/runtime.tar.gz")
binary_hash=$(hash "$VM_TEST_FIXTURES/sovereign")
runtime_url=https://fixtures.invalid/runtime.tar.gz
binary_url=https://fixtures.invalid/sovereign
node_id=0123456789abcdef0123456789abcdef
cp "$here/unpack.sh" "$temporary/helpers/unpack.sh"
cat >"$temporary/helpers/bootstrap.sh" <<'BOOTSTRAP'
require_root() {
    [[ $VM_MOCK_UID == 0 ]] || { printf 'spawn:root-required\n' >&2; return 1; }
}
validate_bootstrap_args() { :; }
check_landlock() {
    printf 'check_landlock\n' >>"$VM_TEST_LOG"
    if [[ $VM_MOCK_LANDLOCK_EXIT != 0 ]]; then
        printf 'spawn:landlock-abi\n' >&2
        return 1
    fi
}
bootstrap_main() {
    printf 'bootstrap' >>"$VM_TEST_LOG"
    printf ' <%s>' "$@" >>"$VM_TEST_LOG"
    printf '\ninstaller\n' >>"$VM_TEST_LOG"
    chat_host="chat-$2-${4//./-}.sslip.io"
    owner_host="owner-$2-${4//./-}.sslip.io"
    if [[ $VM_MOCK_INSTALL_EXIT != 0 ]]; then
        printf 'spawn:install\n' >&2
        return 1
    fi
    claim_link="https://$owner_host/#claim=fixture-one-time-claim"
}
write_claim_handoff() {
    printf 'write_claim_handoff <%s>\n' "$1" >>"$VM_TEST_LOG"
    mkdir -p -m 0700 "${1%/*}"
    printf '%s\n' "$claim_link" > "$1"
    chmod 0600 "$1"
}
BOOTSTRAP
cat >"$temporary/helpers/caddy.sh" <<'CADDY'
caddy_update() {
    printf 'caddy_update' >>"$VM_TEST_LOG"
    printf ' <%s>' "$@" >>"$VM_TEST_LOG"
    printf '\n' >>"$VM_TEST_LOG"
    [[ $VM_MOCK_CADDY_EXIT == 0 ]]
}
CADDY
cat >"$temporary/bin/curl" <<'CURL'
#!/bin/bash
set -euo pipefail
printf 'curl' >>"$VM_TEST_LOG"
printf ' <%s>' "$@" >>"$VM_TEST_LOG"
printf '\n' >>"$VM_TEST_LOG"
printf 'fixture-download-private-diagnostic\n' >&2
url=${!#}
[[ $url != "$VM_MOCK_CURL_FAIL_URL" ]] || exit 22
if [[ $url == https://api.ipify.org ]]; then
    printf '203.0.113.7\n'
    exit 0
fi
output=''
while [[ $# -gt 0 ]]; do
    if [[ $1 == --output ]]; then output=$2; break; fi
    shift
done
[[ -n $output ]]
case "$url" in
    https://fixtures.invalid/runtime.tar.gz)
        if [[ $VM_MOCK_TAMPER == runtime ]]; then
            cp "$VM_TEST_FIXTURES/runtime-altered.tar.gz" "$output"
        else
            cp "$VM_TEST_FIXTURES/runtime.tar.gz" "$output"
        fi ;;
    https://fixtures.invalid/sovereign)
        cp "$VM_TEST_FIXTURES/sovereign" "$output"
        if [[ $VM_MOCK_TAMPER == binary ]]; then printf '\n# altered fixture\n' >>"$output"; fi ;;
    *) exit 22 ;;
esac
CURL
cat >"$temporary/bin/install" <<'INSTALL'
#!/bin/bash
set -euo pipefail
printf 'install' >>"$VM_TEST_LOG"
printf ' <%s>' "$@" >>"$VM_TEST_LOG"
printf '\n' >>"$VM_TEST_LOG"
[[ $# == 8 && $1 == -o && $2 == root && $3 == -g && $4 == root && $5 == -m && $6 == 0755 ]]
cp "$7" "$8"
chmod "$6" "$8"
INSTALL
chmod +x "$temporary/bin/curl" "$temporary/bin/install"
python3 - "$VM_TEST_FIXTURES/runtime.tar.gz" "$VM_TEST_FIXTURES/runtime-altered.tar.gz" <<'PY'
import tarfile, sys
with tarfile.open(sys.argv[1], "r:gz") as source, tarfile.open(sys.argv[2], "w:gz") as output:
    for member in source:
        member.uid = 101
        output.addfile(member, source.extractfile(member) if member.isfile() else None)
PY

fail() { printf 'FAIL vm-init: %s\n' "$1" >&2; exit 1; }
reset_case() {
    root="$temporary/root"
    rm -rf "$root"
    mkdir -p "$root/var/lib"
    : >"$VM_TEST_LOG"
    VM_MOCK_UID=0 VM_MOCK_LANDLOCK_EXIT=0 VM_MOCK_INSTALL_EXIT=0 VM_MOCK_CADDY_EXIT=0
    VM_MOCK_CURL_FAIL_URL='' VM_MOCK_TAMPER=''
    python3 - "$candidate" "$temporary/helpers/vm-init.sh" "$root" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
for path in ("/opt/aukora", "/var/lib/aukora-spawn"):
    text = text.replace(path, sys.argv[3] + path)
Path(sys.argv[2]).write_text(text)
PY
}
run_init() {
    bash "$temporary/helpers/vm-init.sh" alpha "$node_id" "$runtime_url" "$runtime_hash" "${1:-$release}" "$binary_url" "$binary_hash" >"$temporary/stdout" 2>"$temporary/stderr"
}
private_output() {
    [[ ! -s $temporary/stdout && ! -s $temporary/stderr ]] || fail 'claim or diagnostic leaked to cloud-init logs'
}
no_claim_or_install() {
    if grep -q '^installer$\|^claim ' "$VM_TEST_LOG"; then fail 'refusal reached installer or claim'; fi
    [[ ! -e $root/var/lib/aukora-spawn/claim-link && ! -e $root/var/lib/aukora-spawn-claim-issued ]] || fail 'refusal created claim artifacts'
}
refused() {
    local code=$1
    shift
    if run_init "$@"; then fail "$code accepted"; fi
    [[ ! -s $temporary/stdout && $(cat "$temporary/stderr") == "$code" ]] || fail "$code output"
}
test_success() {
    reset_case
    run_init || fail 'valid init failed'
    private_output
    [[ $(cat "$root/var/lib/aukora-spawn/claim-link") == 'https://owner-alpha-203-0-113-7.sslip.io/#claim=fixture-one-time-claim' ]] || fail 'claim file contents'
    [[ -f $root/var/lib/aukora-spawn-claim-issued ]] || fail 'claim marker missing'
    [[ -f $root/var/lib/aukora-spawn-ready ]] || fail 'ready marker missing' 
    python3 - "$VM_TEST_LOG" "$root" "$node_id" "$root/var/lib/aukora-spawn/claim-link" "$release" <<'PY'
import re, stat, sys
from pathlib import Path
log, root, node, claim, release = sys.argv[1:]
text = Path(log).read_text()
text = re.sub(r"<[^<>]*/runtime\.tar\.gz>", "<RUNTIME>", text, count=1)
text = re.sub(r"<[^<>]*/sovereign>", "<BINARY>", text, count=1)
expected = (
    "check_landlock\n"
    "curl <--proto> <=https> <--tlsv1.2> <--fail> <--silent> <--show-error> <--max-time> <1800> <--output> <RUNTIME> <https://fixtures.invalid/runtime.tar.gz>\n"
    "curl <--proto> <=https> <--tlsv1.2> <--fail> <--silent> <--show-error> <--max-time> <1800> <--output> <BINARY> <https://fixtures.invalid/sovereign>\n"
    "install <-o> <root> <-g> <root> <-m> <0755> <" + next(line.split(" <")[-2][:-1] for line in Path(log).read_text().splitlines() if line.startswith("install ")) + "> <" + root + "/opt/aukora/bin/sovereign>\n"
    "curl <--proto> <=https> <--tlsv1.2> <--fail> <--silent> <--show-error> <--max-time> <10> <https://api.ipify.org>\n"
    "bootstrap <vm> <alpha> <" + node + "> <203.0.113.7>\ninstaller\n"
    "write_claim_handoff <" + root + "/var/lib/aukora-spawn/claim-link>\n"
    "caddy_update <add> <alpha> <chat-alpha-203-0-113-7.sslip.io> <owner-alpha-203-0-113-7.sslip.io> <127.0.0.1:18080>\n")
assert text == expected, (text, expected)
assert stat.S_IMODE(Path(claim).stat().st_mode) == 0o600, "claim file mode"
assert stat.S_IMODE(Path(claim).parent.stat().st_mode) == 0o700, "claim directory mode"
for marker in ("claim-issued", "ready"):
    assert stat.S_IMODE(Path(root + "/var/lib/aukora-spawn-" + marker).stat().st_mode) == 0o600, marker + " marker mode"
assert Path(root + "/opt/aukora/runtime/MANIFEST.sha256").read_text() == release + "  MANIFEST\n"
assert Path(root + "/opt/aukora/runtime/node/bin/node").read_text() == "fixture node\n"
assert stat.S_IMODE(Path(root + "/opt/aukora/bin/sovereign").stat().st_mode) == 0o755
PY
}
test_idempotent() {
    reset_case
    run_init || fail 'initial run failed'
    cp "$root/var/lib/aukora-spawn/claim-link" "$temporary/original-claim"
    run_init || fail 'rerun failed'
    private_output
    [[ $(grep -c '^installer$' "$VM_TEST_LOG") == 1 ]] || fail 'rerun reached installer'
    [[ $(grep -c '^curl ' "$VM_TEST_LOG") == 3 ]] || fail 'rerun downloaded artifacts'
    cmp "$temporary/original-claim" "$root/var/lib/aukora-spawn/claim-link" || fail 'rerun replaced claim'
    rm "$root/var/lib/aukora-spawn/claim-link"
    run_init || fail 'rerun after consumption failed'
    private_output
    [[ ! -e $root/var/lib/aukora-spawn/claim-link ]] || fail 'rerun recreated consumed claim'
    [[ $(grep -c '^installer$' "$VM_TEST_LOG") == 1 ]] || fail 'consumed claim rerun reached installer'
}
test_runtime_hash() {
    reset_case
    VM_MOCK_TAMPER=runtime
    refused spawn:artifact-digest
    no_claim_or_install
    [[ ! -d $root/opt/aukora/runtime ]] || fail 'unverified runtime unpacked'
    [[ $(grep -c '^curl ' "$VM_TEST_LOG") == 1 ]] || fail 'runtime refusal download sequence'
}
test_binary_hash() {
    reset_case
    VM_MOCK_TAMPER=binary
    refused spawn:artifact-digest
    no_claim_or_install
    [[ ! -e $root/opt/aukora/bin/sovereign ]] || fail 'unverified binary installed'
    [[ $(grep -c '^curl ' "$VM_TEST_LOG") == 2 ]] || fail 'binary refusal download sequence'
}
test_release() {
    reset_case
    refused bundle:release-digest-mismatch 0000000000000000000000000000000000000000000000000000000000000000
    no_claim_or_install
    [[ ! -d $root/opt/aukora/runtime ]] || fail 'unapproved release unpacked'
    [[ $(grep -c '^curl ' "$VM_TEST_LOG") == 1 ]] || fail 'release refusal download sequence'
}
test_failures() {
    reset_case
    VM_MOCK_LANDLOCK_EXIT=1
    refused spawn:landlock-abi
    no_claim_or_install
    [[ $(cat "$VM_TEST_LOG") == check_landlock ]] || fail 'Landlock refusal order'
    reset_case
    VM_MOCK_CURL_FAIL_URL=$runtime_url
    refused spawn:artifact-download
    no_claim_or_install
    reset_case
    VM_MOCK_INSTALL_EXIT=1
    refused spawn:install
    [[ $(grep -c '^installer$' "$VM_TEST_LOG") == 1 ]] || fail 'installer mock not reached'
    if grep -q '^caddy_update\|^claim ' "$VM_TEST_LOG"; then fail 'failed installer exposed node'; fi
    [[ ! -e $root/var/lib/aukora-spawn/claim-link && ! -e $root/var/lib/aukora-spawn-claim-issued ]] || fail 'failed installer issued claim'
}

test_caddy_retry() {
    reset_case
    VM_MOCK_CADDY_EXIT=1
    if run_init; then fail 'failed Caddy accepted'; fi
    private_output
    [[ -s $root/var/lib/aukora-spawn/claim-link && -f $root/var/lib/aukora-spawn-claim-issued ]] || fail 'failed Caddy lost private handoff'
    [[ ! -e $root/var/lib/aukora-spawn-ready ]] || fail 'failed Caddy marked ready'
    cp "$root/var/lib/aukora-spawn/claim-link" "$temporary/original-claim"
    python3 - "$root" <<'PYMARKER'
from pathlib import Path
import stat, sys
root = Path(sys.argv[1])
for path in (root / "var/lib/aukora-spawn/claim-link", root / "var/lib/aukora-spawn-claim-issued"):
    assert stat.S_IMODE(path.stat().st_mode) == 0o600, str(path)
PYMARKER
    VM_MOCK_CADDY_EXIT=0
    run_init || fail 'Caddy retry failed'
    private_output
    [[ -f $root/var/lib/aukora-spawn-ready ]] || fail 'Caddy retry did not mark ready'
    [[ $(grep -c '^installer$' "$VM_TEST_LOG") == 1 ]] || fail 'Caddy retry reran installer'
    [[ $(grep -c '^write_claim_handoff ' "$VM_TEST_LOG") == 1 ]] || fail 'Caddy retry rewrote claim'
    [[ $(grep -c '^curl ' "$VM_TEST_LOG") == 4 ]] || fail 'Caddy retry downloaded artifacts'
    [[ $(grep -c '^caddy_update ' "$VM_TEST_LOG") == 2 ]] || fail 'Caddy retry skipped reload'
    cmp "$temporary/original-claim" "$root/var/lib/aukora-spawn/claim-link" || fail 'Caddy retry replaced claim'
}
test_root() {
    reset_case
    VM_MOCK_UID=501
    refused spawn:root-required
    [[ ! -s $VM_TEST_LOG ]] || fail 'non-root ran cloud-init work'
    no_claim_or_install
}

if [[ ${1:-} == --case ]]; then
    "test_$2"
    exit 0
fi
for test in success idempotent runtime_hash binary_hash release failures caddy_retry root; do
    "test_$test"
    printf 'PASS vm-init: %s\n' "$test"
done
python3 - "$candidate" "$temporary/mutations" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text()
folder = Path(sys.argv[2])
folder.mkdir()
mutations = [
    ("artifact-sha", "runtime_hash", "if digest != sys.argv[2]:", "if False:"),
    ("binary-sha", "binary_hash", "if digest != sys.argv[2]:", "if False:"),
    ("https-only", "success", "--proto '=https'", "--proto '=http,https'"),
    ("tls-minimum", "success", "--tlsv1.2", "--tlsv1.0"),
    ("landlock-before-download", "failures", "check_landlock\n", ":\n"),
    ("claim-output", "success", "write_claim_handoff /var/lib/aukora-spawn/claim-link", "printf '%s\\n' \"$claim_link\""),
    ("claim-captured", "success", "write_claim_handoff /var/lib/aukora-spawn/claim-link", "/opt/aukora/bin/sovereign claim-link > /var/lib/aukora-spawn/claim-link 2>/dev/null"),
    ("claim-handoff", "success", "write_claim_handoff /var/lib/aukora-spawn/claim-link", ":"),
    ("claim-once", "caddy_retry", "if [[ ! -f /var/lib/aukora-spawn-claim-issued ]]; then", "if true; then"),
    ("claim-marker", "caddy_retry", ": > /var/lib/aukora-spawn-claim-issued", ":"),
    ("ready-once", "idempotent", "if [[ -f /var/lib/aukora-spawn-ready ]]; then", "if false; then"),
    ("ready-marker", "success", ": > /var/lib/aukora-spawn-ready", ":"),
    ("marker-private", "success", "umask 077", "umask 022"),
    ("root-required", "root", "require_root\n", ":\n"),
    ("real-listen", "success", "127.0.0.1:18080", "127.0.0.1:8080"),
    ("installer-failure", "failures", 'bootstrap_main vm "$name" "$node_id" "$ip"', 'bootstrap_main vm "$name" "$node_id" "$ip" || true'),
    ("caddy-failure", "caddy_retry", 'caddy_update add "$name" "$chat_host" "$owner_host" 127.0.0.1:18080', 'caddy_update add "$name" "$chat_host" "$owner_host" 127.0.0.1:18080 || true'),
]
for name, case, before, after in mutations:
    assert before in text, name
    (folder / (name + ".sh")).write_text(text.replace(before, after, 1))
    with (folder / "cases").open("a") as cases:
        cases.write(name + " " + case + "\n")
PY
killed=0
while read -r mutation test; do
    if VM_INIT_TEST_SUT="$temporary/mutations/$mutation.sh" bash "$here/vm-init-test.sh" --case "$test" >"$temporary/mutation-output" 2>&1; then
        fail "mutation survived: $mutation"
    fi
    killed=$((killed + 1))
done <"$temporary/mutations/cases"
printf 'PASS vm-init: %s mutation kills\n' "$killed"
