#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
set +x

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
SUT=${CADDY_TEST_SUT:-$HERE/caddy.sh}
TEST_ROOT=$(mktemp -d "$HERE/.caddy-test.XXXXXX")
trap 'rm -rf "$TEST_ROOT"' EXIT
mkdir "$TEST_ROOT/bin"
export PATH="$TEST_ROOT/bin:$PATH"
export CADDY_TEST_LOG="$TEST_ROOT/commands" CADDY_TEST_STATE="$TEST_ROOT/mock-state"
export AUKORA_CADDYFILE="$TEST_ROOT/Caddyfile"
export CADDY_TEST_VALIDATE_FAILURES=0 CADDY_TEST_RELOAD_FAILURES=0 CADDY_TEST_SIGNAL_RELOAD=0
PYTHON_REAL=$(command -v python3)
export CADDY_TEST_PYTHON_REAL="$PYTHON_REAL" CADDY_TEST_INTERFERENCE=''
cat >"$TEST_ROOT/bin/caddy" <<'MOCK'
#!/bin/bash
set -euo pipefail
printf 'caddy' >>"$CADDY_TEST_LOG"
printf ' <%s>' "$@" >>"$CADDY_TEST_LOG"
printf '\n' >>"$CADDY_TEST_LOG"
state="$CADDY_TEST_STATE.caddy"
count=0
[[ ! -f $state ]] || read -r count <"$state"
count=$((count + 1))
printf '%s\n' "$count" >"$state"
[[ $count -gt $CADDY_TEST_VALIDATE_FAILURES ]]
MOCK
cat >"$TEST_ROOT/bin/systemctl" <<'MOCK'
#!/bin/bash
set -euo pipefail
printf 'systemctl' >>"$CADDY_TEST_LOG"
printf ' <%s>' "$@" >>"$CADDY_TEST_LOG"
printf '\n' >>"$CADDY_TEST_LOG"
state="$CADDY_TEST_STATE.systemctl"
count=0
[[ ! -f $state ]] || read -r count <"$state"
count=$((count + 1))
printf '%s\n' "$count" >"$state"
if [[ $CADDY_TEST_SIGNAL_RELOAD == 1 && $count == 1 ]]; then
    kill -TERM "$PPID"
fi
[[ $count -gt $CADDY_TEST_RELOAD_FAILURES ]]
MOCK
chmod +x "$TEST_ROOT/bin/caddy" "$TEST_ROOT/bin/systemctl"

fail() { printf 'FAIL caddy: %s\n' "$*" >&2; exit 1; }
reset_case() {
    rm -f "$CADDY_TEST_LOG" "$CADDY_TEST_STATE.caddy" "$CADDY_TEST_STATE.systemctl" "$AUKORA_CADDYFILE"
    printf '# existing sibling bytes\r\n:80 {\n\tabort\n}' >"$AUKORA_CADDYFILE"
    chmod 0640 "$AUKORA_CADDYFILE"
    cp -p "$AUKORA_CADDYFILE" "$TEST_ROOT/original"
    : >"$CADDY_TEST_LOG"
    CADDY_TEST_VALIDATE_FAILURES=0
    CADDY_TEST_RELOAD_FAILURES=0
    CADDY_TEST_SIGNAL_RELOAD=0
    CADDY_TEST_INTERFERENCE=''
}
add() { bash "$SUT" add alpha chat-alpha-203-0-113-7.sslip.io owner-alpha-203-0-113-7.sslip.io 127.0.0.1:28080; }
refused() {
    local code=$1
    shift
    if "$@" >"$TEST_ROOT/stdout" 2>"$TEST_ROOT/stderr"; then fail "expected $code"; fi
    [[ ! -s $TEST_ROOT/stdout ]] || fail "refusal printed stdout"
    grep -qF -- "$code" "$TEST_ROOT/stderr" || fail "missing $code"
}
unchanged() {
    cmp "$AUKORA_CADDYFILE" "$TEST_ROOT/original" || fail "unrelated file bytes changed"
    python3 - "$AUKORA_CADDYFILE" <<'PY'
import os, stat, sys
assert stat.S_IMODE(os.stat(sys.argv[1]).st_mode) == 0o640, "file mode changed"
PY
}
sequence() {
    local expected=$1
    printf '%s' "$expected" >"$TEST_ROOT/expected"
    cmp "$TEST_ROOT/expected" "$CADDY_TEST_LOG" || fail "command order changed"
}
validate="caddy <validate> <--config> <$AUKORA_CADDYFILE> <--adapter> <caddyfile>"
reload='systemctl <reload> <caddy>'

test_render() {
    bash -c 'source "$1"; render_site alpha chat-alpha-203-0-113-7.sslip.io owner-alpha-203-0-113-7.sslip.io 127.0.0.1:28080' bash "$SUT" >"$TEST_ROOT/render"
    python3 - "$TEST_ROOT/render" <<'PY'
import sys
text = open(sys.argv[1]).read()
assert text.startswith("\n# BEGIN AUKORA SOVEREIGN alpha\n")
assert text.endswith("# END AUKORA SOVEREIGN alpha\n")
for directive in ('header Strict-Transport-Security "max-age=31536000"',
                  'header X-Content-Type-Options "nosniff"',
                  'header Referrer-Policy "no-referrer"', "max_size 8MB",
                  "header_up -Forwarded",
                  "header_up Host {host}",
                  "header_up X-Forwarded-For {remote_host}",
                  "header_up X-Forwarded-Host {host}",
                  "header_up X-Forwarded-Proto https", "flush_interval -1"):
    assert text.count(directive) == 2, directive
assert text.count('header X-Frame-Options "DENY"') == 1
# Caddy applies header_up deletions after sets: a wildcard delete would erase the
# X-Forwarded-* values set above, and the front door refuses requests without them.
for directive in ("header_up Origin", "header_up Cookie", "header_up Sec-Fetch", "header_up -X-Forwarded-*", "{uri}", "log {"):
    assert directive not in text, directive
sites = text.split("\nhttps://")[1:]
for site in sites:
    assert site.index("@launch_token query token=*") < site.index("handle @launch_token") < site.index("respond 404") < site.index("reverse_proxy")
assert text.count("@launch_token query token=*") == 4
assert text.count("respond 404") == 4
for host in ("chat-alpha-203-0-113-7.sslip.io", "owner-alpha-203-0-113-7.sslip.io"):
    http = text.split("\nhttp://" + host + " {")[1]
    assert http.index("handle @launch_token") < http.index("redir https://" + host + "{path} permanent")
assert text.count("reverse_proxy 127.0.0.1:28080") == 2
PY
}
test_proxy_contract() {
    bash -c 'source "$1"; render_site alpha chat-alpha-203-0-113-7.sslip.io owner-alpha-203-0-113-7.sslip.io 127.0.0.1:28080' bash "$SUT" >"$TEST_ROOT/render"
    python3 - "$TEST_ROOT/render" "$HERE/../Caddyfile.snippet" <<'PY'
import pathlib, re, sys

rendered = pathlib.Path(sys.argv[1]).read_text()
contract = pathlib.Path(sys.argv[2]).read_text()
headers = re.findall(r"^\s*(header_up .+)$", contract, re.MULTILINE)
assert headers, "installer proxy header contract is empty"
proxies = re.findall(r"reverse_proxy [^\n]+ \{\n(.*?)\n\s*\}", rendered, re.DOTALL)
assert len(proxies) == 2, "owner and chat must both proxy"
for proxy in proxies:
    actual = re.findall(r"^\s*(header_up .+)$", proxy, re.MULTILINE)
    assert actual == headers, (actual, headers)
PY
}
test_add_remove() {
    reset_case
    add
    sequence "$validate"$'\n'"$reload"$'\n'
    cp "$AUKORA_CADDYFILE" "$TEST_ROOT/added"
    : >"$CADDY_TEST_LOG"
    add
    sequence ''
    cmp "$AUKORA_CADDYFILE" "$TEST_ROOT/added" || fail "rerun changed bytes"
    bash "$SUT" add beta chat-beta-203-0-113-7.sslip.io owner-beta-203-0-113-7.sslip.io 127.0.0.1:28081
    : >"$CADDY_TEST_LOG"
    bash "$SUT" remove alpha
    sequence "$validate"$'\n'"$reload"$'\n'
    grep -qE -- '^# BEGIN AUKORA SOVEREIGN beta$' "$AUKORA_CADDYFILE" || fail "destroy removed sibling"
    if grep -qE -- '^# BEGIN AUKORA SOVEREIGN alpha$' "$AUKORA_CADDYFILE"; then fail "own block survived"; fi
    bash "$SUT" remove beta
    unchanged
    : >"$CADDY_TEST_LOG"
    bash "$SUT" remove alpha
    sequence ''
    [[ ! -e $AUKORA_CADDYFILE.aukora.lock ]] || fail "lock leaked"
}
test_validate_rollback() {
    reset_case
    CADDY_TEST_VALIDATE_FAILURES=1
    refused caddy:validate-failed add
    unchanged
    sequence "$validate"$'\n'"$validate"$'\n'"$reload"$'\n'
    [[ ! -e $AUKORA_CADDYFILE.aukora.lock ]] || fail "rollback lock leaked"
}
test_reload_rollback() {
    reset_case
    CADDY_TEST_RELOAD_FAILURES=1
    refused caddy:reload-failed add
    unchanged
    sequence "$validate"$'\n'"$reload"$'\n'"$validate"$'\n'"$reload"$'\n'
}
test_rollback_refusal() {
    reset_case
    CADDY_TEST_VALIDATE_FAILURES=2
    refused caddy:rollback-validate-failed add
    unchanged
    sequence "$validate"$'\n'"$validate"$'\n'
    [[ -d $AUKORA_CADDYFILE.aukora.lock ]] || fail "uncertain rollback lock removed"
    rm -rf "$AUKORA_CADDYFILE.aukora.lock"
}
test_signal() {
    reset_case
    CADDY_TEST_SIGNAL_RELOAD=1
    if add >"$TEST_ROOT/stdout" 2>"$TEST_ROOT/stderr"; then fail "termination succeeded"; fi
    unchanged
    sequence "$validate"$'\n'"$reload"$'\n'"$validate"$'\n'"$reload"$'\n'
    [[ ! -e $AUKORA_CADDYFILE.aukora.lock ]] || fail "termination lock leaked"
}
test_interference() {
    cat >"$TEST_ROOT/bin/python3" <<'MOCK'
#!/bin/bash
set -euo pipefail
if [[ ${2:-} == apply ]]; then
    case "$CADDY_TEST_INTERFERENCE" in
        bytes) printf '\n# unrelated writer\n' >>"$AUKORA_CADDYFILE" ;;
        mode) chmod 0600 "$AUKORA_CADDYFILE" ;;
    esac
fi
exec "$CADDY_TEST_PYTHON_REAL" "$@"
MOCK
    chmod +x "$TEST_ROOT/bin/python3"
    reset_case
    CADDY_TEST_INTERFERENCE=bytes
    refused caddy:file-changed add
    sequence ''
    grep -qE -- '^# unrelated writer$' "$AUKORA_CADDYFILE" || fail "overwrote concurrent writer"
    [[ -d $AUKORA_CADDYFILE.aukora.lock ]] || fail "ambiguous file lock removed"
    rm -rf "$AUKORA_CADDYFILE.aukora.lock"
    reset_case
    CADDY_TEST_INTERFERENCE=mode
    refused caddy:file-changed add
    unchanged
    sequence "$validate"$'\n'"$reload"$'\n'
    rm "$TEST_ROOT/bin/python3"
}
test_lock() {
    reset_case
    mkdir "$AUKORA_CADDYFILE.aukora.lock"
    printf 'foreign lock\n' >"$AUKORA_CADDYFILE.aukora.lock/holder"
    refused caddy:locked add
    unchanged
    sequence ''
    [[ -f $AUKORA_CADDYFILE.aukora.lock/holder ]] || fail "stole lock"
    rm -rf "$AUKORA_CADDYFILE.aukora.lock"
}
test_links() {
    reset_case
    mv "$AUKORA_CADDYFILE" "$TEST_ROOT/target"
    ln -s "$TEST_ROOT/target" "$AUKORA_CADDYFILE"
    refused caddy:file-invalid add
    cmp "$TEST_ROOT/target" "$TEST_ROOT/original" || fail "symlink target edited"
    rm "$AUKORA_CADDYFILE"
    mv "$TEST_ROOT/target" "$AUKORA_CADDYFILE"
    ln "$AUKORA_CADDYFILE" "$TEST_ROOT/link"
    refused caddy:file-invalid add
    unchanged
    rm "$TEST_ROOT/link"
    mkdir "$TEST_ROOT/real"
    ln -s "$TEST_ROOT/real" "$TEST_ROOT/alias"
    cp "$AUKORA_CADDYFILE" "$TEST_ROOT/real/Caddyfile"
    AUKORA_CADDYFILE="$TEST_ROOT/alias/Caddyfile" refused caddy:file-symlink add
    cmp "$TEST_ROOT/real/Caddyfile" "$TEST_ROOT/original" || fail "symlink parent edited"
    sequence ''
}
test_validation() {
    reset_case
    for name in a Alpha ../alpha alpha_bad 'alpha;touch bad' abcdefghijklmnopqrstuv; do
        refused caddy:invalid-name bash "$SUT" add "$name" chat.valid.invalid owner.valid.invalid 127.0.0.1:28080
    done
    for host in 'evil.invalid { abort }' '*.invalid' Upper.invalid 'foo..invalid'; do
        refused caddy:invalid-host bash "$SUT" add alpha "$host" owner.valid.invalid 127.0.0.1:28080
    done
    refused caddy:same-host bash "$SUT" add alpha same.valid.invalid same.valid.invalid 127.0.0.1:28080
    for upstream in 0.0.0.0:28080 127.0.0.1:80 127.0.0.1:65536 '127.0.0.1:28080 { abort }'; do
        refused caddy:invalid-upstream bash "$SUT" add alpha chat.valid.invalid owner.valid.invalid "$upstream"
    done
    unchanged
    sequence ''
}
test_mismatch() {
    reset_case
    add
    cp -p "$AUKORA_CADDYFILE" "$TEST_ROOT/original"
    : >"$CADDY_TEST_LOG"
    refused caddy:block-mismatch bash "$SUT" add alpha chat-alpha-203-0-113-7.sslip.io owner-alpha-203-0-113-7.sslip.io 127.0.0.1:28081
    unchanged
    sequence ''
}
test_markers() {
    reset_case
    printf '\n# BEGIN AUKORA SOVEREIGN alpha\n# BEGIN AUKORA SOVEREIGN beta\n# END AUKORA SOVEREIGN beta\n# END AUKORA SOVEREIGN alpha\n' >>"$AUKORA_CADDYFILE"
    cp -p "$AUKORA_CADDYFILE" "$TEST_ROOT/original"
    refused caddy:markers-invalid bash "$SUT" remove alpha
    unchanged
    reset_case
    printf '\n# BEGIN AUKORA SOVEREIGN alpha\n' >>"$AUKORA_CADDYFILE"
    cp -p "$AUKORA_CADDYFILE" "$TEST_ROOT/original"
    refused caddy:markers-invalid bash "$SUT" remove alpha
    unchanged
    sequence ''
}

if [[ ${1:-} == --case ]]; then
    "test_$2"
    exit 0
fi
for test in render proxy_contract add_remove validate_rollback reload_rollback rollback_refusal signal interference lock links validation mismatch markers; do
    "test_$test"
    printf 'PASS caddy: %s\n' "$test"
done

python3 - "$SUT" "$TEST_ROOT/mutations" <<'PY'
import pathlib, sys
source = pathlib.Path(sys.argv[1]).read_text()
root = pathlib.Path(sys.argv[2])
root.mkdir()
mutations = [
    ("name", "validation", '[[ ${1:-} =~ ^[a-z][a-z0-9-]{1,20}$ ]]', '[[ 1 == 1 ]]'),
    ("host", "validation", '[[ ${#host} -le 253 && $host =~ ^$label(\\.$label)+$ && ${host##*.} =~ [a-z] ]]', '[[ 1 == 1 ]]'),
    ("same-host", "validation", '[[ $chat != "$owner" ]]', '[[ 1 == 1 ]]'),
    ("loopback", "validation", '^127\\.0\\.0\\.1:', '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+:'),
    ("port", "validation", '[[ $port -ge 1024 && $port -le 65535 ]]', '[[ 1 == 1 ]]'),
    ("headers", "render", 'header Strict-Transport-Security', 'header Disabled-Transport-Security'),
    ("nosniff", "render", 'header X-Content-Type-Options "nosniff"', 'header X-Content-Type-Options "disabled"'),
    ("referrer", "render", 'header Referrer-Policy "no-referrer"', 'header Referrer-Policy "unsafe-url"'),
    ("body-limit", "render", 'max_size 8MB', 'max_size 80MB'),
    ("frame-denial", "render", 'header X-Frame-Options "DENY"', 'header X-Frame-Options "SAMEORIGIN"'),
    ("token-404", "render", 'respond 404', 'respond 200'),
    ("forwarded", "render", 'header_up -Forwarded', 'header_up Forwarded {http.request.header.Forwarded}'),
    ("forwarded-wildcard", "render", 'header_up -Forwarded', 'header_up -X-Forwarded-*\n\t\t\theader_up -Forwarded'),
    ("proxy-host", "proxy_contract", 'header_up Host {host}', 'header_up Host {http.request.host}'),
    ("proxy-forwarded-host", "proxy_contract", 'header_up X-Forwarded-Host {host}', 'header_up X-Forwarded-Host {http.request.host}'),
    ("proxy-forwarded-proto", "proxy_contract", 'header_up X-Forwarded-Proto https', 'header_up X-Forwarded-Proto http'),
    ("proxy-forwarded-for", "proxy_contract", 'header_up X-Forwarded-For {remote_host}', 'header_up X-Forwarded-For {http.request.remote.host}'),
    ("redirect-query", "render", '$host{path} permanent', '$host{uri} permanent'),
    ("hardlink", "links", ' or info.st_nlink != 1', ''),
    ("symlink", "links", 'getattr(os, "O_NOFOLLOW", 0)', '0'),
    ("ancestor-link", "links", 'if stat.S_ISLNK(os.lstat(parent).st_mode):', 'if False:'),
    ("mode", "validate_rollback", 'os.fchmod(stream.fileno(), stat.S_IMODE(info.st_mode))', 'pass'),
    ("mismatch", "mismatch", 'if current[start:stop] != block:', 'if False:'),
    ("lock", "lock", 'if ! mkdir "$lock" 2>/dev/null; then', 'if false; then'),
    ("validate", "validate_rollback", 'if ! caddy validate --config "$file" --adapter caddyfile >/dev/null 2>&1; then', 'if false; then'),
    ("rollback", "validate_rollback", 'replace(original, saved)', 'pass'),
    ("rollback-validate", "rollback_refusal", 'elif caddy validate --config "$file" --adapter caddyfile >/dev/null 2>&1; then', 'elif true; then'),
    ("termination-cleanup", "signal", 'trap cleanup EXIT', 'trap - EXIT'),
    ("concurrent-bytes", "interference", 'if current != original or stat.S_IMODE(info.st_mode) != stat.S_IMODE(saved.st_mode):', 'if False:'),
    ("concurrent-mode", "interference", ' or stat.S_IMODE(info.st_mode) != stat.S_IMODE(saved.st_mode)', ''),
    ("rollback-concurrency", "interference", 'if current not in (candidate, original):', 'if False:'),
    ("nested-marker", "markers", 'or any(line.startswith((b"# BEGIN AUKORA SOVEREIGN ", b"# END AUKORA SOVEREIGN "))', 'or any(False'),
]
for name, case, before, after in mutations:
    assert before in source, name
    (root / (name + ".sh")).write_text(source.replace(before, after, 1))
    with (root / "cases").open("a") as cases:
        cases.write(name + " " + case + "\n")
PY
mutation_count=0
while read -r mutation case_name; do
    if CADDY_TEST_SUT="$TEST_ROOT/mutations/$mutation.sh" bash "$HERE/caddy-test.sh" --case "$case_name" >"$TEST_ROOT/mutation-result" 2>&1; then
        fail "mutation survived: $mutation"
    fi
    mutation_count=$((mutation_count + 1))
done <"$TEST_ROOT/mutations/cases"
printf 'PASS caddy: %s mutation kills\n' "$mutation_count"
