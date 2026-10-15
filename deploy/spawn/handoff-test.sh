#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
set +x

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
SUT=${HANDOFF_TEST_SUT:-$HERE/bootstrap.sh}
TEST_ROOT=$(mktemp -d "$HERE/.handoff-test.XXXXXX")
trap 'rm -rf "$TEST_ROOT"' EXIT
chmod 0700 "$TEST_ROOT"
mkdir "$TEST_ROOT/bin"
REAL_PYTHON=${HANDOFF_TEST_REAL_PYTHON:-$(command -v python3)}
export HANDOFF_TEST_REAL_PYTHON="$REAL_PYTHON" HANDOFF_TEST_FIXTURE="$TEST_ROOT"
export HANDOFF_TEST_LOG="$TEST_ROOT/commands"
export HANDOFF_TEST_SECRET='https://owner-fixture-203-0-113-7.sslip.io/#claim=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

# Execute the actual embedded Python against real files. Map only this fixture's
# current owner to root; negative cases inject a foreign owner without chown.
cat >"$TEST_ROOT/uid-wrapper.py" <<'PY'
import json, os, pathlib, sys

args = sys.argv[1:]
with open(os.environ['HANDOFF_TEST_LOG'], 'a') as log:
    log.write(json.dumps(args) + '\n')
if args[0] == '-c':
    program = args[1]
    sys.argv = ['-c', *args[2:]]
elif args[0] == '-':
    program = sys.stdin.read()
    sys.argv = ['-', *args[1:]]
else:
    raise SystemExit('unexpected fixture Python invocation')

fixture = pathlib.Path(os.environ['HANDOFF_TEST_FIXTURE'])
fixture_uid = os.getuid()
original_lstat, original_fstat = os.lstat, os.fstat

def mapped(info, foreign=False):
    fields = list(info)
    if info.st_uid == fixture_uid:
        fields[4] = 0
    if foreign:
        fields[4] = 12345
    return os.stat_result(fields)

def lstat(path, *args, **kwargs):
    info = original_lstat(path, *args, **kwargs)
    path = pathlib.Path(path)
    if path == fixture or fixture in path.parents:
        foreign = (os.environ.get('HANDOFF_TEST_DIRECTORY_UID') == 'foreign'
                   and str(path) == os.environ['HANDOFF_TEST_DIRECTORY'])
        return mapped(info, foreign)
    return info

def fstat(fd):
    return mapped(original_fstat(fd), os.environ.get('HANDOFF_TEST_FILE_UID') == 'foreign')

os.lstat, os.fstat = lstat, fstat
exec(compile(program, '<handoff>', 'exec'))
PY
cat >"$TEST_ROOT/bin/python3" <<'MOCK'
#!/bin/bash
set -euo pipefail
exec "$HANDOFF_TEST_REAL_PYTHON" "$HANDOFF_TEST_FIXTURE/uid-wrapper.py" "$@"
MOCK
chmod +x "$TEST_ROOT/bin/python3"
export PATH="$TEST_ROOT/bin:$PATH"

fail() { printf 'FAIL handoff: %s\n' "$*" >&2; exit 1; }
reset_case() {
    rm -rf "$TEST_ROOT/case"
    mkdir -m 0700 "$TEST_ROOT/case"
    export HANDOFF_TEST_DIRECTORY="$TEST_ROOT/case/private"
    export HANDOFF_TEST_DIRECTORY_UID='' HANDOFF_TEST_FILE_UID='' HANDOFF_TEST_ROOT=0
    HANDOFF_PATH="$HANDOFF_TEST_DIRECTORY/claim-link"
    : >"$TEST_ROOT/stdout"
    : >"$TEST_ROOT/stderr"
    : >"$HANDOFF_TEST_LOG"
}
call() {
    (
        source "$SUT"
        require_root() {
            [[ $HANDOFF_TEST_ROOT == 0 ]] || bootstrap_refuse 'spawn:root-required'
        }
        claim_link=$HANDOFF_TEST_SECRET
        "$@"
    ) >"$TEST_ROOT/stdout" 2>"$TEST_ROOT/stderr"
}
refused() {
    local code=$1
    shift
    if call "$@"; then fail "expected $code"; fi
    [[ ! -s $TEST_ROOT/stdout ]] || fail 'refusal emitted stdout'
    [[ $(cat "$TEST_ROOT/stderr") == "$code" ]] || fail 'refusal emitted private diagnostics'
    if grep -qF -- "$HANDOFF_TEST_SECRET" "$HANDOFF_TEST_LOG" "$TEST_ROOT/stderr"; then
        fail 'claim entered command log or stderr'
    fi
}
private_file() {
    "$REAL_PYTHON" - "$HANDOFF_PATH" <<'PY'
import os, pathlib, stat, sys
path = pathlib.Path(sys.argv[1])
assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
assert stat.S_IMODE(path.stat().st_mode) == 0o600
assert path.stat().st_uid == os.getuid()
assert path.read_text() == os.environ['HANDOFF_TEST_SECRET'] + '\n'
PY
}
put_claim() {
    mkdir -m 0700 "$HANDOFF_TEST_DIRECTORY"
    printf '%s\n' "$HANDOFF_TEST_SECRET" >"$HANDOFF_PATH"
    chmod 0600 "$HANDOFF_PATH"
}

test_roundtrip() {
    reset_case
    call write_claim_handoff "$HANDOFF_PATH"
    [[ ! -s $TEST_ROOT/stdout && ! -s $TEST_ROOT/stderr ]] || fail 'producer emitted output'
    private_file
    "$REAL_PYTHON" - "$TEST_ROOT" "$HANDOFF_PATH" <<'PY'
import os, pathlib, sys
root, handoff = map(pathlib.Path, sys.argv[1:])
secret = os.environ['HANDOFF_TEST_SECRET'].encode()
for path in root.rglob('*'):
    if path.is_file() and secret in path.read_bytes():
        assert path == handoff, 'claim leaked to ' + str(path)
PY
    call consume_claim_handoff "$HANDOFF_PATH"
    [[ $(cat "$TEST_ROOT/stdout") == "$HANDOFF_TEST_SECRET" ]] || fail 'claim not consumed intact'
    [[ ! -s $TEST_ROOT/stderr ]] || fail 'consumer emitted diagnostics'
    [[ ! -e $HANDOFF_PATH ]] || fail 'consumer retained claim file'
    ! grep -qF -- "$HANDOFF_TEST_SECRET" "$HANDOFF_TEST_LOG" || fail 'claim entered command log'
    refused spawn:claim-handoff consume_claim_handoff "$HANDOFF_PATH"
}
test_producer_root() {
    reset_case
    HANDOFF_TEST_ROOT=501
    refused spawn:root-required write_claim_handoff "$HANDOFF_PATH"
    [[ ! -e $HANDOFF_PATH && ! -s $HANDOFF_TEST_LOG ]] || fail 'producer ran without root'
}
test_consumer_root() {
    reset_case
    put_claim
    HANDOFF_TEST_ROOT=501
    refused spawn:root-required consume_claim_handoff "$HANDOFF_PATH"
    private_file
    [[ ! -s $HANDOFF_TEST_LOG ]] || fail 'consumer ran without root'
}
test_producer_exclusive() {
    reset_case
    put_claim
    printf 'existing bytes\n' >"$HANDOFF_PATH"
    refused spawn:claim-handoff write_claim_handoff "$HANDOFF_PATH"
    [[ $(cat "$HANDOFF_PATH") == 'existing bytes' ]] || fail 'existing handoff overwritten'
}
test_producer_links() {
    reset_case
    mkdir -m 0700 "$HANDOFF_TEST_DIRECTORY"
    printf 'existing bytes\n' >"$TEST_ROOT/case/target"
    ln -s "$TEST_ROOT/case/target" "$HANDOFF_PATH"
    refused spawn:claim-handoff write_claim_handoff "$HANDOFF_PATH"
    [[ $(cat "$TEST_ROOT/case/target") == 'existing bytes' ]] || fail 'symlink target overwritten'
}
test_producer_parent() {
    reset_case
    mkdir -m 0700 "$TEST_ROOT/case/real"
    ln -s "$TEST_ROOT/case/real" "$HANDOFF_TEST_DIRECTORY"
    refused spawn:claim-handoff write_claim_handoff "$HANDOFF_PATH"
    [[ ! -e $TEST_ROOT/case/real/claim-link ]] || fail 'producer traversed symlink parent'
    rm "$HANDOFF_TEST_DIRECTORY"
    ln -s "$TEST_ROOT/case/real" "$TEST_ROOT/case/alias"
    HANDOFF_TEST_DIRECTORY="$TEST_ROOT/case/alias/private"
    HANDOFF_PATH="$HANDOFF_TEST_DIRECTORY/claim-link"
    refused spawn:claim-handoff write_claim_handoff "$HANDOFF_PATH"
    [[ ! -e $HANDOFF_PATH ]] || fail 'producer traversed symlink ancestor'
}
test_producer_directory() {
    reset_case
    mkdir -m 0755 "$HANDOFF_TEST_DIRECTORY"
    refused spawn:claim-handoff write_claim_handoff "$HANDOFF_PATH"
    [[ ! -e $HANDOFF_PATH ]] || fail 'producer accepted public directory'
    chmod 0700 "$HANDOFF_TEST_DIRECTORY"
    HANDOFF_TEST_DIRECTORY_UID=foreign
    refused spawn:claim-handoff write_claim_handoff "$HANDOFF_PATH"
    [[ ! -e $HANDOFF_PATH ]] || fail 'producer accepted foreign directory'
}
test_consumer_parent() {
    reset_case
    put_claim
    mv "$HANDOFF_TEST_DIRECTORY" "$TEST_ROOT/case/real"
    ln -s "$TEST_ROOT/case/real" "$HANDOFF_TEST_DIRECTORY"
    refused spawn:claim-handoff consume_claim_handoff "$HANDOFF_PATH"
    private_file
    rm "$HANDOFF_TEST_DIRECTORY"
    mkdir -m 0700 "$TEST_ROOT/case/real/nested"
    mv "$TEST_ROOT/case/real/claim-link" "$TEST_ROOT/case/real/nested/claim-link"
    ln -s "$TEST_ROOT/case/real" "$TEST_ROOT/case/alias"
    HANDOFF_TEST_DIRECTORY="$TEST_ROOT/case/alias/nested"
    HANDOFF_PATH="$HANDOFF_TEST_DIRECTORY/claim-link"
    refused spawn:claim-handoff consume_claim_handoff "$HANDOFF_PATH"
    private_file
}
test_consumer_directory() {
    reset_case
    put_claim
    chmod 0755 "$HANDOFF_TEST_DIRECTORY"
    refused spawn:claim-handoff consume_claim_handoff "$HANDOFF_PATH"
    [[ -f $HANDOFF_PATH ]] || fail 'consumer deleted public handoff'
    chmod 0700 "$HANDOFF_TEST_DIRECTORY"
    HANDOFF_TEST_DIRECTORY_UID=foreign
    refused spawn:claim-handoff consume_claim_handoff "$HANDOFF_PATH"
    private_file
}
test_consumer_links() {
    reset_case
    put_claim
    mv "$HANDOFF_PATH" "$TEST_ROOT/case/target"
    ln -s "$TEST_ROOT/case/target" "$HANDOFF_PATH"
    refused spawn:claim-handoff consume_claim_handoff "$HANDOFF_PATH"
    [[ -f $TEST_ROOT/case/target && -L $HANDOFF_PATH ]] || fail 'consumer followed symlink'
    rm "$HANDOFF_PATH"
    mv "$TEST_ROOT/case/target" "$HANDOFF_PATH"
    ln "$HANDOFF_PATH" "$TEST_ROOT/case/hardlink"
    refused spawn:claim-handoff consume_claim_handoff "$HANDOFF_PATH"
    private_file
}
test_consumer_file() {
    reset_case
    put_claim
    chmod 0640 "$HANDOFF_PATH"
    refused spawn:claim-handoff consume_claim_handoff "$HANDOFF_PATH"
    [[ -f $HANDOFF_PATH ]] || fail 'consumer deleted public file'
    chmod 0600 "$HANDOFF_PATH"
    HANDOFF_TEST_FILE_UID=foreign
    refused spawn:claim-handoff consume_claim_handoff "$HANDOFF_PATH"
    private_file
}
test_consumer_type() {
    reset_case
    mkdir -m 0700 "$HANDOFF_TEST_DIRECTORY"
    mkfifo -m 0600 "$HANDOFF_PATH"
    printf '%s\n' "$HANDOFF_TEST_SECRET" >"$HANDOFF_PATH" 2>/dev/null &
    local writer=$!
    refused spawn:claim-handoff consume_claim_handoff "$HANDOFF_PATH"
    wait "$writer" || :
    [[ -p $HANDOFF_PATH ]] || fail 'consumer accepted FIFO'
}
test_consumer_size() {
    reset_case
    put_claim
    : >"$HANDOFF_PATH"
    refused spawn:claim-handoff consume_claim_handoff "$HANDOFF_PATH"
    [[ -f $HANDOFF_PATH ]] || fail 'consumer deleted empty file'
    "$REAL_PYTHON" - "$HANDOFF_PATH" <<'PY'
import pathlib, sys
pathlib.Path(sys.argv[1]).write_bytes(b'A' * 4096)
PY
    refused spawn:claim-handoff consume_claim_handoff "$HANDOFF_PATH"
    [[ -f $HANDOFF_PATH ]] || fail 'consumer deleted oversized file'
}

if [[ ${1:-} == --case ]]; then
    "test_$2"
    exit 0
fi
for test in roundtrip producer_root consumer_root producer_exclusive producer_links producer_parent producer_directory consumer_parent consumer_directory consumer_links consumer_file consumer_type consumer_size; do
    "test_$test"
    printf 'PASS handoff: %s\n' "$test"
done

"$REAL_PYTHON" - "$SUT" "$TEST_ROOT/mutations" <<'PY'
import pathlib, sys
source = pathlib.Path(sys.argv[1]).read_text()
root = pathlib.Path(sys.argv[2])
root.mkdir()
mutations = [
    ('producer-root', 'producer_root', 'write_claim_handoff', 'require_root || return 1', ':'),
    ('consumer-root', 'consumer_root', 'consume_claim_handoff', 'require_root || return 1', ':'),
    ('producer-exclusive', 'producer_exclusive', 'write_claim_handoff', 'os.O_EXCL', '0'),
    ('producer-symlink-open', 'producer_links', 'write_claim_handoff', 'os.O_EXCL | os.O_NOFOLLOW', '0'),
    ('producer-parent-link', 'producer_parent', 'write_claim_handoff', 'if stat.S_ISLNK(os.lstat(parent).st_mode): refuse()', 'if False: refuse()'),
    ('consumer-parent-link', 'consumer_parent', 'consume_claim_handoff', 'if stat.S_ISLNK(os.lstat(parent).st_mode): refuse()', 'if False: refuse()'),
    ('producer-directory-uid', 'producer_directory', 'write_claim_handoff', 'info.st_uid != 0 or ', ''),
    ('producer-directory-mode', 'producer_directory', 'write_claim_handoff', 'stat.S_IMODE(info.st_mode) != 0o700', 'False'),
    ('consumer-directory-uid', 'consumer_directory', 'consume_claim_handoff', 'directory.st_uid != 0 or ', ''),
    ('consumer-directory-mode', 'consumer_directory', 'consume_claim_handoff', 'stat.S_IMODE(directory.st_mode) != 0o700', 'False'),
    ('producer-file-mode', 'roundtrip', 'write_claim_handoff', 'os.O_NOFOLLOW, 0o600', 'os.O_NOFOLLOW, 0o644'),
    ('producer-new-directory-mode', 'roundtrip', 'write_claim_handoff', 'mkdir(mode=0o700', 'mkdir(mode=0o755'),
    ('consumer-no-follow', 'consumer_links', 'consume_claim_handoff', 'os.O_NOFOLLOW', '0'),
    ('consumer-file-links', 'consumer_links', 'consume_claim_handoff', ' or info.st_nlink != 1', ''),
    ('consumer-file-uid', 'consumer_file', 'consume_claim_handoff', 'or info.st_uid != 0 ', ''),
    ('consumer-file-mode', 'consumer_file', 'consume_claim_handoff', 'stat.S_IMODE(info.st_mode) != 0o600', 'False'),
    ('consumer-file-type', 'consumer_type', 'consume_claim_handoff', 'not stat.S_ISREG(info.st_mode)', 'False'),
    ('consumer-file-empty', 'consumer_size', 'consume_claim_handoff', 'not link or ', ''),
    ('consumer-file-size', 'consumer_size', 'consume_claim_handoff', 'len(link) >= 4096', 'False'),
    ('consumer-delete', 'roundtrip', 'consume_claim_handoff', 'os.unlink(path)', 'pass'),
    ('producer-stdout-private', 'roundtrip', 'write_claim_handoff', 'target.flush()', 'print(os.environ["HANDOFF_TEST_SECRET"]); target.flush()'),
    ('producer-stderr-private', 'roundtrip', 'write_claim_handoff', 'target.flush()', 'print(os.environ["HANDOFF_TEST_SECRET"], file=sys.stderr); target.flush()'),
    ('consumer-stderr-private', 'roundtrip', 'consume_claim_handoff', 'sys.stdout.buffer.write(link)', 'sys.stderr.buffer.write(link); sys.stdout.buffer.write(link)'),
]
for name, case, function, before, after in mutations:
    start = source.index(function + '() {')
    end = source.index('\n}\n', start) + 3
    body = source[start:end]
    assert before in body, name
    changed = source[:start] + body.replace(before, after, 1) + source[end:]
    # Both explicit modes and the inherited restrictive umask enforce private
    # creation. Removing a mode alone cannot defeat the second protection.
    if name in ('producer-file-mode', 'producer-new-directory-mode'):
        assert 'umask 077' in changed, name
        changed = changed.replace('umask 077', 'umask 000', 1)
    (root / (name + '.sh')).write_text(changed)
    with (root / 'cases').open('a') as cases:
        cases.write(name + ' ' + case + '\n')
PY
mutation_count=0
while read -r mutation case_name; do
    if HANDOFF_TEST_SUT="$TEST_ROOT/mutations/$mutation.sh" bash "$HERE/handoff-test.sh" --case "$case_name" >"$TEST_ROOT/mutation-result" 2>&1; then
        fail "mutation survived: $mutation"
    fi
    mutation_count=$((mutation_count + 1))
done <"$TEST_ROOT/mutations/cases"
printf 'PASS handoff: %s mutation kills\n' "$mutation_count"
