#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd -P)
self="$here/bundle-test.sh"
bundle=${BUNDLE_SCRIPT:-$here/bundle.sh}
case_name=${1:-all}
work=$(mktemp -d "$here/.bundle-test.XXXXXX")
trap 'rm -rf "$work"' EXIT
real_python=$(command -v python3)
node="$work/node"
harness="$work/harness"
guest="$work/guest"
bridge="$work/bridge"
output="$work/runtime.tar.gz"
mkdir -p "$node/bin" "$harness/apps/cli/lib" "$guest" "$bridge"
printf '#!/bin/sh\nexit 0\n' > "$node/bin/node"
chmod 0755 "$node/bin/node"
printf 'harness fixture\n' > "$harness/apps/cli/lib/bin.js"
printf 'guest fixture\n' > "$guest/preload.mjs"
printf 'bridge fixture\n' > "$bridge/canon.mjs"
python3 "$here/vectors/probe-elf.py" "$guest/probe"

fail() { printf 'FAIL bundle:%s\n' "$1" >&2; exit 1; }
build() {
    bash "$bundle" --node "$node" --harness "$harness" --guest "$guest" --bridge "$bridge" --output "$output" "$@"
}
refused() {
    code=$1
    shift
    printf 'previous artifact\n' > "$output"
    if build "$@" > "$work/stdout" 2> "$work/stderr"; then fail "$code accepted"; fi
    [ "$(cat "$work/stderr")" = "$code" ] || fail "$code refusal: $(cat "$work/stderr")"
    [ ! -s "$work/stdout" ] || fail "$code stdout"
    [ "$(cat "$output")" = 'previous artifact' ] || fail "$code replaced-output"
    [ -z "$(find "$work" -maxdepth 1 -name '.aukora-bundle-*' -print)" ] || fail "$code temporary-output"
}
selected() { [ "$case_name" = all ] || [ "$case_name" = "$1" ]; }
passed=0
ok() { passed=$((passed + 1)); printf 'ok bundle:%s\n' "$1"; }

if selected deterministic; then
    mkdir "$harness/package"
    printf 'package fixture\n' > "$harness/package/a file.js"
    ln -s package "$harness/package-link"
    first=$(build)
    cp "$output" "$work/first.tar.gz"
    touch "$node/bin/node" "$harness/package/a file.js"
    second=$(build)
    [ "$first" = "$second" ] || fail deterministic-digest
    cmp "$output" "$work/first.tar.gz" || fail deterministic-tarball
    python3 - "$output" "$first" <<'PY'
import hashlib
import json
import sys
import tarfile

with tarfile.open(sys.argv[1], "r:gz") as archive:
    manifest = archive.extractfile("MANIFEST").read()
    digest = hashlib.sha256(manifest).hexdigest()
    assert digest == sys.argv[2]
    assert archive.extractfile("MANIFEST.sha256").read() == (digest + "  MANIFEST\n").encode()
    records = [json.loads(line) for line in manifest.splitlines()]
    assert [row["path"] for row in records] == sorted(row["path"] for row in records)
    assert {row["path"] for row in records} == set(archive.getnames()) - {"MANIFEST", "MANIFEST.sha256"}
    for row in records:
        member = archive.getmember(row["path"])
        assert row["mode"] == format(member.mode, "04o")
        assert (member.uid, member.gid, member.mtime, member.uname, member.gname) == (0, 0, 0, "", "")
        if member.isfile():
            assert row["type"] == "file"
            data = archive.extractfile(member).read()
        elif member.issym():
            assert row["type"] == "symlink"
            data = member.linkname.encode()
        else:
            assert member.isdir() and row["type"] == "directory"
            data = b""
        assert row["sha256"] == hashlib.sha256(data).hexdigest()
    assert archive.getmember("harness/package-link").linkname == "package"
    assert archive.getmember("node/bin/node").mode == 0o755
    assert archive.extractfile("sovereign/guest/preload.mjs").read() == b"guest fixture\n"
    assert archive.extractfile("sovereign/bridge/canon.mjs").read() == b"bridge fixture\n"
    assert archive.extractfile("sovereign/guest/probe").read().startswith(b"\x7fELF")
PY
    ok deterministic
fi

if selected antibody-probe-static; then
    for kind in interp needed auxiliary filter unterminated; do
        python3 "$here/vectors/probe-elf.py" "$guest/probe" "$kind"
        refused bundle:probe-static-required
    done
    printf 'not an ELF\n' > "$guest/probe"
    refused bundle:probe-static-required
    python3 "$here/vectors/probe-elf.py" "$guest/probe"
    chmod 0644 "$guest/probe"
    refused bundle:probe-file-required
    chmod 0755 "$guest/probe"
    ln -s "$guest/probe" "$work/probe-link"
    refused bundle:probe-file-required --probe "$work/probe-link"
    python3 "$here/vectors/probe-elf.py" "$guest/probe" static-pie
    build > "$work/release"
    ok antibody-probe-static
fi

if selected antibody-probe-digest; then
    python3 "$here/vectors/probe-elf.py" "$work/probe"
    first=$(build --probe "$work/probe")
    python3 - "$output" "$work/probe" <<'PY'
import hashlib
import json
import pathlib
import sys
import tarfile

probe = pathlib.Path(sys.argv[2]).read_bytes()
with tarfile.open(sys.argv[1], "r:gz") as archive:
    assert archive.extractfile("sovereign/guest/probe").read() == probe
    rows = [json.loads(line) for line in archive.extractfile("MANIFEST").read().splitlines()]
    row = next(row for row in rows if row["path"] == "sovereign/guest/probe")
    assert row == {"path": "sovereign/guest/probe", "mode": "0755", "type": "file",
                   "sha256": hashlib.sha256(probe).hexdigest()}
PY
    printf 'approved probe bytes differ\n' >> "$work/probe"
    second=$(build --probe "$work/probe")
    [ "$first" != "$second" ] || fail probe-digest-unchanged
    ok antibody-probe-digest
fi

if selected input-paths; then
    refused bundle:absolute-path-required --node relative
    refused bundle:source-directory-required --node "$work/missing"
    refused bundle:source-directory-required --node "$node/bin/node"
    refused bundle:output-parent-required --output "$work/missing/output.tar.gz"
    refused bundle:unknown-argument --typo
    refused bundle:argument-value-required --guest
    if bash "$bundle" > "$work/stdout" 2> "$work/stderr"; then fail inputs-required; fi
    [ "$(cat "$work/stderr")" = bundle:inputs-required ] || fail inputs-required-code
    ok input-paths
fi

if selected output-containment; then
    refused bundle:output-inside-source --output "$harness/output.tar.gz"
    ln -s "$harness" "$work/alias"
    refused bundle:output-inside-source --output "$work/alias/output.tar.gz"
    ok output-containment
fi

if selected output-symlink; then
    printf 'protected target\n' > "$work/protected"
    ln -s "$work/protected" "$work/output-link"
    refused bundle:output-symlink --output "$work/output-link"
    [ "$(cat "$work/protected")" = 'protected target' ] || fail output-link-target-changed
    [ -L "$work/output-link" ] || fail output-link-replaced
    ok output-symlink
fi

if selected link-safety; then
    ln -s /etc/passwd "$harness/link"
    refused bundle:absolute-link
    rm "$harness/link"
    ln -s ../node/bin/node "$harness/link"
    refused bundle:escaping-link
    rm "$harness/link"
    ln -s does-not-exist "$harness/link"
    refused bundle:dangling-link
    rm "$harness/link"
    ln -s link "$harness/link"
    refused bundle:link-loop
    rm "$harness/link"
    mkdir "$harness/inner"
    ln -s ../../node "$harness/inner/link"
    ln -s inner/link/bin/node "$harness/link"
    refused bundle:escaping-link
    rm "$harness/link" "$harness/inner/link"
    ok link-safety
fi

if selected special-entry; then
    mkfifo "$harness/fifo"
    refused bundle:special-entry
    rm "$harness/fifo"
    ok special-entry
fi

if selected changed-source; then
    mkdir "$work/shim"
    cat > "$work/shim/python3" <<'SH'
#!/bin/bash
set -euo pipefail
exec "$BUNDLE_REAL_PYTHON" "$BUNDLE_DRIVER" "$@"
SH
    cat > "$work/python-driver.py" <<'PY'
import os
import sys

source = sys.stdin.read()
sys.argv = sys.argv[1:]
original_fdopen = os.fdopen

def changed_fdopen(fd, *args, **kwargs):
    if os.fstat(fd).st_ino == os.stat(os.environ["BUNDLE_WATCH"]).st_ino:
        with open(os.environ["BUNDLE_WATCH"], "ab") as target:
            target.write(b"changed during build\n")
    return original_fdopen(fd, *args, **kwargs)

os.fdopen = changed_fdopen
exec(compile(source, "<bundle-test>", "exec"))
PY
    chmod +x "$work/shim/python3"
    export BUNDLE_REAL_PYTHON="$real_python" BUNDLE_DRIVER="$work/python-driver.py" BUNDLE_WATCH="$node/bin/node"
    PATH="$work/shim:$PATH" refused bundle:source-changed
    ok changed-source
fi

if selected privileged-mode; then
    mkdir "$work/mode-shim"
    cat > "$work/mode-shim/python3" <<'SH'
#!/bin/bash
set -euo pipefail
exec "$BUNDLE_REAL_PYTHON" "$BUNDLE_DRIVER" "$@"
SH
    cat > "$work/mode-driver.py" <<'PY'
import os
import pathlib
import sys

source = sys.stdin.read()
sys.argv = sys.argv[1:]
original_stat, original_fstat = os.stat, os.fstat
watched = original_stat(os.environ["BUNDLE_WATCH"])

def mode(info):
    if (info.st_dev, info.st_ino) == (watched.st_dev, watched.st_ino):
        values = list(info)
        values[0] |= int(os.environ["BUNDLE_MODE_BITS"], 8)
        return os.stat_result(values)
    return info

os.stat = lambda *args, **kwargs: mode(original_stat(*args, **kwargs))
os.fstat = lambda *args, **kwargs: mode(original_fstat(*args, **kwargs))
exec(compile(source, "<bundle-test>", "exec"))
PY
    chmod +x "$work/mode-shim/python3"
    export BUNDLE_REAL_PYTHON="$real_python" BUNDLE_DRIVER="$work/mode-driver.py" BUNDLE_WATCH="$node/bin/node" BUNDLE_MODE_BITS=4000
    PATH="$work/mode-shim:$PATH" refused bundle:privileged-mode
    export BUNDLE_WATCH="$harness" BUNDLE_MODE_BITS=2000
    PATH="$work/mode-shim:$PATH" refused bundle:privileged-mode
    ok privileged-mode
fi

if [ "$case_name" = all ]; then
    python3 - "$bundle" "$work" > "$work/mutations" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text()
mutations = [
    ("absolute-path", "input-paths", "if any(not Path(value).is_absolute() for value in values):", "if False:"),
    ("output-containment", "output-containment", "if any(output.is_relative_to(root) for _, root in roots):", "if False:"),
    ("output-symlink", "output-symlink", "if output.is_symlink():", "if False:"),
    ("absolute-link", "link-safety", 'refuse("absolute-link")', "return"),
    ("escaping-link", "link-safety", 'refuse("escaping-link")', "return"),
    ("dangling-link", "link-safety", 'refuse("dangling-link")', "return"),
    ("link-loop", "link-safety", 'refuse("link-loop")', "return"),
    ("special-entry", "special-entry", 'refuse("special-entry")', "continue"),
    ("source-changed", "changed-source", "if identity(os.fstat(source.fileno())) != identity(original):", "if False:"),
    ("privileged-mode", "privileged-mode", "if mode & 0o6000:", "if False:"),
    ("probe-static", "antibody-probe-static", 'validate_probe(source, original.st_size)', 'pass'),
    ("probe-interp", "antibody-probe-static", 'or tag == 3:', ':'),
    ("probe-needed", "antibody-probe-static", 'if dynamic_tag in (1, 0x7fffffff, 0x7ffffffd):', 'if False:'),
    ("probe-executable", "antibody-probe-static", 'or not probe_mode & 0o111:', ':'),
    ("probe-staged", "antibody-probe-digest", 'entries["sovereign/guest/probe"] = ("file", probe_mode, None, probe_fd, [probe.name], probe_info)', 'pass'),
]
for name, case, before, after in mutations:
    assert before in source, name
    path = pathlib.Path(sys.argv[2]) / (name + ".sh")
    path.write_text(source.replace(before, after))
    print(name + " " + case)
PY
    killed=0
    while read -r mutation check; do
        if BUNDLE_SCRIPT="$work/$mutation.sh" bash "$self" "$check" > "$work/mutant-output" 2>&1; then
            fail "mutation-survived-$mutation"
        fi
        killed=$((killed + 1))
        printf 'killed bundle:%s\n' "$mutation"
    done < "$work/mutations"
    printf 'bundle mutation result: %s killed, 0 survived\n' "$killed"
fi
printf 'bundle test result: %s passed, 0 failed\n' "$passed"
