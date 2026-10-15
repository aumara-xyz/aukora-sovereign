#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd -P)
self="$here/unpack-test.sh"
unpacker=${UNPACK_SCRIPT:-$here/unpack.sh}
case_name=${1:-all}
work=$(mktemp -d "$here/.unpack-test.XXXXXX")
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/node/bin" "$work/harness/package" "$work/guest" "$work/bridge"
printf 'node\n' > "$work/node/bin/node"
chmod 0755 "$work/node/bin/node"
printf 'harness\n' > "$work/harness/package/bin.js"
ln -s package "$work/harness/link"
printf 'guest\n' > "$work/guest/preload.mjs"
printf 'bridge\n' > "$work/bridge/canon.mjs"
python3 "$here/vectors/probe-elf.py" "$work/guest/probe"
archive="$work/runtime.tar.gz"
release=$(bash "$here/bundle.sh" --node "$work/node" --harness "$work/harness" --guest "$work/guest" \
    --bridge "$work/bridge" --output "$archive")
cp "$archive" "$work/original.tar.gz"
destination="$work/runtime"
fail() { printf 'FAIL unpack:%s\n' "$1" >&2; exit 1; }
selected() { [ "$case_name" = all ] || [ "$case_name" = "$1" ]; }
passed=0
ok() { passed=$((passed + 1)); printf 'ok unpack:%s\n' "$1"; }
run_unpack() { bash "$unpacker" "$archive" "$destination" "$release"; }
refused() {
    code=$1
    if run_unpack > "$work/stdout" 2> "$work/stderr"; then fail "$code accepted"; fi
    [ "$(cat "$work/stderr")" = "$code" ] || fail "$code refusal"
    [ ! -s "$work/stdout" ] || fail "$code stdout"
    [ -z "$(find "$work" -maxdepth 1 -name '.aukora-runtime-*' -print)" ] || fail "$code staging-leftover"
}
reset_archive() {
    cp "$work/original.tar.gz" "$archive"
    release=$(python3 - "$archive" <<'PY'
import hashlib
import sys
import tarfile
with tarfile.open(sys.argv[1]) as archive:
    print(hashlib.sha256(archive.extractfile("MANIFEST").read()).hexdigest())
PY
    )
}
tamper() {
    release=$(python3 - "$archive" "$1" <<'PY'
import hashlib
import io
import json
import sys
import tarfile

path, operation = sys.argv[1:]
with tarfile.open(path) as archive:
    members = [(member, archive.extractfile(member).read() if member.isfile() else b"") for member in archive]
manifest = next(data for member, data in members if member.name == "MANIFEST")
rows = [json.loads(line) for line in manifest.splitlines()]
changed = False
if operation == "content":
    members = [(member, b"altered\n" if member.name == "node/bin/node" else data) for member, data in members]
elif operation == "mode":
    next(member for member, _ in members if member.name == "node/bin/node").mode = 0o644
elif operation == "release-file":
    members = [(member, b"0" * 64 + b"  MANIFEST\n" if member.name == "MANIFEST.sha256" else data)
               for member, data in members]
elif operation == "duplicate":
    members.append(next((member, data) for member, data in members if member.name == "node/bin/node"))
elif operation == "extra":
    info = tarfile.TarInfo("node/extra")
    info.mode = 0o644
    members.append((info, b"extra\n"))
elif operation in ("path", "absolute-link", "escaping-link", "dangling-link", "link-loop", "special", "parent", "layout", "privileged-mode", "link-mode"):
    changed = True
    if operation in ("privileged-mode", "link-mode"):
        name = "node/bin/node" if operation == "privileged-mode" else "harness/link"
        mode = 0o4755 if operation == "privileged-mode" else 0o600
        next(member for member, _ in members if member.name == name).mode = mode
        next(row for row in rows if row["path"] == name)["mode"] = format(mode, "04o")
    elif operation == "layout":
        members = [(member, data) for member, data in members if not member.name.startswith("sovereign/bridge")]
        rows = [row for row in rows if not row["path"].startswith("sovereign/bridge")]
    elif operation == "parent":
        info = tarfile.TarInfo("harness/link/child")
        info.mode = 0o644
        members.append((info, b"child\n"))
        rows.append({"path": info.name, "mode": "0644", "type": "file", "sha256": hashlib.sha256(b"child\n").hexdigest()})
    else:
        info = tarfile.TarInfo("../escaped" if operation == "path" else "harness/hostile")
        info.mode = 0o777 if operation.endswith("link") or operation == "link-loop" else 0o644
        kind, data = "file", b"hostile\n"
        if operation == "special":
            info.type, kind, data = tarfile.FIFOTYPE, "fifo", b""
        elif operation != "path":
            info.type, kind = tarfile.SYMTYPE, "symlink"
            info.linkname = {"absolute-link": "/etc/passwd", "escaping-link": "../node/bin/node",
                             "dangling-link": "not-present", "link-loop": "hostile"}[operation]
            data = info.linkname.encode()
        members.append((info, data if kind == "file" else b""))
        rows.append({"path": info.name, "mode": format(info.mode, "04o"), "type": kind,
                     "sha256": hashlib.sha256(data).hexdigest()})
else:
    raise AssertionError(operation)
if changed:
    manifest = "".join(json.dumps(row, separators=(",", ":")) + "\n"
                       for row in sorted(rows, key=lambda row: row["path"])).encode()
release = hashlib.sha256(manifest).hexdigest()
if changed:
    members = [(member, manifest if member.name == "MANIFEST" else
                (release + "  MANIFEST\n").encode() if member.name == "MANIFEST.sha256" else data)
               for member, data in members]
with tarfile.open(path, "w:gz") as archive:
    for member, data in members:
        member.size = len(data) if member.isfile() else 0
        archive.addfile(member, io.BytesIO(data) if member.isfile() else None)
print(release)
PY
    )
}

if selected round-trip; then
    run_unpack
    [ "$(readlink "$destination/harness/link")" = package ] || fail symlink-not-preserved
    cmp "$work/node/bin/node" "$destination/node/bin/node" || fail node-bytes
    cmp "$work/guest/preload.mjs" "$destination/sovereign/guest/preload.mjs" || fail guest-bytes
    before=$(python3 - "$destination/node/bin/node" <<'PY'
import os
import sys
print(os.stat(sys.argv[1]).st_ino)
PY
    )
    run_unpack
    after=$(python3 - "$destination/node/bin/node" <<'PY'
import os
import sys
print(os.stat(sys.argv[1]).st_ino)
PY
    )
    [ "$before" = "$after" ] || fail rerun-mutated-runtime
    rm -rf "$destination"
    ok round-trip
fi

if selected input-paths; then
    original_destination=$destination
    destination=relative
    refused bundle:absolute-path-required
    destination="$work/missing/runtime"
    refused bundle:destination-invalid
    destination=$original_destination
    original_release=$release
    release=bad
    refused bundle:release-digest-required
    release=$original_release
    if bash "$unpacker" > "$work/stdout" 2> "$work/stderr"; then fail usage; fi
    [ "$(cat "$work/stderr")" = bundle:unpack-usage ] || fail usage-code
    ok input-paths
fi

if selected release-digest; then
    release=$(printf '%064d' 0)
    refused bundle:release-digest-mismatch
    reset_archive
    tamper release-file
    refused bundle:manifest-invalid
    reset_archive
    ok release-digest
fi

if selected content-integrity; then
    tamper content
    refused bundle:manifest-content
    [ ! -e "$destination" ] || fail content-wrote-runtime
    reset_archive
    tamper mode
    refused bundle:manifest-entry
    reset_archive
    ok content-integrity
fi

if selected coverage; then
    tamper extra
    refused bundle:manifest-coverage
    reset_archive
    tamper layout
    refused bundle:manifest-layout
    reset_archive
    tamper duplicate
    refused bundle:archive-duplicate
    reset_archive
    ok coverage
fi

if selected path-safety; then
    tamper path
    refused bundle:archive-path
    [ ! -e "$work/escaped" ] || fail escaped-file-written
    reset_archive
    tamper parent
    refused bundle:archive-parent
    reset_archive
    ok path-safety
fi

if selected link-safety; then
    for operation in absolute-link escaping-link dangling-link link-loop; do
        tamper "$operation"
        refused bundle:archive-link
        [ ! -e "$destination" ] || fail unsafe-link-written
        reset_archive
    done
    ok link-safety
fi

if selected special-entry; then
    tamper special
    refused bundle:archive-special
    reset_archive
    ok special-entry
fi

if selected privileged-mode; then
    tamper privileged-mode
    refused bundle:archive-privileged-mode
    reset_archive
    tamper link-mode
    refused bundle:archive-link-mode
    reset_archive
    ok privileged-mode
fi

if selected existing-conflict; then
    run_unpack
    printf 'altered\n' >> "$destination/node/bin/node"
    refused bundle:existing-conflict
    [ "$(tail -n 1 "$destination/node/bin/node")" = altered ] || fail existing-was-overwritten
    rm -rf "$destination"
    run_unpack
    printf 'extra\n' > "$destination/extra"
    refused bundle:existing-conflict
    rm -rf "$destination"
    run_unpack
    chmod 0644 "$destination/node/bin/node"
    refused bundle:existing-conflict
    rm -rf "$destination"
    run_unpack
    rm "$destination/sovereign/bridge/canon.mjs"
    refused bundle:existing-conflict
    rm -rf "$destination"
    run_unpack
    rm "$destination/harness/link"
    ln -s /etc/passwd "$destination/harness/link"
    refused bundle:existing-conflict
    rm -rf "$destination"
    ok existing-conflict
fi

if [ "$case_name" = all ]; then
    python3 - "$unpacker" "$work" > "$work/mutations" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text()
mutations = [
    ("release-digest", "release-digest", 'if hashlib.sha256(manifest).hexdigest() != expected_digest:', "if False:"),
    ("release-file", "release-digest", 'if release != (expected_digest + "  MANIFEST\\n").encode():', "if False:"),
    ("content", "content-integrity", 'refuse("manifest-content")', "pass"),
    ("entry", "content-integrity", 'refuse("manifest-entry")', "pass"),
    ("coverage", "coverage", 'refuse("manifest-coverage")', "pass"),
    ("layout", "coverage", 'refuse("manifest-layout")', "pass"),
    ("duplicate", "coverage", 'refuse("archive-duplicate")', "pass"),
    ("path", "path-safety", 'refuse("archive-path")', "return"),
    ("parent", "path-safety", 'refuse("archive-parent")', "pass"),
    ("links", "link-safety", 'refuse("archive-link")', "return"),
    ("special", "special-entry", 'refuse("archive-special")', "pass"),
    ("existing", "existing-conflict", 'verify_tree(destination, entries, manifest, release)', "pass"),
    ("privileged-mode", "privileged-mode", 'refuse("archive-privileged-mode")', "pass"),
    ("link-mode", "privileged-mode", 'refuse("archive-link-mode")', "pass"),
]
for name, case, before, after in mutations:
    assert before in source, name
    (pathlib.Path(sys.argv[2]) / (name + ".sh")).write_text(source.replace(before, after))
    print(name + " " + case)
PY
    killed=0
    while read -r mutation check; do
        if UNPACK_SCRIPT="$work/$mutation.sh" bash "$self" "$check" > "$work/mutant-output" 2>&1; then
            fail "mutation-survived-$mutation"
        fi
        killed=$((killed + 1))
        printf 'killed unpack:%s\n' "$mutation"
    done < "$work/mutations"
    printf 'unpack mutation result: %s killed, 0 survived\n' "$killed"
fi
printf 'unpack test result: %s passed, 0 failed\n' "$passed"
