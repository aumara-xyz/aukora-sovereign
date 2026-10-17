#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Operator side: build engine-plugins.tar, the packages the node stages under /opt/aukora-engine/plugins.

Every package becomes one folder holding exactly what the engine may load (built JavaScript, assets, package.json);
no sources, no node_modules, no links. On the node the supervisor fingerprints each folder and the owner approves the
set by name and digest (crates/supervisor/src/engine_plugins.rs); the root closure step copies only approved bytes.

  @aukora/door                       engine/plugins/aukora-door, lib/ built here with its own build.mjs (pinned node)
  @aukora/kira                       engine/plugins/aukora-kira, the same way (Kira 2's tools, through the door)
  @aukora/face-<name> (nine)         engine/plugins/aukora-face/<name>, lib/ built by build-face.py (or a built bundle)
  @aukora/dsh-plugin-foundation      engine/plugins/aukora-foundation, lib/ built by build-face.py
  @aukora/face-bundle                the composition: dsh-web-app's patch from the pinned harness, with the four rows the
                                     face replaces removed and the face rows added by package name (no relative paths,
                                     so a face cannot reach a sibling folder that is not itself an approved package)

Usage:
  python3 -B -I deploy/engine/build_plugins.py --dsh DSH_INSTALL --faces FACES_DIR [--foundation DIR] --node NODE \\
      --out OUT_DIR [--tar FILE]
DSH_INSTALL is a folder holding node_modules/@deepseek-ai/dsh-web-app at 0.2.1-alpha.5; FACES_DIR holds <name>/lib/*.js
for the nine faces (engine/plugins/aukora-face after build-face.py, or the aukora-face folder of a built preview bundle).
The tar is written with sorted names, zero owners and a zero clock, so the same inputs give the same bytes.
"""
import argparse
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
FACES = ('layout', 'sidebar', 'threads', 'apps', 'messages', 'documents', 'aumlok', 'settings', 'memory')
CARRY = ('assets', 'vendor')
# The four upstream rows the face replaces (engine/plugins/aukora-face/PORT-NOTES.md, "Composition").
REPLACED = ('ui-layout', 'ui-settings-general', 'ui-sidebar', 'ui-workspace')
NAME = re.compile(r'^@aukora/[a-z0-9][a-z0-9.-]{0,60}$')


def fail(reason):
    sys.exit('build-plugins: ' + reason)


def beneath(path, root):
    """path, resolved, if it stays under root (resolved); otherwise the build fails."""
    resolved, top = path.resolve(), root.resolve()
    if resolved != top and top not in resolved.parents:
        fail('path leaves its root: %s' % path)
    return resolved


def copy_file(source, target, out):
    """One regular file, never through a link, into a target that stays under out (Grok review of the node commit,
    part 5 #4: a symlinked source or an absolute or `..` destination once escaped)."""
    info = os.lstat(source)
    if not stat.S_ISREG(info.st_mode):
        fail('not a regular file (a link?): %s' % source)
    beneath(target.parent if target.parent.exists() else out, out)
    if target.exists() or target.is_symlink():
        fail('target exists: %s' % target)
    target.parent.mkdir(parents=True, exist_ok=True)
    beneath(target.parent, out)
    shutil.copyfile(source, target, follow_symlinks=False)


def copy_tree(src, dst, out, skip=frozenset()):
    """Every file under src into dst, except targets in `skip` (already placed, from the same source)."""
    if src.is_symlink():
        fail('link in package: %s' % src)
    for path in sorted(src.rglob('*')):
        if path.is_symlink():
            fail('link in package: %s' % path)
        target = dst / path.relative_to(src)
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            beneath(target, out)
        elif path.is_file():
            if target not in skip:
                copy_file(path, target, out)
        else:
            fail('special file in package: %s' % path)


def relative_name(rel):
    """A package-relative path from someone else's manifest: plain, relative, no `..`. One leading `./` is allowed and
    dropped: the pinned dsh-web-app names its patch `./cordis.patch.yml` (the node rehearsal's first real build)."""
    if isinstance(rel, str) and rel.startswith('./'):
        rel = rel[2:]
    if not isinstance(rel, str) or not rel or rel.startswith('/') or '\\' in rel or \
            any(part in ('', '.', '..') for part in rel.split('/')):
        fail('bad relative path in a manifest: %r' % (rel,))
    return rel


def package(out, folder, manifest_src, files):
    """One package folder: package.json plus (relative path -> source path)."""
    dst = out / folder
    if dst.exists():
        fail('duplicate package folder ' + folder)
    dst.mkdir(parents=True)
    manifest = json.loads(manifest_src.read_text())
    if not NAME.match(manifest.get('name', '')):
        fail('package name %r is not @aukora/...' % manifest.get('name'))
    copy_file(manifest_src, dst / 'package.json', out)
    for relative, source in files:
        target = dst / relative_name(relative)
        if source.is_dir() and not source.is_symlink():
            copy_tree(source, target, out)
        else:
            copy_file(source, target, out)
    return manifest['name']


def build_own(node, out, folder):
    """A plugin with no dependencies built by its own build.mjs (the door, Kira 2): lib/*.js and its patch."""
    source = REPO / 'engine/plugins' / folder
    done = subprocess.run([node, 'build.mjs'], cwd=source, stdin=subprocess.DEVNULL, capture_output=True, text=True)
    if done.returncode != 0:
        fail('%s build: %s' % (folder, done.stderr[-400:]))
    lib = sorted((source / 'lib').glob('*.js'))
    if not lib:
        fail('%s build left no lib/*.js' % folder)
    return package(out, folder, source / 'package.json',
                   [('lib/' + path.name, path) for path in lib] + [('cordis.patch.yml', source / 'cordis.patch.yml')])


def build_door(node, out):
    return build_own(node, out, 'aukora-door')


def build_kira(node, out):
    """@aukora/kira: the kira_* tools, every call through the door (it holds no token). Mounted by the authority
    overlay after the door (authority.patch.yml row 1)."""
    return build_own(node, out, 'aukora-kira')


def build_faces(faces, out):
    names = []
    for face in FACES:
        src = faces / face
        files = []
        for item in ('index.js', 'client.js'):
            if (src / 'lib' / item).is_file():
                files.append(('lib/' + item, src / 'lib' / item))
        if not any(name == 'lib/client.js' for name, _ in files):
            fail('face not built: %s (run engine/plugins/aukora-face/build-face.py first)' % face)
        files += [(item, src / item) for item in CARRY if (src / item).is_dir()]
        names.append(package(out, 'aukora-face-' + face, src / 'package.json', files))
    return names


def build_foundation(foundation, out):
    files = [('lib/' + item, foundation / 'lib' / item) for item in ('index.js', 'client.js')]
    if not all(source.is_file() for _, source in files):
        fail('foundation not built (run build-face.py first)')
    files += [(item, foundation / item) for item in ('assets',) if (foundation / item).is_dir()]
    return package(out, 'aukora-foundation', foundation / 'package.json', files)


def build_bundle(dsh, face_names, foundation_name, out):
    """@aukora/face-bundle: dsh-web-app's patch and presets, the four replaced rows removed, the face rows added."""
    web = dsh / 'node_modules/@deepseek-ai/dsh-web-app'
    manifest = json.loads((web / 'package.json').read_text())
    if manifest.get('version') != '0.2.1-alpha.5':
        fail('dsh-web-app is %s, not the pinned 0.2.1-alpha.5' % manifest.get('version'))
    patches = manifest['dsh']['bundle']['patch']
    patches = [patches] if isinstance(patches, str) else patches
    dst = out / 'aukora-face-bundle'
    dst.mkdir(parents=True)
    placed = set()
    for rel in patches:
        rel = relative_name(rel)
        beneath(web / rel, web)
        copy_file(web / rel, dst / rel, out)
        placed.add(dst / rel)
    # The pinned dsh-web-app lists its presets among its patches too: the rest of presets/ is copied around them.
    for extra in ('presets',):
        if (web / extra).is_dir():
            copy_tree(web / extra, dst / extra, out, placed)
    main = dst / patches[0]
    text = main.read_text()
    for row in REPLACED:
        text, count = re.subn(r'^    - id: %s\n      name: [^\n]+\n\n?' % re.escape(row), '', text, flags=re.M)
        if count != 1:
            fail('web-bundle-drift: expected exactly one `%s` row in dsh-web-app, found %d' % (row, count))
    ids = {'@aukora/face-settings': 'ui-settings-general'}
    rows = ''.join("    - id: %s\n      name: '%s'\n" % (ids.get(name, 'aukora-' + name.split('/')[1]), name)
                   for name in [foundation_name] + face_names)
    text += '\n# THE FACE (deploy/engine/build_plugins.py): each face is its own approved package, loaded by name.\n- insert:\n' + rows
    main.write_text(text)
    # web_search has no executor at the door (crates/supervisor/DOOR.md): mounted, it would sit in Auma's catalog and
    # fail every call. Every preset that mounts the web tools keeps web_fetch and loses web_search (`search: false`,
    # dsh-tool-web 0.2.1-alpha.5's switch); a preset whose tool-web row is not the pinned shape stops the build.
    rows = found = 0
    for preset in sorted((dst / 'presets').glob('*.yml')) if (dst / 'presets').is_dir() else []:
        body = preset.read_text()
        rows += len(re.findall(r'^ +- id: tool-web$', body, flags=re.M))
        body, count = re.subn(r"^( +)- id: tool-web\n( +)name: '@deepseek-ai/dsh-tool-web'\n( +)config:\n( +)fetch: true\n",
                              lambda m: m.group(0) + m.group(4) + 'search: false\n', body, flags=re.M)
        found += count
        preset.write_text(body)
    if rows == 0 or found != rows:
        fail('web-bundle-drift: %d tool-web rows in the presets, %d in the pinned shape' % (rows, found))
    (dst / 'package.json').write_text(json.dumps({
        'name': '@aukora/face-bundle', 'version': '0.0.0', 'private': True,
        'dsh': {'bundle': {'patch': patches}},
    }, indent=2) + '\n')
    return '@aukora/face-bundle'


def write_tar(out, path):
    with open(path, 'wb') as raw:
        with tarfile.open(fileobj=raw, mode='w', format=tarfile.GNU_FORMAT) as archive:
            for item in sorted(out.rglob('*')):
                info = tarfile.TarInfo(item.relative_to(out).as_posix())
                info.uid = info.gid = 0
                info.uname = info.gname = ''
                info.mtime = 0
                if item.is_dir():
                    info.type, info.mode = tarfile.DIRTYPE, 0o755
                    archive.addfile(info)
                else:
                    data = item.read_bytes()
                    info.size, info.mode = len(data), 0o644
                    archive.addfile(info, io.BytesIO(data))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dsh', type=Path, required=True)
    parser.add_argument('--faces', type=Path, required=True)
    parser.add_argument('--foundation', type=Path, default=REPO / 'engine/plugins/aukora-foundation')
    parser.add_argument('--node', required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--tar', type=Path)
    a = parser.parse_args()
    out = a.out.expanduser().resolve()
    if out.exists() and any(out.iterdir()):
        fail('output folder must be empty: %s' % out)
    out.mkdir(parents=True, exist_ok=True)
    names = [build_door(a.node, out), build_kira(a.node, out)]
    faces = build_faces(a.faces.expanduser().resolve(), out)
    foundation = build_foundation(a.foundation.expanduser().resolve(), out)
    names += faces + [foundation, build_bundle(a.dsh.expanduser().resolve(), faces, foundation, out)]
    if a.tar:
        write_tar(out, a.tar)
    print(json.dumps({'packages': sorted(names), 'out': str(out), 'tar': str(a.tar) if a.tar else None}, indent=2))


if __name__ == '__main__':
    main()
