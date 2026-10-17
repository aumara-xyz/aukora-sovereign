#!/usr/bin/env python3
"""Build the Spatial face (`engine/plugins/aukora-face/*`) against a DeepSeek Harness checkout.

The face is nine harness plugin packages (layout, sidebar, threads, apps, messages, documents, aumlok,
settings, memory). A harness client plugin is bundled by the harness's own tsdown preset
(`packages/client/tsdown.client.ts`): it emits the closure-factory bundle the browser module loader
(`window.__ModuleLoader__`) executes, and its imports are relative into the monorepo, so a face cannot
carry a copy. This script therefore does what Prime's `scripts/build-face.py` did, against the current tag:

  1. places each face under `<dsh>/packages/client/aukora-face-<name>` (the path every config in the face
     already assumes: `../../../tsconfig.base.client.json`, `../tsdown.client.ts`);
  2. runs `pnpm install` so the workspace links the new packages;
  3. `tsc -b` the face (client half judged first, host half reported separately);
  4. `tsdown` bundles `lib/client.js` and `lib/index.js` (host half);
  5. copies `lib/` back next to the source, in `engine/plugins/aukora-face/<name>/lib` (git-ignored).

`<dsh>` MUST BE A DISPOSABLE CLONE of github.com/deepseek-ai/deepseek-harness at tag dsh-v0.2.1-alpha.5, already
installed once (`pnpm install --frozen-lockfile`). This script writes faces and a lockfile change into it.

Usage:
    python3 build-face.py --dsh ~/face-scratch-dsh/src [--only layout --only sidebar] [--types-only]
"""
import argparse, os, shutil, subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
# The AUKORA foundation plugin (brand slots and palette) sits beside the face: the Spatial look needs both.
FOUNDATION = HERE.parent / 'aukora-foundation'
# Order matters only for reporting; `tsc -b` resolves the real graph from references.
FACES = ('layout', 'sidebar', 'threads', 'messages', 'documents', 'aumlok', 'apps', 'settings', 'memory')
CARRY = ('src', 'assets', 'vendor', 'package.json', 'tsconfig.json', 'tsconfig.client.json',
         'tsconfig.host.json', 'tsdown.config.ts')


def run(cmd, cwd, env=None):
    return subprocess.run(cmd, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def place(dsh: Path, names):
    """Copy each face's carried files into the checkout, keeping its node_modules and lib (the build state)."""
    client = dsh / 'packages/client'
    for name in names:
        dst = client / f'aukora-face-{name}'
        dst.mkdir(parents=True, exist_ok=True)
        for item in CARRY:
            src = HERE / name / item
            target = dst / item
            if target.is_dir():
                shutil.rmtree(target)
            elif target.exists():
                target.unlink()
            if src.is_dir():
                shutil.copytree(src, target)
            elif src.is_file():
                shutil.copy2(src, target)


def build_foundation(dsh: Path):
    """Bundle the foundation with its own tsdown config (a plain object: the stock preset resolves packages by name).

    The brand PNG is inlined as a data URI because a dynamically loaded client bundle has no module URL to resolve an
    asset from; the committed 96x96 derivative is used verbatim.
    """
    import base64
    dst = dsh / 'packages/client/aukora-foundation'
    dst.mkdir(parents=True, exist_ok=True)
    for item in ('src', 'assets', 'package.json', 'tsdown.config.ts'):
        src, target = FOUNDATION / item, dst / item
        if target.is_dir():
            shutil.rmtree(target)
        elif target.exists():
            target.unlink()
        if src.is_dir():
            shutil.copytree(src, target)
        else:
            shutil.copy2(src, target)
    icon = 'data:image/png;base64,' + base64.b64encode((FOUNDATION / 'assets/AUMARA-ICON-96.png').read_bytes()).decode()
    for face in ('client', 'host'):
        env = dict(os.environ, AUKORA_BUILD_FACE=face, AUKORA_ICON_DATA_URI=icon)
        out = run([str(dsh / 'node_modules/.bin/tsdown')], dst, env)
        if out.returncode:
            return out.stdout[-2000:]
    (FOUNDATION / 'lib').mkdir(exist_ok=True)
    for item in ('index.js', 'client.js'):
        shutil.copy2(dst / 'lib' / item, FOUNDATION / 'lib' / item)
    return None


def install(dsh: Path):
    env = dict(os.environ, CI='true', LEFTHOOK='0')
    out = run(['pnpm', 'install', '--no-frozen-lockfile', '--prefer-offline',
               '--config.manage-package-manager-versions=false'], dsh, env)
    if out.returncode:
        sys.exit('face-install-failed:\n' + out.stdout[-3000:])


def type_build(dsh: Path, name):
    tsc = dsh / 'node_modules/typescript/bin/tsc'
    pkg = dsh / f'packages/client/aukora-face-{name}'
    targets = [pkg / 'tsconfig.client.json'] if (pkg / 'tsconfig.client.json').exists() else [pkg]
    out = run(['node', '--max-old-space-size=4096', str(tsc), '-b', *map(str, targets)], dsh)
    client = [l for l in out.stdout.splitlines() if 'error TS' in l]
    host = []
    if (pkg / 'tsconfig.host.json').exists():
        out = run(['node', '--max-old-space-size=4096', str(tsc), '-b', str(pkg / 'tsconfig.host.json')], dsh)
        host = [l for l in out.stdout.splitlines() if 'error TS' in l]
    return client, host


def bundle(dsh: Path, name):
    pkg = dsh / f'packages/client/aukora-face-{name}'
    out = run([str(dsh / 'node_modules/.bin/tsdown')], pkg)
    if out.returncode or not (pkg / 'lib/client.js').exists():
        return None, out.stdout[-2000:]
    return pkg / 'lib', ''


def copy_back(dsh: Path, name):
    lib = dsh / f'packages/client/aukora-face-{name}/lib'
    dst = HERE / name / 'lib'
    dst.mkdir(exist_ok=True)
    for item in ('index.js', 'client.js'):
        if (lib / item).exists():
            shutil.copy2(lib / item, dst / item)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dsh', type=Path, required=True, help='disposable DSH checkout at dsh-v0.2.1-alpha.5')
    parser.add_argument('--only', action='append', default=[])
    parser.add_argument('--types-only', action='store_true')
    parser.add_argument('--no-install', action='store_true')
    parser.add_argument('--all', action='store_true', help='print every type error, not the first 25')
    a = parser.parse_args()
    dsh = a.dsh.expanduser().resolve()
    if not (dsh / 'packages/client/tsdown.client.ts').is_file():
        sys.exit(f'not-a-dsh-checkout: {dsh}')
    names = tuple(a.only) or FACES
    place(dsh, FACES)
    (dsh / 'packages/client/aukora-foundation').mkdir(parents=True, exist_ok=True)
    if not a.no_install:
        install(dsh)
    failed = []
    for n in names:
        client, host = type_build(dsh, n)
        if client or host:
            failed.append(n)
            print(f'FACE TYPES {n}: {len(client)} client, {len(host)} host errors')
            for line in (client + host)[:(None if a.all else 25)]:
                print('  ' + line[:240])
            continue
        if a.types_only:
            print(f'FACE TYPES OK {n}')
            continue
        lib, why = bundle(dsh, n)
        if lib is None:
            failed.append(n)
            print(f'FACE BUNDLE FAILED {n}\n{why}')
            continue
        copy_back(dsh, n)
        print(f'FACE BUILT {n}: {HERE / n / "lib/client.js"}')
    if not a.types_only and not a.only:
        why = build_foundation(dsh)
        if why is None:
            print(f'FACE BUILT foundation: {FOUNDATION / "lib/client.js"}')
        else:
            failed.append('foundation')
            print(f'FACE BUNDLE FAILED foundation\n{why}')
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
