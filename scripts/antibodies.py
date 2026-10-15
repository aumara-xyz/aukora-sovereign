#!/usr/bin/env python3
"""Antibody ratchet (issue #41, first step): every regression test named `antibody_*` is
registered in immune/ANTIBODIES.tsv, and no registered antibody ever disappears.

--check fails when: a registered antibody is missing from the source; an antibody in the
source is not registered; or a name that was ever registered (git history) is no longer in
the manifest. A row may be retired only by marking its source `retired:<reason>` in an
owner-approved change; a retired row stays in the manifest. --write registers new
antibodies (append-only). The corpus root is the SHA-256 of the manifest bytes.
"""
import hashlib, re, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'immune/ANTIBODIES.tsv'
HEADER = 'name\tarea\tsource\n'
RUST = re.compile(r'\bfn (antibody_[a-z0-9_]+)\s*\(')
JS = re.compile(r"""\btest\(\s*(['"`])(antibody[^'"`]*)\1""")


def discover():
    found = {}
    for path in sorted((ROOT / 'crates').rglob('*.rs')):
        if 'target' in path.parts:
            continue
        for name in RUST.findall(path.read_text(encoding='utf8')):
            found.setdefault(name, path.relative_to(ROOT).parts[1])
    for top in ('ui', 'guest', 'crates'):
        for path in sorted((ROOT / top).rglob('*.mjs')):
            if 'node_modules' in path.parts:
                continue
            for _, name in JS.findall(path.read_text(encoding='utf8')):
                found.setdefault(name, path.relative_to(ROOT).parts[0] if top != 'crates' else path.relative_to(ROOT).parts[1])
    return found


def read_manifest(text):
    lines = text.splitlines(keepends=True)
    if not lines or lines[0] != HEADER:
        raise SystemExit('immune:manifest-header')
    rows = [line.rstrip('\n').split('\t') for line in lines[1:]]
    if any(len(row) != 3 or not row[0] for row in rows):
        raise SystemExit('immune:manifest-row')
    return rows


def ever_registered():
    try:
        log = subprocess.run(['git', 'log', '--format=', '-p', '--', str(MANIFEST.relative_to(ROOT))],
                             cwd=ROOT, capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return set()
    return {line[1:].split('\t')[0] for line in log.splitlines()
            if line.startswith('+') and not line.startswith('+++') and '\t' in line and not line.startswith('+name\t')}


def main():
    found = discover()
    text = MANIFEST.read_text(encoding='utf8') if MANIFEST.exists() else HEADER
    rows = read_manifest(text)
    names = [row[0] for row in rows]
    if len(set(names)) != len(names):
        raise SystemExit('immune:manifest-duplicate')
    if '--write' in sys.argv:
        new = sorted(set(found) - set(names))
        with MANIFEST.open('w', encoding='utf8') as out:
            out.write(text)
            for name in new:
                out.write(f'{name}\t{found[name]}\t-\n')
        text = MANIFEST.read_text(encoding='utf8')
        rows = read_manifest(text)
        names = [row[0] for row in rows]
    errors = []
    retired = {row[0] for row in rows if row[2].startswith('retired:')}
    errors += [f'antibody missing from source: {n}' for n in names if n not in found and n not in retired]
    errors += [f'antibody not registered in immune/ANTIBODIES.tsv: {n}' for n in sorted(found) if n not in names]
    errors += [f'registered antibody deleted from the manifest: {n}' for n in sorted(ever_registered() - set(names))]
    if errors:
        raise SystemExit('immune:antibody-ratchet\n' + '\n'.join(errors))
    print(f'antibodies: {len(rows)} registered ({len(retired)} retired); corpus root {hashlib.sha256(text.encode()).hexdigest()}')


if __name__ == '__main__':
    main()
