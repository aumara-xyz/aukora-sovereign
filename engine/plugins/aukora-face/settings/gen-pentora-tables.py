"""Generate the Aura Coherence Pentora tables from the pinned sources (run from the repo root)."""
import hashlib, json, math, re, sys
from fractions import Fraction
from itertools import combinations
reg_path = 'crates/canon/src/health_registry.rs'
geo_path = 'crates/pentora/vectors/geometry_index_table_v1.json'
reg_src = open(reg_path, 'rb').read()
geo_src = open(geo_path, 'rb').read()
text = reg_src.decode()
ORG = {'Aumlok': 'aumlok', 'GateAura': 'gate-aura', 'Kira': 'kira', 'Network': 'network', 'Body': 'body'}
def unstr(s): return json.loads(s)
checks = []
for m in re.finditer(r'check\(\s*OrganId::(\w+),\s*(\d+),\s*("(?:[^"\\]|\\.)*"),\s*("(?:[^"\\]|\\.)*"),\s*([\d_]+),?\s*\)', text):
    checks.append({'organ': ORG[m.group(1)], 'index': int(m.group(2)), 'invariant': unstr(m.group(3)), 'source': unstr(m.group(4)), 'freshness_ms': int(m.group(5).replace('_',''))})
corners = []
for m in re.finditer(r'corner\(\s*(\d+),\s*("(?:[^"\\]|\\.)*"),\s*\[OrganId::(\w+),\s*OrganId::(\w+)\],\s*("(?:[^"\\]|\\.)*"),\s*\[\s*("(?:[^"\\]|\\.)*"),\s*("(?:[^"\\]|\\.)*"),?\s*\],\s*([\d_]+),?\s*\)', text):
    corners.append({'index': int(m.group(1)), 'pair': unstr(m.group(2)), 'owners': [ORG[m.group(3)], ORG[m.group(4)]], 'invariant': unstr(m.group(5)), 'sources': [unstr(m.group(6)), unstr(m.group(7))], 'freshness_ms': int(m.group(8).replace('_',''))})
assert len(checks) == 90 and len(corners) == 20, (len(checks), len(corners))
geo = json.loads(geo_src)
phi = (1 + math.sqrt(5)) / 2
def coord(c): return (float(Fraction(*c['a'])) + phi * float(Fraction(*c['b']))) / math.sqrt(3)
pts = {p['global_index']: [round(coord(c), 6) for c in p['coordinates']] for p in geo['points']}
assert len(pts) == 111
private = set(geo['private_indices']); corner_set = set(geo['double_corner_indices'])
assert len(private) == 90 and len(corner_set) == 20
cubes = []
for cube in geo['cubes']:
    cid = cube['cube_id']
    local = {}
    for p in geo['points']:
        for inc in p['incidences']:
            if inc['cube_id'] == cid: local[p['global_index']] = tuple(inc['local_coord'])
    cells = [g for g in local if g != 55]
    assert len(cells) == 26, (cid, len(cells))
    priv = sorted(g for g in cells if g in private)
    corn = sorted(g for g in cells if g in corner_set)
    assert len(priv) == 18 and len(corn) == 8
    edges = [tuple(e) for e in cube['edges_global_indices']]
    by_local = {v: g for g, v in local.items()}
    # each edge's midpoint: the private cell whose local coordinate is the average of the two corners'
    edge_mid = []
    for a, b in edges:
        la, lb = local[a], local[b]
        mid = tuple((x + y) // 2 for x, y in zip(la, lb))
        g = by_local[mid]; assert g in priv
        edge_mid.append(g)
    faces = sorted(g for g in priv if sum(1 for x in local[g] if x == 0) == 2)
    assert len(faces) == 6 and len(set(edge_mid)) == 12
    cubes.append({'cube': cid, 'edges': [list(e) for e in edges], 'edge_midpoints': edge_mid, 'face_centres': faces, 'private': priv, 'corners': corn})
# pair corners: corner k of pair p is the k-th smallest shared noncentre index, pairs in pinned order
pairs = [sorted(p['noncentre_corner_indices']) for p in geo['pair_intersections']]
pair_cubes = [p['cube_ids'] for p in geo['pair_intersections']]
assert len(pairs) == 10
corner_cells = [pairs[i // 2][i % 2] for i in range(20)]
order = ['aumlok', 'gate-aura', 'kira', 'network', 'body']
for i, c in enumerate(corners):
    pc = pair_cubes[i // 2]
    assert [order[pc[0]], order[pc[1]]] == c['owners'], (i, pc, c['owners'])
sha = lambda b: hashlib.sha256(b).hexdigest()
out = []
out.append('// SPDX-License-Identifier: AGPL-3.0-or-later\n// Copyright (c) 2026 Aumara and Peter Viviani\n')
out.append('/**\n * GENERATED: do not edit. The Pentora health map\'s fixed tables, from the pinned sources:\n')
out.append(f' *   {geo_path} sha256 {sha(geo_src)}\n *   {reg_path} sha256 {sha(reg_src)}\n')
out.append(' * Organ i owns cube i; a cube\'s 18 private cells (12 edge midpoints, 6 face centres) are its private checks in\n')
out.append(' * ascending global-index order; its 8 corners are shared, each with one other organ. Coordinates are a+b*phi over sqrt(3),\n')
out.append(' * rounded to 1e-6 (display only). The geometry table says of itself: "PROPOSED geometry adapter; NOT M1-approved".\n */\n')
out.append(f'export const GEOMETRY_SHA256 = \'{sha(geo_src)}\'\nexport const REGISTRY_SHA256 = \'{sha(reg_src)}\'\n\n')
out.append('/** Global cell index -> [x, y, z]; 111 points, 55 is the centre (no cell). */\n')
out.append('export const POINTS: Readonly<Record<number, readonly [number, number, number]>> = {\n')
for g in sorted(pts): out.append(f'  {g}: [{pts[g][0]}, {pts[g][1]}, {pts[g][2]}],\n')
out.append('}\n\n/** The five cubes, organ order (aumlok, gate-aura, kira, network, body). */\n')
out.append('export const CUBES: readonly { readonly edges: readonly (readonly [number, number])[]; readonly edgeMidpoints: readonly number[]; readonly faceCentres: readonly number[]; readonly private: readonly number[]; readonly corners: readonly number[] }[] = [\n')
for c in cubes:
    out.append('  {\n    edges: [' + ', '.join(f'[{a}, {b}]' for a, b in c['edges']) + '],\n')
    out.append('    edgeMidpoints: ' + json.dumps(c['edge_midpoints']) + ',\n    faceCentres: ' + json.dumps(c['face_centres']) + ',\n')
    out.append('    private: ' + json.dumps(c['private']) + ',\n    corners: ' + json.dumps(c['corners']) + ',\n  },\n')
out.append(']\n\n/** Corner k (1..20) sits at this global cell. */\nexport const CORNER_CELLS: readonly number[] = ' + json.dumps(corner_cells) + '\n\n')
out.append('export type OrganWire = \'aumlok\' | \'gate-aura\' | \'kira\' | \'network\' | \'body\'\n\n')
out.append('/** canon CHECKS (HEALTH_REGISTRY_VERSION 1): 18 per organ, organ order then index. */\n')
out.append('export const CHECKS: readonly { readonly organ: OrganWire; readonly index: number; readonly invariant: string; readonly source: string; readonly freshness_ms: number }[] = [\n')
for c in checks: out.append('  ' + json.dumps(c, ensure_ascii=False) + ',\n')
out.append(']\n\n/** canon CORNERS: 20, two per organ pair. */\n')
out.append('export const CORNERS: readonly { readonly index: number; readonly pair: string; readonly owners: readonly [OrganWire, OrganWire]; readonly invariant: string; readonly sources: readonly [string, string]; readonly freshness_ms: number }[] = [\n')
for c in corners: out.append('  ' + json.dumps(c, ensure_ascii=False) + ',\n')
out.append(']\n')
s = ''.join(out)
# JSON keys unquoted style not required; TS accepts quoted keys
sys.stdout.write(s)
