// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { strictJSON } from './codec.mjs';

const hash = parts => createHash('sha256').update(Buffer.concat(parts)).digest('hex');
const ascii = value => Buffer.from(value, 'ascii');
const raw = value => Buffer.from(value, 'hex');
const u32 = value => { const b = Buffer.alloc(4); b.writeUInt32BE(value); return b; };
const u64 = value => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(value)); return b; };
const digest = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const integer = value => Number.isSafeInteger(value) && value >= 0;
const ceiling = { wall_ms: 60_000, cpu_us: 10_000_000, memory_bytes: 268_435_456,
  io_bytes: 16_777_216, output_bytes: 65_536, cases: 16_384 };
const errno = { Permission: 1, Access: 13, ReadOnly: 30, Missing: 2, BadDescriptor: 9,
  FileTooLarge: 27, NotImplemented: 38, Isolated: null, ResourceLimited: null, ParentDeath: null };

function canonical(c, value, depth = 0) {
  c.require('hostile-json-depth', depth <= 20);
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    c.require('hostile-json-integer', integer(value));
    return String(value);
  }
  if (typeof value === 'string') {
    c.require('hostile-json-string', !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value));
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(v => canonical(c, v, depth + 1)).join(',')}]`;
  c.require('hostile-json-object', typeof value === 'object');
  return `{${Object.keys(value).sort().map(k => `${canonical(c, k, depth + 1)}:${canonical(c, value[k], depth + 1)}`).join(',')}}`;
}

function keys(c, value, names, id) {
  c.require(`${id}-object`, value !== null && typeof value === 'object' && !Array.isArray(value));
  c.same(`${id}-keys`, Object.keys(value).sort().join(','), [...names].sort().join(','));
}

function variants(c, source, name) {
  const body = source.match(new RegExp(`pub enum ${name} \\{([^}]+)\\}`))?.[1];
  c.require('hostile-enum-present', typeof body === 'string');
  const values = [...body.matchAll(/^\s*([A-Z][A-Za-z0-9]+),\s*$/gm)].map(m => m[1]);
  c.require('hostile-enum-complete', values.length > 0);
  return values;
}

async function catalogue(c) {
  const source = await readFile(resolve(c.repoRoot, 'crates/immune/src/hostile.rs'), 'utf8');
  const body = source.split('pub const HOSTILE_CASES: &[AttackCase] = &[')[1]?.split('];')[0];
  c.require('hostile-catalogue-present', typeof body === 'string');
  const operations = variants(c, source, 'Operation');
  const fixtures = variants(c, source, 'Fixture');
  const denials = variants(c, source, 'Denial');
  const rows = [...body.matchAll(/case\(\s*"([a-z0-9-]+)",\s*Operation::([A-Za-z0-9]+),\s*Fixture::([A-Za-z0-9]+),\s*Denial::([A-Za-z0-9]+),?\s*\)/g)].map(m => ({
    id: m[1], operation: m[2], fixture: m[3], denial: m[4],
    codes: Buffer.from([operations.indexOf(m[2]), fixtures.indexOf(m[3]), denials.indexOf(m[4])]),
  }));
  c.same('hostile-catalogue-size', rows.length, 53);
  c.same('hostile-catalogue-unique', new Set(rows.map(r => r.id)).size, rows.length);
  for (const row of rows) {
    c.require('hostile-catalogue-variants', operations.includes(row.operation)
      && fixtures.includes(row.fixture) && Object.hasOwn(errno, row.denial));
  }
  const permission = source.match(/denial == Denial::Permission[\s\S]*?self\.operation,([\s\S]*?)\)/)?.[1];
  c.require('hostile-permission-rule', typeof permission === 'string');
  const earlyPermission = new Set([...permission.matchAll(/Operation::([A-Za-z0-9]+)/g)].map(m => m[1]));
  return { rows, earlyPermission };
}

export async function hostile(c) {
  const { rows, earlyPermission } = await catalogue(c);
  const runId = randomBytes(32).toString('hex');
  const installedRelease = await c.digest('m2-hostile-release', 'Read the running binary release digest from the supervisor host, not from the guest:');
  await c.witness('m2-hostile-driver', `Use the installed host integration of immune::hostile::hostile/HostileDriver with run_id ${runId}. It must prepare disposable targets and execute all 53 operations twice: confined and unconfined. The current source has no shipped CLI for this; stop if the installed driver is absent. Confirm the host uses the installed release and measures resources itself. A guest report or replayed report is insufficient.`);
  const line = await c.text('m2-hostile-report', 'Paste one canonical JSON line from that fresh host run: {"schema":"aukora-acceptance-hostile-v1","request":HostileRequest,"run":HostileRun}. Sort all object keys. Rust enum observation Denied is {"denial":"Access","errno":13,"kind":"Denied"}; ReachedTarget is {"kind":"ReachedTarget"}. Native field names are unchanged. No secrets or approval material.');
  let report;
  try { report = strictJSON(Buffer.from(line, 'utf8')); } catch { c.require('hostile-report-json', false); }
  c.same('hostile-report-canonical', canonical(c, report), line);
  keys(c, report, ['schema', 'request', 'run'], 'hostile-report');
  c.same('hostile-report-version', report.schema, 'aukora-acceptance-hostile-v1');
  const { request, run } = report;
  keys(c, request, ['boot', 'fixture_commitment'], 'hostile-request');
  const { boot } = request;
  const names = ['run_id', 'candidate', 'release', 'cage', 'challenge', 'corpus_root'];
  keys(c, boot, [...names, 'limits'], 'hostile-boot');
  for (const name of names) c.require(`hostile-${name}`, digest(boot[name]));
  c.same('hostile-fresh-run', boot.run_id, runId);
  c.same('hostile-installed-release', boot.release, installedRelease);
  c.require('hostile-fixtures', digest(request.fixture_commitment));
  keys(c, boot.limits, Object.keys(ceiling), 'hostile-limits');
  for (const [key, max] of Object.entries(ceiling)) {
    c.require(`hostile-limit-${key}`, integer(boot.limits[key]) && boot.limits[key] > 0 && boot.limits[key] <= max);
  }
  c.require('hostile-pair-budget', boot.limits.cases >= rows.length * 2 && boot.limits.wall_ms >= 1000);
  const bootCommitment = hash([ascii('aukora:boot-self-attack:v1\0'), ...names.map(n => raw(boot[n])),
    ...['wall_ms', 'cpu_us', 'memory_bytes', 'io_bytes'].map(n => u64(boot.limits[n])),
    u32(boot.limits.output_bytes), u32(boot.limits.cases)]);
  const commitment = hash([ascii('aukora:hostile-request:v1\0'), raw(bootCommitment), raw(request.fixture_commitment)]);
  keys(c, run, ['request_commitment', 'parent_cgroup', 'confined_cgroup', 'control_cgroup',
    'grants_at_start', 'grants_at_end', 'results', 'usage', 'budget_exhausted'], 'hostile-run');
  c.same('hostile-request-binding', run.request_commitment, commitment);
  const groups = [run.parent_cgroup, run.confined_cgroup, run.control_cgroup];
  c.require('hostile-cgroups', groups.every(g => integer(g) && g > 0) && new Set(groups).size === 3);
  c.same('hostile-grants-start', run.grants_at_start, 0);
  c.same('hostile-grants-end', run.grants_at_end, 0);
  c.same('hostile-budget-exhausted', run.budget_exhausted, false);
  keys(c, run.usage, Object.keys(ceiling), 'hostile-usage');
  for (const key of Object.keys(ceiling)) {
    c.require(`hostile-usage-${key}`, integer(run.usage[key]) && run.usage[key] <= boot.limits[key]);
  }
  c.same('hostile-attempts', run.usage.cases, rows.length * 2);
  c.require('hostile-resources-measured', run.usage.wall_ms > 0 && run.usage.cpu_us > 0 && run.usage.memory_bytes > 0);
  c.require('hostile-results-array', Array.isArray(run.results));
  c.same('hostile-results-count', run.results.length, rows.length);
  const seen = new Set();
  for (const pair of run.results) {
    keys(c, pair, ['case_id', 'confined_input', 'control_input', 'confined', 'control',
      'confined_elapsed_ms', 'control_elapsed_ms'], 'hostile-pair');
    const row = rows.find(r => r.id === pair.case_id);
    c.require('hostile-case-known-unique', Boolean(row) && !seen.has(pair.case_id));
    seen.add(pair.case_id);
    const expected = hash([ascii('aukora:hostile-case:v1\0'), raw(bootCommitment), raw(request.fixture_commitment),
      u32(row.id.length), ascii(row.id), row.codes]);
    c.same(`hostile-${row.id}-input`, pair.confined_input, expected);
    c.same(`hostile-${row.id}-control-input`, pair.control_input, expected);
    keys(c, pair.control, ['kind'], 'hostile-control');
    c.same(`hostile-${row.id}-control`, pair.control.kind, 'ReachedTarget');
    keys(c, pair.confined, ['kind', 'denial', 'errno'], 'hostile-confined');
    c.same(`hostile-${row.id}-denied`, pair.confined.kind, 'Denied');
    c.require(`hostile-${row.id}-denial`, pair.confined.denial === row.denial
      || (pair.confined.denial === 'Permission' && earlyPermission.has(row.operation)));
    c.same(`hostile-${row.id}-errno`, pair.confined.errno, errno[pair.confined.denial]);
    for (const key of ['confined_elapsed_ms', 'control_elapsed_ms']) {
      c.require(`hostile-${row.id}-time`, integer(pair[key]) && pair[key] <= run.usage.wall_ms);
    }
    if (row.operation === 'SupervisorDeath') {
      c.require('hostile-parent-death', pair.confined_elapsed_ms <= 1000 && pair.control_elapsed_ms >= 1000);
    }
    c.step(`hostile-${row.id}-pair-compared`);
  }
  await c.witness('m2-hostile-host-observation', 'Compare the parsed pair results with the immediately observed host run. Every control reached the same disposable target with the same request input; the three cgroups and aggregate counters are host measurements. Confirm the installed immune judge accepted that exact run without increasing grants. These comparisons validate reported data, not its provenance; do not attest from guest-provided evidence.');
}
