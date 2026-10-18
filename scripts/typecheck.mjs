// SPDX-License-Identifier: AGPL-3.0-or-later
// Reuse the face toolchain's locked TypeScript; never download a compiler during construction checks.
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
if (process.env.AUKORA_SKIP_TYPECHECK === '1') {
  console.log('SKIP browser type-check: AUKORA_SKIP_TYPECHECK=1 (ui/owner, portal and app are NOT type-checked)');
  process.exit(0);
}
const lock = readFileSync(join(root, 'engine/plugins/aukora-face/pnpm-lock.yaml'), 'utf8');
const versions = [...lock.matchAll(/^  typescript@([^:\s]+):$/gm)].map(match => match[1]);
if (versions.length !== 1) throw new Error('typecheck: expected one pinned TypeScript version in face lockfile');
const candidates = process.env.AUKORA_TSC ? [resolve(process.env.AUKORA_TSC)] : [
  join(root, 'node_modules/typescript/bin/tsc'),
  join(root, 'engine/plugins/aukora-face/node_modules/typescript/bin/tsc'),
];
const compiler = candidates.find(path => existsSync(path));
if (!compiler) {
  console.error(`TypeScript ${versions[0]} is unavailable offline. Set AUKORA_TSC to the existing pinned typescript/bin/tsc, or explicitly set AUKORA_SKIP_TYPECHECK=1 to skip.`);
  process.exit(1);
}
const version = execFileSync(process.execPath, [compiler, '--version'], { encoding: 'utf8' }).trim();
if (version !== `Version ${versions[0]}`) throw new Error(`typecheck: expected TypeScript ${versions[0]}, got ${version}`);
console.log(`Type-checking ui/owner, portal and app with TypeScript ${versions[0]}`);
execFileSync(process.execPath, [compiler, '--project', join(root, 'tsconfig.json')], { cwd: root, stdio: 'inherit' });
