// SPDX-License-Identifier: AGPL-3.0-or-later
// Compiles portal/ (erasable TypeScript to ES modules, exactly as app/build.mjs strips it) into a temporary folder so a test can
// import the real modules. Returns { dir, load(name), cleanup() }.
import { stripTypeScriptTypes } from 'node:module';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

export function compilePortal() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'portal-'));
  const walk = (from, to) => {
    fs.mkdirSync(to, { recursive: true });
    for (const entry of fs.readdirSync(from, { withFileTypes: true })) {
      if (entry.isDirectory()) { if (entry.name !== 'joining' && entry.name !== 'vendor') walk(path.join(from, entry.name), path.join(to, entry.name)); continue; }
      if (!entry.name.endsWith('.ts') || entry.name.endsWith('.d.ts')) continue;
      fs.writeFileSync(path.join(to, entry.name.replace(/\.ts$/, '.js')), stripTypeScriptTypes(fs.readFileSync(path.join(from, entry.name), 'utf8'), { mode: 'strip' }));
    }
  };
  walk(path.join(ROOT, 'portal'), dir);
  return { dir, load: name => import(pathToFileURL(path.join(dir, name)).href), cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}
export { ROOT };
