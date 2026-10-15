// SPDX-License-Identifier: AGPL-3.0-or-later

import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
export function generatedCodes() {
  const source = readFileSync(join(here, '../crates/canon/src/codes.rs'), 'utf8')
  const constants = [...source.matchAll(/pub const ([A-Z][A-Z0-9_]*): &str = "([^"]+)";/g)]
  if (!constants.length) throw new Error('Rust refusal-code registry was empty')
  return '// SPDX-License-Identifier: AGPL-3.0-or-later\n// Generated from crates/canon/src/codes.rs by gen-codes.mjs.\n\n' +
    constants.map(([, name, code]) => `export const ${name} = ${JSON.stringify(code)}`).join('\n') + '\n' +
    `export const ALL = Object.freeze([${constants.map(([, name]) => name).join(', ')}].sort())\n`
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const expected = generatedCodes()
  const target = join(here, 'codes.mjs')
  if (process.argv.includes('--check')) {
    if (readFileSync(target, 'utf8') !== expected) throw new Error('bridge/codes.mjs is stale; run node bridge/gen-codes.mjs')
  } else writeFileSync(target, expected)
}
