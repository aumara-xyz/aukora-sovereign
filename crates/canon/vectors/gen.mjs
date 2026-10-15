// SPDX-License-Identifier: AGPL-3.0-or-later

import { readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { canonicalJSON, parse } from '../../../bridge/canon.mjs'

const here = dirname(fileURLToPath(import.meta.url))
const writing = process.argv.includes('--write')

// This is Prime's canonicalJSON rule, restated without importing Prime.
function primeCanonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${Array.from(value, primeCanonical).join(',')}]`
  const keys = Object.keys(value).sort()
  return `{${keys.map(key => `${JSON.stringify(key)}:${primeCanonical(value[key])}`).join(',')}}`
}

let checked = 0
for (const file of readdirSync(here).filter(file => file.endsWith('.json')).sort()) {
  const path = join(here, file)
  const fixture = JSON.parse(readFileSync(path, 'utf8'))
  for (const vector of Array.isArray(fixture) ? fixture : [fixture]) {
  if (vector.refusal) continue
  const expected = primeCanonical(JSON.parse(vector.input))
  const twin = canonicalJSON(parse(Buffer.from(vector.input)))
  if (twin !== expected) throw new Error(`${file}: bridge differs from Prime canonicalJSON`)
  if (writing) {
    vector.canonical = expected
    writeFileSync(path, `${JSON.stringify(fixture, null, 2)}\n`)
  } else if (vector.canonical !== expected) {
    throw new Error(`${file}: run gen.mjs --write; expected bytes differ`)
  }
  checked++
  }
}
console.log(`NODE PRIME VECTORS PASS ${checked}`)
