// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Build src/*.ts into lib/*.js with no dependencies: Node 24's own type stripper (`module.stripTypeScriptTypes`),
// then `.ts` import specifiers become `.js`. DSH loads plugins from JavaScript under node_modules, where Node refuses
// to strip types, so the package entry points at lib/.
//
//   node build.mjs [outDir]      default outDir: ./lib (next to this file)
//
// The output is a pure function of src/: same bytes on every run, so lib/ is not committed (see .gitignore) and
// test/build.test.ts rebuilds twice and compares. Only erasable TypeScript is accepted (no enums, parameter
// properties or namespaces); the stripper throws on anything else, and so does this script on a specifier it could
// not rewrite.

import { readFileSync, readdirSync, writeFileSync, mkdirSync, rmSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { stripTypeScriptTypes } from 'node:module'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))

// A relative specifier in `from '...'` or `import('...')` that ends in `.ts`.
const SPECIFIER = /(\bfrom\s*|\bimport\s*\(\s*|\bimport\s*)(['"])(\.{1,2}\/[^'"\n]*?)\.ts\2/g

/** Rewrite relative `.ts` specifiers to `.js`. */
export function rewriteSpecifiers(code) {
  return code.replace(SPECIFIER, (_, lead, quote, path) => `${lead}${quote}${path}.js${quote}`)
}

/** Turn one TypeScript source text into JavaScript. */
export function compile(source, file) {
  const stripped = stripTypeScriptTypes(source, { mode: 'strip' })
  const code = rewriteSpecifiers(stripped)
  const left = /(?:from\s*|import\s*\(?\s*)['"]\.{1,2}\/[^'"\n]*\.ts['"]/.exec(code)
  if (left) throw new Error(`build: ${file}: a relative .ts specifier survived: ${left[0]}`)
  return code
}

/** What the last build wrote, name to sha256, kept next to its output so a later build can tell its own files from anyone else's. */
const RECORD = '.built-by-build.json'

const sha256 = text => createHash('sha256').update(text).digest('hex')

function previousOutputs(outDir) {
  try {
    const record = JSON.parse(readFileSync(join(outDir, RECORD), 'utf8'))
    const entries = Object.entries(record).filter(([name, digest]) => /^[A-Za-z0-9_-]+\.js$/.test(name) && typeof digest === 'string' && /^[0-9a-f]{64}$/.test(digest))
    return new Map(entries)
  } catch {
    return new Map()
  }
}

/**
 * Build every src/*.ts under `root` into `outDir`; returns the file names written. A .js file already in `outDir` is
 * ours only if the last build recorded it and its bytes are still what was recorded, or it is byte-identical to what
 * this build is about to write. Anything else (somebody's file, or one of ours that was edited) stops the build
 * before it touches anything: a mistyped outDir cannot cost anyone a file. A recorded file whose source is gone is
 * removed, since it is untouched since the build wrote it.
 */
export function build(root = here, outDir = join(root, 'lib')) {
  const srcDir = join(root, 'src')
  const names = readdirSync(srcDir).filter(name => name.endsWith('.ts')).sort()
  // Compile everything first: a source that does not compile leaves the directory as it was.
  const outputs = new Map(names.map(name => [name.replace(/\.ts$/, '.js'), compile(readFileSync(join(srcDir, name), 'utf8'), name)]))
  mkdirSync(outDir, { recursive: true })
  const before = previousOutputs(outDir)
  const foreign = []
  for (const name of readdirSync(outDir).filter(file => file.endsWith('.js'))) {
    const current = sha256(readFileSync(join(outDir, name)))
    const ours = before.get(name) === current || (outputs.has(name) && sha256(outputs.get(name)) === current)
    if (!ours) foreign.push(name)
  }
  if (foreign.length > 0) throw new Error(`build: ${outDir} holds .js files this build did not write (or that were changed since): ${foreign.join(' ')}; remove them or build elsewhere`)
  for (const name of before.keys()) if (!outputs.has(name)) rmSync(join(outDir, name), { force: true })
  for (const [name, code] of outputs) writeFileSync(join(outDir, name), code)
  writeFileSync(join(outDir, RECORD), `${JSON.stringify(Object.fromEntries([...outputs].map(([name, code]) => [name, sha256(code)])))}\n`)
  return [...outputs.keys()]
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const out = process.argv[2] === undefined ? undefined : resolve(process.argv[2])
  const written = build(here, out)
  console.log(`built ${written.length} files: ${written.join(' ')}`)
}
