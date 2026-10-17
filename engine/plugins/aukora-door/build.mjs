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

/** Build every src/*.ts under `root` into `outDir`; returns the file names written. */
export function build(root = here, outDir = join(root, 'lib')) {
  const srcDir = join(root, 'src')
  const names = readdirSync(srcDir).filter(name => name.endsWith('.ts')).sort()
  mkdirSync(outDir, { recursive: true })
  // Only stale .js files go (never the directory), so a mistyped outDir cannot delete anything else.
  for (const stale of readdirSync(outDir)) if (stale.endsWith('.js')) rmSync(join(outDir, stale))
  for (const name of names) {
    writeFileSync(join(outDir, name.replace(/\.ts$/, '.js')), compile(readFileSync(join(srcDir, name), 'utf8'), name))
  }
  return names.map(name => name.replace(/\.ts$/, '.js'))
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const out = process.argv[2] === undefined ? undefined : resolve(process.argv[2])
  const written = build(here, out)
  console.log(`built ${written.length} files: ${written.join(' ')}`)
}
