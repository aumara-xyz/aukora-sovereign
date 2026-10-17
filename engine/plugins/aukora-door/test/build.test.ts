// SPDX-License-Identifier: AGPL-3.0-or-later
//
// lib/ is build output, not source. These tests prove the build is reproducible (same bytes every time), that what it
// writes is plain JavaScript that loads outside node_modules-free TypeScript stripping, and that it exports exactly
// what src/ exports.

import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { build, compile, rewriteSpecifiers } from '../build.mjs'
import * as source from '../src/index.ts'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

function snapshot(dir: string): Record<string, string> {
  return Object.fromEntries(readdirSync(dir).sort().map(name => [name, readFileSync(join(dir, name), 'utf8')]))
}

test('rebuilding gives identical bytes, and every src file has an output', () => {
  const a = mkdtempSync(join(tmpdir(), 'door-build-a-'))
  const b = mkdtempSync(join(tmpdir(), 'door-build-b-'))
  try {
    const first = build(root, a)
    const second = build(root, b)
    assert.deepEqual(first, second)
    assert.deepEqual(snapshot(a), snapshot(b))
    const sources = readdirSync(join(root, 'src')).filter(name => name.endsWith('.ts')).map(name => name.replace(/\.ts$/, '.js')).sort()
    assert.deepEqual(first, sources)
    build(root, a)
    assert.deepEqual(snapshot(a), snapshot(b), 'a rebuild over an existing directory is the same too')
  } finally {
    rmSync(a, { recursive: true, force: true })
    rmSync(b, { recursive: true, force: true })
  }
})

test('built files are JavaScript with no .ts specifier left, and they export what src exports', async () => {
  const out = mkdtempSync(join(tmpdir(), 'door-build-load-'))
  try {
    build(root, out)
    for (const [name, text] of Object.entries(snapshot(out))) {
      assert.doesNotMatch(text, /from\s*['"]\.{1,2}\/[^'"]*\.ts['"]/, name)
      assert.doesNotMatch(text, /import\s*\(\s*['"]\.{1,2}\/[^'"]*\.ts['"]/, name)
    }
    const built = (await import(pathToFileURL(join(out, 'index.js')).href)) as typeof source
    assert.deepEqual(Object.keys(built).sort(), Object.keys(source).sort())
    assert.equal(built.name, 'aukora-door')
    assert.deepEqual(built.inject, ['tools'])
    // Behaviour, not just names: the built classifier agrees with the source one.
    for (const [tool, args] of [['read', { file_path: '/etc/passwd' }], ['web_fetch', {}], ['terminal_send', {}], ['present', { files: [{ path: 'a' }] }]] as const) {
      assert.equal(built.classifyCall(tool, args, ['/sandbox']), source.classifyCall(tool, args, ['/sandbox']), tool)
    }
  } finally {
    rmSync(out, { recursive: true, force: true })
  }
})

test('specifier rewriting touches only relative .ts imports and exports', () => {
  assert.equal(rewriteSpecifiers("import { a } from './a.ts'"), "import { a } from './a.js'")
  assert.equal(rewriteSpecifiers('export * from "../b.ts"'), 'export * from "../b.js"')
  assert.equal(rewriteSpecifiers("const m = await import('./c.ts')"), "const m = await import('./c.js')")
  assert.equal(rewriteSpecifiers("import 'node:fs'"), "import 'node:fs'")
  assert.equal(rewriteSpecifiers("import x from 'pkg/file.ts'"), "import x from 'pkg/file.ts'")
})

test('only erasable TypeScript builds', () => {
  assert.throws(() => compile('enum E { A }\n', 'e.ts'))
})

test('package.json points at the build output and declares the DSH bundle patch', () => {
  const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as Record<string, any>
  assert.equal(pkg.main, './lib/index.js')
  assert.equal(pkg.exports['.'].default, './lib/index.js')
  assert.deepEqual(pkg.dsh, { bundle: { patch: './cordis.patch.yml' } })
  assert.ok(readFileSync(join(root, 'cordis.patch.yml'), 'utf8').includes("name: '@aukora/door'"))
  assert.equal(readFileSync(join(root, '.gitignore'), 'utf8').split('\n').includes('/lib/'), true)
})
