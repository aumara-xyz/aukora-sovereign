// SPDX-License-Identifier: AGPL-3.0-or-later
//
// lib/ is build output, not source. These tests prove the build is reproducible (same bytes every time), that what it
// writes is plain JavaScript that loads outside node_modules-free TypeScript stripping, and that it exports exactly
// what src/ exports.

import assert from 'node:assert/strict'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { build, compile, rewriteSpecifiers } from '../build.mjs'
import * as source from '../src/index.ts'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

function snapshot(dir: string): Record<string, string> {
  return Object.fromEntries(readdirSync(dir).filter(name => name.endsWith('.js')).sort().map(name => [name, readFileSync(join(dir, name), 'utf8')]))
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

test('a build removes only its own stale outputs and refuses to touch any other .js file', () => {
  const project = mkdtempSync(join(tmpdir(), 'door-build-own-'))
  const out = join(project, 'lib')
  try {
    mkdirSync(join(project, 'src'))
    writeFileSync(join(project, 'src', 'x.ts'), 'export const x: number = 1\n')
    assert.deepEqual(build(project, out), ['x.js'])
    // x.ts is renamed y.ts: the old output is ours and untouched, so it goes.
    rmSync(join(project, 'src', 'x.ts'))
    writeFileSync(join(project, 'src', 'y.ts'), 'export const y: number = 2\n')
    assert.deepEqual(build(project, out), ['y.js'])
    assert.equal(existsSync(join(out, 'x.js')), false)
    // A .js file nobody here wrote stops the build and survives it.
    writeFileSync(join(out, 'precious.js'), 'keep me\n')
    assert.throws(() => build(project, out), /precious\.js/)
    assert.equal(readFileSync(join(out, 'precious.js'), 'utf8'), 'keep me\n')
    rmSync(join(out, 'precious.js'))
    // Neither a first build into a directory that already holds somebody's .js file, even one named like an output.
    const elsewhere = join(project, 'elsewhere')
    mkdirSync(elsewhere)
    writeFileSync(join(elsewhere, 'mine.js'), 'not yours\n')
    writeFileSync(join(elsewhere, 'y.js'), 'a different y\n')
    assert.throws(() => build(project, elsewhere), /mine\.js/)
    assert.throws(() => build(project, elsewhere), /y\.js/)
    assert.equal(readFileSync(join(elsewhere, 'mine.js'), 'utf8'), 'not yours\n')
    assert.equal(readFileSync(join(elsewhere, 'y.js'), 'utf8'), 'a different y\n')
  } finally {
    rmSync(project, { recursive: true, force: true })
  }
})

test('a recorded name does not let a later build delete or overwrite a file somebody put there since', () => {
  const project = mkdtempSync(join(tmpdir(), 'door-build-bound-'))
  const out = join(project, 'lib')
  try {
    mkdirSync(join(project, 'src'))
    writeFileSync(join(project, 'src', 'x.ts'), 'export const x: number = 1\n')
    assert.deepEqual(build(project, out), ['x.js'])
    // Somebody replaces the recorded x.js with their own file, and the source x.ts goes away.
    writeFileSync(join(out, 'x.js'), 'theirs\n')
    rmSync(join(project, 'src', 'x.ts'))
    writeFileSync(join(project, 'src', 'y.ts'), 'export const y: number = 2\n')
    assert.throws(() => build(project, out), /x\.js/)
    assert.equal(readFileSync(join(out, 'x.js'), 'utf8'), 'theirs\n')
    // A name in the record that tries to leave the directory is ignored.
    writeFileSync(join(out, '.built-by-build.json'), JSON.stringify({ '../escape.js': 'a'.repeat(64) }))
    rmSync(join(out, 'x.js'))
    assert.deepEqual(build(project, out), ['y.js'])
    assert.equal(existsSync(join(project, 'escape.js')), false)
  } finally {
    rmSync(project, { recursive: true, force: true })
  }
})
