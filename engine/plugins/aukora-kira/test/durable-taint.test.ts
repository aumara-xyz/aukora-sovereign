// SPDX-License-Identifier: AGPL-3.0-or-later
// PL-1: persisted sessions share the door's durable taint and its owner-only clear.
import assert from 'node:assert/strict'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { apply, buildRememberArgs, createKiraController } from '../src/index.ts'
import type { ExecLike, ResultLike, ToolExecutor } from '../src/index.ts'

const allow = async () => ({ kind: 'allow' as const })
const exec = (name: string, args: unknown = {}): ExecLike => ({ name, arguments: args, callId: 'test', token: Symbol() })
const remember = () => exec('kira_remember', buildRememberArgs({ text: 'after restart', subject: 'test' }))

function fixture() {
  const dir = mkdtempSync(join(tmpdir(), 'kira-durable-taint-'))
  const path = join(dir, 'taint.json')
  const execute: ToolExecutor = async (name, args) => {
    assert.equal(name, 'kira_taint')
    if (args.mark === true) writeFileSync(path, '{"v":1,"cause":"engine","since_ms":1}')
    const tainted = existsSync(path)
    if (tainted) JSON.parse(readFileSync(path, 'utf8'))
    return { isError: false, value: { tainted }, content: [] }
  }
  return { execute, path, clean: () => rmSync(path, { force: true }), close: () => rmSync(dir, { recursive: true, force: true }) }
}

test('PL-1: session history taint survives an engine/controller restart', async () => {
  const door = fixture()
  try {
    const before = createKiraController({}, door.execute)
    assert.equal((await before.preExecute(exec('session_search'), allow)).kind, 'allow')
    assert.equal((await before.preExecute(remember(), allow)).kind, 'deny')
    const restarted = createKiraController({}, door.execute)
    const decision = await restarted.preExecute(remember(), allow)
    assert.equal(decision.kind, 'deny', 'restarting a persisted session must not forget its durable taint')
    if (decision.kind === 'deny') assert.equal(decision.info?.code, 'turn-tainted')
  } finally { door.close() }
})

test('PL-1: the owner door clear is reflected by an existing controller; plugin clear cannot clear door', async () => {
  const door = fixture()
  try {
    const controller = createKiraController({}, door.execute)
    await controller.preExecute(exec('subagent'), allow)
    assert.equal((await controller.preExecute(remember(), allow)).kind, 'deny')
    door.clean() // The owner-only POST /api/engine/door/clear-taint removes this authoritative record.
    assert.equal((await controller.preExecute(remember(), allow)).kind, 'allow', 'owner clear must release the existing session too')
  } finally { door.close() }
})

test('PL-1: an unavailable or malformed door taint answer refuses writes and external consumption', async () => {
  for (const reply of [{ isError: true, error: { message: 'down' }, content: [] }, { isError: false, value: {}, content: [] }] as ResultLike[]) {
    const controller = createKiraController({}, async () => reply)
    assert.equal((await controller.preExecute(remember(), allow)).kind, 'deny')
    let ran = false
    assert.equal((await controller.preExecute(exec('session_search'), async () => { ran = true; return { kind: 'allow' } })).kind, 'deny')
    assert.equal(ran, false)
  }
})

test('PL-1: plugin clear cannot override door taint', async () => {
  const door = fixture()
  try {
    const controller = createKiraController({}, door.execute)
    await controller.preExecute(exec('session_search'), allow)
    controller.clearTurnTaint()
    controller.clearTaintAfterCompaction()
    assert.equal((await controller.preExecute(remember(), allow)).kind, 'deny')
  } finally { door.close() }
})


test('PL-1: apply hooks persist before external dispatch and withhold a result if persistence fails', async () => {
  const door = fixture()
  let unavailable = false
  const handlers = new Map<string, (...args: any[]) => Promise<any>>()
  const ctx = {
    tools: {
      register() {},
      execute: async ({ name, arguments: args }: { name: string; arguments: Record<string, unknown> }) => {
        if (unavailable) return { isError: true, error: { message: 'door down' }, content: [] }
        return door.execute(name, args)
      },
    },
    systemPrompt: { section() {} },
    on(event: string, handler: (...args: any[]) => Promise<any>) { handlers.set(event, handler) },
  }
  try {
    apply(ctx as never)
    const pre = handlers.get('tools/pre-execute')!
    const post = handlers.get('tools/post-execute')!
    const search = exec('session_search')
    assert.equal((await pre(search, async () => { assert.equal(existsSync(door.path), true); return { kind: 'allow' } })).kind, 'allow')
    // The owner clears while the external tool is running. Its newly delivered content must taint again.
    door.clean()
    assert.equal((await post(search, { isError: false, value: 'external history', content: [] }, async () => {
      assert.equal(existsSync(door.path), true)
      return { kind: 'accept' }
    })).kind, 'accept')
    unavailable = true
    let released = false
    const withheld = await post(search, { isError: false, value: 'external history', content: [] }, async () => {
      released = true
      return { kind: 'accept' }
    })
    assert.equal(withheld.kind, 'block')
    assert.match(withheld.feedback[0].text, /taint-unavailable/)
    assert.equal(released, false)
  } finally { door.close() }
})

test('PL-1: first web_fetch keeps its existing policy, and successful delivery persists taint', async () => {
  const door = fixture()
  try {
    const controller = createKiraController({}, door.execute)
    const fetch = exec('web_fetch', { url: 'https://example.org/' })
    assert.equal((await controller.preExecute(fetch, async () => {
      assert.equal(existsSync(door.path), false, 'the first fetch must not ask because of its own pre-dispatch marker')
      return { kind: 'allow' }
    })).kind, 'allow')
    assert.equal(await controller.persistResultTaint(fetch, { isError: false, value: 'page', content: [] }), true)
    assert.equal(existsSync(door.path), true)
    // Result observation must not enqueue a redundant mark after the awaited post hook completed.
    door.clean()
    controller.onToolResult(fetch, { isError: false, value: 'page', content: [] })
    assert.equal((await controller.preExecute(remember(), allow)).kind, 'allow')
  } finally { door.close() }
})
