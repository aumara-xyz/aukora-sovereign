// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Unit tests for @aukora/kira: tool schemas, fail-closed in-process bodies, turn-taint enforcement,
// engine ceiling checks, UTF-8 multi-byte boundary truncation, and session-start slot loading.

import assert from 'node:assert/strict'
import test from 'node:test'
import {
  KIRA_REFUSAL_NAME,
  KIRA_TOOL_NAMES,
  KiraDoorRequiredError,
  RESUME_SECTION_ORDER,
  SELF_SECTION_ORDER,
  buildRememberArgs,
  createKiraController,
  createKiraTools,
  isLiveVerifiedNote,
  resolveKiraConfig,
  truncateUtf8,
} from '../src/index.ts'
import type { ExecLike, KiraNote } from '../src/index.ts'
import { createDoor } from '../../aukora-door/src/door.ts'

function sampleNote(overrides: Partial<KiraNote> = {}): KiraNote {
  return {
    id: 'a'.repeat(64),
    seq: 1,
    epoch: 2,
    pubkey: 'b'.repeat(64),
    author: 'owner',
    created_at: 1_760_000_000,
    kind: 30_880,
    content: 'I am Auma.',
    sig: 'c'.repeat(128),
    lane: 'self',
    scope: 'builders',
    subject: 'auma-self',
    form: 'fact',
    privacy: 'builders',
    capture: 'owner-typed',
    owner_signed: true,
    sources: [],
    slot: 'aukora:self',
    superseded_by: null,
    quarantined: false,
    sig_verified: true,
    ...overrides,
  }
}

function makeExec(name: string, args: unknown, agent?: object): ExecLike {
  return {
    callId: 'call-1',
    name,
    arguments: args,
    token: Symbol('exec'),
    ...(agent !== undefined ? { agent } : {}),
  }
}

test('createKiraTools registers the five Kira 2 tools and fails closed if invoked without the door', async () => {
  const tools = createKiraTools()
  assert.deepEqual(tools.map(t => t.name), [...KIRA_TOOL_NAMES])
  for (const tool of tools) {
    assert.equal(tool.parameters.type, 'object')
    assert.equal(tool.parameters.additionalProperties, false)
    await assert.rejects(
      () => tool.execute({}),
      (err: unknown) =>
        err instanceof KiraDoorRequiredError &&
        err.name === KIRA_REFUSAL_NAME &&
        err.code === 'door-required',
    )
  }
})

test('truncateUtf8 respects byte boundaries without splitting multi-byte code points', () => {
  // '🌊' is 4 UTF-8 bytes; 'é' is 2 UTF-8 bytes.
  const text = 'A🌊BéC'
  assert.equal(Buffer.byteLength(text, 'utf8'), 1 + 4 + 1 + 2 + 1)

  const exact = truncateUtf8(text, 9)
  assert.equal(exact.truncated, false)
  assert.equal(exact.text, text)

  // Cutting at 3 bytes lands inside '🌊' (bytes 1..4) -> must back up to 'A' (1 byte).
  const cutInsideEmoji = truncateUtf8(text, 3)
  assert.equal(cutInsideEmoji.truncated, true)
  assert.equal(cutInsideEmoji.text, 'A')
  assert.equal(cutInsideEmoji.byteLength, 1)

  // Cutting at 5 bytes fits 'A🌊' exactly.
  const fitEmoji = truncateUtf8(text, 5)
  assert.equal(fitEmoji.truncated, true)
  assert.equal(fitEmoji.text, 'A🌊')
  assert.equal(fitEmoji.byteLength, 5)

  // Cutting at 7 bytes lands inside 'é' (bytes 6..7) -> must back up to 'A🌊B' (6 bytes).
  const cutInsideAccent = truncateUtf8(text, 7)
  assert.equal(cutInsideAccent.truncated, true)
  assert.equal(cutInsideAccent.text, 'A🌊B')
  assert.equal(cutInsideAccent.byteLength, 6)
})

test('isLiveVerifiedNote refuses superseded, quarantined, withheld, unverified and empty notes', () => {
  assert.equal(isLiveVerifiedNote(sampleNote()), true)
  assert.equal(isLiveVerifiedNote(sampleNote({ superseded_by: '2'.repeat(64) })), false)
  assert.equal(isLiveVerifiedNote(sampleNote({ quarantined: true })), false)
  assert.equal(isLiveVerifiedNote(sampleNote({ withheld: true })), false)
  assert.equal(isLiveVerifiedNote(sampleNote({ sig_verified: false })), false)
  assert.equal(isLiveVerifiedNote(sampleNote({ content: '' })), false)
})

test('turn taint forces capture: "web-derived" on kira_remember across steps until the next turn', async () => {
  const controller = createKiraController({}, async () => ({ isError: false, value: { notes: [] }, content: [] }))
  const agent = {}

  // Before any web/MCP call, model-generated is allowed.
  const cleanArgs = buildRememberArgs({ text: 'clean finding', subject: 'test' })
  const cleanDecision = await controller.preExecute(makeExec('kira_remember', cleanArgs, agent), async () => ({ kind: 'allow' }))
  assert.equal(cleanDecision.kind, 'allow')

  // A web_fetch call taints the turn for this agent.
  await controller.preExecute(makeExec('web_fetch', { url: 'https://example.org/' }, agent), async () => ({ kind: 'allow' }))
  assert.equal(controller.isTurnTainted(agent), true)

  // Now model-generated is denied with turn-tainted.
  const taintedAttempt = await controller.preExecute(makeExec('kira_remember', cleanArgs, agent), async () => ({ kind: 'allow' }))
  assert.equal(taintedAttempt.kind, 'deny')
  if (taintedAttempt.kind === 'deny') {
    assert.equal(taintedAttempt.info?.code, 'turn-tainted')
  }

  // With capture: "web-derived", kira_remember is allowed in the tainted turn.
  const webDerivedArgs = buildRememberArgs({ text: 'from example.org', subject: 'test', capture: 'web-derived' })
  const webDerivedDecision = await controller.preExecute(makeExec('kira_remember', webDerivedArgs, agent), async () => ({ kind: 'allow' }))
  assert.equal(webDerivedDecision.kind, 'allow')

  // Clearing taint at the start of the next turn restores model-generated.
  controller.clearTurnTaint(agent)
  assert.equal(controller.isTurnTainted(agent), false)
  const nextTurnDecision = await controller.preExecute(makeExec('kira_remember', cleanArgs, agent), async () => ({ kind: 'allow' }))
  assert.equal(nextTurnDecision.kind, 'allow')
})

const allow = async () => ({ kind: 'allow' as const })

test('memory_remember, which the Rust door forwards to the same Kira write, is held to the same taint', async () => {
  const controller = createKiraController({}, async () => ({ isError: false, value: {}, content: [] }))
  const agent = {}
  await controller.preExecute(makeExec('web_fetch', { url: 'https://example.org/' }, agent), allow)
  const args = buildRememberArgs({ text: 'laundered through the alias', subject: 'test' })
  const decision = await controller.preExecute(makeExec('memory_remember', args, agent), allow)
  assert.equal(decision.kind, 'deny')
  if (decision.kind === 'deny') assert.equal(decision.info?.code, 'turn-tainted')
  const ceiling = await controller.preExecute(makeExec('memory_remember', { ...args, lane: 'decision' }), allow)
  assert.equal(ceiling.kind, 'deny')
})

test('a delegated agent that read the web taints the caller when its result comes back', async () => {
  const controller = createKiraController({}, async () => ({ isError: false, value: {}, content: [] }))
  const parent = {}
  const child = {}
  const clean = buildRememberArgs({ text: 'child said so', subject: 'test' })
  // A delegation during which nothing was tainted leaves the caller clean.
  const quiet = makeExec('subagent', { prompt: 'think' }, parent)
  await controller.preExecute(quiet, allow)
  controller.onToolResult(quiet, { isError: false, value: 'thought', content: [] })
  assert.equal(controller.isTurnTainted(parent), false)
  // The child fetches inside its own turn; its text comes back as the subagent result.
  const spawn = makeExec('subagent', { prompt: 'look it up' }, parent)
  await controller.preExecute(spawn, allow)
  await controller.preExecute(makeExec('web_fetch', { url: 'https://example.org/' }, child), allow)
  controller.onToolResult(spawn, { isError: false, value: 'example.org says...', content: [] })
  assert.equal(controller.isTurnTainted(parent), true)
  const decision = await controller.preExecute(makeExec('kira_remember', clean, parent), allow)
  assert.equal(decision.kind, 'deny')
  // A delegation result the plugin never saw start is assumed tainted.
  const other = {}
  controller.onToolResult(makeExec('workflow', { script: 'x' }, other), { isError: false, value: 'done', content: [] })
  assert.equal(controller.isTurnTainted(other), true)
})

test('reading a web-derived note back from Kira taints the turn', async () => {
  const controller = createKiraController({}, async () => ({ isError: false, value: {}, content: [] }))
  const agent = {}
  const ok = (value: unknown) => ({ isError: false as const, value, content: [] })
  controller.onToolResult(makeExec('kira_recall', { query: 'x' }, agent), ok({ items: [{ capture: 'model-generated' }] }))
  assert.equal(controller.isTurnTainted(agent), false)
  controller.onToolResult(makeExec('kira_recall', { query: 'x' }, agent), ok({ items: [{ capture: 'web-derived' }] }))
  assert.equal(controller.isTurnTainted(agent), true)
  for (const [name, value] of [['kira_get', { capture: 'web-derived' }], ['kira_list_recent', { notes: [{ capture: 'web-derived' }] }]] as const) {
    const fresh = {}
    controller.onToolResult(makeExec(name, {}, fresh), ok(value))
    assert.equal(controller.isTurnTainted(fresh), true, name)
  }
})

test('behind @aukora/door (prepended, first), the taint deny still decides: the door passes through to it', async () => {
  const door = createDoor({ socketPath: '/nonexistent/door.sock', workspaceRoots: ['/sandbox'] })
  const controller = createKiraController({}, async () => ({ isError: false, value: {}, content: [] }))
  const agent = {}
  const chain = (exec: ExecLike) => door.preExecute(exec, () => controller.preExecute(exec, allow))
  assert.equal((await chain(makeExec('web_fetch', { url: 'https://example.org/' }, agent))).kind, 'allow')
  const decision = await chain(makeExec('kira_remember', buildRememberArgs({ text: 'x', subject: 'y' }), agent))
  assert.equal(decision.kind, 'deny')
  if (decision.kind === 'deny') assert.equal(decision.info?.code, 'turn-tainted')
})

test('preExecute enforces engine ceilings without mutating exec.arguments', async () => {
  const controller = createKiraController({}, async () => ({ isError: false, value: { notes: [] }, content: [] }))

  const closedLaneArgs = Object.freeze({
    ...buildRememberArgs({ text: 'ruling', subject: 'test' }),
    lane: 'decision',
  })
  const laneDecision = await controller.preExecute(makeExec('kira_remember', closedLaneArgs), async () => ({ kind: 'allow' }))
  assert.equal(laneDecision.kind, 'deny')
  if (laneDecision.kind === 'deny') assert.equal(laneDecision.info?.code, 'lane-closed')

  const ownerSignedArgs = Object.freeze({
    ...buildRememberArgs({ text: 'forged', subject: 'test' }),
    owner_signed: true,
  })
  const ownerDecision = await controller.preExecute(makeExec('kira_remember', ownerSignedArgs), async () => ({ kind: 'allow' }))
  assert.equal(ownerDecision.kind, 'deny')
  if (ownerDecision.kind === 'deny') assert.equal(ownerDecision.info?.code, 'owner-only')

  const slotArgs = Object.freeze({
    ...buildRememberArgs({ text: 'self hijack', subject: 'test' }),
    slot: 'aukora:self',
  })
  const slotDecision = await controller.preExecute(makeExec('kira_remember', slotArgs), async () => ({ kind: 'allow' }))
  assert.equal(slotDecision.kind, 'deny')
  if (slotDecision.kind === 'deny') assert.equal(slotDecision.info?.code, 'lane-closed')

  const captureArgs = Object.freeze({
    ...buildRememberArgs({ text: 'owner-typed hijack', subject: 'test' }),
    capture: 'owner-typed',
  })
  const captureDecision = await controller.preExecute(makeExec('kira_remember', captureArgs), async () => ({ kind: 'allow' }))
  assert.equal(captureDecision.kind, 'deny')
  if (captureDecision.kind === 'deny') assert.equal(captureDecision.info?.code, 'capture-ceiling')
})

test('session-start slot loader caps aukora:self at 4 KiB and aukora:resume at 2 KiB with interpolate: false', async () => {
  const oversizedSelf = 'S'.repeat(5_000)
  const resumeWithBraces = 'Resume state with literal {{unregistered_var}} braces — ' + 'R'.repeat(2_500)

  const asked: unknown[] = []
  const controller = createKiraController({}, async (name, args) => {
    assert.equal(name, 'kira_get')
    asked.push(args)
    const slot = (args as { id: string }).id
    const content = slot === 'aukora:self' ? oversizedSelf : resumeWithBraces
    return { isError: false, value: sampleNote({ slot, lane: slot.slice(7), content }), content: [{ type: 'text', text: '{}' }] }
  })

  const assembly = {
    sections: [
      { name: 'aukora:self', text: '', interpolate: false },
      { name: 'aukora:resume', text: '', interpolate: false },
    ],
    contexts: [],
    tools: [],
    variables: {},
  }

  const assembled = await controller.assemblePrompt(assembly, async () => assembly)
  const selfSec = assembled.sections.find(s => s.name === 'aukora:self')!
  const resumeSec = assembled.sections.find(s => s.name === 'aukora:resume')!

  assert.equal(Buffer.byteLength(selfSec.text, 'utf8'), 4_096)
  assert.equal(selfSec.interpolate, false)
  assert.equal(Buffer.byteLength(resumeSec.text, 'utf8'), 2_048)
  assert.equal(resumeSec.interpolate, false)
  assert.ok(resumeSec.text.includes('{{unregistered_var}}'))
  assert.equal(controller.selfSection().order, SELF_SECTION_ORDER)
  assert.equal(controller.resumeSection().order, RESUME_SECTION_ORDER)
  // Each slot is one kira_get by name, through the door; no scan of recent notes.
  assert.deepEqual(asked, [{ id: 'aukora:self' }, { id: 'aukora:resume' }])
})

test('slot loading: an empty slot is loaded as empty, a door outage retries, a mismatched or dead note is never injected', async () => {
  const refusal = (code: string) => ({ isError: true as const, error: { message: code, info: { name: 'AukoraDoorRefusal', code } }, content: [] })
  let reply: (slot: string) => unknown = () => refusal('kira-unavailable')
  const controller = createKiraController({}, async (_name, args) => reply((args as { id: string }).id) as never)
  assert.equal((await controller.ensureSlotsLoaded()).loaded, false, 'the door is down: not loaded, retried later')
  reply = slot => (slot === 'aukora:self' ? refusal('kira:not-found') : refusal('kira-unavailable'))
  assert.equal((await controller.ensureSlotsLoaded()).loaded, false, 'half an answer is not an answer')
  reply = () => refusal('kira:not-found')
  assert.deepEqual(await controller.ensureSlotsLoaded(), { selfText: '', resumeText: '', loaded: true })
  // A reply for another slot, or a superseded or quarantined note, is not injected.
  const ok = (value: unknown) => ({ isError: false as const, value, content: [] })
  reply = slot => ok(slot === 'aukora:self' ? sampleNote({ slot: 'resume:grok', content: 'I am Grok' }) : sampleNote({ slot, quarantined: true }))
  assert.deepEqual(await controller.ensureSlotsLoaded(true), { selfText: '', resumeText: '', loaded: true })
})

test('resolveKiraConfig validates bounds', () => {
  assert.throws(() => resolveKiraConfig({ maxSelfBytes: 10 }))
  assert.throws(() => resolveKiraConfig({ maxResumeBytes: 65_537 }))
  assert.throws(() => resolveKiraConfig({ selfSlot: '' }))
})
