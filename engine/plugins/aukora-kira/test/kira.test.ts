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
  apply,
  buildRememberArgs,
  createKiraController,
  createKiraTools,
  isLiveVerifiedNote,
  isTaintingTool,
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

// The service side of this (a real recall mixing an owner-words note and an unverified lead, and the wording of both
// statuses) is crates/kira/src/shared/service/tests/recall_wording.rs. Here: the tool tells the model what the
// message means, and a service-shaped mixed `found` reply reaches the model unchanged, labels and message included.
test('recall tool describes evidence-backed leads and renders a mixed found reply with its per-note labels intact', () => {
  const recall = createKiraTools().find(t => t.name === 'kira_recall')!
  assert.ok(recall.description.includes("Related notes were found, but K2 couldn't establish an evidence-backed answer. Use these as leads to check."))
  assert.ok(recall.description.includes('found does not verify every returned claim'))
  const item = (id: string, evidence: string, capture: string) => ({
    id, author: 'f'.repeat(64), author_name: 'claude', text: `note ${id}`, score: 0.5, capture, evidence,
    state: evidence === 'unverified' ? 'proposed' : 'supported', validity: 'current', lineage: 'unsupported',
    also_by: [], correction: null, current_id: null,
  })
  const reply = {
    status: 'found',
    reason: null,
    message: 'Evidence labels apply to each note; found does not verify every returned claim.',
    items: [item('d'.repeat(64), 'owner-words', 'owner-typed'), item('e'.repeat(64), 'unverified', 'model-generated')],
    omitted: 0, indexed: 2, total: 2, query_digest: '0'.repeat(64), states: { proposed: 1, supported: 1 },
    judged: { by: 'keyword', rerank_floor: null, cosine_floor: null },
  }
  const rendered = JSON.parse(recall.output.render({}, reply)[0].text)
  assert.deepEqual(rendered, reply)
  assert.deepEqual(rendered.items.map((i: { evidence: string }) => i.evidence), ['owner-words', 'unverified'])
  assert.equal(rendered.message, reply.message)
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
  assert.equal(isLiveVerifiedNote(sampleNote({ capture: 'web-derived' })), false, 'an old web-derived slot note is never injected')
  assert.equal(isLiveVerifiedNote(sampleNote({ superseded_by: '2'.repeat(64) })), false)
  assert.equal(isLiveVerifiedNote(sampleNote({ quarantined: true })), false)
  assert.equal(isLiveVerifiedNote(sampleNote({ withheld: true })), false)
  assert.equal(isLiveVerifiedNote(sampleNote({ sig_verified: false })), false)
  assert.equal(isLiveVerifiedNote(sampleNote({ content: '' })), false)
})

test('session taint forces capture: "web-derived" on kira_remember in every later turn, step and agent of the session', async () => {
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

  // A new turn does NOT restore model-generated: the session history still holds what was fetched (Argon RT-2).
  controller.clearTurnTaint(agent)
  assert.equal(controller.isTurnTainted(agent), true)
  const nextTurnDecision = await controller.preExecute(makeExec('kira_remember', cleanArgs, agent), async () => ({ kind: 'allow' }))
  assert.equal(nextTurnDecision.kind, 'deny')
  // Only a host that has proof the content left the context (a compaction that dropped it) clears the session.
  controller.clearTaintAfterCompaction()
  assert.equal(controller.isTurnTainted(agent), false)
  assert.equal((await controller.preExecute(makeExec('kira_remember', cleanArgs, agent), async () => ({ kind: 'allow' }))).kind, 'allow')
})

test('one session state: a child agent, a call with no agent and the parent after an async delivery all share it (RT-1, RT-3)', async () => {
  const controller = createKiraController({}, async () => ({ isError: false, value: {}, content: [] }))
  const parent = {}
  const child = {}
  const clean = buildRememberArgs({ text: 'from a child', subject: 'test' })
  await controller.preExecute(makeExec('web_fetch', { url: 'https://example.org/' }, parent), allow)
  // The child is a fresh agent object created after the parent was tainted: it inherits, it does not start clean.
  assert.equal(controller.isTurnTainted(child), true)
  assert.equal((await controller.preExecute(makeExec('kira_remember', clean, child), allow)).kind, 'deny', 'RT-1A: parent -> child laundering')
  // An agentless call (ctx.tools.execute without exec.agent) reads the same state (RT-3).
  assert.equal((await controller.preExecute(makeExec('kira_remember', clean), allow)).kind, 'deny', 'RT-3: agentless write')
  // The other direction: a child that reads the web taints the parent that is woken with its output later (RT-1B).
  const fresh = createKiraController({}, async () => ({ isError: false, value: {}, content: [] }))
  await fresh.preExecute(makeExec('web_fetch', { url: 'https://example.org/' }, child), allow)
  assert.equal(fresh.isTurnTainted(parent), true, 'RT-1B: the parent shares the child\'s taint when its output is delivered')
  assert.equal((await fresh.preExecute(makeExec('kira_remember', clean, parent), allow)).kind, 'deny')
  // An agentless taint (e.g. a slot read) is seen by every agent, which the old split state ignored.
  const slot = createKiraController({}, async () => ({ isError: false, value: {}, content: [] }))
  slot.markTurnTainted()
  assert.equal(slot.isTurnTainted(parent), true)
})

test('session history tools taint: they can surface a web_fetch result from an earlier turn (RT-6)', async () => {
  for (const name of ['session_search', 'session_event_search', 'session_trace', 'session_event_trace', 'session_event_read']) {
    assert.equal(isTaintingTool(name), true, name)
    const controller = createKiraController({}, async () => ({ isError: false, value: {}, content: [] }))
    const agent = {}
    await controller.preExecute(makeExec(name, { query: 'earlier' }, agent), allow)
    assert.equal(controller.isTurnTainted(agent), true, name)
    assert.equal((await controller.preExecute(makeExec('kira_remember', buildRememberArgs({ text: 'x', subject: 'y' }), agent), allow)).kind, 'deny', name)
  }
})

test('a recall group whose folded copy is web-derived taints, even when the shown note is model-generated (RT-5)', () => {
  const controller = createKiraController({}, async () => ({ isError: false, value: {}, content: [] }))
  const agent = {}
  const ok = (value: unknown) => ({ isError: false as const, value, content: [] })
  controller.onToolResult(makeExec('kira_recall', { query: 'x' }, agent), ok({ items: [{ capture: 'model-generated', kept_capture: 'model-generated', also_by_captures: ['model-generated'] }] }))
  assert.equal(controller.isTurnTainted(agent), false)
  controller.onToolResult(makeExec('kira_recall', { query: 'x' }, agent), ok({ items: [{ capture: 'model-generated', also_by_captures: ['web-derived'] }] }))
  assert.equal(controller.isTurnTainted(agent), true)
})

test('the plugin hooks neither clear taint at a new turn nor when an agent is created (RT-1, RT-2)', async () => {
  const handlers = new Map<string, Array<(...args: never[]) => unknown>>()
  const ctx = {
    tools: { register() {}, async execute() { return { isError: true, error: { message: 'down', info: { code: 'x' } }, content: [] } } },
    systemPrompt: { section() {} },
    on(event: string, handler: (...args: never[]) => unknown) {
      handlers.set(event, [...(handlers.get(event) ?? []), handler])
    },
  }
  const controller = apply(ctx as never)
  const agent = {}
  const child = {}
  controller.markTurnTainted(agent)
  for (const step of [1, 2, 1]) {
    for (const handler of handlers.get('agent/pre-step') ?? []) await (handler as (p: unknown, n: () => Promise<void>) => Promise<unknown>)({ agent, step }, async () => {})
  }
  for (const handler of handlers.get('agent/created') ?? []) await (handler as (p: unknown) => Promise<unknown>)({ agent: child })
  assert.equal(controller.isTurnTainted(agent), true, 'turn 2, step 1 must not clear it')
  assert.equal(controller.isTurnTainted(child), true, 'a child created afterwards inherits it')
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

test('every delegation taints the caller: a child in another process cannot report its own taint here', async () => {
  const clean = buildRememberArgs({ text: 'child said so', subject: 'test' })
  for (const tool of ['subagent', 'subagent_fork', 'ralph', 'workflow', 'wait_agent', 'spawn_teammate', 'team_task_get', 'team_task_list']) {
    // The parent's controller never sees the child's web_fetch (fresh process); the result alone taints.
    const parent = createKiraController({}, async () => ({ isError: false, value: {}, content: [] }))
    const agent = {}
    const spawn = makeExec(tool, { prompt: 'look it up' }, agent)
    assert.equal((await parent.preExecute(spawn, allow)).kind, 'allow')
    parent.onToolResult(spawn, { isError: false, value: 'example.org says...', content: [] })
    assert.equal(parent.isTurnTainted(agent), true, tool)
    const decision = await parent.preExecute(makeExec('kira_remember', clean, agent), allow)
    assert.equal(decision.kind, 'deny', tool)
  }
  // A result whose start was never seen taints too.
  const other = createKiraController({}, async () => ({ isError: false, value: {}, content: [] }))
  const agent = {}
  other.onToolResult(makeExec('subagent', { prompt: 'x' }, agent), { isError: false, value: 'done', content: [] })
  assert.equal(other.isTurnTainted(agent), true)
})

test('superseding a web-derived note returns its text, so it taints the turn under either name', async () => {
  const ok = (value: unknown) => ({ isError: false as const, value, content: [] })
  for (const name of ['kira_supersede', 'memory_supersede']) {
    const controller = createKiraController({}, async () => ({ isError: false, value: {}, content: [] }))
    const agent = {}
    controller.onToolResult(makeExec(name, { target: 'a'.repeat(64) }, agent), ok({ event: 'e', target: { text: 'own words', capture: 'model-generated' } }))
    assert.equal(controller.isTurnTainted(agent), false, name)
    controller.onToolResult(makeExec(name, { target: 'a'.repeat(64) }, agent), ok({ event: 'e', target: { text: 'web content', capture: 'web-derived' } }))
    assert.equal(controller.isTurnTainted(agent), true, name)
    const decision = await controller.preExecute(makeExec('kira_remember', buildRememberArgs({ text: 'web content', subject: 's' }), agent), allow)
    assert.equal(decision.kind, 'deny', name)
  }
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

test('slot refresh withholds a failed slot, applies the other withdrawal, and retries only the failed read', async t => {
  for (const failedSlot of ['aukora:self', 'aukora:resume']) {
    for (const failure of ['refusal', 'throw']) {
      await t.test(`${failedSlot}: ${failure}`, async () => {
        let phase = 'initial'
        const asked: string[] = []
        const controller = createKiraController({}, async (_name, args) => {
          const slot = args.id as string
          asked.push(slot)
          if (phase === 'refresh') {
            if (slot === failedSlot) {
              if (failure === 'throw') throw new Error('door unavailable')
              return { isError: true, error: { message: 'refused', info: { name: 'AukoraDoorRefusal', code: 'refused' } }, content: [] }
            }
            return { isError: false, value: sampleNote({ slot, superseded_by: '2'.repeat(64) }), content: [] }
          }
          return { isError: false, value: sampleNote({ id: (phase === 'retry' ? '3' : 'a').repeat(64), slot, content: `${phase} ${slot}` }), content: [] }
        })
        await controller.ensureSlotsLoaded()
        assert.equal(controller.slotHead(failedSlot), 'a'.repeat(64))
        phase = 'refresh'
        assert.deepEqual(await controller.ensureSlotsLoaded(true), { selfText: '', resumeText: '', loaded: false })
        assert.equal(controller.selfText(), '', 'the withdrawn or unverifiable self note is withheld')
        assert.equal(controller.resumeText(), '', 'the withdrawn or unverifiable resume note is withheld')
        assert.equal(controller.slotHead(failedSlot), undefined, 'a failed refresh cannot supply a stale expected_head')
        phase = 'retry'
        asked.length = 0
        const loaded = await controller.ensureSlotsLoaded()
        assert.equal(loaded.loaded, true)
        assert.deepEqual(asked, [failedSlot], 'the successful withdrawal was already applied')
        assert.equal(controller.selfText(), failedSlot === 'aukora:self' ? `retry ${failedSlot}` : '')
        assert.equal(controller.resumeText(), failedSlot === 'aukora:resume' ? `retry ${failedSlot}` : '')
        assert.equal(controller.slotHead(failedSlot), 'a'.repeat(64), 'a successful retry cannot advance the session head')
        assert.equal(controller.slotHead(failedSlot === 'aukora:self' ? 'aukora:resume' : 'aukora:self'), undefined, 'the withdrawn note cannot supply a head')
      })
    }
  }
})

test('a forced refresh waits for a partial retry and then rechecks both slots', async () => {
  let phase = 'initial'
  let finishRetry!: () => void
  const retryGate = new Promise<void>(resolve => { finishRetry = resolve })
  const asked: string[] = []
  const controller = createKiraController({}, async (_name, args) => {
    const slot = args.id as string
    asked.push(slot)
    if (phase === 'initial' && slot === 'aukora:resume') {
      return { isError: true, error: { message: 'unavailable' }, content: [] }
    }
    if (phase === 'retry' && slot === 'aukora:resume') {
      await retryGate
      return { isError: false, value: sampleNote({ slot, content: 'resume before forced refresh' }), content: [] }
    }
    return { isError: false, value: sampleNote({ slot, superseded_by: phase === 'refresh' ? '2'.repeat(64) : null }), content: [] }
  })
  assert.equal((await controller.ensureSlotsLoaded()).loaded, false)
  assert.equal(controller.selfText(), 'I am Auma.')
  phase = 'retry'
  asked.length = 0
  const retry = controller.ensureSlotsLoaded()
  const refresh = controller.ensureSlotsLoaded(true)
  assert.deepEqual(asked, ['aukora:resume'], 'the forced reads wait for the earlier read to finish')
  phase = 'refresh'
  finishRetry()
  await retry
  assert.deepEqual(await refresh, { selfText: '', resumeText: '', loaded: true })
  assert.deepEqual(asked, ['aukora:resume', 'aukora:self', 'aukora:resume'])
})

test('the plugin remembers the head of each slot it loaded, and a handoff can carry it as expected_head', async () => {
  const head = 'ab'.repeat(32)
  const controller = createKiraController({}, async (_name, args) => {
    const slot = (args as { id: string }).id
    if (slot === 'aukora:self') return { isError: true as const, error: { message: 'none', info: { name: 'x', code: 'kira:not-found' } }, content: [] } as never
    return { isError: false, value: sampleNote({ id: head, slot, lane: 'resume', content: 'step 9' }), content: [{ type: 'text', text: '{}' }] } as never
  })
  assert.equal(controller.slotHead('aukora:resume'), undefined, 'nothing is known before the slots are loaded')
  await controller.ensureSlotsLoaded()
  assert.equal(controller.slotHead('aukora:resume'), head)
  assert.equal(controller.slotHead('aukora:self'), 'none', 'a slot loaded empty is guarded with "none"')
  const args = buildRememberArgs({ text: 'step 12', subject: 'resume', expected_head: controller.slotHead('aukora:resume') })
  assert.equal(args.expected_head, head)
  assert.equal('expected_head' in buildRememberArgs({ text: 'x', subject: 'y' }), false, 'absent unless asked for')
})

test('turn-start prompt refresh keeps the session handoff head, so a concurrent handoff refuses a stale write', async () => {
  const handlers = new Map<string, (...args: never[]) => Promise<unknown> | unknown>()
  const h1 = '1'.repeat(64)
  const h2 = '2'.repeat(64)
  let head = h1
  const ctx = {
    on: (event: string, handler: (...args: never[]) => Promise<unknown> | unknown) => handlers.set(event, handler),
    tools: {
      register: () => undefined,
      execute: async ({ name, arguments: args }: { name: string; arguments: Record<string, unknown> }) => {
        if (name === 'kira_remember') {
          return args.expected_head === head
            ? { isError: false, value: { id: '3'.repeat(64) }, content: [] }
            : { isError: true, error: { message: 'newer handoff', info: { name: 'AukoraDoorRefusal', code: 'kira:resume-stale' } }, content: [] }
        }
        return args.id === 'aukora:resume'
          ? { isError: false, value: sampleNote({ id: head, slot: args.id, lane: 'resume', content: head === h1 ? 'H1' : 'H2' }), content: [] }
          : { isError: true, error: { message: 'empty', info: { name: 'AukoraDoorRefusal', code: 'kira:not-found' } }, content: [] }
      },
    },
    systemPrompt: { section: () => undefined },
  }
  const controller = apply(ctx as never)
  const preStep = handlers.get('agent/pre-step') as (payload: { step: number }, next: () => Promise<void>) => Promise<unknown>
  await preStep({ step: 1 }, async () => {})
  assert.equal(controller.slotHead('aukora:resume'), h1)
  head = h2
  await preStep({ step: 1 }, async () => {})
  assert.equal(controller.resumeText(), 'H2', 'the displayed prompt still refreshes')
  assert.equal(controller.slotHead('aukora:resume'), h1, 'refreshing prompt text must not rebase the session write')
  const result = await ctx.tools.execute({
    name: 'kira_remember',
    arguments: buildRememberArgs({ text: 'stale session handoff', subject: 'resume', expected_head: controller.slotHead('aukora:resume') }),
  })
  assert.equal(result.isError, true)
  if (result.isError) assert.equal(result.error!.info!.code, 'kira:resume-stale')
})

test('an initially empty slot keeps its empty expected_head when a newer handoff appears', async () => {
  let empty = true
  const controller = createKiraController({}, async (_name, args) => empty
    ? { isError: true, error: { message: 'empty', info: { name: 'AukoraDoorRefusal', code: 'kira:not-found' } }, content: [] }
    : { isError: false, value: sampleNote({ id: '2'.repeat(64), slot: args.id as string, content: 'new handoff' }), content: [] })
  await controller.ensureSlotsLoaded()
  assert.equal(controller.slotHead('aukora:resume'), 'none')
  empty = false
  await controller.ensureSlotsLoaded(true)
  assert.equal(controller.resumeText(), 'new handoff')
  assert.equal(controller.slotHead('aukora:resume'), 'none')
})

test('the slots are read again at step 1 of every turn: a superseded self file stops being injected', async () => {
  const handlers = new Map<string, (...args: never[]) => Promise<unknown> | unknown>()
  let self = sampleNote({ content: 'I am Auma, version one.' })
  let asked = 0
  const ctx = {
    on: (event: string, handler: (...args: never[]) => Promise<unknown> | unknown) => handlers.set(event, handler),
    tools: {
      register: () => undefined,
      execute: async ({ arguments: args }: { arguments: { id: string } }) => {
        asked += 1
        return args.id === 'aukora:self'
          ? { isError: false, value: self, content: [] }
          : { isError: true, error: { message: 'kira:not-found', info: { name: 'AukoraDoorRefusal', code: 'kira:not-found' } }, content: [] }
      },
    },
    systemPrompt: { section: () => undefined },
  }
  const controller = apply(ctx as never)
  const preStep = handlers.get('agent/pre-step') as (payload: { agent: object; step: number }, next: () => Promise<unknown>) => Promise<unknown>
  const next = async () => 'next'
  const agent = {}
  await preStep({ agent, step: 1 }, next)
  assert.equal(controller.selfText(), 'I am Auma, version one.')
  // Later steps of the same turn reuse the cache (no extra door call), so a turn is not slowed.
  const before = asked
  await preStep({ agent, step: 2 }, next)
  assert.equal(asked, before)
  // The owner supersedes the self file between turns; step 1 of the next turn must not inject it.
  self = sampleNote({ content: 'I am Auma, version one.', superseded_by: '2'.repeat(64) })
  await preStep({ agent, step: 1 }, next)
  assert.equal(controller.selfText(), '')
  // A newer self file replaces it.
  self = sampleNote({ content: 'I am Auma, version two.' })
  await preStep({ agent, step: 1 }, next)
  assert.equal(controller.selfText(), 'I am Auma, version two.')
})

test('resolveKiraConfig validates bounds', () => {
  assert.throws(() => resolveKiraConfig({ maxSelfBytes: 10 }))
  assert.throws(() => resolveKiraConfig({ maxResumeBytes: 65_537 }))
  assert.throws(() => resolveKiraConfig({ selfSlot: '' }))
})
