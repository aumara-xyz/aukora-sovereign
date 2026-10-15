// SPDX-License-Identifier: AGPL-3.0-or-later
import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createSovereignAdapter, registerAdapter, DEFAULT_MODEL } from '../llm-adapter.mjs'
import { GuestRefusal } from '../fd3.mjs'
import { apply, name, inject } from '../plugin.mjs'

class LlmAdapter {}
class LlmError extends Error {
  constructor(message, code, options) {
    super(message, options)
    this.code = code
    this.failure = Object.freeze({ message, code })
  }
}
const harness = { LlmAdapter, LlmError }
const status = { kind: 'status.reply', body: { ready: true, bound: true, grant_id: 'grant-1', grant_remaining: 1000 } }
const replyBody = () => ({
  content: 'Queued suggestion.',
  tool_calls: [{ id: 'call-1', type: 'function', function: { name: 'aukora_propose', arguments: '{"target":"note.md","text":"hello"}' } }],
  finish_reason: 'tool_calls',
  usage: { prompt_tokens: 13, completion_tokens: 8, cost_microusd: 27 }, receipt_seq: 9,
})
const options = () => ({
  provider: 'sovereign', model: DEFAULT_MODEL,
  messages: [{ role: 'user', content: [{ type: 'text', text: 'Update my note.' }] }],
})
const collect = async stream => { const chunks = []; for await (const chunk of stream) chunks.push(chunk); return chunks }
const providerRefusals = [
  ['broker:provider-key-rejected', 'the provider rejected the model key: replace it on the owner page'],
  ['broker:provider-no-credit', 'the provider account has no credit'],
  ['broker:provider-rate-limited', 'the provider is rate limiting: try again shortly'],
  ['broker:provider-request-rejected', 'the provider rejected the request: model name or parameters'],
  ['broker:provider-unavailable', 'the provider is unavailable'],
  ['broker:provider-refused', 'the provider refused the call: check the model and account on the owner page'],
]
const providerBody = 'provider body: fake-key-antibody-123 private-prompt-antibody-456'

async function safeProviderRefusal(adapter, code, next, classes) {
  const emitted = []
  await assert.rejects(async () => {
    for await (const chunk of adapter.stream(options())) emitted.push(chunk)
  }, error => {
    assert.ok(error instanceof (classes.LlmError ?? GuestRefusal))
    assert.equal(error.code, code)
    assert.equal(error.failure.message, `${code}: ${next}`)
    assert.equal(error.cause, undefined)
    if (error instanceof GuestRefusal) assert.equal(error.next, next)
    assert.equal(error.retryable, false)
    assert.equal(error.nonRetryable, true)
    assert.equal(`${error.stack}\n${JSON.stringify(error)}`.includes(providerBody), false)
    return true
  })
  assert.deepEqual(emitted, [])
}
function fixture(response = { kind: 'model.reply', body: replyBody() }, config = {}, statusResponse = status) {
  const calls = []
  const link = { async call(kind, body, callOptions) {
    calls.push({ kind, body, options: callOptions })
    return kind === 'status' ? structuredClone(statusResponse) : structuredClone(response)
  } }
  return { adapter: createSovereignAdapter(link, config, harness), calls }
}
async function refused(stream, code) {
  await assert.rejects(collect(stream), error => {
    assert.ok(error instanceof LlmError)
    assert.equal(error.code, code)
    assert.equal(error.failure.code, code)
    assert.equal(error.nonRetryable, true)
    assert.equal(error.retryable, false)
    return true
  })
}

test('registers a real harness adapter with every inherited seam and zero retries', async () => {
  const held = []
  const disposed = []
  const ctx = { llm: { registerAdapter(providers, adapter) {
    held.push({ providers, adapter })
    return () => disposed.push(providers)
  } } }
  const { adapter, dispose } = registerAdapter(ctx, { call() {} }, {}, harness)
  assert.ok(adapter instanceof LlmAdapter)
  assert.deepEqual(held[0].providers, ['sovereign'])
  assert.deepEqual(adapter.providerInfo('sovereign'), { id: 'sovereign', name: 'Sovereign' })
  const policy = adapter.providerRetryPolicy('sovereign')
  assert.equal(policy.mode, 'normal')
  assert.equal(policy.maxRetries, 0)
  assert.deepEqual(policy.retryableCodes, [])
  assert.ok(Object.isFrozen(policy) && Object.isFrozen(policy.retryableCodes))
  assert.equal(adapter.imageRequestPricing('sovereign', DEFAULT_MODEL), undefined)
  const models = await adapter.listModels('sovereign')
  assert.equal(models[0].id, DEFAULT_MODEL)
  assert.deepEqual(models[0].inputModalities, ['text'])
  const prepared = await adapter.prepareCall('sovereign', DEFAULT_MODEL)
  assert.equal(prepared.model.defaultMaxTokens, 4096)
  assert.equal(typeof prepared.stream, 'function')
  dispose()
  assert.deepEqual(disposed, [['sovereign']])
})

test('maps harness history, schemas, limits, and tool-calling reply through C4', async () => {
  const { adapter, calls } = fixture()
  const input = options()
  input.system = 'Be precise.'
  input.maxTokens = 100
  input.tools = [{ name: 'aukora_propose', description: 'Propose a change.', parameters: { type: 'object', properties: { target: { type: 'string' } } } }]
  input.messages = [
    { role: 'system', content: [{ type: 'text', text: 'Existing system.' }] },
    { role: 'user', content: [{ type: 'text', text: 'Part one' }, { type: 'text', text: ' and two.' }] },
    { role: 'assistant', content: [{ type: 'tool-call', id: 'old-call', name: 'kira_recall', arguments: '{"query":"notes"}' }] },
    { role: 'user', content: [{ type: 'tool-result', toolCallId: 'old-call', content: [{ type: 'text', text: 'Found.' }] }] },
  ]
  const signal = new AbortController().signal
  input.signal = signal
  const original = structuredClone({ ...input, signal: undefined })
  const chunks = await collect(adapter.stream(input))
  assert.deepEqual({ ...input, signal: undefined }, original)
  assert.deepEqual(calls.map(call => call.kind), ['status', 'model.call'])
  assert.equal(calls[1].options.signal, signal)
  assert.deepEqual(calls[1].body, {
    grant_id: 'grant-1', model: DEFAULT_MODEL, max_output_tokens: 100,
    messages: [
      { role: 'system', content: 'Be precise.' }, { role: 'system', content: 'Existing system.' },
      { role: 'user', content: 'Part one and two.' },
      { role: 'assistant', content: '', tool_calls: [{ id: 'old-call', type: 'function', function: { name: 'kira_recall', arguments: '{"query":"notes"}' } }] },
      { role: 'tool', content: 'Found.', tool_call_id: 'old-call' },
    ],
    tools: [{ type: 'function', function: input.tools[0] }],
  })
  assert.deepEqual(chunks, [
    { type: 'block-start', index: 0, blockType: 'text' },
    { type: 'text-delta', index: 0, text: 'Queued suggestion.' },
    { type: 'block-end', index: 0, block: { type: 'text', text: 'Queued suggestion.' } },
    { type: 'block-start', index: 1, blockType: 'tool-call' },
    { type: 'tool-call-delta', index: 1, id: 'call-1', name: 'aukora_propose', argumentsDelta: replyBody().tool_calls[0].function.arguments },
    { type: 'block-end', index: 1, block: { type: 'tool-call', id: 'call-1', name: 'aukora_propose', arguments: replyBody().tool_calls[0].function.arguments } },
    { type: 'usage', usage: { inputTokens: 13, outputTokens: 8, totalTokens: 21 } },
    { type: 'finish', reason: { kind: 'tool-calls' }, replayState: { response: { receipt_seq: 9, cost_microusd: 27 } } },
  ])
})

test('maps text stop, length limits, and a tool-only response', async () => {
  for (const [finish, expected] of [['stop', 'stop'], ['length', 'max-tokens']]) {
    const body = { ...replyBody(), tool_calls: [], finish_reason: finish }
    const { adapter } = fixture({ kind: 'model.reply', body })
    const chunks = await collect(adapter.stream(options()))
    assert.equal(chunks.at(-1).reason.kind, expected)
  }
  const body = { ...replyBody(), content: null }
  const { adapter } = fixture({ kind: 'model.reply', body })
  const chunks = await collect(adapter.stream(options()))
  assert.equal(chunks[0].blockType, 'tool-call')
  assert.equal(chunks[0].index, 0)
})

test('preserves unknown outcomes and refusals as non-retryable LlmErrors without redispatch', async () => {
  for (const response of [
    { state: 'unknown' },
    { kind: 'refusal', body: { code: 'broker:grant-exhausted', next: 'Ask the owner.' } },
  ]) {
    const { adapter, calls } = fixture(response, { grantId: 'grant-1' })
    await refused(adapter.stream(options()), response.kind === 'refusal' ? response.body.code : 'guest:outcome-unknown')
    assert.equal(calls.length, 1)
  }
  const link = { async call() { throw new GuestRefusal('frame:not-canonical') } }
  await refused(createSovereignAdapter(link, { grantId: 'grant-1' }, harness).stream(options()), 'frame:not-canonical')
})

test('antibody_provider_refusal_categories_override_frame_text', async () => {
  for (const [code, next] of providerRefusals) {
    for (const classes of [harness, {}]) {
      let calls = 0
      const link = { async call() {
        calls++
        return { kind: 'refusal', body: { code, next: providerBody } }
      } }
      const adapter = createSovereignAdapter(link, { grantId: 'grant-1' }, classes)
      await safeProviderRefusal(adapter, code, next, classes)
      assert.equal(calls, 1)
    }
  }
})

test('antibody_provider_refusal_categories_override_thrown_text', async () => {
  for (const [code, next] of providerRefusals) {
    for (const classes of [harness, {}]) {
      let calls = 0
      const link = { async call() {
        calls++
        const error = new GuestRefusal(code, providerBody)
        error.cause = new Error(providerBody)
        throw error
      } }
      const adapter = createSovereignAdapter(link, { grantId: 'grant-1' }, classes)
      await safeProviderRefusal(adapter, code, next, classes)
      assert.equal(calls, 1)
    }
  }
})

test('requires a ready, bound supervisor and a current grant before model dispatch', async () => {
  for (const [patch, code] of [
    [{ ready: false }, 'guest:not-ready'], [{ bound: false }, 'guest:not-ready'],
    [{ grant_id: null }, 'broker:grant-required'], [{ grant_id: '' }, 'broker:grant-required'],
  ]) {
    const { adapter, calls } = fixture(undefined, {}, { ...status, body: { ...status.body, ...patch } })
    await refused(adapter.stream(options()), code)
    assert.deepEqual(calls.map(call => call.kind), ['status'])
  }
  // The chat shows the owner what to do, not only the code.
  const { adapter } = fixture(undefined, {}, { ...status, body: { ...status.body, ready: false } })
  await assert.rejects(collect(adapter.stream(options())), error =>
    error.failure.message.startsWith('guest:not-ready: ') && error.failure.message.includes('owner page'))
  for (const [response, code] of [[{ state: 'unknown' }, 'guest:outcome-unknown'], [{ kind: 'accepted', body: {} }, 'guest:invalid-status']]) {
    const { adapter, calls } = fixture(undefined, {}, response)
    await refused(adapter.stream(options()), code)
    assert.equal(calls.length, 1)
  }
})

test('refuses unsupported controls and content instead of silently dropping them', async () => {
  const cases = [
    [{ temperature: 0.2 }, 'guest:unsupported-model-control'],
    [{ stop: ['stop'] }, 'guest:unsupported-model-control'],
    [{ reasoningEffort: 'high' }, 'guest:unsupported-model-control'],
    [{ provider: 'deepseek' }, 'guest:invalid-model-route'],
    [{ model: '' }, 'guest:invalid-model-route'],
    [{ maxTokens: 0 }, 'guest:invalid-output-limit'],
    [{ maxTokens: 1.5 }, 'guest:invalid-output-limit'],
    [{ messages: null }, 'guest:invalid-messages'],
    [{ messages: [{ role: 'bogus', content: [] }] }, 'guest:invalid-messages'],
    [{ messages: [{ role: 'user', content: [{ type: 'image', attachment: {} }] }] }, 'guest:unsupported-content'],
    [{ messages: [{ role: 'assistant', content: [{ type: 'reasoning', text: 'private' }] }] }, 'guest:unsupported-content'],
    [{ messages: [{ role: 'user', content: [{ type: 'tool-result', toolCallId: '', content: [] }] }] }, 'guest:invalid-tool-call'],
    [{ messages: [{ role: 'assistant', content: [{ type: 'tool-call', id: 'a', name: 'memory.put', arguments: '{}' }] }] }, 'guest:invalid-tool-call'],
    [{ messages: [{ role: 'system', content: [{ type: 'text', text: 1 }] }] }, 'guest:unsupported-content'],
    [{ tools: [{ name: 'memory.put', description: '', parameters: {} }] }, 'guest:invalid-tools'],
    [{ tools: [{ name: 'ok', description: '', parameters: [] }] }, 'guest:invalid-tools'],
  ]
  for (const [patch, code] of cases) {
    const { adapter, calls } = fixture()
    await refused(adapter.stream({ ...options(), ...patch }), code)
    assert.equal(calls.length, 0)
  }
})

test('rejects malformed model replies before emitting any content', async () => {
  const cases = [
    body => { body.content = 1 }, body => { body.tool_calls = null },
    body => { body.tool_calls[0].type = 'other' }, body => { body.tool_calls.push(body.tool_calls[0]) },
    body => { body.finish_reason = 'unrecognised' }, body => { body.tool_calls = [] },
    body => { body.usage.cost_microusd = -1 }, body => { body.usage.prompt_tokens = 0.1 },
    body => { body.usage = null }, body => { body.receipt_seq = 0 },
    body => { body.usage.prompt_tokens = Number.MAX_SAFE_INTEGER },
  ]
  for (const corrupt of cases) {
    const body = replyBody()
    corrupt(body)
    const { adapter } = fixture({ kind: 'model.reply', body })
    await refused(adapter.stream(options()), 'guest:invalid-model-reply')
  }
  const { adapter } = fixture({ kind: 'model.reply', body: { ...replyBody(), content: '', tool_calls: [], finish_reason: 'stop' } })
  await refused(adapter.stream(options()), 'guest:empty-model-reply')
  await refused(fixture({ kind: 'accepted', body: {} }).adapter.stream(options()), 'guest:invalid-model-reply')
  await refused(fixture({ kind: 'refusal', body: {} }).adapter.stream(options()), 'guest:invalid-refusal')
})

test('plugin requires the harness loader and real Llm classes before touching FD 3', async () => {
  assert.equal(name, 'sovereign-bridge')
  assert.deepEqual(inject, ['llm', 'tools'])
  await assert.rejects(apply({}), { code: 'guest:harness-loader-unavailable' })
  await assert.rejects(apply({ loader: { internal: { async import() { return {} } } } }), { code: 'guest:harness-llm-unavailable' })
})

test('plugin wires one inherited FD 3 link, the sovereign adapter, and three tools', () => {
  const code = `
    import assert from 'node:assert/strict'
    import { apply } from ${JSON.stringify(new URL('../plugin.mjs', import.meta.url).href)}
    process.argv[1] = '/harness/lib/cli.mjs'
    class LlmAdapter {}
    class LlmError extends Error {}
    const registrations = [], tools = [], cleanup = []
    const ctx = {
      loader: { internal: { async import(specifier, parent, attributes) {
        assert.equal(specifier, '@deepseek-ai/dsh-llm')
        assert.equal(parent, 'file:///harness/lib/cli.mjs')
        assert.deepEqual(attributes, {})
        return { LlmAdapter, LlmError }
      } } },
      llm: { registerAdapter(providers, adapter) {
        assert.ok(adapter instanceof LlmAdapter)
        registrations.push(providers)
        return () => {}
      } },
      tools: { register(tool) { tools.push(tool.name); return () => {} } },
      inject(names, callback) {
        assert.deepEqual(names, ['webServer', 'connection'])
        callback({ webServer: { register(route) { assert.ok(['/api/sovereign/organs', '/api/aukora/aura-snapshot', '/api/kira/memories', '/api/aukora/memory/remembered', '/api/aukora/memory/openviking'].includes(route.path)); return () => {} } }, connection: {}, effect(effect) { effect() } })
      },
      effect(effect) { cleanup.push(effect()) },
    }
    await apply(ctx)
    assert.deepEqual(registrations, [['sovereign']])
    assert.deepEqual(tools, ['aukora_propose', 'kira_recall', 'kira_save'])
    assert.equal(cleanup.length, 1)
    cleanup[0]()
    process.stdout.write('plugin wiring passed\\n')
  `
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', code], {
    encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe', 'pipe'], timeout: 5000,
  })
  assert.equal(result.status, 0, result.stderr)
  assert.equal(result.stdout, 'plugin wiring passed\n')
})
