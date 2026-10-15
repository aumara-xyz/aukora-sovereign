// SPDX-License-Identifier: AGPL-3.0-or-later
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { createTools, memoryCellArguments, registerTools } from '../tools.mjs'
import { canonicalJSON } from '../canon.mjs'
import {
  CELL_BUDGET_BYTES, MODULE_SHA256, cellEffectBody, consumeMemoryPutCellProposal,
  exactDataObject, memoryCellProof, proposeMemoryPutInWasm, sha256,
} from '../wasm-cell.mjs'

const args = { key: 'memory:test', value: { category: 'fact', statement: 'A test note.' } }
const proposal = (overrides = {}) => ({
  argumentsJson: canonicalJSON(args), moduleSha256: MODULE_SHA256, toolName: 'memory.put', ...overrides,
})
const refused = (run, code) => assert.throws(run, error => error.code === code && error.retryable === false)
const frame = (kind, body) => ({ v: 1, id: 'test', kind, body })
const makeLink = replies => ({
  calls: [],
  async call(kind, body, options) { this.calls.push({ kind, body, options }); return replies.shift() },
})
const find = (link, name, config) => createTools(link, config).find(tool => tool.name === name)

function withInstance(invoke, run, memory = new WebAssembly.Memory({ initial: 1, maximum: 1 })) {
  const original = WebAssembly.Instance
  WebAssembly.Instance = class {
    constructor(_module, imports) {
      this.exports = { memory, memory_put: (...spans) => invoke(imports.aukora.propose_memory_put, memory, spans) }
    }
  }
  try { return run() } finally { WebAssembly.Instance = original }
}

test('pinned 101-byte cell reproduces canonical arguments and LF effect digests', () => {
  const emitted = proposeMemoryPutInWasm(args)
  assert.deepEqual(emitted, proposal())
  assert.equal(canonicalJSON(consumeMemoryPutCellProposal(emitted, args, args)), canonicalJSON(args))
  assert.equal(cellEffectBody(args), `${canonicalJSON(args)}\n`)
  assert.deepEqual(memoryCellProof(args), {
    module_sha256: MODULE_SHA256,
    input_sha256: sha256(canonicalJSON(args)),
    effect_sha256: sha256(`${canonicalJSON(args)}\n`),
  })
})

test('cell closed objects reject extra, symbolic, hidden, prototype and accessor fields', () => {
  let invoked = false
  for (const malformed of [
    { ...args, extra: true }, { ...args, [Symbol('rider')]: true }, Object.assign(Object.create({}), args),
    Object.defineProperty({ ...args }, 'hidden', { value: true }),
    { key: args.key, get value() { invoked = true; return args.value } },
  ]) refused(() => proposeMemoryPutInWasm(malformed), 'wasm-cell:arguments-not-exact')
  assert.equal(invoked, false)
  assert.equal(exactDataObject(new Proxy({}, { ownKeys() { throw new Error('proxy') } }), []), null)
  assert.equal(exactDataObject({ get value() { invoked = true; return 1 } }, ['value']), null)
  assert.equal(exactDataObject(Object.defineProperty({}, 'value', { value: 1 }), ['value']), null)
  assert.equal(invoked, false)
  for (const malformed of [null, [], { key: 2, value: true }, { key: 'ok', value: undefined }]) {
    refused(() => proposeMemoryPutInWasm(malformed), 'wasm-cell:arguments-not-exact')
  }
  for (const key of ['', '../target', 'a'.repeat(129)]) refused(() => proposeMemoryPutInWasm({ key, value: true }), 'wasm-cell:key-not-a-name')
  refused(() => cellEffectBody({ key: '../target', value: true }), 'wasm-cell:key-not-a-name')
})

test('cell accepts exactly 64 KiB key plus canonical value and refuses the next byte', () => {
  const key = 'a'
  assert.equal(proposeMemoryPutInWasm({ key, value: 'v'.repeat(CELL_BUDGET_BYTES - 3) }).toolName, 'memory.put')
  refused(() => proposeMemoryPutInWasm({ key, value: 'v'.repeat(CELL_BUDGET_BYTES - 2) }), 'wasm-cell:proposal-too-large')
})

test('cell output is closed, pinned, canonical and bound to both argument snapshots', () => {
  for (const malformed of [null, [], { ...proposal(), extra: true }, { ...proposal(), toolName: 2 },
    { ...proposal(), [Symbol('rider')]: true }, Object.defineProperty(proposal(), 'hidden', { value: true }),
    { ...proposal(), get argumentsJson() { throw new Error('getter ran') } },
  ]) refused(() => consumeMemoryPutCellProposal(malformed, args, args), 'wasm-cell:proposal-fields-not-exact')
  refused(() => consumeMemoryPutCellProposal(proposal({ toolName: 'file.write' }), args, args), 'wasm-cell:tool-name-mismatch')
  refused(() => consumeMemoryPutCellProposal(proposal({ moduleSha256: '0'.repeat(64) }), args, args), 'wasm-cell:module-digest-mismatch')
  refused(() => consumeMemoryPutCellProposal(proposal({ argumentsJson: '{' }), args, args), 'wasm-cell:arguments-json-invalid')
  refused(() => consumeMemoryPutCellProposal(proposal({ argumentsJson: '{"key":"a","key":"b","value":true}' }), args, args), 'wasm-cell:arguments-json-invalid')
  refused(() => consumeMemoryPutCellProposal(proposal({ argumentsJson: '{"key":"a","value":true,"extra":1}' }), args, args), 'wasm-cell:arguments-not-exact')
  refused(() => consumeMemoryPutCellProposal(proposal({ argumentsJson: '{"key":"../a","value":true}' }), args, args), 'wasm-cell:key-not-a-name')
  refused(() => consumeMemoryPutCellProposal(proposal({ argumentsJson: ` ${canonicalJSON(args)}` }), args, args), 'wasm-cell:arguments-json-not-canonical')
  const changed = { key: args.key, value: false }
  refused(() => consumeMemoryPutCellProposal(proposal(), changed, args), 'wasm-cell:arguments-binding-mismatch')
  refused(() => consumeMemoryPutCellProposal(proposal(), args, changed), 'wasm-cell:arguments-binding-mismatch')
})

test('cell pins module bytes before compilation', async () => {
  const source = await readFile(new URL('../wasm-cell.mjs', import.meta.url), 'utf8')
  const changed = source.replace("'AGFzbQE", "'BGFzbQE")
    .replace("'./canon.mjs'", JSON.stringify(new URL('../canon.mjs', import.meta.url).href))
    .replace("'./fd3.mjs'", JSON.stringify(new URL('../fd3.mjs', import.meta.url).href))
  const altered = await import(`data:text/javascript,${encodeURIComponent(changed)}`)
  refused(() => altered.proposeMemoryPutInWasm(args), 'wasm-cell:module-digest-mismatch')
})

test('cell checks complete imports and exports before instantiation', () => {
  for (const [method, code] of [['imports', 'wasm-cell:import-inventory-mismatch'], ['exports', 'wasm-cell:export-inventory-mismatch']]) {
    const original = WebAssembly.Module[method]
    WebAssembly.Module[method] = module => [...original(module), { module: 'wasi', name: 'extra', kind: 'function' }]
    try { refused(() => proposeMemoryPutInWasm(args), code) } finally { WebAssembly.Module[method] = original }
  }
})

test('cell validates memory and requires one successful emission', () => {
  const original = WebAssembly.Instance
  WebAssembly.Instance = class { constructor(_module, imports) { imports.aukora.propose_memory_put(0, 1, 1, 1) } }
  try { refused(() => proposeMemoryPutInWasm(args), 'wasm-cell:memory-not-ready') } finally { WebAssembly.Instance = original }
  withInstance(() => 1, () => refused(() => proposeMemoryPutInWasm(args), 'wasm-cell:memory-export-invalid'), {})
  withInstance(() => 1, () => refused(() => proposeMemoryPutInWasm(args), 'wasm-cell:memory-export-invalid'), new WebAssembly.Memory({ initial: 2 }))
  withInstance(() => 1, () => refused(() => proposeMemoryPutInWasm(args), 'wasm-cell:proposal-not-emitted'))
  withInstance((emit, _memory, spans) => { emit(...spans); return 0 }, () => refused(() => proposeMemoryPutInWasm(args), 'wasm-cell:proposal-not-emitted'))
  withInstance((emit, _memory, spans) => { emit(...spans); return emit(...spans) }, () => refused(() => proposeMemoryPutInWasm(args), 'wasm-cell:proposal-already-emitted'))
})

test('cell checks memory ranges, fatal UTF-8, decoded key and canonical value', () => {
  for (const offset of [-1, 0.5, CELL_BUDGET_BYTES]) {
    withInstance(emit => emit(offset, 1, 0, 1), () => refused(() => proposeMemoryPutInWasm(args), 'wasm-cell:key-range-invalid'))
  }
  for (const [span, code] of [[0, 'wasm-cell:key-utf8-invalid'], [1, 'wasm-cell:value-utf8-invalid']]) {
    withInstance((emit, memory, spans) => {
      new Uint8Array(memory.buffer)[span === 0 ? spans[0] : spans[2]] = 0xff
      return emit(...spans)
    }, () => refused(() => proposeMemoryPutInWasm(args), code))
  }
  withInstance((emit, memory, spans) => {
    new Uint8Array(memory.buffer)[0] = '/'.charCodeAt(0)
    return emit(...spans)
  }, () => refused(() => proposeMemoryPutInWasm(args), 'wasm-cell:key-not-a-name'))
  withInstance((emit, memory, spans) => {
    new Uint8Array(memory.buffer).set(Buffer.from('{'), spans[2])
    return emit(spans[0], spans[1], spans[2], 1)
  }, () => refused(() => proposeMemoryPutInWasm(args), 'wasm-cell:value-json-invalid'))
  withInstance((emit, memory, spans) => {
    new Uint8Array(memory.buffer).set(Buffer.from(' true'), spans[2])
    return emit(spans[0], spans[1], spans[2], 5)
  }, () => refused(() => proposeMemoryPutInWasm(args), 'wasm-cell:value-json-not-canonical'))
})

test('cell deadline interrupts a slow invocation', () => {
  withInstance(() => { const until = Date.now() + 250; while (Date.now() < until) {} }, () => refused(() => proposeMemoryPutInWasm(args), 'wasm-cell:execution-timeout'))
})

test('cell proof refuses changed emitted effect instead of adopting it', () => {
  withInstance((emit, memory, spans) => {
    new Uint8Array(memory.buffer).set(Buffer.from('false'), spans[2])
    return emit(spans[0], spans[1], spans[2], 5)
  }, () => refused(() => memoryCellProof(args), 'wasm-cell:arguments-binding-mismatch'))
})

test('proposal reads FD 3 bytes and only reports PENDING_OWNER after acceptance', async () => {
  const base = Buffer.from('before\n')
  const link = makeLink([frame('read.reply', { target: 'note.md', sha256: sha256(base), bytes_b64: base.toString('base64') }), frame('accepted', { proposal_id: 'p1' })])
  const signal = new AbortController().signal
  const result = JSON.parse(await find(link, 'aukora_propose', { timeoutMs: 12 }).execute({ target: 'note.md', text: 'after\n', note: 'model note' }, { signal }))
  assert.deepEqual(result, { state: 'PENDING_OWNER', proposal_id: 'p1' })
  assert.deepEqual(link.calls, [
    { kind: 'read', body: { target: 'note.md' }, options: { timeoutMs: 12, signal } },
    { kind: 'propose', body: { target: 'note.md', base_sha256: sha256(base), new_bytes_b64: Buffer.from('after\n').toString('base64'), note: 'model note' }, options: { timeoutMs: 12, signal } },
  ])
})

test('antibody_path0_proposal_binds_pinned_cell_proof_to_exact_effect_bytes', async () => {
  const target = 'plugins/owner-note/note.md'
  const pair = { key: 'path0', value: { note: 'Exact bytes.\n', revision: 1 } }
  const link = makeLink([
    frame('read.reply', { target, sha256: sha256('before\n'), bytes_b64: Buffer.from('before\n').toString('base64') }),
    frame('accepted', { proposal_id: 'path0' }),
  ])
  let instances = 0
  const original = WebAssembly.Instance
  WebAssembly.Instance = class extends original {
    constructor(module, imports) { super(module, imports); instances++ }
  }
  let result
  try { result = JSON.parse(await find(link, 'aukora_propose').execute({ target, cell: pair, note: 'untrusted model text' })) }
  finally { WebAssembly.Instance = original }
  assert.equal(instances, 1)
  assert.deepEqual(result, { state: 'PENDING_OWNER', proposal_id: 'path0' })
  assert.equal(link.calls.length, 2)
  const request = link.calls[1]
  assert.equal(request.kind, 'propose')
  assert.deepEqual(request.body, {
    target, base_sha256: sha256('before\n'), note: 'untrusted model text',
    new_bytes_b64: Buffer.from('{"key":"path0","value":{"note":"Exact bytes.\\n","revision":1}}\n').toString('base64'),
    cell: memoryCellProof(pair),
  })
  assert.equal(request.body.cell.module_sha256, MODULE_SHA256)
  assert.equal(request.body.cell.effect_sha256, sha256(Buffer.from(request.body.new_bytes_b64, 'base64')))
})

test('antibody_path0_proposal_requires_one_closed_text_or_cell_input', async () => {
  const target = 'plugins/owner-note/note.md'
  for (const fields of [
    {}, { text: 'different', cell: args }, { cell: { ...args, extra: true } },
    { cell: { key: '../target', value: true } }, { cell: { key: 'path0' } },
  ]) {
    const link = makeLink([])
    await assert.rejects(find(link, 'aukora_propose').execute({ target, note: '', ...fields }), error => [
      'guest:tool-arguments-invalid', 'wasm-cell:arguments-not-exact', 'wasm-cell:key-not-a-name',
    ].includes(error.code))
    assert.equal(link.calls.length, 0)
  }
})

test('antibody_path0_proposal_cell_budget_is_enforced_before_fd3', async () => {
  const link = makeLink([])
  await assert.rejects(find(link, 'aukora_propose').execute({
    target: 'plugins/owner-note/note.md', note: '', cell: { key: 'path0', value: 'x'.repeat(CELL_BUDGET_BYTES) },
  }), { code: 'wasm-cell:proposal-too-large' })
  assert.equal(link.calls.length, 0)
})

test('antibody_path0_proposal_uncertainty_never_retries_or_reports_applied', async () => {
  const target = 'plugins/owner-note/note.md'
  const input = { target, note: '', cell: { key: 'path0', value: true } }
  const read = frame('read.reply', { target, sha256: sha256(''), bytes_b64: '' })
  const beforeRead = makeLink([{ state: 'unknown' }])
  assert.deepEqual(JSON.parse(await find(beforeRead, 'aukora_propose').execute(input)), { state: 'unknown' })
  assert.equal(beforeRead.calls.length, 1)
  const afterRead = makeLink([read, { state: 'unknown' }])
  assert.deepEqual(JSON.parse(await find(afterRead, 'aukora_propose').execute(input)), { state: 'unknown' })
  assert.equal(afterRead.calls.length, 2)
  await assert.rejects(find(makeLink([read, frame('outcome', { proposal_id: 'path0', state: 'applied' })]), 'aukora_propose').execute(input), { code: 'guest:reply-kind-invalid' })
})

test('proposal refuses mismatched target, noncanonical base64 and mismatched digest before proposing', async () => {
  const normal = { target: 'note.md', sha256: sha256('before'), bytes_b64: Buffer.from('before').toString('base64') }
  for (const [override, code] of [
    [{ target: 'other.md' }, 'guest:read-reply-invalid'], [{ bytes_b64: '!!!' }, 'guest:read-reply-invalid'],
    [{ bytes_b64: 'Zh==' }, 'guest:read-digest-mismatch'], [{ sha256: '0'.repeat(64) }, 'guest:read-digest-mismatch'],
  ]) {
    const link = makeLink([frame('read.reply', { ...normal, ...override })])
    await assert.rejects(find(link, 'aukora_propose').execute({ target: 'note.md', text: 'new', note: '' }), { code })
    assert.equal(link.calls.length, 1)
  }
})

test('proposal timeouts stay unknown and supervisor refusal is non-retryable', async () => {
  const input = { target: 'note.md', text: 'new', note: '' }
  const link = makeLink([{ state: 'unknown' }])
  assert.deepEqual(JSON.parse(await find(link, 'aukora_propose').execute(input)), { state: 'unknown' })
  assert.equal(link.calls.length, 1)
  const read = frame('read.reply', { target: 'note.md', sha256: sha256(''), bytes_b64: '' })
  const afterRead = makeLink([read, { state: 'unknown' }])
  assert.deepEqual(JSON.parse(await find(afterRead, 'aukora_propose').execute(input)), { state: 'unknown' })
  assert.equal(afterRead.calls.length, 2)
  const denied = makeLink([read, frame('refusal', { code: 'gate:stale-base', next: 'Read again.' })])
  await assert.rejects(find(denied, 'aukora_propose').execute(input), error => error.code === 'gate:stale-base' && !error.retryable)
  assert.equal(denied.calls.length, 2)
  for (const reply of [frame('outcome', { proposal_id: 'p1', state: 'applied' }), frame('wrong.kind', { proposal_id: 'p1' }), frame('accepted', { proposal_id: '../p1' }), frame('accepted', { proposal_id: 'p1', applied: true })]) {
    await assert.rejects(find(makeLink([read, reply]), 'aukora_propose').execute(input), error => ['guest:reply-kind-invalid', 'guest:reply-body-invalid'].includes(error.code))
  }
})

test('recall preserves cited found, empty and undetermined responses', async () => {
  for (const body of [
    { result: 'found', items: [{ note_id: 'n1', text: 'untrusted remembered text', cite_seq: 3 }] },
    { result: 'empty', items: [] }, { result: 'undetermined', items: [] },
  ]) {
    const link = makeLink([frame('recall', body)])
    assert.deepEqual(JSON.parse(await find(link, 'kira_recall').execute({ query: 'test' })), body)
    assert.deepEqual(link.calls[0].body, { query: 'test', limit: 10 })
  }
  const link = makeLink([{ state: 'unknown' }])
  assert.deepEqual(JSON.parse(await find(link, 'kira_recall').execute({ query: '' })), { result: 'undetermined', items: [] })
  assert.equal(link.calls.length, 1)
  for (const body of [{ result: 'saved', items: [] }, { result: 'found', items: [{}] },
    { result: 'found', items: [{ note_id: 'n1', text: 'text', cite_seq: 0 }] }]) {
    await assert.rejects(find(makeLink([frame('recall', body)]), 'kira_recall').execute({ query: 'test' }), { code: 'guest:recall-reply-invalid' })
  }
})

test('save runs pinned cell and sends C4 digests without claiming persistence', async () => {
  const input = { statement: 'A note.', quote: 'A quote.', category: 'fact' }
  const pair = memoryCellArguments(input)
  assert.equal(canonicalJSON(pair.value), '{"category":"fact","quote":"A quote.","statement":"A note."}')
  assert.equal(pair.key, 'memory:3c529a9363c13fe8f92beeca25927a0d9a0a8dc0bffa50ae9f8769ce0cabe177')
  assert.deepEqual(memoryCellProof(pair), {
    module_sha256: MODULE_SHA256,
    input_sha256: '3775b9f718af8ca08b76371abe942a289786a91dea1066f786b51413f43da211',
    effect_sha256: '891cefa25ad08c62187b9fd4a910de87ff38f3b1051dd80148df216a02711cb7',
  })
  const link = makeLink([frame('accepted', { proposal_id: 'm1' })])
  assert.deepEqual(JSON.parse(await find(link, 'kira_save').execute(input)), { state: 'ACKNOWLEDGED_PENDING', proposal_id: 'm1' })
  assert.deepEqual(link.calls[0].body, { cell: memoryCellProof(pair), ...input })
  assert.equal(link.calls[0].kind, 'memory.put')
  for (const reply of [{ state: 'unknown' }, frame('outcome', { proposal_id: 'm1', state: 'applied' })]) {
    const uncertain = makeLink([reply])
    assert.deepEqual(JSON.parse(await find(uncertain, 'kira_save').execute(input)), { state: 'unknown' })
    assert.equal(uncertain.calls.length, 1)
  }
  const oversized = makeLink([])
  await assert.rejects(find(oversized, 'kira_save').execute({ statement: 'x'.repeat(65_536), category: 'fact' }), { code: 'wasm-cell:proposal-too-large' })
  assert.equal(oversized.calls.length, 0)
})

test('tool schemas are closed and tools register in the pinned harness pattern', async () => {
  const link = makeLink([])
  const registered = []
  const ctx = { tools: { register(tool) { registered.push(tool); return () => {} } } }
  assert.equal(registerTools(ctx, link).length, 3)
  assert.deepEqual(registered.map(tool => tool.name), ['aukora_propose', 'kira_recall', 'kira_save'])
  for (const tool of registered) {
    assert.match(tool.name, /^[a-zA-Z0-9_-]+$/)
    assert.equal(tool.parameters.additionalProperties, false)
    assert.equal(tool.isConcurrencySafe(), false)
    assert.deepEqual(tool.output.render({}, 'text'), [{ type: 'text', text: 'text' }])
    await assert.rejects(tool.execute({ extra: true }), { code: 'guest:tool-arguments-invalid' })
  }
  for (const input of [{ query: 1 }, { query: 'x', limit: 0 }, { query: 'x', limit: 101 }, { query: 'x', limit: 1.5 }]) {
    await assert.rejects(find(link, 'kira_recall').execute(input), { code: 'guest:tool-arguments-invalid' })
  }
  for (const input of [{ statement: '', category: 'fact' }, { statement: 'note', category: '' }, { statement: 'note', category: 'fact', quote: 2 }]) {
    await assert.rejects(find(link, 'kira_save').execute(input), { code: 'guest:tool-arguments-invalid' })
  }
  assert.equal(link.calls.length, 0)
})
