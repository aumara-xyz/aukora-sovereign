// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict'
import { Fd3Link } from '../fd3.mjs'
import { createSovereignAdapter } from '../llm-adapter.mjs'
import { createTools } from '../tools.mjs'

const scenario = process.argv[2]
const link = new Fd3Link({ timeoutMs: 1500 })
const pushed = []
link.onOutcome(body => pushed.push(body))
try {
  if (scenario === 'adapter') {
    const adapter = createSovereignAdapter(link, { timeoutMs: 1500 })
    const chunks = []
    for await (const chunk of adapter.stream({
      provider: 'sovereign', model: 'test-model', system: 'system',
      messages: [{ role: 'user', content: [{ type: 'text', text: 'hello' }] }],
      tools: [{ name: 'kira_recall', description: 'Recall', parameters: { type: 'object' } }], maxTokens: 64,
    })) chunks.push(chunk)
    assert.equal(chunks.find(chunk => chunk.type === 'block-end' && chunk.block.type === 'tool-call').block.name, 'kira_recall')
    assert.deepEqual(chunks.at(-1).reason, { kind: 'tool-calls' })
    console.log(JSON.stringify({ types: chunks.map(chunk => chunk.type) }))
  } else if (scenario === 'path0') {
    const tool = createTools(link, { timeoutMs: 1500 }).find(tool => tool.name === 'aukora_propose')
    const result = JSON.parse(await tool.execute({
      target: 'plugins/owner-note/note.md', note: 'untrusted model note',
      cell: { key: 'path0', value: { revision: 1, statement: 'Exact owner-reviewed bytes.' } },
    }))
    assert.deepEqual(result, { state: 'PENDING_OWNER', proposal_id: 'path0' })
    console.log(JSON.stringify(result))
  } else if (scenario === 'tools') {
    const tools = new Map(createTools(link, { timeoutMs: 1500 }).map(tool => [tool.name, tool]))
    const proposal = JSON.parse(await tools.get('aukora_propose').execute({ target: 'notes/a.txt', text: 'new', note: 'model text' }))
    const recall = JSON.parse(await tools.get('kira_recall').execute({ query: 'hello', limit: 3 }))
    const memory = JSON.parse(await tools.get('kira_save').execute({ statement: 'hello', category: 'fact' }))
    assert.equal(proposal.state, 'PENDING_OWNER')
    assert.equal(recall.items[0].cite_seq, 8)
    assert.equal(memory.state, 'ACKNOWLEDGED_PENDING')
    console.log(JSON.stringify({ proposal, recall, memory }))
  } else if (scenario === 'roundtrip') {
    const requests = [
      ['read', { target: 'notes/a.txt' }],
      ['propose', { target: 'notes/a.txt', base_sha256: '0'.repeat(64), new_bytes_b64: 'bmV3', note: 'model text' }],
      ['model.call', { grant_id: 'grant', model: 'test-model', messages: [{ role: 'user', content: 'hello' }], tools: [], max_output_tokens: 64 }],
      ['memory.recall', { query: 'hello', limit: 3 }],
      ['memory.put', { cell: { module_sha256: '0'.repeat(64), input_sha256: '1'.repeat(64), effect_sha256: '2'.repeat(64) }, statement: 'hello', category: 'fact' }],
      ['status', {}],
    ]
    const replies = await Promise.all(requests.map(([kind, body]) => link.call(kind, body)))
    assert.deepEqual(replies.map(reply => reply.kind), ['read.reply', 'accepted', 'model.reply', 'recall', 'accepted', 'status.reply'])
    assert.equal(new Set(replies.map(reply => reply.id)).size, 6)
    assert.equal(replies[2].body.tool_calls[0].function.name, 'kira_recall')
    assert.equal(pushed[0].state, 'applied')
    console.log(JSON.stringify({ replies: replies.map(reply => reply.kind), pushed }))
  } else if (scenario === 'timeout' || scenario === 'abort') {
    const controller = new AbortController()
    const promise = link.call('status', {}, { timeoutMs: 30, signal: controller.signal })
    if (scenario === 'abort') setTimeout(() => controller.abort(), 10)
    assert.deepEqual(await promise, { state: 'unknown' })
    await new Promise(resolve => setTimeout(resolve, 130))
    assert.equal(link.pending.size, 0)
    console.log(JSON.stringify({ state: 'unknown' }))
  } else {
    const reply = await link.call('status', {})
    assert.deepEqual(reply, { state: 'unknown' })
    assert.equal(link.closed, true)
    console.log(JSON.stringify({ state: reply.state, code: link.error.code }))
  }
} finally { link.close() }
