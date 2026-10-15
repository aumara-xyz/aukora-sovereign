// SPDX-License-Identifier: AGPL-3.0-or-later
import { canonicalJSON, parse } from './canon.mjs'
import { GuestRefusal } from './fd3.mjs'
import { cellEffectBody, exactDataObject, memoryCellProof, sha256 } from './wasm-cell.mjs'

const refuse = reason => { throw new GuestRefusal(`guest:${reason}`) }
const object = (input, required, optional = []) => {
  const fields = exactDataObject(input, required, optional)
  if (fields === null) refuse('tool-arguments-invalid')
  return fields
}
const text = (value, nonempty = false) => {
  if (typeof value !== 'string' || (nonempty && value.length === 0)) refuse('tool-arguments-invalid')
  canonicalJSON(value)
  return value
}
const unknown = reply => reply?.state === 'unknown'

function replyBody(reply, kind, required, optional = []) {
  if (reply?.kind === 'refusal') throw new GuestRefusal(reply.body?.code ?? 'guest:supervisor-refused', reply.body?.next)
  if (reply?.kind !== kind) refuse('reply-kind-invalid')
  const body = exactDataObject(reply.body, required, optional)
  if (body === null) refuse('reply-body-invalid')
  return body
}

function proposalId(body) {
  if (typeof body.proposal_id !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(body.proposal_id)) refuse('reply-body-invalid')
  return body.proposal_id
}

export function memoryCellArguments(input) {
  const fields = object(input, ['statement', 'category'], ['quote'])
  const value = { category: text(fields.category, true), statement: text(fields.statement, true) }
  if (Object.hasOwn(fields, 'quote')) value.quote = text(fields.quote)
  return { key: `memory:${sha256(canonicalJSON(value))}`, value }
}

export function createTools(link, config = {}) {
  const timeoutMs = config.timeoutMs ?? 20_000
  const callOptions = exec => ({ timeoutMs, signal: exec?.signal })
  const output = { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] }
  const tool = (name, description, parameters, execute) => ({
    name, description, parameters, execute, output, timeoutMs: timeoutMs * 2,
    isConcurrencySafe: () => false,
  })
  return [
    tool('aukora_propose', 'Propose exact replacement text or a pinned-cell {key,value} effect for owner review. Supply exactly one of text or cell. A queued proposal is PENDING_OWNER; only the owner can approve it.', {
      type: 'object', additionalProperties: false, required: ['target', 'note'],
      oneOf: [{ required: ['text'] }, { required: ['cell'] }],
      properties: {
        target: { type: 'string' }, text: { type: 'string' }, note: { type: 'string' },
        cell: { type: 'object', additionalProperties: false, required: ['key', 'value'], properties: { key: { type: 'string' }, value: {} } },
      },
    }, async (input, exec) => {
      const args = object(input, ['target', 'note'], ['text', 'cell'])
      if (Object.hasOwn(args, 'text') === Object.hasOwn(args, 'cell')) refuse('tool-arguments-invalid')
      const target = text(args.target, true)
      const note = text(args.note)
      let newBytes
      let cell
      if (Object.hasOwn(args, 'cell')) {
        const pair = parse(canonicalJSON(args.cell))
        cell = memoryCellProof(pair)
        newBytes = Buffer.from(cellEffectBody(pair), 'utf8')
      } else newBytes = Buffer.from(text(args.text), 'utf8')
      const read = await link.call('read', { target }, callOptions(exec))
      if (unknown(read)) return JSON.stringify({ state: 'unknown' })
      const base = replyBody(read, 'read.reply', ['target', 'sha256', 'bytes_b64'])
      if (base.target !== target || typeof base.bytes_b64 !== 'string'
        || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(base.bytes_b64)) refuse('read-reply-invalid')
      const baseBytes = Buffer.from(base.bytes_b64, 'base64')
      if (baseBytes.toString('base64') !== base.bytes_b64 || sha256(baseBytes) !== base.sha256) refuse('read-digest-mismatch')
      const body = { target, base_sha256: sha256(baseBytes), new_bytes_b64: newBytes.toString('base64'), note }
      if (cell !== undefined) body.cell = cell
      const reply = await link.call('propose', body, callOptions(exec))
      if (unknown(reply)) return JSON.stringify({ state: 'unknown' })
      const accepted = replyBody(reply, 'accepted', ['proposal_id'])
      return JSON.stringify({ state: 'PENDING_OWNER', proposal_id: proposalId(accepted) })
    }),
    tool('kira_recall', 'Recall cited memory. An undetermined reply does not mean that no memory exists.', {
      type: 'object', additionalProperties: false, required: ['query'],
      properties: { query: { type: 'string' }, limit: { type: 'integer', minimum: 1, maximum: 100 } },
    }, async (input, exec) => {
      const args = object(input, ['query'], ['limit'])
      const query = text(args.query)
      const limit = args.limit ?? 10
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) refuse('tool-arguments-invalid')
      const reply = await link.call('memory.recall', { query, limit }, callOptions(exec))
      if (unknown(reply)) return JSON.stringify({ result: 'undetermined', items: [] })
      const body = replyBody(reply, 'recall', ['result', 'items'])
      if (!['found', 'empty', 'undetermined'].includes(body.result) || !Array.isArray(body.items)) refuse('recall-reply-invalid')
      for (const item of body.items) {
        const fields = exactDataObject(item, ['note_id', 'text', 'cite_seq'])
        if (fields === null || typeof fields.note_id !== 'string' || fields.note_id.length === 0
          || typeof fields.text !== 'string' || !Number.isSafeInteger(fields.cite_seq) || fields.cite_seq < 1) refuse('recall-reply-invalid')
      }
      return JSON.stringify(body)
    }),
    tool('kira_save', 'Capture a statement through the pinned proposal cell. An acknowledgement does not prove that memory was saved.', {
      type: 'object', additionalProperties: false, required: ['statement', 'category'],
      properties: { statement: { type: 'string' }, quote: { type: 'string' }, category: { type: 'string' } },
    }, async (input, exec) => {
      const args = memoryCellArguments(input)
      const cell = memoryCellProof(args)
      const reply = await link.call('memory.put', { cell, ...args.value }, callOptions(exec))
      if (unknown(reply)) return JSON.stringify({ state: 'unknown' })
      if (reply?.kind === 'outcome') return JSON.stringify({ state: 'unknown' })
      const accepted = replyBody(reply, 'accepted', ['proposal_id'])
      return JSON.stringify({ state: 'ACKNOWLEDGED_PENDING', proposal_id: proposalId(accepted) })
    }),
  ]
}

export function registerTools(ctx, link, config = {}) {
  return createTools(link, config).map(tool => ctx.tools.register(tool))
}
