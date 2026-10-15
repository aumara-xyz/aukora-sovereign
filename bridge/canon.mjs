// SPDX-License-Identifier: AGPL-3.0-or-later

import * as codes from './codes.mjs'

export const MAX_FRAME_BYTES = 65_536
export const MAX_ORGAN_NPUB_BYTES = 128
export const MAX_OWNER_ORIGIN_BYTES = 2048
export const MAX_SAFE_INTEGER = 9_007_199_254_740_991
const MAX_DEPTH = 64

export class CanonError extends Error {
  constructor(code, offset = 0) {
    super(`${code} at byte ${offset}`)
    this.name = 'CanonError'
    this.code = code
    this.offset = offset
  }
}

const refuse = (code, offset = 0) => { throw new CanonError(code, offset) }

function bytesOf(input) {
  if (typeof input === 'string') {
    if (!wellFormed(input)) refuse(codes.CANON_LONE_SURROGATE)
    return new TextEncoder().encode(input)
  }
  if (input instanceof Uint8Array) return input
  throw new TypeError('canonical input must be a string or Uint8Array')
}

export function parse(input) {
  const bytes = bytesOf(input)
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) refuse(codes.CANON_BOM)
  let text
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    refuse(codes.CANON_INVALID_UTF8)
  }
  const parser = new Parser(text)
  parser.whitespace()
  const value = parser.value(0)
  parser.whitespace()
  if (parser.position !== text.length) refuse(codes.CANON_TRAILING_BYTES, parser.position)
  return value
}

export function canonicalJSON(value) {
  return serialize(value, 0)
}

function serialize(value, depth) {
  if (value === null) return 'null'
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) refuse(codes.CANON_INVALID_JSON)
    if (!Number.isSafeInteger(value)) refuse(codes.CANON_INTEGER_RANGE)
    if (Object.is(value, -0)) refuse(codes.CANON_INVALID_NUMBER)
    return String(value)
  }
  if (typeof value === 'string') {
    if (!wellFormed(value)) refuse(codes.CANON_LONE_SURROGATE)
    return JSON.stringify(value)
  }
  if (typeof value === 'object') {
    if (depth === MAX_DEPTH) refuse(codes.CANON_NESTING_TOO_DEEP)
    if (Array.isArray(value)) {
      const ownKeys = Reflect.ownKeys(value)
      if (ownKeys.some(key => key !== 'length' && (typeof key !== 'string' || !Number.isInteger(Number(key)) || Number(key) < 0 || String(Number(key)) !== key || Number(key) >= value.length))) refuse(codes.CANON_INVALID_JSON)
      const items = []
      for (let index = 0; index < value.length; index++) {
        if (!Object.hasOwn(value, index)) refuse(codes.CANON_INVALID_JSON)
        const descriptor = Object.getOwnPropertyDescriptor(value, index)
        if (!Object.hasOwn(descriptor, 'value')) refuse(codes.CANON_INVALID_JSON)
        items.push(serialize(value[index], depth + 1))
      }
      return `[${items.join(',')}]`
    }
    const prototype = Object.getPrototypeOf(value)
    if (prototype !== Object.prototype && prototype !== null) refuse(codes.CANON_INVALID_JSON)
    if (Object.getOwnPropertySymbols(value).length) refuse(codes.CANON_INVALID_JSON)
    const keys = Object.getOwnPropertyNames(value).sort()
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key)
      if (!descriptor.enumerable) refuse(codes.CANON_INVALID_JSON)
      if (!Object.hasOwn(descriptor, 'value')) refuse(codes.CANON_INVALID_JSON)
    }
    for (const key of keys) if (!wellFormed(key)) refuse(codes.CANON_LONE_SURROGATE)
    return `{${keys.map(key => `${JSON.stringify(key)}:${serialize(value[key], depth + 1)}`).join(',')}}`
  }
  refuse(codes.CANON_INVALID_JSON)
}

function wellFormed(value) {
  for (let index = 0; index < value.length; index++) {
    const unit = value.charCodeAt(index)
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const low = value.charCodeAt(++index)
      if (!(low >= 0xdc00 && low <= 0xdfff)) return false
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return false
  }
  return true
}

class Parser {
  constructor(text) {
    this.text = text
    this.position = 0
  }

  value(depth) {
    const character = this.text[this.position]
    if (character === 'n') return this.literal('null', null)
    if (character === 't') return this.literal('true', true)
    if (character === 'f') return this.literal('false', false)
    if (character === '"') return this.string()
    if (character === '[') return this.array(depth)
    if (character === '{') return this.object(depth)
    if (character === '-' || (character >= '0' && character <= '9')) return this.integer()
    refuse(codes.CANON_INVALID_JSON, this.position)
  }

  literal(token, value) {
    if (!this.text.startsWith(token, this.position)) refuse(codes.CANON_INVALID_JSON, this.position)
    this.position += token.length
    return value
  }

  integer() {
    const start = this.position
    if (this.text[this.position] === '-') this.position++
    const first = this.text[this.position]
    if (first === '0') {
      this.position++
      if (digit(this.text[this.position])) refuse(codes.CANON_INVALID_NUMBER, this.position)
    } else if (first >= '1' && first <= '9') {
      do this.position++
      while (digit(this.text[this.position]))
    } else refuse(codes.CANON_INVALID_NUMBER, this.position)
    const token = this.text.slice(start, this.position)
    if (token === '-0' || ['.', 'e', 'E'].includes(this.text[this.position])) refuse(codes.CANON_INVALID_NUMBER, this.position)
    let integer
    try {
      integer = BigInt(token)
    } catch {
      refuse(codes.CANON_INVALID_NUMBER, start)
    }
    if (integer < -9007199254740991n || integer > 9007199254740991n) refuse(codes.CANON_INTEGER_RANGE, start)
    return Number(integer)
  }

  string() {
    this.position++
    let output = ''
    for (;;) {
      if (this.position >= this.text.length) refuse(codes.CANON_INVALID_JSON, this.position)
      const unit = this.text.charCodeAt(this.position)
      if (unit === 0x22) {
        this.position++
        return output
      }
      if (unit === 0x5c) {
        this.position++
        output += this.escape()
        continue
      }
      if (unit <= 0x1f) refuse(codes.CANON_INVALID_JSON, this.position)
      if (unit >= 0xd800 && unit <= 0xdbff) {
        const low = this.text.charCodeAt(this.position + 1)
        if (!(low >= 0xdc00 && low <= 0xdfff)) refuse(codes.CANON_LONE_SURROGATE, this.position)
        output += this.text.slice(this.position, this.position + 2)
        this.position += 2
      } else if (unit >= 0xdc00 && unit <= 0xdfff) {
        refuse(codes.CANON_LONE_SURROGATE, this.position)
      } else {
        output += this.text[this.position++]
      }
    }
  }

  escape() {
    const escaped = this.text[this.position++]
    const simple = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' }
    if (Object.hasOwn(simple, escaped)) return simple[escaped]
    if (escaped !== 'u') refuse(codes.CANON_INVALID_JSON, this.position)
    const first = this.hexQuad()
    if (first >= 0xd800 && first <= 0xdbff) {
      if (this.text.slice(this.position, this.position + 2) !== '\\u') refuse(codes.CANON_LONE_SURROGATE, this.position)
      this.position += 2
      const second = this.hexQuad()
      if (!(second >= 0xdc00 && second <= 0xdfff)) refuse(codes.CANON_LONE_SURROGATE, this.position)
      return String.fromCodePoint(0x10000 + ((first - 0xd800) << 10) + second - 0xdc00)
    }
    if (first >= 0xdc00 && first <= 0xdfff) refuse(codes.CANON_LONE_SURROGATE, this.position)
    return String.fromCharCode(first)
  }

  hexQuad() {
    const token = this.text.slice(this.position, this.position + 4)
    if (!/^[0-9a-fA-F]{4}$/.test(token)) refuse(codes.CANON_INVALID_JSON, this.position)
    this.position += 4
    return Number.parseInt(token, 16)
  }

  array(depth) {
    if (depth === MAX_DEPTH) refuse(codes.CANON_NESTING_TOO_DEEP, this.position)
    this.position++
    this.whitespace()
    const result = []
    if (this.text[this.position] === ']') {
      this.position++
      return result
    }
    for (;;) {
      result.push(this.value(depth + 1))
      this.whitespace()
      if (this.text[this.position] === ']') {
        this.position++
        return result
      }
      if (this.text[this.position++] !== ',') refuse(codes.CANON_INVALID_JSON, this.position)
      this.whitespace()
    }
  }

  object(depth) {
    if (depth === MAX_DEPTH) refuse(codes.CANON_NESTING_TOO_DEEP, this.position)
    this.position++
    this.whitespace()
    const result = Object.create(null)
    if (this.text[this.position] === '}') {
      this.position++
      return result
    }
    for (;;) {
      if (this.text[this.position] !== '"') refuse(codes.CANON_INVALID_JSON, this.position)
      const key = this.string()
      if (Object.hasOwn(result, key)) refuse(codes.CANON_DUPLICATE_KEY, this.position)
      this.whitespace()
      if (this.text[this.position++] !== ':') refuse(codes.CANON_INVALID_JSON, this.position)
      this.whitespace()
      result[key] = this.value(depth + 1)
      this.whitespace()
      if (this.text[this.position] === '}') {
        this.position++
        return result
      }
      if (this.text[this.position++] !== ',') refuse(codes.CANON_INVALID_JSON, this.position)
      this.whitespace()
    }
  }

  whitespace() {
    while ([' ', '\n', '\r', '\t'].includes(this.text[this.position])) this.position++
  }
}

const digit = character => character >= '0' && character <= '9'

export function decodeFrame(input, direction) {
  requireDirection(direction)
  const bytes = bytesOf(input)
  if (bytes.length > MAX_FRAME_BYTES) refuse(codes.FRAME_TOO_LARGE)
  const frame = parse(bytes)
  const canonical = new TextEncoder().encode(canonicalJSON(frame))
  if (!equalBytes(bytes, canonical)) refuse(codes.FRAME_NOT_CANONICAL)
  exact(frame, ['body', 'id', 'kind', 'v'], ['body', 'id', 'kind', 'v'])
  integerField(frame.v)
  if (frame.v !== 1) refuse(codes.FRAME_UNSUPPORTED_VERSION)
  stringField(frame.id)
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(frame.id)) refuse(codes.FRAME_INVALID_ID)
  stringField(frame.kind)
  validateBody(frame.kind, frame.body, direction)
  return frame
}

export const decodeGuestFrame = input => decodeFrame(input, 'guest')
export const decodeSupervisorFrame = input => decodeFrame(input, 'supervisor')

export function encodeFrame(frame, direction) {
  requireDirection(direction)
  const text = canonicalJSON(frame)
  const bytes = new TextEncoder().encode(text)
  if (bytes.length > MAX_FRAME_BYTES) refuse(codes.FRAME_TOO_LARGE)
  decodeFrame(bytes, direction)
  return bytes
}

function requireDirection(direction) {
  if (direction !== 'guest' && direction !== 'supervisor') refuse(codes.FRAME_INVALID_FIELD)
}

// Field order is normative in crates/canon/src/codes.rs: exact object fields,
// then scalar fields in UTF-16 order, then nested fields in UTF-16 order.
function validateBody(kind, body, direction) {
  if (kind === 'propose' && direction === 'guest') {
    exact(body, ['base_sha256', 'cell', 'new_bytes_b64', 'note', 'target'], ['base_sha256', 'new_bytes_b64', 'note', 'target'])
    digestField(body.base_sha256)
    base64Field(body.new_bytes_b64)
    stringField(body.note)
    stringField(body.target)
    if (Object.hasOwn(body, 'cell')) cell(body.cell)
  } else if (kind === 'read' && direction === 'guest') {
    exact(body, ['target'], ['target'])
    stringField(body.target)
  } else if (kind === 'model.call' && direction === 'guest') {
    exact(body, ['grant_id', 'max_output_tokens', 'messages', 'model', 'tools'], ['grant_id', 'max_output_tokens', 'messages', 'model', 'tools'])
    stringField(body.grant_id)
    countField(body.max_output_tokens, 1, 32_768)
    stringField(body.model)
    arrayField(body.messages)
    for (const message of body.messages) validateMessage(message)
    arrayField(body.tools)
    for (const tool of body.tools) validateTool(tool)
  } else if (kind === 'memory.put' && direction === 'guest') {
    exact(body, ['category', 'cell', 'quote', 'statement'], ['category', 'cell', 'statement'])
    stringField(body.category)
    if (Object.hasOwn(body, 'quote')) stringField(body.quote)
    stringField(body.statement)
    cell(body.cell)
  } else if (kind === 'memory.recall' && direction === 'guest') {
    exact(body, ['limit', 'query'], ['limit', 'query'])
    countField(body.limit, 1, 100)
    stringField(body.query)
  } else if (kind === 'memory.list' && direction === 'guest') {
    exact(body, ['before', 'tier'], ['before', 'tier'])
    if (body.before !== null) boundedStringField(body.before, MAX_FRAME_BYTES)
    memoryTierField(body.tier)
  } else if (kind === 'memory.list.reply' && direction === 'supervisor') {
    validateMemoryListReply(body)
  } else if (kind === 'organs.reply' && direction === 'supervisor') {
    validateOrgansReply(body)
  } else if ((kind === 'status' || kind === 'organs') && direction === 'guest') {
    exact(body, [], [])
  } else if (kind === 'accepted' && direction === 'supervisor') {
    exact(body, ['proposal_id'], ['proposal_id'])
    stringField(body.proposal_id)
  } else if (kind === 'outcome' && direction === 'supervisor') {
    exact(body, ['proposal_id', 'state'], ['proposal_id', 'state'])
    stringField(body.proposal_id)
    stringField(body.state)
    if (!['applied', 'refused', 'expired', 'retired', 'incomplete', 'failed', 'conflict', 'unknown'].includes(body.state)) refuse(codes.FRAME_INVALID_FIELD)
  } else if (kind === 'model.reply' && direction === 'supervisor') {
    exact(body, ['content', 'finish_reason', 'receipt_seq', 'tool_calls', 'usage'], ['content', 'finish_reason', 'receipt_seq', 'tool_calls', 'usage'])
    nullableStringField(body.content)
    nullableStringField(body.finish_reason)
    countField(body.receipt_seq, 1, MAX_SAFE_INTEGER)
    arrayField(body.tool_calls)
    for (const call of body.tool_calls) validateToolCall(call)
    exact(body.usage, ['completion_tokens', 'cost_microusd', 'prompt_tokens'], ['completion_tokens', 'cost_microusd', 'prompt_tokens'])
    countField(body.usage.completion_tokens, 0, 32_768)
    countField(body.usage.cost_microusd, 0, MAX_SAFE_INTEGER)
    countField(body.usage.prompt_tokens, 0, 32_768)
  } else if (kind === 'read.reply' && direction === 'supervisor') {
    exact(body, ['bytes_b64', 'sha256', 'target'], ['bytes_b64', 'sha256', 'target'])
    base64Field(body.bytes_b64)
    digestField(body.sha256)
    stringField(body.target)
  } else if (kind === 'status.reply' && direction === 'supervisor') {
    exact(body, ['bound', 'grant_id', 'grant_remaining', 'ready'], ['bound', 'grant_id', 'grant_remaining', 'ready'])
    booleanField(body.bound)
    nullableStringField(body.grant_id)
    if (body.grant_remaining !== null) countField(body.grant_remaining, 0, MAX_SAFE_INTEGER)
    booleanField(body.ready)
  } else if (kind === 'recall' && direction === 'supervisor') {
    exact(body, ['items', 'result'], ['items', 'result'])
    stringField(body.result)
    if (!['found', 'empty', 'undetermined'].includes(body.result)) refuse(codes.FRAME_INVALID_FIELD)
    arrayField(body.items)
    for (const item of body.items) {
      exact(item, ['cite_seq', 'note_id', 'text'], ['cite_seq', 'note_id', 'text'])
      countField(item.cite_seq, 1, MAX_SAFE_INTEGER)
      stringField(item.note_id)
      stringField(item.text)
    }
  } else if (kind === 'refusal' && direction === 'supervisor') {
    exact(body, ['code', 'next'], ['code', 'next'])
    stringField(body.code)
    if (!codes.ALL.includes(body.code)) refuse(codes.FRAME_INVALID_FIELD)
    stringField(body.next)
  } else refuse(codes.FRAME_UNKNOWN_KIND)
}

function memoryTierField(tier) {
  stringField(tier)
  if (!['remembered', 'forgotten'].includes(tier)) refuse(codes.FRAME_INVALID_FIELD)
}

function validateMemoryListReply(body) {
  const fields = ['items', 'next', 'tier']
  exact(body, fields, fields)
  if (body.next !== null) boundedStringField(body.next, MAX_FRAME_BYTES)
  memoryTierField(body.tier)
  arrayField(body.items)
  for (const item of body.items) {
    const fields = ['at', 'category', 'cite_seq', 'demoted_at', 'demoted_seq', 'note_id', 'text']
    exact(item, fields, fields)
    countField(item.at, 0, MAX_SAFE_INTEGER)
    boundedStringField(item.category, 64)
    if (!/^[A-Za-z0-9_-]+$/.test(item.category)) refuse(codes.FRAME_INVALID_FIELD)
    countField(item.cite_seq, 1, MAX_SAFE_INTEGER)
    if (item.demoted_at !== null) countField(item.demoted_at, 0, MAX_SAFE_INTEGER)
    if (item.demoted_seq !== null) integerField(item.demoted_seq)
    boundedStringField(item.note_id, MAX_FRAME_BYTES)
    nullableStringField(item.text)
    if (body.tier === 'remembered') {
      if (item.text === null || item.demoted_at !== null || item.demoted_seq !== null) refuse(codes.FRAME_INVALID_FIELD)
    } else if (item.text !== null || item.demoted_at === null || item.demoted_seq === null || item.demoted_seq <= item.cite_seq) refuse(codes.FRAME_INVALID_FIELD)
  }
  if (body.items.length > 100) refuse(codes.FRAME_INVALID_FIELD)
}

function validateOrgansReply(body) {
  const fields = ['approvals_pending', 'aumlok', 'aura', 'kira', 'nostr', 'owner_origin', 'wasm']
  exact(body, fields, fields)
  countField(body.approvals_pending, 0, MAX_SAFE_INTEGER)
  boundedStringField(body.owner_origin, MAX_OWNER_ORIGIN_BYTES)
  exact(body.aumlok, ['bound', 'passkeys', 'refresh_due'], ['bound', 'passkeys', 'refresh_due'])
  booleanField(body.aumlok.bound)
  countField(body.aumlok.passkeys, 0, MAX_SAFE_INTEGER)
  booleanField(body.aumlok.refresh_due)
  exact(body.aura, ['root', 'sequence', 'sources'], ['root', 'sequence', 'sources'])
  digestField(body.aura.root)
  countField(body.aura.sequence, 0, MAX_SAFE_INTEGER)
  validateAuraSources(body.aura.sources)
  exact(body.kira, ['demoted', 'notes'], ['demoted', 'notes'])
  countField(body.kira.demoted, 0, MAX_SAFE_INTEGER)
  countField(body.kira.notes, 0, MAX_SAFE_INTEGER)
  exact(body.nostr, ['agent_npub', 'node_npub', 'witness_accepted'], ['agent_npub', 'node_npub', 'witness_accepted'])
  if (body.nostr.agent_npub !== null) boundedStringField(body.nostr.agent_npub, MAX_ORGAN_NPUB_BYTES)
  if (body.nostr.node_npub !== null) boundedStringField(body.nostr.node_npub, MAX_ORGAN_NPUB_BYTES)
  countField(body.nostr.witness_accepted, 0, MAX_SAFE_INTEGER)
  exact(body.wasm, ['module_sha256'], ['module_sha256'])
  digestField(body.wasm.module_sha256)
}

function validateAuraSources(sources) {
  arrayField(sources)
  if (sources.length !== 3) refuse(codes.FRAME_INVALID_FIELD)
  const expected = [
    ['gate-ledger', 'gate-ledger-empty'],
    ['kira-chain', 'kira-ledger-empty'],
    ['code-chain', 'code-record-missing'],
  ]
  for (const [index, [name, absence]] of expected.entries()) {
    const source = sources[index]
    const fields = ['absence', 'entries', 'head', 'name']
    exact(source, fields, fields)
    stringField(source.name)
    if (source.name !== name) refuse(codes.FRAME_INVALID_FIELD)
    integerField(source.entries)
    if (source.head === null) {
      stringField(source.absence)
      if (source.entries !== 0 || source.absence !== absence) refuse(codes.FRAME_INVALID_FIELD)
    } else {
      digestField(source.head)
      if (source.head.length !== 64 || source.entries < 1 || source.absence !== null) refuse(codes.FRAME_INVALID_FIELD)
    }
  }
}

function validateMessage(message) {
  exact(message, ['content', 'role', 'tool_call_id', 'tool_calls'], ['content', 'role'])
  nullableStringField(message.content)
  stringField(message.role)
  if (Object.hasOwn(message, 'tool_call_id')) stringField(message.tool_call_id)
  if (Object.hasOwn(message, 'tool_calls')) {
    arrayField(message.tool_calls)
    for (const call of message.tool_calls) validateToolCall(call)
  }
}

function validateTool(tool) {
  exact(tool, ['function', 'type'], ['function', 'type'])
  stringField(tool.type)
  if (tool.type !== 'function') refuse(codes.FRAME_INVALID_FIELD)
  exact(tool.function, ['description', 'name', 'parameters'], ['description', 'name', 'parameters'])
  stringField(tool.function.description)
  stringField(tool.function.name)
  objectField(tool.function.parameters)
}

function validateToolCall(call) {
  exact(call, ['function', 'id', 'type'], ['function', 'id', 'type'])
  stringField(call.id)
  stringField(call.type)
  if (call.type !== 'function') refuse(codes.FRAME_INVALID_FIELD)
  exact(call.function, ['arguments', 'name'], ['arguments', 'name'])
  stringField(call.function.arguments)
  stringField(call.function.name)
}

function cell(value) {
  exact(value, ['effect_sha256', 'input_sha256', 'module_sha256'], ['effect_sha256', 'input_sha256', 'module_sha256'])
  digestField(value.effect_sha256)
  digestField(value.input_sha256)
  digestField(value.module_sha256)
}

function objectField(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) refuse(codes.FRAME_NOT_OBJECT)
}

function exact(value, allowed, required) {
  objectField(value)
  const keys = Object.keys(value)
  if (keys.some(key => !allowed.includes(key))) refuse(codes.FRAME_UNKNOWN_FIELD)
  if (required.some(key => !Object.hasOwn(value, key))) refuse(codes.FRAME_MISSING_FIELD)
}

function stringField(value) {
  if (typeof value !== 'string') refuse(codes.FRAME_INVALID_FIELD)
}

function boundedStringField(value, maximum) {
  stringField(value)
  const size = new TextEncoder().encode(value).length
  if (size === 0 || size > maximum) refuse(codes.FRAME_INVALID_FIELD)
}

function nullableStringField(value) {
  if (value !== null) stringField(value)
}

function booleanField(value) {
  if (typeof value !== 'boolean') refuse(codes.FRAME_INVALID_FIELD)
}

function arrayField(value) {
  if (!Array.isArray(value)) refuse(codes.FRAME_INVALID_FIELD)
}

function integerField(value) {
  if (!Number.isSafeInteger(value) || Object.is(value, -0)) refuse(codes.FRAME_INVALID_FIELD)
}

function countField(value, minimum, maximum) {
  integerField(value)
  if (value < minimum || value > maximum) refuse(codes.FRAME_INVALID_FIELD)
}

function digestField(value) {
  stringField(value)
  if (!/^[0-9a-f]{64}$/.test(value)) refuse(codes.FRAME_INVALID_FIELD)
}

const base64Field = value => { decodeBase64(value) }

export function decodeBase64(value) {
  stringField(value)
  const bytes = Buffer.from(value, 'base64')
  if (bytes.length > MAX_FRAME_BYTES || bytes.toString('base64') !== value) refuse(codes.FRAME_INVALID_FIELD)
  return bytes
}

function equalBytes(left, right) {
  return left.length === right.length && left.every((byte, index) => byte === right[index])
}

// The reader copies each received byte once into a length prefix or payload.
// Partial chunks and multiple frames per chunk share the same bounded buffer.
// Returned payloads require decodeFrame(payload, direction) before interpretation.
// read()/readFrame() require exactly one frame; EOF is a fatal short read.
// Async iteration permits a clean EOF between frames, never inside a frame.
export class FrameReader {
  constructor(stream) {
    this.stream = stream
    this.iterator = stream[Symbol.asyncIterator]()
    this.chunk = Buffer.alloc(0)
    this.offset = 0
    this.failure = null
    this.pending = Promise.resolve()
  }

  read() { return this.queuedRead(false) }

  queuedRead(allowEOF) {
    const operation = this.pending.then(() => this.readOne(allowEOF))
    this.pending = operation.catch(() => {})
    return operation
  }

  readFrame() { return this.read() }

  async readOne(allowEOF) {
    if (this.failure) throw this.failure
    const header = Buffer.alloc(4)
    const prefixBytes = await this.fill(header)
    if (prefixBytes === 0 && allowEOF) return null
    if (prefixBytes !== header.length) this.fatal(codes.FRAME_SHORT_READ)
    const length = header.readUInt32BE(0)
    if (length === 0) this.fatal(codes.FRAME_ZERO_LENGTH)
    if (length > MAX_FRAME_BYTES) this.fatal(codes.FRAME_TOO_LARGE)
    const payload = Buffer.alloc(length)
    if (await this.fill(payload) !== length) this.fatal(codes.FRAME_SHORT_READ)
    return payload
  }

  async fill(target) {
    let written = 0
    while (written < target.length) {
      if (this.offset === this.chunk.length) {
        let next
        try { next = await this.iterator.next() } catch { this.fatal(codes.FRAME_IO) }
        if (next.done) return written
        if (!(next.value instanceof Uint8Array)) this.fatal(codes.FRAME_IO)
        this.chunk = next.value
        this.offset = 0
        if (this.chunk.length === 0) continue
      }
      const count = Math.min(target.length - written, this.chunk.length - this.offset)
      target.set(this.chunk.subarray(this.offset, this.offset + count), written)
      written += count
      this.offset += count
    }
    return written
  }

  fatal(code) {
    this.failure = new CanonError(code)
    this.stream.destroy()
    throw this.failure
  }

  async *[Symbol.asyncIterator]() {
    for (;;) {
      const payload = await this.queuedRead(true)
      if (payload === null) return
      yield payload
    }
  }
}

const writes = new WeakMap()

// Prefix a raw payload from encodeFrame(frame, direction).
// Node streams serialize callbacks; the queue also prevents separate callers
// from putting a second framed write in flight before the first completes.
export function writeFrame(stream, input) {
  const operation = (writes.get(stream) ?? Promise.resolve()).then(async () => {
    const bytes = bytesOf(input)
    if (bytes.length === 0 || bytes.length > MAX_FRAME_BYTES) {
      stream.destroy()
      refuse(bytes.length === 0 ? codes.FRAME_ZERO_LENGTH : codes.FRAME_TOO_LARGE)
    }
    const wire = Buffer.alloc(bytes.length + 4)
    wire.writeUInt32BE(bytes.length, 0)
    wire.set(bytes, 4)
    await new Promise((resolve, reject) => {
      const onError = () => { stream.destroy(); reject(new CanonError(codes.FRAME_IO)) }
      // Node emits a write error after its callback; keep the once listener in
      // place on failure so that event cannot become an unhandled exception.
      stream.once?.('error', onError)
      try {
        stream.write(wire, error => {
          if (error) onError()
          else {
            stream.removeListener?.('error', onError)
            resolve()
          }
        })
      } catch { onError() }
    })
  })
  writes.set(stream, operation.catch(() => {}))
  return operation
}
