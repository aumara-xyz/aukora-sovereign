// SPDX-License-Identifier: AGPL-3.0-or-later
//
// C1 canonical JSON and the door call digest, byte-for-byte what crates/canon/src/json.rs produces.
//
// Objects sort by UTF-16 code units, arrays keep index order, no insignificant whitespace, strings escape
// quote, backslash and the five short controls (\b \f \n \r \t), other U+0000..U+001F as lowercase \u00xx, every
// other scalar literal UTF-8. Integers alone, in -(2^53-1)..=(2^53-1), no -0, no fraction, no exponent. The only
// literals are null, true and false. Depth at most 64 containers. No lone surrogates.
//
// The input is the data a tool call carries, which a hostile plugin may have shaped, so this reads it as plain
// data only: own enumerable string keys with data descriptors, no accessors, no proxies, no class instances, and
// each value is read exactly once.

import { createHash } from 'node:crypto'
import { types } from 'node:util'

/** Domain tag for the call digest (NUL follows it, then u32be(len(tool)), the tool name, the canonical arguments). */
export const DOOR_CALL_DOMAIN = 'aukora:door-call:v1'
/** Deepest container nesting C1 accepts, counting the root container. */
export const MAX_DEPTH = 64
/** Largest integer magnitude C1 accepts. */
export const MAX_SAFE_INTEGER = 9_007_199_254_740_991
/** Longest tool name, in UTF-8 bytes, the digest accepts. */
export const MAX_TOOL_NAME_BYTES = 256

/** A refusal to canonicalize, with a stable code the caller can route on. */
export class CanonError extends Error {
  code: string

  constructor(code: string, message: string) {
    super(message)
    this.name = 'CanonError'
    this.code = code
  }
}

const SHORT_ESCAPES: Record<number, string> = { 8: '\\b', 9: '\\t', 10: '\\n', 12: '\\f', 13: '\\r' }

function hex4(unit: number): string {
  return unit.toString(16).padStart(4, '0')
}

function writeString(text: string, out: string[]): void {
  if (!text.isWellFormed()) throw new CanonError('canon-surrogate', 'string holds a lone surrogate')
  out.push('"')
  let run = 0
  for (let i = 0; i < text.length; i += 1) {
    const unit = text.charCodeAt(i)
    let escaped: string | undefined
    if (unit === 0x22) escaped = '\\"'
    else if (unit === 0x5c) escaped = '\\\\'
    else if (unit < 0x20) escaped = SHORT_ESCAPES[unit] ?? `\\u${hex4(unit)}`
    if (escaped !== undefined) {
      out.push(text.slice(run, i), escaped)
      run = i + 1
    }
  }
  out.push(text.slice(run), '"')
}

function writeInteger(value: number, out: string[]): void {
  if (!Number.isInteger(value)) throw new CanonError('canon-number', 'only integers are canonical (no fraction, NaN or infinity)')
  if (Object.is(value, -0)) throw new CanonError('canon-number', 'negative zero is not canonical')
  if (Math.abs(value) > MAX_SAFE_INTEGER) throw new CanonError('canon-number', 'integer outside the safe range')
  out.push(String(value))
}

function dataValue(holder: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(holder, key)
  if (descriptor === undefined || !('value' in descriptor)) {
    throw new CanonError('canon-accessor', 'property is missing or an accessor')
  }
  return descriptor.value
}

function write(value: unknown, depth: number, out: string[]): void {
  if (value === null) {
    out.push('null')
    return
  }
  switch (typeof value) {
    case 'boolean':
      out.push(value ? 'true' : 'false')
      return
    case 'number':
      writeInteger(value, out)
      return
    case 'string':
      writeString(value, out)
      return
    case 'object':
      break
    default:
      throw new CanonError('canon-type', `a ${typeof value} is not JSON data`)
  }
  if (types.isProxy(value)) throw new CanonError('canon-proxy', 'a proxy is not plain data')
  if (depth + 1 > MAX_DEPTH) throw new CanonError('canon-depth', `nesting beyond ${MAX_DEPTH} containers`)
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype) throw new CanonError('canon-class', 'only plain arrays are JSON data')
    const keys = Reflect.ownKeys(value)
    if (keys.length !== value.length + 1) throw new CanonError('canon-array', 'array is sparse or has extra properties')
    out.push('[')
    for (let i = 0; i < value.length; i += 1) {
      if (i > 0) out.push(',')
      write(dataValue(value, String(i)), depth + 1, out)
    }
    out.push(']')
    return
  }
  const proto = Object.getPrototypeOf(value)
  if (proto !== Object.prototype && proto !== null) throw new CanonError('canon-class', 'only plain objects are JSON data')
  const names: string[] = []
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') throw new CanonError('canon-symbol', 'symbol keys are not JSON data')
    const descriptor = Object.getOwnPropertyDescriptor(value, key)
    if (descriptor === undefined || !descriptor.enumerable) throw new CanonError('canon-hidden', 'non-enumerable property')
    names.push(key)
  }
  names.sort()
  out.push('{')
  for (let i = 0; i < names.length; i += 1) {
    const name = names[i] as string
    if (i > 0) out.push(',')
    writeString(name, out)
    out.push(':')
    write(dataValue(value, name), depth + 1, out)
  }
  out.push('}')
}

/** The C1 canonical text of a JSON value, or a CanonError saying exactly why it is not canonical data. */
export function canonicalize(value: unknown): string {
  const out: string[] = []
  write(value, 0, out)
  return out.join('')
}

/** What the door signs over and the Rust side recomputes: the digest of one tool call. */
export interface BoundCall {
  /** The tool name exactly as dispatched. */
  tool: string
  /** The canonical arguments as text. */
  argsText: string
  /** The canonical arguments as UTF-8 bytes (what travels, base64, in the frame). */
  argsBytes: Buffer
  /** SHA-256 over domain, NUL, u32be(len(tool)), tool, canonical arguments; lowercase hex. */
  digest: string
}

/** Digest of a tool call from its name and canonical argument bytes. */
export function callDigestHex(tool: string, argsBytes: Uint8Array): string {
  if (!tool.isWellFormed()) throw new CanonError('canon-tool', 'tool name holds a lone surrogate')
  const name = Buffer.from(tool, 'utf8')
  if (name.length === 0 || name.length > MAX_TOOL_NAME_BYTES) throw new CanonError('canon-tool', 'tool name length is out of range')
  if (name.includes(0)) throw new CanonError('canon-tool', 'tool name holds a NUL')
  const length = Buffer.alloc(4)
  length.writeUInt32BE(name.length)
  const hash = createHash('sha256')
  hash.update(DOOR_CALL_DOMAIN)
  hash.update(Buffer.from([0]))
  hash.update(length)
  hash.update(name)
  hash.update(argsBytes)
  return hash.digest('hex')
}

/** Canonicalize and digest one call. Reads the live arguments exactly once. */
export function bindCall(tool: unknown, args: unknown): BoundCall {
  if (typeof tool !== 'string') throw new CanonError('canon-tool', 'tool name is not a string')
  const argsText = canonicalize(args)
  const argsBytes = Buffer.from(argsText, 'utf8')
  return { tool, argsText, argsBytes, digest: callDigestHex(tool, argsBytes) }
}
