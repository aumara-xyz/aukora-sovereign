// SPDX-License-Identifier: AGPL-3.0-or-later
// Restated from aukora-prime plugins/aukora-kira/lib/wasm-proposal.mjs and wasm-cell/aukora/guest/wasm-proposal-cell.mjs.
import { createHash } from 'node:crypto'
import { runInNewContext } from 'node:vm'
import { canonicalJSON, parse } from './canon.mjs'
import { GuestRefusal } from './fd3.mjs'

const MODULE_BASE64 = 'AGFzbQEAAAABCQFgBH9/f38BfwIdAQZhdWtvcmEScHJvcG9zZV9tZW1vcnlfcHV0AAADAgEABQQBAQEBBxcCBm1lbW9yeQIACm1lbW9yeV9wdXQAAQoOAQwAIAAgASACIAMQAAs='
const MODULE_BYTES = Buffer.from(MODULE_BASE64, 'base64')
export const MODULE_SHA256 = '34ce6cab618b626243e876befb49ccf8a6780dc836e757484886b34ae977a438'
export const CELL_BUDGET_BYTES = 65_536
const KEY_SHAPE = /^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/
const EXPECTED_IMPORTS = [{ module: 'aukora', name: 'propose_memory_put', kind: 'function' }]
const EXPECTED_EXPORTS = [{ name: 'memory', kind: 'memory' }, { name: 'memory_put', kind: 'function' }]
const utf8 = new TextDecoder('utf-8', { fatal: true })

const refuse = reason => { throw new GuestRefusal(`wasm-cell:${reason}`) }
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex')

export function exactDataObject(input, required, optional = []) {
  try {
    const proto = Reflect.getPrototypeOf(input)
    if (proto !== Object.prototype && proto !== null) return null
    const keys = Reflect.ownKeys(input)
    if (keys.some(key => !required.includes(key) && !optional.includes(key))
      || required.some(key => !keys.includes(key))) return null
    const result = Object.create(null)
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(input, key)
      if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) return null
      result[key] = descriptor.value
    }
    return result
  } catch {
    return null
  }
}

function exactArgs(input) {
  const args = exactDataObject(input, ['key', 'value'])
  if (args === null || typeof args.key !== 'string' || args.value === undefined) refuse('arguments-not-exact')
  if (!KEY_SHAPE.test(args.key)) refuse('key-not-a-name')
  return args
}

export function cellEffectBody(input) {
  const args = exactArgs(input)
  return `${canonicalJSON(args)}\n`
}

export function consumeMemoryPutCellProposal(input, executingArgs, reviewedArgs) {
  const fields = exactDataObject(input, ['argumentsJson', 'moduleSha256', 'toolName'])
  if (fields === null || Object.values(fields).some(value => typeof value !== 'string')) refuse('proposal-fields-not-exact')
  if (fields.toolName !== 'memory.put') refuse('tool-name-mismatch')
  if (fields.moduleSha256 !== MODULE_SHA256) refuse('module-digest-mismatch')
  let detached
  try { detached = parse(fields.argumentsJson) } catch { refuse('arguments-json-invalid') }
  exactArgs(detached)
  if (canonicalJSON(detached) !== fields.argumentsJson) refuse('arguments-json-not-canonical')
  if (fields.argumentsJson !== canonicalJSON(exactArgs(executingArgs))
    || fields.argumentsJson !== canonicalJSON(exactArgs(reviewedArgs))) refuse('arguments-binding-mismatch')
  return detached
}

function compilePinnedModule() {
  if (MODULE_BYTES.length !== 101 || sha256(MODULE_BYTES) !== MODULE_SHA256) refuse('module-digest-mismatch')
  const module = new WebAssembly.Module(MODULE_BYTES)
  if (JSON.stringify(WebAssembly.Module.imports(module)) !== JSON.stringify(EXPECTED_IMPORTS)) refuse('import-inventory-mismatch')
  if (JSON.stringify(WebAssembly.Module.exports(module)) !== JSON.stringify(EXPECTED_EXPORTS)) refuse('export-inventory-mismatch')
  return module
}

function decodeMemory(memory, offset, length, label) {
  if (!(memory instanceof WebAssembly.Memory)) refuse('memory-not-ready')
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || offset < 0 || length < 0
    || offset + length > memory.buffer.byteLength) refuse(`${label}-range-invalid`)
  try { return utf8.decode(new Uint8Array(memory.buffer, offset, length)) } catch { refuse(`${label}-utf8-invalid`) }
}

function runCell(keyBytes, valueBytes) {
  const module = compilePinnedModule()
  let proposal = null
  let memory = null
  const imports = { aukora: { propose_memory_put(keyOffset, keyLength, valueOffset, valueLength) {
    if (proposal !== null) refuse('proposal-already-emitted')
    const key = decodeMemory(memory, keyOffset, keyLength, 'key')
    const encodedValue = decodeMemory(memory, valueOffset, valueLength, 'value')
    let value
    try { value = parse(encodedValue) } catch { refuse('value-json-invalid') }
    if (canonicalJSON(value) !== encodedValue) refuse('value-json-not-canonical')
    if (!KEY_SHAPE.test(key)) refuse('key-not-a-name')
    proposal = Object.freeze({ toolName: 'memory.put', argumentsJson: canonicalJSON({ key, value }), moduleSha256: MODULE_SHA256 })
    return 1
  } } }
  const instance = new WebAssembly.Instance(module, imports)
  memory = instance.exports.memory
  if (!(memory instanceof WebAssembly.Memory) || memory.buffer.byteLength !== CELL_BUDGET_BYTES) refuse('memory-export-invalid')
  const bytes = new Uint8Array(memory.buffer)
  bytes.set(keyBytes, 0)
  bytes.set(valueBytes, keyBytes.length)
  const result = instance.exports.memory_put(0, keyBytes.length, keyBytes.length, valueBytes.length)
  if (result !== 1 || proposal === null) refuse('proposal-not-emitted')
  return proposal
}

export function proposeMemoryPutInWasm(input) {
  const args = exactArgs(input)
  const keyBytes = Buffer.from(args.key, 'utf8')
  const valueBytes = Buffer.from(canonicalJSON(args.value), 'utf8')
  if (keyBytes.length + valueBytes.length > CELL_BUDGET_BYTES) refuse('proposal-too-large')
  try {
    return runInNewContext('run()', { run: () => runCell(keyBytes, valueBytes) }, { timeout: 100 })
  } catch (error) {
    if (error?.code === 'ERR_SCRIPT_EXECUTION_TIMEOUT') refuse('execution-timeout')
    throw error
  }
}

export function memoryCellProof(input) {
  const args = exactArgs(input)
  const inputJson = canonicalJSON(args)
  const detached = consumeMemoryPutCellProposal(proposeMemoryPutInWasm(args), args, parse(inputJson))
  return { module_sha256: MODULE_SHA256, input_sha256: sha256(inputJson), effect_sha256: sha256(cellEffectBody(detached)) }
}
