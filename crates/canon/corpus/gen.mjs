// SPDX-License-Identifier: AGPL-3.0-or-later
// Deterministic Node differential artifacts. --write refreshes checked-in cases;
// default verifies exact source/expected-output reproducibility without writing.
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { Readable } from 'node:stream'
import { canonicalJSON, decodeBase64, decodeFrame, encodeFrame, FrameReader, parse } from '../../../bridge/canon.mjs'
import * as codes from '../../../bridge/codes.mjs'

const here = dirname(fileURLToPath(import.meta.url))
const root = resolve(here, '../../..')
const writing = process.argv.includes('--write')
const corpus = []
const vectors = []
let seed = 0x41554b4f
const random = n => { seed ^= seed << 13; seed ^= seed >>> 17; seed ^= seed << 5; return (seed >>> 0) % n }
const clone = x => JSON.parse(JSON.stringify(x))
// Independent restatement of Prime's JSON.stringify + UTF-16 key sort. Array.from
// is deliberate: the reference emits null for holes; our strict input refuses holes.
const prime = v => v === null || typeof v !== 'object' ? JSON.stringify(v)
  : Array.isArray(v) ? `[${Array.from(v, prime).join(',')}]`
    : `{${Object.keys(v).sort().map(k => `${JSON.stringify(k)}:${prime(v[k])}`).join(',')}}`
const frame = (kind, body) => ({v: 1, id: 'a', kind, body})
const cell = {module_sha256: 'a'.repeat(64), input_sha256: 'b'.repeat(64), effect_sha256: 'c'.repeat(64)}
const call = {id: 'tc', type: 'function', function: {name: 'read', arguments: '{"target":"note.md"}'}}
const tool = {type: 'function', function: {name: 'read', description: 'Read a target', parameters: {type: 'object', properties: {'😀': {type: 'string'}, '\ue000': {type: 'string'}}, required: ['😀']}}}
const samples = [
  ['guest', frame('propose', {target: 'note.md', base_sha256: 'd'.repeat(64), new_bytes_b64: 'bg==', note: '中😀\u2028\u2029\u007f\u0000\b\f\n\r\t"\\', cell})],
  ['guest', frame('read', {target: 'note.md'})],
  ['guest', frame('model.call', {grant_id: 'g', model: 'm', messages: [{role: 'assistant', content: null, tool_calls: [call]}, {role: 'tool', content: 'ok', tool_call_id: 'tc'}], tools: [tool], max_output_tokens: 32768})],
  ['guest', frame('memory.put', {category: 'fact', statement: 's', quote: 'q', cell})],
  ['guest', frame('memory.recall', {limit: 100, query: 'q'})],
  ['guest', frame('status', {})],
  ['supervisor', frame('accepted', {proposal_id: 'p'})],
  ['supervisor', frame('outcome', {proposal_id: 'p', state: 'applied'})],
  ['supervisor', frame('model.reply', {content: null, tool_calls: [call], finish_reason: 'tool_calls', usage: {prompt_tokens: 32768, completion_tokens: 0, cost_microusd: 9007199254740991}, receipt_seq: 9007199254740991})],
  ['supervisor', frame('read.reply', {target: 'note.md', sha256: 'f'.repeat(64), bytes_b64: 'bg=='})],
  ['supervisor', frame('status.reply', {ready: true, bound: false, grant_id: null, grant_remaining: null})],
  ['supervisor', frame('recall', {result: 'found', items: [{cite_seq: 1, note_id: 'n', text: '中😀'}]})],
  ['supervisor', frame('refusal', {code: codes.GATE_STALE_BASE, next: 'review'})]
]
async function add(name, mode, input, direction, expectedCode) {
  const bytes = Buffer.isBuffer(input) ? input : Buffer.from(input)
  const item = {name, mode, ...(direction ? {direction} : {}), input_hex: bytes.toString('hex')}
  try {
    let output
    if (mode === 'parse') {
      const value = parse(bytes)
      if (expectedCode) throw new Error(`${name}: parse accepted, expected ${expectedCode}`)
      output = canonicalJSON(value)
    }
    else if (mode === 'base64') output = decodeBase64(bytes.toString('utf8'))
    else {
      let payload = bytes
      if (mode === 'transport' || mode === 'transport-io') {
        const stream = mode === 'transport-io' ? Readable.from((async function* () { throw new Error('injected read failure') })()) : Readable.from([bytes])
        const reader = new FrameReader(stream)
        payload = await reader.read()
        if (payload === null) throw new Error('empty transport case has no requested frame')
      }
      const value = decodeFrame(payload, direction)
      output = canonicalJSON(value)
      assert.equal(Buffer.from(encodeFrame(value, direction)).toString('utf8'), output)
      assert.equal(output, prime(JSON.parse(output)), `${name}: independent Prime bytes`)
    }
    if (expectedCode) throw new Error(`${name}: accepted, expected ${expectedCode}`)
    if (mode === 'base64') item.output_hex = output.toString('hex')
    else item.canonical = output
  } catch (error) {
    if (!error.code || !codes.ALL.includes(error.code)) throw error
    if (expectedCode) assert.equal(error.code, expectedCode, name)
    item.code = error.code
  }
  corpus.push(item)
}
const addFrame = (name, value, direction, code) => add(name, 'frame', prime(value), direction, code)
function paths(value, prefix = []) {
  const out = []
  if (value !== null && typeof value === 'object') {
    for (const key of Object.keys(value)) {
      const path = [...prefix, key]
      out.push(path)
      out.push(...paths(value[key], path))
    }
  }
  return out
}
function change(value, path, replacement, remove = false) {
  const copy = clone(value)
  let parent = copy
  for (const key of path.slice(0, -1)) parent = parent[key]
  if (remove) delete parent[path.at(-1)]
  else parent[path.at(-1)] = replacement
  return copy
}
for (const [direction, sample] of samples) {
  await addFrame(`${sample.kind} accepted`, sample, direction)
  await addFrame(`${sample.kind} wrong direction`, sample, direction === 'guest' ? 'supervisor' : 'guest', codes.FRAME_UNKNOWN_KIND)
  for (const path of paths(sample)) {
    // Array deletion is avoided here: sparse arrays belong to JS value tests,
    // while every shared artifact is actual bytes received on FD 3.
    if (!/^\d+$/.test(path.at(-1))) await addFrame(`${sample.kind} missing ${path.join('.')}`, change(sample, path, null, true), direction)
    for (const bad of [null, false, -1, 0, 32769, '', 'UPPER', [], {}]) {
      await addFrame(`${sample.kind} ${path.join('.')} -> ${JSON.stringify(bad)}`, change(sample, path, bad), direction)
    }
  }
  const extra = clone(sample); extra.body.extra = 0
  await addFrame(`${sample.kind} unknown body and missing id`, change(extra, ['id'], null, true), direction, codes.FRAME_MISSING_FIELD)
  for (let n = 0; n < 40; n++) {
    const all = paths(sample)
    let value = change(sample, all[random(all.length)], [null, {}, [], 'bad', -1][random(5)])
    const current = paths(value)
    value = change(value, current[random(current.length)], [false, {}, [], 0, ''][random(5)])
    await addFrame(`${sample.kind} seeded two-defect ${n}`, value, direction)
  }
}
// Explicit precedence pins and reproductions from the findings.
const multi = [
  ['model.call', {grant_id: 1, max_output_tokens: 1, messages: [1], model: 'm', tools: []}, 'guest', codes.FRAME_INVALID_FIELD],
  ['memory.put', {category: 'c', cell: 1, statement: 1}, 'guest', codes.FRAME_INVALID_FIELD],
  ['memory.put', {category: 1, cell: null, statement: 's'}, 'guest', codes.FRAME_INVALID_FIELD],
  ['memory.put', {category: 'c', cell: {}, statement: 1}, 'guest', codes.FRAME_INVALID_FIELD],
  ['recall', {items: [1], result: 'bogus'}, 'supervisor', codes.FRAME_INVALID_FIELD],
  ['recall', {items: [{}], result: 'x'}, 'supervisor', codes.FRAME_INVALID_FIELD]
]
for (const [kind, body, direction, code] of multi) await addFrame(`findings ${kind} ${corpus.length}`, frame(kind, body), direction, code)
for (const v of [null, true, [], {}, '1']) await addFrame(`v type ${JSON.stringify(v)} plus invalid id/kind`, {...frame('unknown', {}), v, id: 0}, 'guest', codes.FRAME_INVALID_FIELD)
await addFrame('v value precedes id type', {...frame('status', {}), v: 2, id: 0}, 'guest', codes.FRAME_UNSUPPORTED_VERSION)
for (const id of [null, 1, [], {}]) await addFrame(`id type ${JSON.stringify(id)}`, {...frame('status', {}), id}, 'guest', codes.FRAME_INVALID_FIELD)
for (const id of ['', '!', 'é', '😀', 'a'.repeat(65)]) await addFrame(`id charset-length ${id}`, {...frame('status', {}), id}, 'guest', codes.FRAME_INVALID_ID)
await addFrame('id max length', {...frame('status', {}), id: 'a'.repeat(64)}, 'guest')
for (const state of ['applied','refused','expired','retired','incomplete','failed','conflict','unknown']) await addFrame(`outcome ${state}`, frame('outcome',{proposal_id:'p',state}), 'supervisor')
for (const result of ['found','empty','undetermined']) await addFrame(`recall ${result}`, frame('recall',{result,items:[]}), 'supervisor')
for (const code of codes.ALL) await addFrame(`registry refusal ${code}`, frame('refusal',{code,next:'review'}),'supervisor')
for (const text of ['', 'bg==', 'bm8=', 'bmV3', 'bh==', 'bm9=', 'bg', 'b g = =', 'bg==junk', '!!!!', '====', 'AA-_', 'a===']) {
  await add('standard base64 '+text, 'base64', text)
  const value = clone(samples[0][1]); value.body.new_bytes_b64 = text
  await addFrame('propose base64 '+text, value, 'guest')
}
for (const n of [65535,65536,65537]) await add(`decoded base64 ${n}`, 'base64', Buffer.alloc(n,0x61).toString('base64'), undefined, n >65536 ? codes.FRAME_INVALID_FIELD : undefined)
for (const text of ['-9223372036854775808','[-9223372036854775808"x"]','-9223372036854775808\u000b','-9223372036854775809','9223372036854775807','9007199254740992','-9007199254740992']) {
  await add(`integer range ${JSON.stringify(text)}`,'parse',text,undefined,codes.CANON_INTEGER_RANGE)
  await add(`frame integer range ${JSON.stringify(text)}`,'frame',text,'guest',codes.CANON_INTEGER_RANGE)
}
for (const [input,code] of [
  ['{"a":1,"a":2}',codes.CANON_DUPLICATE_KEY], ['{"a":1,"\\u0061":2}',codes.CANON_DUPLICATE_KEY],
  ['-0',codes.CANON_INVALID_NUMBER],['1.0',codes.CANON_INVALID_NUMBER],['1e0',codes.CANON_INVALID_NUMBER],['01',codes.CANON_INVALID_NUMBER],
  ['"\\ud800"',codes.CANON_LONE_SURROGATE],['"\\udc00"',codes.CANON_LONE_SURROGATE],
  ['"\\ud800\\u0061"',codes.CANON_LONE_SURROGATE],['"\\ud800\\u00xz"',codes.CANON_INVALID_JSON],
  ['null true',codes.CANON_TRAILING_BYTES],['[',codes.CANON_INVALID_JSON],['"\u0000"',codes.CANON_INVALID_JSON],
  ['['.repeat(65)+'0'+']'.repeat(65),codes.CANON_NESTING_TOO_DEEP],
  ['{\"x\":'.repeat(65)+'0'+'}'.repeat(65),codes.CANON_NESTING_TOO_DEEP],
  ['',codes.CANON_INVALID_JSON], ['truX',codes.CANON_INVALID_JSON], ['nulX',codes.CANON_INVALID_JSON], ['falXe',codes.CANON_INVALID_JSON],
  ['-',codes.CANON_INVALID_NUMBER], ['-x',codes.CANON_INVALID_NUMBER],
  ['\"abc',codes.CANON_INVALID_JSON], ['\"\\q\"',codes.CANON_INVALID_JSON], ['\"\\uZZZZ\"',codes.CANON_INVALID_JSON],
  ['{x\":1}',codes.CANON_INVALID_JSON], ['{\"a\",1}',codes.CANON_INVALID_JSON], ['[0}',codes.CANON_INVALID_JSON], ['{\"a\":0]',codes.CANON_INVALID_JSON],
  ['[0 1]',codes.CANON_INVALID_JSON], ['{\"a\":1 \"b\":2}',codes.CANON_INVALID_JSON],
  ['[0,]',codes.CANON_INVALID_JSON], ['{\"a\":0,}',codes.CANON_INVALID_JSON]
]) await add(`explicit parser ${input}`,'parse',input,undefined,code)
await add('BOM','parse',Buffer.from([0xef,0xbb,0xbf,0x30]),undefined,codes.CANON_BOM)
for (const bytes of [[0xff],[0xed,0xa0,0x80],[0xc0,0x80]]) await add('invalid UTF8 '+bytes,'parse',Buffer.from(bytes),undefined,codes.CANON_INVALID_UTF8)
await add('not object','frame','[]','guest',codes.FRAME_NOT_OBJECT)
await add('not canonical','frame','{ "body":{},"id":"a","kind":"status","v":1}','guest',codes.FRAME_NOT_CANONICAL)
await addFrame('unknown envelope plus missing v', {body:{},id:'a',kind:'status',extra:0},'guest',codes.FRAME_UNKNOWN_FIELD)
await addFrame('missing envelope', {body:{},id:'a',kind:'status'},'guest',codes.FRAME_MISSING_FIELD)
await addFrame('unknown kind',frame('unknown',{}),'guest',codes.FRAME_UNKNOWN_KIND)
const prefix = '{"body":{"code":"gate:stale-base","next":"'
const suffix = '"},"id":"a","kind":"refusal","v":1}'
const exact = Buffer.from(prefix+'a'.repeat(65536-Buffer.byteLength(prefix)-Buffer.byteLength(suffix))+suffix)
await add('frame exact budget','frame',exact,'supervisor')
await add('frame over budget','frame',Buffer.concat([exact,Buffer.from(' ')]),'supervisor',codes.FRAME_TOO_LARGE)
const packet = bytes => {const header = Buffer.alloc(4);header.writeUInt32BE(bytes.length);return Buffer.concat([header,bytes])}
for (const [direction,sample] of samples) await add(`transport ${sample.kind}`,'transport',packet(Buffer.from(prime(sample))),direction)
await add('transport exact budget','transport',packet(exact),'supervisor')
await add('transport IO failure','transport-io',Buffer.alloc(0),'guest',codes.FRAME_IO)
await add('transport empty read','transport',Buffer.alloc(0),'guest',codes.FRAME_SHORT_READ)
await add('transport zero','transport',Buffer.alloc(4),'guest',codes.FRAME_ZERO_LENGTH)
const over = Buffer.alloc(4);over.writeUInt32BE(65537)
await add('transport oversize prefix','transport',over,'guest',codes.FRAME_TOO_LARGE)
for (const cut of [1,2,3,4,5,6,20]) await add(`transport short ${cut}`,'transport',packet(Buffer.from(prime(frame('status',{})))).subarray(0,cut),'guest',codes.FRAME_SHORT_READ)
// Parse vectors stress UTF-16 ordering, every escape/control, astral keys, safe
// integer endpoints, alternate source escapes and structured seeded values.
const strings = ['','中','é','😀','\ue000','\u2028','\u2029','\u007f','"\\/\b\f\n\r\t',...Array.from({length:32},(_,n)=>String.fromCharCode(n))]
for (let n=0;n<384;n++) {
  const a=strings[random(strings.length)], b=strings[random(strings.length)]
  const value={'😀':a,'\ue000':b, '𝄞': [n, -n || 0, 9007199254740991, -9007199254740991], [a+'key']:{[b+'key']:[null,true,false,a+b]}}
  const input=JSON.stringify(value,null,n%3===0?2:undefined)
  const expected=prime(JSON.parse(input))
  assert.equal(canonicalJSON(parse(Buffer.from(input))),expected)
  vectors.push({name:`seeded canonical ${n}`,input,canonical:expected})
}
for (const input of ['"\\/"','"\\u0041"','"\\ud83d\\ude00"','{"\\ud83d\\ude00":1,"\\ue000":2}', '['.repeat(64)+'0'+']'.repeat(64)]) vectors.push({name:`escaped boundary ${input}`,input,canonical:prime(JSON.parse(input))})
for (const item of corpus.filter(x=>x.mode==='parse'&&x.code)) vectors.push({name:item.name,input:Buffer.from(item.input_hex,'hex').toString('utf8'),refusal:item.code})
// Invalid raw UTF-8 can't be represented in a JSON string vector. Those remain
// byte fixtures above; don't turn replacement characters into a false expectation.
for(let n=vectors.length-1;n>=0;n--) if(vectors[n].refusal===codes.CANON_INVALID_UTF8) vectors.splice(n,1)
assert(corpus.length>=300&&vectors.length>=300)
const covered=new Set(corpus.filter(x=>x.code).map(x=>x.code))
for(const item of corpus.filter(x=>x.canonical)) {const value=JSON.parse(item.canonical);if(value.kind==='refusal')covered.add(value.body.code)}
for(const code of codes.ALL) assert(covered.has(code),`registry code unrepresented: ${code}`)
for(const [file,data] of [[join(here,'generated.json'),corpus],[join(root,'crates/canon/vectors/generated.json'),vectors]]) {
  const content=JSON.stringify(data,null,2)+'\n'
  if(writing)writeFileSync(file,content)
  else assert.equal(readFileSync(file,'utf8'),content,`${file}: run node crates/canon/corpus/gen.mjs --write`)
}
console.log(`NODE GENERATED DIFFERENTIAL PASS ${corpus.length} corpus ${vectors.length} vectors seed 0x41554b4f`)
