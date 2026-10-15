import { createHash } from 'node:crypto'

const DOMAIN = 'aukora:aura-record:v1'

// Restated from Prime scripts/aura/verify-append-only.mjs.
function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`
  const keys = Object.keys(value).filter(key => value[key] !== undefined).sort()
  return `{${keys.map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`
}

function entryHash(prev, fields) {
  return createHash('sha256')
    .update(Buffer.from(canonical({ prev, ...fields, domain: DOMAIN }), 'utf8'))
    .digest('hex')
}

const bodies = [
  { message: 'boot', nested: { z: null, a: [true, false, 0] } },
  { text: '"\\\b\f\n\r\t\u0000\u001f\u007f\u2028\u2029' },
  { '\ue000': 'BMP', '\ud83d\ude00': 'astral', '10': 10, '2': 2 },
  { minimum: -9007199254740991, maximum: 9007199254740991 },
  { unicode: '雪 café 👁', arrays: [[], {}, ['x', { b: 2, a: 1 }]] },
]

let prev = DOMAIN
for (const [index, body] of bodies.entries()) {
  const fields = {
    sequence: index + 1,
    at: 1700000000000 + index,
    kind: 'boot.facts',
    actor: 'supervisor',
    op: '',
    phase: 'fact',
    body,
  }
  const hash = entryHash(prev, fields)
  process.stdout.write(`${JSON.stringify({ ...fields, prev, hash })}\n`)
  prev = hash
}
