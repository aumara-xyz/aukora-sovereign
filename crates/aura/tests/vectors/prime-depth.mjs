import { createHash } from 'node:crypto'

const DOMAIN = 'aukora:aura-record:v1'

// Prime's canonicalJSON and auraEntryHash, restated for the C1 boundary vectors.
function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`
  const keys = Object.keys(value).filter(key => value[key] !== undefined).sort()
  return `{${keys.map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`
}

for (const kind of ['array', 'object']) {
  for (const depth of [63, 64]) {
    let body = 0
    for (let index = 0; index < depth; index++) {
      body = kind === 'array' ? [body] : { a: body }
    }
    const fields = {
      sequence: 1,
      at: 0,
      kind: 'boot.facts',
      actor: 'a',
      op: '',
      phase: 'fact',
      body,
    }
    const bytes = canonical({ prev: DOMAIN, ...fields, domain: DOMAIN })
    const hash = createHash('sha256').update(Buffer.from(bytes, 'utf8')).digest('hex')
    process.stdout.write(`${JSON.stringify({ kind, depth, fields, hash })}\n`)
  }
}
