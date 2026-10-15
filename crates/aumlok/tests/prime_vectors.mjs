// SPDX-License-Identifier: AGPL-3.0-or-later
// Disposable software-authenticator vectors follow Prime's passkey tests.
import assert from 'node:assert/strict'
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const directory = path.dirname(fileURLToPath(import.meta.url))
const vectorPath = path.resolve(directory, '../vectors/prime-webauthn.json')
const primeRoot = process.env.AUKORA_PRIME ?? '/Users/peterviviani/aukora-prime'
async function primeModule(relative) {
  const file = path.join(primeRoot, relative)
  try {
    return await import(pathToFileURL(file))
  } catch (cause) {
    throw new Error(`AUKORA_PRIME: cannot load required reference ${file}; set AUKORA_PRIME to the Prime checkout`, { cause })
  }
}
const { prepareWebauthnConfig, verifyWebauthnAssertion } = await primeModule('packages/owner-key/src/webauthn.mjs')
const { verifyPasskeyRegistration } = await primeModule('packages/authority/src/passkey-enrollment.mjs')
const { didKeyFromEd25519PublicKey } = await primeModule('packages/authority/upstream/plugins/aukora-aumlok/lib/did-key.mjs')
const sha = value => createHash('sha256').update(value).digest()
const b64 = value => Buffer.from(value).toString('base64url')
const bytes = value => Buffer.from(value, 'base64url')
const rp = 'owner.example.test', origin = 'https://owner.example.test'
const id = Buffer.from('software-credential'), user = Buffer.from('software-owner')
const challenge = b64(sha('disposable Prime/Sovereign WebAuthn vector challenge'))
const scalar = Buffer.alloc(32); scalar[31] = 1
const x = Buffer.from('6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296', 'hex')
const y = Buffer.from('4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5', 'hex')
const esKey = createPrivateKey({ format: 'jwk', key: { kty: 'EC', crv: 'P-256', x: b64(x), y: b64(y), d: b64(scalar) } })
const edSeed = sha('disposable Ed25519 WebAuthn test seed')
const edKey = createPrivateKey({ format: 'der', type: 'pkcs8', key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), edSeed]) })
const edPublic = bytes(createPublicKey(edKey).export({ format: 'jwk' }).x)

function head(major, n) {
  if (n < 24) return Buffer.from([major * 32 + n])
  if (n < 256) return Buffer.from([major * 32 + 24, n])
  return Buffer.from([major * 32 + 25, n >>> 8, n & 255])
}
function cbor(value) {
  if (Number.isInteger(value)) return value >= 0 ? head(0, value) : head(1, -1 - value)
  if (Buffer.isBuffer(value)) return Buffer.concat([head(2, value.length), value])
  if (typeof value === 'string') return Buffer.concat([head(3, Buffer.byteLength(value)), Buffer.from(value)])
  return Buffer.concat([head(5, value.size), ...[...value].flatMap(([k, v]) => [cbor(k), cbor(v)])])
}
function keyCbor(algorithm, changes = {}) {
  const entries = algorithm === 'ES256' ? [[1, 2], [3, -7], [-1, 1], [-2, x], [-3, y]] : [[1, 1], [3, -8], [-1, 6], [-2, edPublic]]
  if (changes.keyOrder) entries.reverse()
  if (changes.keyAlgorithm) entries[1][1] = -257
  if (changes.shortCoordinate) entries[3][1] = entries[3][1].subarray(1)
  if (changes.invalidPoint) { entries[3][1] = Buffer.alloc(32); if (algorithm === 'ES256') entries[4][1] = Buffer.alloc(32) }
  let encoded = cbor(new Map(entries))
  if (changes.keyExtra) encoded = cbor(new Map([...entries, [4, 1]]))
  if (changes.keyDuplicate) encoded = Buffer.concat([Buffer.from([0xa6]), encoded.subarray(1), cbor(1), cbor(2)])
  if (changes.keyNonminimal) encoded = Buffer.concat([encoded.subarray(0, 1), Buffer.from([0x18, 1]), encoded.subarray(2)])
  if (changes.keyTrailing) encoded = Buffer.concat([encoded, Buffer.from([0])])
  return encoded
}
function registration(algorithm, changes = {}, prior = 0, backupEligible = false) {
  const client = changes.clientBytes ?? Buffer.from(changes.raw ?? JSON.stringify({ type: 'webauthn.create', challenge,
    origin, crossOrigin: false, ...changes.client }))
  const auth = Buffer.alloc(55)
  sha(changes.rp ?? rp).copy(auth); auth[32] = changes.flags ?? (backupEligible ? 0x4d : 0x45)
  auth.writeUInt32BE(prior, 33); auth.writeUInt16BE(id.length, 53)
  const data = Buffer.concat([auth, changes.id ?? id, keyCbor(algorithm, changes)])
  const entries = [['fmt', changes.format ?? 'none'], ['attStmt', new Map(changes.statement ?? [])], ['authData', data]]
  let attestation = cbor(new Map(entries))
  if (changes.attestationExtra) attestation = cbor(new Map([...entries, ['extra', 1]]))
  if (changes.attestationDuplicate) attestation = Buffer.concat([Buffer.from([0xa4]), attestation.subarray(1), cbor('fmt'), cbor('none')])
  if (changes.attestationNonminimal) attestation = Buffer.concat([Buffer.from([0xb8, 3]), attestation.subarray(1)])
  if (changes.attestationTrailing) attestation = Buffer.concat([attestation, Buffer.from([0])])
  if (changes.attestationIndefinite) attestation = Buffer.concat([Buffer.from([0xbf]), attestation.subarray(1), Buffer.from([0xff])])
  if (changes.attestationMalformed) attestation = attestation.subarray(0, -1)
  if (changes.attestationRaw) attestation = changes.attestationRaw
  return { kind: 'passkey-registration', type: 'public-key', id: b64(id), raw_id: b64(id),
    client_data_json: b64(client), attestation_object: b64(attestation), client_extension_results: {}, ...changes.material }
}
function assertion(algorithm, changes = {}) {
  const client = changes.clientBytes ?? Buffer.from(changes.raw ?? JSON.stringify({ type: 'webauthn.get', challenge,
    origin, crossOrigin: false, ...changes.client }))
  const auth = Buffer.alloc(changes.trailing ? 38 : 37)
  sha(changes.rp ?? rp).copy(auth); auth[32] = changes.flags ?? 5; auth.writeUInt32BE(changes.count ?? 1, 33)
  const signed = Buffer.concat([auth, sha(client)])
  let signature = sign(algorithm === 'ES256' ? 'sha256' : null, signed, changes.key ?? (algorithm === 'ES256' ? esKey : edKey))
  if (changes.badSignature) signature[signature.length - 1] ^= 1
  if (changes.highS || changes.lowS) signature = transformS(signature, Boolean(changes.highS))
  return { kind: 'passkey', credential_id: b64(id), client_data_json: b64(client), authenticator_data: b64(auth),
    signature: b64(signature), user_handle: b64(user), ...changes.material }
}
function transformS(signature, high) {
  const order = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551')
  const rLength = signature[3], sOffset = 4 + rLength, sLength = signature[sOffset + 1]
  let s = BigInt('0x' + signature.subarray(sOffset + 2, sOffset + 2 + sLength).toString('hex'))
  if ((s > order / 2n) !== high) s = order - s
  let hex = s.toString(16); if (hex.length % 2) hex = '0' + hex
  let integer = Buffer.from(hex, 'hex'); if (integer[0] & 0x80) integer = Buffer.concat([Buffer.from([0]), integer])
  const rPart = signature.subarray(2, sOffset)
  return Buffer.concat([Buffer.from([0x30, rPart.length + 2 + integer.length]), rPart, Buffer.from([2, integer.length]), integer])
}
function binding(fixture) {
  return { identity: { owner_id: fixture.owner_id, subject: 'aukora:1:' + 'a'.repeat(64),
    approval_key_did: didKeyFromEd25519PublicKey('b'.repeat(64)), control_digest: 'd'.repeat(64), authorization_epoch: 1 },
  identity_provenance: { kind: 'owner-approved-initial-public-identity/v1', identity_source_sha256: 'e'.repeat(64), approval_reference: 'root-selected-test-binding' },
  passkey_profile: { profile: 'https', origin: fixture.origin, rp_id: fixture.rp_id },
  user: { id: fixture.user_handle, name: 'Owner', display_name: 'Owner' }, existing_credential_ids: [] }
}
function oracle(fixture) {
  try {
    if (fixture.phase === 'registration') verifyPasskeyRegistration({ material: fixture.registration, binding: binding(fixture), challenge: fixture.challenge })
    else {
      const config = prepareWebauthnConfig({ rp_id: fixture.rp_id, origins: [fixture.origin], credentials: [{ owner_id: fixture.owner_id,
        credential_id: fixture.credential_id, public_key_hex: fixture.public_key_hex, user_handle: fixture.user_handle,
        sign_count: fixture.prior_count, backup_eligible: fixture.backup_eligible }] })
      verifyWebauthnAssertion({ material: fixture.assertion, config, ownerId: fixture.owner_id, challenge: fixture.challenge, counter: fixture.prior_count })
    }
    return 'ok'
  } catch (error) { return error.message }
}
function refusal(reason) {
  if (reason === 'ok') return reason
  if (!/^(WEBAUTHN_|PASSKEY_)/u.test(reason)) return 'aumlok:data-invalid'
  return 'aumlok:' + reason.replace(/^WEBAUTHN_|^PASSKEY_/, '').toLowerCase().replaceAll('_', '-')
}
function fixture(name, phase, changes = {}, options = {}) {
  const algorithm = options.algorithm ?? 'ES256', prior = options.prior ?? 0, backupEligible = options.backupEligible ?? false
  const value = { name, phase, rp_id: rp, origin, owner_id: 'software-owner', user_handle: b64(user), credential_id: b64(id),
    public_key_hex: algorithm === 'ES256' ? '04' + x.toString('hex') + y.toString('hex') : edPublic.toString('hex'),
    algorithm, prior_count: prior, backup_eligible: backupEligible, challenge,
    registration: registration(algorithm, phase === 'registration' ? changes : {}, prior, backupEligible),
    assertion: assertion(algorithm, phase === 'assertion' ? changes : { flags: backupEligible ? 0x0d : 5, count: prior + 1 }) }
  if (algorithm === 'ES256') { value.prime_expected = oracle(value); value.expected = refusal(value.prime_expected) }
  else { value.prime_expected = null; value.expected = options.expected ?? 'ok' }
  return value
}

if (process.argv.includes('--generate')) {
  const assertionCases = [
    ['baseline', {}], ['low-s', { lowS: true }], ['high-s', { highS: true }],
    ['wrong-origin', { client: { origin: 'https://other.example.test' } }], ['wrong-rp-id', { rp: 'other.example.test' }],
    ['wrong-type', { client: { type: 'webauthn.create' } }], ['wrong-challenge', { client: { challenge: b64(sha('wrong')) } }],
    ['missing-up', { flags: 4 }], ['missing-uv', { flags: 1 }], ['reserved-flags', { flags: 0x25 }],
    ['backup-eligibility-changed', { flags: 0x0d }], ['backup-state-without-eligibility', { flags: 0x15 }],
    ['counter-regression', { count: 1 }, { prior: 2 }], ['counter-equal', { count: 2 }, { prior: 2 }],
    ['counter-zero-zero', { count: 0 }], ['counter-nonzero-to-zero', { count: 0 }, { prior: 2 }],
    ['counter-zero-to-nonzero', { count: 2 }], ['backup-synced', { flags: 0x1d }, { backupEligible: true }],
    ['cross-origin-true', { client: { crossOrigin: true } }], ['cross-origin-string', { client: { crossOrigin: 'false' } }],
    ['top-origin', { client: { topOrigin: origin } }], ['bad-signature', { badSignature: true }],
    ['wrong-credential', { material: { credential_id: b64('software-credential-two') } }],
    ['wrong-user-handle', { material: { user_handle: b64('software-owner-two') } }], ['null-user-handle', { material: { user_handle: null } }],
    ['wrong-kind', { material: { kind: 'cookie' } }], ['extra-material', { material: { extra: true } }],
    ['authenticator-data-trailing', { trailing: true }], ['padded-encoding', { material: { signature: 'AAAA=' } }],
    ['unsafe-integer', { client: { extra: 9007199254740992 } }], ['lone-surrogate', { client: { extra: '\ud800' } }],
    ['duplicate-client-key', { raw: JSON.stringify({ type: 'webauthn.get', challenge, origin }).replace('"type":', '"type":"webauthn.create","type":') }],
    ['duplicate-nested-key', { raw: JSON.stringify({ type: 'webauthn.get', challenge, origin }).slice(0, -1) + ',"extra":{"x":1,"x":2}}' }],
    ['trailing-client-data', { raw: JSON.stringify({ type: 'webauthn.get', challenge, origin }) + 'null' }],
    ['invalid-client-utf8', { clientBytes: Buffer.concat([Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin }).slice(0, -1) + ',"extra":"'), Buffer.from([0xff]), Buffer.from('"}')]) }],
    ['client-depth-budget', { raw: JSON.stringify({ type: 'webauthn.get', challenge, origin }).slice(0, -1) + ',"extra":' + '['.repeat(513) + '0' + ']'.repeat(513) + '}' }],
    ['client-byte-budget', { client: { extra: 'x'.repeat(17000) } }],
    ['fraction-client-extra', { client: { extra: 1.5 } }], ['negative-zero-client-extra', { raw: JSON.stringify({ type: 'webauthn.get', challenge, origin }).slice(0, -1) + ',"extra":-0}' }],
  ]
  const registrationCases = [
    ['baseline', {}], ['backup-eligible', { flags: 0x4d }, { backupEligible: true }], ['backup-synced', { flags: 0x5d }, { backupEligible: true }],
    ['wrong-origin', { client: { origin: 'https://other.example.test' } }], ['wrong-rp-id', { rp: 'other.example.test' }],
    ['wrong-type', { client: { type: 'webauthn.get' } }], ['wrong-challenge', { client: { challenge: b64(sha('wrong')) } }],
    ['cross-origin', { client: { crossOrigin: true } }], ['missing-up', { flags: 0x44 }], ['missing-uv', { flags: 0x41 }],
    ['missing-attested-data', { flags: 5 }], ['reserved-flags', { flags: 0x65 }], ['backup-state-without-eligibility', { flags: 0x55 }],
    ['credential-id-mismatch', { id: Buffer.from('different-id-length') }], ['wrong-material-id', { material: { id: b64('another-credential') } }],
    ['extension-results', { material: { client_extension_results: { unknown: true } } }], ['wrong-format', { format: 'packed' }],
    ['nonempty-attestation-statement', { statement: [['alg', -7]] }], ['attestation-extra', { attestationExtra: true }],
    ['attestation-duplicate', { attestationDuplicate: true }], ['attestation-nonminimal', { attestationNonminimal: true }],
    ['attestation-trailing', { attestationTrailing: true }], ['attestation-indefinite', { attestationIndefinite: true }],
    ['malformed-cbor', { attestationMalformed: true }], ['key-order', { keyOrder: true }], ['key-algorithm', { keyAlgorithm: true }],
    ['key-coordinate-length', { shortCoordinate: true }], ['invalid-point', { invalidPoint: true }], ['key-extra', { keyExtra: true }],
    ['key-duplicate', { keyDuplicate: true }], ['key-nonminimal', { keyNonminimal: true }], ['key-trailing', { keyTrailing: true }],
    ['cbor-array', { attestationRaw: Buffer.from([0x80]) }], ['cbor-tag', { attestationRaw: Buffer.from([0xc0, 0xa0]) }],
    ['cbor-simple', { attestationRaw: Buffer.from([0xa1, 0x01, 0xf4]) }], ['cbor-float', { attestationRaw: Buffer.from('a101f93e00', 'hex') }],
    ['cbor-unsafe-positive', { attestationRaw: Buffer.from('1b0020000000000000', 'hex') }],
    ['cbor-unsafe-negative', { attestationRaw: Buffer.from('3b001fffffffffffff', 'hex') }],
    ['cbor-invalid-utf8', { attestationRaw: Buffer.from([0xa1, 0x61, 0xff, 0x01]) }],
    ['cbor-map-entry-budget', { attestationRaw: cbor(new Map(Array.from({ length: 17 }, (_, i) => [i, 1]))) }],
    ['cbor-item-budget', { attestationRaw: cbor(new Map(Array.from({ length: 16 }, (_, i) => [i,
      new Map(Array.from({ length: 16 }, (_, j) => [j, 1]))]))) }],
    ['cbor-depth-budget', { attestationRaw: cbor(new Map([[1, new Map([[1, new Map([[1, new Map([[1, new Map([[1, 1]])]])]])]])]])) }],
    ['cbor-byte-budget', { attestationRaw: Buffer.alloc(16385, 1) }],
    ['duplicate-client-key', { raw: JSON.stringify({ type: 'webauthn.create', challenge, origin }).replace('"type":', '"type":"webauthn.get","type":') }],
    ['unsafe-integer', { client: { extra: 9007199254740992 } }], ['lone-surrogate', { client: { extra: '\ud800' } }],
    ['fraction-client-extra', { client: { extra: 1.5 } }],
  ]
  const fixtures = assertionCases.map(([name, changes, options]) => fixture('assertion-' + name, 'assertion', changes, options))
  fixtures.push(...registrationCases.map(([name, changes, options]) => fixture('registration-' + name, 'registration', changes, options)))
  fixtures.push(fixture('eddsa-registration', 'registration', {}, { algorithm: 'EdDSA' }), fixture('eddsa-assertion', 'assertion', {}, { algorithm: 'EdDSA' }),
    fixture('eddsa-signature-invalid', 'assertion', { badSignature: true }, { algorithm: 'EdDSA', expected: 'aumlok:signature-invalid' }))
  const result = { schema: 'aukora-sovereign-webauthn-vectors-v1', source: ['tests/owner-passkey-gate.test.mjs', 'tests/owner-passkey-proof.test.mjs',
    'packages/owner-key/src/webauthn.mjs', 'packages/authority/src/passkey-enrollment.mjs', 'packages/authority/src/webauthn-registration-cbor.mjs'],
  note: 'Disposable software authenticators. ES256 cases checked against Prime. EdDSA is the explicitly requested extension; Prime does not implement it. High-S and low-S signatures both accepted by Prime.', fixtures }
  writeFileSync(vectorPath, JSON.stringify(result, null, 2) + '\n')
}

const { fixtures } = JSON.parse(readFileSync(vectorPath, 'utf8'))
let primeCount = 0, extensionCount = 0
for (const value of fixtures) {
  if (value.prime_expected !== null) {
    assert.equal(oracle(value), value.prime_expected, value.name)
    assert.equal(refusal(value.prime_expected), value.expected, value.name + ': refusal mapping')
    primeCount++
  } else {
    if (value.phase === 'assertion') {
      const material = value.assertion, signed = Buffer.concat([bytes(material.authenticator_data), sha(bytes(material.client_data_json))])
      const key = createPublicKey({ format: 'jwk', key: { kty: 'OKP', crv: 'Ed25519', x: b64(Buffer.from(value.public_key_hex, 'hex')) } })
      assert.equal(verify(null, signed, key, bytes(material.signature)), value.expected === 'ok', value.name)
    }
    extensionCount++
  }
}
assert.equal(fixtures.find(value => value.name === 'assertion-high-s').expected, 'ok')
assert.equal(fixtures.find(value => value.name === 'assertion-low-s').expected, 'ok')
assert.equal(fixtures.find(value => value.name === 'assertion-counter-zero-zero').expected, 'ok')
assert.equal(fixtures.find(value => value.name === 'assertion-counter-nonzero-to-zero').expected, 'aumlok:counter-replayed')
console.log(`Prime WebAuthn parity: ${primeCount} passed; EdDSA extension vectors: ${extensionCount} checked`)
