// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict'
import { createHash, createPublicKey, verify } from 'node:crypto'
import test from 'node:test'
import { canonicalJSON } from '../../../guest/canon.mjs'
import { SoftwareKey, verifyCard } from './a3_reboot_live.mjs'

const sha = input => createHash('sha256').update(input).digest()

test('antibody_a3_live_driver_refuses_altered_card_and_authorization', () => {
  const card = { v: 1, says: 'Disposable test approval', facts: [], model_note: '', from_to: {}, risk: 'routine' }
  const digest = sha(canonicalJSON(card)).toString('hex')
  const auth = { v: 1, display_sha256: digest, challenge: '1'.repeat(64) }
  const review = { card, auth, display_sha256: digest, public_key: {
    challenge: sha(Buffer.concat([Buffer.from('aukora:owner-authorization:v1\0'), Buffer.from(canonicalJSON(auth))])).toString('base64url'),
  } }
  verifyCard(review)
  for (const change of [
    value => { value.card.says = 'Different displayed effect' },
    value => { value.auth.display_sha256 = '0'.repeat(64) },
    value => { value.auth.challenge = '2'.repeat(64) },
    value => { value.public_key.challenge = 'wrong' },
  ]) {
    const changed = structuredClone(review)
    change(changed)
    assert.throws(() => verifyCard(changed))
  }
})

test('a3 software key signs the exact WebAuthn client hash and increments its counter', () => {
  const node = '1'.repeat(32)
  const rp = `owner-${node}`
  const key = new SoftwareKey(node, rp, `https://${rp}`)
  const material = key.assertion('first')
  const auth = Buffer.from(material.authenticator_data, 'base64url')
  const client = Buffer.from(material.client_data_json, 'base64url')
  assert.deepEqual(auth.subarray(0, 32), sha(rp))
  assert.equal(auth[32], 5)
  assert.equal(auth.readUInt32BE(33), 1)
  assert.equal(Buffer.from(material.user_handle, 'base64url').toString(), node)
  assert.equal(JSON.parse(client).challenge, 'first')
  const publicKey = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: key.publicKey.toString('base64url') }, format: 'jwk' })
  assert(verify(null, Buffer.concat([auth, sha(client)]), publicKey, Buffer.from(material.signature, 'base64url')))
  assert(!verify(null, Buffer.concat([auth, sha('altered')]), publicKey, Buffer.from(material.signature, 'base64url')))
  assert.equal(Buffer.from(key.assertion('second').authenticator_data, 'base64url').readUInt32BE(33), 2)
})
