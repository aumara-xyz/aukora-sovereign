// SPDX-License-Identifier: AGPL-3.0-or-later
// Prime supplies ordering results; release identities map to Sovereign digests.
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'

// Prime's reference implementation; set AUKORA_PRIME to a checkout of aumara-xyz/aukora-prime.
const reference = `${process.env.AUKORA_PRIME ?? `${process.env.HOME}/aukora-prime`}/packages/boundary-gate/src/release-floor.mjs`
const source = fs.readFileSync(reference)
const prime = await import(`data:text/javascript;base64,${source.toString('base64')}`)
const target = fileURLToPath(new URL('../vectors/prime-order.json', import.meta.url))
const release = n => n.toString(16).padStart(40, '0')
const sha = n => n.toString(16).padStart(64, '0')
const directory = n => `release-${n.toString(16).padStart(7, '0')}`
const approval = (changes = {}) => ({ release: release(1), release_dir: directory(1), record: sha(1),
  signerEpoch: 1, ledgerSeq: 10, signerKeySha256: sha(2), ledgerHash: sha(3),
  appliedAt: '2026-10-04T00:00:00.000Z', ...changes })
const installed = prime.advanceFloor(null, approval())
const code = raw => raw === 'release-below-floor' ? 'floor:release-below-floor'
  : `floor:${raw.replace(/^release-floor-/u, '')}`
const digest = value => value.padStart(64, '0')
function mapFloor(value) {
  if (value === null) return null
  const known = new Set(['kind', 'release', 'release_dir', 'record', 'signer_epoch', 'ledger_seq',
    'signer_key_sha256', 'ledger_hash', 'history'])
  const extra = Object.fromEntries(Object.entries(value).filter(([name]) => !known.has(name)))
  return { ...extra, digest: digest(value.release), record: value.record, signer_epoch: value.signer_epoch,
    ledger_seq: value.ledger_seq, signer_key_sha256: value.signer_key_sha256,
    ledger_hash: value.ledger_hash, history: value.history.map(digest) }
}
function mapApproval(value) {
  return { digest: digest(value.release), record: value.record, signer_epoch: value.signerEpoch,
    ledger_seq: value.ledgerSeq, signer_key_sha256: value.signerKeySha256,
    ledger_hash: value.ledgerHash }
}
const cases = []
function exercise(name, command, floor, verified, expected) {
  let actual
  try {
    const result = command === 'check' ? prime.checkFloor(floor, verified)
      : command === 'advance' ? prime.advanceFloor(floor, verified)
        : prime.isRollback(floor, verified.release)
    actual = command === 'advance' ? mapFloor(result) : command === 'rollback' ? result : true
  } catch (error) {
    assert.equal(typeof error.code, 'string', `${name} must carry a refusal code`)
    actual = code(error.code)
  }
  assert.deepEqual(actual, expected, `${name} changed in Prime`)
  cases.push({ name, command, prime: { floor, approval: verified },
    sovereign: { floor: floor?.kind === prime.FLOOR_KIND ? mapFloor(floor) : floor,
      approval: mapApproval(verified) }, expected })
}

exercise('absent', 'check', null, approval(), 'floor:absent')
exercise('exact-installed', 'check', installed, approval(), true)
exercise('lower-sequence', 'check', installed, approval({ ledgerSeq: 9 }), 'floor:release-below-floor')
exercise('newer-sequence', 'check', installed, approval({ ledgerSeq: 11 }), 'floor:install-incomplete')
exercise('lower-epoch-higher-sequence', 'check', { ...installed, signer_epoch: 2, ledger_seq: 1 },
  approval({ ledgerSeq: Number.MAX_SAFE_INTEGER }), 'floor:release-below-floor')
exercise('higher-epoch-lower-sequence', 'check', installed,
  approval({ signerEpoch: 2, ledgerSeq: 1, signerKeySha256: sha(9) }), 'floor:install-incomplete')
for (const [field, value] of [['release', release(2)], ['record', sha(9)], ['ledgerHash', sha(9)]]) {
  exercise(`equal-conflict-${field}`, 'check', installed, approval({ [field]: value }), 'floor:equal-conflict')
}
for (const ledgerSeq of [9, 10, 11]) {
  exercise(`same-epoch-different-key-${ledgerSeq}`, 'check', installed,
    approval({ ledgerSeq, signerKeySha256: sha(9) }), 'floor:signer-epoch-mismatch')
}
for (const ledgerSeq of [9, 10]) {
  exercise(`not-newer-${ledgerSeq}`, 'advance', installed, approval({ ledgerSeq }), 'floor:not-newer')
}
exercise('equal-order-other-release-not-newer', 'advance', installed,
  approval({ release: release(2) }), 'floor:not-newer')
exercise('newer-order-older-clock', 'advance', installed,
  approval({ ledgerSeq: 11, appliedAt: '1990-01-01T00:00:00.000Z' }),
  mapFloor({ ...installed, ledger_seq: 11 }))
exercise('older-order-newer-clock', 'advance', installed,
  approval({ ledgerSeq: 9, appliedAt: '2099-01-01T00:00:00.000Z' }), 'floor:not-newer')
const rotated = approval({ release: release(2), release_dir: directory(2), signerEpoch: 2,
  ledgerSeq: 1, signerKeySha256: sha(8) })
exercise('epoch-precedes-sequence', 'advance', { ...installed, ledger_seq: Number.MAX_SAFE_INTEGER },
  rotated, mapFloor({ ...prime.advanceFloor(installed, rotated), ledger_seq: 1 }))
const current = prime.advanceFloor(installed, rotated)
exercise('prior-release-is-rollback', 'rollback', current, approval(), true)
exercise('current-release-is-not-rollback', 'rollback', current, rotated, false)
exercise('fresh-proof-allows-rollback', 'advance', current,
  approval({ signerEpoch: 2, ledgerSeq: 2, signerKeySha256: sha(8), ledgerHash: sha(10) }),
  mapFloor({ ...installed, signer_epoch: 2, ledger_seq: 2, signer_key_sha256: sha(8),
    ledger_hash: sha(10), history: [release(2)] }))
for (const field of ['signerEpoch', 'ledgerSeq']) {
  for (const value of [null, '10', 0, -1, 0.5, Number.MAX_SAFE_INTEGER + 1]) {
    exercise(`invalid-${field}-${JSON.stringify(value)}`, 'advance', null,
      approval({ [field]: value }), 'floor:ordering-evidence')
  }
}
for (const field of ['signerKeySha256', 'ledgerHash', 'record']) {
  for (const value of [null, 'A'.repeat(64), '0'.repeat(63), 10]) {
    exercise(`invalid-${field}-${JSON.stringify(value)}`, 'advance', null,
      approval({ [field]: value }), 'floor:ordering-evidence')
  }
}
for (const [name, changes] of [
  ['sequence-string', { ledger_seq: '10' }], ['zero-epoch', { signer_epoch: 0 }],
  ['upper-hash', { ledger_hash: 'A'.repeat(64) }], ['extra-key', { extra: true }],
  ['history-current', { history: [installed.release] }],
  ['history-duplicate', { history: [release(9), release(9)] }],
  ['history-unbounded', { history: Array.from({ length: 65 }, (_, n) => release(n + 10)) }],
]) {
  exercise(`malformed-floor-${name}`, 'check', { ...installed, ...changes }, approval(), 'floor:malformed')
}
exercise('legacy-clock-floor', 'check', { kind: 'aukora-release-floor/v1', release: release(1),
  release_dir: directory(1), record: sha(1), applied_at: '2026-10-04T00:00:00.000Z', history: [] },
  approval(), 'floor:migration-required')
let history = null
for (let n = 1; n <= 70; n++) {
  history = prime.advanceFloor(history, approval({ release: release(n), release_dir: directory(n), ledgerSeq: n }))
}
exercise('bounded-last-64-history', 'advance', history,
  approval({ release: release(71), release_dir: directory(71), ledgerSeq: 71 }),
  { ...mapFloor(history), digest: digest(release(71)), ledger_seq: 71,
    history: Array.from({ length: 64 }, (_, i) => digest(release(i + 7))) })
exercise('same-release-does-not-add-history', 'advance', history,
  approval({ release: release(70), release_dir: directory(70), ledgerSeq: 71 }),
  { ...mapFloor(history), ledger_seq: 71 })
exercise('history-removes-new-current', 'advance', history,
  approval({ release: release(68), release_dir: directory(68), ledgerSeq: 71 }),
  { ...mapFloor(history), digest: digest(release(68)), ledger_seq: 71,
    history: [...history.history.filter(value => value !== release(68)), release(70)].map(digest) })

const output = JSON.stringify({ schema: 'aukora-floor-prime-order-v1',
  reference: 'aukora-prime@de410bb packages/boundary-gate/src/release-floor.mjs', reference_sha256: createHash('sha256').update(source).digest('hex'),
  mapping: 'Prime release40 left-padded to digest64; Sovereign has no release-directory identity', cases }, null, 2) + '\n'
if (process.argv.includes('--check')) {
  assert.equal(fs.readFileSync(target, 'utf8'), output, 'Prime floor vectors must be regenerated')
} else {
  fs.mkdirSync(fileURLToPath(new URL('../vectors/', import.meta.url)), { recursive: true })
  fs.writeFileSync(target, output)
}
console.log(`Prime ordering vectors: ${cases.length} passed; SOURCE_ONLY; no installed runtime verification`)
