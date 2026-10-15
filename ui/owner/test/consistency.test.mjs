/* Head-witness proof check: the JS port of vendor/append-only/verify.py
   verify_consistency must agree with the Python self-test vectors (Prime
   vendor/append-only/verify.py lines 108-144) and the edge cases. */

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { verifyConsistency } from '../consistency.js';

const sha256 = async bytes => createHash('sha256').update(bytes).digest();

const R5 = '6f7f213a4c7fe7c7b034c3879840a49918481b4796c7f8583d3604e09158fa4b';
const R14 = '9fde8beaf87fd07070b5bc2068ef543e830653ab0245412e8a6d25a829db78de';
const P5_14 = [
  '2117942a52d6136b5020766f489c4c95063c3dd7d050743685f1e58af4189c56',
  '9fd396c9621758169909f320cd76d6d13c47e1df1f2a52615e9c6968fed6eb43',
  'f54a41ca7a75620fad5c51ab8310dbf6ca91e9c56ed2e48be64297b9ca8b6b99',
  '90283eea2a3492d5a7219a00a16389e132f01600e947b06392b47dd95f7f1567',
  'e72cc2893ebac0de5b880d9ebe2dbb26f1fba9f5d8d4196295dd3e8f4c580e23',
];
const R4 = '90283eea2a3492d5a7219a00a16389e132f01600e947b06392b47dd95f7f1567';
const P4_14 = [
  '1ecf2a95d2edb667f8009d3d80730298b5375a959e62152e666ddc04aa9a181d',
  'e72cc2893ebac0de5b880d9ebe2dbb26f1fba9f5d8d4196295dd3e8f4c580e23',
];

test('positive control (m=5, n=14) -> APPEND_ONLY', async () => {
  const r = await verifyConsistency({ m: 5, n: 14, root1: R5, root2: R14, proof: P5_14 }, sha256);
  assert.equal(r.verdict, 'APPEND_ONLY');
});

test('power-of-two valid extension (m=4, n=14) -> APPEND_ONLY', async () => {
  const r = await verifyConsistency({ m: 4, n: 14, root1: R4, root2: R14, proof: P4_14 }, sha256);
  assert.equal(r.verdict, 'APPEND_ONLY');
});

test('earned accusation (modified retained root) -> OBSERVATION_CONFLICT', async () => {
  const r = await verifyConsistency({ m: 5, n: 14, root1: '00'.repeat(32), root2: R14, proof: P5_14 }, sha256);
  assert.equal(r.verdict, 'OBSERVATION_CONFLICT');
});

test('power-of-two blind spot (corrupted proof) -> UNDETERMINED', async () => {
  const r = await verifyConsistency({ m: 4, n: 14, root1: R4, root2: R14, proof: ['00'.repeat(32), P4_14[1]] }, sha256);
  assert.equal(r.verdict, 'UNDETERMINED');
  assert.equal(r.reason, 'POWER_OF_TWO_PREFIX_NOT_INDEPENDENTLY_DERIVABLE');
});

test('same size, same root -> APPEND_ONLY identical_trees_match', async () => {
  const r = await verifyConsistency({ m: 14, n: 14, root1: R14, root2: R14, proof: [] }, sha256);
  assert.deepEqual(r, { verdict: 'APPEND_ONLY', reason: 'identical_trees_match' });
});

test('same size, different root -> OBSERVATION_CONFLICT (fork at same height)', async () => {
  const r = await verifyConsistency({ m: 14, n: 14, root1: R5, root2: R14, proof: [] }, sha256);
  assert.deepEqual(r, { verdict: 'OBSERVATION_CONFLICT', reason: 'same_size_root_mismatch' });
});

test('same size with a proof is refused', async () => {
  const r = await verifyConsistency({ m: 14, n: 14, root1: R14, root2: R14, proof: P4_14 }, sha256);
  assert.deepEqual(r, { verdict: 'UNDETERMINED', reason: 'non_empty_proof_for_same_size' });
});

test('truncated history (m > n) -> UNDETERMINED', async () => {
  const r = await verifyConsistency({ m: 14, n: 5, root1: R14, root2: R5, proof: [] }, sha256);
  assert.deepEqual(r, { verdict: 'UNDETERMINED', reason: 'invalid_tree_sizes' });
});

test('no prior observation (m = 0) -> UNDETERMINED', async () => {
  const r = await verifyConsistency({ m: 0, n: 14, root1: R14, root2: R14, proof: P4_14 }, sha256);
  assert.deepEqual(r, { verdict: 'UNDETERMINED', reason: 'missing_prior_observation' });
});

test('malformed inputs -> UNDETERMINED, never an exception', async () => {
  assert.deepEqual(await verifyConsistency({ m: 1.5, n: 2, root1: R5, root2: R14, proof: [] }, sha256),
    { verdict: 'UNDETERMINED', reason: 'invalid_tree_sizes' });
  assert.deepEqual(await verifyConsistency({ m: 5, n: 14, root1: 'zz', root2: R14, proof: P5_14 }, sha256),
    { verdict: 'UNDETERMINED', reason: 'root_is_not_a_digest' });
  assert.deepEqual(await verifyConsistency({ m: 5, n: 14, root1: R5, root2: R14, proof: ['00'] }, sha256),
    { verdict: 'UNDETERMINED', reason: 'proof_element_is_not_a_digest' });
  assert.deepEqual(await verifyConsistency({ m: 5, n: 14, root1: R5, root2: R14, proof: [] }, sha256),
    { verdict: 'UNDETERMINED', reason: 'empty_proof_for_different_sizes' });
});
