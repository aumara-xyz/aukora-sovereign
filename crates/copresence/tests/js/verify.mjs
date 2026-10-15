#!/usr/bin/env node
/**
 * verify.mjs — Zero-dependency independent receipt verifier for Co-presence Portal v0
 * Node 22 compatible. Verifies cryptographic validity, timestamp bounds, and structure.
 */

import fs from 'node:fs';
import crypto from 'node:crypto';
import process from 'node:process';

const SPKI_PREFIX_P256 = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');

function fail(reason) {
  console.log(`invalid ${reason}`);
  process.exit(1);
}

function succeed() {
  console.log('valid');
  process.exit(0);
}

const filePath = process.argv[2];
if (!filePath) {
  fail('missing_file_path');
}

let rawJson;
try {
  rawJson = fs.readFileSync(filePath, 'utf8');
} catch (err) {
  fail(`file_read_error: ${err.message}`);
}

let receipt;
try {
  receipt = JSON.parse(rawJson);
} catch (err) {
  fail(`json_parse_error: ${err.message}`);
}

// 1. Version check
if (receipt.v !== 0) {
  fail(`unsupported_version: expected 0, got ${receipt.v}`);
}

// 2. Validate fields exist
const requiredFields = ['v', 'pk_A', 'pk_B', 'nonce_A', 'nonce_B', 't_A', 't_B', 'sig_A', 'sig_B'];
for (const field of requiredFields) {
  if (receipt[field] === undefined || receipt[field] === null) {
    fail(`missing_field: ${field}`);
  }
}

// 3. Validate timestamps and 10s window: 0 <= t_B - t_A <= 10
if (typeof receipt.t_A !== 'number' || typeof receipt.t_B !== 'number') {
  fail('timestamps_must_be_numbers');
}

const timeDiff = receipt.t_B - receipt.t_A;
if (timeDiff < 0) {
  fail(`negative_time_skew: t_B (${receipt.t_B}) < t_A (${receipt.t_A})`);
}
if (timeDiff > 10) {
  fail(`ceremony_window_exceeded: t_B - t_A = ${timeDiff}s > 10s`);
}

// 4. Validate public keys (65 bytes uncompressed P-256 = 130 hex characters, starting with 04)
function parsePublicKey(hex, label) {
  if (typeof hex !== 'string' || hex.length !== 130 || !hex.startsWith('04') || !/^[0-9a-fA-F]+$/.test(hex)) {
    fail(`malformed_public_key_${label}: expected 65-byte uncompressed hex`);
  }
  const rawBytes = Buffer.from(hex, 'hex');
  const spki = Buffer.concat([SPKI_PREFIX_P256, rawBytes]);
  try {
    return { key: crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' }), rawBytes };
  } catch (err) {
    fail(`invalid_public_key_${label}: ${err.message}`);
  }
}

const pubA = parsePublicKey(receipt.pk_A, 'A');
const pubB = parsePublicKey(receipt.pk_B, 'B');

// 5. Validate nonces (16 hex chars = 8 bytes)
if (typeof receipt.nonce_A !== 'string' || receipt.nonce_A.length !== 16 || !/^[0-9a-fA-F]+$/.test(receipt.nonce_A)) {
  fail('malformed_nonce_A: expected 16 hex chars');
}
if (typeof receipt.nonce_B !== 'string' || receipt.nonce_B.length !== 16 || !/^[0-9a-fA-F]+$/.test(receipt.nonce_B)) {
  fail('malformed_nonce_B: expected 16 hex chars');
}
const nonceABytes = Buffer.from(receipt.nonce_A, 'hex');
const nonceBBytes = Buffer.from(receipt.nonce_B, 'hex');

// 6. Recompute Receipt Core C
// C = SHA-256("copresence.v0" || 0x00 || bytes(pk_A) || bytes(pk_B) || nonce_A || nonce_B || BE64(t_B))
const label = Buffer.from('copresence.v0', 'utf8');
const sep = Buffer.from([0x00]);
const be64TimeB = Buffer.alloc(8);
be64TimeB.writeBigUInt64BE(BigInt(receipt.t_B));

const corePayload = Buffer.concat([
  label,
  sep,
  pubA.rawBytes,
  pubB.rawBytes,
  nonceABytes,
  nonceBBytes,
  be64TimeB,
]);

const C = crypto.createHash('sha256').update(corePayload).digest();

// 7. Validate signatures (raw IEEE P1363 r||s = 64 bytes = 128 hex chars)
function parseSignature(hex, label) {
  if (typeof hex !== 'string' || hex.length !== 128 || !/^[0-9a-fA-F]+$/.test(hex)) {
    fail(`malformed_signature_${label}: expected 64-byte raw hex (128 chars)`);
  }
  return Buffer.from(hex, 'hex');
}

const sigABytes = parseSignature(receipt.sig_A, 'A');
const sigBBytes = parseSignature(receipt.sig_B, 'B');

// 8. Verify sig_A under pk_A over C
let validA = false;
try {
  validA = crypto.verify('sha256', C, { key: pubA.key, dsaEncoding: 'ieee-p1363' }, sigABytes);
} catch (err) {
  fail(`sig_A_verification_error: ${err.message}`);
}
if (!validA) {
  fail('sig_A_invalid');
}

// 9. Verify sig_B under pk_B over C
let validB = false;
try {
  validB = crypto.verify('sha256', C, { key: pubB.key, dsaEncoding: 'ieee-p1363' }, sigBBytes);
} catch (err) {
  fail(`sig_B_verification_error: ${err.message}`);
}
if (!validB) {
  fail('sig_B_invalid');
}

// 10. Optional Spacetime Telemetry & Sentinel Validation
if (receipt.geo_A && receipt.geo_B) {
  const { lat: latA, lon: lonA, acc: accA = 15 } = receipt.geo_A;
  const { lat: latB, lon: lonB, acc: accB = 15 } = receipt.geo_B;
  if (typeof latA !== 'number' || typeof lonA !== 'number' || typeof latB !== 'number' || typeof lonB !== 'number') {
    fail('invalid_geo_coordinates: lat/lon must be numbers');
  }

  // SA1/SA3: check for spoofed acc <= 0 or sub-meter perfection
  if (accA <= 0 || accB <= 0 || accA < 1.0 || accB < 1.0) {
    fail(`suspicious_spoofed_accuracy: acc_A=${accA}m, acc_B=${accB}m; sub-meter perfection indicates client position synthesis`);
  }

  // Haversine distance
  const R = 6371000;
  const toRad = (x) => (x * Math.PI) / 180;
  const dLat = toRad(latB - latA);
  const dLon = toRad(lonB - lonA);
  const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
            Math.cos(toRad(latA)) * Math.cos(toRad(latB)) *
            Math.sin(dLon / 2) * Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  const distM = R * c;

  const maxAllowedDist = accA + accB + 50; // allow GPS variance + 50m margin
  const claimedConsistent = receipt.sentinel_verdict === 'CONSISTENT_CLAIMED' || receipt.sentinel_verdict === 'GENUINE_LOCAL_PROXIMITY';
  if (claimedConsistent && distM > maxAllowedDist) {
    fail(`suspicious_spacetime_contradiction: claimed ${receipt.sentinel_verdict} but distance is ${Math.round(distM)}m > ${Math.round(maxAllowedDist)}m`);
  }
}

// 11. Optional Acoustic Telemetry & Rendezvous Validation (v1.1)
if (receipt.audio) {
  const { nonce: audioNonce, delay_ms: audioDelayMs, matched: audioMatched } = receipt.audio;
  if (audioNonce !== undefined) {
    if (typeof audioNonce !== 'string' || audioNonce.length !== 32 || !/^[0-9a-fA-F]+$/.test(audioNonce)) {
      fail('malformed_audio_nonce: expected 16-byte hex (32 chars)');
    }
  }
  if (audioMatched !== undefined && typeof audioMatched !== 'boolean') {
    fail('invalid_audio_matched: must be boolean');
  }
  if (audioMatched === false) {
    fail('suspicious_audio_nonce_mismatch: receiver failed to decode acoustic nonce');
  }
  if (audioDelayMs !== undefined) {
    if (typeof audioDelayMs !== 'number') {
      fail('invalid_audio_delay: must be number');
    }
    if (audioDelayMs < 5.0) {
      fail(`suspicious_audio_delay_impossible: ${audioDelayMs}ms < 5ms lower physical buffer floor`);
    }
    if (audioDelayMs > 150.0) {
      fail(`suspicious_audio_relay_detected: acoustic transit delay ${audioDelayMs}ms > 150ms indicates remote audio relay link`);
    }
  }
}


succeed();


