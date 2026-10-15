/* RFC 6962 §2.1.2 consistency-proof verification, ported from aukora-prime
   vendor/append-only/verify.py (verify_consistency, lines 31-69). Same three
   verdicts, same reasons, same power-of-two blind spot.
   sha256: async (Uint8Array) -> Uint8Array | ArrayBuffer (32 bytes). */

const MAX_SAFE_INT = 9007199254740991;

const isPowerOfTwo = v => v > 0 && (BigInt(v) & (BigInt(v) - 1n)) === 0n;
const isDigest = v => typeof v === 'string' && /^[0-9a-fA-F]{64}$/.test(v);
const isSize = v => typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= MAX_SAFE_INT;

function hexToBytes(hex) {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function bytesToHex(bytes) {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

export async function verifyConsistency({ m, n, root1, root2, proof }, sha256) {
  const node = async (l, r) => {
    const msg = new Uint8Array(65);
    msg[0] = 0x01;
    msg.set(hexToBytes(l), 1);
    msg.set(hexToBytes(r), 33);
    const out = await sha256(msg);
    return bytesToHex(out instanceof ArrayBuffer ? new Uint8Array(out) : out);
  };

  if (!isSize(m) || !isSize(n) || m > n) return { verdict: 'UNDETERMINED', reason: 'invalid_tree_sizes' };
  if (!isDigest(root1) || !isDigest(root2)) return { verdict: 'UNDETERMINED', reason: 'root_is_not_a_digest' };
  if (!Array.isArray(proof) || !proof.every(isDigest)) return { verdict: 'UNDETERMINED', reason: 'proof_element_is_not_a_digest' };

  if (m === 0) return { verdict: 'UNDETERMINED', reason: 'missing_prior_observation' };
  if (m === n) {
    if (proof.length !== 0) return { verdict: 'UNDETERMINED', reason: 'non_empty_proof_for_same_size' };
    if (root1.toLowerCase() === root2.toLowerCase()) return { verdict: 'APPEND_ONLY', reason: 'identical_trees_match' };
    return { verdict: 'OBSERVATION_CONFLICT', reason: 'same_size_root_mismatch' };
  }

  if (!proof || proof.length === 0) return { verdict: 'UNDETERMINED', reason: 'empty_proof_for_different_sizes' };

  let pIdx = 0, fr, sr;
  if (isPowerOfTwo(m)) { fr = root1; sr = root1; }
  else { fr = proof[pIdx]; sr = proof[pIdx]; pIdx += 1; }

  let fn = m - 1, sn = n - 1;
  while (fn % 2 === 1) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }

  while (sn > 0) {
    if (fn % 2 === 1 || fn === sn) {
      if (pIdx >= proof.length) return { verdict: 'UNDETERMINED', reason: 'proof_path_truncated' };
      const nxt = proof[pIdx];
      pIdx += 1;
      fr = await node(nxt, fr);
      sr = await node(nxt, sr);
      while (fn > 0 && fn % 2 === 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
    } else {
      if (pIdx >= proof.length) return { verdict: 'UNDETERMINED', reason: 'proof_path_truncated' };
      const nxt = proof[pIdx];
      pIdx += 1;
      sr = await node(sr, nxt);
    }
    fn = Math.floor(fn / 2); sn = Math.floor(sn / 2);
  }

  if (sr.toLowerCase() !== root2.toLowerCase()) {
    if (isPowerOfTwo(m)) return { verdict: 'UNDETERMINED', reason: 'POWER_OF_TWO_PREFIX_NOT_INDEPENDENTLY_DERIVABLE' };
    return { verdict: 'UNDETERMINED', reason: 'proof_did_not_connect_to_presented_head' };
  }
  if (pIdx !== proof.length) return { verdict: 'UNDETERMINED', reason: 'unconsumed_proof_elements' };

  if (fr.toLowerCase() === root1.toLowerCase()) return { verdict: 'APPEND_ONLY', reason: 'valid_append_only_extension' };
  if (isPowerOfTwo(m)) return { verdict: 'UNDETERMINED', reason: 'POWER_OF_TWO_PREFIX_NOT_INDEPENDENTLY_DERIVABLE' };
  return { verdict: 'OBSERVATION_CONFLICT', reason: 'consistency:prefix-mismatch' };
}
