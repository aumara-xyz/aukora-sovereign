// SPDX-License-Identifier: AGPL-3.0-or-later
//! RFC 6962 proof contracts over entry hashes, never over displayed hex text.

use canon::{digest::Digest32, Result};

/// All inputs are raw C2 entry digests; this API applies the leaf prefix itself.
pub fn root(_entry_hashes: &[Digest32]) -> Result<Digest32> {
    crate::unavailable()
}

/// The proof order is leaf toward root; index is zero based and must exist.
pub fn inclusion(_entry_hashes: &[Digest32], _index: usize) -> Result<Vec<Digest32>> {
    crate::unavailable()
}

/// SUBPROOF(M,D[N],true), with 1 <= M <= N; equal sizes require an empty proof.
pub fn consistency(_entry_hashes: &[Digest32], _retained_size: usize) -> Result<Vec<Digest32>> {
    crate::unavailable()
}

pub fn verify_inclusion(
    _entry_hash: Digest32,
    _index: u64,
    _tree_size: u64,
    _root: Digest32,
    _proof: &[Digest32],
) -> Result<()> {
    crate::unavailable()
}

/// A Merkle result does not replace the arm-one walk or an independent retained head.
pub fn verify_consistency(
    _retained_size: u64,
    _presented_size: u64,
    _retained_root: Digest32,
    _presented_root: Digest32,
    _proof: &[Digest32],
) -> Result<()> {
    crate::unavailable()
}
