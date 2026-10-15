// SPDX-License-Identifier: AGPL-3.0-or-later
//! RFC 6962 trees consume raw entry digests and apply the leaf domain once.

use canon::{codes::AURA_UNVERIFIED, digest::Digest32, Result};

/// An incremental tree head retains one subtree per occupied binary digit.
#[derive(Clone, Debug, Default)]
pub struct Frontier {
    subtrees: Vec<Option<Digest32>>,
    size: u64,
}

impl Frontier {
    pub fn push(&mut self, entry_hash: Digest32) -> Result<()> {
        let next = self.size.checked_add(1).ok_or(AURA_UNVERIFIED)?;
        let mut carry = Digest32::rfc6962_leaf(entry_hash);
        let mut level = 0;
        while level < self.subtrees.len() {
            match self.subtrees[level].take() {
                Some(left) => carry = Digest32::rfc6962_node(left, carry),
                None => {
                    self.subtrees[level] = Some(carry);
                    self.size = next;
                    return Ok(());
                }
            }
            level += 1;
        }
        self.subtrees.push(Some(carry));
        self.size = next;
        Ok(())
    }

    pub fn root(&self) -> Digest32 {
        self.subtrees
            .iter()
            .flatten()
            .copied()
            .reduce(|right, left| Digest32::rfc6962_node(left, right))
            .unwrap_or_else(|| Digest32::sha256(&[]))
    }

    pub const fn size(&self) -> u64 {
        self.size
    }
}

/// All inputs are raw C2 entry digests; this API applies the leaf prefix itself.
pub fn root(entry_hashes: &[Digest32]) -> Result<Digest32> {
    let mut frontier = Frontier::default();
    for entry in entry_hashes {
        frontier.push(*entry)?;
    }
    Ok(frontier.root())
}

/// The proof order is leaf toward root; index is zero based and must exist.
pub fn inclusion(entry_hashes: &[Digest32], index: usize) -> Result<Vec<Digest32>> {
    if index >= entry_hashes.len() {
        return Err(AURA_UNVERIFIED);
    }
    let mut branch = entry_hashes;
    let mut position = index;
    let mut siblings = Vec::new();
    while branch.len() > 1 {
        let (left, right) = branch.split_at(branch_split(branch.len()));
        if position < left.len() {
            siblings.push(root(right)?);
            branch = left;
        } else {
            siblings.push(root(left)?);
            position -= left.len();
            branch = right;
        }
    }
    siblings.reverse();
    Ok(siblings)
}

/// SUBPROOF(M,D[N],true), with 1 <= M <= N; equal sizes require an empty proof.
pub fn consistency(entry_hashes: &[Digest32], retained_size: usize) -> Result<Vec<Digest32>> {
    if retained_size == 0 || retained_size > entry_hashes.len() {
        return Err(AURA_UNVERIFIED);
    }
    let mut branch = entry_hashes;
    let mut covered = retained_size;
    let mut complete = true;
    let mut siblings = Vec::new();
    while covered != branch.len() {
        let (left, right) = branch.split_at(branch_split(branch.len()));
        if covered <= left.len() {
            siblings.push(root(right)?);
            branch = left;
        } else {
            siblings.push(root(left)?);
            covered -= left.len();
            branch = right;
            complete = false;
        }
    }
    if !complete {
        siblings.push(root(branch)?);
    }
    siblings.reverse();
    Ok(siblings)
}

fn branch_split(length: usize) -> usize {
    // The largest power of two strictly below length; callers have length > 1.
    1_usize << (usize::BITS - (length - 1).leading_zeros() - 1)
}

pub fn verify_inclusion(
    entry_hash: Digest32,
    index: u64,
    tree_size: u64,
    expected_root: Digest32,
    proof: &[Digest32],
) -> Result<()> {
    if tree_size == 0 || index >= tree_size || proof.len() > 64 {
        return Err(AURA_UNVERIFIED);
    }
    let mut position = index;
    let mut rightmost = tree_size - 1;
    let mut computed = Digest32::rfc6962_leaf(entry_hash);
    for sibling in proof {
        if rightmost == 0 {
            return Err(AURA_UNVERIFIED);
        }
        if position & 1 == 1 || position == rightmost {
            computed = Digest32::rfc6962_node(*sibling, computed);
            while position != 0 && position & 1 == 0 {
                position >>= 1;
                rightmost >>= 1;
            }
        } else {
            computed = Digest32::rfc6962_node(computed, *sibling);
        }
        position >>= 1;
        rightmost >>= 1;
    }
    if rightmost != 0 || computed != expected_root {
        return Err(AURA_UNVERIFIED);
    }
    Ok(())
}

/// A Merkle result does not replace the arm-one walk or an independent retained head.
pub fn verify_consistency(
    retained_size: u64,
    presented_size: u64,
    retained_root: Digest32,
    presented_root: Digest32,
    proof: &[Digest32],
) -> Result<()> {
    if retained_size == 0 || retained_size > presented_size || proof.len() > 65 {
        return Err(AURA_UNVERIFIED);
    }
    if retained_size == presented_size {
        return if proof.is_empty() && retained_root == presented_root {
            Ok(())
        } else {
            Err(AURA_UNVERIFIED)
        };
    }
    let mut old_index = retained_size - 1;
    let mut new_index = presented_size - 1;
    while old_index & 1 == 1 {
        old_index >>= 1;
        new_index >>= 1;
    }
    let mut nodes = proof.iter();
    let seed = if old_index == 0 {
        retained_root
    } else {
        *nodes.next().ok_or(AURA_UNVERIFIED)?
    };
    let (mut old, mut new) = (seed, seed);
    for sibling in nodes {
        if new_index == 0 {
            return Err(AURA_UNVERIFIED);
        }
        if old_index & 1 == 1 || old_index == new_index {
            old = Digest32::rfc6962_node(*sibling, old);
            new = Digest32::rfc6962_node(*sibling, new);
            while old_index != 0 && old_index & 1 == 0 {
                old_index >>= 1;
                new_index >>= 1;
            }
        } else {
            new = Digest32::rfc6962_node(new, *sibling);
        }
        old_index >>= 1;
        new_index >>= 1;
    }
    if new_index != 0 || old != retained_root || new != presented_root {
        return Err(AURA_UNVERIFIED);
    }
    Ok(())
}
