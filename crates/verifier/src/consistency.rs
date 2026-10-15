// SPDX-License-Identifier: AGPL-3.0-or-later
//! C3 observations and RFC 6962 proofs supplied as independent byte inputs.

use canon::{json::ValueView, Refusal, Result};
use sha2::{Digest, Sha256};

use crate::format;

/// Neither observation is fetched from the node or an external service.
#[derive(Clone, Copy, Debug)]
pub struct ConsistencyInputs<'a> {
    /// The caller's independently retained C3 observation.
    pub retained: &'a [u8],
    /// An untrusted C3 presented observation and RFC 6962 proof.
    pub presented: &'a [u8],
}

/// Consistency alone makes no claim about identity, occurrence or owner permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsistencyVerdict {
    /// The proof connects both supplied roots under the declared leaf convention.
    AppendOnly,
    /// A connected proof reconstructs a conflicting retained root.
    ObservationConflict,
    /// No positive consistency conclusion, including an underivable prefix.
    Undetermined,
}

/// The fields are readable but the verifier alone constructs a result.
#[derive(Clone, Copy, Debug)]
pub struct ConsistencyReport {
    verdict: ConsistencyVerdict,
    retained_size: u64,
    presented_size: u64,
}

impl ConsistencyReport {
    /// Returns the consistency finding without converting Undetermined to success.
    pub const fn verdict(self) -> ConsistencyVerdict {
        self.verdict
    }

    /// The earlier and later tree sizes used by the consistency check.
    pub const fn sizes(self) -> (u64, u64) {
        (self.retained_size, self.presented_size)
    }
}

/// Checks exact C3 schemas, declared sizes, and the supplied consistency path.
pub fn verify(inputs: ConsistencyInputs<'_>) -> Result<ConsistencyReport> {
    let earlier = retained(inputs.retained)?;
    let later = presented(inputs.presented)?;
    let verdict = if earlier.size == later.retained_size {
        verify_proof(
            earlier.size,
            later.size,
            earlier.root,
            later.root,
            &later.proof,
        )
    } else {
        ConsistencyVerdict::Undetermined
    };
    Ok(ConsistencyReport {
        verdict,
        retained_size: earlier.size,
        presented_size: later.size,
    })
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RetainedHead {
    pub(crate) size: u64,
    pub(crate) hash: [u8; 32],
    pub(crate) root: [u8; 32],
}

#[derive(Clone, Debug)]
pub(crate) struct PresentedHead {
    pub(crate) size: u64,
    pub(crate) retained_size: u64,
    pub(crate) root: [u8; 32],
    pub(crate) proof: Vec<[u8; 32]>,
}

fn refusal(reason: &'static str) -> Refusal {
    Refusal {
        organ: "verifier",
        reason,
    }
}

fn positive_size(value: &canon::json::Value) -> Result<u64> {
    let size = format::uint(value)?;
    if size == 0 {
        return Err(refusal("head-size"));
    }
    Ok(size)
}

pub(crate) fn retained(bytes: &[u8]) -> Result<RetainedHead> {
    let value = format::parse(bytes)?;
    format::keys(
        &value,
        &[
            "schema",
            "leafConvention",
            "sequence",
            "hash",
            "treeSize",
            "root",
        ],
    )
    .map_err(|_| refusal("retained-format"))?;
    if format::text(format::field(&value, "schema")?)? != format::RETAINED_HEAD_V1
        || format::text(format::field(&value, "leafConvention")?)?
            != canon::domain::RFC6962_LEAF_CONVENTION
    {
        return Err(refusal("retained-format"));
    }
    let size = positive_size(format::field(&value, "treeSize")?)?;
    if positive_size(format::field(&value, "sequence")?)? != size {
        return Err(refusal("head-sequence"));
    }
    Ok(RetainedHead {
        size,
        hash: format::hex32(format::text(format::field(&value, "hash")?)?)?,
        root: format::hex32(format::text(format::field(&value, "root")?)?)?,
    })
}

pub(crate) fn presented(bytes: &[u8]) -> Result<PresentedHead> {
    let value = format::parse(bytes)?;
    format::keys(
        &value,
        &[
            "schema",
            "leafConvention",
            "treeSize",
            "root",
            "retainedTreeSize",
            "proofFromPrevious",
        ],
    )
    .map_err(|_| refusal("presented-format"))?;
    if format::text(format::field(&value, "schema")?)? != format::PRESENTED_HEAD_V1
        || format::text(format::field(&value, "leafConvention")?)?
            != canon::domain::RFC6962_LEAF_CONVENTION
    {
        return Err(refusal("presented-format"));
    }
    let ValueView::Array(elements) = format::field(&value, "proofFromPrevious")?.view() else {
        return Err(refusal("proof-format"));
    };
    if elements.len() > 64 {
        return Err(refusal("proof-length"));
    }
    let proof = elements
        .iter()
        .map(|element| format::hex32(format::text(element)?))
        .collect::<Result<Vec<_>>>()?;
    Ok(PresentedHead {
        size: positive_size(format::field(&value, "treeSize")?)?,
        retained_size: positive_size(format::field(&value, "retainedTreeSize")?)?,
        root: format::hex32(format::text(format::field(&value, "root")?)?)?,
        proof,
    })
}

fn combine(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 65];
    input[0] = 1;
    input[1..33].copy_from_slice(&left);
    input[33..].copy_from_slice(&right);
    Sha256::digest(input).into()
}

/// Applies the C2 leaf prefix to entry hashes before building the RFC 6962 tree.
pub(crate) fn root(entry_hashes: &[[u8; 32]]) -> [u8; 32] {
    let mut frontier: Vec<Option<[u8; 32]>> = Vec::new();
    for entry in entry_hashes {
        let mut input = [0u8; 33];
        input[1..].copy_from_slice(entry);
        let mut subtree = Sha256::digest(input).into();
        let mut height = 0;
        loop {
            if height == frontier.len() {
                frontier.push(Some(subtree));
                break;
            }
            match frontier[height].take() {
                Some(left) => subtree = combine(left, subtree),
                None => {
                    frontier[height] = Some(subtree);
                    break;
                }
            }
            height += 1;
        }
    }
    let mut result = None;
    for subtree in frontier.into_iter().flatten() {
        result = Some(match result {
            Some(right) => combine(subtree, right),
            None => subtree,
        });
    }
    result.unwrap_or_else(|| Sha256::digest([]).into())
}

struct ProofCursor<'a> {
    rest: &'a [[u8; 32]],
    retained_root: [u8; 32],
}

impl ProofCursor<'_> {
    fn next(&mut self) -> Option<[u8; 32]> {
        let (next, rest) = self.rest.split_first()?;
        self.rest = rest;
        Some(*next)
    }

    // Reverses SUBPROOF: each step returns the old and new subtree roots.
    fn reconstruct(&mut self, old: u64, new: u64, complete: bool) -> Option<([u8; 32], [u8; 32])> {
        if old == new {
            let subtree = if complete {
                self.retained_root
            } else {
                self.next()?
            };
            return Some((subtree, subtree));
        }
        let split = 1u64 << ((new - 1).ilog2());
        if old <= split {
            let (earlier, left) = self.reconstruct(old, split, complete)?;
            let right = self.next()?;
            Some((earlier, combine(left, right)))
        } else {
            let (earlier_right, later_right) = self.reconstruct(old - split, new - split, false)?;
            let left = self.next()?;
            Some((combine(left, earlier_right), combine(left, later_right)))
        }
    }
}

pub(crate) fn verify_proof(
    old_size: u64,
    new_size: u64,
    old_root: [u8; 32],
    new_root: [u8; 32],
    proof: &[[u8; 32]],
) -> ConsistencyVerdict {
    use ConsistencyVerdict::{AppendOnly, ObservationConflict, Undetermined};
    if old_size == 0
        || old_size > new_size
        || new_size > canon::json::MAX_SAFE_INTEGER as u64
        || proof.len() > 64
    {
        return Undetermined;
    }
    if old_size == new_size {
        return if !proof.is_empty() {
            Undetermined
        } else if old_root == new_root {
            AppendOnly
        } else {
            ObservationConflict
        };
    }
    let mut cursor = ProofCursor {
        rest: proof,
        retained_root: old_root,
    };
    let Some((derived_old, derived_new)) = cursor.reconstruct(old_size, new_size, true) else {
        return Undetermined;
    };
    if !cursor.rest.is_empty() || derived_new != new_root {
        return Undetermined;
    }
    if derived_old == old_root {
        AppendOnly
    } else if old_size.is_power_of_two() {
        Undetermined
    } else {
        ObservationConflict
    }
}
