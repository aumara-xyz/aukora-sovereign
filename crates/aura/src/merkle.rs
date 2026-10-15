//! RFC 6962 trees over Aura entry hashes.

use canon::{canonical_json, Value};
use sha2::{Digest, Sha256};

use crate::Error;

pub type Hash = [u8; 32];

pub const LEAF_CONVENTION: &str = "rfc6962-leaf-sha256-0x00-prefixed-v1";

pub fn leaf_hash(entry_hash: &Hash) -> Hash {
    let mut digest = Sha256::new();
    digest.update([0]);
    digest.update(entry_hash);
    digest.finalize().into()
}

pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut digest = Sha256::new();
    digest.update([1]);
    digest.update(left);
    digest.update(right);
    digest.finalize().into()
}

/// Inputs are leaf hashes, with the RFC 6962 leaf prefix already applied.
pub fn tree_head(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => Sha256::digest([]).into(),
        1 => leaves[0],
        size => {
            let split = split(size);
            node_hash(&tree_head(&leaves[..split]), &tree_head(&leaves[split..]))
        }
    }
}

/// The proof is ordered from the leaf to the root.
pub fn inclusion_proof(index: usize, leaves: &[Hash]) -> Result<Vec<Hash>, Error> {
    if index >= leaves.len() {
        return Err(Error::new("aura:invalid-leaf-index"));
    }
    let mut proof = Vec::new();
    inclusion_path(index, leaves, &mut proof);
    Ok(proof)
}

pub fn consistency_proof(retained_size: usize, leaves: &[Hash]) -> Result<Vec<Hash>, Error> {
    if retained_size == 0 || retained_size > leaves.len() {
        return Err(Error::new("aura:invalid-tree-size"));
    }
    let mut proof = Vec::new();
    subproof(retained_size, leaves, true, &mut proof);
    Ok(proof)
}

fn split(size: usize) -> usize {
    debug_assert!(size > 1);
    1 << (usize::BITS - 1 - (size - 1).leading_zeros())
}

fn inclusion_path(index: usize, leaves: &[Hash], proof: &mut Vec<Hash>) {
    if leaves.len() == 1 {
        return;
    }
    let split = split(leaves.len());
    if index < split {
        inclusion_path(index, &leaves[..split], proof);
        proof.push(tree_head(&leaves[split..]));
    } else {
        inclusion_path(index - split, &leaves[split..], proof);
        proof.push(tree_head(&leaves[..split]));
    }
}

// RFC 6962 section 2.1.2 SUBPROOF(m, D[n], b).
fn subproof(retained_size: usize, leaves: &[Hash], complete: bool, proof: &mut Vec<Hash>) {
    if retained_size == leaves.len() {
        if !complete {
            proof.push(tree_head(leaves));
        }
        return;
    }
    let split = split(leaves.len());
    if retained_size <= split {
        subproof(retained_size, &leaves[..split], complete, proof);
        proof.push(tree_head(&leaves[split..]));
    } else {
        subproof(retained_size - split, &leaves[split..], false, proof);
        proof.push(tree_head(&leaves[..split]));
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedHead {
    pub schema: String,
    pub leaf_convention: String,
    pub sequence: usize,
    pub hash: String,
    pub tree_size: usize,
    pub root: String,
}

impl RetainedHead {
    pub fn to_json(&self) -> Result<String, Error> {
        export_json(Value::Object(vec![
            ("schema".into(), Value::String(self.schema.clone())),
            (
                "leafConvention".into(),
                Value::String(self.leaf_convention.clone()),
            ),
            ("sequence".into(), export_integer(self.sequence)?),
            ("hash".into(), Value::String(self.hash.clone())),
            ("treeSize".into(), export_integer(self.tree_size)?),
            ("root".into(), Value::String(self.root.clone())),
        ]))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresentedHead {
    pub schema: String,
    pub leaf_convention: String,
    pub tree_size: usize,
    pub root: String,
    pub retained_tree_size: usize,
    pub proof_from_previous: Vec<String>,
    pub next_index: Option<usize>,
    pub next_leaf_hash: Option<String>,
    pub next_inclusion_proof: Option<Vec<String>>,
}

impl PresentedHead {
    pub fn to_json(&self) -> Result<String, Error> {
        let mut fields = vec![
            ("schema".into(), Value::String(self.schema.clone())),
            (
                "leafConvention".into(),
                Value::String(self.leaf_convention.clone()),
            ),
            ("treeSize".into(), export_integer(self.tree_size)?),
            ("root".into(), Value::String(self.root.clone())),
            (
                "retainedTreeSize".into(),
                export_integer(self.retained_tree_size)?,
            ),
            (
                "proofFromPrevious".into(),
                strings(&self.proof_from_previous),
            ),
        ];
        if let Some(index) = self.next_index {
            fields.push(("nextIndex".into(), export_integer(index)?));
        }
        if let Some(hash) = &self.next_leaf_hash {
            fields.push(("nextLeafHash".into(), Value::String(hash.clone())));
        }
        if let Some(proof) = &self.next_inclusion_proof {
            fields.push(("nextInclusionProof".into(), strings(proof)));
        }
        export_json(Value::Object(fields))
    }
}

fn export_integer(value: usize) -> Result<Value, Error> {
    i64::try_from(value)
        .ok()
        .filter(|value| value.unsigned_abs() <= canon::MAX_SAFE_INTEGER as u64)
        .map(Value::Integer)
        .ok_or_else(|| Error::new("aura:export"))
}

fn strings(values: &[String]) -> Value {
    Value::Array(values.iter().cloned().map(Value::String).collect())
}

fn export_json(value: Value) -> Result<String, Error> {
    canonical_json(&value)
        .map(|bytes| String::from_utf8(bytes).expect("canonical JSON is UTF-8"))
        .map_err(|_| Error::new("aura:export"))
}

/// Inputs are rederived entry hashes; this function applies the leaf prefix.
pub fn retained_head(entry_hashes: &[Hash], retained_size: usize) -> Result<RetainedHead, Error> {
    if retained_size == 0 || retained_size > entry_hashes.len() {
        return Err(Error::new("aura:invalid-retained-size"));
    }
    if retained_size > crate::MAX_BUFFER_BYTES / 32 {
        return Err(Error::new("aura:memory-limit"));
    }
    let leaves: Vec<_> = entry_hashes[..retained_size]
        .iter()
        .map(leaf_hash)
        .collect();
    Ok(RetainedHead {
        schema: "aukora-aura-retained-head-v1".into(),
        leaf_convention: LEAF_CONVENTION.into(),
        sequence: retained_size,
        hash: hex::encode(entry_hashes[retained_size - 1]),
        tree_size: retained_size,
        root: hex::encode(tree_head(&leaves)),
    })
}

/// Inputs are rederived entry hashes; this function applies the leaf prefix.
pub fn presented_head(entry_hashes: &[Hash], retained_size: usize) -> Result<PresentedHead, Error> {
    if retained_size == 0 || retained_size > entry_hashes.len() {
        return Err(Error::new("aura:invalid-retained-size"));
    }
    if entry_hashes.len() > crate::MAX_BUFFER_BYTES / 32 {
        return Err(Error::new("aura:memory-limit"));
    }
    let leaves: Vec<_> = entry_hashes.iter().map(leaf_hash).collect();
    let include_next = retained_size.is_power_of_two() && retained_size < leaves.len();
    Ok(PresentedHead {
        schema: "aukora-aura-presented-head-v1".into(),
        leaf_convention: LEAF_CONVENTION.into(),
        tree_size: entry_hashes.len(),
        root: hex::encode(tree_head(&leaves)),
        retained_tree_size: retained_size,
        proof_from_previous: consistency_proof(retained_size, &leaves)?
            .iter()
            .map(hex::encode)
            .collect(),
        next_index: include_next.then_some(retained_size),
        next_leaf_hash: include_next.then(|| hex::encode(leaves[retained_size])),
        next_inclusion_proof: if include_next {
            Some(
                inclusion_proof(retained_size, &leaves)?
                    .iter()
                    .map(hex::encode)
                    .collect(),
            )
        } else {
            None
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(size: usize) -> Vec<Hash> {
        (0..size).map(|index| [index as u8; 32]).collect()
    }

    fn hexes(hashes: &[Hash]) -> Vec<String> {
        hashes.iter().map(hex::encode).collect()
    }

    fn verify_inclusion(index: usize, size: usize, leaf: Hash, proof: &[Hash]) -> Hash {
        let mut hash = leaf;
        let (mut index, mut last) = (index, size - 1);
        for sibling in proof {
            if index & 1 == 1 || index == last {
                hash = node_hash(sibling, &hash);
                while index > 0 && index & 1 == 0 {
                    index >>= 1;
                    last >>= 1;
                }
            } else {
                hash = node_hash(&hash, sibling);
            }
            index >>= 1;
            last >>= 1;
        }
        assert_eq!(last, 0);
        hash
    }

    fn verify_consistency(m: usize, n: usize, old: Hash, new: Hash, proof: &[Hash]) -> bool {
        if m == n {
            return proof.is_empty() && old == new;
        }
        let (mut first, mut second) = (m - 1, n - 1);
        while first & 1 == 1 {
            first >>= 1;
            second >>= 1;
        }
        let (mut old_hash, mut new_hash, mut path) = if m.is_power_of_two() {
            (old, old, proof.iter())
        } else {
            (proof[0], proof[0], proof[1..].iter())
        };
        while second > 0 {
            let Some(sibling) = path.next() else {
                return false;
            };
            if first & 1 == 1 || first == second {
                old_hash = node_hash(sibling, &old_hash);
                new_hash = node_hash(sibling, &new_hash);
                while first > 0 && first & 1 == 0 {
                    first >>= 1;
                    second >>= 1;
                }
            } else {
                new_hash = node_hash(&new_hash, sibling);
            }
            first >>= 1;
            second >>= 1;
        }
        path.next().is_none() && old_hash == old && new_hash == new
    }

    #[test]
    fn head_constructors_bound_leaf_buffers() {
        let hashes = vec![[0; 32]; crate::MAX_BUFFER_BYTES / 32 + 1];
        assert_eq!(
            retained_head(&hashes, hashes.len()).unwrap_err().code,
            "aura:memory-limit"
        );
        assert_eq!(
            presented_head(&hashes, 1).unwrap_err().code,
            "aura:memory-limit"
        );
    }

    #[test]
    fn python_hashlib_vectors_fix_leaf_and_node_domains_and_tree_shape() {
        let leaves: Vec<_> = entries(8).iter().map(leaf_hash).collect();
        assert_eq!(
            hex::encode(leaves[0]),
            "7f9c9e31ac8256ca2f258583df262dbc7d6f68f2a03043d5c99a4ae5a7396ce9"
        );
        let roots = [
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "7f9c9e31ac8256ca2f258583df262dbc7d6f68f2a03043d5c99a4ae5a7396ce9",
            "28fb81e496897e0ce886f08602392e9239b65c659041e5202163e58ad898f444",
            "ba8d94b7fbcecae7b81c4c80574fe24734a6917bf9c1ecd66ff3e0c34ead4620",
            "fdea52008cdae79fa8bf806261959e23f5e11681646a2fa2bc9b5e56b32030a2",
            "85e20cac1f02fda7bcdb2fc3f908568c57018c77815f1fa361acad13994f08bf",
            "380272ed524daf3398067faf4717782ba90805d4823ea6e1e594668c9fd40bba",
            "7318881c41fce3c1de3640df8e8c110c93f43f686b74204a9d1ad5b8c71c2047",
            "f907f23f76aa01b755a614d31ef9832909f44638b4590073301e61e6d01f9a1d",
        ];
        for (size, expected) in roots.into_iter().enumerate() {
            assert_eq!(hex::encode(tree_head(&leaves[..size])), expected);
        }
    }

    #[test]
    fn python_hashlib_vectors_fix_inclusion_and_subproof_order() {
        let leaves: Vec<_> = entries(7).iter().map(leaf_hash).collect();
        assert_eq!(
            hexes(&inclusion_proof(4, &leaves).unwrap()),
            [
                "f3ab555d06a67b08ab25039fdbe2a6fcb305c83bc165492ce81d3dea13ec1fbf",
                "511c6562982c9bfa05ba4145ca5f2bba85a11a178a4131b5cebde26dd9ffe704",
                "fdea52008cdae79fa8bf806261959e23f5e11681646a2fa2bc9b5e56b32030a2",
            ]
        );
        assert_eq!(
            hexes(&consistency_proof(3, &leaves).unwrap()),
            [
                "cba8c596120bdb69debbd923d92cba948bde7c7d06a465a1bb7d98d3116038fa",
                "acaa04663a8547a2f70c60cc18f9378796b13c4f9a08f70d6adae662365b30c6",
                "28fb81e496897e0ce886f08602392e9239b65c659041e5202163e58ad898f444",
                "1f3f95843413191fe7521996b6b1e4147d703b1702c475a478ad25a6f6b415b4",
            ]
        );
        assert_eq!(
            hexes(&consistency_proof(4, &leaves).unwrap()),
            ["1f3f95843413191fe7521996b6b1e4147d703b1702c475a478ad25a6f6b415b4",]
        );
    }

    #[test]
    fn every_inclusion_and_consistency_proof_through_40_verifies() {
        let leaves: Vec<_> = entries(40).iter().map(leaf_hash).collect();
        for size in 1..=leaves.len() {
            let current = &leaves[..size];
            let root = tree_head(current);
            for (index, leaf) in current.iter().enumerate() {
                let proof = inclusion_proof(index, current).unwrap();
                assert_eq!(verify_inclusion(index, size, *leaf, &proof), root);
            }
            for previous in 1..=size {
                let proof = consistency_proof(previous, current).unwrap();
                assert!(verify_consistency(
                    previous,
                    size,
                    tree_head(&current[..previous]),
                    root,
                    &proof
                ));
            }
        }
    }

    #[test]
    fn invalid_proof_and_export_bounds_are_refused() {
        let hashes = entries(2);
        assert_eq!(
            inclusion_proof(0, &[]).unwrap_err().code,
            "aura:invalid-leaf-index"
        );
        assert_eq!(
            inclusion_proof(2, &hashes).unwrap_err().code,
            "aura:invalid-leaf-index"
        );
        assert_eq!(
            consistency_proof(0, &hashes).unwrap_err().code,
            "aura:invalid-tree-size"
        );
        assert_eq!(
            consistency_proof(3, &hashes).unwrap_err().code,
            "aura:invalid-tree-size"
        );
        for size in [0, 3] {
            assert_eq!(
                retained_head(&hashes, size).unwrap_err().code,
                "aura:invalid-retained-size"
            );
            assert_eq!(
                presented_head(&hashes, size).unwrap_err().code,
                "aura:invalid-retained-size"
            );
        }
        assert_eq!(
            retained_head(&[], 1).unwrap_err().code,
            "aura:invalid-retained-size"
        );
        assert_eq!(
            presented_head(&[], 1).unwrap_err().code,
            "aura:invalid-retained-size"
        );
    }

    #[test]
    fn exports_bind_prefix_head_and_serialize_contract_names() {
        let hashes = entries(7);
        let retained = retained_head(&hashes, 3).unwrap();
        let leaves: Vec<_> = hashes.iter().map(leaf_hash).collect();
        assert_eq!(
            retained.to_json().unwrap(),
            export_json(Value::Object(vec![
                (
                    "schema".into(),
                    Value::String("aukora-aura-retained-head-v1".into()),
                ),
                (
                    "leafConvention".into(),
                    Value::String(LEAF_CONVENTION.into()),
                ),
                ("sequence".into(), Value::Integer(3)),
                ("hash".into(), Value::String(hex::encode(hashes[2]))),
                ("treeSize".into(), Value::Integer(3)),
                (
                    "root".into(),
                    Value::String(hex::encode(tree_head(&leaves[..3]))),
                ),
            ]))
            .unwrap()
        );
        let presented = presented_head(&hashes, 3).unwrap();
        assert_eq!(
            presented.to_json().unwrap(),
            export_json(Value::Object(vec![
                (
                    "schema".into(),
                    Value::String("aukora-aura-presented-head-v1".into()),
                ),
                (
                    "leafConvention".into(),
                    Value::String(LEAF_CONVENTION.into()),
                ),
                ("treeSize".into(), Value::Integer(7)),
                (
                    "root".into(),
                    Value::String(hex::encode(tree_head(&leaves))),
                ),
                ("retainedTreeSize".into(), Value::Integer(3)),
                (
                    "proofFromPrevious".into(),
                    strings(&hexes(&consistency_proof(3, &leaves).unwrap())),
                ),
            ]))
            .unwrap()
        );
    }

    #[test]
    fn power_of_two_export_adds_next_leaf_and_its_inclusion_path() {
        let hashes = entries(40);
        let leaves: Vec<_> = hashes.iter().map(leaf_hash).collect();
        for previous in [1, 2, 4, 8, 16, 32] {
            let presented = presented_head(&hashes, previous).unwrap();
            assert_eq!(presented.next_index, Some(previous));
            assert_eq!(
                presented.next_leaf_hash,
                Some(hex::encode(leaves[previous]))
            );
            assert_eq!(
                presented.next_inclusion_proof,
                Some(hexes(&inclusion_proof(previous, &leaves).unwrap()))
            );
            let same = presented_head(&hashes[..previous], previous).unwrap();
            assert!(same.proof_from_previous.is_empty());
            assert_eq!(
                (
                    same.next_index,
                    same.next_leaf_hash,
                    same.next_inclusion_proof
                ),
                (None, None, None)
            );
        }
        for previous in [3, 5, 6, 7, 9, 31] {
            let presented = presented_head(&hashes, previous).unwrap();
            assert_eq!(
                (
                    presented.next_index,
                    presented.next_leaf_hash,
                    presented.next_inclusion_proof
                ),
                (None, None, None)
            );
        }
    }
}
