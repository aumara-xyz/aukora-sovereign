use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

pub fn leaf(entry_hash: &Hash) -> Hash {
    let mut digest = Sha256::new();
    digest.update([0]);
    digest.update(entry_hash);
    digest.finalize().into()
}

fn node(left: &Hash, right: &Hash) -> Hash {
    let mut digest = Sha256::new();
    digest.update([1]);
    digest.update(left);
    digest.update(right);
    digest.finalize().into()
}

pub fn root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => Sha256::digest([]).into(),
        1 => leaves[0],
        size => {
            let split = 1usize << (usize::BITS - (size - 1).leading_zeros() - 1);
            node(&root(&leaves[..split]), &root(&leaves[split..]))
        }
    }
}

pub fn verify_consistency(
    old_size: usize,
    new_size: usize,
    old_root: Hash,
    new_root: Hash,
    proof: &[Hash],
) -> bool {
    if old_size == 0 || old_size > new_size {
        return false;
    }
    if old_size == new_size {
        return proof.is_empty() && old_root == new_root;
    }

    let mut old_index = old_size - 1;
    let mut new_index = new_size - 1;
    while old_index & 1 == 1 {
        old_index >>= 1;
        new_index >>= 1;
    }

    let (mut old_hash, mut new_hash, proof) = if old_index == 0 {
        (old_root, old_root, proof)
    } else {
        let Some((first, rest)) = proof.split_first() else {
            return false;
        };
        (*first, *first, rest)
    };

    for sibling in proof {
        if new_index == 0 {
            return false;
        }
        if old_index & 1 == 1 || old_index == new_index {
            old_hash = node(sibling, &old_hash);
            new_hash = node(sibling, &new_hash);
            while old_index != 0 && old_index & 1 == 0 {
                old_index >>= 1;
                new_index >>= 1;
            }
        } else {
            new_hash = node(&new_hash, sibling);
        }
        old_index >>= 1;
        new_index >>= 1;
    }

    old_index == 0 && new_index == 0 && old_hash == old_root && new_hash == new_root
}

#[cfg(test)]
mod tests {
    use super::{leaf, root, verify_consistency, Hash};
    use sha2::{Digest, Sha256};

    fn independent_node(left: Hash, right: Hash) -> Hash {
        let bytes: Vec<_> = [vec![1], left.to_vec(), right.to_vec()].concat();
        Sha256::digest(bytes).into()
    }

    fn independent_root(hashes: &[Hash]) -> Hash {
        let mut level = hashes.to_vec();
        if level.is_empty() {
            return Sha256::digest([]).into();
        }
        while level.len() > 1 {
            level = level
                .chunks(2)
                .map(|pair| match pair {
                    [left, right] => independent_node(*left, *right),
                    [only] => *only,
                    _ => unreachable!(),
                })
                .collect();
        }
        level[0]
    }

    fn independent_proof(old_size: usize, leaves: &[Hash], complete: bool) -> Vec<Hash> {
        if old_size == leaves.len() {
            return if complete {
                Vec::new()
            } else {
                vec![independent_root(leaves)]
            };
        }
        let split = (1..leaves.len())
            .rfind(|size| size.is_power_of_two())
            .unwrap();
        if old_size <= split {
            let mut proof = independent_proof(old_size, &leaves[..split], complete);
            proof.push(independent_root(&leaves[split..]));
            proof
        } else {
            let mut proof = independent_proof(old_size - split, &leaves[split..], false);
            proof.push(independent_root(&leaves[..split]));
            proof
        }
    }

    fn leaves(count: usize) -> Vec<Hash> {
        (0..count)
            .map(|index| {
                let hash: Hash = Sha256::digest(index.to_be_bytes()).into();
                let bytes: Vec<_> = [vec![0], hash.to_vec()].concat();
                Sha256::digest(bytes).into()
            })
            .collect()
    }

    #[test]
    fn leaf_has_rfc6962_domain_prefix() {
        let hash = [0x61; 32];
        let expected: Hash = Sha256::digest([vec![0], hash.to_vec()].concat()).into();
        let unprefixed: Hash = Sha256::digest(hash).into();
        assert_eq!(leaf(&hash), expected);
        assert_ne!(leaf(&hash), hash);
        assert_ne!(leaf(&hash), unprefixed);
    }

    #[test]
    fn roots_use_prefixed_nodes_and_largest_power_of_two_split() {
        let hashes = leaves(129);
        for size in 0..=hashes.len() {
            assert_eq!(root(&hashes[..size]), independent_root(&hashes[..size]));
        }
        assert_eq!(root(&hashes[..1]), hashes[0]);
        assert_ne!(root(&hashes[..2]), hashes[0]);
    }

    #[test]
    fn consistency_all_small_tree_sizes_and_power_of_two_retained_heads() {
        let hashes = leaves(64);
        for new_size in 1..=64 {
            for old_size in 1..=new_size {
                let proof = independent_proof(old_size, &hashes[..new_size], true);
                assert!(
                    verify_consistency(
                        old_size,
                        new_size,
                        independent_root(&hashes[..old_size]),
                        independent_root(&hashes[..new_size]),
                        &proof,
                    ),
                    "consistency {old_size} -> {new_size}"
                );
            }
        }
        for old_size in [1, 2, 4, 8, 16, 32] {
            for new_size in [old_size + 1, old_size * 2] {
                let proof = independent_proof(old_size, &hashes[..new_size], true);
                assert!(verify_consistency(
                    old_size,
                    new_size,
                    independent_root(&hashes[..old_size]),
                    independent_root(&hashes[..new_size]),
                    &proof,
                ));
            }
        }
    }

    #[test]
    fn consistency_rejects_missing_extra_and_changed_proof_nodes() {
        let hashes = leaves(33);
        for old_size in 1..33 {
            let old_root = independent_root(&hashes[..old_size]);
            let new_root = independent_root(&hashes);
            let proof = independent_proof(old_size, &hashes, true);
            for index in 0..proof.len() {
                let mut missing = proof.clone();
                missing.remove(index);
                assert!(!verify_consistency(
                    old_size, 33, old_root, new_root, &missing
                ));
                let mut changed = proof.clone();
                changed[index][0] ^= 1;
                assert!(!verify_consistency(
                    old_size, 33, old_root, new_root, &changed
                ));
            }
            let mut extra = proof.clone();
            extra.push([0; 32]);
            assert!(!verify_consistency(
                old_size, 33, old_root, new_root, &extra
            ));
        }
    }

    #[test]
    fn consistency_rejects_short_proof_even_when_supplied_root_matches_it() {
        let hashes = leaves(4);
        assert!(!verify_consistency(
            1,
            4,
            hashes[0],
            independent_root(&hashes[..2]),
            &[hashes[1]],
        ));
    }

    #[test]
    fn consistency_rejects_forks_and_mismatched_roots() {
        let hashes = leaves(33);
        let mut fork = hashes.clone();
        fork[0][0] ^= 1;
        for old_size in 1..=32 {
            let old_root = independent_root(&hashes[..old_size]);
            let new_root = independent_root(&hashes);
            let proof = independent_proof(old_size, &hashes, true);
            let mut bad_old_root = old_root;
            bad_old_root[0] ^= 1;
            assert!(!verify_consistency(
                old_size,
                33,
                bad_old_root,
                new_root,
                &proof
            ));
            let mut bad_new_root = new_root;
            bad_new_root[0] ^= 1;
            assert!(!verify_consistency(
                old_size,
                33,
                old_root,
                bad_new_root,
                &proof
            ));
            let fork_proof = independent_proof(old_size, &fork, true);
            assert!(!verify_consistency(
                old_size,
                33,
                old_root,
                independent_root(&fork),
                &fork_proof,
            ));
        }
    }

    #[test]
    fn consistency_requires_retained_head_valid_sizes_and_empty_equal_proof() {
        let hashes = leaves(8);
        let retained_root = independent_root(&hashes);
        let empty_root = independent_root(&[]);
        assert!(verify_consistency(8, 8, retained_root, retained_root, &[]));
        assert!(!verify_consistency(
            8,
            8,
            retained_root,
            retained_root,
            &[retained_root]
        ));
        assert!(!verify_consistency(8, 8, retained_root, [0; 32], &[]));
        assert!(!verify_consistency(8, 7, retained_root, retained_root, &[]));
        assert!(!verify_consistency(0, 0, empty_root, empty_root, &[]));
        assert!(!verify_consistency(0, 8, empty_root, retained_root, &[]));
        assert!(!verify_consistency(1, 0, hashes[0], empty_root, &[]));
        assert!(!verify_consistency(
            usize::MAX,
            1,
            retained_root,
            retained_root,
            &[]
        ));
    }
}
