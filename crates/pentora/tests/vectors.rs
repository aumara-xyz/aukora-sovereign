// SPDX-License-Identifier: AGPL-3.0-or-later

use pentora::{
    balanced_cells, expand, pentora_cells, CENTRE_INDEX, CUBES, DIGEST_LEN, DOUBLE_CORNER_INDICES,
    EDGES, MUTABLE_INDICES, TRIT_COUNT,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

const VECTOR_FILES: [(&str, &[u8], &str); 2] = [
    (
        "expansion_vectors_1006.json",
        include_bytes!("../vectors/expansion_vectors_1006.json"),
        "02f5c5b9dee82b6eb36fbf02b430af50958165a6c07d7e652524183773e24529",
    ),
    (
        "expansion_vectors_4354.json",
        include_bytes!("../vectors/expansion_vectors_4354.json"),
        "930bfbb5d8088de1c8aa94b99cdbc868505c79acde504c26b813b714c846e044",
    ),
];

const GEOMETRY_FILE: (&str, &[u8], &str) = (
    "geometry_index_table_v1.json",
    include_bytes!("../vectors/geometry_index_table_v1.json"),
    "96b27c9b4de41cd961612be5b1e88d40e973a2fded16bd320415b3e15e3b8c61",
);

#[test]
fn copied_vectors_match_the_recorded_manifest() {
    let manifest = include_str!("../vectors/MANIFEST");
    for (name, bytes, expected_hash) in VECTOR_FILES.into_iter().chain([GEOMETRY_FILE]) {
        assert!(manifest
            .lines()
            .any(|line| { line == format!("{expected_hash}  {name}") }));
        assert_eq!(hex::encode(Sha256::digest(bytes)), expected_hash, "{name}");
    }
    assert_eq!(manifest.lines().count(), VECTOR_FILES.len() + 1);
}

#[test]
fn integer_geometry_matches_the_normative_index_table() {
    let geometry: Value = serde_json::from_slice(GEOMETRY_FILE.1).unwrap();
    assert_eq!(
        geometry["centre_index"].as_u64().unwrap() as usize,
        CENTRE_INDEX
    );
    assert_eq!(usize_values(&geometry["mutable_indices"]), MUTABLE_INDICES);
    assert_eq!(
        usize_values(&geometry["double_corner_indices"]),
        DOUBLE_CORNER_INDICES
    );

    let cubes = geometry["cubes"].as_array().unwrap();
    for (expected, cube) in CUBES.iter().zip(cubes) {
        let slots: Vec<usize> = cube["slots"]
            .as_array()
            .unwrap()
            .iter()
            .map(|slot| slot["global_index"].as_u64().unwrap() as usize)
            .collect();
        assert_eq!(slots, expected);
    }
    let normative_edges: Vec<[usize; 2]> = cubes
        .iter()
        .flat_map(|cube| cube["edges_global_indices"].as_array().unwrap())
        .map(|edge| {
            let indices = usize_values(edge);
            [indices[0], indices[1]]
        })
        .collect();
    let reversed: Vec<usize> = normative_edges
        .iter()
        .enumerate()
        .filter_map(|(index, edge)| (edge[0] > edge[1]).then_some(index))
        .collect();
    assert_eq!(
        reversed,
        [
            13, 15, 17, 18, 21, 22, 25, 27, 29, 30, 33, 35, 37, 39, 41, 43, 44, 46, 49, 51, 53, 55,
            56, 59
        ]
    );
    let prime_edges: Vec<[usize; 2]> = normative_edges
        .into_iter()
        .map(|[left, right]| [left.min(right), left.max(right)])
        .collect();
    assert_eq!(prime_edges, EDGES);
}

#[test]
fn all_5360_normative_expansions_match() {
    let mut checked = 0;
    for (name, bytes, _) in VECTOR_FILES {
        let vectors: Vec<Value> = serde_json::from_slice(bytes).unwrap();
        for (index, vector) in vectors.iter().enumerate() {
            let head = decode_hex_field(vector, "head", name, index);
            let expected_digest = decode_hex_field(vector, "sha256", name, index);
            let expected_trits = decode_hex_field(vector, "wire_hex", name, index);
            assert_eq!(head.len(), DIGEST_LEN, "{name} vector {index} head");
            assert_eq!(
                expected_digest.len(),
                DIGEST_LEN,
                "{name} vector {index} digest"
            );
            assert_eq!(
                expected_trits.len(),
                TRIT_COUNT,
                "{name} vector {index} trits"
            );
            assert!(
                expected_trits.iter().all(|&trit| trit <= 2),
                "{name} vector {index} wire trit"
            );

            let got = expand(&head).unwrap();
            assert_eq!(
                got.digest.as_slice(),
                expected_digest,
                "{name} vector {index} digest"
            );
            assert_eq!(
                got.trits.as_slice(),
                expected_trits,
                "{name} vector {index} trits"
            );
            assert_eq!(
                pentora_cells(&head).unwrap(),
                got.trits,
                "{name} vector {index} Prime cells"
            );

            if let Some(expected_balanced) = vector.get("balanced") {
                let expected: Vec<i8> = expected_balanced
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|value| value.as_i64().unwrap() as i8)
                    .collect();
                assert_eq!(
                    balanced_cells(&got.trits).unwrap().as_slice(),
                    expected,
                    "{name} vector {index} balanced cells"
                );
            }
            checked += 1;
        }
    }
    assert_eq!(checked, 5_360);
}

fn decode_hex_field(vector: &Value, field: &str, name: &str, index: usize) -> Vec<u8> {
    hex::decode(vector[field].as_str().unwrap())
        .unwrap_or_else(|error| panic!("{name} vector {index} {field}: {error}"))
}

fn usize_values(value: &Value) -> Vec<usize> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_u64().unwrap() as usize)
        .collect()
}
