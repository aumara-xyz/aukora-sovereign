// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Refusal;

named_codes! {
    PENTORA_IDENTITY_INVALID => ("pentora", "identity-invalid", "A person public key must contain exactly 32 bytes."),
    PENTORA_IDENTITIES_EQUAL => ("pentora", "identities-equal", "A relationship requires two different person public keys."),
    PENTORA_COMMITMENT_EMPTY => ("pentora", "commitment-empty", "Legacy bloom v1 refuses an all-zero commitment."),
    PENTORA_PERSON_KEYS_REQUIRED => ("pentora", "person-keys-required", "A bare commitment cannot identify the two people in a relationship."),
    PENTORA_HEAD_INVALID => ("pentora", "head-invalid", "A fingerprint input must contain exactly 32 bytes."),
    PENTORA_CELL_INDEX => ("pentora", "cell-index", "A cell must be one of the 110 non-centre geometry cells."),
    PENTORA_TRITS_INVALID => ("pentora", "trits-invalid", "An expansion must contain 110 digits in the range zero through two."),
    PENTORA_PAIRING_EXPANSION_UNAVAILABLE => ("pentora", "pairing-expansion-unavailable", "The Rust person-key expansion adapter is unavailable."),
    PENTORA_PAIRING_EXPANSION_INVALID => ("pentora", "pairing-expansion-invalid", "The person-key expansion result has an invalid shape."),
    PENTORA_GEOMETRY_INVALID => ("pentora", "geometry-invalid", "The supplied geometry does not have the required cells and edges."),
    PENTORA_CANVAS_UNAVAILABLE => ("pentora", "canvas-unavailable", "The relationship canvas has no drawing context."),
    PENTORA_DISPOSED => ("pentora", "disposed", "A disposed bloom view cannot draw another relationship."),
}

organ_codes! {
    pub(super) SUPPLEMENTAL_CODES => {
        "pentora" => [
            "display-unavailable", "generation-exhausted", "geometry-pin", "pair-intersection", "source-absence", "source-entries",
            "source-order", "stale-observation", "time-invalid",
        ],
    },
}
