// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Refusal;

organ_codes! {
    pub(super) SUPPLEMENTAL_CODES => {
        "witness" => [
            "aborted", "hash-unavailable", "head-invalid", "invalid-scope", "invalid-timeout", "retained-invalid", "store-unavailable",
        ],
    },
}
