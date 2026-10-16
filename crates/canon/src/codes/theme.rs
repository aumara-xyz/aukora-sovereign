// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Refusal;

organ_codes! {
    pub(super) SUPPLEMENTAL_CODES => {
        "theme" => [
            "accent-invalid", "accepted-invalid", "budget-exceeded", "cancelled", "cell-digest-mismatch", "cell-effect-mismatch",
            "cell-invalid", "digest-invalid", "digest-unavailable", "disposed", "effect-invalid", "note-invalid", "read-cancelled",
            "read-deadline", "read-digest-mismatch", "read-invalid", "read-unavailable", "reader-unavailable", "root-in-use",
            "target-mismatch", "unchanged",
        ],
    },
}
