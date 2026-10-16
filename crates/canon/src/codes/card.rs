// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Refusal;

organ_codes! {
    pub(super) SUPPLEMENTAL_CODES => {
        "card" => [
            "assertion-empty", "authorization-base", "authorization-digest", "authorization-identity", "authorization-shape",
            "authorization-time-or-epoch", "cell", "depth", "display-mismatch", "facts", "integer", "json", "noncanonical",
            "operation-mismatch", "route", "says", "shape", "supervisor-response", "target", "unavailable", "unicode", "unknown-operation",
            "version-or-risk",
        ],
    },
}
