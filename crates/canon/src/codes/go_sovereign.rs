// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Refusal;

organ_codes! {
    pub(super) SUPPLEMENTAL_CODES => {
        "go-sovereign" => [
            "allocation-unavailable", "body-invalid", "body-timeout", "body-too-large", "cancelled", "claim-mismatch", "clock-invalid",
            "configuration-invalid", "handoff-invalid", "invite-invalid", "origin-refused", "page-context", "readback-mismatch",
            "request-invalid", "response-invalid", "shell-invalid", "token-invalid", "unknown-route",
        ],
    },
}
