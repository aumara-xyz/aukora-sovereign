// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Refusal;

organ_codes! {
    pub(super) SUPPLEMENTAL_CODES => {
        "owner" => [
            "configuration-invalid", "configuration-unavailable", "dispose-failed", "frame-required", "invalid-message", "invalid-origin",
            "invalid-phase", "invalid-shell-origin", "pane-unavailable", "request-refused", "request-unconfirmed", "response-invalid",
            "startup-refused", "unknown-operation", "unknown-route",
        ],
    },
}
