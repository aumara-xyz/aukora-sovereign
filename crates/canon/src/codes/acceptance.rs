// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Refusal;

organ_codes! {
    pub(super) SUPPLEMENTAL_CODES => {
        "acceptance" => [
            "arguments", "cookie-budget", "cookie-invalid", "duplicate-human-observation", "https-unavailable",
            "interactive-terminal-required", "json-invalid", "observation-missing", "origin-invalid", "origin-required", "origins-must-differ",
            "peer-origins-required", "prerequisite-unavailable", "relative-file-required", "release-required", "secret-cancelled", "step-id",
            "unknown-operation", "verifier-budget", "verifier-output", "verifier-unavailable",
        ],
    },
}
