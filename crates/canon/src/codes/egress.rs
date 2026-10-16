// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Refusal;

organ_codes! {
    pub(super) SUPPLEMENTAL_CODES => {
        "egress" => [
            "addresses", "command-failed", "command-missing", "command-timeout", "duplicate-key", "file-invalid", "file-unreadable",
            "invalid-json", "io", "loaded", "nft-failed", "no-public-address", "not-utf8", "policy", "provider", "relay", "relay-url",
            "root-required", "service-user", "too-large", "unresolved", "usage",
        ],
    },
}
