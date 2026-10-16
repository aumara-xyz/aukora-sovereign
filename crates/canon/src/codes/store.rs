// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Refusal;

organ_codes! {
    pub(super) SUPPLEMENTAL_CODES => {
        "store" => [
            "app-opening", "app-start-deadline", "app-start-failed", "author-mismatch", "cage-mismatch", "catalog-limit", "catalog-mismatch",
            "cleanup-failed", "digest-unavailable", "disposed", "duplicate-app", "duplicate-publication", "duplicate-rating",
            "forbidden-grant", "install-mismatch", "install-pending", "installed-limit", "installed-mismatch", "invalid-base64",
            "invalid-bytes", "invalid-catalog", "invalid-digest", "invalid-entry", "invalid-face", "invalid-face-url", "invalid-fields",
            "invalid-grants", "invalid-installed", "invalid-query", "invalid-rating", "invalid-receipt", "invalid-runtime",
            "invalid-store-entry", "invalid-text", "invalid-utf8", "invalid-version", "manifest-version", "noncanonical-data", "not-installed",
            "open-mismatch", "package-limit", "package-mismatch", "proposal-mismatch", "rating-limit", "runtime-policy", "runtime-unavailable",
            "shell-required", "signature-algorithm", "unavailable", "unknown-operation", "unknown-publication",
        ],
    },
}
