// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Refusal;

named_codes! {
    CANON_SITE_BUNDLE_INVALID => ("canon", "site-bundle-invalid", "The site bundle violates its versioned canonical schema."),
    CANON_SITE_BUNDLE_LIMIT => ("canon", "site-bundle-limit", "The site bundle exceeds its byte or file-count bound."),
    CANON_SITE_HOST_INVALID => ("canon", "site-host-invalid", "The site host is not a lowercase DNS name with a nonnumeric final label."),
    CANON_SITE_PATH_INVALID => ("canon", "site-path-invalid", "The site asset path is unsafe, duplicated or outside the closed suffix set."),
    CANON_SITE_MEDIA_INVALID => ("canon", "site-media-invalid", "The site media type does not match its closed suffix mapping."),
    CANON_SITE_ENCODING_INVALID => ("canon", "site-encoding-invalid", "The site asset bytes do not use canonical padded base64."),
    CANON_AUTHORIZATION_STATE_UNAVAILABLE => ("canon", "authorization-state-unavailable", "The authority transaction cannot establish live authorization state."),
    CANON_STANDING_REVOCATION_UNAVAILABLE => ("canon", "standing-revocation-unavailable", "The authority transaction has no standing-permission revocation adapter."),
    CANON_INVALID_UTF8 => ("canon", "invalid-utf8", "Input is not valid UTF-8."),
    CANON_BOM => ("canon", "bom", "Input starts with a forbidden byte-order mark."),
    CANON_INVALID_JSON => ("canon", "invalid-json", "Input violates the JSON grammar."),
    CANON_DUPLICATE_KEY => ("canon", "duplicate-key", "An object repeats a decoded key."),
    CANON_INVALID_NUMBER => ("canon", "invalid-number", "Number spelling is not a canonical integer."),
    CANON_INTEGER_RANGE => ("canon", "integer-range", "Integer exceeds the C1 safe range."),
    CANON_LONE_SURROGATE => ("canon", "lone-surrogate", "Text contains an unpaired surrogate."),
    CANON_NESTING_TOO_DEEP => ("canon", "nesting-too-deep", "More than 64 containers are nested."),
    CANON_TRAILING_BYTES => ("canon", "trailing-bytes", "Material follows the one JSON value."),
    CANON_SIGNATURE_COMPONENTS => ("canon", "signature-components", "A signature list is empty or exceeds six components."),
    CANON_COMMITTED_AUTHORITY_STATE_UNAVAILABLE => ("canon", "committed-authority-state-unavailable", "The adapter cannot read verified committed owner-consumed organ state."),
    CANON_OBSERVATION_CONTEXT_UNAVAILABLE => ("canon", "observation-context-unavailable", "The adapter cannot provide locked nonauthorizing fact append coordinates."),
    CANON_OBSERVATION_STATE_UNAVAILABLE => ("canon", "observation-state-unavailable", "The adapter cannot read verified committed observation state."),
    CANON_OBSERVATION_COMMIT_UNAVAILABLE => ("canon", "observation-commit-unavailable", "The adapter cannot atomically commit a transaction containing only observations."),
}

organ_codes! {
    pub(super) SUPPLEMENTAL_CODES => {
        "canon" => [
            "authority-state-unavailable", "epoch-transition-unavailable", "immune-history-unavailable",
        ],
    },
}
