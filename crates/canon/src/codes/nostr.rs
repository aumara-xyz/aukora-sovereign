// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Refusal;

named_codes! {
    NOSTR_BINDING_INVALID => ("nostr", "binding-invalid", "The binding version or distinct role keys are invalid."),
    NOSTR_BINDING_AUTHORITY => ("nostr", "binding-authority", "The binding authority coordinates, append clock or approval expiry are invalid."),
    NOSTR_BINDING_TRANSACTION => ("nostr", "binding-transaction", "The binding proof belongs to a different authority transaction."),
    NOSTR_BINDING_AUTHORIZATION => ("nostr", "binding-authorization", "The binding does not match the exact C5 permission authorization."),
    NOSTR_BINDING_OWNER => ("nostr", "binding-owner", "The current owner binding does not match the verified passkey proof."),
    NOSTR_NPUB_INVALID => ("nostr", "npub-invalid", "The address is not canonical NIP-19 for a valid x-only public key."),
}

organ_codes! {
    pub(super) SUPPLEMENTAL_CODES => {
        "nostr" => [
            "antibody-bounds", "antibody-case", "antibody-case-id", "antibody-content", "antibody-duplicate-case", "antibody-engine",
            "antibody-input", "antibody-kind", "antibody-refusal", "antibody-tags", "antibody-version", "base64-invalid", "catalog-algorithm",
            "catalog-bounds", "catalog-content", "catalog-digest", "catalog-encoding", "catalog-fields", "catalog-kind", "catalog-manifest",
            "catalog-manifest-author", "catalog-manifest-bounds", "catalog-manifest-encoding", "catalog-manifest-entry",
            "catalog-manifest-face", "catalog-manifest-grants", "catalog-manifest-id", "catalog-manifest-name", "catalog-manifest-package",
            "catalog-manifest-runtime", "catalog-manifest-signature", "catalog-manifest-version", "catalog-query", "catalog-rating-target",
            "catalog-rating-value", "catalog-tags", "catalog-version", "delegated-key-mismatch", "envelope-id", "envelope-kind",
            "envelope-recipient", "envelope-size", "ephemeral-key-collision", "event-control-character", "event-hex-invalid",
            "event-id-mismatch", "event-malformed", "event-signature-invalid", "event-too-large", "key-invalid", "mac-invalid",
            "padding-invalid", "payload-length", "plaintext-length", "plaintext-not-utf8", "public-key-invalid", "random-unavailable",
            "recipient-mismatch", "rumor-id-mismatch", "rumor-kind-invalid", "rumor-time-invalid", "seal-kind-invalid", "seal-tags-invalid",
            "seal-time-invalid", "secret-invalid", "sender-mismatch", "sign-failed", "signature-invalid", "transport-unavailable",
            "transport-unknown", "transport-version", "unsupported-version", "wrap-kind-invalid", "wrap-not-for-us", "wrap-time-invalid",
        ],
    },
}
