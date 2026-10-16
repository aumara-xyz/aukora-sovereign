// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Refusal;

organ_codes! {
    pub(super) SUPPLEMENTAL_CODES => {
        "invites" => [
            "admission-context", "admission-record", "algorithm-unsupported", "allowance-bounds", "allowance-conservation",
            "allowance-exhausted", "allowance-headroom", "allowance-overflow", "allowance-stale", "allowance-state-unavailable",
            "allowance-transfer", "allowance-version", "ancestry-bound", "ancestry-parent", "ancestry-root", "ancestry-unavailable",
            "body-invalid", "claim-binding", "claim-binding-required", "claim-configuration", "claim-context", "claim-owner-proof-required",
            "claim-refused", "claim-response", "claim-secret", "claim-shape", "commitment-invalid", "confirmation-shape",
            "confirmation-signer", "invite-bound", "invite-expired", "invite-future", "invite-not-expired", "invite-shape", "invite-time",
            "issuer-unknown", "joining-adapter", "joining-attempt", "joining-binding-mismatch", "joining-cancelled",
            "joining-checkpoint-mismatch", "joining-context", "joining-context-mismatch", "joining-context-size",
            "joining-evidence-unconfirmed", "joining-expired", "joining-fields", "joining-format-unpinned", "joining-intent-required",
            "joining-layers", "joining-observation", "joining-optical", "joining-optical-bytes", "joining-optical-exchange",
            "joining-optical-refused", "joining-optical-scan", "joining-optical-subscription", "joining-optical-verdict", "joining-origin",
            "joining-owner-frame", "joining-participants", "joining-receipt-changed", "joining-receipt-size", "joining-route",
            "joining-scopes", "joining-stage", "joining-unavailable", "legacy-shape", "member-exists", "member-state", "member-subject",
            "member-unknown", "network-root", "not-canonical", "owner-context", "redemption-context", "redemption-shape",
            "reservation-context", "reservation-receipt", "reservation-reused", "reservation-spent", "reservation-state",
            "reservation-unknown", "transaction-changed", "unknown-operation",
        ],
    },
}
