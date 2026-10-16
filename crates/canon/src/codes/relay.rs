// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Refusal;

organ_codes! {
    pub(super) SUPPLEMENTAL_CODES => {
        "relay" => [
            "auth-invalid", "auth-rejected", "auth-required", "batch-limit", "clock-already-set", "clock-regressed", "clock-unavailable",
            "connect", "connection-closed", "cursor-unsupported", "egress-address", "egress-duplicate", "egress-observer-already-set",
            "egress-peer", "egress-policy", "egress-port", "egress-stale", "egress-unavailable", "egress-unlisted", "egress-version",
            "event-invalid", "filters-invalid", "handshake", "message-invalid", "message-kind", "message-too-large", "operation-timeout",
            "query-byte-limit", "query-event-limit", "query-incomplete", "relay-set", "subscription-closed", "subscription-limit",
            "tls-config", "tls-name", "tls-required", "tls-roots-already-set", "tls-roots-empty", "tls-roots-unavailable", "transport",
            "url-fragment", "url-invalid", "url-scheme", "url-too-long", "url-userinfo", "witness-binding", "witness-head",
            "witness-incomplete", "witness-malformed",
        ],
    },
}
