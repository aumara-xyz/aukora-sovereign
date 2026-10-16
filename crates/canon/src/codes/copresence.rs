// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Refusal;

organ_codes! {
    pub COPRESENCE_CODES => {
        "copresence" => [
            "attempt-id", "attempt-sequence", "attempt-storage", "attempt-ticket", "bad_owner_signature", "bloom-expansion",
            "bloom-person-keys", "camera-decoder-unavailable", "cancelled", "canvas", "ceremony-window", "ceremony_window_exceeded",
            "channels-unavailable", "context", "context-expired", "context-mismatch", "context-owner", "context-scopes", "core-mismatch",
            "depth", "device-unavailable", "domain", "exchange-closed", "exchange-timeout", "expected-context-required", "face-mismatch",
            "field-missing", "field-type", "fields", "format-unpinned", "frame-budget", "frame-not-canonical", "frame-order", "frame-replay",
            "frame-schema", "frame-stale", "frame-type", "future-frame", "hex", "integer", "integer-range", "intent-ack",
            "intent-ack-required", "intent-mismatch", "intent-required", "intent_mismatch", "intent_not_committed", "invalid-input",
            "invalid_audio_delay", "invalid_audio_matched", "invalid_geo_coordinates", "invalid_public_key_A", "invalid_public_key_B",
            "json-limit", "json_parse_error", "key", "layers", "local-face-mismatch", "malformed_audio_nonce", "malformed_intent",
            "malformed_nonce_A", "malformed_nonce_B", "malformed_public_key_A", "malformed_public_key_B", "malformed_signature_A",
            "malformed_signature_B", "method", "method-mismatch", "missing_field", "motion-not-prepared", "motion-permission",
            "motion-required", "motion-unobserved", "negative-time-skew", "negative_time_skew", "no_intent", "no_owner_signature",
            "noncanonical", "nonce-commitment", "nonce-commitment-changed", "nonce-mismatch", "object", "optical-frame-size",
            "pairing-label-mismatch", "participant", "participant-counter", "participants", "peer-changed", "peer-mismatch", "public-key",
            "purpose-length", "receipt-not-canonical", "receipt-replay", "receipt-schema", "receipt-stale", "receipt_from_the_future",
            "refused", "reveal-changed", "same-participant", "same_key_on_both_sides", "sender", "side", "sig_A_invalid", "sig_B_invalid",
            "signature", "size", "sound-not-prepared", "sound-required", "sound-unmatched", "stale-frame", "stale_receipt", "state", "string",
            "suspicious_audio_delay_impossible", "suspicious_audio_nonce_mismatch", "suspicious_audio_relay_detected",
            "suspicious_spacetime_contradiction", "suspicious_spoofed_accuracy", "telemetry_coercion_error", "text",
            "timestamp_encoding_error", "timestamps_must_be_numbers", "transcript", "transcript-mismatch", "unexpected-bloom",
            "unexpected-handshake", "unexpected-intent", "unexpected-receipt", "unicode", "unimplemented", "unsupported_version", "window",
            "wrong_approver",
        ],
    },
}
