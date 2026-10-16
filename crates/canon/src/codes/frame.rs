// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Refusal;

named_codes! {
    FRAME_ZERO_LENGTH => ("frame", "zero-length", "Empty transport payload; close the stream."),
    FRAME_TOO_LARGE => ("frame", "too-large", "Payload exceeds 65,536 bytes; inbound length requires close."),
    FRAME_SHORT_READ => ("frame", "short-read", "Header or payload ended early; close the stream."),
    FRAME_IO => ("frame", "io", "Transport failed; close the stream."),
    FRAME_NOT_CANONICAL => ("frame", "not-canonical", "Reserialized payload differs from the input."),
    FRAME_NOT_OBJECT => ("frame", "not-object", "A required envelope, body or nested value is not a JSON object."),
    FRAME_UNKNOWN_FIELD => ("frame", "unknown-field", "An object has an unrecognized field."),
    FRAME_MISSING_FIELD => ("frame", "missing-field", "An object lacks a required field."),
    FRAME_INVALID_FIELD => ("frame", "invalid-field", "A field violates its type, encoding or bound."),
    FRAME_UNSUPPORTED_VERSION => ("frame", "unsupported-version", "The format version has no decoder."),
    FRAME_INVALID_ID => ("frame", "invalid-id", "Correlation id is not 1..=64 allowed ASCII bytes."),
    FRAME_UNKNOWN_KIND => ("frame", "unknown-kind", "Operation is unknown or invalid in this direction."),
    FRAME_PROVENANCE => ("frame", "provenance", "Untrusted source claim conflicts with trusted ingress."),
    FRAME_STREAM_ORDER => ("frame", "stream-order", "A stream repeats, skips or follows its terminal chunk."),
    FRAME_STREAM_LIMIT => ("frame", "stream-limit", "A stream exceeds its frozen bounds."),
}
