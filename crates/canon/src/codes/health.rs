// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Refusal;

named_codes! {
    HEALTH_INVALID_CHECK => ("health", "invalid-check", "The check id is outside the frozen registry."),
    HEALTH_CHECK_INDEX => ("health", "check-index", "A private check index is outside 1..=18."),
    HEALTH_CORNER_INDEX => ("health", "corner-index", "A paired corner index is outside 1..=20."),
    HEALTH_INVALID_EVIDENCE => ("health", "invalid-evidence", "Evidence violates its owner, context or time bounds."),
}
