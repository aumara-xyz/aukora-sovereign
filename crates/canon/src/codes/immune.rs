// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Refusal;

organ_codes! {
    pub(super) SUPPLEMENTAL_CODES => {
        "immune" => [
            "already-quarantined", "antibody-format", "antibody-retired", "attack-budget", "attack-corpus-count", "attack-corpus-duplicate",
            "attack-corpus-schema", "cage-attack-failed", "cage-attack-incomplete", "corpus-empty", "corpus-limit", "duplicate-antibody",
            "duplicate-id", "fingerprint-corpus-count", "fingerprint-corpus-schema", "health-snapshot-mismatch", "heldout-count",
            "heldout-history", "heldout-id", "heldout-reused", "herd-case-collision", "herd-case-id", "herd-case-limit", "herd-case-schema",
            "herd-duplicate-case", "herd-engine", "herd-floor", "herd-import-limit", "herd-input", "herd-limit", "herd-not-canonical",
            "herd-refusal", "herd-replay-budget", "herd-verdict-conflict", "historical-corpus-pin", "historical-corpus-schema",
            "hypermutation-budget", "hypermutation-cleanup", "hypermutation-finding", "hypermutation-incomplete", "hypermutation-input",
            "hypermutation-isolation", "hypermutation-record-unverified", "hypermutation-usage", "issue-corpus-count", "issue-corpus-encoding",
            "issue-corpus-encoding-size", "issue-corpus-order", "issue-corpus-schema", "issue-corpus-size", "mhc-budget", "mhc-clock-range",
            "mhc-evidence-limit", "mhc-not-due", "mhc-target-limit", "not-quarantined", "organ-map-geometry", "posture-body",
            "posture-clock-range", "posture-guest-stopped", "posture-not-due", "quarantine-authorization", "quarantine-backend-unavailable",
            "quarantine-concern", "quarantine-not-committed", "quarantine-resource", "quarantine-state", "ratchet-floor", "registry-count",
            "registry-format", "registry-history", "registry-history-order", "registry-history-schema", "registry-history-wrapper",
            "registry-limit", "registry-pin", "registry-stale", "release-fact-context", "release-facts", "replay-budget-unavailable",
            "replay-usage-regressed", "retirement-authorization", "retirement-commit-mismatch", "retirement-disposition", "shadow-binding",
            "shadow-incomplete", "shadow-input", "shadow-live-changed", "shadow-read", "shadow-refused", "shadow-stale-source",
            "shadow-undetermined", "unknown-antibody", "vector-limit", "vector-not-canonical", "vector-schema",
        ],
    },
}
