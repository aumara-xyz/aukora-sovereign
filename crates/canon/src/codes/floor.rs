// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Refusal;

named_codes! {
    FLOOR_ABSENT => ("floor", "absent", "No retained release floor is available."),
    FLOOR_EQUAL_CONFLICT => ("floor", "equal-conflict", "Equal ordering coordinates identify different release evidence."),
    FLOOR_INSTALL_INCOMPLETE => ("floor", "install-incomplete", "The approved release orders after the installed release."),
    FLOOR_MALFORMED => ("floor", "malformed", "The retained floor violates its exact seven-key schema."),
    FLOOR_MIGRATION_REQUIRED => ("floor", "migration-required", "The retained floor uses a format requiring explicit migration."),
    FLOOR_NOT_NEWER => ("floor", "not-newer", "The candidate does not advance the retained epoch and sequence ordering."),
    FLOOR_ORDERING_EVIDENCE => ("floor", "ordering-evidence", "Release ordering evidence has invalid coordinates or digest fields."),
    FLOOR_RELEASE_BELOW_FLOOR => ("floor", "release-below-floor", "The installed release orders before the retained floor."),
    FLOOR_SIGNER_EPOCH_MISMATCH => ("floor", "signer-epoch-mismatch", "One signer epoch names different signer keys."),
}

organ_codes! {
    pub(super) SUPPLEMENTAL_CODES => {
        "floor" => [
            "algorithm-unsupported", "already-exists", "approval-spent", "approval-unspent", "counter-replayed", "credential-not-pinned",
            "credential-rollback", "directory-identity", "high-water-full", "high-water-malformed", "high-water-predecessor",
            "high-water-rollback", "install-floor-exists", "install-state-malformed", "interrupted-write", "io", "ledger-state-mismatch",
            "lock-absent", "lock-identity", "locked", "path", "proof-transaction", "protected-file", "protection", "read-conflict",
            "receipt-mismatch", "recovery-ledger-mismatch", "recovery-ledger-required", "release-binding", "release-record", "reserved-path",
            "size", "stage-conflict", "stage-malformed", "state-malformed", "state-not-canonical", "uncommitted-stage", "write-conflict",
        ],
    },
}
