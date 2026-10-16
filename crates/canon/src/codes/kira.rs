// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Refusal;

named_codes! {
    KIRA_DISCLOSURE_NOT_PERMITTED => ("kira", "disclosure-not-permitted", "The current principal lacks hosted-context permission."),
    KIRA_NOTE_NOT_FOUND => ("kira", "note-not-found", "The note is absent for the current principal."),
    KIRA_NOTE_ID => ("kira", "note-id", "The opaque note handle violates its byte or text bounds."),
    KIRA_AUTHENTICATION_FAILED => ("kira", "authentication-failed", "Encrypted memory failed authenticated decryption."),
    KIRA_INVALID_FIELD => ("kira", "invalid-field", "A memory request field violates its required type or bound."),
    KIRA_LEDGER_UNVERIFIED => ("kira", "ledger-unverified", "The memory ledger has not passed verification."),
    KIRA_RANDOM_UNAVAILABLE => ("kira", "random-unavailable", "The operating system could not supply required random bytes."),
    KIRA_STORE_CORRUPT => ("kira", "store-corrupt", "Stored memory data violates its retained format or invariant."),
    KIRA_STORE_UNAVAILABLE => ("kira", "store-unavailable", "The memory store could not be opened or accessed."),
}

organ_codes! {
    pub(super) SUPPLEMENTAL_CODES => {
        "kira" => [
            "backup-acknowledgement", "backup-archive", "backup-chunks", "backup-destination", "backup-head", "backup-restore-target",
            "backup-rollback", "embedding-input", "embedding-model", "embedding-unavailable", "embedding-vector", "semantic-index-incomplete",
            "semantic-index-stale", "semantic-model", "semantic-response", "semantic-too-large", "semantic-unavailable",
        ],
    },
}
