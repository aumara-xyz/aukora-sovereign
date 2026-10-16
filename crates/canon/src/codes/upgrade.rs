// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Refusal;

organ_codes! {
    pub(super) SUPPLEMENTAL_CODES => {
        "upgrade" => [
            "backend", "build-failed", "command-failed", "command-missing", "command-timeout", "duplicate-key", "file-invalid",
            "file-unreadable", "invalid-json", "io", "nebius-settings", "node-not-running", "not-utf8", "openssl-missing", "pointer",
            "pointer-assertion", "pointer-authenticator", "pointer-client-data", "pointer-key", "pointer-not-canonical", "pointer-signature",
            "release-mismatch", "reproduce-missing", "rolled-back", "state-invalid", "switch-failed", "too-large", "unknown-node", "usage",
        ],
    },
}
