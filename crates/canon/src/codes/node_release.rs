// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Refusal;

organ_codes! {
    pub(super) SUPPLEMENTAL_CODES => {
        "node-release" => [
            "active-invalid", "arguments", "claim-delivered", "command-failed", "duplicate-key", "epoch-stale", "file-invalid",
            "file-unreadable", "hosts-markers", "invalid-json", "io", "node-config", "not-installed", "not-staged", "not-utf8",
            "pointer-replayed", "root-required", "too-large", "usage",
        ],
    },
}
