// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Refusal;

organ_codes! {
    pub(super) SUPPLEMENTAL_CODES => {
        "install" => [
            "cgroup-v2", "command-failed", "duplicate-key", "file-invalid", "file-unreadable", "invalid-json", "io", "landlock-abi",
            "node-exists", "node-input", "not-utf8", "package-plan", "package-query", "package-stage", "packages-missing", "packages-offline",
            "root-required", "service-not-active", "stage", "subordinate-ids", "too-large", "usage", "userns-policy",
        ],
    },
}
