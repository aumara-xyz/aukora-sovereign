// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Refusal;

organ_codes! {
    pub(super) SUPPLEMENTAL_CODES => {
        "spawn" => [
            "allocation-unknown", "backend", "claimed-node", "container-missing", "container-not-ready", "cpu-preset", "device-conflict",
            "duplicate-key", "estimate-required", "file-invalid", "file-unreadable", "identity-mismatch", "image-invalid", "install-unknown",
            "invalid-host", "invalid-json", "inventory-invalid", "io", "locked", "nebius-settings", "node-exists", "not-admitted", "not-utf8",
            "package-download", "package-plan", "package-platform", "package-platform-mismatch", "package-query", "package-removal",
            "public-ip", "release-dir", "root-required", "spend-required", "ssh-public-key", "state-invalid", "state-path",
            "state-permissions", "too-large", "unknown-node", "usage", "vm-not-ready",
        ],
    },
}
