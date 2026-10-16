// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Refusal;

organ_codes! {
    pub(super) SUPPLEMENTAL_CODES => {
        "caddy" => [
            "file-invalid", "file-symlink", "file-unreadable", "invalid-host", "invalid-upstream", "locked", "markers-invalid",
            "reload-failed", "rollback-failed", "rollback-failed-earlier", "same-host", "validate-failed",
        ],
    },
}
