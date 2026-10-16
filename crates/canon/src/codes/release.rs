// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Refusal;

organ_codes! {
    pub(super) SUPPLEMENTAL_CODES => {
        "release" => [
            "archive", "archive-member", "archive-path", "digest", "duplicate-key", "exists-different", "file-invalid", "file-missing",
            "file-unreadable", "files-missing", "invalid-json", "manifest", "not-utf8", "too-large",
        ],
    },
}
