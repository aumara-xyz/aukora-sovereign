// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Refusal;

organ_codes! {
    pub(super) SUPPLEMENTAL_CODES => {
        "inventory" => [
            "budget", "duplicate-id", "duplicate-key", "empty-inventory", "encoding", "git", "git-timeout", "git-tree", "hidden-markup",
            "history", "json", "missing-source", "old-tech-seed", "owner-record", "owner-record-author", "owner-record-commit",
            "owner-record-count", "owner-record-date", "owner-record-duplicate", "owner-record-id", "owner-record-issue",
            "owner-record-missing", "owner-record-quote", "owner-record-revision", "owner-record-schema", "packet-count", "partial-clone",
            "path", "policy", "policy-drift", "regular-file", "release-ref", "repository", "revision", "row-id", "schema", "table", "usage",
            "worktree-changed",
        ],
    },
}
