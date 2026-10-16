// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Refusal;

organ_codes! {
    pub(super) SUPPLEMENTAL_CODES => {
        "verifier" => [
            "array", "authorization-digest", "authorization-shape", "bad-digest", "bom", "bundle-format", "bundle-head", "bundle-key-mismatch",
            "bundle-row-schema", "bundle-rows", "bundle-tail-size", "cell-effect", "checkpoint-mismatch",
            "completeness-no-covering-checkpoint", "consistency-conflict", "consistency-prefix-mismatch", "consistency-proof",
            "crypto-unavailable", "depth", "duplicate-key", "empty-proof-for-different-sizes", "entry-hash", "expected-bytes", "gate-evidence",
            "gate-reference", "head-sequence", "head-size", "hex", "identity-no-pinned-key", "implementation-unavailable", "input-not-file",
            "input-not-regular", "input-too-large", "input-unreadable", "integer", "invalid-retained-prefix", "invalid-tree-sizes", "json",
            "json-bom", "json-depth", "json-duplicate-key", "json-integer", "json-integer-range", "json-not-canonical", "json-number",
            "json-surrogate", "json-value", "key", "key-encoding", "key-weak", "keys", "missing-field", "missing-prior-observation",
            "missing-retained-head", "no-rows", "non-empty-proof-for-same-size", "nostr-agent-signature", "nostr-aura-key",
            "nostr-binding-shape", "nostr-node-signature", "nostr-npub", "nostr-second-binding", "nostr-statement", "not-canonical",
            "observation-pair", "operation-digest", "operation-id", "owner-assertion-link", "owner-assertion-operation",
            "owner-assertions-coverage", "owner-assertions-unavailable", "owner-bindings-or-terminal-count", "owner-counter-replay",
            "owner-key", "owner-key-encoding", "owner-key-mismatch", "owner-no-pinned-key", "owner-proof", "owner-proof-context",
            "owner-proof-format", "owner-proof-invalid", "owner-proof-replay", "owner-provenance", "owner-signature", "owner-standing-format",
            "power-of-two-prefix-not-independently-derivable", "presented-format", "presented-head-mismatch", "presented-root",
            "presented-size", "prev-link", "proof-did-not-connect-to-presented-head", "proof-format", "proof-length", "proof-path-truncated",
            "restore-counts", "restore-demote-row", "restore-demotion", "restore-file-hash", "restore-file-layout", "restore-file-missing",
            "restore-file-size", "restore-forgotten", "restore-head", "restore-header", "restore-keys", "restore-manifest",
            "restore-memory-format", "restore-memory-truncated", "restore-note-citation", "restore-note-commitment", "restore-note-format",
            "restore-note-metadata", "restore-note-missing", "restore-note-unsaved", "restore-public-keys", "restore-save-row",
            "restore-signing-key", "restore-tip", "retained-format", "retained-prefix-differs", "retained-proof-size", "retained-row-mismatch",
            "row-columns", "row-schema", "rows-format", "rows-truncated", "same-size-root-mismatch", "sequence", "shorter-than-checkpoint",
            "signature", "standing-count", "standing-expired", "standing-owner", "standing-permission", "standing-reference",
            "standing-revoked", "standing-scope", "surrogate", "terminal-count", "text", "trailing", "tree-root-no-anchor",
            "unconsumed-proof-elements", "unimplemented", "unsupported-schema", "usage", "utf8", "witness-binding", "witness-fork",
            "witness-malformed", "witness-proof", "witness-signature", "witness-signer", "witness-size",
        ],
    },
}
