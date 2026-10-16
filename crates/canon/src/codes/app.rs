// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Refusal;

organ_codes! {
    pub(super) SUPPLEMENTAL_CODES => {
        "app" => [
            "aborted", "already-mounted", "asset-collision", "asset-directory", "asset-link", "asset-path", "attribute-refused",
            "backpressure", "build-arguments", "busy", "capability-denied", "catalog-format", "catalog-mismatch", "cleanup-failed",
            "consumer-failed", "data-limit", "deadline", "design-captures", "design-captures-incomplete", "design-copy", "design-digest",
            "design-fonts", "design-icons", "design-lock", "design-tokens", "design-unpinned", "disconnected", "disposed", "duplicate-plugin",
            "duplicate-service", "dynamic-import", "entry-missing", "id-exhausted", "invalid-capability", "invalid-data", "invalid-effect",
            "invalid-menu", "invalid-message", "invalid-name", "invalid-observer", "invalid-plugin", "invalid-reply", "invalid-sandbox",
            "invalid-service", "invalid-shell", "invalid-surface", "lock-format", "lock-mismatch", "manifest-format", "manifest-missing",
            "module-missing", "module-specifier", "reconnected", "release-directory", "service-failed", "service-unavailable",
            "session-too-long", "setup-failed", "shell-required", "surface-missing", "syntax", "unknown-face", "unknown-operation",
            "wasm-exports", "wasm-imports", "wasm-in-source", "wasm-missing", "wasm-size",
        ],
    },
}
