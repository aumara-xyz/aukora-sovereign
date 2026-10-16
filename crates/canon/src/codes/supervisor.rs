// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Refusal;

named_codes! {
    SUPERVISOR_GATE_TARGETS_VERSION => ("supervisor", "gate-targets-version", "The configured gate target manifest has an unsupported version."),
    SUPERVISOR_GATE_TARGETS_NODE => ("supervisor", "gate-targets-node", "The configured gate target manifest names another node."),
    SUPERVISOR_GATE_TARGETS_LIMIT => ("supervisor", "gate-targets-limit", "The configured gate target manifest exceeds its target limit."),
    SUPERVISOR_GATE_TARGETS_NAME => ("supervisor", "gate-targets-name", "A configured gate target name is invalid or repeated."),
    SUPERVISOR_GATE_TARGETS_CLASS => ("supervisor", "gate-targets-class", "The configured target class is unsupported."),
    SUPERVISOR_GATE_TARGETS_RISK => ("supervisor", "gate-targets-risk", "The configured target risk is unsupported."),
    SUPERVISOR_GATE_TARGETS_SIZE => ("supervisor", "gate-targets-size", "The configured target byte limit is invalid."),
    SUPERVISOR_GATE_SCOPE_UNAVAILABLE => ("supervisor", "gate-scope-unavailable", "The gate cannot enforce the host principal scope in its authority transaction."),
    SUPERVISOR_PUBLIC_COUNTERS_UNAVAILABLE => ("supervisor", "public-counters-unavailable", "Owning-organ public counter projections are unavailable."),
    SUPERVISOR_READ_RATE_LIMITED => ("supervisor", "read-rate-limited", "The bounded supervisor read allowance is exhausted."),
    SUPERVISOR_STATE => ("supervisor", "state", "Supervisor state is unavailable or inconsistent."),
    SUPERVISOR_NOT_READY => ("supervisor", "not-ready", "The responsible organ is not available."),
}

organ_codes! {
    pub(super) SUPPLEMENTAL_CODES => {
        "supervisor" => [
            "already-running", "approval-channels-full", "approval-limit", "approval-poll-not-due", "config-address", "config-canonical",
            "config-id", "config-ip", "config-json", "config-listen", "config-node", "config-origin", "config-path", "config-permissions",
            "config-proxy", "config-shape", "config-size", "config-unreadable", "config-version", "contact-projection-unavailable",
            "egress-config", "egress-port", "egress-version", "exit-format", "exit-inconsistent", "exit-not-empty", "exit-not-permitted",
            "exit-revival", "face-counts-invalid", "face-message-invalid", "face-number-invalid", "face-operation-unknown",
            "face-page-invalid", "face-principal-mismatch", "face-read-deadline", "face-reply-too-large", "face-runtime-unavailable",
            "face-shape-invalid", "genesis-claim-spent", "genesis-owner-present", "genesis-session-lock", "genesis-session-state",
            "harness-presets-unavailable", "health-page-invalid", "health-snapshot-changed", "health-stale", "health-unavailable",
            "identity-format", "identity-missing", "identity-node", "identity-read", "listen", "manifest-changed", "memory-unavailable",
            "message-history-unavailable", "model-settings-unavailable", "network-store-unavailable", "network-unavailable",
            "pentora-asset-missing", "queue-full", "randomness", "release-directory", "release-file", "release-file-mismatch",
            "release-file-missing", "release-manifest", "release-not-approved", "release-not-verified", "release-path", "release-permissions",
            "release-read", "running-executable", "running-release-mismatch", "sessions-missing", "sessions-unavailable",
            "settings-release-invalid", "settings-reply-invalid", "settings-unavailable", "shell-plugin-state-unavailable", "signing-key",
            "state-directory", "state-file", "state-lock", "state-name", "state-permissions", "state-sync", "state-write",
            "stream-event-invalid", "stream-session-conflict", "stream-session-missing", "usage",
        ],
    },
}
