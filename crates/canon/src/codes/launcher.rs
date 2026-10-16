// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Refusal;

named_codes! {
    LAUNCHER_GUEST_PROVISIONING_UNAVAILABLE => ("launcher", "guest-provisioning-unavailable", "Trusted guest cage provisioning and attack-driver resources are unavailable."),
    LAUNCHER_BOOT_ATTACK_REQUIRED => ("launcher", "boot-attack-required", "The boot recorder has no before-agent-start attack implementation."),
    LAUNCHER_BOOT_KERNEL => ("launcher", "boot-kernel", "The kernel observation is unavailable or invalid."),
    LAUNCHER_BOOT_LANDLOCK => ("launcher", "boot-landlock", "The host Landlock ABI query failed or returned an invalid value."),
    LAUNCHER_BOOT_NUMBER_RANGE => ("launcher", "boot-number-range", "A boot fact exceeds the canonical integer range."),
    LAUNCHER_BOOT_RECEIPT => ("launcher", "boot-receipt", "The boot append returned an invalid receipt."),
    LAUNCHER_PROBE_BUDGET => ("launcher", "probe-budget", "The attack probe wall duration is zero, exceeds 60 seconds or overflows its deadline."),
    LAUNCHER_PROBE_FIXTURE => ("launcher", "probe-fixture", "The attack probe fixture is invalid."),
    LAUNCHER_PROBE_FORK => ("launcher", "probe-fork", "The attack probe process could not be created."),
    LAUNCHER_PROBE_OUTPUT_LIMIT => ("launcher", "probe-output-limit", "The attack probe output exceeds its bound."),
    LAUNCHER_PROBE_PIPE => ("launcher", "probe-pipe", "The attack probe reporting pipe failed."),
    LAUNCHER_PROBE_REPORT => ("launcher", "probe-report", "The attack probe report is incomplete or invalid."),
    LAUNCHER_PROBE_WAIT => ("launcher", "probe-wait", "The attack probe process could not be reaped."),
}

organ_codes! {
    pub LAUNCHER_CODES => {
        "launcher" => [
            "architecture", "arguments", "boot-record", "capabilities", "cgroup-child", "cgroup-controller", "cgroup-duplicate",
            "cgroup-membership", "cgroup-not-empty", "cgroup-not-v2-leaf", "cgroup-open", "cgroup-read", "cgroup-readback", "cgroup-stat",
            "cgroup-write", "channels", "child-context-required", "child-pid", "child-status", "commands", "deadline", "descriptors",
            "disposable-disabled", "disposable-request", "fork", "identity", "identity-groups", "identity-open", "identity-readback",
            "identity-write", "image-address", "image-alignment", "image-arguments", "image-digest", "image-dynamic", "image-elf",
            "image-entry", "image-finalized", "image-headers", "image-map", "image-maps", "image-maps-bound", "image-overlap",
            "image-page-size", "image-protection", "image-random", "image-range", "image-read", "image-register-state", "image-relocation",
            "image-seals", "image-segment", "image-size", "image-stat", "image-trampoline", "kernel", "landlock-abi", "landlock-incomplete",
            "landlock-restrict", "landlock-rule", "landlock-ruleset", "limits", "mounts", "namespace-observation", "namespace-open",
            "namespace-read", "namespace-readback", "namespace-stat", "namespaces", "network", "network-observation", "parent-death",
            "parent-exited", "personality", "pidfd", "pidfd-observation", "policy", "policy-mismatch", "profile", "rlimits",
            "rlimits-readback", "seccomp-architecture", "seccomp-compile", "seccomp-filter", "seccomp-install", "seccomp-observation",
            "setup-memory", "setup-timeout", "setup-watchdog", "signal-mask", "stdio", "thread-clear-tid", "thread-robust-list", "thread-rseq",
            "thread-rseq-runtime", "unsupported-architecture", "unsupported-platform", "wait", "work-directory", "work-directory-bound",
            "work-directory-changed", "work-directory-clone", "work-directory-entry", "work-directory-mount", "work-directory-owner",
            "work-directory-private", "work-directory-read", "work-directory-stat", "work-directory-type",
        ],
    },
}
