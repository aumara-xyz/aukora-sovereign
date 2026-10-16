// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Refusal;

organ_codes! {
    pub(super) SUPPLEMENTAL_CODES => {
        "coherence" => [
            "canvas-unavailable", "digest-length", "disposed", "expansion", "head-invalid", "head-length", "health-allocation",
            "health-compile", "health-decode", "health-decoder-unavailable", "health-descriptor", "health-exports", "health-imports",
            "health-refused", "health-release", "health-unavailable", "pentora-abi", "pentora-allocation", "pentora-bounds", "pentora-compile",
            "pentora-descriptor", "pentora-expand", "pentora-exports", "pentora-imports", "pentora-mismatch", "pentora-pointer",
            "pentora-refusal", "pentora-refused", "pentora-release", "pentora-result", "pentora-trits", "pentora-unavailable", "repair-index",
            "snapshot-bounds", "snapshot-cells", "snapshot-context", "snapshot-encoding", "snapshot-format", "sources-invalid",
        ],
    },
}
