// SPDX-License-Identifier: AGPL-3.0-or-later
//! Row 137: contact labels carry evidence, never approval or permissions.

use crate::{v0, v1, Result, UNIMPLEMENTED};
use canon::digest::Digest32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingLabel {
    MetInPerson,
    Remote,
    Relayed,
    UnverifiedMethod,
}

impl PairingLabel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MetInPerson => "met-in-person",
            Self::Remote => "remote",
            Self::Relayed => "relayed",
            Self::UnverifiedMethod => "unverified-method",
        }
    }
}

/// Capture source comes from local channel wiring, never peer-provided labels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureSource {
    LocalScreenCamera,
    RemoteChannel,
    RelayedChannel,
    ImportedReceipt,
}

/// Private construction prevents a raw peer label being treated as this output.
/// This type has no conversion to a gate, passkey or contact approval proof.
#[derive(Clone, Debug)]
pub struct PairingEvidence {
    label: PairingLabel,
    receipt: Digest32,
    source: CaptureSource,
}

impl PairingEvidence {
    pub const fn label(&self) -> PairingLabel {
        self.label
    }

    pub const fn receipt(&self) -> Digest32 {
        self.receipt
    }

    pub const fn source(&self) -> CaptureSource {
        self.source
    }
}

/// A local screen capture and signed screen method are both required by the
/// new contract. Remote, relayed and imported captures cannot claim local met.
pub fn from_hardened(
    _receipt: &v1::VerifiedReceipt,
    _source: CaptureSource,
) -> Result<PairingEvidence> {
    Err(UNIMPLEMENTED)
}

/// V0 does not sign its method; legacy receipts retain an unverified-method label.
pub fn from_legacy(_receipt: &v0::VerifiedReceipt) -> Result<PairingEvidence> {
    Err(UNIMPLEMENTED)
}
