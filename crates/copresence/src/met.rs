// SPDX-License-Identifier: AGPL-3.0-or-later
//! Row 137: contact labels carry evidence, never approval or permissions.

use crate::{v0, v1, v2, Result};
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
    receipt: &v2::VerifiedReceipt,
    exchange: &v1::Exchange,
    source: CaptureSource,
) -> Result<PairingEvidence> {
    let core = &receipt.body().exchange_receipt.core;
    if exchange.verified_core() != Some((v1::core_digest(core)?, core.t_b_seconds)) {
        return Err(crate::Refusal {
            organ: "copresence",
            reason: "core-mismatch",
        });
    }
    let method = receipt.body().context.exchange.method;
    let label = match source {
        CaptureSource::RemoteChannel => PairingLabel::Remote,
        CaptureSource::RelayedChannel => PairingLabel::Relayed,
        CaptureSource::LocalScreenCamera | CaptureSource::ImportedReceipt => match method {
            v1::Method::Remote => PairingLabel::Remote,
            v1::Method::Relayed => PairingLabel::Relayed,
            v1::Method::ScreenToScreen if source == CaptureSource::LocalScreenCamera => {
                PairingLabel::MetInPerson
            }
            v1::Method::ScreenToScreen => PairingLabel::UnverifiedMethod,
        },
    };
    Ok(PairingEvidence {
        label,
        receipt: receipt.digest(),
        source,
    })
}

/// V0 does not sign its method; legacy receipts retain an unverified-method label.
pub fn from_legacy(receipt: &v0::VerifiedReceipt) -> Result<PairingEvidence> {
    Ok(PairingEvidence {
        label: PairingLabel::UnverifiedMethod,
        receipt: receipt.core(),
        source: CaptureSource::ImportedReceipt,
    })
}

/// The v1 core omits owner subjects, scopes and expiry; it cannot prove local pairing.
pub fn from_v1(receipt: &v1::VerifiedReceipt) -> Result<PairingEvidence> {
    Ok(PairingEvidence {
        label: PairingLabel::UnverifiedMethod,
        receipt: receipt.digest(),
        source: CaptureSource::ImportedReceipt,
    })
}
