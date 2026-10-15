// SPDX-License-Identifier: AGPL-3.0-or-later
//! Independent evidence collection for immune; not a routing or admission input.

use crate::services::ServiceFuture;
use canon::{
    digest::Digest32,
    health::{HealthEvidence, OrganId},
    Result,
};

/// Context supplied by the supervisor from the actual observed node state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObservationContext {
    pub epoch: u64,
    pub sequence: u64,
    pub observed_at_ms: u64,
    pub commitment: Digest32,
}

/// Each observer reports its registered private checks and its independent corners.
/// Body adapters receive raw facts from their owning code; immune makes their cells.
pub trait OrganObserver: Send + Sync {
    fn organ(&self) -> OrganId;
    fn observe(&self, context: ObservationContext) -> ServiceFuture<'_, Vec<HealthEvidence>>;
}

/// Missing/unreachable observers are retained as absence, never invented verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObservationFailure {
    Missing(OrganId),
    Unreachable(OrganId),
    Refused(OrganId, canon::Refusal),
}

/// At most 130 reports; 90 private observations and two independent sides per corner.
/// The reducer interprets missing and unwritten checks; collection never approves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectedEvidence {
    pub context: ObservationContext,
    pub reports: Vec<HealthEvidence>,
    pub unavailable: Vec<ObservationFailure>,
}

/// Exact opaque bytes returned by immune for the coherence data endpoint.
/// This wrapper provides no authorization or fingerprint conversion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoherenceBytes(Vec<u8>);

impl CoherenceBytes {
    /// Row 128: retain only an immune-produced canonical snapshot within the FD 4 cap.
    /// The health reducer validates cells; the frontdoor only relays these bytes.
    pub fn from_immune(_bytes: Vec<u8>) -> Result<Self> {
        todo!("row 128")
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Immune is the only converter of raw Body facts and collected evidence into cells.
pub trait ImmuneService: Send + Sync {
    fn reduce(&self, evidence: CollectedEvidence) -> ServiceFuture<'_, CoherenceBytes>;
}

/// Row 128: call each of the five distinct trusted observers at most once per sample.
/// Validate reporter against the registered channel/owner, check duplicates and the
/// 130-report cap, and retain all failures for immune. No result feeds back to routing,
/// credentials, release admission, grant admission or an authority transaction.
pub async fn collect(
    _context: ObservationContext,
    _observers: &[&dyn OrganObserver],
) -> Result<CollectedEvidence> {
    todo!("row 128")
}
