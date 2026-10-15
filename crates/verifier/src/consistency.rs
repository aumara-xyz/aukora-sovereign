// SPDX-License-Identifier: AGPL-3.0-or-later
//! Reserved verification of C3 retained/presented observations from exact bytes.

use canon::Result;

/// Neither observation is fetched from the node or an external service.
#[derive(Clone, Copy, Debug)]
pub struct ConsistencyInputs<'a> {
    /// The caller's independently retained C3 observation.
    pub retained: &'a [u8],
    /// An untrusted C3 presented observation and RFC 6962 proof.
    pub presented: &'a [u8],
}

/// Consistency alone makes no claim about identity, occurrence or owner permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsistencyVerdict {
    /// The proof connects both supplied roots under the declared leaf convention.
    AppendOnly,
    /// A connected proof reconstructs a conflicting retained root.
    ObservationConflict,
    /// No positive consistency conclusion, including an underivable prefix.
    Undetermined,
}

/// The fields are readable but the verifier alone constructs a result.
#[derive(Clone, Copy, Debug)]
pub struct ConsistencyReport {
    verdict: ConsistencyVerdict,
    retained_size: u64,
    presented_size: u64,
}

impl ConsistencyReport {
    /// Returns the consistency finding without converting Undetermined to success.
    pub const fn verdict(self) -> ConsistencyVerdict {
        self.verdict
    }

    /// The earlier and later tree sizes used by the consistency check.
    pub const fn sizes(self) -> (u64, u64) {
        (self.retained_size, self.presented_size)
    }
}

/// The body is reserved for wave 1 and always refuses in this contract wave.
pub fn verify(_inputs: ConsistencyInputs<'_>) -> Result<ConsistencyReport> {
    Err(crate::UNIMPLEMENTED)
}
