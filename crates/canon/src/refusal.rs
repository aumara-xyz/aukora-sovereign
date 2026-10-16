// SPDX-License-Identifier: AGPL-3.0-or-later
//! Refusals are data. Their wire code is always an organ and a reason.

use core::fmt;

/// A stable refusal code, rendered as `<organ>:<reason>` without extra text.
/// Components are nonempty ASCII tokens without colons. Wire decoders accept
/// only codes in the registry; a wire string never creates a new refusal code.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Refusal {
    /// The responsible organ or protocol component, such as `gate` or `frame`.
    pub organ: &'static str,
    /// The stable reason token within that component's namespace.
    pub reason: &'static str,
}

impl Refusal {
    /// Constructs a refusal only when its complete code is in the shared registry.
    pub fn from_code(code: &str) -> Result<Self> {
        crate::codes::parse(code)
    }

    /// Returns the organ or protocol component token.
    pub const fn organ(&self) -> &'static str {
        self.organ
    }

    /// Returns the stable reason token within the organ's namespace.
    pub const fn reason(&self) -> &'static str {
        self.reason
    }

    /// Forms an internal code from trusted registry tokens; this does no wire decoding.
    pub(crate) const fn new(organ: &'static str, reason: &'static str) -> Self {
        Self { organ, reason }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.organ, self.reason)
    }
}

impl std::error::Error for Refusal {}

/// A fallible canon operation with a stable refusal code.
pub type Result<T> = core::result::Result<T, Refusal>;
