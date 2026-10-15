// SPDX-License-Identifier: AGPL-3.0-or-later
//! Opaque identifiers; construction never supplies randomness or authority.

use crate::{alg::AlgorithmId, digest::Digest32, refusal::Refusal, Result};
use core::fmt;

/// Random id width in C7; source bytes are supplied by the owning organ's RNG.
pub const RANDOM_ID_BYTES: usize = 16;
/// Upper bound of the opaque WebAuthn credential id accepted by this format.
pub const MAX_CREDENTIAL_ID_BYTES: usize = 1_024;
/// Upper bound of a C4 opaque note handle; legacy values need not be hexadecimal.
pub const MAX_NOTE_ID_BYTES: usize = 128;

macro_rules! random_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; RANDOM_ID_BYTES]);

        impl $name {
            /// Retain 16 caller-supplied random bytes; never generate or verify randomness.
            pub const fn from_bytes(bytes: [u8; RANDOM_ID_BYTES]) -> Self {
                Self(bytes)
            }

            /// Borrow the exact id bytes without converting them to an instruction.
            pub const fn as_bytes(&self) -> &[u8; RANDOM_ID_BYTES] {
                &self.0
            }

            /// Parse exactly 32 lowercase hexadecimal digits; other spellings refuse.
            pub fn from_hex(_text: &str) -> Result<Self> {
                todo!("row 32")
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
                for byte in self.0 {
                    write!(output, "{byte:02x}")?;
                }
                Ok(())
            }
        }
    };
}

random_id!(
    ProposalId,
    "A proposal id: 16 random bytes, lowercase hex on the C7 wire."
);
random_id!(
    SessionId,
    "A session id: 16 random bytes, lowercase hex in versioned records."
);
random_id!(
    ThreadId,
    "A thread id: 16 random bytes, lowercase hex in versioned records."
);
random_id!(
    NodeId,
    "A node id: 16 random bytes, lowercase hex on the C7 wire."
);
random_id!(RequestId, "A request id: 16 random bytes, lowercase hex on the C7 wire; v1 C4 envelope ids retain their wider grammar.");
random_id!(
    ReservationId,
    "A broker reservation id: 16 random bytes, lowercase hex."
);
random_id!(
    AppId,
    "An application id: 16 random bytes, lowercase hex; possession grants no capability."
);
random_id!(
    GrantId,
    "A grant id: 16 random bytes, lowercase hex in new records; possession grants no authority."
);
random_id!(OperationId, "An Aura operation id: 16 random bytes, lowercase hex under C7; distinct from the C5 operation-content digest.");

/// The C5 operation-content SHA-256 commitment, distinct from a random `OperationId`.
/// Its wire representation is exactly 64 lowercase hex digits. It commits to
/// `aukora:operation-content:v1\0` followed by the exact canonical C5 target object;
/// retaining a claimed digest never establishes that it matches the target bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OperationDigest(Digest32);

impl OperationDigest {
    /// Retain a computed or claimed SHA-256 digest without verifying its preimage.
    pub const fn from_digest(digest: Digest32) -> Self {
        Self(digest)
    }

    /// Borrow the 32-byte commitment, never a C7 random operation id.
    pub const fn digest(&self) -> &Digest32 {
        &self.0
    }

    /// Identify the fixed C5 commitment primitive.
    pub const fn algorithm(&self) -> AlgorithmId {
        AlgorithmId::Sha256
    }

    /// Parse exactly 64 lowercase hexadecimal digits; other spellings refuse.
    pub fn from_hex(_text: &str) -> Result<Self> {
        todo!("row 32")
    }
}

impl fmt::Display for OperationDigest {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, output)
    }
}

/// An opaque C4 note handle; 1..=128 UTF-8 bytes without control characters.
/// C7's 16-byte random-id rule does not apply to note handles.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NoteId(String);

impl NoteId {
    /// Retain a bounded data handle, including legacy handles such as `note-1`.
    pub fn new(text: String) -> Result<Self> {
        if text.is_empty() || text.len() > MAX_NOTE_ID_BYTES || text.chars().any(char::is_control) {
            return Err(Refusal::new("kira", "note-id"));
        }
        Ok(Self(text))
    }

    /// Borrow the opaque note handle without interpreting it as a path or instruction.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NoteId {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(&self.0)
    }
}

/// A WebAuthn credential handle, never the key itself; 1..=1,024 opaque bytes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CredentialId(Vec<u8>);

impl CredentialId {
    /// Retain a bounded nonempty handle; this does not establish an owner binding.
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_CREDENTIAL_ID_BYTES {
            return Err(Refusal::new("aumlok", "credential-id"));
        }
        Ok(Self(bytes))
    }

    /// Borrow opaque credential bytes; the owning epoch must be checked separately.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A C7 subject, displayed only as `aukora:1:` followed by 64 lowercase hex digits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubjectId(Digest32);

impl SubjectId {
    /// Wrap the subject identifier digest without assigning an owner or authority.
    pub const fn from_digest(digest: Digest32) -> Self {
        Self(digest)
    }

    /// Borrow the digest component of the version-1 subject identifier.
    pub const fn digest(&self) -> &Digest32 {
        &self.0
    }

    /// Parse exactly `aukora:1:` plus 64 lowercase hex digits; unknown versions refuse.
    pub fn parse(_text: &str) -> Result<Self> {
        todo!("row 32")
    }
}

impl fmt::Display for SubjectId {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "aukora:1:{}", self.0)
    }
}
