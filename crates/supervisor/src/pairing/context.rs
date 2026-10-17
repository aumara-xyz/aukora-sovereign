// SPDX-License-Identifier: AGPL-3.0-or-later
//! The pinned pairing context: the exact bytes both devices bind as the v1 `purpose`.
//!
//! The node writes it once per pairing, after both device keys are known, as C1
//! canonical JSON. Each device copies the bytes unchanged into its exchange, so both
//! device signatures over the receipt core commit to every field below.

use canon::{
    digest::Digest32,
    ids::{NodeId, SubjectId},
    json::{SafeInteger, Value},
    Result,
};

/// Version of the context object; a change of any field's meaning is a new schema.
pub const CONTEXT_SCHEMA: &str = "aukora.copresence.pairing-context.v1";
/// The one purpose this node issues: the owner pairs one more of their own devices.
pub const PURPOSE: &str = "pair-own-device";
/// Domain for binding the owner's browser session without disclosing its digest.
pub const SESSION_DOMAIN: &str = "aukora:copresence-owner-session:v1";
/// The browser engine refuses longer contexts.
pub const MAX_CONTEXT_BYTES: usize = 4_096;

/// Everything the transcript binds. Device keys are uncompressed SEC1 P-256.
pub struct PairingContext<'a> {
    pub node: NodeId,
    pub owner: SubjectId,
    pub owner_epoch: u64,
    pub owner_session: Digest32,
    pub pairing: [u8; 16],
    pub origin: &'a str,
    pub initiator_key: &'a [u8; 65],
    pub joiner_key: &'a [u8; 65],
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

/// SHA-256 of the domain, a NUL, then the owner session's token digest.
pub fn session_binding(token_digest: &Digest32) -> Digest32 {
    let mut bytes = SESSION_DOMAIN.as_bytes().to_vec();
    bytes.push(0);
    bytes.extend_from_slice(token_digest.as_bytes());
    Digest32::sha256(&bytes)
}

fn integer(value: u64) -> Result<Value> {
    let value = i64::try_from(value).map_err(|_| super::refuse("context-integer"))?;
    Ok(Value::integer(SafeInteger::new(value)?))
}

fn text(value: impl Into<String>) -> Result<Value> {
    Value::text(value.into())
}

impl PairingContext<'_> {
    /// C1 canonical bytes. Keys sort by UTF-16 code unit; integers are plain decimals.
    pub fn canonical_text(&self) -> Result<String> {
        if self.expires_at_ms <= self.issued_at_ms || self.initiator_key == self.joiner_key {
            return Err(super::refuse("context-invalid"));
        }
        let value = Value::object(vec![
            ("schema".into(), text(CONTEXT_SCHEMA)?),
            ("purpose".into(), text(PURPOSE)?),
            ("node".into(), text(self.node.to_string())?),
            ("owner".into(), text(self.owner.to_string())?),
            ("ownerEpoch".into(), integer(self.owner_epoch)?),
            ("ownerSession".into(), text(self.owner_session.to_string())?),
            ("pairing".into(), text(hex::encode(self.pairing))?),
            ("origin".into(), text(self.origin)?),
            ("method".into(), text("screen-to-screen")?),
            ("layers".into(), text("optical")?),
            (
                "devices".into(),
                Value::object(vec![
                    ("initiator".into(), text(hex::encode(self.initiator_key))?),
                    ("joiner".into(), text(hex::encode(self.joiner_key))?),
                ])?,
            ),
            ("issuedAtMs".into(), integer(self.issued_at_ms)?),
            ("expiresAtMs".into(), integer(self.expires_at_ms)?),
        ])?;
        let bytes = value.canonical_bytes();
        if bytes.len() > MAX_CONTEXT_BYTES {
            return Err(super::refuse("context-size"));
        }
        String::from_utf8(bytes).map_err(|_| super::refuse("context-invalid"))
    }
}
