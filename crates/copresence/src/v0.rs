// SPDX-License-Identifier: AGPL-3.0-or-later
//! Frozen `copresence.v0` evidence. Hardened rules belong to `v1`.

use crate::{PublicKeyBytes, Result, UNIMPLEMENTED};
use canon::digest::Digest32;

pub use canon::domain::{
    COPRESENCE_CORE_DOMAIN as CORE_DOMAIN, COPRESENCE_INTENT_ACK_DOMAIN as INTENT_ACK_DOMAIN,
    COPRESENCE_INTENT_DOMAIN as INTENT_DOMAIN,
    COPRESENCE_INTENT_NONCE_DOMAIN as INTENT_NONCE_DOMAIN,
};

pub const MAX_WINDOW_SECONDS: u64 = 10;
pub const NONCE_BYTES: usize = 8;
pub const INTENT_SALT_BYTES: usize = 16;

/// V0 core layout: domain, NUL, pk_A, pk_B, nonce_A, nonce_B, BE64(t_B).
/// t_A remains outside the signed core; its window check is 0..=10 seconds.
/// Both signatures use P-256/SHA-256 over the 32-byte core digest as a message.
#[derive(Clone, Debug)]
pub struct CoreInput {
    pub pk_a: PublicKeyBytes,
    pub pk_b: PublicKeyBytes,
    pub nonce_a: [u8; NONCE_BYTES],
    pub nonce_b: [u8; NONCE_BYTES],
    pub t_b_seconds: u64,
}

/// Opaque verifier output. Neither public keys nor times identify a human.
#[derive(Clone, Debug)]
pub struct VerifiedReceipt {
    core: Digest32,
    pk_a: PublicKeyBytes,
    pk_b: PublicKeyBytes,
    t_a_seconds: f64,
    t_b_seconds: f64,
}

impl VerifiedReceipt {
    pub const fn core(&self) -> Digest32 {
        self.core
    }

    pub const fn public_keys(&self) -> (PublicKeyBytes, PublicKeyBytes) {
        (self.pk_a, self.pk_b)
    }

    pub const fn timestamps_seconds(&self) -> (f64, f64) {
        (self.t_a_seconds, self.t_b_seconds)
    }
}

/// Optional legacy intent freshness and expected approver, supplied by caller.
#[derive(Clone, Copy, Debug, Default)]
pub struct IntentOptions<'a> {
    pub approver_hex: Option<&'a str>,
    pub max_age_seconds: Option<f64>,
    pub now_seconds: f64,
}

/// Exact-text device acknowledgement evidence; no passkey approval is implied.
#[derive(Clone, Debug)]
pub struct VerifiedIntent {
    receipt: VerifiedReceipt,
    text_digest: Digest32,
    asker: PublicKeyBytes,
    approver: PublicKeyBytes,
}

impl VerifiedIntent {
    pub const fn receipt(&self) -> &VerifiedReceipt {
        &self.receipt
    }

    pub const fn text_digest(&self) -> Digest32 {
        self.text_digest
    }

    pub const fn participants(&self) -> (PublicKeyBytes, PublicKeyBytes) {
        (self.asker, self.approver)
    }
}

/// Computes the frozen digest; no digest is produced by this wave-0 declaration.
pub fn core_digest(_input: &CoreInput) -> Result<Digest32> {
    Err(UNIMPLEMENTED)
}

/// V0 verification entry point. Refusal order and telemetry coercions follow
/// the pinned corpus; no hardened restrictions are retrofitted onto v0.
pub fn verify_receipt(_bytes: &[u8]) -> Result<VerifiedReceipt> {
    Err(UNIMPLEMENTED)
}

/// Adds exact text, nonce commitment and approver signature checks to v0.
/// Fixture text means TEXT.txt without its one trailing LF.
pub fn verify_intent(
    _bytes: &[u8],
    _expected_text: &str,
    _options: IntentOptions<'_>,
) -> Result<VerifiedIntent> {
    Err(UNIMPLEMENTED)
}
