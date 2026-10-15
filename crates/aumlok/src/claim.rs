// SPDX-License-Identifier: AGPL-3.0-or-later
//! Compare a bootstrap candidate with the host's SHA-256 claim commitment.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use canon::{codes::AUMLOK_CLAIM_UNKNOWN, digest::Digest32, Result};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Host configuration supplies this commitment; request bodies never do.
pub struct HostClaimCommitment(Digest32);

impl HostClaimCommitment {
    pub const fn from_host_digest(digest: Digest32) -> Self {
        Self(digest)
    }

    /// Spawn encodes 32 random bytes without padding and hashes those raw bytes.
    pub fn verify(&self, token: &[u8]) -> Result<()> {
        if token.len() != 43 {
            return Err(AUMLOK_CLAIM_UNKNOWN);
        }
        let secret = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(token)
                .map_err(|_| AUMLOK_CLAIM_UNKNOWN)?,
        );
        if secret.len() != 32 {
            return Err(AUMLOK_CLAIM_UNKNOWN);
        }
        let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(secret.as_slice()));
        if encoded.as_bytes() != token {
            return Err(AUMLOK_CLAIM_UNKNOWN);
        }
        let actual = Digest32::sha256(secret.as_slice());
        if !bool::from(self.0.as_bytes().ct_eq(actual.as_bytes())) {
            return Err(AUMLOK_CLAIM_UNKNOWN);
        }
        Ok(())
    }
}
