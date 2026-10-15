// SPDX-License-Identifier: AGPL-3.0-or-later
//! BIP-340 keys and canonical NIP-19 public addresses.

use crate::{Refusal, Result};
use bech32::{primitives::decode::CheckedHrpstring, Bech32, Hrp};
use canon::alg::AlgorithmId;
use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

const fn refusal(reason: &'static str) -> Refusal {
    Refusal {
        organ: "nostr",
        reason,
    }
}

/// A validated x-only secp256k1 point. No owner binding is implied.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// Validates the x coordinate and its even-y lift with k256.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        VerifyingKey::from_slice(&bytes).map_err(|_| refusal("public-key-invalid"))?;
        Ok(Self(bytes))
    }

    /// Accepts exactly 64 lowercase hexadecimal digits and a valid point.
    pub fn from_hex(text: &str) -> Result<Self> {
        if text.len() != 64
            || !text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(refusal("public-key-invalid"));
        }
        let mut bytes = [0; 32];
        hex::decode_to_slice(text, &mut bytes).map_err(|_| refusal("public-key-invalid"))?;
        Self::from_bytes(bytes)
    }

    /// Borrows the x-only point bytes, never secret scalar bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// BIP-340 is fixed by the Nostr v1 wire format.
    pub const fn algorithm(&self) -> AlgorithmId {
        AlgorithmId::Secp256k1Schnorr
    }

    /// Encodes lowercase npub using the original Bech32 checksum.
    pub fn to_npub(&self) -> Result<canon::provenance::Npub> {
        canon::provenance::Npub::parse(self.algorithm(), &self.encoded_npub()?)
    }

    /// Checks checksum, npub HRP, 32-byte length and canonical round trip.
    pub fn from_npub(text: &str) -> Result<Self> {
        if text.len() > 128 {
            return Err(refusal("npub-invalid"));
        }
        let parsed = CheckedHrpstring::new::<Bech32>(text).map_err(|_| refusal("npub-invalid"))?;
        if parsed.hrp().as_str() != "npub" {
            return Err(refusal("npub-invalid"));
        }
        let bytes: [u8; 32] = parsed
            .byte_iter()
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| refusal("npub-invalid"))?;
        let key = Self::from_bytes(bytes).map_err(|_| refusal("npub-invalid"))?;
        if key.encoded_npub()? != text {
            return Err(refusal("npub-invalid"));
        }
        Ok(key)
    }

    fn encoded_npub(&self) -> Result<String> {
        let prefix = Hrp::parse("npub").map_err(|_| refusal("npub-invalid"))?;
        bech32::encode::<Bech32>(prefix, &self.0).map_err(|_| refusal("npub-invalid"))
    }
}

/// Zeroizing private scalar storage with no Clone, Debug, serialization or export.
pub struct SecretKey {
    _material: Zeroizing<[u8; 32]>,
}

impl SecretKey {
    /// Draws a valid nonzero scalar from the operating system RNG.
    pub fn generate() -> Result<Self> {
        loop {
            let mut material = Zeroizing::new([0; 32]);
            getrandom::fill(material.as_mut()).map_err(|_| refusal("random-unavailable"))?;
            if k256::SecretKey::from_slice(material.as_ref()).is_ok() {
                return Ok(Self {
                    _material: material,
                });
            }
        }
    }

    /// Imports a scalar into zeroizing storage; refuses zero and out-of-range.
    pub fn import(bytes: Zeroizing<[u8; 32]>) -> Result<Self> {
        k256::SecretKey::from_slice(bytes.as_ref()).map_err(|_| refusal("secret-invalid"))?;
        Ok(Self { _material: bytes })
    }

    /// Derives the corresponding BIP-340 public point with k256.
    pub fn public_key(&self) -> Result<PublicKey> {
        let signing = self.signing_key()?;
        PublicKey::from_bytes(signing.verifying_key().to_bytes().into())
    }

    /// Signs the exact bytes, without an extra hash, using fresh auxiliary
    /// randomness. Arbitrary message lengths follow the pinned BIP-340 corpus.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64]> {
        let mut auxiliary = Zeroizing::new([0; 32]);
        getrandom::fill(auxiliary.as_mut()).map_err(|_| refusal("random-unavailable"))?;
        self.signing_key()?
            .sign_raw(message, &auxiliary)
            .map(|signature| signature.to_bytes())
            .map_err(|_| refusal("sign-failed"))
    }

    fn signing_key(&self) -> Result<SigningKey> {
        SigningKey::from_slice(self._material.as_ref()).map_err(|_| refusal("secret-invalid"))
    }

    pub(crate) fn shared_secret(&self, peer: &PublicKey) -> Result<Zeroizing<[u8; 32]>> {
        let own = k256::SecretKey::from_slice(self._material.as_ref())
            .map_err(|_| refusal("secret-invalid"))?;
        let mut point = [0; 33];
        point[0] = 2;
        point[1..].copy_from_slice(peer.as_bytes());
        let other =
            k256::PublicKey::from_sec1_bytes(&point).map_err(|_| refusal("public-key-invalid"))?;
        let shared = k256::ecdh::diffie_hellman(own.to_nonzero_scalar(), other.as_affine());
        let mut material = Zeroizing::new([0; 32]);
        material.copy_from_slice(shared.raw_secret_bytes());
        Ok(material)
    }
}

/// Verifies exact message bytes using k256 BIP-340, including the pinned
/// variable-length vectors. A signature check never approves its signer.
pub fn verify(key: &PublicKey, message: &[u8], signature: &[u8; 64]) -> Result<()> {
    let verifier =
        VerifyingKey::from_slice(key.as_bytes()).map_err(|_| refusal("public-key-invalid"))?;
    let parsed =
        Signature::try_from(signature.as_slice()).map_err(|_| refusal("signature-invalid"))?;
    verifier
        .verify_raw(message, &parsed)
        .map_err(|_| refusal("signature-invalid"))
}
