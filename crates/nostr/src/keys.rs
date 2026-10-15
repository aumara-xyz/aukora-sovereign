// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{Error, Result};
use bech32::{primitives::decode::CheckedHrpstring, Bech32, Hrp};
use k256::schnorr::SigningKey;
use zeroize::{Zeroize, Zeroizing};

/// A scalar with no formatting, serializing, cloning, or secret export API.
///
/// ```compile_fail
/// let key = nostr::SecretKey::generate().unwrap();
/// println!("{key:?}");
/// ```
/// ```compile_fail
/// let key = nostr::SecretKey::generate().unwrap();
/// println!("{key}");
/// ```
/// ```compile_fail
/// let key = nostr::SecretKey::generate().unwrap();
/// let _secret_bytes = key.to_bytes();
/// ```
pub struct SecretKey(pub(crate) [u8; 32]);

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl SecretKey {
    pub fn generate() -> Result<Self> {
        loop {
            let mut bytes = Zeroizing::new([0; 32]);
            getrandom::fill(&mut *bytes).map_err(|_| Error("nostr:random-unavailable"))?;
            if SigningKey::from_slice(&*bytes).is_ok() {
                return Ok(Self(*bytes));
            }
        }
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        let secret = Zeroizing::new(bytes);
        SigningKey::from_slice(&*secret).map_err(|_| Error("nostr:secret-invalid"))?;
        Ok(Self(*secret))
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key().verifying_key().to_bytes().into()
    }

    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64]> {
        let mut auxiliary = Zeroizing::new([0; 32]);
        getrandom::fill(&mut *auxiliary).map_err(|_| Error("nostr:random-unavailable"))?;
        self.sign_inner(message, &auxiliary)
    }

    #[cfg(test)]
    pub(crate) fn sign_with_aux(&self, message: &[u8], auxiliary: &[u8; 32]) -> Result<[u8; 64]> {
        self.sign_inner(message, auxiliary)
    }

    fn sign_inner(&self, message: &[u8], auxiliary: &[u8; 32]) -> Result<[u8; 64]> {
        self.signing_key()
            .sign_raw(message, auxiliary)
            .map(|signature| signature.to_bytes())
            .map_err(|_| Error("nostr:sign-failed"))
    }

    fn signing_key(&self) -> SigningKey {
        SigningKey::from_slice(&self.0).expect("SecretKey validates its scalar on creation")
    }
}

pub fn npub_encode(public_key: &[u8; 32]) -> Result<String> {
    bech32::encode::<Bech32>(Hrp::parse("npub").expect("fixed valid HRP"), public_key)
        .map_err(|_| Error("nostr:npub-invalid"))
}

pub fn npub_decode(npub: &str) -> Result<[u8; 32]> {
    let decoded = CheckedHrpstring::new::<Bech32>(npub).map_err(|_| Error("nostr:npub-invalid"))?;
    if decoded.hrp() != Hrp::parse("npub").expect("fixed valid HRP") {
        return Err(Error("nostr:npub-invalid"));
    }
    let key = decoded
        .byte_iter()
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| Error("nostr:npub-invalid"))?;
    if npub_encode(&key)? != npub {
        return Err(Error("nostr:npub-invalid"));
    }
    Ok(key)
}
