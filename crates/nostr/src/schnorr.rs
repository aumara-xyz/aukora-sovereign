// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{Error, Result};
use k256::schnorr::{Signature, VerifyingKey};

pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<()> {
    let key =
        VerifyingKey::from_slice(public_key).map_err(|_| Error("nostr:public-key-invalid"))?;
    let signature =
        Signature::try_from(signature.as_slice()).map_err(|_| Error("nostr:signature-invalid"))?;
    key.verify_raw(message, &signature)
        .map_err(|_| Error("nostr:signature-invalid"))
}
