// SPDX-License-Identifier: AGPL-3.0-or-later
//! Open Light's envelope v1 without generating or replacing its identity root.

use crate::{
    envelope::{EnvelopeV1, KdfParameters},
    keys::person_nostr::owner::PersonNostrKey,
    phrase::owner::{OwnerBrowser, OwnerPhrase},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use canon::json::Value;

pub(super) fn open(
    owner_origin: &str,
    shell_origin: &str,
    recovery: &str,
    entered: &str,
) -> Result<Vec<u8>, String> {
    let browser =
        OwnerBrowser::verify(owner_origin, shell_origin).map_err(|error| error.to_string())?;
    let envelope =
        EnvelopeV1::from_canonical_bytes(recovery.as_bytes()).map_err(|error| error.to_string())?;
    if envelope.parts().0 != KdfParameters::PRODUCTION {
        return Err(super::refusal("envelope-kdf"));
    }
    let phrase = OwnerPhrase::parse(&browser, entered).map_err(|error| error.to_string())?;
    let root = crate::envelope::owner::open(&browser, &envelope, &phrase)
        .map_err(|error| error.to_string())?;
    drop(phrase);
    let identity = root
        .public_identity(&browser)
        .map_err(|error| error.to_string())?;
    let person = PersonNostrKey::derive(&browser, &root, 0).map_err(|error| error.to_string())?;
    drop(root);
    let npub = person.npub().map_err(|error| error.to_string())?;
    let key = person.public_key();
    let payload = (|| -> canon::Result<Value> {
        let submission = Value::object(vec![
            (
                "envelope".into(),
                canon::json::parse_strict(envelope.canonical_bytes())?,
            ),
            (
                "identity_public_key".into(),
                Value::text(STANDARD.encode(&identity.public_key.bytes))?,
            ),
            ("subject".into(), Value::text(identity.subject.to_string())?),
            ("v".into(), canon::json::parse_strict(b"2")?),
        ])?;
        Value::object(vec![
            ("submission".into(), submission),
            (
                "person_nostr_public_key".into(),
                Value::text(hex::encode(key.bytes))?,
            ),
            (
                "person_nostr_npub".into(),
                Value::text(npub.as_str().to_owned())?,
            ),
        ])
    })()
    .map_err(|error| error.to_string())?;
    Ok(payload.canonical_bytes())
}
