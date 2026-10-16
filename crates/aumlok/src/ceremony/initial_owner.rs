// SPDX-License-Identifier: AGPL-3.0-or-later
//! Initial phrase generation and confirmation confined to the owner frame.

use crate::{
    envelope::{owner::IdentityRoot, EnvelopeV1, KdfParameters, RootIdentity},
    phrase::{
        owner::{OwnerBrowser, OwnerPhrase},
        SHIPPED_ENTROPY,
    },
};
use base64::{engine::general_purpose::STANDARD, Engine};
use canon::{json::Value, Refusal};
use subtle::ConstantTimeEq;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

fn js_refusal(refusal: Refusal) -> JsValue {
    JsValue::from_str(&refusal.to_string())
}

fn refused(reason: &'static str) -> JsValue {
    js_refusal(Refusal {
        organ: "aumlok",
        reason,
    })
}

/// Holds a local seven-word confirmation and its public encrypted submission.
#[wasm_bindgen]
pub struct InitialBindingSession {
    browser: OwnerBrowser,
    phrase: Option<OwnerPhrase>,
    envelope: Option<EnvelopeV1>,
    identity: Option<RootIdentity>,
    confirmed: bool,
}

impl InitialBindingSession {
    fn check_frame(&self) -> core::result::Result<(), JsValue> {
        OwnerBrowser::verify(self.browser.owner_origin(), self.browser.shell_origin())
            .map(|_| ())
            .map_err(js_refusal)
    }

    fn check_confirmed(&self) -> core::result::Result<(), JsValue> {
        self.check_frame()?;
        if !self.confirmed {
            return Err(refused("word-mismatch"));
        }
        Ok(())
    }
}

#[wasm_bindgen]
impl InitialBindingSession {
    /// Draw the phrase and independent random root, then seal the root with envelope v1.
    pub fn prepare(owner_origin: &str, shell_origin: &str) -> core::result::Result<Self, JsValue> {
        let browser = OwnerBrowser::verify(owner_origin, shell_origin).map_err(js_refusal)?;
        let phrase = OwnerPhrase::draw(&browser).map_err(js_refusal)?;
        let root = IdentityRoot::generate(&browser).map_err(js_refusal)?;
        let identity = root.public_identity(&browser).map_err(js_refusal)?;
        let envelope =
            crate::envelope::owner::seal(&browser, &root, &phrase, KdfParameters::PRODUCTION)
                .map_err(js_refusal)?;
        drop(root);
        Ok(Self {
            browser,
            phrase: Some(phrase),
            envelope: Some(envelope),
            identity: Some(identity),
            confirmed: false,
        })
    }

    /// Expose the seven words only to the currently verified owner frame.
    pub fn phrase(&self) -> core::result::Result<String, JsValue> {
        self.check_frame()?;
        self.phrase
            .as_ref()
            .map(|phrase| phrase.expose(&self.browser).to_owned())
            .ok_or_else(|| refused("phrase-locked"))
    }

    /// Minimum entropy of the shipped generation vocabulary.
    pub fn minimum_entropy_bits(&self) -> f64 {
        SHIPPED_ENTROPY.minimum_bits
    }

    /// Average entropy of the shipped generation vocabulary.
    pub fn average_entropy_bits(&self) -> f64 {
        SHIPPED_ENTROPY.average_bits
    }

    /// Compare all seven normalized words locally, then erase the held phrase.
    pub fn confirm(&mut self, entered: &str) -> core::result::Result<(), JsValue> {
        self.check_frame()?;
        if self.confirmed {
            return Err(refused("ceremony-spent"));
        }
        let phrase = self
            .phrase
            .as_ref()
            .ok_or_else(|| refused("phrase-locked"))?;
        let confirmation =
            OwnerPhrase::parse(&self.browser, entered).map_err(|_| refused("word-mismatch"))?;
        if !bool::from(
            phrase
                .expose(&self.browser)
                .as_bytes()
                .ct_eq(confirmation.expose(&self.browser).as_bytes()),
        ) {
            return Err(refused("word-mismatch"));
        }
        self.phrase = None;
        self.confirmed = true;
        Ok(())
    }

    /// Public ciphertext bytes become available only after local phrase confirmation.
    pub fn envelope(&self) -> core::result::Result<Vec<u8>, JsValue> {
        self.check_confirmed()?;
        self.envelope
            .as_ref()
            .map(|envelope| envelope.canonical_bytes().to_vec())
            .ok_or_else(|| refused("binding-input"))
    }

    /// The subject derives solely from the random root, never from a node or passkey.
    pub fn subject(&self) -> core::result::Result<String, JsValue> {
        self.check_confirmed()?;
        self.identity
            .as_ref()
            .map(|identity| identity.subject.to_string())
            .ok_or_else(|| refused("binding-input"))
    }

    /// Return only the root-derived Ed25519 public key, never its seed or root.
    pub fn public_key(&self) -> core::result::Result<Vec<u8>, JsValue> {
        self.check_confirmed()?;
        self.identity
            .as_ref()
            .map(|identity| identity.public_key.bytes.clone())
            .ok_or_else(|| refused("binding-input"))
    }

    /// Canonical v2 preparation data contains only the public identity and envelope v1.
    pub fn confirmation_payload(&self) -> core::result::Result<Vec<u8>, JsValue> {
        self.check_confirmed()?;
        let envelope = self
            .envelope
            .as_ref()
            .ok_or_else(|| refused("binding-input"))?;
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| refused("binding-input"))?;
        let payload = Value::object(vec![
            (
                "envelope".into(),
                canon::json::parse_strict(envelope.canonical_bytes()).map_err(js_refusal)?,
            ),
            (
                "identity_public_key".into(),
                Value::text(STANDARD.encode(&identity.public_key.bytes)).map_err(js_refusal)?,
            ),
            (
                "subject".into(),
                Value::text(identity.subject.to_string()).map_err(js_refusal)?,
            ),
            (
                "v".into(),
                canon::json::parse_strict(b"2").map_err(js_refusal)?,
            ),
        ])
        .map_err(js_refusal)?;
        Ok(payload.canonical_bytes())
    }

    /// Erase pending phrase material and prevent later export from this session.
    pub fn discard(&mut self) {
        self.phrase = None;
        self.envelope = None;
        self.identity = None;
        self.confirmed = false;
    }
}
