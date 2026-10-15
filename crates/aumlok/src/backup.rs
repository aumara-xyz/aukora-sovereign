// SPDX-License-Identifier: AGPL-3.0-or-later
//! Passkey-bound download v2 and explicit phrase-only recovery-copy contracts.

use crate::{
    ceremony::CeremonyId,
    envelope::{EnvelopeV1, KdfParameters, CIPHERTEXT_BYTES, NONCE_BYTES, SALT_BYTES},
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use canon::{alg::AlgorithmId, ids::CredentialId, Refusal, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The downloaded copy's version; the node's current envelope stays v1.
pub const BACKUP_VERSION: u16 = 2;
/// Maximum canonical downloaded backup size.
pub const MAX_BACKUP_BYTES: usize = 4_096;
/// Hash exactly these bytes without a trailing NUL for PRF eval.first.
pub const PRF_EVALUATION_TAG: &[u8] = b"aukora:aumlok-backup-prf:v2";
/// HKDF extract salt, including the terminating NUL.
pub const BACKUP_HKDF_SALT: &[u8] = b"aukora:aumlok-backup-hkdf:v2\0";
/// HKDF expand info, including the terminating NUL.
pub const BACKUP_HKDF_INFO: &[u8] = b"aukora:aumlok-backup-key:v2\0";
/// AAD prefix before the complete canonical header, including PRF metadata.
pub const BACKUP_AAD_DOMAIN: &[u8] = b"aukora:aumlok-backup-aead:v2\0";

/// Public credential/RP binding retained by the encrypted backup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrfBinding {
    /// The credential originally used to seal this backup.
    pub credential_id: CredentialId,
    /// Its original relying-party DNS name, not the recovery machine's RP.
    pub original_rp_id: String,
}

/// Public request context for a fresh node-issued backup ceremony.
/// Supplying these fields does not prove that a live ceremony exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrfEvaluationRequest {
    /// Original credential and relying party retained by the backup.
    pub binding: PrfBinding,
    /// Node-issued durable backup ceremony handle.
    pub ceremony: CeremonyId,
    /// Fresh WebAuthn challenge, distinct from the fixed PRF eval.first input.
    pub challenge: [u8; 32],
    /// Owner epoch to recheck when the node finishes the ceremony.
    pub expected_epoch: u64,
    /// Supervisor expiry in milliseconds; expiry never creates authority.
    pub expires_at_ms: i64,
}

/// Parsed backup ciphertext with validated canonical metadata.
/// Its wire has exactly `ciphertext`, `kdf`, `nonce`, `prf`, `salt`, `version`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupEnvelopeV2 {
    canonical: Vec<u8>,
    kdf: KdfParameters,
    salt: [u8; SALT_BYTES],
    nonce: [u8; NONCE_BYTES],
    ciphertext: [u8; CIPHERTEXT_BYTES],
    prf: PrfBinding,
}

impl BackupEnvelopeV2 {
    /// The decoder requires canonical v2 bytes, exact field sets,
    /// bounded costs, fixed byte widths, and the pinned PRF evaluation salt.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_BACKUP_BYTES {
            return Err(refuse("envelope-too-large"));
        }
        let wire: BackupWire =
            serde_json::from_slice(bytes).map_err(|_| refuse("envelope-json"))?;
        if wire.version != BACKUP_VERSION {
            return Err(refuse("envelope-version"));
        }
        let kdf = wire.kdf.parameters()?;
        let credential = URL_SAFE_NO_PAD
            .decode(&wire.prf.credential_id)
            .map_err(|_| refuse("backup-prf-metadata"))?;
        if URL_SAFE_NO_PAD.encode(&credential) != wire.prf.credential_id {
            return Err(refuse("backup-prf-metadata"));
        }
        let prf = PrfBinding {
            credential_id: CredentialId::new(credential)
                .map_err(|_| refuse("backup-prf-metadata"))?,
            original_rp_id: wire.prf.rp_id,
        };
        validate_binding(&prf)?;
        if decode_fixed::<32>(&wire.prf.salt)? != evaluation_salt() {
            return Err(refuse("backup-prf-metadata"));
        }
        let decoded = Self {
            canonical: bytes.to_vec(),
            kdf,
            salt: decode_fixed(&wire.salt)?,
            nonce: decode_fixed(&wire.nonce)?,
            ciphertext: decode_fixed(&wire.ciphertext)?,
            prf,
        };
        if decoded.encode()? != bytes {
            return Err(refuse("envelope-not-canonical"));
        }
        Ok(decoded)
    }

    /// Borrow exact validated backup bytes.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    /// Frozen outer backup version.
    pub const fn version(&self) -> u16 {
        BACKUP_VERSION
    }

    /// PRF metadata is public; no PRF secret result is stored here.
    pub const fn prf_binding(&self) -> &PrfBinding {
        &self.prf
    }

    /// Explicit semantic primitive tags without adding fields to the v2 wire.
    pub const fn algorithms(&self) -> [AlgorithmId; 3] {
        [
            AlgorithmId::Argon2id,
            AlgorithmId::Sha256,
            AlgorithmId::XChaCha20Poly1305,
        ]
    }

    /// Public KDF metadata and encrypted root bytes.
    pub const fn parts(
        &self,
    ) -> (
        KdfParameters,
        &[u8; SALT_BYTES],
        &[u8; NONCE_BYTES],
        &[u8; CIPHERTEXT_BYTES],
    ) {
        (self.kdf, &self.salt, &self.nonce, &self.ciphertext)
    }

    fn encode(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&BackupWire {
            ciphertext: STANDARD.encode(self.ciphertext),
            kdf: KdfWire::from(self.kdf),
            nonce: STANDARD.encode(self.nonce),
            prf: PrfWire::from(&self.prf),
            salt: STANDARD.encode(self.salt),
            version: BACKUP_VERSION,
        })
        .map_err(|_| refuse("envelope-json"))
    }

    #[cfg(target_arch = "wasm32")]
    fn associated_data(&self) -> Result<Vec<u8>> {
        let header = serde_json::to_vec(&BackupHeader {
            kdf: KdfWire::from(self.kdf),
            nonce: STANDARD.encode(self.nonce),
            prf: PrfWire::from(&self.prf),
            salt: STANDARD.encode(self.salt),
            version: BACKUP_VERSION,
        })
        .map_err(|_| refuse("envelope-json"))?;
        let mut data = BACKUP_AAD_DOMAIN.to_vec();
        data.extend_from_slice(&header);
        Ok(data)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BackupWire {
    ciphertext: String,
    kdf: KdfWire,
    nonce: String,
    prf: PrfWire,
    salt: String,
    version: u16,
}

#[cfg(target_arch = "wasm32")]
#[derive(Serialize)]
struct BackupHeader {
    kdf: KdfWire,
    nonce: String,
    prf: PrfWire,
    salt: String,
    version: u16,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct KdfWire {
    algorithm: String,
    memory_kib: u32,
    parallelism: u32,
    time_cost: u32,
    version: u32,
}

impl KdfWire {
    fn parameters(&self) -> Result<KdfParameters> {
        if self.algorithm != "argon2id" || self.version != crate::envelope::ARGON2_VERSION {
            return Err(refuse("envelope-kdf"));
        }
        let parameters = KdfParameters {
            memory_kib: self.memory_kib,
            parallelism: self.parallelism,
            time_cost: self.time_cost,
        };
        parameters.validate()?;
        Ok(parameters)
    }
}

impl From<KdfParameters> for KdfWire {
    fn from(value: KdfParameters) -> Self {
        Self {
            algorithm: "argon2id".into(),
            memory_kib: value.memory_kib,
            parallelism: value.parallelism,
            time_cost: value.time_cost,
            version: crate::envelope::ARGON2_VERSION,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PrfWire {
    credential_id: String,
    rp_id: String,
    salt: String,
}

impl From<&PrfBinding> for PrfWire {
    fn from(value: &PrfBinding) -> Self {
        Self {
            credential_id: URL_SAFE_NO_PAD.encode(value.credential_id.as_bytes()),
            rp_id: value.original_rp_id.clone(),
            salt: STANDARD.encode(evaluation_salt()),
        }
    }
}

fn evaluation_salt() -> [u8; 32] {
    Sha256::digest(PRF_EVALUATION_TAG).into()
}

fn refuse(reason: &'static str) -> Refusal {
    Refusal {
        organ: "aumlok",
        reason,
    }
}

fn decode_fixed<const N: usize>(encoded: &str) -> Result<[u8; N]> {
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| refuse("envelope-base64"))?;
    if STANDARD.encode(&bytes) != encoded {
        return Err(refuse("envelope-base64"));
    }
    bytes.try_into().map_err(|_| refuse("envelope-length"))
}

fn validate_binding(binding: &PrfBinding) -> Result<()> {
    let rp = &binding.original_rp_id;
    if rp.is_empty()
        || rp.len() > 253
        || rp.split(['.', '-']).any(|part| {
            part.is_empty()
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
        || !matches!(url::Host::parse(rp), Ok(url::Host::Domain(_)))
    {
        return Err(refuse("backup-prf-metadata"));
    }
    Ok(())
}

/// Download choice; automatic selection never falls back to phrase-only v1.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum BackupRequest {
    /// Require the same credential's PRF under its original RP.
    #[default]
    PasskeyBoundV2,
    /// An explicit request for the independently guessable v1 recovery copy.
    ExplicitPhraseOnlyV1,
}

/// Data offered to the owner for download, never installed as authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BackupDownload {
    /// Default two-input encrypted copy.
    PasskeyBound(BackupEnvelopeV2),
    /// Separately and explicitly requested phrase-only copy.
    PhraseOnly(EnvelopeV1),
}

/// PRF results and phrase-derived keys are confined to the owner-browser build.
#[cfg(target_arch = "wasm32")]
pub mod owner {
    use super::{
        evaluation_salt, refuse, validate_binding, BackupDownload, BackupEnvelopeV2, BackupRequest,
        PrfBinding, PrfEvaluationRequest, BACKUP_HKDF_INFO, BACKUP_HKDF_SALT,
    };
    use crate::{
        envelope::{
            owner::{derive_phrase_key, IdentityRoot},
            KdfParameters,
        },
        phrase::owner::{OwnerBrowser, OwnerPhrase},
        webauthn::AssertionMaterial,
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use canon::Result;
    use chacha20poly1305::{
        aead::{Aead, KeyInit, Payload},
        XChaCha20Poly1305, XNonce,
    };
    use hkdf::Hkdf;
    use js_sys::{Array, ArrayBuffer, Object, Reflect, Uint8Array};
    use sha2::Sha256;
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{
        AuthenticationExtensionsClientInputs, AuthenticatorAssertionResponse,
        CredentialRequestOptions, PublicKeyCredential, PublicKeyCredentialDescriptor,
        PublicKeyCredentialRequestOptions, PublicKeyCredentialType, UserVerificationRequirement,
    };
    use zeroize::Zeroizing;

    /// A local PRF result; no Debug, serialization or native-node constructor.
    pub struct OwnerPrf {
        binding: PrfBinding,
        output: Zeroizing<[u8; 32]>,
        assertion: AssertionMaterial,
    }

    impl OwnerPrf {
        /// Obtain exactly one eval.first result
        /// from this credential under its original RP using the fresh challenge.
        /// The node's backup finish remains blocked until canon has a standalone
        /// ceremony proof with atomic nonce and counter persistence.
        pub async fn evaluate(
            browser: &OwnerBrowser,
            request: &PrfEvaluationRequest,
        ) -> Result<Self> {
            validate_binding(&request.binding)?;
            let window = web_sys::window().ok_or_else(|| refuse("owner-origin"))?;
            let actual = window
                .location()
                .origin()
                .map_err(|_| refuse("owner-origin"))?;
            let origin = url::Url::parse(&actual).map_err(|_| refuse("owner-origin"))?;
            let host = origin.host_str().ok_or_else(|| refuse("owner-origin"))?;
            let rp = &request.binding.original_rp_id;
            if actual != browser.owner_origin()
                || origin.scheme() != "https"
                || !(host == rp.as_str() || host.ends_with(&format!(".{rp}")))
            {
                return Err(refuse("backup-prf-metadata"));
            }
            let remaining = request.expires_at_ms as f64 - js_sys::Date::now();
            if !remaining.is_finite() || remaining <= 0.0 || remaining > 300_000.0 {
                return Err(refuse("ceremony-expired"));
            }
            let options = PublicKeyCredentialRequestOptions::new_with_u8_array(&Uint8Array::from(
                request.challenge.as_slice(),
            ));
            options.set_rp_id(rp);
            options.set_timeout(remaining.ceil() as u32);
            options.set_user_verification(UserVerificationRequirement::Required);
            let descriptor = PublicKeyCredentialDescriptor::new_with_u8_array(
                &Uint8Array::from(request.binding.credential_id.as_bytes()),
                PublicKeyCredentialType::PublicKey,
            );
            let allowed = Array::new();
            allowed.push(descriptor.as_ref());
            options.set_allow_credentials(allowed.as_ref());
            let eval = Object::new();
            put(
                &eval,
                "first",
                Uint8Array::from(evaluation_salt().as_slice()).as_ref(),
            )?;
            let prf = Object::new();
            put(&prf, "eval", eval.as_ref())?;
            let extensions = AuthenticationExtensionsClientInputs::new();
            put(extensions.as_ref(), "prf", prf.as_ref())?;
            options.set_extensions(&extensions);
            let outer = CredentialRequestOptions::new();
            outer.set_public_key(&options);
            let promise = window
                .navigator()
                .credentials()
                .get_with_options(&outer)
                .map_err(|_| refuse("backup-prf-unavailable"))?;
            let credential: PublicKeyCredential = JsFuture::from(promise)
                .await
                .map_err(|_| refuse("backup-prf-unavailable"))?
                .dyn_into()
                .map_err(|_| refuse("backup-prf-unavailable"))?;
            let raw_id = Uint8Array::new(&credential.raw_id()).to_vec();
            if credential.type_() != "public-key"
                || raw_id.as_slice() != request.binding.credential_id.as_bytes()
                || js_sys::Date::now() >= request.expires_at_ms as f64
            {
                return Err(refuse("backup-prf-metadata"));
            }
            let results = credential.get_client_extension_results();
            let prf = field(results.as_ref(), "prf")?;
            let values = field(&prf, "results")?;
            if Reflect::has(&values, &JsValue::from_str("second"))
                .map_err(|_| refuse("backup-prf-required"))?
            {
                return Err(refuse("backup-prf-required"));
            }
            let first: ArrayBuffer = field(&values, "first")?
                .dyn_into()
                .map_err(|_| refuse("backup-prf-required"))?;
            let view = Uint8Array::new(&first);
            if view.length() != 32 {
                view.fill(0, 0, view.length());
                return Err(refuse("backup-prf-required"));
            }
            let mut output = Zeroizing::new([0; 32]);
            view.copy_to(output.as_mut());
            view.fill(0, 0, view.length());
            let response: AuthenticatorAssertionResponse = credential
                .response()
                .dyn_into()
                .map_err(|_| refuse("backup-prf-unavailable"))?;
            let assertion = AssertionMaterial {
                kind: "passkey".into(),
                credential_id: URL_SAFE_NO_PAD.encode(raw_id),
                client_data_json: encode_buffer(&response.client_data_json(), 16_384)?,
                authenticator_data: encode_buffer(&response.authenticator_data(), 4_096)?,
                signature: encode_buffer(&response.signature(), 128)?,
                user_handle: response
                    .user_handle()
                    .map(|value| encode_buffer(&value, 64))
                    .transpose()?,
            };
            Ok(Self {
                binding: request.binding.clone(),
                output,
                assertion,
            })
        }

        /// Borrow public recovery metadata; the PRF result stays local.
        pub fn binding(&self) -> &PrfBinding {
            &self.binding
        }

        /// Nonsecret assertion bytes for node verification, with no PRF result.
        /// Returning these bytes does not verify or finish a ceremony.
        pub fn assertion(&self) -> &AssertionMaterial {
            &self.assertion
        }
    }

    /// V2 requires both inputs: Argon2id phrase key followed by
    /// 32 PRF bytes as HKDF-SHA256 input, then XChaCha20-Poly1305 with fresh salt/nonce.
    /// A missing PRF cannot silently select the explicit phrase-only choice.
    pub fn download(
        browser: &OwnerBrowser,
        root: &IdentityRoot,
        phrase: &OwnerPhrase,
        request: BackupRequest,
        prf: Option<&OwnerPrf>,
        parameters: KdfParameters,
    ) -> Result<BackupDownload> {
        parameters.validate()?;
        if request == BackupRequest::ExplicitPhraseOnlyV1 {
            return crate::envelope::owner::seal(browser, root, phrase, parameters)
                .map(BackupDownload::PhraseOnly);
        }
        let prf = prf.ok_or_else(|| refuse("backup-prf-required"))?;
        validate_binding(&prf.binding)?;
        let mut backup = BackupEnvelopeV2 {
            canonical: Vec::new(),
            kdf: parameters,
            salt: [0; super::SALT_BYTES],
            nonce: [0; super::NONCE_BYTES],
            ciphertext: [0; super::CIPHERTEXT_BYTES],
            prf: prf.binding.clone(),
        };
        getrandom::fill(&mut backup.salt).map_err(|_| refuse("random-unavailable"))?;
        getrandom::fill(&mut backup.nonce).map_err(|_| refuse("random-unavailable"))?;
        let key = derive_key(browser, phrase, parameters, &backup.salt, prf)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| refuse("envelope-seal-failed"))?;
        let sealed = cipher
            .encrypt(
                &XNonce::from(backup.nonce),
                Payload {
                    msg: root.bytes(browser),
                    aad: &backup.associated_data()?,
                },
            )
            .map_err(|_| refuse("envelope-seal-failed"))?;
        backup.ciphertext = sealed.try_into().map_err(|_| refuse("envelope-length"))?;
        backup.canonical = backup.encode()?;
        Ok(BackupDownload::PasskeyBound(backup))
    }

    /// Recovery requires the original phrase and credential/RP
    /// PRF result; a different RP's credential cannot be substituted.
    pub fn restore(
        browser: &OwnerBrowser,
        backup: &BackupEnvelopeV2,
        phrase: &OwnerPhrase,
        prf: &OwnerPrf,
    ) -> Result<IdentityRoot> {
        if prf.binding != backup.prf {
            return Err(refuse("backup-prf-metadata"));
        }
        let key = derive_key(browser, phrase, backup.kdf, &backup.salt, prf)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| refuse("envelope-authentication"))?;
        let opened = Zeroizing::new(
            cipher
                .decrypt(
                    &XNonce::from(backup.nonce),
                    Payload {
                        msg: &backup.ciphertext,
                        aad: &backup.associated_data()?,
                    },
                )
                .map_err(|_| refuse("envelope-authentication"))?,
        );
        let mut secret = Zeroizing::new([0; 32]);
        if opened.len() != secret.len() {
            return Err(refuse("envelope-length"));
        }
        secret.copy_from_slice(&opened);
        Ok(IdentityRoot::from_secret(secret))
    }

    fn derive_key(
        browser: &OwnerBrowser,
        phrase: &OwnerPhrase,
        parameters: KdfParameters,
        salt: &[u8; super::SALT_BYTES],
        prf: &OwnerPrf,
    ) -> Result<Zeroizing<[u8; 32]>> {
        let phrase_key = derive_phrase_key(browser, phrase, parameters, salt)?;
        let mut inputs = Zeroizing::new([0; 64]);
        inputs[..32].copy_from_slice(phrase_key.as_ref());
        inputs[32..].copy_from_slice(prf.output.as_ref());
        let hkdf = Hkdf::<Sha256>::new(Some(BACKUP_HKDF_SALT), inputs.as_ref());
        let mut key = Zeroizing::new([0; 32]);
        hkdf.expand(BACKUP_HKDF_INFO, key.as_mut())
            .map_err(|_| refuse("envelope-kdf-failed"))?;
        Ok(key)
    }

    fn put(target: &JsValue, key: &str, value: &JsValue) -> Result<()> {
        if !Reflect::set(target, &JsValue::from_str(key), value)
            .map_err(|_| refuse("backup-prf-unavailable"))?
        {
            return Err(refuse("backup-prf-unavailable"));
        }
        Ok(())
    }

    fn field(value: &JsValue, key: &str) -> Result<JsValue> {
        let field = Reflect::get(value, &JsValue::from_str(key))
            .map_err(|_| refuse("backup-prf-required"))?;
        if field.is_null() || field.is_undefined() {
            return Err(refuse("backup-prf-required"));
        }
        Ok(field)
    }

    fn encode_buffer(value: &ArrayBuffer, maximum: usize) -> Result<String> {
        if value.byte_length() as usize > maximum {
            return Err(refuse("assertion-refused"));
        }
        Ok(URL_SAFE_NO_PAD.encode(Uint8Array::new(value).to_vec()))
    }
}
