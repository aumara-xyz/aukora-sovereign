// SPDX-License-Identifier: AGPL-3.0-or-later
//! Durable ceremony v2 codecs retain the legacy credential candidate format.

use super::*;
use base64::engine::general_purpose::STANDARD;
use canon::alg::{AlgorithmId, PublicKey};
use serde::{Deserialize, Serialize};

pub(super) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS aumlok_ceremonies_v2(
 id BLOB PRIMARY KEY CHECK(length(id)=16),
 purpose TEXT NOT NULL CHECK(purpose IN ('enrolment','binding','signin','refresh')),
 state TEXT NOT NULL CHECK(state IN ('fresh','registered','prepared','spent','finished','expired')),
 context TEXT NOT NULL, nonce BLOB NOT NULL UNIQUE CHECK(length(nonce)=32),
 issued INTEGER NOT NULL CHECK(issued>=0),deadline INTEGER NOT NULL,last_seen INTEGER NOT NULL,
 candidate TEXT,candidate_digest BLOB,payload TEXT,
 CHECK(deadline>issued AND deadline-issued<=300000 AND last_seen>=issued),
 CHECK(candidate_digest IS NULL OR length(candidate_digest)=32),
 CHECK((candidate IS NULL)=(candidate_digest IS NULL)),
 CHECK(state!='registered' OR (purpose='enrolment' AND candidate IS NOT NULL)),
 CHECK(state!='prepared' OR (purpose IN ('binding','refresh') AND payload IS NOT NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS aumlok_ceremony_active_enrol_v2
 ON aumlok_ceremonies_v2(purpose) WHERE purpose='enrolment' AND state!='expired';
CREATE UNIQUE INDEX IF NOT EXISTS aumlok_ceremony_active_session_v2
 ON aumlok_ceremonies_v2(purpose,json_extract(context,'$.session'))
 WHERE state IN ('fresh','registered','prepared');
CREATE TRIGGER IF NOT EXISTS aumlok_ceremony_retain_v2 BEFORE DELETE ON aumlok_ceremonies_v2
 BEGIN SELECT RAISE(ABORT,'aumlok:ceremony-retained'); END;
CREATE TRIGGER IF NOT EXISTS aumlok_ceremony_new_v2 BEFORE INSERT ON aumlok_ceremonies_v2
 WHEN NEW.state!='fresh' OR NEW.candidate IS NOT NULL OR NEW.payload IS NOT NULL
 BEGIN SELECT RAISE(ABORT,'aumlok:ceremony-state'); END;
CREATE TRIGGER IF NOT EXISTS aumlok_ceremony_forward_v2 BEFORE UPDATE ON aumlok_ceremonies_v2
 WHEN NEW.id IS NOT OLD.id OR NEW.purpose IS NOT OLD.purpose OR NEW.context IS NOT OLD.context
 OR NEW.nonce IS NOT OLD.nonce OR NEW.issued IS NOT OLD.issued OR NEW.deadline IS NOT OLD.deadline
 OR NEW.last_seen<OLD.last_seen
 OR (OLD.candidate IS NOT NULL AND (NEW.candidate IS NOT OLD.candidate OR NEW.candidate_digest IS NOT OLD.candidate_digest))
 OR (OLD.payload IS NOT NULL AND NEW.payload IS NOT OLD.payload)
 OR (OLD.candidate IS NULL AND NEW.candidate IS NOT NULL AND NOT(OLD.state='fresh' AND NEW.state='registered'))
 OR (OLD.payload IS NULL AND NEW.payload IS NOT NULL AND NOT(OLD.state='fresh' AND NEW.state='prepared'))
 OR NOT(NEW.state=OLD.state OR (OLD.state='fresh' AND NEW.state IN ('registered','prepared','spent','expired'))
 OR (OLD.state IN ('registered','prepared') AND NEW.state IN ('spent','expired')) OR (OLD.state='spent' AND NEW.state='finished'))
 BEGIN SELECT RAISE(ABORT,'aumlok:ceremony-rewind'); END;
"#;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextWire {
    v: u16,
    rp: String,
    owner_origin: String,
    top_origin: String,
    owner_id: String,
    user_handle: String,
    session: String,
    subject: Option<String>,
    credential: Option<String>,
    epoch: u64,
    sequence: u64,
    previous_hash: Option<String>,
}

pub(super) fn canonical(value: &serde_json::Value) -> Result<String> {
    let bytes = serde_json::to_vec(value).map_err(|_| refusal("ceremony-data-invalid"))?;
    String::from_utf8(canon::json::parse_strict(&bytes)?.canonical_bytes())
        .map_err(|_| refusal("ceremony-data-invalid"))
}

pub(super) fn context_json(context: &Context) -> Result<String> {
    canonical(
        &serde_json::to_value(ContextWire {
            v: 2,
            rp: context.origins.relying_party.clone(),
            owner_origin: context.origins.owner_origin.clone(),
            top_origin: context
                .origins
                .expected_top_origin
                .clone()
                .ok_or_else(|| refusal("top-origin-invalid"))?,
            owner_id: context.identity.owner_id.clone(),
            user_handle: URL_SAFE_NO_PAD.encode(&context.identity.user_handle),
            session: context.session.to_string(),
            subject: context.subject.map(|s| s.to_string()),
            credential: context
                .credential
                .as_ref()
                .map(|id| URL_SAFE_NO_PAD.encode(id.as_bytes())),
            epoch: context.authority.epoch,
            sequence: context.authority.sequence,
            previous_hash: context.authority.previous_hash.map(|h| h.to_string()),
        })
        .map_err(|_| refusal("ceremony-data-invalid"))?,
    )
}

pub(super) fn parse_context(encoded: &str) -> Result<Context> {
    let value = canon::json::parse_strict(encoded.as_bytes())?;
    if value.canonical_bytes() != encoded.as_bytes() {
        return Err(refusal("store-corrupt"));
    }
    let wire: ContextWire = serde_json::from_str(encoded).map_err(|_| refusal("store-corrupt"))?;
    if wire.v != 2 || wire.sequence == 0 || (wire.sequence == 1) != wire.previous_hash.is_none() {
        return Err(refusal("store-corrupt"));
    }
    let context = Context {
        origins: OriginContext {
            relying_party: wire.rp,
            owner_origin: wire.owner_origin,
            expected_top_origin: Some(wire.top_origin),
        },
        identity: EnrolmentIdentity {
            owner_id: wire.owner_id,
            user_handle: crate::webauthn::decode_base64url(&wire.user_handle, 64)?,
        },
        session: SessionId::from_hex(&wire.session)?,
        subject: wire.subject.as_deref().map(SubjectId::parse).transpose()?,
        credential: wire
            .credential
            .as_deref()
            .map(|s| CredentialId::new(crate::webauthn::decode_base64url(s, 1023)?))
            .transpose()?,
        authority: AuthorityVersion {
            epoch: wire.epoch,
            sequence: wire.sequence,
            previous_hash: wire
                .previous_hash
                .as_deref()
                .map(Digest32::from_hex)
                .transpose()?,
        },
    };
    crate::webauthn::validate_origins(&context.origins)?;
    validate_identity(&context.identity)?;
    Ok(context)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateWire {
    v: u16,
    credential_id: String,
    algorithm: String,
    key_version: u16,
    public_key: String,
    initial_counter: u32,
    backup_eligible: bool,
    backup_state: bool,
    aaguid: String,
    client_data_digest: String,
    attestation_digest: String,
}

pub(super) fn parse_candidate(encoded: &str) -> Result<RegistrationCandidate> {
    let value = canon::json::parse_strict(encoded.as_bytes())?;
    if value.canonical_bytes() != encoded.as_bytes() {
        return Err(refusal("store-corrupt"));
    }
    let wire: CandidateWire =
        serde_json::from_str(encoded).map_err(|_| refusal("store-corrupt"))?;
    let algorithm = AlgorithmId::from_wire(&wire.algorithm)?;
    if wire.v != 1
        || wire.key_version != 1
        || !matches!(
            algorithm,
            AlgorithmId::Ed25519 | AlgorithmId::EcdsaP256Sha256
        )
    {
        return Err(refusal("store-corrupt"));
    }
    fn bytes(s: &str) -> Result<Vec<u8>> {
        let bytes = hex::decode(s).map_err(|_| refusal("store-corrupt"))?;
        if hex::encode(&bytes) != s {
            return Err(refusal("store-corrupt"));
        }
        Ok(bytes)
    }
    Ok(RegistrationCandidate {
        credential_id: CredentialId::new(bytes(&wire.credential_id)?)?,
        public_key: PublicKey {
            v: 1,
            algorithm,
            bytes: bytes(&wire.public_key)?,
        },
        initial_counter: wire.initial_counter,
        backup_eligible: wire.backup_eligible,
        backup_state: wire.backup_state,
        aaguid: bytes(&wire.aaguid)?
            .try_into()
            .map_err(|_| refusal("store-corrupt"))?,
        client_data_digest: Digest32::from_hex(&wire.client_data_digest)?,
        attestation_digest: Digest32::from_hex(&wire.attestation_digest)?,
    })
}

pub(super) fn validate_payload(
    payload: &Value,
    purpose: CeremonyPurpose,
    expected: Option<SubjectId>,
) -> Result<()> {
    let raw = payload.canonical_bytes();
    if raw.len() > 8192 {
        return Err(refusal("ceremony-data-invalid"));
    }
    let json: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|_| refusal("ceremony-data-invalid"))?;
    let object = json
        .as_object()
        .ok_or_else(|| refusal("ceremony-data-invalid"))?;
    let keys: &[&str] = if purpose == CeremonyPurpose::Binding {
        &["v", "subject", "identity_public_key", "envelope"]
    } else {
        &[
            "v",
            "subject",
            "identity_public_key",
            "envelope",
            "previous_envelope_sha256",
        ]
    };
    if object.len() != keys.len() || keys.iter().any(|k| !object.contains_key(*k)) || json["v"] != 2
    {
        return Err(refusal("ceremony-data-invalid"));
    }
    let subject = SubjectId::parse(
        json["subject"]
            .as_str()
            .ok_or_else(|| refusal("ceremony-subject"))?,
    )?;
    if expected.is_some_and(|s| s != subject) {
        return Err(refusal("ceremony-subject"));
    }
    let encoded = json["identity_public_key"]
        .as_str()
        .ok_or_else(|| refusal("binding-root-key"))?;
    let public = STANDARD
        .decode(encoded)
        .map_err(|_| refusal("binding-root-key"))?;
    if public.len() != 32 || STANDARD.encode(&public) != encoded {
        return Err(refusal("binding-root-key"));
    }
    let mut digest = Sha256::new();
    digest.update(crate::envelope::SUBJECT_DOMAIN);
    digest.update(&public);
    if subject != SubjectId::from_digest(Digest32::from_bytes(digest.finalize().into())) {
        return Err(refusal("binding-subject"));
    }
    let key: &[u8; 32] = public
        .as_slice()
        .try_into()
        .map_err(|_| refusal("binding-root-key"))?;
    if ed25519_dalek::VerifyingKey::from_bytes(key)
        .map_err(|_| refusal("binding-root-key"))?
        .is_weak()
    {
        return Err(refusal("binding-root-key"));
    }
    crate::envelope::EnvelopeV1::from_canonical_bytes(canonical(&json["envelope"])?.as_bytes())?;
    if purpose == CeremonyPurpose::Refresh {
        Digest32::from_hex(
            json["previous_envelope_sha256"]
                .as_str()
                .ok_or_else(|| refusal("refresh-input"))?,
        )?;
    }
    Ok(())
}
