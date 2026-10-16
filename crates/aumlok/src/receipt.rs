// SPDX-License-Identifier: AGPL-3.0-or-later
//! Identity-receipt inspection for health after the caller verifies the Aura signature.

use crate::keys::{exact_fields, field, value_text, value_u64};
use base64::{engine::general_purpose::STANDARD, Engine};
use canon::{
    alg::AlgorithmId,
    authority::{AuthorityRecord, Kind, Phase},
    digest::Digest32,
    ids::{OperationId, RequestId, SessionId, SubjectId},
    json::{Value, ValueView},
    Refusal, Result,
};
use sha2::{Digest, Sha256};

const ENROL: &str = "aukora-aumlok-pending-enrolment-v2";
const PENDING_SIGNIN: &str = "aukora-aumlok-pending-signin-v2";
const BIND: &str = "aukora-aumlok-initial-binding-v2";
const SIGNIN: &str = "aukora-aumlok-bound-signin-v2";
const REFRESH: &str = "aukora-aumlok-envelope-refresh-v2";

pub(crate) fn recognizes(payload: &Value) -> bool {
    matches!(
        payload.get("schema").map(Value::view),
        Some(ValueView::Text(
            ENROL | PENDING_SIGNIN | BIND | SIGNIN | REFRESH
        ))
    )
}

/// No authority capability is returned. Counter history remains Aura's replay obligation.
pub fn owner_epoch(record: &AuthorityRecord) -> Result<Option<u64>> {
    let wrapper = aura::record::AuthorityBodyV1::parse(&record.body)?;
    if !recognizes(&wrapper.payload) {
        return Ok(None);
    }
    if wrapper.payload.canonical_bytes().len() > 65536 {
        return Err(invalid());
    }
    if record.v != 1
        || record.algorithm != AlgorithmId::Sha256
        || wrapper.algorithm != record.algorithm
        || wrapper.authority != record.authority
        || record.phase != Phase::Terminal
        || record.at < 0
    {
        return Err(invalid());
    }
    record.c3_v1_export()?;
    let body = &wrapper.payload;
    exact_fields(
        body,
        &[
            "schema",
            "ceremony",
            "subject",
            "context",
            "nonce",
            "issued",
            "deadline",
            "candidate",
            "candidate_digest",
            "payload",
            "assertion",
            "binding",
            "enrolment_sequence",
            "enrolment_hash",
        ],
    )?;
    let schema = text(body, "schema")?;
    let pending = matches!(schema, ENROL | PENDING_SIGNIN);
    let kind = match schema {
        ENROL => Kind::AumlokEnrol,
        BIND | REFRESH => Kind::AumlokBind,
        PENDING_SIGNIN | SIGNIN => Kind::AumlokSignin,
        _ => return Err(invalid()),
    };
    let id = RequestId::from_hex(text(body, "ceremony")?)?;
    let issued = number(body, "issued")?;
    let deadline = number(body, "deadline")?;
    if record.kind != kind
        || record.operation != Some(OperationId::from_bytes(*id.as_bytes()))
        || issued > record.at as u64
        || deadline <= record.at as u64
        || deadline
            .checked_sub(issued)
            .is_none_or(|n| !(1..=300000).contains(&n))
        || pending != (record.authority.epoch == 0)
        || (schema == BIND && record.authority.epoch != 1)
    {
        return Err(invalid());
    }
    let context = field(body, "context")?;
    exact_fields(
        context,
        &[
            "v",
            "rp",
            "owner_origin",
            "top_origin",
            "owner_id",
            "user_handle",
            "session",
            "subject",
            "credential",
            "epoch",
            "sequence",
            "previous_hash",
        ],
    )?;
    let context_epoch = number(context, "epoch")?;
    let sequence = number(context, "sequence")?;
    if number(context, "v")? != 2
        || sequence == 0
        || sequence > record.authority.sequence
        || context_epoch
            != if schema == BIND {
                0
            } else {
                record.authority.epoch
            }
        || text(context, "owner_id")? != record.actor
        || record.actor.is_empty()
        || record.actor.len() > 256
        || record.actor.chars().any(char::is_control)
    {
        return Err(invalid());
    }
    SessionId::from_hex(text(context, "session")?)?;
    match field(context, "previous_hash")?.view() {
        ValueView::Null if sequence == 1 => {}
        ValueView::Text(hash) if sequence > 1 => {
            Digest32::from_hex(hash)?;
        }
        _ => return Err(invalid()),
    }
    let mut binding = aura::storage::owner_binding_from_value(field(body, "binding")?)?;
    if binding.epoch != record.authority.epoch
        || binding.relying_party != text(context, "rp")?
        || binding.owner_origin != text(context, "owner_origin")?
        || binding.top_origin != text(context, "top_origin")?
    {
        return Err(invalid());
    }
    let user = crate::webauthn::decode_base64url(text(context, "user_handle")?, 64)?;
    if user.is_empty() {
        return Err(invalid());
    }
    let nonce: [u8; 32] = standard(text(body, "nonce")?, 32)?
        .try_into()
        .map_err(|_| invalid())?;
    let payload = field(body, "payload")?;
    let candidate = field(body, "candidate")?;
    let (challenge, backup) = if schema == ENROL {
        if !null(body, "subject")?
            || !null(context, "subject")?
            || !null(context, "credential")?
            || !null(body, "enrolment_sequence")?
            || !null(body, "enrolment_hash")?
            || !matches!(payload.view(), ValueView::Null)
        {
            return Err(invalid());
        }
        let candidate = crate::ceremony::pending::receipt_candidate(candidate)?;
        let digest = crate::ceremony::candidate_digest(&candidate)?;
        if text(body, "candidate_digest")? != digest.to_string()
            || binding.credential_id != candidate.credential_id
            || binding.public_key != candidate.public_key
        {
            return Err(invalid());
        }
        binding.sign_counter = candidate.initial_counter;
        let mut hash = Sha256::new();
        hash.update(b"aukora:enrol-possession:v1\0");
        hash.update(id.to_string().as_bytes());
        hash.update(digest.as_bytes());
        (hash.finalize().into(), candidate.backup_eligible)
    } else {
        if !matches!(candidate.view(), ValueView::Null)
            || !null(body, "candidate_digest")?
            || number(body, "enrolment_sequence")? == 0
            || number(body, "enrolment_sequence")? >= record.authority.sequence
            || crate::webauthn::decode_base64url(text(context, "credential")?, 1023)?
                != binding.credential_id.as_bytes()
        {
            return Err(invalid());
        }
        Digest32::from_hex(text(body, "enrolment_hash")?)?;
        let challenge = if matches!(schema, BIND | REFRESH) {
            public_identity(body, context, schema)?;
            let mut hash = Sha256::new();
            hash.update(if schema == BIND {
                b"aukora:aumlok-binding:v2\0".as_slice()
            } else {
                b"aukora:aumlok-refresh:v2\0".as_slice()
            });
            hash.update(nonce);
            hash.update(payload.canonical_bytes());
            hash.finalize().into()
        } else {
            if !matches!(payload.view(), ValueView::Null) {
                return Err(invalid());
            }
            if schema == PENDING_SIGNIN {
                if !null(body, "subject")? || !null(context, "subject")? {
                    return Err(invalid());
                }
            } else if SubjectId::parse(text(body, "subject")?)?
                != SubjectId::parse(text(context, "subject")?)?
            {
                return Err(invalid());
            }
            nonce
        };
        binding.sign_counter = 0;
        let auth = crate::webauthn::decode_base64url(
            text(field(body, "assertion")?, "authenticator_data")?,
            37,
        )?;
        if auth.len() != 37 {
            return Err(invalid());
        }
        (challenge, auth[32] & 8 != 0)
    };
    let recorded_counter =
        aura::storage::owner_binding_from_value(field(body, "binding")?)?.sign_counter;
    let assertion =
        crate::webauthn::decode_assertion(&field(body, "assertion")?.canonical_bytes())?;
    let origins = crate::webauthn::OriginContext {
        relying_party: binding.relying_party.clone(),
        owner_origin: binding.owner_origin.clone(),
        expected_top_origin: Some(binding.top_origin.clone()),
    };
    let credential = crate::webauthn::Credential {
        version: 1,
        binding,
        owner_id: record.actor.clone(),
        user_handle: user,
        backup_eligible: backup,
    };
    if crate::webauthn::inspect_assertion(
        &assertion,
        &credential,
        &origins,
        &challenge,
        crate::webauthn::ExtensionPolicy::None,
    )?
    .counter()
        != recorded_counter
    {
        return Err(invalid());
    }
    Ok(Some(record.authority.epoch))
}

fn public_identity(body: &Value, context: &Value, schema: &str) -> Result<()> {
    let payload = field(body, "payload")?;
    let mut names = vec!["v", "subject", "identity_public_key", "envelope"];
    if schema == REFRESH {
        names.push("previous_envelope_sha256");
    }
    exact_fields(payload, &names)?;
    if number(payload, "v")? != 2 {
        return Err(invalid());
    }
    let subject = SubjectId::parse(text(payload, "subject")?)?;
    if SubjectId::parse(text(body, "subject")?)? != subject
        || (schema == BIND && !null(context, "subject")?)
        || (schema == REFRESH && SubjectId::parse(text(context, "subject")?)? != subject)
    {
        return Err(invalid());
    }
    let public = standard(text(payload, "identity_public_key")?, 32)?;
    let mut hash = Sha256::new();
    hash.update(crate::envelope::SUBJECT_DOMAIN);
    hash.update(&public);
    if subject != SubjectId::from_digest(Digest32::from_bytes(hash.finalize().into())) {
        return Err(invalid());
    }
    let public: &[u8; 32] = public.as_slice().try_into().map_err(|_| invalid())?;
    if ed25519_dalek::VerifyingKey::from_bytes(public)
        .map_err(|_| invalid())?
        .is_weak()
    {
        return Err(invalid());
    }
    crate::envelope::EnvelopeV1::from_canonical_bytes(
        &field(payload, "envelope")?.canonical_bytes(),
    )?;
    if schema == REFRESH {
        Digest32::from_hex(text(payload, "previous_envelope_sha256")?)?;
    }
    Ok(())
}

fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value_text(field(value, name)?)
}
fn number(value: &Value, name: &str) -> Result<u64> {
    value_u64(field(value, name)?)
}
fn null(value: &Value, name: &str) -> Result<bool> {
    Ok(matches!(field(value, name)?.view(), ValueView::Null))
}
fn standard(encoded: &str, width: usize) -> Result<Vec<u8>> {
    if encoded.len() > width * 2 + 4 {
        return Err(invalid());
    }
    let bytes = STANDARD.decode(encoded).map_err(|_| invalid())?;
    if bytes.len() != width || STANDARD.encode(&bytes) != encoded {
        return Err(invalid());
    }
    Ok(bytes)
}
fn invalid() -> Refusal {
    Refusal {
        organ: "aumlok",
        reason: "health-record-format",
    }
}
