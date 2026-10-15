// SPDX-License-Identifier: AGPL-3.0-or-later
//! Frozen authority-object encodings; wrapper metadata never enters v1 wire bytes.

use super::*;
use crate::{
    codes, domain,
    json::{self, SafeInteger},
};
use base64::{engine::general_purpose::STANDARD, Engine};

fn text(value: impl ToString) -> Result<Value> {
    Value::text(value.to_string())
}

fn number(value: u64) -> Result<Value> {
    let value = i64::try_from(value).map_err(|_| codes::FRAME_INVALID_FIELD)?;
    Ok(Value::integer(SafeInteger::new(value)?))
}

fn object(fields: Vec<(&str, Value)>) -> Result<Value> {
    Value::object(
        fields
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

fn cell(value: Option<CellCommitment>) -> Result<Value> {
    match value {
        None => Ok(Value::null()),
        Some(value) => object(vec![
            ("module_sha256", text(value.module_sha256)?),
            ("input_sha256", text(value.input_sha256)?),
            ("effect_sha256", text(value.effect_sha256)?),
        ]),
    }
}

fn base(value: BaseDigest) -> Result<Value> {
    match value {
        BaseDigest::Absent => text("absent"),
        BaseDigest::Present(digest) => text(digest),
    }
}

pub(super) fn card(card: &Card) -> Result<Vec<u8>> {
    if card.v != 1
        || card
            .says
            .chars()
            .any(|c| matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}'))
    {
        return Err(codes::FRAME_INVALID_FIELD);
    }
    let facts = card
        .facts
        .iter()
        .map(|(label, value)| Value::array(vec![text(label)?, value.clone()]))
        .collect::<Result<Vec<_>>>()?;
    Ok(json::to_canonical(&object(vec![
        ("v", number(1)?),
        ("risk", text(card.risk.wire_name())?),
        ("says", text(&card.says)?),
        ("facts", Value::array(facts)?),
        ("from_to", Value::object(card.from_to.clone())?),
        ("model_note", text(&card.model_note)?),
    ])?))
}

pub(super) fn authorization(auth: &OwnerAuthorization) -> Result<Vec<u8>> {
    if auth.algorithm != AlgorithmId::Sha256 {
        return Err(codes::ALG_UNSUPPORTED);
    }
    if auth.v != 1 || auth.target.is_empty() || auth.expires_at < 0 {
        return Err(codes::FRAME_INVALID_FIELD);
    }
    let operation = object(vec![
        ("v", number(1)?),
        ("node", text(auth.node)?),
        ("target", text(&auth.target)?),
        ("base_sha256", base(auth.base_sha256)?),
        ("new_sha256", text(auth.new_sha256)?),
        ("cell", cell(auth.cell)?),
    ])?;
    let mut operation_preimage = domain::OPERATION_CONTENT_DOMAIN.as_bytes().to_vec();
    operation_preimage.push(0);
    operation_preimage.extend(json::to_canonical(&operation));
    if Digest32::sha256(&operation_preimage).as_bytes() != auth.operation.digest().as_bytes() {
        return Err(codes::GATE_AUTHORIZATION_MISMATCH);
    }
    Ok(json::to_canonical(&object(vec![
        ("v", number(1)?),
        ("node", text(auth.node)?),
        ("subject", text(auth.subject)?),
        ("op", text(auth.op.wire_name())?),
        ("proposal", text(auth.proposal)?),
        ("target", text(&auth.target)?),
        ("base_sha256", base(auth.base_sha256)?),
        ("new_sha256", text(auth.new_sha256)?),
        ("cell", cell(auth.cell)?),
        ("display_sha256", text(auth.display_sha256)?),
        ("challenge", text(auth.challenge)?),
        (
            "expires_at",
            Value::integer(SafeInteger::new(auth.expires_at)?),
        ),
        ("epoch", number(auth.epoch)?),
        ("operation", text(auth.operation)?),
    ])?))
}

pub(super) fn export(record: &AuthorityRecord) -> Result<Value> {
    if record.v != 1 || record.signatures.version() != 1 {
        return Err(codes::FRAME_UNSUPPORTED_VERSION);
    }
    if record.algorithm != AlgorithmId::Sha256 {
        return Err(codes::ALG_UNSUPPORTED);
    }
    if record.authority.sequence == 0
        || (record.authority.sequence == 1) != record.authority.previous_hash.is_none()
        || (record.operation.is_none() && record.phase != Phase::Fact)
    {
        return Err(codes::FRAME_INVALID_FIELD);
    }
    number(record.authority.epoch)?;
    let mut algorithms = std::collections::BTreeSet::new();
    let mut ed25519 = None;
    for component in record.signatures.components() {
        if component.v != 1
            || !algorithms.insert(component.algorithm)
            || !matches!(
                component.algorithm,
                AlgorithmId::Ed25519
                    | AlgorithmId::EcdsaP256Sha256
                    | AlgorithmId::Secp256k1Schnorr
                    | AlgorithmId::MlDsa65
            )
        {
            return Err(codes::FRAME_INVALID_FIELD);
        }
        if component.algorithm == AlgorithmId::Ed25519 {
            if component.bytes.len() != 64 {
                return Err(codes::FRAME_INVALID_FIELD);
            }
            ed25519 = Some(STANDARD.encode(&component.bytes));
        }
    }
    let signature = ed25519.ok_or(codes::FRAME_INVALID_FIELD)?;
    let previous = record
        .authority
        .previous_hash
        .map(|digest| digest.to_string())
        .unwrap_or_else(|| domain::AURA_RECORD_DOMAIN.to_owned());
    let operation = record
        .operation
        .map(|id| id.to_string())
        .unwrap_or_default();
    let common = vec![
        ("prev", text(&previous)?),
        ("at", Value::integer(SafeInteger::new(record.at)?)),
        ("kind", text(record.kind.wire_name())?),
        ("actor", text(&record.actor)?),
        ("op", text(&operation)?),
        ("phase", text(record.phase.wire_name())?),
        ("body", record.body.clone()),
    ];
    let mut hash_fields = common.clone();
    hash_fields.push(("sequence", number(record.authority.sequence)?));
    hash_fields.push(("domain", text(domain::AURA_RECORD_DOMAIN)?));
    if Digest32::sha256(&json::to_canonical(&object(hash_fields)?)) != record.hash {
        return Err(codes::AURA_UNVERIFIED);
    }
    let mut wire = common;
    wire.extend([
        ("seq", number(record.authority.sequence)?),
        ("hash", text(record.hash)?),
        ("sig", text(signature)?),
    ]);
    object(wire)
}
