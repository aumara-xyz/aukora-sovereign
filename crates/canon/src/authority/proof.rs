// SPDX-License-Identifier: AGPL-3.0-or-later
//! Passkey proof construction bound to the active authority transaction.

use super::*;
use crate::{codes, domain};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

mod client;

pub(super) fn verify<T: AuthorityTxn + ?Sized>(
    txn: &mut T,
    proposal: &ProposalId,
    action: OwnerOperation,
    assertion: OwnerAssertion,
) -> Result<VerifiedProof> {
    let invalid = codes::GATE_PROOF_INVALID;
    let transaction_id = txn.transaction_id();
    let binding = txn.owner_binding(&assertion.credential_id)?;
    let authorization = txn.rebuild_authorization(proposal, action)?;
    if authorization.proposal != *proposal || authorization.op != action {
        return Err(codes::GATE_AUTHORIZATION_MISMATCH);
    }
    if authorization.epoch != binding.epoch {
        return Err(codes::GATE_OWNER_EPOCH);
    }
    if assertion.credential_id != binding.credential_id {
        return Err(codes::GATE_CREDENTIAL_MISMATCH);
    }
    if assertion.v != 1
        || binding.v != 1
        || binding.public_key.v != 1
        || assertion.signature.v != 1
        || binding.algorithm != binding.public_key.algorithm
        || binding.algorithm != assertion.algorithm
        || assertion.algorithm != assertion.signature.algorithm
        || !matches!(
            assertion.algorithm,
            AlgorithmId::Ed25519 | AlgorithmId::EcdsaP256Sha256
        )
    {
        return Err(codes::ALG_UNSUPPORTED);
    }
    let auth_data = &assertion.authenticator_data;
    if auth_data.len() != 37
        || assertion.client_data_json.len() > 16_384
        || assertion.signature.bytes.is_empty()
        || assertion.signature.bytes.len() > 128
        || binding.relying_party.is_empty()
        || binding.owner_origin.is_empty()
        || binding.top_origin.is_empty()
    {
        return Err(invalid);
    }
    let flags = auth_data[32];
    if flags & 5 != 5
        || flags & 0xe2 != 0
        || flags & 16 != 0 && flags & 8 == 0
        || auth_data[..32] != Digest32::sha256(binding.relying_party.as_bytes()).as_bytes()[..]
    {
        return Err(invalid);
    }
    let sign_counter = u32::from_be_bytes(auth_data[33..37].try_into().map_err(|_| invalid)?);
    if binding.sign_counter != 0 && sign_counter <= binding.sign_counter {
        return Err(codes::GATE_COUNTER_REPLAY);
    }
    let authorization_bytes = authorization.canonical_bytes()?;
    let mut challenge_preimage = domain::OWNER_AUTHORIZATION_DOMAIN.as_bytes().to_vec();
    challenge_preimage.push(0);
    challenge_preimage.extend_from_slice(&authorization_bytes);
    let challenge = URL_SAFE_NO_PAD.encode(Digest32::sha256(&challenge_preimage).as_bytes());
    let client = client::parse(&assertion.client_data_json)?;
    if client.get("type").and_then(serde_json::Value::as_str) != Some("webauthn.get")
        || client.get("challenge").and_then(serde_json::Value::as_str) != Some(challenge.as_str())
        || client.get("origin").and_then(serde_json::Value::as_str)
            != Some(binding.owner_origin.as_str())
        || client
            .get("crossOrigin")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
        || client.get("topOrigin").and_then(serde_json::Value::as_str)
            != Some(binding.top_origin.as_str())
    {
        return Err(invalid);
    }
    txn.check_authorization_live(&authorization)?;
    let authenticator_data_digest = Digest32::sha256(auth_data);
    let client_data_digest = Digest32::sha256(&assertion.client_data_json);
    let mut signed_bytes = auth_data.clone();
    signed_bytes.extend_from_slice(client_data_digest.as_bytes());
    txn.verify_signature(&binding.public_key, &signed_bytes, &assertion.signature)?;
    if txn.transaction_id() != transaction_id {
        return Err(codes::AURA_TRANSACTION);
    }
    Ok(VerifiedProof {
        credential_id: binding.credential_id,
        algorithm: assertion.algorithm,
        sign_counter,
        authenticator_data_digest,
        client_data_digest,
        signed_bytes_digest: Digest32::sha256(&signed_bytes),
        top_origin: binding.top_origin,
        assertion,
        authorization,
        authorization_bytes,
        signed_bytes,
        public_key: binding.public_key,
        transaction_id,
    })
}
