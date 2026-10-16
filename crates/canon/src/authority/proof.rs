// SPDX-License-Identifier: AGPL-3.0-or-later
//! Passkey proof construction bound to the active authority transaction.

use super::*;
use crate::{codes, domain};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

mod client;

impl OwnerAssertion {
    /// Check a caller's exact challenge against the transaction's anchored owner.
    /// This creates no proof capability and neither consumes nor persists a counter.
    pub fn verify_challenge<T: AuthorityTxn + ?Sized>(
        &self,
        txn: &mut T,
        challenge: &[u8; 32],
    ) -> Result<OwnerBinding> {
        let binding = txn.owner_binding(&self.credential_id)?;
        if self.v != 1
            || binding.v != 1
            || self.credential_id != binding.credential_id
            || self.algorithm != binding.algorithm
            || self.algorithm != binding.public_key.algorithm
            || self.signature.v != 1
            || self.signature.algorithm != binding.algorithm
        {
            return Err(codes::GATE_CREDENTIAL_MISMATCH);
        }
        let authenticator = Authenticator::read(self, &binding)?;
        verify_ceremony_client_data(&self.client_data_json, challenge, &binding)?;
        let message = authenticator.signature_message(Digest32::sha256(&self.client_data_json));
        txn.verify_signature(&binding.public_key, &message, &self.signature)?;
        Ok(binding)
    }
}

/// Validate framed possession client data against a locked ceremony challenge.
/// This checks context only; callers must verify the original signature bytes.
pub fn verify_ceremony_client_data(
    raw: &[u8],
    challenge: &[u8; 32],
    binding: &OwnerBinding,
) -> Result<()> {
    if raw.len() > 16_384 || binding.owner_origin.is_empty() || binding.top_origin.is_empty() {
        return Err(codes::GATE_PROOF_INVALID);
    }
    let fields = client::parse(raw)?;
    let challenge = URL_SAFE_NO_PAD.encode(challenge);
    for (field, expected) in [
        ("type", "webauthn.get"),
        ("challenge", challenge.as_str()),
        ("origin", binding.owner_origin.as_str()),
        ("topOrigin", binding.top_origin.as_str()),
    ] {
        if fields.get(field).and_then(serde_json::Value::as_str) != Some(expected) {
            return Err(codes::GATE_PROOF_INVALID);
        }
    }
    if fields.get("crossOrigin").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err(codes::GATE_PROOF_INVALID);
    }
    Ok(())
}

/// Recheck an already committed assertion without exporting an authority capability.
/// The caller supplies its authenticated historical binding and authorization.
pub fn verify_retained_owner_assertion(
    binding: OwnerBinding,
    authorization: OwnerAuthorization,
    assertion: OwnerAssertion,
    verify_signature: impl Fn(&PublicKey, &[u8], &Signature) -> Result<()>,
) -> Result<()> {
    struct Replay<F> {
        binding: OwnerBinding,
        authorization: OwnerAuthorization,
        identity: Digest32,
        verifier: F,
    }
    impl<F: Fn(&PublicKey, &[u8], &Signature) -> Result<()>> AuthorityTxn for Replay<F> {
        fn transaction_id(&self) -> Digest32 {
            self.identity
        }
        fn owner_binding(&mut self, credential: &CredentialId) -> Result<OwnerBinding> {
            if credential != &self.binding.credential_id {
                return Err(codes::GATE_CREDENTIAL_MISMATCH);
            }
            Ok(self.binding.clone())
        }
        fn rebuild_authorization(
            &mut self,
            proposal: &ProposalId,
            action: OwnerOperation,
        ) -> Result<OwnerAuthorization> {
            if proposal != &self.authorization.proposal || action != self.authorization.op {
                return Err(codes::GATE_AUTHORIZATION_MISMATCH);
            }
            Ok(self.authorization.clone())
        }
        fn check_authorization_live(&mut self, authorization: &OwnerAuthorization) -> Result<()> {
            if authorization != &self.authorization {
                return Err(codes::GATE_AUTHORIZATION_MISMATCH);
            }
            Ok(())
        }
        fn verify_signature(
            &mut self,
            key: &PublicKey,
            bytes: &[u8],
            signature: &Signature,
        ) -> Result<()> {
            (self.verifier)(key, bytes, signature)
        }
        fn persist_counter(&mut self, _: &VerifiedProof) -> Result<()> {
            Err(codes::AURA_TRANSACTION)
        }
        fn consume(&mut self, _: &VerifiedProof) -> Result<()> {
            Err(codes::AURA_TRANSACTION)
        }
        fn append(
            &mut self,
            _: VerifiedProof,
            _: PendingAuthorityRecord,
        ) -> Result<AuthorityRecord> {
            Err(codes::AURA_TRANSACTION)
        }
        fn check_standing_use(
            &mut self,
            _: &ProposalId,
            _: Digest32,
            _: &ProposalId,
            _: OwnerOperation,
        ) -> Result<StandingUseContext> {
            Err(codes::AURA_TRANSACTION)
        }
        fn append_standing(
            &mut self,
            _: VerifiedStandingUse,
            _: PendingAuthorityRecord,
        ) -> Result<AuthorityRecord> {
            Err(codes::AURA_TRANSACTION)
        }
        fn append_lifecycle(&mut self, _: LifecycleRecord) -> Result<AuthorityRecord> {
            Err(codes::AURA_TRANSACTION)
        }
        fn append_fact(&mut self, _: FactRecord) -> Result<AuthorityRecord> {
            Err(codes::AURA_TRANSACTION)
        }
    }
    let proposal = authorization.proposal;
    let action = authorization.op;
    let identity = Digest32::sha256(&authorization.canonical_bytes()?);
    let mut replay = Replay {
        binding,
        authorization,
        identity,
        verifier: verify_signature,
    };
    verify(&mut replay, &proposal, action, assertion).map(|_| ())
}

struct BoundOperation {
    transaction_id: Digest32,
    binding: OwnerBinding,
    authorization: OwnerAuthorization,
}

impl BoundOperation {
    fn load<T: AuthorityTxn + ?Sized>(
        txn: &mut T,
        proposal: &ProposalId,
        action: OwnerOperation,
        assertion: &OwnerAssertion,
    ) -> Result<Self> {
        let transaction_id = txn.transaction_id();
        let binding = txn.owner_binding(&assertion.credential_id)?;
        let authorization = txn.rebuild_authorization(proposal, action)?;
        if (authorization.proposal, authorization.op) != (*proposal, action) {
            return Err(codes::GATE_AUTHORIZATION_MISMATCH);
        }
        if binding.epoch != authorization.epoch {
            return Err(codes::GATE_OWNER_EPOCH);
        }
        if binding.credential_id != assertion.credential_id {
            return Err(codes::GATE_CREDENTIAL_MISMATCH);
        }
        let tags = [
            (binding.v, binding.algorithm),
            (binding.public_key.v, binding.public_key.algorithm),
            (assertion.v, assertion.algorithm),
            (assertion.signature.v, assertion.signature.algorithm),
        ];
        match binding.algorithm {
            AlgorithmId::Ed25519 | AlgorithmId::EcdsaP256Sha256
                if tags.iter().all(|tag| *tag == (1, binding.algorithm)) => {}
            _ => return Err(codes::ALG_UNSUPPORTED),
        }
        Ok(Self {
            transaction_id,
            binding,
            authorization,
        })
    }
}

struct Authenticator<'a> {
    bytes: &'a [u8; 37],
    counter: u32,
}

impl<'a> Authenticator<'a> {
    fn read(assertion: &'a OwnerAssertion, binding: &OwnerBinding) -> Result<Self> {
        let bytes: &[u8; 37] = assertion
            .authenticator_data
            .as_slice()
            .try_into()
            .map_err(|_| codes::GATE_PROOF_INVALID)?;
        if assertion.client_data_json.len() > 16_384
            || !(1..=128).contains(&assertion.signature.bytes.len())
            || [
                &binding.relying_party,
                &binding.owner_origin,
                &binding.top_origin,
            ]
            .iter()
            .any(|value| value.is_empty())
        {
            return Err(codes::GATE_PROOF_INVALID);
        }
        // UP and UV are required; only eligible credentials may set backup state.
        if !matches!(bytes[32], 0x05 | 0x0d | 0x1d) {
            return Err(codes::GATE_PROOF_INVALID);
        }
        let rp_digest = Digest32::sha256(binding.relying_party.as_bytes());
        if bytes[..32] != rp_digest.as_bytes()[..] {
            return Err(codes::GATE_PROOF_INVALID);
        }
        let counter = u32::from_be_bytes([bytes[33], bytes[34], bytes[35], bytes[36]]);
        match (binding.sign_counter, counter) {
            (0, _) => {}
            (previous, current) if current > previous => {}
            _ => return Err(codes::GATE_COUNTER_REPLAY),
        }
        Ok(Self { bytes, counter })
    }

    fn signature_message(&self, client_digest: Digest32) -> [u8; 69] {
        let mut message = [0; 69];
        message[..37].copy_from_slice(self.bytes);
        message[37..].copy_from_slice(client_digest.as_bytes());
        message
    }
}

fn check_ceremony(raw: &[u8], binding: &OwnerBinding, authorization: &[u8]) -> Result<()> {
    let challenge_bytes = [
        domain::OWNER_AUTHORIZATION_DOMAIN.as_bytes(),
        &[0],
        authorization,
    ]
    .concat();
    let challenge = URL_SAFE_NO_PAD.encode(Digest32::sha256(&challenge_bytes).as_bytes());
    let fields = client::parse(raw)?;
    for (name, expected) in [
        ("type", "webauthn.get"),
        ("challenge", challenge.as_str()),
        ("origin", binding.owner_origin.as_str()),
        ("topOrigin", binding.top_origin.as_str()),
    ] {
        if fields.get(name).and_then(serde_json::Value::as_str) != Some(expected) {
            return Err(codes::GATE_PROOF_INVALID);
        }
    }
    match fields.get("crossOrigin") {
        Some(serde_json::Value::Bool(true)) => Ok(()),
        _ => Err(codes::GATE_PROOF_INVALID),
    }
}

pub(super) fn verify<T: AuthorityTxn + ?Sized>(
    txn: &mut T,
    proposal: &ProposalId,
    action: OwnerOperation,
    assertion: OwnerAssertion,
) -> Result<VerifiedProof> {
    let BoundOperation {
        transaction_id,
        binding,
        authorization,
    } = BoundOperation::load(txn, proposal, action, &assertion)?;
    let authenticator = Authenticator::read(&assertion, &binding)?;
    let authorization_bytes = authorization.canonical_bytes()?;
    check_ceremony(&assertion.client_data_json, &binding, &authorization_bytes)?;
    txn.check_authorization_live(&authorization)?;
    let client_data_digest = Digest32::sha256(&assertion.client_data_json);
    let message = authenticator.signature_message(client_data_digest);
    txn.verify_signature(&binding.public_key, &message, &assertion.signature)?;
    if transaction_id != txn.transaction_id() {
        return Err(codes::AURA_TRANSACTION);
    }
    Ok(VerifiedProof {
        credential_id: binding.credential_id,
        algorithm: binding.algorithm,
        sign_counter: authenticator.counter,
        authenticator_data_digest: Digest32::sha256(authenticator.bytes),
        client_data_digest,
        signed_bytes_digest: Digest32::sha256(&message),
        top_origin: binding.top_origin,
        assertion,
        authorization,
        authorization_bytes,
        signed_bytes: message.to_vec(),
        public_key: binding.public_key,
        transaction_id,
    })
}
