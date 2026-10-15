// SPDX-License-Identifier: AGPL-3.0-or-later
//! Passkey input and verification contracts. Cryptographic entrypoints fail closed
//! in wave 0. clientDataJSON has its own parser; it is never parsed through C1.

use canon::alg::{AlgorithmId, PublicKey};
use canon::authority::{AuthorityTxn, OwnerAssertion, OwnerBinding, OwnerOperation, VerifiedProof};
use canon::digest::Digest32;
use canon::ids::{CredentialId, ProposalId};
use canon::{Refusal, Result};
use serde::{Deserialize, Serialize};

pub const MAX_CLIENT_DATA_BYTES: usize = 16_384;
pub const MAX_ATTESTATION_BYTES: usize = 16_384;
pub const MAX_AUTHENTICATOR_BYTES: usize = 4_096;
pub const MAX_SIGNATURE_BYTES: usize = 128;
pub const MAX_USER_HANDLE_BYTES: usize = 64;
pub const CHALLENGE_BYTES: usize = 32;

/// Wire input, still untrusted. Base64url fields retain the pinned spellings.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationMaterial {
    pub kind: String,
    #[serde(rename = "type")]
    pub credential_type: String,
    pub id: String,
    pub raw_id: String,
    pub client_data_json: String,
    pub attestation_object: String,
    pub client_extension_results: serde_json::Value,
}

/// No algorithm or epoch is added to the pinned v1 assertion object.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssertionMaterial {
    pub kind: String,
    pub credential_id: String,
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
    #[serde(deserialize_with = "required_user_handle")]
    pub user_handle: Option<String>,
}

fn required_user_handle<'de, D: serde::Deserializer<'de>>(
    input: D,
) -> core::result::Result<Option<String>, D::Error> {
    Deserialize::deserialize(input)
}

/// Internal context supplied from node configuration, never the received JSON.
/// None selects the pinned legacy vectors; production ceremonies require Some(shell).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginContext {
    pub relying_party: String,
    pub owner_origin: String,
    pub expected_top_origin: Option<String>,
}

/// Versioned stored wrapper; v1 WebAuthn material gains no extra fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credential {
    pub version: u16,
    pub binding: OwnerBinding,
    pub owner_id: String,
    pub user_handle: Vec<u8>,
    pub backup_eligible: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtensionPolicy {
    None,
    RegistrationPrf,
    BackupPrf,
}

/// A durable ceremony supplies these values; this data does not authorize anything.
#[derive(Clone, Debug)]
pub struct RegistrationContext {
    pub origins: OriginContext,
    pub owner_id: String,
    pub user_handle: Vec<u8>,
    pub existing_credentials: Vec<CredentialId>,
    pub challenge: [u8; CHALLENGE_BYTES],
    pub extensions: ExtensionPolicy,
}

/// Candidate public data is evidence only. No owner binding is installed by parsing it.
#[derive(Clone, Debug)]
pub struct RegistrationCandidate {
    pub credential_id: CredentialId,
    pub public_key: PublicKey,
    pub initial_counter: u32,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub aaguid: [u8; 16],
    pub client_data_digest: Digest32,
    pub attestation_digest: Digest32,
}

/// Signature observations cannot be passed to AuthorityTxn::persist_counter.
#[derive(Debug)]
pub struct AssertionObservation {
    credential_id: CredentialId,
    counter: u32,
    signed_bytes_digest: Digest32,
}

impl AssertionObservation {
    pub fn credential_id(&self) -> &CredentialId {
        &self.credential_id
    }
    pub fn counter(&self) -> u32 {
        self.counter
    }
    pub fn signed_bytes_digest(&self) -> Digest32 {
        self.signed_bytes_digest
    }
}

/// Pure counter rule; success here is neither a signature check nor persistence.
pub fn check_counter(stored: u32, presented: u32) -> Result<()> {
    if (stored == 0 && presented == 0) || presented > stored {
        Ok(())
    } else {
        Err(Refusal {
            organ: "aumlok",
            reason: "counter-replayed",
        })
    }
}

/// Only the pinned COSE signature algorithms are admitted at this boundary.
pub fn passkey_algorithm(cose: i64) -> Result<AlgorithmId> {
    match cose {
        -7 => Ok(AlgorithmId::EcdsaP256Sha256),
        -8 => Ok(AlgorithmId::Ed25519),
        _ => Err(Refusal {
            organ: "aumlok",
            reason: "key-invalid",
        }),
    }
}

/// Wave-1 parser: strip a leading BOM, reject decoded duplicate keys, unsafe
/// integers, lone surrogates and excess depth; allow fractional extra fields as pinned.
/// The original bytes, including any BOM, remain the signature input. Not implemented.
pub fn parse_client_data(_raw: &[u8]) -> Result<serde_json::Map<String, serde_json::Value>> {
    Err(Refusal {
        organ: "aumlok",
        reason: "not-implemented",
    })
}

/// Wave-1 registration contract: pinned rejection order, none attestation, bounded
/// COSE, RP hash, UP/UV/AT, challenge, owner origin and backup flags. With Some(shell),
/// crossOrigin must be true and topOrigin exactly shell. Currently refuses.
pub fn verify_registration(
    _material: &RegistrationMaterial,
    _context: &RegistrationContext,
) -> Result<RegistrationCandidate> {
    Err(Refusal {
        organ: "aumlok",
        reason: "not-implemented",
    })
}

/// Standalone signature checking remains non-authorizing. Wave 1 checks all pinned
/// fields and counters against the locked credential, with the supplied top origin.
/// No caller can turn this observation into a canon proof or persist a counter.
pub fn inspect_assertion(
    _material: &AssertionMaterial,
    _credential: &Credential,
    _context: &OriginContext,
    _challenge: &[u8; CHALLENGE_BYTES],
    _extensions: ExtensionPolicy,
) -> Result<AssertionObservation> {
    Err(Refusal {
        organ: "aumlok",
        reason: "not-implemented",
    })
}

/// C5 proof API. Wave 1 must use canon's sole VerifiedProof::verify constructor
/// and then AuthorityTxn::persist_counter in this same transaction. The caller
/// retains the transaction for consume/append/commit; this function never commits.
/// Currently refuses because canon's verification body is also unwritten.
pub fn verify_owner_assertion<T: AuthorityTxn + ?Sized>(
    _txn: &mut T,
    _proposal: &ProposalId,
    _action: OwnerOperation,
    _assertion: OwnerAssertion,
) -> Result<VerifiedProof> {
    Err(Refusal {
        organ: "aumlok",
        reason: "not-implemented",
    })
}
