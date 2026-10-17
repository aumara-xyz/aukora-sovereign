// SPDX-License-Identifier: AGPL-3.0-or-later
//! Retained passkey evidence checked against a separately supplied credential key.

use crate::format::{array, field, hex_bytes, keys, refusal, text, uint};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use canon::{
    alg::{AlgorithmId, PublicKey, Signature},
    authority::{
        AuthorizationChallenge, BaseDigest, CellCommitment, OwnerAssertion, OwnerAuthorization,
        OwnerBinding, OwnerOperation,
    },
    digest::Digest32,
    ids::{CredentialId, NodeId, OperationDigest, ProposalId, SubjectId},
    json::{Value, ValueView},
    Result,
};

pub const COLD_PROOF_V2: &str = "aukora-aura-cold-proof-v2";

mod link;

pub(crate) fn check(value: &Value, pinned: Option<&[u8]>, report: &mut crate::VerificationReport) {
    if let Err(code) = check_all(value, pinned, report) {
        report.finding(
            if code.reason == "owner-key-mismatch" {
                crate::Verdict::KeyMismatch
            } else if code.reason == "owner-signature" {
                crate::Verdict::Forged
            } else {
                crate::Verdict::InvalidInput
            },
            code,
            None,
            false,
        );
    }
}

fn check_all(
    value: &Value,
    pinned: Option<&[u8]>,
    report: &mut crate::VerificationReport,
) -> Result<()> {
    let pin = pinned.map(pin).transpose()?;
    let (proof, entries) = unpack(value)?;
    let Some(entries) = entries else {
        if pin.is_some() {
            report.finding(
                crate::Verdict::Unchecked,
                refusal("owner-assertions-unavailable"),
                None,
                false,
            );
        }
        return Ok(());
    };
    let rows = array(field(proof, "rows")?)?;
    let mut required = std::collections::BTreeSet::new();
    for row in rows {
        link::standing(rows, row)?;
        if link::required(row)? {
            required.insert(uint(field(row, "seq")?)?);
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut approvals = std::collections::BTreeSet::new();
    let mut challenges = std::collections::BTreeSet::new();
    let mut counters = std::collections::BTreeMap::new();
    let mut credentials = std::collections::BTreeMap::new();
    let mut last_sequence = 0;
    for entry in entries {
        keys(entry, &["sequence", "binding", "proof"])?;
        let seq = uint(field(entry, "sequence")?)?;
        require(seq > last_sequence && required.contains(&seq) && seen.insert(seq))?;
        last_sequence = seq;
        let binding = binding(field(entry, "binding")?)?;
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&binding.public_key.bytes)
            .map_err(|_| refusal("owner-key"))?;
        let point = key.to_sec1_point(false);
        if pin
            .as_ref()
            .is_some_and(|pin| pin.as_slice() != point.as_bytes())
        {
            return Err(refusal("owner-key-mismatch"));
        }
        let (authorization, assertion) = assertion(field(entry, "proof")?, &binding)?;
        require(approvals.insert(authorization.canonical_bytes()?))?;
        require(challenges.insert(authorization.challenge.to_string()))?;
        link::verify(rows, entry, &authorization)?;
        let credential_key = point.as_bytes().to_vec();
        let credential = binding.credential_id.as_bytes().to_vec();
        if let Some(previous_key) = credentials.get(&credential) {
            require(previous_key == &credential_key)?;
        }
        let counter = u32::from_be_bytes(
            assertion
                .authenticator_data
                .get(33..37)
                .ok_or(refusal("owner-proof"))?
                .try_into()
                .map_err(|_| refusal("owner-proof"))?,
        );
        if binding.sign_counter != 0 && counter <= binding.sign_counter {
            return Err(refusal("owner-counter-replay"));
        }
        if let Some(previous_counter) = counters.get(&credential_key) {
            if binding.sign_counter < *previous_counter
                || (*previous_counter != 0 && counter <= *previous_counter)
            {
                return Err(refusal("owner-counter-replay"));
            }
        }
        canon::authority::verify_retained_owner_assertion(
            binding,
            authorization,
            assertion,
            signature,
        )?;
        counters.insert(credential_key.clone(), counter);
        credentials.insert(credential, credential_key);
    }
    require(seen == required)?;
    if entries.is_empty() {
        report.finding(
            crate::Verdict::Unchecked,
            refusal("owner-assertions-unavailable"),
            None,
            false,
        );
    } else if pin.is_none() {
        report.finding(
            crate::Verdict::Unchecked,
            refusal("owner-no-pinned-key"),
            None,
            false,
        );
    } else if report.integrity().chain == crate::Scope::Checked
        && report.integrity().signatures == crate::Scope::Checked
    {
        report.owner_signatures_checked();
    }
    Ok(())
}

/// Select a closed wrapper without adding any member to the v1 proof. A wrapper or proof whose members are not exactly
/// the closed set is `verifier:bundle-format`, as in the Python twin.
pub(crate) fn unpack(value: &Value) -> Result<(&Value, Option<&[Value]>)> {
    let shape = |wanted: &[&str], value: &Value| keys(value, wanted).map_err(|_| refusal("bundle-format"));
    match text(field(value, "schema")?)? {
        crate::format::COLD_PROOF_V1 => {
            shape(&["schema", "publicKey", "head", "rows"], value)?;
            Ok((value, None))
        }
        COLD_PROOF_V2 => {
            shape(&["schema", "body"], value)?;
            let body = field(value, "body")?;
            shape(&["proof", "owner_assertions"], body)?;
            let proof = field(body, "proof")?;
            shape(&["schema", "publicKey", "head", "rows"], proof)?;
            if text(field(proof, "schema")?)? != crate::format::COLD_PROOF_V1 {
                return Err(refusal("bundle-format"));
            }
            Ok((proof, Some(array(field(body, "owner_assertions")?)?)))
        }
        _ => Err(crate::UNSUPPORTED_SCHEMA),
    }
}

fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(refusal("owner-proof"))
    }
}

fn bytes(value: &Value, url: bool) -> Result<Vec<u8>> {
    let encoded = text(value)?;
    let engine = if url { &URL_SAFE_NO_PAD } else { &STANDARD };
    let raw = engine.decode(encoded).map_err(|_| refusal("owner-proof"))?;
    require(engine.encode(&raw) == encoded)?;
    Ok(raw)
}

fn tagged(value: &Value) -> Result<PublicKey> {
    keys(value, &["v", "algorithm", "bytes"])?;
    require(uint(field(value, "v")?)? == 1)?;
    let algorithm = AlgorithmId::from_wire(text(field(value, "algorithm")?)?)?;
    require(algorithm == AlgorithmId::EcdsaP256Sha256)?;
    Ok(PublicKey {
        v: 1,
        algorithm,
        bytes: bytes(field(value, "bytes")?, false)?,
    })
}

fn binding(value: &Value) -> Result<OwnerBinding> {
    keys(
        value,
        &[
            "schema",
            "v",
            "algorithm",
            "credential",
            "key",
            "epoch",
            "relying_party",
            "owner_origin",
            "top_origin",
            "counter",
        ],
    )?;
    require(
        text(field(value, "schema")?)? == "aukora-aura-owner-binding-storage-v1"
            && uint(field(value, "v")?)? == 1
            && text(field(value, "algorithm")?)? == "ecdsa-p256-sha256",
    )?;
    let epoch = uint(field(value, "epoch")?)?;
    require(epoch > 0)?;
    Ok(OwnerBinding {
        v: 1,
        algorithm: AlgorithmId::EcdsaP256Sha256,
        credential_id: CredentialId::new(bytes(field(value, "credential")?, false)?)?,
        public_key: tagged(field(value, "key")?)?,
        epoch,
        relying_party: text(field(value, "relying_party")?)?.to_owned(),
        owner_origin: text(field(value, "owner_origin")?)?.to_owned(),
        top_origin: text(field(value, "top_origin")?)?.to_owned(),
        sign_counter: u32::try_from(uint(field(value, "counter")?)?)
            .map_err(|_| refusal("owner-proof"))?,
    })
}

fn authorization(value: &Value) -> Result<OwnerAuthorization> {
    let read = |name| text(field(value, name)?);
    let digest = |name| Digest32::from_hex(read(name)?);
    let cell = field(value, "cell")?;
    let cell = if matches!(cell.view(), ValueView::Null) {
        None
    } else {
        keys(cell, &["module_sha256", "input_sha256", "effect_sha256"])?;
        Some(CellCommitment {
            module_sha256: Digest32::from_hex(text(field(cell, "module_sha256")?)?)?,
            input_sha256: Digest32::from_hex(text(field(cell, "input_sha256")?)?)?,
            effect_sha256: Digest32::from_hex(text(field(cell, "effect_sha256")?)?)?,
        })
    };
    let op = match read("op")? {
        "apply" => OwnerOperation::Apply,
        "retire" => OwnerOperation::Retire,
        "release" => OwnerOperation::Release,
        "grant" => OwnerOperation::Grant,
        "permission" => OwnerOperation::Permission,
        _ => return Err(refusal("owner-proof")),
    };
    let auth = OwnerAuthorization {
        v: 1,
        algorithm: AlgorithmId::Sha256,
        node: NodeId::from_hex(read("node")?)?,
        subject: SubjectId::parse(read("subject")?)?,
        op,
        proposal: ProposalId::from_hex(read("proposal")?)?,
        target: read("target")?.to_owned(),
        base_sha256: if read("base_sha256")? == "absent" {
            BaseDigest::Absent
        } else {
            BaseDigest::Present(digest("base_sha256")?)
        },
        new_sha256: digest("new_sha256")?,
        cell,
        display_sha256: digest("display_sha256")?,
        challenge: AuthorizationChallenge::from_hex(read("challenge")?)?,
        expires_at: i64::try_from(uint(field(value, "expires_at")?)?)
            .map_err(|_| refusal("owner-proof"))?,
        epoch: uint(field(value, "epoch")?)?,
        operation: OperationDigest::from_hex(read("operation")?)?,
    };
    require(auth.epoch > 0 && auth.canonical_bytes()? == value.canonical_bytes())?;
    Ok(auth)
}

fn signature(key: &PublicKey, message: &[u8], signature: &Signature) -> Result<()> {
    use p256::ecdsa::{signature::Verifier, Signature as Es256, VerifyingKey};
    require(
        key.v == 1
            && signature.v == 1
            && key.algorithm == AlgorithmId::EcdsaP256Sha256
            && signature.algorithm == key.algorithm,
    )?;
    let key = VerifyingKey::from_sec1_bytes(&key.bytes).map_err(|_| refusal("owner-key"))?;
    let signature = Es256::from_der(&signature.bytes).map_err(|_| refusal("owner-signature"))?;
    key.verify(message, &signature)
        .map_err(|_| refusal("owner-signature"))
}

fn pin(bytes: &[u8]) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(bytes.strip_suffix(b"\n").unwrap_or(bytes))
        .map_err(|_| refusal("owner-key"))?;
    let raw = hex_bytes::<65>(text).map_err(|_| refusal("owner-key"))?;
    require(raw[0] == 4)?;
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&raw).map_err(|_| refusal("owner-key"))?;
    Ok(raw.to_vec())
}

fn assertion(
    value: &Value,
    binding: &OwnerBinding,
) -> Result<(OwnerAuthorization, OwnerAssertion)> {
    keys(
        value,
        &[
            "authorization",
            "credential",
            "authenticator_data",
            "client_data_json",
            "signed_bytes",
            "public_keys",
            "signatures",
        ],
    )?;
    let public_keys = array(field(value, "public_keys")?)?;
    require(public_keys.len() == 1 && tagged(&public_keys[0])? == binding.public_key)?;
    let signatures = field(value, "signatures")?;
    keys(signatures, &["v", "components"])?;
    require(uint(field(signatures, "v")?)? == 1)?;
    let components = array(field(signatures, "components")?)?;
    require(components.len() == 1)?;
    let component = tagged(&components[0])?;
    let assertion = OwnerAssertion {
        v: 1,
        algorithm: AlgorithmId::EcdsaP256Sha256,
        credential_id: CredentialId::new(bytes(field(value, "credential")?, true)?)?,
        authenticator_data: bytes(field(value, "authenticator_data")?, false)?,
        client_data_json: bytes(field(value, "client_data_json")?, false)?,
        signature: Signature {
            v: 1,
            algorithm: component.algorithm,
            bytes: component.bytes,
        },
    };
    let mut signed = assertion.authenticator_data.clone();
    signed.extend_from_slice(Digest32::sha256(&assertion.client_data_json).as_bytes());
    require(signed == bytes(field(value, "signed_bytes")?, false)?)?;
    Ok((authorization(field(value, "authorization")?)?, assertion))
}
