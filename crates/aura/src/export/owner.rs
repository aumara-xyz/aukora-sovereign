// SPDX-License-Identifier: AGPL-3.0-or-later
//! A versioned envelope retains owner assertions without changing cold-proof-v1.

use super::*;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use canon::authority::{OwnerAssertion, OwnerAuthorization, OwnerBinding, OwnerOperation};

pub const COLD_PROOF_V2_SCHEMA: &str = "aukora-aura-cold-proof-v2";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerAssertionEvidenceV2 {
    pub sequence: u64,
    pub binding: OwnerBinding,
    pub proof: Value,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ColdProofV2 {
    pub proof: ColdProofV1,
    pub owner_assertions: Vec<OwnerAssertionEvidenceV2>,
}

impl ColdProofV2 {
    pub fn parse(bytes: &[u8], limits: ExportLimits) -> Result<Self> {
        if bytes.len() > limits.max_bytes {
            return Err(BAD);
        }
        let value = json::parse_strict(bytes)?;
        exact_keys(&value, &["schema", "body"])?;
        require_text(&value, "schema", COLD_PROOF_V2_SCHEMA)?;
        let body = member(&value, "body")?;
        exact_keys(body, &["proof", "owner_assertions"])?;
        let proof = ColdProofV1::parse(&member(body, "proof")?.canonical_bytes(), limits)?;
        let raw = array(member(body, "owner_assertions")?)?;
        if raw.len() > limits.max_rows {
            return Err(BAD);
        }
        let owner_assertions = raw
            .iter()
            .map(|entry| {
                exact_keys(entry, &["sequence", "binding", "proof"])?;
                Ok(OwnerAssertionEvidenceV2 {
                    sequence: number(member(entry, "sequence")?)?,
                    binding: crate::storage::owner_binding_from_value(member(entry, "binding")?)?,
                    proof: member(entry, "proof")?.clone(),
                })
            })
            .collect::<Result<_>>()?;
        let result = Self {
            proof,
            owner_assertions,
        };
        result.verify()?;
        Ok(result)
    }

    /// Valid signatures under embedded keys are evidence, never an independent key pin.
    pub fn verify(&self) -> Result<()> {
        self.proof.verify()?;
        let mut previous = 0;
        let mut supplied = std::collections::BTreeSet::new();
        let mut approvals = std::collections::BTreeSet::new();
        let mut challenges = std::collections::BTreeSet::new();
        for entry in &self.owner_assertions {
            if entry.sequence <= previous {
                return Err(BAD);
            }
            let row = self
                .proof
                .rows
                .get(usize::try_from(entry.sequence - 1).map_err(|_| BAD)?)
                .ok_or(BAD)?;
            entry.verify(row)?;
            let authorization = entry.authorization()?;
            if !approvals.insert(Digest32::sha256(&authorization.canonical_bytes()?))
                || !challenges.insert((
                    entry.binding.credential_id.clone(),
                    authorization.challenge.to_string(),
                ))
            {
                return Err(BAD);
            }
            supplied.insert(entry.sequence);
            previous = entry.sequence;
        }
        let mut required = std::collections::BTreeSet::new();
        for row in &self.proof.rows {
            check_standing(&self.proof.rows, row)?;
            let payload = if row.body.get("schema").is_some_and(|schema| {
                matches!(
                    schema.view(),
                    ValueView::Text(crate::record::AUTHORITY_BODY_SCHEMA)
                )
            }) {
                member(&row.body, "payload")?
            } else {
                &row.body
            };
            let needed = match row.kind {
                Kind::GateConsume => payload.get("standing").is_none(),
                Kind::GateRetire | Kind::FloorAdvance => true,
                Kind::GateApply => payload.get("target").is_some_and(|value| {
                    matches!(value.view(), ValueView::Text("gate/permission"))
                }),
                Kind::AumlokBind => !payload.get("schema").is_some_and(|schema| {
                    matches!(
                        schema.view(),
                        ValueView::Text(
                            "aukora-aumlok-initial-binding-v2"
                                | "aukora-aumlok-envelope-refresh-v2"
                        )
                    )
                }),
                _ => false,
            };
            if needed {
                required.insert(row.sequence);
            }
        }
        if supplied != required {
            return Err(BAD);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self, limits: ExportLimits) -> Result<Vec<u8>> {
        self.verify()?;
        if self.owner_assertions.len() > limits.max_rows {
            return Err(BAD);
        }
        let proof = json::parse_strict(&self.proof.canonical_bytes(limits)?)?;
        let assertions = self
            .owner_assertions
            .iter()
            .map(|entry| {
                object(vec![
                    ("sequence", unsigned(entry.sequence)?),
                    (
                        "binding",
                        crate::storage::owner_binding_value(&entry.binding)?,
                    ),
                    ("proof", entry.proof.clone()),
                ])
            })
            .collect::<Result<Vec<_>>>()?;
        let value = object(vec![
            ("schema", text(COLD_PROOF_V2_SCHEMA)?),
            (
                "body",
                object(vec![
                    ("proof", proof),
                    ("owner_assertions", Value::array(assertions)?),
                ])?,
            ),
        ])?;
        check_depth(&value, 0)?;
        if encoded_len(&value)? > limits.max_bytes {
            return Err(BAD);
        }
        Ok(value.canonical_bytes())
    }
}

impl OwnerAssertionEvidenceV2 {
    pub(crate) fn authorization(&self) -> Result<OwnerAuthorization> {
        crate::storage::decode_authorization(
            &member(&self.proof, "authorization")?.canonical_bytes(),
        )
    }

    fn verify(&self, row: &RowV1) -> Result<()> {
        exact_keys(
            &self.proof,
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
        if self.proof.canonical_bytes().len() > 65_536 || row.sequence != self.sequence {
            return Err(BAD);
        }
        let authorization = self.authorization()?;
        let encoded = authorization.canonical_bytes()?;
        if member(&self.proof, "authorization")?.canonical_bytes() != encoded
            || string(member(&self.proof, "credential")?)?
                != URL_SAFE_NO_PAD.encode(self.binding.credential_id.as_bytes())
        {
            return Err(BAD);
        }
        let keys =
            crate::storage::decode_keys(&member(&self.proof, "public_keys")?.canonical_bytes())?;
        let signatures = crate::storage::decode_signatures(
            &member(&self.proof, "signatures")?.canonical_bytes(),
        )?;
        if keys.as_slice() != std::slice::from_ref(&self.binding.public_key)
            || signatures.components().len() != 1
        {
            return Err(BAD);
        }
        let authenticator_data = decode(member(&self.proof, "authenticator_data")?)?;
        let client_data_json = decode(member(&self.proof, "client_data_json")?)?;
        let mut signed = authenticator_data.clone();
        signed.extend_from_slice(Digest32::sha256(&client_data_json).as_bytes());
        if signed != decode(member(&self.proof, "signed_bytes")?)? {
            return Err(BAD);
        }
        link(row, &authorization, Digest32::sha256(&encoded))?;
        canon::authority::verify_retained_owner_assertion(
            self.binding.clone(),
            authorization,
            OwnerAssertion {
                v: 1,
                algorithm: self.binding.algorithm,
                credential_id: self.binding.credential_id.clone(),
                authenticator_data,
                client_data_json,
                signature: signatures.components()[0].clone(),
            },
            crate::record::verify_signature,
        )
    }
}

fn decode(value: &Value) -> Result<Vec<u8>> {
    let raw = string(value)?;
    let bytes = STANDARD.decode(raw).map_err(|_| BAD)?;
    if STANDARD.encode(&bytes) != raw {
        return Err(BAD);
    }
    Ok(bytes)
}

fn check_standing(rows: &[RowV1], row: &RowV1) -> Result<()> {
    if row.kind != Kind::GateConsume {
        return Ok(());
    }
    let wrapper = crate::record::AuthorityBodyV1::parse(&row.body)?;
    let payload = &wrapper.payload;
    if payload.get("standing_permission").is_some() {
        return Err(BAD);
    }
    let Some(reference) = payload.get("standing") else {
        return Ok(());
    };
    exact_keys(
        reference,
        &[
            "permission",
            "permission_proposal",
            "permission_digest",
            "proposal",
            "operation",
            "use_number",
        ],
    )?;
    if wrapper.authority.sequence != row.sequence
        || wrapper.authority.previous_hash != row.previous
        || row.phase != Phase::Settle
        || row.actor != "owner"
        || row.operation.is_none()
        || number(member(reference, "use_number")?)? == 0
        || member(reference, "proposal")? != member(payload, "proposal")?
        || member(reference, "operation")? != member(payload, "operation")?
        || digest(member(payload, "consumed_approval")?)?
            != Digest32::sha256(&reference.canonical_bytes())
    {
        return Err(BAD);
    }
    require_text(payload, "state", "consumed")?;
    let permission = OperationId::from_hex(string(member(reference, "permission")?)?)?;
    let mut found = false;
    for grant in rows
        .iter()
        .take_while(|prior| prior.sequence < row.sequence)
    {
        if grant.kind != Kind::GateApply || grant.operation != Some(permission) {
            continue;
        }
        let granted = crate::record::AuthorityBodyV1::parse(&grant.body)?;
        if found
            || grant.phase != Phase::Terminal
            || grant.actor != "owner"
            || granted.authority.sequence != grant.sequence
            || granted.authority.previous_hash != grant.previous
            || granted.authority.epoch != wrapper.authority.epoch
            || member(&granted.payload, "proposal")? != member(reference, "permission_proposal")?
            || member(&granted.payload, "new_sha256")? != member(reference, "permission_digest")?
        {
            return Err(BAD);
        }
        require_text(&granted.payload, "state", "applied")?;
        require_text(&granted.payload, "target", "gate/permission")?;
        found = true;
    }
    if !found {
        return Err(BAD);
    }
    Ok(())
}

fn link(row: &RowV1, auth: &OwnerAuthorization, approval: Digest32) -> Result<()> {
    let wrapper = crate::record::AuthorityBodyV1::parse(&row.body)?;
    let payload = &wrapper.payload;
    if wrapper.authority.sequence != row.sequence
        || wrapper.authority.previous_hash != row.previous
        || auth.expires_at <= row.at
        || row.operation.is_none()
    {
        return Err(BAD);
    }
    let epoch_change = row.kind == Kind::AumlokBind && payload.get("membership").is_some();
    let epoch = auth.epoch.checked_add(u64::from(epoch_change)).ok_or(BAD)?;
    if wrapper.authority.epoch != epoch {
        return Err(BAD);
    }
    let actor = if matches!(row.kind, Kind::AumlokBind | Kind::FloorAdvance) {
        auth.subject.to_string()
    } else {
        "owner".to_owned()
    };
    if row.actor != actor {
        return Err(BAD);
    }
    match (row.kind, row.phase, auth.op) {
        (Kind::GateConsume, Phase::Settle, OwnerOperation::Apply)
        | (Kind::GateRetire, Phase::Terminal, OwnerOperation::Retire)
        | (Kind::GateApply, Phase::Terminal, OwnerOperation::Permission) => {
            if string(member(payload, "consumed_approval")?)? != approval.to_string()
                || string(member(payload, "proposal")?)? != auth.proposal.to_string()
                || string(member(payload, "target")?)? != auth.target
                || string(member(payload, "operation")?)? != auth.operation.to_string()
                || string(member(payload, "new_sha256")?)? != auth.new_sha256.to_string()
            {
                return Err(BAD);
            }
            let state = match row.kind {
                Kind::GateConsume => "consumed",
                Kind::GateRetire => "retired",
                _ => "applied",
            };
            require_text(payload, "state", state)?;
            if let Some(base) = payload.get("base_sha256") {
                if Some(base) != json::parse_strict(&auth.canonical_bytes()?)?.get("base_sha256") {
                    return Err(BAD);
                }
            }
        }
        (Kind::FloorAdvance, Phase::Terminal, OwnerOperation::Release) => {
            require_text(payload, "schema", "aukora-floor-advance-v1")?;
            exact_keys(
                payload,
                &["schema", "floor", "proposal", "authorization_sha256"],
            )?;
            let floor = member(payload, "floor")?;
            if auth.target != "release"
                || string(member(floor, "record")?)? != auth.new_sha256.to_string()
                || number(member(floor, "signer_epoch")?)? != auth.epoch
                || string(member(payload, "authorization_sha256")?)? != approval.to_string()
                || string(member(payload, "proposal")?)? != auth.proposal.to_string()
            {
                return Err(BAD);
            }
        }
        (Kind::AumlokBind, Phase::Terminal, OwnerOperation::Permission) => {
            let bytes = payload.canonical_bytes();
            let mut matches = auth.new_sha256 == Digest32::sha256(&bytes);
            for domain in [
                crate::record::MEMBERSHIP_DOMAIN,
                "aukora:aumlok-key-binding:v1",
                "aukora:aumlok-person-nostr-binding:v1",
                "aukora:aumlok-delegation:v1",
                "aukora:aumlok-device-binding:v1",
                "aukora:aumlok-device-revocation:v1",
                "aukora:aumlok-device-approval:v1",
            ] {
                let mut tagged = domain.as_bytes().to_vec();
                tagged.push(0);
                tagged.extend_from_slice(&bytes);
                matches |= auth.new_sha256 == Digest32::sha256(&tagged);
            }
            if !matches {
                return Err(BAD);
            }
        }
        _ => return Err(BAD),
    }
    Ok(())
}
