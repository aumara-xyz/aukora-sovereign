// SPDX-License-Identifier: AGPL-3.0-or-later
//! The granting permission retains the exact consumed owner assertion.

use super::*;
use canon::authority::OwnerAssertion;

impl LedgerTxn<'_> {
    pub(super) fn verify_standing_proof(
        &self,
        stored: &Stored,
        proposal: &storage::ProposalState,
        record: &AuthorityRecord,
    ) -> Result<OwnerAuthorization> {
        type Consumption = (
            Vec<u8>,
            String,
            u32,
            i64,
            i64,
            Option<String>,
            String,
            String,
            String,
            i64,
        );
        let (bytes, credential, counter, epoch, sequence, previous, operation, id, action, appended): Consumption =
            self.transaction.query_row(
                "SELECT proof,credential,counter,epoch,sequence,previous_hash,operation,proposal,action,appended FROM authority_consumptions WHERE approval=?1",
                [stored.approval.to_string()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?,
                    row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?)),
            ).map_err(sql)?;
        if bytes.len() > 65_536
            || epoch != sql_number(record.authority.epoch)?
            || sequence != sql_number(record.authority.sequence)?
            || previous != record.authority.previous_hash.map(|hash| hash.to_string())
            || operation != proposal.operation.to_string()
            || id != proposal.proposal.to_string()
            || action != "permission"
            || appended != 1
        {
            return Err(refusal("standing-grant-proof"));
        }
        let proof = json::parse_strict(&bytes)?;
        exact(
            &proof,
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
        let authorization_bytes = member(&proof, "authorization")?.canonical_bytes();
        let auth = storage::decode_authorization(&authorization_bytes)?;
        if proof.canonical_bytes() != bytes
            || auth.canonical_bytes()? != authorization_bytes
            || Digest32::sha256(&authorization_bytes) != stored.approval
            || text_field(&proof, "credential")? != credential
            || auth.op != OwnerOperation::Permission
            || auth.proposal != proposal.proposal
            || auth.epoch != record.authority.epoch
            || auth.target != proposal.target
            || auth.base_sha256 != proposal.base_sha256
            || auth.cell != proposal.cell
            || auth.new_sha256 != stored.digest
            || auth.operation != proposal.operation_digest
            || auth.expires_at <= record.at
            || auth.subject != self.gate_owner_subject()?
        {
            return Err(refusal("standing-grant-proof"));
        }
        let (challenge_body, card_bytes, challenge, spent): (Vec<u8>, Vec<u8>, String, i64) =
            self.transaction.query_row(
                "SELECT body,card,challenge,spent FROM authority_challenges WHERE proposal=?1 AND action='permission'",
                [proposal.proposal.to_string()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            ).map_err(sql)?;
        let card = storage::decode_card(&card_bytes)?;
        if challenge_body != authorization_bytes
            || challenge != auth.challenge.to_string()
            || spent != 1
            || card.canonical_bytes()? != card_bytes
            || Digest32::sha256(&card_bytes) != auth.display_sha256
            || card.risk != CardRisk::Critical
            || card.model_note != proposal.model_note
        {
            return Err(refusal("standing-grant-proof"));
        }
        let credential_bytes = URL_SAFE_NO_PAD
            .decode(&credential)
            .map_err(|_| refusal("standing-grant-proof"))?;
        if URL_SAFE_NO_PAD.encode(&credential_bytes) != credential {
            return Err(refusal("standing-grant-proof"));
        }
        let credential_id = CredentialId::new(credential_bytes)?;
        let historical = super::super::super::epochs::immune_binding_before(
            &self.transaction,
            &credential_id,
            record.authority.epoch,
            record.authority.sequence,
            &self.state.keys,
        )?;
        let (binding_bytes, current_counter): (Vec<u8>, u32) = self.transaction.query_row(
            "SELECT body,counter FROM authority_bindings WHERE credential=?1",
            [&credential], |row| Ok((row.get(0)?, row.get(1)?)),
        ).map_err(sql)?;
        let mut current = storage::decode_binding(&binding_bytes)?;
        if current.credential_id != credential_id || current.epoch != self.state.epoch
            || current_counter < current.sign_counter {
            return Err(refusal("standing-owner-changed"));
        }
        current.sign_counter = current_counter;
        super::super::super::epochs::binding_anchor(&self.transaction, &current, &self.state.keys)?;
        let mut equivalent = historical.clone();
        equivalent.sign_counter = current.sign_counter;
        if equivalent != current || current.sign_counter < counter {
            return Err(refusal("standing-owner-changed"));
        }
        let keys = storage::decode_keys(&member(&proof, "public_keys")?.canonical_bytes())?;
        let signatures =
            storage::decode_signatures(&member(&proof, "signatures")?.canonical_bytes())?;
        if keys != [historical.public_key.clone()] || signatures.components().len() != 1 {
            return Err(refusal("standing-grant-proof"));
        }
        let signature = signatures.components()[0].clone();
        let authenticator_data = immune_standard_bytes(&proof, "authenticator_data")?;
        let client_data_json = immune_standard_bytes(&proof, "client_data_json")?;
        if authenticator_data.len() != 37 || authenticator_data[33..37] != counter.to_be_bytes() {
            return Err(refusal("standing-grant-proof"));
        }
        let mut signed = authenticator_data.clone();
        signed.extend_from_slice(Digest32::sha256(&client_data_json).as_bytes());
        if signed != immune_standard_bytes(&proof, "signed_bytes")? {
            return Err(refusal("standing-grant-proof"));
        }
        canon::authority::verify_retained_owner_assertion(
            historical,
            auth.clone(),
            OwnerAssertion {
                v: 1,
                algorithm: signature.algorithm,
                credential_id,
                authenticator_data,
                client_data_json,
                signature,
            },
            crate::record::verify_signature,
        )?;
        Ok(auth)
    }
}

impl LedgerTxn<'_> {
    pub(super) fn historical_standing_proof(
        &self,
        stored: &Stored,
        proposal: &storage::ProposalState,
        grant: &AuthorityRecord,
    ) -> Result<OwnerAuthorization> {
        let (bytes, credential, counter): (Vec<u8>, String, u32) = self.transaction.query_row(
            "SELECT proof,credential,counter FROM authority_consumptions WHERE approval=?1 AND proposal=?2 AND operation=?3 AND epoch=?4 AND sequence=?5 AND previous_hash IS ?6 AND action='permission' AND appended=1",
            params![stored.approval.to_string(), proposal.proposal.to_string(), proposal.operation.to_string(),
                sql_number(grant.authority.epoch)?, sql_number(grant.authority.sequence)?,
                grant.authority.previous_hash.map(|hash| hash.to_string())],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).map_err(sql)?;
        if bytes.len() > 65_536 {
            return Err(refusal("standing-grant-proof"));
        }
        let proof = json::parse_strict(&bytes)?;
        exact(&proof, &[
            "authorization", "credential", "authenticator_data", "client_data_json",
            "signed_bytes", "public_keys", "signatures",
        ])?;
        let encoded_auth = member(&proof, "authorization")?.canonical_bytes();
        let auth = storage::decode_authorization(&encoded_auth)?;
        if proof.canonical_bytes() != bytes
            || text_field(&proof, "credential")? != credential
            || auth.canonical_bytes()? != encoded_auth
            || Digest32::sha256(&encoded_auth) != stored.approval
            || auth.op != OwnerOperation::Permission
            || auth.proposal != proposal.proposal
            || auth.epoch != grant.authority.epoch
            || auth.target != proposal.target
            || auth.base_sha256 != proposal.base_sha256
            || auth.new_sha256 != stored.digest
            || auth.cell != proposal.cell
            || auth.operation != proposal.operation_digest
            || auth.expires_at <= grant.at
        {
            return Err(refusal("standing-grant-proof"));
        }
        let (challenge, card_bytes, nonce, spent): (Vec<u8>, Vec<u8>, String, i64) =
            self.transaction.query_row(
                "SELECT body,card,challenge,spent FROM authority_challenges WHERE proposal=?1 AND action='permission'",
                [proposal.proposal.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            ).map_err(sql)?;
        let card = storage::decode_card(&card_bytes)?;
        if challenge != encoded_auth || nonce != auth.challenge.to_string() || spent != 1
            || card.canonical_bytes()? != card_bytes
            || Digest32::sha256(&card_bytes) != auth.display_sha256
            || card.risk != CardRisk::Critical || card.model_note != proposal.model_note
        {
            return Err(refusal("standing-grant-proof"));
        }
        let subject_sequence: i64 = self.transaction.query_row(
            "SELECT seq FROM aura WHERE seq<?1 AND kind IN ('aumlok.enrol','aumlok.bind') AND phase='terminal' ORDER BY seq DESC LIMIT 1",
            [sql_number(grant.authority.sequence)?], |row| row.get(0),
        ).map_err(sql)?;
        let subject_record = self.floor_record_at_sequence(
            u64::try_from(subject_sequence).map_err(|_| refusal("standing-grant-proof"))?,
        )?.ok_or(refusal("standing-grant-proof"))?;
        if subject_record.authority.epoch != grant.authority.epoch
            || !matches!(subject_record.kind, Kind::AumlokEnrol | Kind::AumlokBind)
            || subject_record.phase != Phase::Terminal
            || subject_record.operation.is_none()
            || field(gate_payload(&subject_record.body), "subject") != Some(auth.subject.to_string().as_str())
        {
            return Err(refusal("standing-grant-proof"));
        }
        let credential_raw = URL_SAFE_NO_PAD.decode(&credential)
            .map_err(|_| refusal("standing-grant-proof"))?;
        if URL_SAFE_NO_PAD.encode(&credential_raw) != credential {
            return Err(refusal("standing-grant-proof"));
        }
        let credential_id = CredentialId::new(credential_raw)?;
        let binding = super::super::super::epochs::immune_binding_before(
            &self.transaction, &credential_id, grant.authority.epoch,
            grant.authority.sequence, &self.state.keys,
        )?;
        let keys = storage::decode_keys(&member(&proof, "public_keys")?.canonical_bytes())?;
        let signatures = storage::decode_signatures(&member(&proof, "signatures")?.canonical_bytes())?;
        if keys != [binding.public_key.clone()] || signatures.components().len() != 1 {
            return Err(refusal("standing-grant-proof"));
        }
        let signature = signatures.components()[0].clone();
        let authenticator_data = immune_standard_bytes(&proof, "authenticator_data")?;
        let client_data_json = immune_standard_bytes(&proof, "client_data_json")?;
        let mut signed_bytes = authenticator_data.clone();
        signed_bytes.extend_from_slice(Digest32::sha256(&client_data_json).as_bytes());
        if authenticator_data.len() != 37
            || authenticator_data[33..37] != counter.to_be_bytes()
            || signed_bytes != immune_standard_bytes(&proof, "signed_bytes")?
        {
            return Err(refusal("standing-grant-proof"));
        }
        canon::authority::verify_retained_owner_assertion(
            binding, auth.clone(), OwnerAssertion {
                v: 1, algorithm: signature.algorithm, credential_id,
                authenticator_data, client_data_json, signature,
            }, crate::record::verify_signature,
        )?;
        Ok(auth)
    }
}
