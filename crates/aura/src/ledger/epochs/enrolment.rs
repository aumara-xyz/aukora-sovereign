// SPDX-License-Identifier: AGPL-3.0-or-later
//! First-owner possession is checked under the same lock as its binding and receipt.

use super::super::{io, refusal, sql, LedgerTxn};
use crate::{
    record::{AuthorityBodyV1, MembershipSet},
    storage,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use canon::{
    alg::{AlgorithmId, Signature},
    authority::{
        ceremony::{CeremonyFinish, CeremonyKind},
        AuthorityRecord, AuthorityVersion, Kind, OwnerBinding, PendingAuthorityRecord, Phase,
    },
    digest::Digest32,
    ids::{OperationId, RequestId, SessionId, SubjectId},
    json::{self, Value, ValueView},
    Result,
};
use rusqlite::{params, Connection, OptionalExtension};

mod codec;
use codec::{boolean, bytes, exact, field, number, text};

struct Registered {
    state: String,
    context: Value,
    candidate: Value,
    candidate_digest: Digest32,
    initial_counter: u32,
}

impl LedgerTxn<'_> {
    pub(in crate::ledger) fn enrol_owner(&mut self, request: CeremonyFinish<'_>) -> Result<()> {
        self.active()?;
        let now = self.services.clock.now_ms()?;
        let next = self.current_version()?;
        if request.kind != CeremonyKind::Enrolment
            || request.transaction_id != self.identity
            || self.state.epoch != 0
            || request.authority.epoch != 0
            || request.binding.epoch != 1
            || request.now_ms < 0
            || request.now_ms > now
            || now < 0
            || request.authority.sequence > next.sequence
            || !self.counters.is_empty()
            || !self.consumptions.is_empty()
            || self.floor_obligation.is_some()
            || self.target_observation.is_some()
        {
            return Err(refusal("enrolment-context"));
        }
        match request.authority.sequence.checked_sub(1) {
            Some(0) if request.authority.previous_hash.is_none() => {}
            Some(sequence) if sequence > 0 => {
                let previous = io::record_at(&self.transaction, sequence)?;
                crate::record::verify_record(&previous, &self.state.keys)?;
                if request.authority.previous_hash != Some(previous.hash)
                    || previous.authority.epoch != 0
                {
                    return Err(refusal("enrolment-context"));
                }
            }
            _ => return Err(refusal("enrolment-context")),
        }
        let occupied: bool = self.transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM authority_bindings) OR EXISTS(SELECT 1 FROM aura WHERE kind IN ('aumlok.enrol','aumlok.bind'))",
            [], |row| row.get(0),
        ).map_err(sql)?;
        if occupied {
            return Err(refusal("enrolment-closed"));
        }
        let registered = load_registered(&self.transaction, &request, now, false)?;
        verify_candidate(&registered, &request)?;
        let assertion = verify_possession(&registered, &request)?;
        let authority = AuthorityVersion { epoch: 1, ..next };
        let payload = codec::payload(&request, authority, assertion)?;
        let binding = storage::encode_binding(request.binding)?;
        change_state(&self.transaction, &request, &registered.state, "spent", now)?;
        self.transaction
            .execute(
                "INSERT INTO authority_bindings(credential,body,counter) VALUES (?1,?2,?3)",
                params![
                    URL_SAFE_NO_PAD.encode(request.binding.credential_id.as_bytes()),
                    binding,
                    request.binding.sign_counter
                ],
            )
            .map_err(sql)?;
        self.state.epoch = 1;
        let record = self.write_record(PendingAuthorityRecord {
            v: 1,
            algorithm: AlgorithmId::Sha256,
            authority,
            at: now,
            kind: Kind::AumlokEnrol,
            actor: request.owner_id.to_owned(),
            operation: Some(OperationId::from_bytes(*request.id.as_bytes())),
            phase: Phase::Terminal,
            body: payload,
        })?;
        verify_anchor(&record, &self.transaction)?;
        change_state(&self.transaction, &request, "spent", "finished", now)?;
        Ok(())
    }
}

fn load_registered(
    connection: &Connection,
    request: &CeremonyFinish<'_>,
    now: i64,
    retained: bool,
) -> Result<Registered> {
    let row = connection
        .query_row(
            "SELECT state,context,candidate,candidate_digest FROM aumlok_ceremonies_v1
         WHERE id=?1 AND purpose='enrolment'
         AND ((?6=0 AND state IN ('registered','spent')) OR (?6=1 AND state IN ('spent','finished')))
         AND nonce=?2 AND deadline=?3 AND issued<=?5 AND deadline>?4
         AND ((?6=0 AND last_seen<=?5) OR (?6=1 AND last_seen>=?4))
         AND issued>=0 AND last_seen>=issued AND deadline-issued BETWEEN 1 AND 300000
         AND length(claim_digest)=32 AND length(resume_digest)=32",
            params![
                request.id.as_bytes().as_slice(),
                request.nonce.as_slice(),
                request.expires_at_ms,
                now,
                request.now_ms,
                retained
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .optional()
        .map_err(sql)?
        .ok_or(refusal("enrolment-ceremony"))?;
    if row.1.len() > 8192 || row.2.len() > 16384 {
        return Err(refusal("enrolment-ceremony"));
    }
    let context = json::parse_strict(row.1.as_bytes())?;
    let candidate = json::parse_strict(row.2.as_bytes())?;
    let candidate_digest = Digest32::from_bytes(
        row.3
            .try_into()
            .map_err(|_| refusal("enrolment-candidate"))?,
    );
    if candidate.canonical_bytes() != row.2.as_bytes()
        || Digest32::sha256(row.2.as_bytes()) != candidate_digest
        || request.candidate_digest != Some(candidate_digest)
    {
        return Err(refusal("enrolment-candidate"));
    }
    let initial_counter = u32::try_from(number(&candidate, "initial_counter")?)
        .map_err(|_| refusal("enrolment-candidate"))?;
    Ok(Registered {
        state: row.0,
        context,
        candidate,
        candidate_digest,
        initial_counter,
    })
}

fn verify_candidate(registered: &Registered, request: &CeremonyFinish<'_>) -> Result<()> {
    let context = &registered.context;
    exact(
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
    let previous = match field(context, "previous_hash")?.view() {
        ValueView::Null => None,
        ValueView::Text(value) => Some(Digest32::from_hex(value)?),
        _ => return Err(refusal("enrolment-context")),
    };
    let binding = request.binding;
    if number(context, "v")? != 1
        || text(context, "rp")? != binding.relying_party
        || text(context, "owner_origin")? != binding.owner_origin
        || text(context, "top_origin")? != binding.top_origin
        || text(context, "owner_id")? != request.owner_id
        || text(context, "session")? != request.session.to_string()
        || text(context, "subject")? != request.subject.to_string()
        || !matches!(field(context, "credential")?.view(), ValueView::Null)
        || number(context, "epoch")? != request.authority.epoch
        || number(context, "sequence")? != request.authority.sequence
        || previous != request.authority.previous_hash
        || bytes(text(context, "user_handle")?)? != request.user_handle
        || request.user_handle.is_empty()
        || request.user_handle.len() > 64
        || request.owner_id.is_empty()
        || request.owner_id.len() > 256
    {
        return Err(refusal("enrolment-context"));
    }
    let candidate = &registered.candidate;
    exact(
        candidate,
        &[
            "v",
            "credential_id",
            "algorithm",
            "key_version",
            "public_key",
            "initial_counter",
            "backup_eligible",
            "backup_state",
            "aaguid",
            "client_data_digest",
            "attestation_digest",
        ],
    )?;
    if number(candidate, "v")? != 1
        || number(candidate, "key_version")? != 1
        || binding.v != 1
        || binding.public_key.v != 1
        || binding.algorithm != binding.public_key.algorithm
        || !matches!(
            (binding.algorithm, binding.public_key.bytes.len()),
            (AlgorithmId::Ed25519, 32) | (AlgorithmId::EcdsaP256Sha256, 65)
        )
        || text(candidate, "algorithm")? != binding.algorithm.wire_name()
        || bytes(text(candidate, "credential_id")?)? != binding.credential_id.as_bytes()
        || bytes(text(candidate, "public_key")?)? != binding.public_key.bytes
        || boolean(candidate, "backup_eligible")? != request.backup_eligible
        || boolean(candidate, "backup_state")? && !request.backup_eligible
        || bytes(text(candidate, "aaguid")?)?.len() != 16
    {
        return Err(refusal("enrolment-candidate"));
    }
    Digest32::from_hex(text(candidate, "client_data_digest")?)?;
    Digest32::from_hex(text(candidate, "attestation_digest")?)?;
    MembershipSet {
        epoch: 1,
        members: vec![binding.public_key.clone()],
        required_signers: 1,
    }
    .canonical_value()?;
    Ok(())
}

fn verify_possession(registered: &Registered, request: &CeremonyFinish<'_>) -> Result<Value> {
    if request.assertion_json.len() > 32768 {
        return Err(refusal("enrolment-assertion"));
    }
    let assertion = json::parse_strict(request.assertion_json)?;
    exact(
        &assertion,
        &[
            "kind",
            "credential_id",
            "client_data_json",
            "authenticator_data",
            "signature",
            "user_handle",
        ],
    )?;
    if text(&assertion, "kind")? != "passkey"
        || decode_url(text(&assertion, "credential_id")?, 1024)?
            != request.binding.credential_id.as_bytes()
    {
        return Err(refusal("enrolment-assertion"));
    }
    match field(&assertion, "user_handle")?.view() {
        ValueView::Null => {}
        ValueView::Text(value) if decode_url(value, 64)? == request.user_handle => {}
        _ => return Err(refusal("enrolment-assertion")),
    }
    let client = decode_url(text(&assertion, "client_data_json")?, 16384)?;
    let authenticator = decode_url(text(&assertion, "authenticator_data")?, 37)?;
    let signature = decode_url(text(&assertion, "signature")?, 128)?;
    let mut challenge = b"aukora:enrol-possession:v1\0".to_vec();
    challenge.extend_from_slice(request.id.to_string().as_bytes());
    challenge.extend_from_slice(registered.candidate_digest.as_bytes());
    canon::authority::verify_ceremony_client_data(
        &client,
        Digest32::sha256(&challenge).as_bytes(),
        request.binding,
    )?;
    if authenticator.len() != 37
        || authenticator[..32]
            != Digest32::sha256(request.binding.relying_party.as_bytes()).as_bytes()[..]
        || !matches!(authenticator[32], 0x05 | 0x0d | 0x1d)
        || (authenticator[32] & 8 != 0) != request.backup_eligible
    {
        return Err(refusal("enrolment-assertion"));
    }
    let counter = u32::from_be_bytes(
        authenticator[33..37]
            .try_into()
            .map_err(|_| refusal("enrolment-assertion"))?,
    );
    if counter != request.binding.sign_counter
        || ((registered.initial_counter != 0 || counter != 0)
            && counter <= registered.initial_counter)
    {
        return Err(refusal("enrolment-counter"));
    }
    let mut signed = authenticator;
    signed.extend_from_slice(Digest32::sha256(&client).as_bytes());
    crate::record::verify_signature(
        &request.binding.public_key,
        &signed,
        &Signature {
            v: 1,
            algorithm: request.binding.algorithm,
            bytes: signature,
        },
    )?;
    Ok(assertion)
}

fn decode_url(encoded: &str, maximum: usize) -> Result<Vec<u8>> {
    if encoded.len() > maximum.saturating_mul(2) {
        return Err(refusal("enrolment-assertion"));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| refusal("enrolment-assertion"))?;
    if decoded.is_empty() || decoded.len() > maximum || URL_SAFE_NO_PAD.encode(&decoded) != encoded
    {
        return Err(refusal("enrolment-assertion"));
    }
    Ok(decoded)
}

fn change_state(
    connection: &Connection,
    request: &CeremonyFinish<'_>,
    old: &str,
    new: &str,
    now: i64,
) -> Result<()> {
    let changed = connection
        .execute(
            "UPDATE aumlok_ceremonies_v1 SET state=?1,last_seen=?2 WHERE id=?3 AND nonce=?4
         AND state=?5 AND purpose='enrolment' AND issued<=?2 AND last_seen<=?2 AND deadline>?2",
            params![
                new,
                now,
                request.id.as_bytes().as_slice(),
                request.nonce.as_slice(),
                old
            ],
        )
        .map_err(sql)?;
    if changed != 1 {
        return Err(refusal("enrolment-ceremony"));
    }
    Ok(())
}

pub(super) fn verify_anchor(
    record: &AuthorityRecord,
    connection: &Connection,
) -> Result<OwnerBinding> {
    if record.kind != Kind::AumlokEnrol
        || record.phase != Phase::Terminal
        || record.operation.is_none()
        || record.authority.epoch != 1
    {
        return Err(refusal("enrolment-anchor"));
    }
    let wrapper = AuthorityBodyV1::parse(&record.body)?;
    if wrapper.authority != record.authority || wrapper.algorithm != record.algorithm {
        return Err(refusal("enrolment-anchor"));
    }
    let payload = &wrapper.payload;
    exact(
        payload,
        &[
            "schema",
            "algorithm",
            "epoch",
            "sequence",
            "previous_hash",
            "ceremony",
            "nonce",
            "session",
            "subject",
            "expires_at",
            "candidate_digest",
            "ceremony_authority",
            "owner_id",
            "user_handle",
            "backup_eligible",
            "assertion",
            "binding",
        ],
    )?;
    let previous = match field(payload, "previous_hash")?.view() {
        ValueView::Null => None,
        ValueView::Text(hash) => Some(Digest32::from_hex(hash)?),
        _ => return Err(refusal("enrolment-anchor")),
    };
    let ceremony = field(payload, "ceremony_authority")?;
    exact(ceremony, &["epoch", "sequence", "previous_hash"])?;
    if text(payload, "schema")? != "aukora-aumlok-ceremony-finish-v1"
        || text(payload, "algorithm")? != "sha256"
        || text(payload, "ceremony")?
            != record
                .operation
                .ok_or(refusal("enrolment-anchor"))?
                .to_string()
        || text(payload, "owner_id")? != record.actor
        || number(payload, "epoch")? != 1
        || number(payload, "sequence")? != record.authority.sequence
        || previous != record.authority.previous_hash
        || record.at < 0
        || number(payload, "expires_at")? <= record.at as u64
        || number(ceremony, "epoch")? != 0
        || number(ceremony, "sequence")? == 0
        || number(ceremony, "sequence")? > record.authority.sequence
    {
        return Err(refusal("enrolment-anchor"));
    }
    let binding = storage::decode_binding(&field(payload, "binding")?.canonical_bytes())?;
    if binding.epoch != 1 {
        return Err(refusal("enrolment-anchor"));
    }
    let nonce = bytes(text(payload, "nonce")?)?
        .try_into()
        .map_err(|_| refusal("enrolment-anchor"))?;
    let user_handle = bytes(text(payload, "user_handle")?)?;
    let assertion = field(payload, "assertion")?.canonical_bytes();
    let ceremony_previous = match field(ceremony, "previous_hash")?.view() {
        ValueView::Null => None,
        ValueView::Text(hash) => Some(Digest32::from_hex(hash)?),
        _ => return Err(refusal("enrolment-anchor")),
    };
    let authority = AuthorityVersion {
        epoch: 0,
        sequence: number(ceremony, "sequence")?,
        previous_hash: ceremony_previous,
    };
    match authority.sequence.checked_sub(1) {
        Some(0) if ceremony_previous.is_none() => {}
        Some(sequence) if sequence > 0 => {
            let previous = io::record_at(connection, sequence)?;
            if previous.authority.epoch != 0 || ceremony_previous != Some(previous.hash) {
                return Err(refusal("enrolment-anchor"));
            }
        }
        _ => return Err(refusal("enrolment-anchor")),
    }
    let request = CeremonyFinish {
        transaction_id: record.hash,
        id: RequestId::from_hex(text(payload, "ceremony")?)?,
        kind: CeremonyKind::Enrolment,
        session: SessionId::from_hex(text(payload, "session")?)?,
        subject: SubjectId::parse(text(payload, "subject")?)?,
        authority,
        nonce,
        expires_at_ms: i64::try_from(number(payload, "expires_at")?)
            .map_err(|_| refusal("enrolment-anchor"))?,
        candidate_digest: Some(Digest32::from_hex(text(payload, "candidate_digest")?)?),
        binding: &binding,
        owner_id: &record.actor,
        user_handle: &user_handle,
        backup_eligible: boolean(payload, "backup_eligible")?,
        assertion_json: &assertion,
        now_ms: record.at,
    };
    let registered = load_registered(connection, &request, record.at, true)?;
    verify_candidate(&registered, &request)?;
    verify_possession(&registered, &request)?;
    let predecessor: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM aura_record_wrappers WHERE seq<?1 AND epoch!=0)
         OR EXISTS(SELECT 1 FROM aura WHERE seq<?1 AND kind='aumlok.enrol')",
            [i64::try_from(record.authority.sequence).map_err(|_| refusal("sequence-range"))?],
            |row| row.get(0),
        )
        .map_err(sql)?;
    if predecessor {
        return Err(refusal("enrolment-anchor"));
    }
    Ok(binding)
}

pub(super) fn initial_membership(connection: &Connection, before: u64) -> Result<MembershipSet> {
    let mut statement = connection.prepare(
        "SELECT seq FROM aura WHERE seq<?1 AND kind='aumlok.enrol' AND phase='terminal' ORDER BY seq",
    ).map_err(sql)?;
    let mut rows = statement
        .query([i64::try_from(before).map_err(|_| refusal("sequence-range"))?])
        .map_err(sql)?;
    let sequence: i64 = rows
        .next()
        .map_err(sql)?
        .ok_or(refusal("membership-unavailable"))?
        .get(0)
        .map_err(sql)?;
    if rows.next().map_err(sql)?.is_some() {
        return Err(refusal("enrolment-anchor"));
    }
    let record = io::record_at(
        connection,
        u64::try_from(sequence).map_err(|_| refusal("sequence-range"))?,
    )?;
    let keys: Vec<u8> = connection
        .query_row(
            "SELECT public_keys FROM aura_record_wrappers WHERE seq=?1",
            [sequence],
            |row| row.get(0),
        )
        .map_err(sql)?;
    crate::record::verify_record(&record, &storage::decode_keys(&keys)?)?;
    let binding = verify_anchor(&record, connection)?;
    let membership = MembershipSet {
        epoch: 1,
        members: vec![binding.public_key],
        required_signers: 1,
    };
    membership.canonical_value()?;
    Ok(membership)
}
