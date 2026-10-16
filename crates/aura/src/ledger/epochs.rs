// SPDX-License-Identifier: AGPL-3.0-or-later
//! Membership transitions are checked against the previously verified ledger epoch.

use canon::{
    alg::PublicKey,
    authority::{AuthorityRecord, AuthorityVersion, Kind, OwnerBinding, Phase},
    digest::Digest32,
    json::{self, Value, ValueView},
    Result,
};
use rusqlite::{Connection, OptionalExtension};

use crate::record::{AuthorityBodyV1, MembershipSet, MembershipTransition, AUTHORITY_BODY_SCHEMA};

use super::{io, refusal, sql};

mod enrolment;

/// Accept either a pending payload or its exact authority-body wrapper.
pub(super) fn epoch_transition(body: &Value) -> Result<MembershipTransition> {
    let payload = if body
        .get("schema")
        .is_some_and(|value| matches!(value.view(), ValueView::Text(AUTHORITY_BODY_SCHEMA)))
    {
        AuthorityBodyV1::parse(body)?.payload
    } else {
        body.clone()
    };
    MembershipTransition::parse(
        payload
            .get("membership")
            .ok_or(refusal("membership-missing"))?,
    )
}

/// The connection must be in the verified history walk or a locked verified snapshot.
pub(super) fn verify_epoch_body(
    record: &AuthorityRecord,
    old_epoch: u64,
    connection: &Connection,
) -> Result<()> {
    if record.phase != Phase::Terminal || record.operation.is_none() {
        return Err(refusal("epoch-terminal-required"));
    }
    let wrapper = AuthorityBodyV1::parse(&record.body)?;
    if wrapper.authority != record.authority || wrapper.algorithm != record.algorithm {
        return Err(refusal("epoch-context"));
    }
    if old_epoch == 0 {
        enrolment::verify_anchor(record, connection)?;
    } else {
        verify_epoch_transition(&record.body, record.authority, old_epoch, connection)?;
    }
    Ok(())
}

/// Validate pending coordinates before the caller consumes or appends anything.
pub(super) fn verify_epoch_transition(
    body: &Value,
    authority: AuthorityVersion,
    old_epoch: u64,
    connection: &Connection,
) -> Result<MembershipTransition> {
    let transition = epoch_transition(body)?;
    let expected = AuthorityVersion {
        epoch: old_epoch,
        ..authority
    };
    if old_epoch.checked_add(1) != Some(authority.epoch)
        || transition.old.epoch != old_epoch
        || transition.new.epoch != authority.epoch
        || transition.predecessor != expected
    {
        return Err(refusal("epoch-context"));
    }
    let previous = previous_membership(connection, old_epoch, authority.sequence)?;
    transition.verify_joint(&previous)?;
    Ok(transition)
}

fn previous_membership(connection: &Connection, epoch: u64, before: u64) -> Result<MembershipSet> {
    if epoch == 1 {
        return enrolment::initial_membership(connection, before);
    }
    let prior_epoch = epoch
        .checked_sub(1)
        .ok_or(refusal("membership-unavailable"))?;
    let epoch = i64::try_from(epoch).map_err(|_| refusal("epoch-range"))?;
    let prior_epoch = i64::try_from(prior_epoch).map_err(|_| refusal("epoch-range"))?;
    let before = i64::try_from(before).map_err(|_| refusal("sequence-range"))?;
    let stored: Option<(String, i64, String)> = connection
        .query_row(
            "SELECT a.body,a.seq,a.prev FROM aura a
         JOIN aura_record_wrappers w ON w.seq=a.seq
         JOIN aura_record_wrappers p ON p.seq=a.seq-1
         WHERE a.seq<?1 AND w.epoch=?2 AND p.epoch=?3
           AND a.phase='terminal' AND a.op!=''
         ORDER BY a.seq DESC LIMIT 1",
            rusqlite::params![before, epoch, prior_epoch],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sql)?;
    let (body, sequence, previous) = stored.ok_or(refusal("membership-unavailable"))?;
    let value = json::parse_strict(body.as_bytes())?;
    if value.canonical_bytes() != body.as_bytes() {
        return Err(refusal("body-not-canonical"));
    }
    let wrapper = AuthorityBodyV1::parse(&value)?;
    let sequence = u64::try_from(sequence).map_err(|_| refusal("sequence-range"))?;
    if wrapper.authority
        != (AuthorityVersion {
            epoch: epoch as u64,
            sequence,
            previous_hash: Some(Digest32::from_hex(&previous)?),
        })
    {
        return Err(refusal("epoch-context"));
    }
    let transition = epoch_transition(&value)?;
    if transition.new.epoch != epoch as u64
        || transition.predecessor
            != (AuthorityVersion {
                epoch: prior_epoch as u64,
                ..wrapper.authority
            })
    {
        return Err(refusal("epoch-context"));
    }
    transition.verify_joint(&transition.old)?;
    Ok(transition.new)
}

/// Stored credentials need a signed binding receipt and uninterrupted membership.
pub(super) fn binding_anchor(
    connection: &Connection,
    binding: &OwnerBinding,
    keys: &[PublicKey],
) -> Result<()> {
    let mut statement = connection
        .prepare(
            "SELECT seq FROM aura WHERE kind IN ('aumlok.enrol','aumlok.bind')
         AND phase='terminal' ORDER BY seq DESC",
        )
        .map_err(sql)?;
    let mut rows = statement.query([]).map_err(sql)?;
    while let Some(row) = rows.next().map_err(sql)? {
        let sequence = u64::try_from(row.get::<_, i64>(0).map_err(sql)?)
            .map_err(|_| refusal("sequence-range"))?;
        let record = io::record_at(connection, sequence)?;
        crate::record::verify_record(&record, keys)?;
        let payload = AuthorityBodyV1::parse(&record.body)?.payload;
        let Some(value) = payload.get("binding") else {
            continue;
        };
        let mut anchored = crate::storage::decode_binding(&value.canonical_bytes())?;
        if anchored.credential_id != binding.credential_id {
            continue;
        }
        if record.operation.is_none()
            || anchored.epoch != record.authority.epoch
            || anchored.epoch > binding.epoch
            || anchored.sign_counter > binding.sign_counter
        {
            return Err(refusal("binding-unanchored"));
        }
        let enrolled_epoch = anchored.epoch;
        anchored.epoch = binding.epoch;
        anchored.sign_counter = binding.sign_counter;
        if &anchored != binding {
            return Err(refusal("binding-unanchored"));
        }
        verify_membership_promotions(connection, binding, keys, sequence, enrolled_epoch)?;
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let counter: Option<i64> = connection
            .query_row(
                "SELECT max(counter) FROM authority_consumptions WHERE credential=?1",
                [URL_SAFE_NO_PAD.encode(binding.credential_id.as_bytes())],
                |row| row.get(0),
            )
            .map_err(sql)?;
        if counter.is_some_and(|counter| counter < 0 || counter > i64::from(binding.sign_counter)) {
            return Err(refusal("counter-rollback"));
        }
        return Ok(());
    }
    Err(refusal("binding-unanchored"))
}

/// Resolve the signed owner binding and preceding counter at a retained row.
pub(super) fn immune_binding_before(
    connection: &Connection,
    credential: &canon::ids::CredentialId,
    epoch: u64,
    before: u64,
    keys: &[PublicKey],
) -> Result<OwnerBinding> {
    let before_sql = i64::try_from(before).map_err(|_| refusal("sequence-range"))?;
    let mut statement = connection.prepare(
        "SELECT seq FROM aura WHERE seq<?1 AND kind IN ('aumlok.enrol','aumlok.bind') AND phase='terminal' ORDER BY seq DESC",
    ).map_err(sql)?;
    let mut rows = statement.query([before_sql]).map_err(sql)?;
    while let Some(row) = rows.next().map_err(sql)? {
        let sequence = u64::try_from(row.get::<_, i64>(0).map_err(sql)?)
            .map_err(|_| refusal("sequence-range"))?;
        let record = io::record_at(connection, sequence)?;
        crate::record::verify_record(&record, keys)?;
        let payload = AuthorityBodyV1::parse(&record.body)?.payload;
        let Some(value) = payload.get("binding") else {
            continue;
        };
        let mut binding = crate::storage::decode_binding(&value.canonical_bytes())?;
        if &binding.credential_id != credential {
            continue;
        }
        if record.operation.is_none()
            || binding.epoch != record.authority.epoch
            || binding.epoch > epoch
        {
            return Err(refusal("immune-binding-context"));
        }
        let enrolled_epoch = binding.epoch;
        binding.epoch = epoch;
        verify_membership_promotions(connection, &binding, keys, sequence, enrolled_epoch)?;
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let previous: Option<u32> = connection.query_row(
            "SELECT max(counter) FROM authority_consumptions WHERE credential=?1 AND sequence<?2",
            rusqlite::params![URL_SAFE_NO_PAD.encode(credential.as_bytes()), before_sql],
            |row| row.get(0),
        ).map_err(sql)?;
        binding.sign_counter = binding.sign_counter.max(previous.unwrap_or(0));
        return Ok(binding);
    }
    Err(refusal("immune-binding-unavailable"))
}

fn verify_membership_promotions(
    connection: &Connection,
    binding: &OwnerBinding,
    keys: &[PublicKey],
    enrolled_sequence: u64,
    mut epoch: u64,
) -> Result<()> {
    let sequence = i64::try_from(enrolled_sequence).map_err(|_| refusal("sequence-range"))?;
    let target_epoch = i64::try_from(binding.epoch).map_err(|_| refusal("epoch-range"))?;
    let mut statement = connection
        .prepare(
            "SELECT a.seq FROM aura a
         JOIN aura_record_wrappers w ON w.seq=a.seq
         JOIN aura_record_wrappers p ON p.seq=a.seq-1
         WHERE a.seq>?1 AND w.epoch<=?2 AND w.epoch!=p.epoch ORDER BY a.seq",
        )
        .map_err(sql)?;
    let mut rows = statement
        .query(rusqlite::params![sequence, target_epoch])
        .map_err(sql)?;
    while let Some(row) = rows.next().map_err(sql)? {
        let sequence = u64::try_from(row.get::<_, i64>(0).map_err(sql)?)
            .map_err(|_| refusal("sequence-range"))?;
        let record = io::record_at(connection, sequence)?;
        crate::record::verify_record(&record, keys)?;
        if record.kind != Kind::AumlokBind {
            return Err(refusal("binding-unanchored"));
        }
        verify_epoch_body(&record, epoch, connection)?;
        let transition = epoch_transition(&record.body)?;
        if !transition.old.members.contains(&binding.public_key)
            || !transition.new.members.contains(&binding.public_key)
        {
            return Err(refusal("binding-membership"));
        }
        epoch = transition.new.epoch;
    }
    if epoch != binding.epoch {
        return Err(refusal("binding-unanchored"));
    }
    Ok(())
}
