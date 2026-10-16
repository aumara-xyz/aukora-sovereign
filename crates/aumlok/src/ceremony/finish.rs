// SPDX-License-Identifier: AGPL-3.0-or-later
//! Nonce consumption and signed terminal checks share one borrowed transaction.

use super::*;
use canon::alg::PublicKey;
use canon::authority::ceremony::{CeremonyFinish, CeremonyKind};
use canon::authority::{AuthorityRecord, Kind};
use canon::json::Value;
use rusqlite::{params, OptionalExtension, Transaction};

mod receipt;

/// The supplied transaction already holds the ceremony in its spent state.
pub trait CeremonyAuthorityWriter {
    fn persist(
        &self,
        transaction: &Transaction<'_>,
        request: &CeremonyFinish<'_>,
        body: &Value,
    ) -> Result<AuthorityRecord>;
    fn credential(&self, transaction: &Transaction<'_>, id: &CredentialId) -> Result<Credential>;
    fn owner_binding(
        &self,
        transaction: &Transaction<'_>,
        id: &CredentialId,
    ) -> Result<OwnerBinding>;
}

/// Borrowed storage and trusted signer keys; construction grants no owner proof.
pub struct CeremonyWrite<'a> {
    transaction: &'a Transaction<'a>,
    identity: Digest32,
    signing_keys: &'a [PublicKey],
    writer: &'a dyn CeremonyAuthorityWriter,
}

impl<'a> CeremonyWrite<'a> {
    pub fn new(
        transaction: &'a Transaction<'a>,
        identity: Digest32,
        signing_keys: &'a [PublicKey],
        writer: &'a dyn CeremonyAuthorityWriter,
    ) -> Self {
        Self {
            transaction,
            identity,
            signing_keys,
            writer,
        }
    }

    fn finish(
        &self,
        row: &CeremonySnapshot,
        credential: &Credential,
        request: &CeremonyFinish<'_>,
        authority: AuthorityVersion,
    ) -> Result<()> {
        let tx = self.transaction;
        if self.identity != request.transaction_id
            || tx.is_autocommit()
            || tx.path().is_none_or(str::is_empty)
            || authority.epoch != row.authority.epoch
            || authority.sequence < row.authority.sequence
            || (authority.sequence == row.authority.sequence
                && authority.previous_hash != row.authority.previous_hash)
        {
            return Err(refusal("canon-ceremony-contract"));
        }
        let kind = match (row.purpose, row.state) {
            (CeremonyPurpose::Enrolment, CeremonyState::Registered) => Kind::AumlokEnrol,
            (CeremonyPurpose::SignIn, CeremonyState::Fresh) => Kind::AumlokSignin,
            _ => return Err(refusal("ceremony-state")),
        };
        tx.execute_batch("SAVEPOINT aumlok_finish_v1")
            .map_err(store_error)?;
        let mut rollback = Rollback {
            transaction: tx,
            active: true,
        };
        durable::check_finish_row(tx, row, request.now_ms)?;
        require_head(tx, authority)?;
        let body = record_body(request, authority)?;
        transition(tx, row, "spent", request.now_ms)?;
        let mut stored = row.clone();
        stored.state = CeremonyState::Spent;
        durable::check_finish_row(tx, &stored, request.now_ms)?;
        let record = self.writer.persist(tx, request, &body)?;
        durable::check_finish_row(tx, &stored, request.now_ms)?;
        if record.actor != request.owner_id
            || self
                .writer
                .credential(tx, &credential.binding.credential_id)?
                != *credential
            || self
                .writer
                .owner_binding(tx, &credential.binding.credential_id)?
                != credential.binding
        {
            return Err(refusal("canon-ceremony-contract"));
        }
        receipt::verify(
            tx,
            &record,
            &body,
            authority,
            kind,
            row.id,
            request.now_ms,
            self.signing_keys,
        )?;
        transition(tx, &stored, "finished", request.now_ms)?;
        stored.state = CeremonyState::Finished;
        durable::check_finish_row(tx, &stored, request.now_ms)?;
        tx.execute_batch("RELEASE aumlok_finish_v1")
            .map_err(store_error)?;
        rollback.active = false;
        Ok(())
    }
}

pub(super) fn complete<T: CeremonyReadTxn + ?Sized>(
    txn: &mut T,
    transaction_id: Digest32,
    row: CeremonySnapshot,
    credential: &Credential,
    assertion: &AssertionMaterial,
    now_ms: i64,
) -> Result<()> {
    let kind = match row.purpose {
        CeremonyPurpose::Enrolment => CeremonyKind::Enrolment,
        CeremonyPurpose::SignIn => CeremonyKind::SignIn,
        _ => return Err(refusal("ceremony-kind")),
    };
    let authority = txn.ceremony_authority()?;
    if txn.transaction_id() != transaction_id {
        return Err(refusal("ceremony-stale"));
    }
    let assertion_json =
        serde_json::to_vec(assertion).map_err(|_| refusal("ceremony-data-invalid"))?;
    let request = CeremonyFinish {
        transaction_id,
        id: row.id,
        kind,
        session: row.session,
        subject: row.subject.ok_or_else(|| refusal("ceremony-subject"))?,
        authority: row.authority,
        nonce: row.nonce,
        expires_at_ms: row.expires_at_ms,
        candidate_digest: row.candidate_digest,
        binding: &credential.binding,
        owner_id: &credential.owner_id,
        user_handle: &credential.user_handle,
        backup_eligible: credential.backup_eligible,
        assertion_json: &assertion_json,
        now_ms,
    };
    if kind == CeremonyKind::Enrolment {
        if authority.epoch != 0 || credential.binding.epoch != 1 {
            return Err(refusal("ceremony-stale"));
        }
        return txn.finish_ceremony(request);
    }
    txn.ceremony_write()?
        .finish(&row, credential, &request, authority)
}

fn require_head(tx: &Transaction<'_>, expected: AuthorityVersion) -> Result<()> {
    let head: Option<(i64, String)> = tx
        .query_row(
            "SELECT seq,hash FROM aura ORDER BY seq DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(store_error)?;
    let matches = match head {
        None => expected.sequence == 1 && expected.previous_hash.is_none(),
        Some((sequence, hash)) => {
            u64::try_from(sequence).ok().and_then(|n| n.checked_add(1)) == Some(expected.sequence)
                && expected.previous_hash == Some(Digest32::from_hex(&hash)?)
        }
    };
    if !matches {
        return Err(refusal("ceremony-stale"));
    }
    Ok(())
}

fn transition(tx: &Transaction<'_>, row: &CeremonySnapshot, next: &str, now_ms: i64) -> Result<()> {
    let previous = match (row.purpose, row.state, next) {
        (CeremonyPurpose::Enrolment, CeremonyState::Registered, "spent") => "registered",
        (CeremonyPurpose::SignIn, CeremonyState::Fresh, "spent") => "fresh",
        (
            CeremonyPurpose::Enrolment | CeremonyPurpose::SignIn,
            CeremonyState::Spent,
            "finished",
        ) => "spent",
        _ => return Err(refusal("ceremony-state")),
    };
    let changed = tx
        .execute(
            "UPDATE aumlok_ceremonies_v1 SET state=?1,last_seen=?2
         WHERE id=?3 AND nonce=?4 AND purpose=?5 AND state=?6
         AND issued<=?2 AND last_seen<=?2 AND deadline>?2",
            params![
                next,
                now_ms,
                row.id.as_bytes().as_slice(),
                row.nonce.as_slice(),
                row.purpose.wire_name(),
                previous
            ],
        )
        .map_err(store_error)?;
    if changed != 1 {
        return Err(refusal("ceremony-state"));
    }
    Ok(())
}

fn record_body(request: &CeremonyFinish<'_>, authority: AuthorityVersion) -> Result<Value> {
    let binding = request.binding;
    let assertion: serde_json::Value = serde_json::from_slice(request.assertion_json)
        .map_err(|_| refusal("ceremony-data-invalid"))?;
    let body = serde_json::json!({
        "schema": "aukora-aumlok-ceremony-finish-v1",
        "algorithm": "sha256", "epoch": authority.epoch, "sequence": authority.sequence,
        "previous_hash": authority.previous_hash.map(|hash| hash.to_string()),
        "ceremony": request.id.to_string(), "nonce": hex::encode(request.nonce),
        "session": request.session.to_string(), "subject": request.subject.to_string(),
        "expires_at": request.expires_at_ms,
        "candidate_digest": request.candidate_digest.map(|hash| hash.to_string()),
        "ceremony_authority": {
            "epoch": request.authority.epoch, "sequence": request.authority.sequence,
            "previous_hash": request.authority.previous_hash.map(|hash| hash.to_string()),
        },
        "owner_id": request.owner_id, "user_handle": hex::encode(request.user_handle),
        "backup_eligible": request.backup_eligible, "assertion": assertion,
        "binding": {
            "v": binding.v, "algorithm": binding.algorithm.wire_name(),
            "credential": hex::encode(binding.credential_id.as_bytes()),
            "key_version": binding.public_key.v,
            "key_algorithm": binding.public_key.algorithm.wire_name(),
            "public_key": hex::encode(&binding.public_key.bytes), "epoch": binding.epoch,
            "rp": binding.relying_party, "owner_origin": binding.owner_origin,
            "top_origin": binding.top_origin, "counter": binding.sign_counter,
        },
    });
    let bytes = serde_json::to_vec(&body).map_err(|_| refusal("ceremony-data-invalid"))?;
    canon::json::parse_strict(&bytes)
}

struct Rollback<'a> {
    transaction: &'a Transaction<'a>,
    active: bool,
}

impl Drop for Rollback<'_> {
    fn drop(&mut self) {
        if self.active
            && self
                .transaction
                .execute_batch("ROLLBACK TO aumlok_finish_v1; RELEASE aumlok_finish_v1")
                .is_err()
        {
            let _ = self.transaction.execute_batch("ROLLBACK");
        }
    }
}

fn store_error(_: rusqlite::Error) -> Refusal {
    refusal("store-error")
}
