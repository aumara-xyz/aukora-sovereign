// SPDX-License-Identifier: AGPL-3.0-or-later
//! Signed identity binding and ciphertext refresh retain the enrolment anchor.

use super::*;

fn checked_identity(
    row: &Ceremony,
    credential: &PendingOwnerCredential,
    refresh: bool,
) -> Result<(SubjectId, PublicKey)> {
    check_credential_context(&row.context, credential)?;
    if !matches!(row.candidate.view(), ValueView::Null) || row.candidate_digest.is_some() {
        return Err(refusal("identity-context"));
    }
    identity(&row.payload, refresh)
}

pub(super) fn verify_initial(
    connection: &Connection,
    record: &AuthorityRecord,
    keys: &[PublicKey],
) -> Result<BoundOwnerIdentity> {
    let body = payload(record)?;
    if text(&body, "schema")? != BIND
        || record.kind != Kind::AumlokBind
        || record.authority.epoch != 1
    {
        return Err(refusal("binding-anchor"));
    }
    let mut credential = read_pending(connection, keys, record.authority.sequence)?
        .ok_or(refusal("enrolment-required"))?;
    let row = Ceremony::retained(record, &body, "binding")?;
    let session = SessionId::from_hex(text(&row.context, "session")?)?;
    check_context(
        connection,
        &row.context,
        AuthorityVersion {
            epoch: 0,
            ..record.authority
        },
        session,
    )?;
    check_enrolment_reference(&body, &credential)?;
    if !matches!(field(&row.context, "subject")?.view(), ValueView::Null) {
        return Err(refusal("identity-context"));
    }
    let (subject, identity_public_key) = checked_identity(&row, &credential, false)?;
    if text(&body, "subject")? != subject.to_string() {
        return Err(refusal("identity-subject"));
    }
    let (_, counter) = assert_possession(
        &field(&body, "assertion")?.canonical_bytes(),
        &credential.binding,
        &credential.user_handle,
        credential.backup_eligible,
        &challenge("binding", &row.nonce, &row.payload)?,
    )?;
    credential.binding.epoch = 1;
    credential.binding.sign_counter = counter;
    credential.session = session;
    if storage::owner_binding_from_value(field(&body, "binding")?)? != credential.binding {
        return Err(refusal("binding-anchor"));
    }
    Ok(BoundOwnerIdentity {
        subject,
        identity_public_key,
        envelope: field(&row.payload, "envelope")?.clone(),
        revision: 1,
        credential,
    })
}

fn verify_later(
    connection: &Connection,
    record: &AuthorityRecord,
    owner: &mut BoundOwnerIdentity,
) -> Result<()> {
    let body = payload(record)?;
    let (purpose, expected_kind, refresh) = match text(&body, "schema")? {
        SIGNIN => ("signin", Kind::AumlokSignin, false),
        REFRESH => ("refresh", Kind::AumlokBind, true),
        _ => return Err(refusal("identity-anchor")),
    };
    if record.kind != expected_kind || record.authority.epoch != owner.credential.binding.epoch {
        return Err(refusal("identity-anchor"));
    }
    let row = Ceremony::retained(record, &body, purpose)?;
    let session = SessionId::from_hex(text(&row.context, "session")?)?;
    check_context(connection, &row.context, record.authority, session)?;
    check_credential_context(&row.context, &owner.credential)?;
    check_enrolment_reference(&body, &owner.credential)?;
    if text(&row.context, "subject")? != owner.subject.to_string()
        || text(&body, "subject")? != owner.subject.to_string()
        || !matches!(row.candidate.view(), ValueView::Null)
        || row.candidate_digest.is_some()
    {
        return Err(refusal("identity-context"));
    }
    let challenge = if refresh {
        let (subject, key) = checked_identity(&row, &owner.credential, true)?;
        if subject != owner.subject
            || key != owner.identity_public_key
            || text(&row.payload, "previous_envelope_sha256")?
                != Digest32::sha256(&owner.envelope.canonical_bytes()).to_string()
            || field(&row.payload, "envelope")? == &owner.envelope
        {
            return Err(refusal("identity-envelope-stale"));
        }
        challenge("refresh", &row.nonce, &row.payload)?
    } else {
        if !matches!(row.payload.view(), ValueView::Null) {
            return Err(refusal("identity-context"));
        }
        row.nonce
    };
    if let Some(counter) = prior_consumption_counter(
        connection,
        &owner.credential.binding.credential_id,
        record.authority.sequence,
    )? {
        owner.credential.binding.sign_counter = owner.credential.binding.sign_counter.max(counter);
    }
    let (_, counter) = assert_possession(
        &field(&body, "assertion")?.canonical_bytes(),
        &owner.credential.binding,
        &owner.credential.user_handle,
        owner.credential.backup_eligible,
        &challenge,
    )?;
    owner.credential.binding.sign_counter = counter;
    owner.credential.session = session;
    if storage::owner_binding_from_value(field(&body, "binding")?)? != owner.credential.binding {
        return Err(refusal("identity-anchor"));
    }
    if refresh {
        owner.envelope = field(&row.payload, "envelope")?.clone();
        owner.revision = owner
            .revision
            .checked_add(1)
            .ok_or(refusal("identity-range"))?;
    }
    Ok(())
}

pub(in crate::ledger) fn read_bound(
    connection: &Connection,
    keys: &[PublicKey],
    before: u64,
) -> Result<Option<BoundOwnerIdentity>> {
    let mut statement = connection.prepare("SELECT a.seq FROM aura a JOIN aura_record_wrappers w ON w.seq=a.seq WHERE a.seq<?1 AND w.epoch>0 AND a.kind IN ('aumlok.bind','aumlok.signin') AND a.phase='terminal' ORDER BY a.seq").map_err(sql)?;
    let mut rows = statement
        .query([i64::try_from(before).map_err(|_| refusal("identity-range"))?])
        .map_err(sql)?;
    let mut owner = None;
    while let Some(row) = rows.next().map_err(sql)? {
        let sequence = u64::try_from(row.get::<_, i64>(0).map_err(sql)?)
            .map_err(|_| refusal("identity-range"))?;
        let record = io::record_at(connection, sequence)?;
        crate::record::verify_record(&record, keys)?;
        let body = payload(&record)?;
        let schema = body.get("schema").and_then(|value| match value.view() {
            ValueView::Text(value) => Some(value),
            _ => None,
        });
        match schema {
            Some(BIND) if owner.is_none() => {
                owner = Some(verify_initial(connection, &record, keys)?)
            }
            Some(SIGNIN | REFRESH) => verify_later(
                connection,
                &record,
                owner.as_mut().ok_or(refusal("binding-required"))?,
            )?,
            Some(BIND) => return Err(refusal("binding-exists")),
            _ => {
                if let Some(current) = owner.as_mut() {
                    let old_epoch = current.credential.binding.epoch;
                    if record.authority.epoch != old_epoch {
                        super::super::verify_epoch_body(&record, old_epoch, connection)?;
                        let transition = super::super::epoch_transition(&record.body)?;
                        if !transition
                            .old
                            .members
                            .contains(&current.credential.binding.public_key)
                            || !transition
                                .new
                                .members
                                .contains(&current.credential.binding.public_key)
                        {
                            return Err(refusal("binding-membership"));
                        }
                        current.credential.binding.epoch = transition.new.epoch;
                    }
                }
            }
        }
    }
    Ok(owner)
}

impl LedgerTxn<'_> {
    pub(in crate::ledger) fn bound_identity(&self) -> Result<Option<BoundOwnerIdentity>> {
        self.active()?;
        if self.state.epoch == 0 {
            return Ok(None);
        }
        let mut owner = match read_bound(
            &self.transaction,
            &self.state.keys,
            self.state.next()?.sequence,
        )? {
            Some(owner) => owner,
            None => return Ok(None),
        };
        if owner.credential.binding.epoch != self.state.epoch {
            return Err(refusal("identity-epoch-transition"));
        }
        let (bytes, counter): (Vec<u8>, u32) = self
            .transaction
            .query_row(
                "SELECT body,counter FROM authority_bindings WHERE credential=?1",
                [URL_SAFE_NO_PAD.encode(owner.credential.binding.credential_id.as_bytes())],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(sql)?;
        let mut binding = storage::decode_binding(&bytes)?;
        if binding.sign_counter > counter
            || owner.credential.binding.sign_counter > counter
            || prior_consumption_counter(
                &self.transaction,
                &binding.credential_id,
                self.state.next()?.sequence,
            )?
            .is_some_and(|maximum| maximum > counter)
        {
            return Err(refusal("counter-rollback"));
        }
        binding.sign_counter = owner.credential.binding.sign_counter;
        if binding != owner.credential.binding {
            return Err(refusal("binding-context"));
        }
        owner.credential.binding.sign_counter = counter;
        Ok(Some(owner))
    }
    pub(in crate::ledger) fn bind_pending(
        &mut self,
        request: BindingFinish<'_>,
    ) -> Result<BoundOwnerIdentity> {
        self.identity_ready(request.transaction_id)?;
        let mut credential = self
            .pending_credential()?
            .ok_or(refusal("enrolment-required"))?;
        let occupied: bool = self
            .transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM authority_bindings)",
                [],
                |row| row.get(0),
            )
            .map_err(sql)?;
        if occupied {
            return Err(refusal("binding-exists"));
        }
        let now = self.services.clock.now_ms()?;
        let row = Ceremony::load(
            &self.transaction,
            request.id,
            request.session,
            now,
            request.now_ms,
            self.state.next()?,
        )?;
        if row.purpose != "binding"
            || row.state != "prepared"
            || !matches!(field(&row.context, "subject")?.view(), ValueView::Null)
        {
            return Err(refusal("binding-context"));
        }
        let (subject, public_key) = checked_identity(&row, &credential, false)?;
        if subject != request.subject
            || &public_key != request.identity_public_key
            || field(&row.payload, "envelope")? != request.envelope
        {
            return Err(refusal("binding-context"));
        }
        let (assertion, counter) = assert_possession(
            request.assertion_json,
            &credential.binding,
            &credential.user_handle,
            credential.backup_eligible,
            &challenge("binding", &row.nonce, &row.payload)?,
        )?;
        credential.binding.epoch = 1;
        credential.binding.sign_counter = counter;
        let body = row.receipt(BIND, assertion, &credential.binding, Some(&credential))?;
        row.transition(&self.transaction, "prepared", "spent", now)?;
        self.transaction
            .execute(
                "INSERT INTO authority_bindings(credential,body,counter) VALUES(?1,?2,?3)",
                params![
                    URL_SAFE_NO_PAD.encode(credential.binding.credential_id.as_bytes()),
                    storage::encode_binding(&credential.binding)?,
                    counter
                ],
            )
            .map_err(sql)?;
        self.state.epoch = 1;
        let record = self.identity_record(&row, Kind::AumlokBind, body, now)?;
        let owner = verify_initial(&self.transaction, &record, &self.state.keys)?;
        row.transition(&self.transaction, "spent", "finished", now)?;
        Ok(owner)
    }
    pub(in crate::ledger) fn finish_bound(
        &mut self,
        request: BoundCeremonyFinish<'_>,
    ) -> Result<BoundOwnerIdentity> {
        self.identity_ready(request.transaction_id)?;
        let mut owner = self.bound_identity()?.ok_or(refusal("binding-required"))?;
        let now = self.services.clock.now_ms()?;
        let row = Ceremony::load(
            &self.transaction,
            request.id,
            request.session,
            now,
            request.now_ms,
            self.state.next()?,
        )?;
        let (schema, kind, initial_state, challenge) = match row.purpose.as_str() {
            "signin" if row.state == "fresh" && matches!(row.payload.view(), ValueView::Null) => {
                (SIGNIN, Kind::AumlokSignin, "fresh", row.nonce)
            }
            "refresh" if row.state == "prepared" => {
                let (subject, key) = checked_identity(&row, &owner.credential, true)?;
                if subject != owner.subject
                    || key != owner.identity_public_key
                    || text(&row.payload, "previous_envelope_sha256")?
                        != Digest32::sha256(&owner.envelope.canonical_bytes()).to_string()
                    || field(&row.payload, "envelope")? == &owner.envelope
                {
                    return Err(refusal("identity-envelope-stale"));
                }
                (
                    REFRESH,
                    Kind::AumlokBind,
                    "prepared",
                    challenge("refresh", &row.nonce, &row.payload)?,
                )
            }
            _ => return Err(refusal("identity-ceremony")),
        };
        check_credential_context(&row.context, &owner.credential)?;
        if text(&row.context, "subject")? != owner.subject.to_string() {
            return Err(refusal("identity-context"));
        }
        let old_counter = owner.credential.binding.sign_counter;
        let (assertion, counter) = assert_possession(
            request.assertion_json,
            &owner.credential.binding,
            &owner.credential.user_handle,
            owner.credential.backup_eligible,
            &challenge,
        )?;
        owner.credential.binding.sign_counter = counter;
        owner.credential.session = request.session;
        let body = row.receipt(
            schema,
            assertion,
            &owner.credential.binding,
            Some(&owner.credential),
        )?;
        row.transition(&self.transaction, initial_state, "spent", now)?;
        let changed = self
            .transaction
            .execute(
                "UPDATE authority_bindings SET counter=?1 WHERE credential=?2 AND counter=?3",
                params![
                    counter,
                    URL_SAFE_NO_PAD.encode(owner.credential.binding.credential_id.as_bytes()),
                    old_counter
                ],
            )
            .map_err(sql)?;
        if changed != 1 {
            return Err(refusal("counter-rollback"));
        }
        self.identity_record(&row, kind, body, now)?;
        row.transition(&self.transaction, "spent", "finished", now)?;
        if schema == REFRESH {
            owner.envelope = field(&row.payload, "envelope")?.clone();
            owner.revision = owner
                .revision
                .checked_add(1)
                .ok_or(refusal("identity-range"))?;
        }
        Ok(owner)
    }
}

fn prior_consumption_counter(
    connection: &Connection,
    credential: &CredentialId,
    before: u64,
) -> Result<Option<u32>> {
    connection
        .query_row(
            "SELECT max(counter) FROM authority_consumptions WHERE credential=?1 AND sequence<?2",
            params![
                URL_SAFE_NO_PAD.encode(credential.as_bytes()),
                i64::try_from(before).map_err(|_| refusal("identity-range"))?
            ],
            |row| row.get(0),
        )
        .map_err(sql)
}
