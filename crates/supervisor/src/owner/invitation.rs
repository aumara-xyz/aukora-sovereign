// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;

const INVITE_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS supervisor_invite_card (
 id TEXT PRIMARY KEY, auth TEXT NOT NULL, draft TEXT NOT NULL, expires_at INTEGER NOT NULL,
 spent INTEGER NOT NULL DEFAULT 0 CHECK(spent IN(0,1))
);
CREATE TRIGGER IF NOT EXISTS supervisor_invite_card_pin BEFORE UPDATE ON supervisor_invite_card
WHEN NEW.id IS NOT OLD.id OR NEW.auth IS NOT OLD.auth OR NEW.draft IS NOT OLD.draft
 OR NEW.expires_at IS NOT OLD.expires_at OR OLD.spent<>0 OR NEW.spent<>1
BEGIN SELECT RAISE(ABORT,'invites:proof-spent'); END;
CREATE TRIGGER IF NOT EXISTS supervisor_invite_card_retain BEFORE DELETE ON supervisor_invite_card
BEGIN SELECT RAISE(ABORT,'invites:proof-spent'); END;
CREATE TABLE IF NOT EXISTS supervisor_invite (
 id TEXT PRIMARY KEY, event TEXT NOT NULL, expires_at INTEGER NOT NULL
);
CREATE TRIGGER IF NOT EXISTS supervisor_invite_pin BEFORE UPDATE ON supervisor_invite
BEGIN SELECT RAISE(ABORT,'invites:immutable'); END;
CREATE TRIGGER IF NOT EXISTS supervisor_invite_retain BEFORE DELETE ON supervisor_invite
BEGIN SELECT RAISE(ABORT,'invites:immutable'); END;
";

impl Owner {
    pub fn invite_card(
        &mut self,
        request: Value,
        key: &nostr::SecretKey,
    ) -> Result<Value, ApiError> {
        self.invite_card_at(request, key, now()?)
    }

    fn invite_card_at(
        &mut self,
        request: Value,
        key: &nostr::SecretKey,
        at: i64,
    ) -> Result<Value, ApiError> {
        exact(&request, &["root", "invitee_label", "claim_sha256"])?;
        let credential = self
            .credential()?
            .ok_or_else(|| refusal("aumlok:enrolment-required"))?;
        let binding = self
            .binding
            .binding()
            .map_err(|_| storage())?
            .ok_or_else(|| refusal("aumlok:binding-required"))?;
        let id = hex::encode(random::<16>()?);
        let draft = crate::invites::invite_draft(
            key,
            text(&request, "root")?,
            text(&request, "invitee_label")?,
            text(&request, "claim_sha256")?,
            u64::try_from(at).map_err(|_| storage())? / 1000,
            &hex::encode(random::<16>()?),
        )
        .map_err(|_| refusal("invites:shape"))?;
        let (auth, card) = authorization(
            &self.node,
            &binding.subject,
            &id,
            &hex::encode(random::<32>()?),
            at + CEREMONY_MS,
            &draft,
        )?;
        let tx = self
            .binding
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| storage())?;
        tx.execute_batch(INVITE_SCHEMA).map_err(|_| storage())?;
        quota(&tx, at / 1000)?;
        tx.execute(
            "INSERT INTO supervisor_invite_card(id,auth,draft,expires_at) VALUES(?1,?2,?3,?4)",
            params![
                id,
                String::from_utf8(canonical(&auth)?).map_err(|_| storage())?,
                String::from_utf8(canonical(&draft)?).map_err(|_| storage())?,
                at + CEREMONY_MS
            ],
        )
        .map_err(|_| storage())?;
        tx.commit().map_err(|_| storage())?;
        let challenge =
            webauthn::owner_authorization_challenge(&canonical(&auth)?).map_err(|_| storage())?;
        Ok(
            json!({"ceremony_id":id,"card":card,"auth":auth,"display_sha256":auth["display_sha256"],
            "public_key":assertion_options(&self.rp,&credential,&challenge)}),
        )
    }

    pub fn invite_issue(
        &mut self,
        request: Value,
        key: &nostr::SecretKey,
    ) -> Result<Value, ApiError> {
        self.invite_issue_at(request, key, now()?)
    }

    fn invite_issue_at(
        &mut self,
        request: Value,
        key: &nostr::SecretKey,
        at: i64,
    ) -> Result<Value, ApiError> {
        exact(&request, &["ceremony_id", "assertion"])?;
        let id = text(&request, "ceremony_id")?;
        let subject = self
            .binding
            .binding()
            .map_err(|_| storage())?
            .ok_or_else(|| refusal("aumlok:binding-required"))?
            .subject;
        let tx = self
            .binding
            .connection_mut()
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| storage())?;
        tx.execute_batch(INVITE_SCHEMA).map_err(|_| storage())?;
        let row: Option<(String, String, i64, i64)> = tx
            .query_row(
                "SELECT auth,draft,expires_at,spent FROM supervisor_invite_card WHERE id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()
            .map_err(|_| storage())?;
        let (stored, draft, expires, spent) =
            row.ok_or_else(|| refusal("invites:proof-unknown"))?;
        if spent != 0 {
            return Err(refusal("invites:proof-spent"));
        }
        if expires <= at {
            return Err(refusal("invites:proof-expired"));
        }
        let auth: Value = serde_json::from_str(&stored).map_err(|_| storage())?;
        let draft: Value = serde_json::from_str(&draft).map_err(|_| storage())?;
        let (rebuilt, card) = authorization(
            &self.node,
            &subject,
            id,
            text(&auth, "challenge")?,
            expires,
            &draft,
        )?;
        if canonical(&rebuilt)? != stored.as_bytes()
            || draft["pubkey"] != hex::encode(key.public_key())
        {
            return Err(refusal("invites:proof-stale"));
        }
        let verified = verify_refresh_assertion(
            &tx,
            &self.rp,
            &self.origin,
            stored.as_bytes(),
            &request["assertion"],
        )?;
        quota(&tx, at / 1000)?;
        let body: Value = serde_json::from_str(text(&draft, "content")?).map_err(|_| storage())?;
        let event = crate::invites::signed_invite(
            key,
            text(&body, "root")?,
            text(&body, "invitee_label")?,
            text(&body, "claim_sha256")?,
            body["issued_at"].as_u64().ok_or_else(storage)?,
            text(&body, "code")?,
        )
        .map_err(|_| refusal("invites:shape"))?;
        if tx
            .execute(
                "UPDATE supervisor_invite_card SET spent=1 WHERE id=?1 AND spent=0",
                [id],
            )
            .map_err(|_| storage())?
            != 1
        {
            return Err(refusal("invites:proof-spent"));
        }
        persist_assertion_counter(&tx, &verified)?;
        tx.execute(
            "INSERT INTO supervisor_invite VALUES(?1,?2,?3)",
            params![
                hex::encode(event.id),
                event.to_json(),
                body["expires_at"].as_i64().ok_or_else(storage)?
            ],
        )
        .map_err(|_| storage())?;
        append_phase(
            &tx,
            &self.signer,
            at,
            "aumlok.bind",
            id,
            "terminal",
            json!({"schema":"aukora-invite-issue-v1","authorization":rebuilt,"card":card,
                "event_id":hex::encode(event.id),"inviter_npub":body["inviter_npub"],
                "assertion":request["assertion"]}),
        )?;
        tx.commit().map_err(|_| storage())?;
        serde_json::from_str(&event.to_json()).map_err(|_| storage())
    }
}

fn exact(value: &Value, names: &[&str]) -> Result<(), ApiError> {
    if value.as_object().is_none_or(|fields| {
        fields.len() != names.len() || names.iter().any(|name| !fields.contains_key(*name))
    }) {
        return Err(refusal("invites:shape"));
    }
    Ok(())
}

fn quota(tx: &Transaction<'_>, at: i64) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_row(
            "SELECT count(*) FROM supervisor_invite WHERE expires_at>?1",
            [at],
            |r| r.get(0),
        )
        .map_err(|_| storage())?;
    if count >= 3 {
        return Err(refusal("invites:outstanding-limit"));
    }
    Ok(())
}

fn authorization(
    node: &str,
    subject: &str,
    id: &str,
    nonce: &str,
    expires: i64,
    draft: &Value,
) -> Result<(Value, Value), ApiError> {
    let body: Value = serde_json::from_str(text(draft, "content")?).map_err(|_| storage())?;
    let target = "aumlok/invites/issue";
    let card = json!({"v":1,"risk":"critical","says":"Go Sovereign: invite a friend to create one node",
        "facts":[["inviter",body["inviter_npub"]],["invitee",body["invitee_label"]],
            ["root",body["root"]],["expires at (seconds)",body["expires_at"]],
            ["one-time code",body["code"]],["handover commitment",body["claim_sha256"]],
            ["authority","One node creation only; no permission over the friend's node"]],
        "from_to":{"new":draft},"model_note":""});
    let new = gate::sha256(&canonical(draft)?);
    let content = json!({"v":1,"node":node,"target":target,"base_sha256":"absent","new_sha256":new,"cell":null});
    let mut operation = b"aukora:operation-content:v1\0".to_vec();
    operation.extend(canonical(&content)?);
    Ok((
        json!({"v":1,"node":node,"subject":subject,"op":"permission","proposal":id,
        "target":target,"base_sha256":"absent","new_sha256":new,"cell":null,
        "display_sha256":gate::sha256(&canonical(&card)?),"challenge":nonce,"expires_at":expires,
        "epoch":1,"operation":gate::sha256(&operation)}),
        card,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (tempfile::TempDir, Owner, nostr::SecretKey, Value) {
        let dir = tempfile::tempdir().unwrap();
        let mut owner = Owner::open(
            Connection::open(dir.path().join("node.sqlite3")).unwrap(),
            "00000000000000000000000000000001".into(),
            "owner-test.example".into(),
            "https://owner-test.example".into(),
            Arc::new(SigningKey::from_bytes(&[7; 32])),
        )
        .unwrap();
        let p = "owner:00000000000000000000000000000001";
        let start = owner.call(p, Operation::EnrolStart, json!({})).unwrap();
        let stage=owner.call(p,Operation::EnrolFinish,json!({"enrolment_id":start["enrolment_id"],
            "attestation":crate::owner::tests::registration(start["public_key"]["challenge"].as_str().unwrap())})).unwrap();
        owner.call(p,Operation::EnrolFinish,json!({"enrolment_id":start["enrolment_id"],
            "assertion":crate::owner::tests::assertion(stage["public_key"]["challenge"].as_str().unwrap(),1)})).unwrap();
        let prepared = crate::owner::tests::prepare_fast(&mut owner);
        owner.call(p, Operation::BindingConfirm, prepared).unwrap();
        let key = nostr::SecretKey::from_bytes([59; 32]).unwrap();
        let request = json!({"root":nostr::npub_encode(&key.public_key()).unwrap(),"invitee_label":"Friend",
            "claim_sha256":gate::sha256("ab".repeat(32).as_bytes())});
        (dir, owner, key, request)
    }
    fn proof(card: &Value, count: u32) -> Value {
        json!({"ceremony_id":card["ceremony_id"],"assertion":crate::owner::tests::assertion(card["public_key"]["challenge"].as_str().unwrap(),count)})
    }
    #[test]
    fn antibody_invite_fourth_outstanding_is_refused_after_restart() {
        let (dir, mut owner, key, request) = fixture();
        for count in 2..5 {
            let card = owner.invite_card(request.clone(), &key).unwrap();
            let event = owner.invite_issue(proof(&card, count), &key).unwrap();
            nostr::event::Event::parse(&serde_json::to_vec(&event).unwrap()).unwrap();
        }
        drop(owner);
        let mut owner = Owner::open(
            Connection::open(dir.path().join("node.sqlite3")).unwrap(),
            "00000000000000000000000000000001".into(),
            "owner-test.example".into(),
            "https://owner-test.example".into(),
            Arc::new(SigningKey::from_bytes(&[7; 32])),
        )
        .unwrap();
        assert_eq!(
            owner.invite_card(request, &key).unwrap_err().code,
            "invites:outstanding-limit"
        );
    }
    #[test]
    fn antibody_invite_issue_requires_exact_owner_passkey_and_single_use() {
        let (_dir, mut owner, key, request) = fixture();
        let card = owner.invite_card(request.clone(), &key).unwrap();
        assert_eq!(card["auth"]["op"], "permission");
        let mut bad = proof(&card, 2);
        bad["assertion"]["signature"] = json!(URL_SAFE_NO_PAD.encode([0; 64]));
        assert_eq!(
            owner.invite_issue(bad, &key).unwrap_err().code,
            "aumlok:assertion-refused"
        );
        let other = owner.invite_card(request, &key).unwrap();
        assert_eq!(owner.invite_issue(json!({"ceremony_id":other["ceremony_id"],"assertion":proof(&card,2)["assertion"]}),&key).unwrap_err().code,"aumlok:assertion-refused");
        let event = owner.invite_issue(proof(&card, 2), &key).unwrap();
        assert_eq!(event["pubkey"], hex::encode(key.public_key()));
        assert_eq!(
            owner.invite_issue(proof(&card, 3), &key).unwrap_err().code,
            "invites:proof-spent"
        );
        let db = owner.binding.connection();
        assert!(db.execute("DELETE FROM supervisor_invite", []).is_err());
        assert!(db
            .execute("UPDATE supervisor_invite SET expires_at=0", [])
            .is_err());
    }
    #[test]
    fn antibody_invite_issue_rechecks_quota_and_card_expiry() {
        let (_dir, mut owner, key, request) = fixture();
        let at = now().unwrap();
        let pending = owner.invite_card_at(request.clone(), &key, at).unwrap();
        assert_eq!(
            owner
                .invite_issue_at(proof(&pending, 2), &key, at + CEREMONY_MS)
                .unwrap_err()
                .code,
            "invites:proof-expired"
        );
        for count in 2..5 {
            let card = owner.invite_card_at(request.clone(), &key, at).unwrap();
            owner
                .invite_issue_at(proof(&card, count), &key, at)
                .unwrap();
        }
        assert_eq!(
            owner
                .invite_issue_at(proof(&pending, 5), &key, at)
                .unwrap_err()
                .code,
            "invites:outstanding-limit"
        );
        assert_eq!(
            owner
                .invite_issue_at(proof(&pending, 5), &key, at + CEREMONY_MS)
                .unwrap_err()
                .code,
            "invites:proof-expired"
        );
        owner
            .invite_card_at(
                request,
                &key,
                at + (crate::invites::TTL_SECONDS as i64) * 1000,
            )
            .unwrap();
    }

    #[test]
    fn antibody_invite_card_bytes_are_rebuilt_before_signing() {
        let (_dir, mut owner, key, request) = fixture();
        let card = owner.invite_card(request, &key).unwrap();
        let db = owner.binding.connection();
        db.execute_batch("DROP TRIGGER supervisor_invite_card_pin")
            .unwrap();
        db.execute("UPDATE supervisor_invite_card SET auth=json_set(auth,'$.target','aumlok/other') WHERE id=?1",[card["ceremony_id"].as_str().unwrap()]).unwrap();
        assert_eq!(
            owner.invite_issue(proof(&card, 2), &key).unwrap_err().code,
            "invites:proof-stale"
        );
    }
}
