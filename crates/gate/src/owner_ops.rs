use super::*;
type RetainedOwnerAction = (
    String,
    Vec<u8>,
    Vec<u8>,
    String,
    i64,
    i64,
    String,
    i64,
    String,
    String,
);

impl<S: TargetStore, L: Ledger, P: OwnerProof, C: Clock> Gate<S, L, P, C> {
    pub(crate) fn retire_authorization(&mut self, id: &str) -> Result<Vec<u8>> {
        self.action_authorization(id, "retire")
    }
    pub(crate) fn reconcile_authorization(&mut self, id: &str) -> Result<Vec<u8>> {
        self.action_authorization(id, "reconcile")
    }
    fn action_authorization(&mut self, id: &str, op: &str) -> Result<Vec<u8>> {
        let at = self.now()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let p = load_proposal(&tx, id)?.ok_or(Error::Refused("gate:unknown-proposal"))?;
        if (op == "retire" && p.state == State::Retired)
            || (op == "reconcile"
                && tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM gate_reconciliations WHERE proposal_id=?)",
                    [id],
                    |r| r.get::<_, bool>(0),
                )?)
        {
            return Ok(tx.query_row("SELECT auth FROM gate_actions WHERE proposal_id=? AND op=? AND state='spent' ORDER BY issued DESC LIMIT 1",params![id,op],|r|r.get(0))?);
        }
        if op == "retire" && p.state != State::Pending {
            return Err(Error::Refused("gate:not-retirable"));
        }
        if op == "reconcile" && !matches!(p.state, State::Incomplete | State::Conflict) {
            return Err(Error::Refused("gate:not-reconcilable"));
        }
        let current = target_hash(&self.store.read(&p.target)?);
        let card=canonical(&json!({"v":1,"risk":"critical","says":if op=="retire" {"Retire this pending proposal without applying it."} else {"Close this observed outcome without retrying it; adopt the current target hash as the new base."},
            "facts":[["operation",op],["proposal",id],["target",p.target],["digest",p.digest],["current_sha256",current]],"from_to":{"state":p.state.as_str(),"operation":op},"model_note":"","model_note_label":"UNVERIFIED MODEL NOTE; DATA ONLY"}))?.into_bytes();
        if card.len() > self.config.limits.display_max_bytes {
            return Err(Error::Refused("gate:display-too-large"));
        }
        let expires = checked_time(
            at.checked_add(self.config.limits.review_ttl_ms)
                .ok_or(Error::Refused("gate:clock"))?,
        )?;
        let challenge = random_hex(32)?;
        let auth = if op == "retire" {
            retirement_auth(
                &tx,
                &self.config,
                &p,
                &challenge,
                at,
                expires,
                &sha256(&card),
            )?
        } else {
            authorization_for_op(
                &tx,
                &self.config,
                &p,
                &challenge,
                at,
                expires,
                &sha256(&card),
                op,
            )?
        };
        let owner = owner_text(&self.config.owner)?;
        assert_owner(&tx, &owner)?;
        tx.execute("UPDATE gate_actions SET state='invalidated' WHERE proposal_id=? AND op=? AND state='live'",params![id,op])?;
        let issue = append(
            &self.ledger,
            &tx,
            at,
            "gate.review",
            "gate",
            id,
            "fact",
            json!({"authorization":serde_json::from_slice::<Value>(&auth)?,"card":serde_json::from_slice::<Value>(&card)?,"owner_state":serde_json::from_str::<Value>(&owner)?}),
        )?;
        tx.execute(
            "INSERT INTO gate_actions VALUES(?,?,?,?,?,?,?,?,?,?,?,'live')",
            params![
                id, op, challenge, auth, card, owner, at, expires, current, issue.seq, issue.hash
            ],
        )?;
        let final_at = checked_time(self.clock.now_ms()?)?;
        if final_at < at || final_at >= expires {
            return Err(Error::Refused("gate:expired"));
        }
        assert_owner(&tx, &owner)?;
        tx.commit()?;
        Ok(auth)
    }
    pub(crate) fn retire(&mut self, id: &str, proof: &[u8]) -> Result<String> {
        self.finish_action(id, proof, "retire")
    }
    pub(crate) fn reconcile(&mut self, id: &str, proof: &[u8]) -> Result<String> {
        self.finish_action(id, proof, "reconcile")
    }
    fn finish_action(&mut self, id: &str, proof: &[u8], op: &str) -> Result<String> {
        let at = self.now()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let p = load_proposal(&tx, id)?.ok_or(Error::Refused("gate:unknown-proposal"))?;
        let retained = if op == "retire" {
            p.state == State::Retired
        } else {
            tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM gate_reconciliations WHERE proposal_id=?)",
                [id],
                |r| r.get::<_, bool>(0),
            )?
        };
        let action:RetainedOwnerAction=tx.query_row("SELECT challenge,auth,card,owner_text,issued,expires,current_sha256,issue_seq,issue_hash,state FROM gate_actions WHERE proposal_id=? AND op=? AND state=? ORDER BY issued DESC LIMIT 1",params![id,op,if retained {"spent"} else {"live"}],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?)))?;
        let verified = self
            .proof
            .verify_in_transaction(&tx, &action.1, proof, retained)?;
        if verified.credential_id != self.config.owner.binding_sha256 {
            return Err(Error::Refused("gate:credential-mismatch"));
        }
        assert_owner(&tx, &action.3)?;
        if action.3 != owner_text(&self.config.owner)? {
            return Err(Error::Refused("gate:owner-state-changed"));
        }
        let rebuilt = authorization_for_op(
            &tx,
            &self.config,
            &p,
            &action.0,
            action.4,
            action.5,
            &sha256(&action.2),
            op,
        )?;
        if rebuilt != action.1 {
            return Err(Error::Refused("gate:authorization-mismatch"));
        }
        let issue = self.ledger.read_verified(
            &tx,
            &LedgerRef {
                seq: action.7,
                hash: action.8.clone(),
            },
        )?;
        let detail: Value = serde_json::from_str(&issue.body)?;
        if issue.kind != "gate.review"
            || issue.op != id
            || issue.phase != "fact"
            || canonical(&detail["authorization"])?.as_bytes() != action.1
            || canonical(&detail["card"])?.as_bytes() != action.2
            || canonical(&detail["owner_state"])? != action.3
        {
            return Err(Error::Refused("gate:review-evidence-unavailable"));
        }
        if retained {
            if op == "retire" {
                drop(tx);
                return self
                    .receipt(id)?
                    .ok_or(Error::Refused("gate:receipt-unavailable"));
            }
            verified_reconciliation(&tx, &self.ledger, id)?
                .ok_or(Error::Refused("gate:reconciliation-unavailable"))?;
            let (seq, hash): (i64, String) = tx.query_row(
                "SELECT seq,hash FROM gate_reconciliations WHERE proposal_id=?",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let row = self.ledger.read_verified(&tx, &LedgerRef { seq, hash })?;
            if row.kind != "gate.recover" || row.op != id || row.phase != "fact" {
                return Err(Error::Refused("gate:reconciliation-unavailable"));
            }
            return Ok(row.body);
        }
        if at < action.4 || at >= action.5 {
            return Err(Error::Refused("gate:expired"));
        }
        if op == "retire" && p.state != State::Pending {
            return Err(Error::Refused("gate:not-retirable"));
        }
        if op == "reconcile" && !matches!(p.state, State::Incomplete | State::Conflict) {
            return Err(Error::Refused("gate:not-reconcilable"));
        }
        if target_hash(&self.store.read(&p.target)?) != action.6 {
            return Err(Error::Refused("gate:reconcile-target-changed"));
        }
        counter_cas(&tx, &verified.credential_id, verified.counter)?;
        self.proof.persist_counter(&tx, &verified)?;
        let receipt = canonical(
            &json!({"v":3,"kind":op,"operation_id":id,"digest":p.digest,"operation":op,"decision":"DENIED","intent_confirmed":false,"effect_confirmed":false,"node":self.config.node,"owner_epoch":self.config.owner.epoch,
            "approver":self.config.owner.subject,"pubkey_fp":&self.config.gate_pubkey_sha256[..16],"gate_pubkey_sha256":self.config.gate_pubkey_sha256,"owner_accepted_at_ms":at,
            "owner_authorization":{"version":1,"kind":"aukora-owner-authorization-ref/v1","authorization_id":sha256(&[b"aukora:owner-authorization:v1\0".as_slice(),&action.1].concat()),"proof_sha256":sha256(proof)},
            "owner_consumption":{"review_issue":{"seq":action.7,"hash":action.8,"ledger_seq":action.7,"ledger_hash":action.8}},"base_sha256":action.6,"retry":false,"at":at}),
        )?;
        let row = append(
            &self.ledger,
            &tx,
            at,
            if op == "retire" {
                "gate.retire"
            } else {
                "gate.recover"
            },
            &self.config.owner.subject,
            id,
            if op == "retire" { "terminal" } else { "fact" },
            json!({"receipt":serde_json::from_str::<Value>(&receipt)?,"authorization":serde_json::from_slice::<Value>(&action.1)?,"proof_hex":hex::encode(proof)}),
        )?;
        let final_at = checked_time(self.clock.now_ms()?)?;
        if final_at < at || final_at >= action.5 {
            return Err(Error::Refused("gate:expired"));
        }
        assert_owner(&tx, &action.3)?;
        if target_hash(&self.store.read(&p.target)?) != action.6 {
            return Err(Error::Refused("gate:reconcile-target-changed"));
        }
        if op == "retire" {
            tx.execute(
                "INSERT INTO gate_receipts VALUES(?,?,?,?)",
                params![id, receipt, row.seq, row.hash],
            )?;
            transition(&tx, &p, State::Retired, at)?;
            tx.execute(
                "UPDATE gate_reviews SET state='invalidated' WHERE proposal_id=? AND state='live'",
                [id],
            )?;
        } else {
            tx.execute(
                "INSERT INTO gate_reconciliations VALUES(?,?,?,?)",
                params![id, action.6, row.seq, row.hash],
            )?;
        }
        if tx.execute(
            "UPDATE gate_actions SET state='spent' WHERE challenge=? AND state='live'",
            [action.0],
        )? != 1
        {
            return Err(Error::Refused("gate:challenge-conflict"));
        }
        tx.commit()?;
        Ok(receipt)
    }
}
