//! Standing authority is an applied, passkey-signed permission proposal.
use super::*;
pub const TARGET: &str = "gate/permission";
pub const DAY_MS: i64 = 86_400_000;

pub fn protected_target(target: &str) -> bool {
    target
        .to_ascii_lowercase()
        .split(['/', '.', '-', '_'])
        .any(|part| {
            [
                "release",
                "broker",
                "grant",
                "floor",
                "identity",
                "aumlok",
                "gate",
                "slider",
                "permission",
            ]
            .contains(&part)
        })
}

pub fn validate(bytes: &[u8]) -> Result<()> {
    let parsed = canon::parse(bytes).map_err(|_| Error::Refused("gate:record-schema"))?;
    if canon::canonical_json(&parsed).map_err(|_| Error::Refused("gate:record-schema"))? != bytes {
        return Err(Error::Refused("gate:record-schema"));
    }
    let value: Value = serde_json::from_slice(bytes)?;
    let fields = value
        .as_object()
        .ok_or(Error::Refused("gate:record-schema"))?;
    let keys = [
        "v",
        "mode",
        "targets",
        "kinds",
        "max_count",
        "expires_at",
        "nonce",
    ];
    let mode = value["mode"].as_str().unwrap_or("");
    let targets = value["targets"]
        .as_array()
        .ok_or(Error::Refused("gate:record-schema"))?;
    let kinds = value["kinds"]
        .as_array()
        .ok_or(Error::Refused("gate:record-schema"))?;
    let count = value["max_count"].as_i64().unwrap_or(-1);
    let valid_targets = targets.len() <= 32
        && targets.iter().all(|target| {
            target.as_str().is_some_and(|name| {
                !protected_target(name)
                    && TargetSpec::custom(name, 4096, |_| Ok(()))
                        .validate_name()
                        .is_ok()
            })
        });
    if fields.len() != keys.len()
        || keys.iter().any(|key| !fields.contains_key(*key))
        || value["v"] != 1
        || !["ask", "risky", "limits"].contains(&mode)
        || !valid_targets
        || kinds != &[json!("put")]
        || !(0..=1_000_000).contains(&count)
        || (mode != "ask" && (targets.is_empty() || count == 0))
        || (mode == "ask" && (!targets.is_empty() || count != 0))
        || !value["expires_at"]
            .as_i64()
            .is_some_and(|time| time > 0 && time <= 9_007_199_254_740_991)
        || !value["nonce"]
            .as_str()
            .is_some_and(|nonce| hex_width(nonce, 32))
    {
        return Err(Error::Refused("gate:record-schema"));
    }
    canonical(&value)?;
    Ok(())
}

struct Permission {
    id: String,
    value: Value,
    digest: String,
    proof_sha256: String,
    reference: LedgerRef,
}

fn load<S: TargetStore, L: Ledger, P: OwnerProof, C: Clock>(
    gate: &Gate<S, L, P, C>,
) -> Result<Option<Permission>> {
    let latest: Option<(String,String)> = gate.db.query_row(
        "SELECT p.id,p.state FROM gate_proposals p JOIN gate_consumptions c ON c.proposal_id=p.id WHERE p.target=? ORDER BY c.consume_seq DESC LIMIT 1",
        [TARGET], |r| Ok((r.get(0)?,r.get(1)?))).optional()?;
    let Some((latest_id, state)) = latest else {
        return Ok(None);
    };
    if state != "applied" {
        return Ok(None);
    }
    let retained: Option<(String, String, i64, String)> = gate
        .db
        .query_row(
            "SELECT proposal_id,body,seq,hash FROM gate_receipts WHERE proposal_id=?",
            [&latest_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let (id, receipt, seq, hash) =
        retained.ok_or(Error::Refused("gate:consumption-evidence-unavailable"))?;
    let row = gate
        .ledger
        .read_verified(&gate.db, &LedgerRef { seq, hash })?;
    let body: Value = serde_json::from_str(&row.body)?;
    if row.kind != "gate.apply"
        || row.op != id
        || row.phase != "terminal"
        || canonical(&body["receipt"])? != receipt
    {
        return Err(Error::Refused("gate:consumption-evidence-unavailable"));
    }
    let reference = &body["receipt"]["owner_consumption"];
    let reference = LedgerRef {
        seq: reference["seq"]
            .as_i64()
            .ok_or(Error::Refused("gate:consumption-evidence-unavailable"))?,
        hash: reference["hash"]
            .as_str()
            .ok_or(Error::Refused("gate:consumption-evidence-unavailable"))?
            .into(),
    };
    let consumed = gate.ledger.read_verified(&gate.db, &reference)?;
    let consume: Value = serde_json::from_str(&consumed.body)?;
    let auth = &consume["authorization"];
    let bytes = load_blob(
        &gate.db,
        auth["new_sha256"]
            .as_str()
            .ok_or(Error::Refused("gate:consumption-evidence-unavailable"))?,
    )?;
    let digest = sha256(
        &[
            b"aukora:owner-authorization:v1\0".as_slice(),
            canonical(auth)?.as_bytes(),
        ]
        .concat(),
    );
    if consumed.kind != "gate.consume"
        || consumed.op != id
        || consumed.phase != "settle"
        || consume.get("standing_permission").is_some()
        || auth["proposal"] != id
        || auth["target"] != TARGET
        || auth["op"] != "permission"
        || auth["node"] != gate.config.node
        || consume["authorization_sha256"] != digest
        || body["receipt"]["new_sha256"] != sha256(&bytes)
    {
        return Err(Error::Refused("gate:consumption-evidence-unavailable"));
    }
    let proof = consume["proof_hex"]
        .as_str()
        .and_then(|text| hex::decode(text).ok())
        .filter(|proof| !proof.is_empty())
        .ok_or(Error::Refused("gate:consumption-evidence-unavailable"))?;
    let proof_sha256 = sha256(&proof);
    if consume["proof_sha256"] != proof_sha256 {
        return Err(Error::Refused("gate:consumption-evidence-unavailable"));
    }
    if consume["owner_state"] != serde_json::from_str::<Value>(&owner_text(&gate.config.owner)?)? {
        return Ok(None);
    }
    validate(&bytes)?;
    let value: Value = serde_json::from_slice(&bytes)?;
    Ok(Some(Permission {
        id,
        value,
        digest,
        proof_sha256,
        reference,
    }))
}

pub(super) fn safe(db: &Connection, proposal: &Proposal, spec: &TargetSpec) -> Result<bool> {
    if protected_target(&proposal.target) || spec.operator_only || spec.risk != "routine" {
        return Ok(false);
    }
    let old = if proposal.base_sha256 == "absent" {
        Vec::new()
    } else {
        load_blob(db, &proposal.base_sha256)?
    };
    if old.len() > 65_536 {
        return Ok(false);
    }
    let cell: String = db.query_row(
        "SELECT cell FROM gate_proposals WHERE id=?",
        [&proposal.id],
        |r| r.get(0),
    )?;
    let cell: Value = serde_json::from_str(&cell)?;
    if cell.is_null() {
        return Ok(true);
    }
    let new = load_blob(db, &proposal.new_sha256)?;
    let Some(input) = new.strip_suffix(b"\n") else {
        return Ok(false);
    };
    let Ok(parsed) = canon::parse(input) else {
        return Ok(false);
    };
    let canonical_input =
        canon::canonical_json(&parsed).map_err(|_| Error::Refused("gate:cell"))?;
    if canonical_input != input {
        return Ok(false);
    }
    let value: Value = serde_json::from_slice(&canonical_input)?;
    let valid_key = value["key"].as_str().is_some_and(|key| {
        !key.is_empty()
            && key.len() <= 128
            && key.as_bytes()[0].is_ascii_alphanumeric()
            && key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
            && key.len() + canonical(&value["value"]).map_or(usize::MAX, |bytes| bytes.len())
                <= 65_536
    });
    Ok(
        cell["module_sha256"] == "34ce6cab618b626243e876befb49ccf8a6780dc836e757484886b34ae977a438"
            && cell["input_sha256"] == sha256(input)
            && cell["effect_sha256"] == proposal.new_sha256
            && value
                .as_object()
                .is_some_and(|object| object.len() == 2 && object.contains_key("value"))
            && valid_key,
    )
}

impl<S: TargetStore, L: Ledger, P: OwnerProof, C: Clock> Gate<S, L, P, C> {
    pub fn slider_status(&self) -> Result<Value> {
        let Some(permission) = load(self)? else {
            return Ok(
                json!({"mode":"ask","active":false,"remaining":0,"targets":[],"kinds":["put"]}),
            );
        };
        let used: i64 = self.db.query_row(
            "SELECT count(*) FROM gate_auto WHERE permission_id=?",
            [&permission.id],
            |r| r.get(0),
        )?;
        let remaining = (permission.value["max_count"].as_i64().unwrap_or(0) - used).max(0);
        let at = self.now()?;
        let active = permission.value["mode"] != "ask"
            && remaining > 0
            && permission.value["expires_at"]
                .as_i64()
                .is_some_and(|expires| at < expires);
        let mut status = permission.value;
        status["active"] = json!(active);
        status["remaining"] = json!(remaining);
        status["authorization_sha256"] = json!(permission.digest);
        Ok(status)
    }
    fn covering_permission(&self, p: &Proposal, at: i64) -> Result<Option<Permission>> {
        let Some(permission) = load(self)? else {
            return Ok(None);
        };
        let spec = self
            .targets
            .get(&p.target)
            .ok_or(Error::Refused("gate:target-not-allowed"))?;
        let value = &permission.value;
        let used: i64 = self.db.query_row(
            "SELECT count(*) FROM gate_auto WHERE permission_id=?",
            [&permission.id],
            |r| r.get(0),
        )?;
        if value["mode"] == "ask"
            || !value["targets"]
                .as_array()
                .is_some_and(|targets| targets.contains(&json!(p.target)))
            || !value["kinds"]
                .as_array()
                .is_some_and(|kinds| kinds.contains(&json!("put")))
            || value["expires_at"]
                .as_i64()
                .is_none_or(|expires| at >= expires)
            || used >= value["max_count"].as_i64().unwrap_or(0)
            || !safe(&self.db, p, spec)?
        {
            return Ok(None);
        }
        Ok(Some(permission))
    }
    pub(crate) fn auto_apply(&mut self, id: &str) -> Result<Option<State>> {
        let p = load_proposal(&self.db, id)?.ok_or(Error::Refused("gate:unknown-proposal"))?;
        if p.state != State::Pending || self.covering_permission(&p, self.now()?)?.is_none() {
            return Ok(None);
        }
        let expires = self
            .covering_permission(&p, self.now()?)?
            .ok_or(Error::Refused("gate:expired"))?
            .value["expires_at"]
            .as_i64()
            .ok_or(Error::Refused("gate:record-schema"))?;
        let review = self.review_until(id, false, Some(expires))?;
        // The lifetime writer lock and mutable handle serialize reserve, revoke and effect.
        let permission = self
            .covering_permission(&p, self.now()?)?
            .ok_or(Error::Refused("gate:expired"))?;
        let at = self.now()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let auth: Value = serde_json::from_slice(&review.auth_bytes)?;
        let owner = owner_text(&self.config.owner)?;
        assert_owner(&tx, &owner)?;
        let authorization_sha256 = sha256(
            &[
                b"aukora:owner-authorization:v1\0".as_slice(),
                &review.auth_bytes,
            ]
            .concat(),
        );
        let (issue_seq, issue_hash): (i64, String) = tx.query_row(
            "SELECT issue_seq,issue_hash FROM gate_reviews WHERE challenge=?",
            [&review.challenge],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let reference = json!({"v":1,"proposal":permission.id,"authorization_sha256":permission.digest,"proof_sha256":permission.proof_sha256,"consume":{"seq":permission.reference.seq,"hash":permission.reference.hash},"kind":"put"});
        tx.execute(
            "INSERT INTO gate_auto VALUES(?,?,?)",
            params![id, permission.id, permission.digest],
        )?;
        if tx.execute(
            "UPDATE gate_reviews SET state='spent' WHERE challenge=? AND state='live'",
            [&review.challenge],
        )? != 1
        {
            return Err(Error::Refused("gate:challenge-conflict"));
        }
        transition(&tx, &p, State::Applying, at)?;
        let proof_sha = permission.proof_sha256;
        let row = append(
            &self.ledger,
            &tx,
            at,
            "gate.consume",
            &self.config.owner.subject,
            id,
            "settle",
            json!({"authorization":auth,"authorization_sha256":authorization_sha256,"proof_sha256":proof_sha,"owner_state":serde_json::from_str::<Value>(&owner)?,"review_issue":{"seq":issue_seq,"hash":issue_hash},"spent":true,"standing_permission":reference}),
        )?;
        tx.execute(
            "INSERT INTO gate_consumptions VALUES(?,?,?,?,?,?,?,?)",
            params![
                id,
                review.challenge,
                authorization_sha256,
                proof_sha,
                owner,
                at,
                row.seq,
                row.hash
            ],
        )?;
        tx.commit()?;
        self.apply(id).map(Some)
    }
    pub(super) fn check_auto_before_write(&self, id: &str, at: i64) -> Result<()> {
        let auto: Option<(String, String)> = self
            .db
            .query_row(
                "SELECT permission_id,authorization_sha256 FROM gate_auto WHERE proposal_id=?",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((permission_id, digest)) = auto {
            let permission = load(self)?.ok_or(Error::Refused("gate:expired"))?;
            let p = load_proposal(&self.db, id)?.ok_or(Error::Refused("gate:unknown-proposal"))?;
            let spec = self
                .targets
                .get(&p.target)
                .ok_or(Error::Refused("gate:target-not-allowed"))?;
            if permission.id != permission_id
                || permission.digest != digest
                || permission.value["mode"] == "ask"
                || permission.value["expires_at"]
                    .as_i64()
                    .is_none_or(|expires| at >= expires)
                || !safe(&self.db, &p, spec)?
            {
                return Err(Error::Refused("gate:expired"));
            }
        }
        Ok(())
    }
}
