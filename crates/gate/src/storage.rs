use super::*;

pub(super) fn hex_width(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(super) fn checked_time(at: i64) -> Result<i64> {
    if !(0..=9_007_199_254_740_991).contains(&at) {
        return Err(Error::Refused("gate:clock"));
    }
    Ok(at)
}
pub(super) fn validate_owner(o: &OwnerState) -> Result<()> {
    if !(1..=9_007_199_254_740_991).contains(&o.epoch)
        || !o.subject.starts_with("aukora:1:")
        || !hex_width(&o.subject[9..], 64)
        || !hex_width(&o.binding_sha256, 64)
    {
        return Err(Error::Refused("gate:owner-state"));
    }
    Ok(())
}
pub(super) fn validate_config(c: &Config) -> Result<()> {
    validate_owner(&c.owner)?;
    if !hex_width(&c.node, 32) || !hex_width(&c.gate_pubkey_sha256, 64) {
        return Err(Error::Refused("gate:node"));
    }
    let l = &c.limits;
    if l.ttl_ms <= 0
        || l.review_ttl_ms <= 0
        || l.review_ttl_ms > 120_000
        || !(1_000..=3_600_000).contains(&l.guest_window_ms)
        || !(1..=1024).contains(&l.guest_max_per_window)
        || l.max_pending < 1
        || l.max_per_window < 1
        || l.window_ms <= 0
        || l.reject_cooldown_ms < 0
        || l.dedupe_ms < 0
        || l.display_max_bytes == 0
        || l.note_max_chars > 4_000
    {
        return Err(Error::Refused("gate:limits"));
    }
    Ok(())
}
// This encoder receives only gate-built values, never browser-supplied JSON.
pub(super) fn canonical(v: &Value) -> Result<String> {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            let fields: Result<Vec<_>> = keys
                .into_iter()
                .map(|k| {
                    Ok(format!(
                        "{}:{}",
                        serde_json::to_string(k)?,
                        canonical(&map[k])?
                    ))
                })
                .collect();
            Ok(format!("{{{}}}", fields?.join(",")))
        }
        Value::Array(values) => {
            let items: Result<Vec<_>> = values.iter().map(canonical).collect();
            Ok(format!("[{}]", items?.join(",")))
        }
        Value::Number(n) => {
            let n = n.as_i64().ok_or(Error::Refused("gate:integer"))?;
            if !(-9_007_199_254_740_991..=9_007_199_254_740_991).contains(&n) {
                return Err(Error::Refused("gate:integer"));
            }
            Ok(n.to_string())
        }
        _ => Ok(serde_json::to_string(v)?),
    }
}
pub(super) fn owner_text(o: &OwnerState) -> Result<String> {
    canonical(&json!({"subject":o.subject,"epoch":o.epoch,"binding_sha256":o.binding_sha256}))
}
pub(super) fn target_hash(b: &Option<Vec<u8>>) -> String {
    b.as_ref()
        .map(|b| sha256(b))
        .unwrap_or_else(|| "absent".into())
}
pub(super) fn load_proposal(db: &Connection, id: &str) -> Result<Option<Proposal>> {
    let row:Option<(Proposal,String)>=db.query_row("SELECT id,target,base_sha256,new_sha256,digest,idempotency_key,note,expires_at,state FROM gate_proposals WHERE id=?",[id],|r|Ok((Proposal {
        id:r.get(0)?,target:r.get(1)?,base_sha256:r.get(2)?,new_sha256:r.get(3)?,digest:r.get(4)?,idempotency_key:r.get(5)?,note:r.get(6)?,expires_at:r.get(7)?,state:State::Pending},r.get(8)?))).optional()?;
    row.map(|(mut p, s)| {
        p.state = State::parse(&s)?;
        p.note = crate::card::clean_note(&p.note);
        Ok(p)
    })
    .transpose()
}
pub(super) fn load_blob(db: &Connection, hash: &str) -> Result<Vec<u8>> {
    let bytes: Vec<u8> = db
        .query_row("SELECT bytes FROM gate_blobs WHERE sha256=?", [hash], |r| {
            r.get(0)
        })
        .optional()?
        .ok_or(Error::Refused("gate:blob-missing"))?;
    if sha256(&bytes) != hash {
        return Err(Error::Refused("gate:blob-hash"));
    }
    Ok(bytes)
}
pub(super) fn put_blob(tx: &Transaction<'_>, hash: &str, bytes: &[u8]) -> Result<()> {
    if sha256(bytes) != hash {
        return Err(Error::Refused("gate:blob-hash"));
    }
    tx.execute(
        "INSERT OR IGNORE INTO gate_blobs VALUES(?,?)",
        params![hash, bytes],
    )?;
    load_blob(tx, hash)?;
    Ok(())
}
pub(super) fn content_digest(
    node: &str,
    target: &str,
    base: &str,
    new: &str,
    cell: &Value,
) -> Result<String> {
    let body = canonical(
        &json!({"v":1,"node":node,"target":target,"base_sha256":base,"new_sha256":new,"cell":cell}),
    )?;
    Ok(sha256(
        &[b"aukora:operation-content:v1\0".as_slice(), body.as_bytes()].concat(),
    ))
}
pub(super) fn authorization(
    db: &Connection,
    c: &Config,
    p: &Proposal,
    challenge: &str,
    issued: i64,
    expires: i64,
    display: &str,
) -> Result<Vec<u8>> {
    let op = if p.target == crate::standing::TARGET {
        "permission"
    } else if p.target == "release" {
        "release"
    } else {
        "apply"
    };
    authorization_for_op(db, c, p, challenge, issued, expires, display, op)
}
#[allow(clippy::too_many_arguments)]
pub(super) fn authorization_for_op(
    db: &Connection,
    c: &Config,
    p: &Proposal,
    challenge: &str,
    issued: i64,
    expires: i64,
    display: &str,
    op: &str,
) -> Result<Vec<u8>> {
    let cell: String =
        db.query_row("SELECT cell FROM gate_proposals WHERE id=?", [&p.id], |r| {
            r.get(0)
        })?;
    if p.target == "release" && op != "reconcile" {
        // The protected floor verifies the frozen C5 layout independently.
        return Ok(canonical(
            &json!({"v":1,"node":c.node,"subject":c.owner.subject,"op":op,
            "proposal":p.id,"target":p.target,"epoch":c.owner.epoch,"operation":p.digest,
            "base_sha256":p.base_sha256,"new_sha256":p.new_sha256,
            "cell":serde_json::from_str::<Value>(&cell)?,"display_sha256":display,
            "challenge":challenge,"expires_at":expires}),
        )?
        .into_bytes());
    }
    Ok(canonical(&json!({"v":1,"node":c.node,"subject":c.owner.subject,"op":op,"proposal":p.id,"target":p.target,
        "epoch":c.owner.epoch,"operation":p.digest,"owner_epoch":c.owner.epoch,"owner_root_id":c.owner.binding_sha256,
        "binding_sha256":c.owner.binding_sha256,"issued_at":issued,"issued_at_ms":issued,"gate":c.gate_pubkey_sha256,
        "pubkey_fp":&c.gate_pubkey_sha256[..16],
        "base_sha256":p.base_sha256,"new_sha256":p.new_sha256,"cell":serde_json::from_str::<Value>(&cell)?,"display_sha256":display,
        "challenge":challenge,"expires_at":expires}))?.into_bytes())
}
#[allow(clippy::too_many_arguments)]
pub(super) fn retirement_auth(
    db: &Connection,
    c: &Config,
    p: &Proposal,
    challenge: &str,
    issued: i64,
    expires: i64,
    display: &str,
) -> Result<Vec<u8>> {
    authorization_for_op(db, c, p, challenge, issued, expires, display, "retire")
}
pub(super) fn card_bytes(db: &Connection, p: &Proposal, s: &TargetSpec) -> Result<Vec<u8>> {
    let mut p = p.clone();
    p.note = db.query_row("SELECT note FROM gate_proposals WHERE id=?", [&p.id], |r| {
        r.get(0)
    })?;
    let old = if p.base_sha256 == "absent" {
        None
    } else {
        Some(load_blob(db, &p.base_sha256)?)
    };
    let new = load_blob(db, &p.new_sha256)?;
    s.validate(&new)?;
    let has_history: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM gate_proposals WHERE target=? AND state='applied')",
        [&p.target],
        |r| r.get(0),
    )?;
    let mut selected_spec = s.clone();
    if matches!(s.schema, Schema::Release) {
        if let Some(evidence) = s.pinned_facts.as_ref().and_then(|runs| runs.get(&p.id)) {
            if evidence.get("proposal_id").and_then(Value::as_str) != Some(p.id.as_str()) {
                return Err(Error::Refused("gate:review-facts-unavailable"));
            }
            selected_spec.pinned_facts = Some(json!({p.new_sha256.clone():evidence}));
        }
    }
    let facts =
        crate::card::checked_review_facts(&selected_spec, old.as_deref(), &new, has_history)?;
    let bytes = crate::card::bytes(&p, s, old.as_deref(), &new, facts)?;
    let cell: String = db.query_row(
        "SELECT cell FROM gate_proposals WHERE id=?",
        [&p.id],
        |row| row.get(0),
    )?;
    let cell: Value = serde_json::from_str(&cell)?;
    if cell.is_null() {
        return Ok(bytes);
    }
    let mut card: Value = serde_json::from_slice(&bytes)?;
    let facts = card["facts"]
        .as_array_mut()
        .ok_or(Error::Refused("gate:review-facts-unavailable"))?;
    for field in ["module_sha256", "input_sha256", "effect_sha256"] {
        let digest = cell[field]
            .as_str()
            .filter(|value| hex_width(value, 64))
            .ok_or(Error::Refused("gate:cell"))?;
        facts.push(json!([format!("cell.{field}"), digest]));
    }
    Ok(canonical(&card)?.into_bytes())
}
pub(super) fn review_card_bytes(
    db: &Connection,
    p: &Proposal,
    s: &TargetSpec,
    despite: bool,
) -> Result<Vec<u8>> {
    let card = card_bytes(db, p, s)?;
    let mut value: Value = serde_json::from_slice(&card)?;
    let requires = value["requires_antibody_override"] == true;
    if requires && !despite {
        return Err(Error::Refused("immune:override-required"));
    }
    if despite {
        if !matches!(s.schema, Schema::Release) || !requires {
            return Err(Error::Refused("immune:override-not-required"));
        }
        value["release_override"] = json!(true);
        value["says"] = json!("Approve despite failing antibodies and start the agent runtime");
        value["facts"].as_array_mut().ok_or(Error::Refused("gate:review-facts-unavailable"))?.push(json!(["antibody_override", "This passkey confirmation approves the release despite the displayed failed or missing antibody evidence."]));
    }
    Ok(canonical(&value)?.into_bytes())
}

pub(super) fn retained_override(card: &[u8]) -> Result<bool> {
    let value: Value = serde_json::from_slice(card)?;
    Ok(value["release_override"] == true)
}
pub(super) fn assert_owner(db: &Connection, text: &str) -> Result<()> {
    let current: String = db.query_row(
        "SELECT owner_text FROM gate_owner WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    if current != text {
        return Err(Error::Refused("gate:owner-state-changed"));
    }
    Ok(())
}
pub(super) fn counter_cas(tx: &Transaction<'_>, credential: &str, next: u32) -> Result<()> {
    let (stored_credential, old): (String, u32) = tx.query_row(
        "SELECT credential_id,sign_count FROM gate_owner WHERE singleton=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if credential != stored_credential {
        return Err(Error::Refused("gate:credential-mismatch"));
    }
    if (next != 0 || old != 0) && next <= old {
        return Err(Error::Refused("gate:counter-replay"));
    }
    if next == 0 {
        return Ok(());
    }
    if tx.execute(
        "UPDATE gate_owner SET sign_count=? WHERE singleton=1 AND credential_id=? AND sign_count=?",
        params![next, credential, old],
    )? != 1
    {
        return Err(Error::Refused("gate:counter-conflict"));
    }
    Ok(())
}
pub(super) fn transition(tx: &Transaction<'_>, p: &Proposal, to: State, at: i64) -> Result<()> {
    if tx.execute(
        "UPDATE gate_proposals SET state=?,updated=? WHERE id=? AND state=?",
        params![to.as_str(), at, p.id, p.state.as_str()],
    )? != 1
    {
        return Err(Error::Refused("gate:state-conflict"));
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
pub(super) fn append<L: Ledger>(
    ledger: &L,
    tx: &Transaction<'_>,
    at: i64,
    kind: &'static str,
    actor: &str,
    op: &str,
    phase: &'static str,
    body: Value,
) -> Result<LedgerRef> {
    let reference = ledger.append(
        tx,
        &LedgerRow {
            at,
            kind,
            actor: actor.into(),
            op: op.into(),
            phase,
            body: canonical(&body)?,
        },
    )?;
    if reference.seq < 1 || !hex_width(&reference.hash, 64) {
        return Err(Error::Refused("gate:ledger-reference"));
    }
    Ok(reference)
}
#[allow(clippy::too_many_arguments)]
pub(super) fn consume_attempt<S: TargetStore, L: Ledger, P: OwnerProof, C: Clock>(
    tx: &Transaction<'_>,
    config: &Config,
    targets: &BTreeMap<String, TargetSpec>,
    store: &S,
    ledger: &L,
    proof: &P,
    clock: &C,
    request: &ConsumeRequest,
) -> Result<State> {
    let p =
        load_proposal(tx, &request.proposal_id)?.ok_or(Error::Refused("gate:unknown-proposal"))?;
    if p.state != State::Pending {
        return Err(Error::Refused("gate:not-pending"));
    }
    let r:Option<RetainedReview>=tx.query_row("SELECT challenge,base_sha256,new_sha256,display_sha256,auth,card,owner_text,issued_at,expires_at,issue_seq,issue_hash FROM gate_reviews WHERE proposal_id=? AND state='live'",[&p.id],|r|Ok(RetainedReview {challenge:r.get(0)?,base:r.get(1)?,new:r.get(2)?,display:r.get(3)?,auth:r.get(4)?,card:r.get(5)?,owner:r.get(6)?,issued:r.get(7)?,expires:r.get(8)?,seq:r.get(9)?,hash:r.get(10)?})).optional()?;
    let r = r.ok_or(Error::Refused("gate:no-live-review"))?;
    let burned: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM gate_burns WHERE challenge=?)",
        [&r.challenge],
        |r| r.get(0),
    )?;
    if burned {
        return Err(Error::Refused("gate:challenge-burned"));
    }
    let issue = ledger.read_verified(
        tx,
        &LedgerRef {
            seq: r.seq,
            hash: r.hash.clone(),
        },
    )?;
    let detail: Value = serde_json::from_str(&issue.body)?;
    if issue.kind != "gate.review"
        || issue.op != p.id
        || issue.phase != "fact"
        || canonical(&detail["authorization"])?.as_bytes() != r.auth
        || canonical(&detail["card"])?.as_bytes() != r.card
        || canonical(&detail["owner_state"])? != r.owner
    {
        return Err(Error::Refused("gate:review-evidence-unavailable"));
    }
    if !hex_width(&request.challenge, 64) || request.challenge != r.challenge {
        return Err(Error::Refused("gate:challenge-mismatch"));
    }
    if request.base_sha256 != r.base
        || request.new_sha256 != r.new
        || request.display_sha256 != r.display
        || p.base_sha256 != r.base
        || p.new_sha256 != r.new
    {
        return Err(Error::Refused("gate:review-mismatch"));
    }
    let at = checked_time(clock.now_ms()?)?;
    if at < r.issued || at >= r.expires || at >= p.expires_at {
        return Err(Error::Refused("gate:expired"));
    }
    if request.decision == Decision::Deny {
        transition(tx, &p, State::Refused, at)?;
        if tx.execute(
            "UPDATE gate_reviews SET state='spent' WHERE challenge=? AND state='live'",
            [&r.challenge],
        )? != 1
        {
            return Err(Error::Refused("gate:challenge-conflict"));
        }
        append(
            ledger,
            tx,
            at,
            "gate.refuse",
            "owner-channel (unsigned)",
            &p.id,
            "terminal",
            json!({"decision":"DENIED"}),
        )?;
        return Ok(State::Refused);
    }
    if !request.decision.permits() {
        return Err(Error::Refused("gate:unknown-decision"));
    }
    if p.target == "release" {
        let auth: Value = serde_json::from_slice(&r.auth)?;
        if auth.as_object().is_some_and(|fields| {
            fields.len() == 21
                && fields.keys().all(|name| {
                    matches!(
                        name.as_str(),
                        "v" | "node"
                            | "subject"
                            | "op"
                            | "proposal"
                            | "target"
                            | "epoch"
                            | "operation"
                            | "owner_epoch"
                            | "owner_root_id"
                            | "binding_sha256"
                            | "issued_at"
                            | "issued_at_ms"
                            | "gate"
                            | "pubkey_fp"
                            | "base_sha256"
                            | "new_sha256"
                            | "cell"
                            | "display_sha256"
                            | "challenge"
                            | "expires_at"
                    )
                })
        }) && auth["op"] == "release"
            && auth["target"] == "release"
        {
            return Err(Error::Refused("gate:pre-a3-release-reapprove"));
        }
    }
    assert_owner(tx, &r.owner)?;
    if owner_text(&config.owner)? != r.owner {
        return Err(Error::Refused("gate:owner-state-changed"));
    }
    let spec = targets
        .get(&p.target)
        .ok_or(Error::Refused("gate:target-not-allowed"))?;
    let despite = retained_override(&r.card)?;
    let card = review_card_bytes(tx, &p, spec, despite)?;
    if card != r.card
        || sha256(&card) != r.display
        || authorization(
            tx,
            config,
            &p,
            &r.challenge,
            r.issued,
            r.expires,
            &r.display,
        )? != r.auth
    {
        return Err(Error::Refused("gate:display-mismatch"));
    }
    if card.len() > config.limits.display_max_bytes {
        return Err(Error::Refused("gate:display-too-large"));
    }
    let verified = proof.verify_in_transaction(tx, &r.auth, &request.proof, false)?;
    if verified.credential_id != config.owner.binding_sha256 {
        return Err(Error::Refused("gate:credential-mismatch"));
    }
    let completed: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM gate_receipts WHERE proposal_id=?)",
        [&p.id],
        |r| r.get(0),
    )?;
    if completed {
        return Err(Error::Refused("gate:completion-already-retained"));
    }
    if target_hash(&store.read(&p.target)?) != p.base_sha256 {
        return Err(Error::Refused("gate:stale-base"));
    }
    load_blob(tx, &p.new_sha256)?;
    let accepted = checked_time(clock.now_ms()?)?;
    if accepted < at || accepted >= r.expires || accepted >= p.expires_at {
        return Err(Error::Refused("gate:expired"));
    }
    if tx.execute("UPDATE gate_reviews SET state='spent' WHERE challenge=? AND proposal_id=? AND state='live'",params![r.challenge,p.id])?!=1 {return Err(Error::Refused("gate:challenge-conflict"));}
    transition(tx, &p, State::Applying, accepted)?;
    let auth_sha = sha256(
        &[
            b"aukora:owner-authorization:v1\0".as_slice(),
            r.auth.as_slice(),
        ]
        .concat(),
    );
    let proof_sha = sha256(&request.proof);
    let row = append(
        ledger,
        tx,
        accepted,
        "gate.consume",
        &config.owner.subject,
        &p.id,
        "settle",
        json!({"authorization_sha256":auth_sha,"proof_sha256":proof_sha,"proof_hex":hex::encode(&request.proof),"authorization":serde_json::from_slice::<Value>(&r.auth)?,"owner_state":serde_json::from_str::<Value>(&r.owner)?,"review_issue":{"seq":r.seq,"hash":r.hash},"spent":true}),
    )?;
    if tx.execute(
        "INSERT INTO gate_consumptions VALUES(?,?,?,?,?,?,?,?)",
        params![
            p.id,
            r.challenge,
            auth_sha,
            proof_sha,
            r.owner,
            accepted,
            row.seq,
            row.hash
        ],
    )? != 1
    {
        return Err(Error::Refused("gate:consumption-conflict"));
    }
    counter_cas(tx, &verified.credential_id, verified.counter)?;
    proof.persist_counter(tx, &verified)?;
    assert_owner(tx, &r.owner)?;
    if review_card_bytes(tx, &p, spec, despite)? != r.card {
        return Err(Error::Refused("gate:review-facts-changed"));
    }
    let final_at = checked_time(clock.now_ms()?)?;
    if final_at < accepted || final_at >= r.expires || final_at >= p.expires_at {
        return Err(Error::Refused("gate:expired"));
    }
    Ok(State::Applying)
}
struct RetainedReview {
    challenge: String,
    base: String,
    new: String,
    display: String,
    auth: Vec<u8>,
    card: Vec<u8>,
    owner: String,
    issued: i64,
    expires: i64,
    seq: i64,
    hash: String,
}
pub(super) fn reconcile<S: TargetStore, L: Ledger>(
    tx: &Transaction<'_>,
    ledger: &L,
    store: &S,
    p: &Proposal,
    actor: &str,
    at: i64,
    write_reached: Option<bool>,
) -> Result<()> {
    let claimed: bool = tx.query_row(
        "SELECT write_claimed FROM gate_proposals WHERE id=?",
        [&p.id],
        |r| r.get(0),
    )?;
    let may_have_written = write_reached.unwrap_or(claimed);
    let current = if may_have_written {
        store.read(&p.target).ok().map(|b| target_hash(&b))
    } else {
        None
    };
    if may_have_written && current.is_none() {
        append(
            ledger,
            tx,
            at,
            "gate.recover",
            actor,
            &p.id,
            "fact",
            json!({"state":"applying","current_sha256":Value::Null,"retry":false,"receipt":Value::Null,"write_claimed":claimed}),
        )?;
        return Ok(());
    }
    let state = match (may_have_written, current.as_deref()) {
        (false, _) => State::Failed,
        (true, Some(hash)) if hash == p.new_sha256 => State::Incomplete,
        (true, Some(hash)) if hash == p.base_sha256 => State::Failed,
        (true, Some(_)) => State::Conflict,
        (true, None) => unreachable!(),
    };
    transition(tx, p, state, at)?;
    append(
        ledger,
        tx,
        at,
        "gate.recover",
        actor,
        &p.id,
        "terminal",
        json!({"state":state.as_str(),"current_sha256":current,"retry":false,"receipt":Value::Null,"write_claimed":claimed,"write_reached":write_reached}),
    )?;
    Ok(())
}
pub(super) fn expire<L: Ledger>(
    tx: &Transaction<'_>,
    ledger: &L,
    actor: &str,
    at: i64,
) -> Result<usize> {
    let ids: Vec<String> = {
        let mut q =
            tx.prepare("SELECT id FROM gate_proposals WHERE state='pending' AND expires_at<=?")?;
        let rows = q
            .query_map([at], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        rows
    };
    let count = ids.len();
    for id in ids {
        let p = load_proposal(tx, &id)?.ok_or(Error::Refused("gate:proposal-missing"))?;
        transition(tx, &p, State::Expired, at)?;
        tx.execute(
            "UPDATE gate_reviews SET state='invalidated' WHERE proposal_id=? AND state='live'",
            [&id],
        )?;
        append(
            ledger,
            tx,
            at,
            "gate.expire",
            actor,
            &id,
            "terminal",
            json!({"state":"expired"}),
        )?;
    }
    Ok(count)
}

/// Mutable fence metadata has authority only through its retained signed fact.
pub(super) fn verified_reconciliation<L: Ledger>(
    db: &Connection,
    ledger: &L,
    id: &str,
) -> Result<Option<(String, i64)>> {
    let retained: Option<(String, i64, String)> = db
        .query_row(
            "SELECT base_sha256,seq,hash FROM gate_reconciliations WHERE proposal_id=?",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let Some((base, seq, hash)) = retained else {
        return Ok(None);
    };
    let p = load_proposal(db, id)?.ok_or(Error::Refused("gate:reconciliation-unavailable"))?;
    let row = ledger.read_verified(db, &LedgerRef { seq, hash })?;
    let body: Value = serde_json::from_str(&row.body)?;
    let receipt = &body["receipt"];
    let auth = &body["authorization"];
    let proof = hex::decode(body["proof_hex"].as_str().unwrap_or(""))
        .map_err(|_| Error::Refused("gate:reconciliation-unavailable"))?;
    let auth_hash = sha256(
        &[
            b"aukora:owner-authorization:v1\0".as_slice(),
            canonical(auth)?.as_bytes(),
        ]
        .concat(),
    );
    if row.kind != "gate.recover"
        || row.op != id
        || row.phase != "fact"
        || receipt["v"] != 3
        || receipt["kind"] != "reconcile"
        || receipt["operation"] != "reconcile"
        || receipt["operation_id"] != id
        || receipt["digest"] != p.digest
        || receipt["base_sha256"] != base
        || receipt["retry"] != false
        || (base != "absent" && !hex_width(&base, 64))
        || auth["op"] != "reconcile"
        || auth["v"] != 1
        || auth["proposal"] != id
        || auth["target"] != p.target
        || auth["operation"] != p.digest
        || auth["subject"] != receipt["approver"]
        || auth["owner_epoch"] != receipt["owner_epoch"]
        || auth["gate"] != receipt["gate_pubkey_sha256"]
        || receipt["owner_authorization"]["version"] != 1
        || receipt["owner_authorization"]["kind"] != "aukora-owner-authorization-ref/v1"
        || receipt["owner_authorization"]["authorization_id"] != auth_hash
        || proof.is_empty()
        || receipt["owner_authorization"]["proof_sha256"] != sha256(&proof)
    {
        return Err(Error::Refused("gate:reconciliation-unavailable"));
    }
    Ok(Some((base, seq)))
}
