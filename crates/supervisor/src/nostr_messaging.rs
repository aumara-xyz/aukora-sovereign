// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::{
    node::{canon_bytes, signed_card, Node},
    owner, state,
};
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use nostr::{
    event::{Event, Rumor},
    nip59,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use std::{
    sync::{Arc, Weak},
    time::Duration,
};

pub(crate) const CONTACT_TARGET: &str = "plugins/nostr/contacts.json";
pub(crate) const SEND_TARGET: &str = "plugins/nostr/send.json";
pub(crate) const MAX_CONTENT_BYTES: usize = 1024;
pub(crate) const MAX_INBOX: usize = 200;
const MAX_CONTACTS: usize = 100;
const INTERVAL: Duration = Duration::from_secs(30);

#[cfg(test)]
pub(crate) enum TestRequest {
    Publish(
        Event,
        tokio::sync::oneshot::Sender<relay::Result<relay::PublishResult>>,
    ),
    Query(tokio::sync::oneshot::Sender<relay::Result<relay::QueryResult>>),
}

pub(crate) fn schema(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS supervisor_nostr_contacts(npub TEXT PRIMARY KEY,label TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS supervisor_nostr_inbox(id TEXT PRIMARY KEY,npub TEXT NOT NULL,content BLOB NOT NULL,created_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS supervisor_nostr_outbox(proposal TEXT PRIMARY KEY,event TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('pending','spent','sent','failed')));
        CREATE TRIGGER IF NOT EXISTS supervisor_nostr_outbox_pin BEFORE UPDATE ON supervisor_nostr_outbox
          WHEN NEW.proposal!=OLD.proposal OR NOT ((OLD.state='pending' AND NEW.state='spent') OR (OLD.state='spent' AND NEW.state IN ('sent','failed') AND NEW.event=OLD.event))
          BEGIN SELECT RAISE(ABORT,'nostr:send-spent'); END;
        CREATE TRIGGER IF NOT EXISTS supervisor_nostr_outbox_retained BEFORE DELETE ON supervisor_nostr_outbox
          BEGIN SELECT RAISE(ABORT,'nostr:send-spent'); END;
        CREATE TABLE IF NOT EXISTS supervisor_nostr_refusals(code TEXT PRIMARY KEY,count INTEGER NOT NULL);")?;
    Ok(())
}

fn record(bytes: &[u8], fields: &[&str]) -> gate::Result<Value> {
    let value: Value = serde_json::from_slice(bytes)?;
    if !value
        .as_object()
        .is_some_and(|o| o.len() == fields.len() && fields.iter().all(|f| o.contains_key(*f)))
        || value["v"] != 1
        || canon_bytes(&value).ok().as_deref() != Some(bytes)
        || nostr::npub_decode(value["npub"].as_str().unwrap_or("")).is_err()
    {
        return Err(gate::Error::Refused("nostr:record-schema"));
    }
    Ok(value)
}
fn decoded(value: &Value, field: &str, max: usize) -> gate::Result<String> {
    let text = value[field]
        .as_str()
        .ok_or(gate::Error::Refused("nostr:record-schema"))?;
    let bytes = STANDARD
        .decode(text)
        .map_err(|_| gate::Error::Refused("nostr:record-schema"))?;
    if bytes.is_empty() || bytes.len() > max || STANDARD.encode(&bytes) != text {
        return Err(gate::Error::Refused("nostr:message-too-large"));
    }
    String::from_utf8(bytes).map_err(|_| gate::Error::Refused("nostr:record-schema"))
}
fn validate_contact(bytes: &[u8]) -> gate::Result<()> {
    let value = record(bytes, &["v", "npub", "action", "label_b64", "nonce"])?;
    if !matches!(value["action"].as_str(), Some("add" | "remove"))
        || !crate::config::hex_value(value["nonce"].as_str().unwrap_or(""), 32)
    {
        return Err(gate::Error::Refused("nostr:record-schema"));
    }
    decoded(&value, "label_b64", 128)?;
    Ok(())
}
fn validate_send(bytes: &[u8]) -> gate::Result<()> {
    let value = record(
        bytes,
        &["v", "npub", "content_sealed", "content_sha256", "nonce"],
    )?;
    if !crate::config::hex_value(value["nonce"].as_str().unwrap_or(""), 32)
        || !crate::config::hex_value(value["content_sha256"].as_str().unwrap_or(""), 64)
    {
        return Err(gate::Error::Refused("nostr:record-schema"));
    }
    let text = value["content_sealed"]
        .as_str()
        .ok_or(gate::Error::Refused("nostr:record-schema"))?;
    let sealed = STANDARD
        .decode(text)
        .map_err(|_| gate::Error::Refused("nostr:record-schema"))?;
    if sealed.len() < 57
        || sealed.len() > MAX_CONTENT_BYTES + 56
        || STANDARD.encode(&sealed) != text
    {
        return Err(gate::Error::Refused("nostr:record-schema"));
    }
    Ok(())
}
fn facts(_: Option<&[u8]>, bytes: &[u8]) -> gate::Result<Value> {
    let value: Value = serde_json::from_slice(bytes)?;
    let rows = if value.get("content_sealed").is_some() {
        json!([
            ["Recipient npub", value["npub"]],
            ["Message sha256", value["content_sha256"]],
            ["Message ciphertext", value["content_sealed"]],
            [
                "Authority",
                "Transport only; this message grants no authority"
            ]
        ])
    } else {
        json!([
            ["Contact npub", value["npub"]],
            ["Action", value["action"]],
            ["Contact label (base64 UTF-8)", value["label_b64"]]
        ])
    };
    Ok(json!({"from_to":"Apply this exact owner-approved Nostr operation", "facts":rows}))
}
pub(crate) fn targets() -> Vec<gate::TargetSpec> {
    [
        (
            CONTACT_TARGET,
            validate_contact as fn(&[u8]) -> gate::Result<()>,
            "Change this Nostr contact",
        ),
        (
            SEND_TARGET,
            validate_send as fn(&[u8]) -> gate::Result<()>,
            "Send this private Nostr message",
        ),
    ]
    .into_iter()
    .map(|(name, validate, says)| {
        let mut spec = gate::TargetSpec::custom(name, 4096, validate);
        spec.says = says;
        spec.review_facts = Some(facts);
        spec
    })
    .collect()
}
pub(crate) fn contact_record(body: &Value) -> Result<Value, &'static str> {
    let npub = body["npub"].as_str().ok_or("nostr:invalid-contact")?;
    nostr::npub_decode(npub).map_err(|_| "nostr:invalid-contact")?;
    let label = body["label"]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 128)
        .ok_or("nostr:invalid-contact")?;
    if !matches!(body["action"].as_str(), Some("add" | "remove")) {
        return Err("nostr:invalid-contact");
    }
    Ok(
        json!({"v":1,"npub":npub,"label_b64":STANDARD.encode(label),"action":body["action"],"nonce":state::random_id().map_err(|_| "nostr:storage")?}),
    )
}
pub(crate) fn send_record(node: &Node, body: &Value) -> Result<Value, &'static str> {
    if node.config.nostr.relays.is_empty() {
        return Err("nostr:relays-off");
    }
    let npub = body["npub"].as_str().ok_or("nostr:invalid-contact")?;
    nostr::npub_decode(npub).map_err(|_| "nostr:invalid-contact")?;
    if !contact(&*node.db.lock().map_err(|_| "nostr:storage")?, npub)
        .map_err(|_| "nostr:storage")?
    {
        return Err("nostr:non-contact");
    }
    let content = body["content"]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= MAX_CONTENT_BYTES)
        .ok_or("nostr:message-too-large")?;
    let recipient = nostr::npub_decode(npub).map_err(|_| "nostr:invalid-contact")?;
    nostr::nip44::get_conversation_key(node.nostr.node_key(), &recipient)
        .map_err(|_| "nostr:invalid-contact")?;
    let now = u64::try_from(state::now_ms().map_err(|_| "nostr:storage")?)
        .map_err(|_| "nostr:storage")?
        / 1000;
    Rumor::new(
        node.nostr.node_key().public_key(),
        now,
        14,
        vec![],
        content.into(),
    )
    .map_err(|_| "nostr:message-invalid")?;
    let nonce = state::random_id().map_err(|_| "nostr:storage")?;
    let purpose = format!("nostr:send:v1:{npub}:{nonce}");
    let mut blind = [0; 16];
    getrandom::fill(&mut blind).map_err(|_| "nostr:storage")?;
    let mut payload = zeroize::Zeroizing::new(blind.to_vec());
    payload.extend_from_slice(content.as_bytes());
    let commitment = message_commitment(&blind, content.as_bytes());
    let sealed = owner::encrypt(
        &owner::stored_wrap_key(&node.signer),
        &payload,
        purpose.as_bytes(),
    )
    .map_err(|_| "nostr:storage")?;
    Ok(
        json!({"v":1,"npub":npub,"content_sealed":STANDARD.encode(sealed),"content_sha256":commitment,"nonce":nonce}),
    )
}
fn message_commitment(blind: &[u8], content: &[u8]) -> String {
    let mut bytes = b"nostr:message:v1\0".to_vec();
    bytes.extend_from_slice(blind);
    bytes.extend_from_slice(content);
    gate::sha256(&bytes)
}
fn send_plaintext(node: &Node, value: &Value) -> Result<String> {
    Ok(send_payload(node, value)?.0)
}
fn send_payload(node: &Node, value: &Value) -> Result<(String, String)> {
    let purpose = format!(
        "nostr:send:v1:{}:{}",
        value["npub"].as_str().unwrap_or(""),
        value["nonce"].as_str().unwrap_or("")
    );
    let sealed = STANDARD.decode(value["content_sealed"].as_str().unwrap_or(""))?;
    let plain = owner::decrypt(
        &owner::stored_wrap_key(&node.signer),
        &sealed,
        purpose.as_bytes(),
    )
    .map_err(|_| anyhow!("nostr:message-invalid"))?;
    if plain.len() <= 16 || plain.len() > MAX_CONTENT_BYTES + 16 {
        return Err(anyhow!("nostr:message-invalid"));
    }
    let (blind, content) = plain.split_at(16);
    if value["content_sha256"] != message_commitment(blind, content) {
        return Err(anyhow!("nostr:message-invalid"));
    }
    Ok((std::str::from_utf8(content)?.to_owned(), hex::encode(blind)))
}
pub(crate) fn preview(node: &Node, id: &str) -> Result<Value> {
    let db = node.db.lock().map_err(|_| anyhow!("nostr:storage"))?;
    let bytes: Vec<u8> = db.query_row("SELECT b.bytes FROM gate_proposals p JOIN gate_blobs b ON b.sha256=p.new_sha256 WHERE p.id=?1 AND p.target=?2",params![id,SEND_TARGET],|r|r.get(0))?;
    validate_send(&bytes)?;
    let value: Value = serde_json::from_slice(&bytes)?;
    let (content, blind) = send_payload(node, &value)?;
    Ok(
        json!({"id":id,"content":content,"content_blind":blind,"content_sha256":value["content_sha256"]}),
    )
}
fn contact(db: &Connection, npub: &str) -> Result<bool> {
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM supervisor_nostr_contacts WHERE npub=?)",
        [npub],
        |r| r.get(0),
    )?)
}
pub(crate) fn contacts(node: &Node) -> Result<Value> {
    let db = node.db.lock().map_err(|_| anyhow!("nostr:storage"))?;
    let mut stmt = db.prepare("SELECT npub,label FROM supervisor_nostr_contacts ORDER BY npub")?;
    let rows = stmt
        .query_map([], |r| {
            Ok(json!({"npub":r.get::<_,String>(0)?,"label":r.get::<_,String>(1)?}))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(json!({"contacts":rows}))
}
pub(crate) fn counts(node: &Node) -> Result<Value> {
    let db = node.db.lock().map_err(|_| anyhow!("nostr:storage"))?;
    let received: i64 = db.query_row("SELECT count(*) FROM supervisor_nostr_inbox", [], |r| {
        r.get(0)
    })?;
    let sent: i64 = db.query_row(
        "SELECT count(*) FROM supervisor_nostr_outbox WHERE state='sent'",
        [],
        |r| r.get(0),
    )?;
    let refused: i64 = db.query_row(
        "SELECT coalesce(sum(count),0) FROM supervisor_nostr_refusals",
        [],
        |r| r.get(0),
    )?;
    Ok(json!({"received":received,"inbox":received,"sent":sent,"refused":refused}))
}
pub(crate) fn inbox(node: &Node) -> Result<Value> {
    let messages = {
        let db = node.db.lock().map_err(|_| anyhow!("nostr:storage"))?;
        let key = owner::stored_wrap_key(&node.signer);
        let mut stmt = db.prepare(
            "SELECT id,npub,content,created_at FROM supervisor_nostr_inbox ORDER BY rowid",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut messages = Vec::new();
        for (id, npub, sealed, created_at) in rows {
            let plain = owner::decrypt(&key, &sealed, id.as_bytes())
                .map_err(|_| anyhow!("nostr:storage"))?;
            let content = std::str::from_utf8(&plain).map_err(|_| anyhow!("nostr:storage"))?;
            messages.push(json!({"id":id,"npub":npub,"content":content,"created_at":created_at}));
        }
        messages
    };
    Ok(json!({"messages":messages,"counts":counts(node)?}))
}

pub(crate) fn reconcile(node: &Node) -> Result<()> {
    let mut db = node.db.lock().map_err(|_| anyhow!("nostr:storage"))?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let proposals = {
        let mut stmt = tx.prepare("SELECT p.id,p.target,b.bytes FROM gate_proposals p JOIN gate_blobs b ON b.sha256=p.new_sha256 WHERE p.state='applied' AND p.target IN (?1,?2) AND NOT EXISTS(SELECT 1 FROM supervisor_effects e WHERE e.proposal=p.id) ORDER BY p.rowid")?;
        let rows = stmt
            .query_map([CONTACT_TARGET, SEND_TARGET], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    for (id, target, bytes) in proposals {
        signed_card(&tx, &node.signer.verifying_key(), &id, &target, &bytes)?;
        let value: Value = serde_json::from_slice(&bytes)?;
        let npub = value["npub"]
            .as_str()
            .ok_or_else(|| anyhow!("nostr:record-schema"))?;
        if target == CONTACT_TARGET {
            validate_contact(&bytes)?;
            if value["action"] == "remove" {
                tx.execute("DELETE FROM supervisor_nostr_contacts WHERE npub=?", [npub])?;
            } else {
                let count: i64 =
                    tx.query_row("SELECT count(*) FROM supervisor_nostr_contacts", [], |r| {
                        r.get(0)
                    })?;
                if count < MAX_CONTACTS as i64 || contact(&tx, npub)? {
                    tx.execute("INSERT INTO supervisor_nostr_contacts(npub,label) VALUES(?1,?2) ON CONFLICT(npub) DO UPDATE SET label=excluded.label",params![npub,decoded(&value,"label_b64",128)?])?;
                } else {
                    refuse(&tx, "nostr:contact-limit")?;
                }
            }
        } else {
            validate_send(&bytes)?;
            let count: i64 =
                tx.query_row("SELECT count(*) FROM supervisor_nostr_outbox", [], |r| {
                    r.get(0)
                })?;
            if contact(&tx, npub)?
                && count < MAX_INBOX as i64
                && !node.config.nostr.relays.is_empty()
            {
                tx.execute("INSERT INTO supervisor_nostr_outbox(proposal,event,state) VALUES(?1,'','pending')",[&id])?;
            } else {
                refuse(&tx, "nostr:send-unavailable")?;
            }
        }
        tx.execute(
            "INSERT INTO supervisor_effects(proposal,target) VALUES(?1,?2)",
            params![id, target],
        )?;
    }
    tx.commit()?;
    node.message_notify.notify_one();
    Ok(())
}
fn refuse(db: &Connection, code: &'static str) -> Result<()> {
    db.execute("INSERT INTO supervisor_nostr_refusals(code,count) VALUES(?1,1) ON CONFLICT(code) DO UPDATE SET count=min(count+1,9007199254740991)",[code])?;
    Ok(())
}
pub(crate) fn receive(node: &Node, event: &Event, now: u64) -> Result<(), &'static str> {
    let result = receive_inner(node, event, now);
    if let Err(code) = result {
        let db = node.db.lock().map_err(|_| "nostr:storage")?;
        refuse(&db, code).map_err(|_| "nostr:storage")?;
    }
    result
}
fn receive_inner(node: &Node, event: &Event, now: u64) -> Result<(), &'static str> {
    let seal = nip59::unwrap_seal(event, node.nostr.node_key(), now).map_err(|e| e.code())?;
    let npub = nostr::npub_encode(&seal.pubkey).map_err(|e| e.code())?;
    let mut db = node.db.lock().map_err(|_| "nostr:storage")?;
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| "nostr:storage")?;
    // A stranger's rumor is never decrypted.
    if !contact(&tx, &npub).map_err(|_| "nostr:storage")? {
        return Err("nostr:non-contact");
    }
    let rumor = nip59::open_seal(&seal, node.nostr.node_key(), now).map_err(|e| e.code())?;
    if rumor.kind != 14 {
        return Err("nostr:rumor-kind");
    }
    let recipients: Vec<_> = rumor
        .tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|t| t == "p"))
        .collect();
    if recipients.len() != 1
        || recipients[0].get(1) != Some(&nostr::hex_encode(&node.nostr.node_key().public_key()))
    {
        return Err("nostr:rumor-recipient");
    }
    if rumor.content.is_empty() || rumor.content.len() > MAX_CONTENT_BYTES {
        return Err("nostr:message-too-large");
    }
    let id = nostr::hex_encode(&rumor.id);
    let replay: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM supervisor_nostr_inbox WHERE id=?)",
            [&id],
            |r| r.get(0),
        )
        .map_err(|_| "nostr:storage")?;
    if replay {
        return Err("nostr:replay");
    }
    let count: i64 = tx
        .query_row("SELECT count(*) FROM supervisor_nostr_inbox", [], |r| {
            r.get(0)
        })
        .map_err(|_| "nostr:storage")?;
    if count >= MAX_INBOX as i64 {
        return Err("nostr:inbox-full");
    }
    let key = owner::stored_wrap_key(&node.signer);
    let sealed = owner::encrypt(&key, rumor.content.as_bytes(), id.as_bytes())
        .map_err(|_| "nostr:storage")?;
    tx.execute(
        "INSERT INTO supervisor_nostr_inbox(id,npub,content,created_at) VALUES(?1,?2,?3,?4)",
        params![
            id,
            npub,
            sealed,
            i64::try_from(rumor.created_at).map_err(|_| "nostr:rumor-time-invalid")?
        ],
    )
    .map_err(|_| "nostr:storage")?;
    tx.commit().map_err(|_| "nostr:storage")?;
    Ok(())
}

pub(crate) fn start(node: &Arc<Node>) -> Option<tokio::task::JoinHandle<()>> {
    if node.config.nostr.relays.is_empty() {
        return None;
    }
    Some(node.handle.spawn(run(Arc::downgrade(node))))
}
async fn run(weak: Weak<Node>) {
    let mut next_poll = tokio::time::Instant::now();
    loop {
        let Some(node) = weak.upgrade() else { return };
        if tokio::time::Instant::now() >= next_poll {
            let _ = poll(&node).await;
            next_poll = tokio::time::Instant::now() + INTERVAL;
        }
        let _ = flush(&node).await;
        let notify = node.message_notify.clone();
        drop(node);
        tokio::select! {
            _ = tokio::time::sleep_until(next_poll) => {},
            _ = notify.notified() => {},
        }
    }
}
pub(crate) async fn poll(node: &Arc<Node>) -> Result<()> {
    if node.config.nostr.relays.is_empty() {
        return Ok(());
    }
    let now = u64::try_from(state::now_ms()?)? / 1000;
    for url in &node.config.nostr.relays {
        match query(node, url, now).await {
            Ok(result) => {
                if result.dropped != 0 {
                    let db = node.db.lock().map_err(|_| anyhow!("nostr:storage"))?;
                    for _ in 0..result.dropped {
                        refuse(&db, "nostr:relay-dropped")?;
                    }
                }
                for event in result.events {
                    let _ = receive(node, &event, now);
                }
            }
            Err(error) => {
                refuse(
                    &*node.db.lock().map_err(|_| anyhow!("nostr:storage"))?,
                    error.code(),
                )?;
            }
        }
    }
    Ok(())
}
async fn query(node: &Node, url: &str, now: u64) -> relay::Result<relay::QueryResult> {
    #[cfg(test)]
    {
        let transport = node.message_transport.lock().unwrap().clone();
        if let Some(transport) = transport {
            let (tx, rx) = tokio::sync::oneshot::channel();
            transport.send(TestRequest::Query(tx)).unwrap();
            return rx.await.unwrap();
        }
    }
    relay::Client::connect(url, node.nostr.node_key(), now)
        .await?
        .query(&[relay::Filter {
            kinds: vec![1059],
            p: vec![node.nostr.node_key().public_key()],
            ..Default::default()
        }])
        .await
}
pub(crate) async fn flush(node: &Arc<Node>) -> Result<()> {
    if node.config.nostr.relays.is_empty() {
        return Ok(());
    }
    loop {
        let pending: Option<Event> = {
            let mut db = node.db.lock().map_err(|_| anyhow!("nostr:storage"))?;
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let row: Option<String> = tx.query_row("SELECT proposal FROM supervisor_nostr_outbox WHERE state='pending' ORDER BY rowid LIMIT 1",[],|r|r.get(0)).optional()?;
            if let Some(id) = row {
                let bytes: Vec<u8> = tx.query_row("SELECT b.bytes FROM gate_proposals p JOIN gate_blobs b ON b.sha256=p.new_sha256 WHERE p.id=? AND p.target=? AND p.state='applied'",params![id,SEND_TARGET],|r|r.get(0))?;
                signed_card(&tx, &node.signer.verifying_key(), &id, SEND_TARGET, &bytes)?;
                validate_send(&bytes)?;
                let value: Value = serde_json::from_slice(&bytes)?;
                let npub = value["npub"]
                    .as_str()
                    .ok_or_else(|| anyhow!("nostr:record-schema"))?;
                if !contact(&tx, npub)? {
                    tx.execute(
                        "UPDATE supervisor_nostr_outbox SET state='spent' WHERE proposal=?",
                        [&id],
                    )?;
                    tx.execute(
                        "UPDATE supervisor_nostr_outbox SET state='failed' WHERE proposal=?",
                        [&id],
                    )?;
                    refuse(&tx, "nostr:non-contact")?;
                    tx.commit()?;
                    continue;
                }
                let recipient = nostr::npub_decode(npub)?;
                let now = u64::try_from(state::now_ms()?)? / 1000;
                let rumor = Rumor::new(
                    node.nostr.node_key().public_key(),
                    now,
                    14,
                    vec![
                        vec!["p".into(), nostr::hex_encode(&recipient)],
                        vec!["nonce".into(), value["nonce"].as_str().unwrap().into()],
                    ],
                    send_plaintext(node, &value)?,
                )?;
                let event = nip59::gift_wrap(&rumor, node.nostr.node_key(), &recipient, now)?;
                // Spend before network I/O; uncertain delivery is never retried.
                tx.execute(
                    "UPDATE supervisor_nostr_outbox SET state='spent',event=?1 WHERE proposal=?2",
                    params![event.to_json(), id],
                )?;
                tx.commit()?;
                Some(event)
            } else {
                None
            }
        };
        let Some(event) = pending else { return Ok(()) };
        let now = u64::try_from(state::now_ms()?)? / 1000;
        let mut accepted = false;
        for url in &node.config.nostr.relays {
            accepted |= publish(node, url, &event, now)
                .await
                .is_ok_and(|r| r.accepted);
        }
        let db = node.db.lock().map_err(|_| anyhow!("nostr:storage"))?;
        db.execute(
            "UPDATE supervisor_nostr_outbox SET state=?1 WHERE event=?2 AND state='spent'",
            params![if accepted { "sent" } else { "failed" }, event.to_json()],
        )?;
    }
}
async fn publish(
    node: &Node,
    url: &str,
    event: &Event,
    now: u64,
) -> relay::Result<relay::PublishResult> {
    #[cfg(test)]
    {
        let transport = node.message_transport.lock().unwrap().clone();
        if let Some(transport) = transport {
            let (tx, rx) = tokio::sync::oneshot::channel();
            transport
                .send(TestRequest::Publish(event.clone(), tx))
                .unwrap();
            return rx.await.unwrap();
        }
    }
    relay::publish(url, event, node.nostr.node_key(), now).await
}

#[cfg(test)]
#[path = "nostr_messaging_tests.rs"]
mod tests;

#[cfg(test)]
mod record_tests {
    use super::*;

    #[test]
    fn antibody_nostr_message_records_are_exact_bounded_and_canonical() {
        let npub = nostr::npub_encode(
            &nostr::SecretKey::from_bytes([225; 32])
                .unwrap()
                .public_key(),
        )
        .unwrap();
        let contact =
            contact_record(&json!({"npub":npub,"label":"contact","action":"add"})).unwrap();
        let send = json!({"v":1,"npub":npub,"content_sealed":STANDARD.encode([0;57]),"content_sha256":"b".repeat(64),"nonce":"a".repeat(32)});
        for (good, validate, field) in [
            (
                contact,
                validate_contact as fn(&[u8]) -> gate::Result<()>,
                "label_b64",
            ),
            (
                send,
                validate_send as fn(&[u8]) -> gate::Result<()>,
                "content_sealed",
            ),
        ] {
            validate(&canon_bytes(&good).unwrap()).unwrap();
            let mut bad_cases = Vec::new();
            for (key, value) in [
                ("v", json!(2)),
                ("npub", json!("npub-invalid")),
                ("nonce", json!("bad")),
                ("extra", json!(true)),
                (field, json!("not base64")),
                (field, json!("")),
                (field, json!(STANDARD.encode([255]))),
                (
                    field,
                    json!(STANDARD.encode("x".repeat(if field == "label_b64" {
                        129
                    } else {
                        MAX_CONTENT_BYTES + 57
                    }))),
                ),
            ] {
                let mut bad = good.clone();
                bad[key] = value;
                bad_cases.push(bad);
            }
            for bad in bad_cases {
                assert!(
                    validate(&canon_bytes(&bad).unwrap()).is_err(),
                    "accepted malformed {field}"
                );
            }
            let mut missing = good.clone();
            missing.as_object_mut().unwrap().remove("nonce");
            assert!(validate(&canon_bytes(&missing).unwrap()).is_err());
            let mut noncanonical = vec![b' '];
            noncanonical.extend(canon_bytes(&good).unwrap());
            assert!(validate(&noncanonical).is_err());
            if field == "label_b64" {
                let mut invalid = good;
                invalid["action"] = json!("authorize");
                assert!(validate(&canon_bytes(&invalid).unwrap()).is_err());
            }
        }
    }
}
