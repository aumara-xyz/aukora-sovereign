// SPDX-License-Identifier: AGPL-3.0-or-later
//! Co-presence pairing on the node: the owner's second device, screen to screen.
//!
//! Flow (COPRESENCE-NODE.md): the bound owner starts a pairing with the owner device's
//! public key; the node returns a single-use join token for the phone; the phone joins
//! with its own public key and gets a phone bearer; the node then pins one context that
//! names both keys; both devices run the portal exchange over that exact context; the
//! owner device submits the receipt; the node verifies it with `copresence::v1`, spends
//! it once, records both devices and appends one Aura fact.
//!
//! The receipt is evidence that two keys exchanged light within a few seconds of each
//! other while bound to this context. It grants no permission, device scope or authority.

mod context;
mod store;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod twin;

use context::{session_binding, PairingContext};
#[cfg(test)]
use context::{CONTEXT_SCHEMA, MAX_CONTEXT_BYTES, PURPOSE};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use canon::{
    digest::Digest32,
    ids::{NodeId, SubjectId},
    json::{SafeInteger, Value},
    Refusal, Result,
};
use copresence::{v1, PublicKeyBytes};
use std::{path::Path, sync::Mutex};
use store::{Row, Store};

/// How long a pairing, its join token and its context stay valid.
pub const PAIRING_LIFETIME_MS: u64 = 300_000;
/// Receipt submissions counted per pairing; more closes it. A new start always works.
pub const MAX_RECEIPT_ATTEMPTS: u64 = 8;
/// Bound on submitted receipt bytes, well above a v1 receipt.
pub const MAX_RECEIPT_BYTES: usize = 16_384;
/// A device clock this many seconds ahead of the node still verifies.
pub const CLOCK_AHEAD_SECONDS: u64 = 3;
pub const STATUS_SCHEMA: &str = "aukora.copresence.pairing-status.v1";
pub const VERDICT_SCHEMA: &str = "aukora.copresence.pairing-verdict.v1";
pub const FACT_SCHEMA: &str = "aukora:copresence-pairing:v1";
pub const DEVICES_SCHEMA: &str = "aukora.copresence.paired-devices.v1";
pub const EVIDENCE: &str = "Co-presence is evidence and grants no authority.";
const JOIN_DOMAIN: &str = "aukora:copresence-join:v1";
const PHONE_DOMAIN: &str = "aukora:copresence-phone:v1";
const KEY_DOMAIN: &str = "aukora:copresence-device-key:v1";

pub(crate) const fn refuse(reason: &'static str) -> Refusal {
    Refusal {
        organ: "copresence",
        reason,
    }
}

/// The bound owner behind one owner-origin session.
#[derive(Clone, Copy, Debug)]
pub struct Owner {
    pub subject: SubjectId,
    pub epoch: u64,
    /// Digest of the owner session's bearer token, never the token.
    pub session: Digest32,
}

/// Where the node writes the one Aura fact per spent receipt.
///
/// The append is idempotent: the pairing store persists `frontier()` before the first
/// append, and `record` looks, inside the same Aura transaction, for a copresence fact
/// with the same `receipt` after that sequence before it appends. A crash after the Aura
/// commit and before the store's acknowledgement therefore returns the existing fact.
pub trait FactRecorder {
    /// Sequence of the last committed Aura record (0 for an empty ledger).
    fn frontier(&self) -> Result<u64>;
    /// The fact for `body.receipt` recorded after `since`, appended now if there is none.
    fn record(&self, subject: &SubjectId, body: &Value, since: u64) -> Result<Recorded>;
}

#[derive(Clone, Copy, Debug)]
pub struct Recorded {
    pub sequence: u64,
    pub entry: Digest32,
}

pub struct Pairing {
    store: Mutex<Store>,
    node: NodeId,
    origin: String,
}

fn text(value: impl Into<String>) -> Result<Value> {
    Value::text(value.into())
}

fn integer(value: u64) -> Result<Value> {
    let value = i64::try_from(value).map_err(|_| refuse("integer"))?;
    Ok(Value::integer(SafeInteger::new(value)?))
}

fn object(members: Vec<(&str, Value)>) -> Result<Value> {
    Value::object(
        members
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|_| refuse("randomness"))?;
    Ok(bytes)
}

fn token_digest(domain: &str, token: &str) -> Result<String> {
    if token.len() != 43 {
        return Err(refuse("token-invalid"));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| refuse("token-invalid"))?;
    if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != token {
        return Err(refuse("token-invalid"));
    }
    let mut preimage = domain.as_bytes().to_vec();
    preimage.push(0);
    preimage.extend_from_slice(&bytes);
    Ok(Digest32::sha256(&preimage).to_string())
}

fn new_token(domain: &str) -> Result<(String, String)> {
    let token = URL_SAFE_NO_PAD.encode(random::<32>()?);
    let digest = token_digest(domain, &token)?;
    Ok((token, digest))
}

/// Parses lowercase hex SEC1 uncompressed P-256 and checks the point.
pub fn device_key(hex_text: &str) -> Result<[u8; 65]> {
    if hex_text.len() != 130 || hex_text.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(refuse("public-key"));
    }
    let mut key = [0u8; 65];
    hex::decode_to_slice(hex_text, &mut key).map_err(|_| refuse("public-key"))?;
    PublicKeyBytes(key).validate()?;
    Ok(key)
}

/// The id the device list shows: SHA-256 over a domain and the SEC1 key bytes.
pub fn key_id(key: &[u8; 65]) -> String {
    let mut preimage = KEY_DOMAIN.as_bytes().to_vec();
    preimage.push(0);
    preimage.extend_from_slice(key);
    Digest32::sha256(&preimage).to_string()
}

fn pairing_id(text: &str) -> Result<()> {
    if text.len() != 32 || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(refuse("pairing-unknown"));
    }
    Ok(())
}

fn owns(row: &Row, owner: &Owner) -> Result<()> {
    if row.subject != owner.subject.to_string()
        || row.epoch != owner.epoch
        || row.session != owner.session.to_string()
    {
        // The same answer as an unknown id: another session learns nothing.
        return Err(refuse("pairing-unknown"));
    }
    Ok(())
}

impl Pairing {
    /// Opens (or creates) the store for this node. `origin` is the owner origin.
    pub fn open(path: &Path, node: NodeId, origin: &str) -> Result<Self> {
        Ok(Self {
            store: Mutex::new(Store::open(path, &node.to_string())?),
            node,
            origin: origin.to_owned(),
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Store>> {
        self.store.lock().map_err(|_| refuse("store"))
    }

    /// Records the Aura facts of spent pairings that are still pending, at most 64 per call.
    /// Returns how many this call recorded and how many are still pending. Run at boot, on
    /// every start and every device-list read, so a fact that failed once is recorded
    /// without anyone polling its pairing id again.
    pub fn settle_pending(&self, recorder: &dyn FactRecorder) -> Result<(usize, usize)> {
        let store = self.lock()?;
        let mut recorded = 0;
        for id in store.pending_facts(64)? {
            if let Some(row) = store.by_id(&id)? {
                if self.settle(&store, row, recorder)?.aura_sequence.is_some() {
                    recorded += 1;
                }
            }
        }
        Ok((recorded, store.pending_count()?))
    }

    fn sweep(&self, recorder: &dyn FactRecorder) {
        if let Err(refusal) = self.settle_pending(recorder) {
            eprintln!("copresence: pending facts not swept: {}:{}", refusal.organ, refusal.reason);
        }
    }

    /// A bound owner session starts a pairing for the device it runs on.
    pub fn start(&self, owner: &Owner, initiator_key: &str, now_ms: u64, recorder: &dyn FactRecorder) -> Result<Value> {
        self.sweep(recorder);
        let key = device_key(initiator_key)?;
        let id = hex::encode(random::<16>()?);
        let (join, join_digest) = new_token(JOIN_DOMAIN)?;
        let expires_ms = now_ms
            .checked_add(PAIRING_LIFETIME_MS)
            .ok_or(refuse("clock"))?;
        let row = Row {
            id: id.clone(),
            subject: owner.subject.to_string(),
            epoch: owner.epoch,
            session: owner.session.to_string(),
            initiator_key: hex::encode(key),
            joiner_key: None,
            context: None,
            created_ms: now_ms,
            expires_ms,
            attempts: 0,
            state: "open".into(),
            verdict: None,
            fact: None,
            aura_floor: None,
            aura_sequence: None,
            aura_entry: None,
        };
        self.lock()?.insert(&row, &join_digest, now_ms)?;
        object(vec![
            ("schema", text("aukora.copresence.pairing-start.v1")?),
            ("pairing", text(id)?),
            ("join", text(join.clone())?),
            ("joinPath", text(format!("/pair#j={join}"))?),
            ("expiresAtMs", integer(expires_ms)?),
            ("nodeTimeMs", integer(now_ms)?),
        ])
    }

    /// The phone joins with the token from the owner's screen and its own public key.
    /// The token works once; the phone gets a bearer for this pairing only.
    pub fn join(&self, join: &str, joiner_key: &str, now_ms: u64) -> Result<Value> {
        let digest = token_digest(JOIN_DOMAIN, join)?;
        let key = device_key(joiner_key)?;
        let store = self.lock()?;
        let row = store.by_join(&digest)?.ok_or(refuse("join-invalid"))?;
        if row.state != "open" {
            return Err(refuse("join-used"));
        }
        if now_ms >= row.expires_ms {
            return Err(refuse("pairing-expired"));
        }
        let initiator = device_key(&row.initiator_key)?;
        if initiator == key {
            return Err(refuse("same-device"));
        }
        let subject = SubjectId::parse(&row.subject)?;
        let session = Digest32::from_hex(&row.session)?;
        let mut pairing = [0u8; 16];
        hex::decode_to_slice(&row.id, &mut pairing).map_err(|_| refuse("store"))?;
        let context = PairingContext {
            node: self.node,
            owner: subject,
            owner_epoch: row.epoch,
            owner_session: session_binding(&session),
            pairing,
            origin: &self.origin,
            initiator_key: &initiator,
            joiner_key: &key,
            issued_at_ms: now_ms,
            expires_at_ms: row.expires_ms,
        }
        .canonical_text()?;
        let (phone, phone_digest) = new_token(PHONE_DOMAIN)?;
        store.join(&row.id, &phone_digest, &hex::encode(key), &context)?;
        let row = store.by_id(&row.id)?.ok_or(refuse("store"))?;
        object(vec![
            ("schema", text("aukora.copresence.pairing-join.v1")?),
            ("phone", text(phone)?),
            ("status", self.status_value(&row, now_ms)?),
        ])
    }

    /// The owner device polls until the phone has joined and the context exists.
    pub fn owner_status(&self, owner: &Owner, pairing: &str, now_ms: u64, recorder: &dyn FactRecorder) -> Result<Value> {
        pairing_id(pairing)?;
        let store = self.lock()?;
        let row = store.by_id(pairing)?.ok_or(refuse("pairing-unknown"))?;
        owns(&row, owner)?;
        let row = self.settle(&store, row, recorder)?;
        self.status_value(&row, now_ms)
    }

    /// The phone polls with its bearer; it sees the same context and the node's verdict.
    pub fn phone_status(&self, phone: &str, now_ms: u64) -> Result<Value> {
        let digest = token_digest(PHONE_DOMAIN, phone)?;
        let store = self.lock()?;
        let row = store.by_phone(&digest)?.ok_or(refuse("pairing-unknown"))?;
        self.status_value(&row, now_ms)
    }

    fn status_value(&self, row: &Row, now_ms: u64) -> Result<Value> {
        let state = match row.state.as_str() {
            "open" | "joined" if now_ms >= row.expires_ms => "expired",
            state => state,
        };
        let state = state.to_owned();
        let context = match (&row.context, state.as_str()) {
            (Some(context), "joined" | "spent") => text(context.clone())?,
            _ => Value::null(),
        };
        object(vec![
            ("schema", text(STATUS_SCHEMA)?),
            ("pairing", text(row.id.clone())?),
            ("state", text(state)?),
            ("expiresAtMs", integer(row.expires_ms)?),
            ("nodeTimeMs", integer(now_ms)?),
            ("context", context),
            ("verdict", self.verdict_value(row)?),
        ])
    }

    fn verdict_value(&self, row: &Row) -> Result<Value> {
        let Some(verdict) = &row.verdict else {
            return Ok(Value::null());
        };
        let stored = canon::json::parse_strict(verdict.as_bytes())?;
        let canon::json::ValueView::Object(members) = stored.view() else {
            return Err(refuse("store"));
        };
        let mut members: Vec<(String, Value)> = members
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        let recorded = match (row.aura_sequence, &row.aura_entry) {
            (Some(sequence), Some(entry)) => object(vec![
                ("sequence", integer(sequence)?),
                ("entry", text(entry.clone())?),
            ])?,
            _ => Value::null(),
        };
        members.push(("recorded".into(), recorded));
        Value::object(members)
    }

    /// Appends the pending Aura fact for a spent pairing; a failure stays pending
    /// and the next status read tries again. The receipt itself is already spent.
    fn settle(&self, store: &Store, row: Row, recorder: &dyn FactRecorder) -> Result<Row> {
        if row.state != "spent" || row.aura_sequence.is_some() {
            return Ok(row);
        }
        let Some(fact) = &row.fact else {
            return Ok(row);
        };
        let body = canon::json::parse_strict(fact.as_bytes())?;
        let subject = SubjectId::parse(&row.subject)?;
        let since = match row.aura_floor {
            Some(floor) => floor,
            None => match recorder.frontier() {
                // Durable before any append, so a retry searches from the same point.
                Ok(floor) => store.set_floor(&row.id, floor)?,
                Err(refusal) => {
                    eprintln!("copresence: pairing fact pending: {}:{}", refusal.organ, refusal.reason);
                    return Ok(row);
                }
            },
        };
        match recorder.record(&subject, &body, since) {
            Ok(recorded) => {
                store.recorded(&row.id, recorded.sequence, &recorded.entry.to_string())?;
                store.by_id(&row.id)?.ok_or(refuse("store"))
            }
            Err(refusal) => {
                eprintln!("copresence: pairing fact pending: {}:{}", refusal.organ, refusal.reason);
                Ok(row)
            }
        }
    }

    /// The node's expected context: the claimed v1 context, accepted only when every
    /// field the node pins matches. Session ids and attempt counters stay the devices'.
    fn expected(&self, row: &Row, receipt: &[u8]) -> Result<(v1::Context, [u8; 65], [u8; 65])> {
        let claims = v1::read_receipt_claims(receipt)?;
        let context = claims.core.context;
        let pinned = row.context.as_deref().ok_or(refuse("pairing-state"))?;
        let initiator = device_key(&row.initiator_key)?;
        let joiner = device_key(row.joiner_key.as_deref().ok_or(refuse("pairing-state"))?)?;
        let keys = [context.a.device_key.0, context.b.device_key.0];
        if context.purpose != pinned
            || context.method != v1::Method::ScreenToScreen
            || context.required_layers
                != (v1::RequiredLayers {
                    sound: false,
                    motion: false,
                    intent_ack: false,
                })
            || context.intent.is_some()
            || context.a.node != self.node
            || context.b.node != self.node
        {
            return Err(refuse("context-mismatch"));
        }
        if !(keys == [initiator, joiner] || keys == [joiner, initiator]) {
            return Err(refuse("device-mismatch"));
        }
        Ok((context, initiator, joiner))
    }

    /// Verify, then spend once, record both devices and append the Aura fact.
    pub fn submit(
        &self,
        owner: &Owner,
        pairing: &str,
        receipt: &[u8],
        now_ms: u64,
        recorder: &dyn FactRecorder,
    ) -> Result<Value> {
        pairing_id(pairing)?;
        let mut store = self.lock()?;
        let row = store.by_id(pairing)?.ok_or(refuse("pairing-unknown"))?;
        owns(&row, owner)?;
        match row.state.as_str() {
            "joined" => {}
            "spent" => return Err(refuse("receipt-spent")),
            _ => return Err(refuse("pairing-state")),
        }
        if now_ms >= row.expires_ms {
            store.close(pairing)?;
            return Err(refuse("pairing-expired"));
        }
        if store.count_attempt(pairing)? > MAX_RECEIPT_ATTEMPTS {
            store.close(pairing)?;
            return Err(refuse("attempts-exhausted"));
        }
        if receipt.is_empty() || receipt.len() > MAX_RECEIPT_BYTES {
            return Err(refuse("receipt-size"));
        }
        let (expected, initiator, joiner) = self.expected(&row, receipt)?;
        let checked_now = (now_ms / 1000)
            .checked_add(CLOCK_AHEAD_SECONDS)
            .ok_or(refuse("clock"))?;
        let verified = {
            let mut journal = store.journal(pairing, now_ms);
            v1::verify_receipt(receipt, &expected, checked_now, &mut journal)?
        };
        let core = &verified.body().core;
        if core.t_a_seconds < row.created_ms / 1000
            || core.t_b_seconds.saturating_mul(1000) >= row.expires_ms
        {
            return Err(refuse("receipt-window"));
        }
        let digest = verified.digest().to_string();
        let (initiator_id, joiner_id) = (key_id(&initiator), key_id(&joiner));
        let devices = || -> Result<Value> {
            object(vec![
                ("initiator", text(initiator_id.clone())?),
                ("joiner", text(joiner_id.clone())?),
            ])
        };
        let verdict = object(vec![
            ("schema", text(VERDICT_SCHEMA)?),
            ("pairing", text(pairing)?),
            ("verdict", text("UNDETERMINED")?),
            ("code", Value::null()),
            ("receipt", text(digest.clone())?),
            ("devices", devices()?),
            ("personNostrKeys", Value::null()),
            ("evidence", text(EVIDENCE)?),
        ])?;
        let fact = object(vec![
            ("schema", text(FACT_SCHEMA)?),
            ("evidenceOnly", Value::boolean(true)),
            ("pairing", text(pairing)?),
            ("node", text(self.node.to_string())?),
            ("owner", text(row.subject.clone())?),
            ("ownerEpoch", integer(row.epoch)?),
            (
                "context",
                text(Digest32::sha256(row.context.as_deref().unwrap_or("").as_bytes()).to_string())?,
            ),
            ("receipt", text(digest.clone())?),
            ("receiptBytes", text(Digest32::sha256(receipt).to_string())?),
            ("method", text("screen-to-screen")?),
            ("tA", integer(core.t_a_seconds)?),
            ("tB", integer(core.t_b_seconds)?),
            ("devices", devices()?),
        ])?;
        let verdict_text = String::from_utf8(verdict.canonical_bytes()).map_err(|_| refuse("store"))?;
        let fact_text = String::from_utf8(fact.canonical_bytes()).map_err(|_| refuse("store"))?;
        let (initiator_hex, joiner_hex) = (hex::encode(initiator), hex::encode(joiner));
        store.spend(
            pairing,
            &row.subject,
            &digest,
            &verdict_text,
            &fact_text,
            [
                (&initiator_id, &initiator_hex, "initiator"),
                (&joiner_id, &joiner_hex, "joiner"),
            ],
            now_ms,
        )?;
        let row = store.by_id(pairing)?.ok_or(refuse("store"))?;
        let row = self.settle(&store, row, recorder)?;
        self.verdict_value(&row)
    }

    /// Every device this owner has paired, for the Sovereignty app's device list.
    pub fn devices(&self, owner: &SubjectId, recorder: &dyn FactRecorder) -> Result<Value> {
        self.sweep(recorder);
        let rows = self.lock()?.devices(&owner.to_string())?;
        let mut devices = Vec::new();
        for row in rows {
            devices.push(object(vec![
                ("key", text(row.key_sha256)?),
                ("publicKey", text(row.public_key)?),
                ("role", text(row.role)?),
                ("firstPairing", text(row.first_pairing)?),
                ("lastPairing", text(row.last_pairing)?),
                ("firstPairedAtMs", integer(row.first_ms)?),
                ("lastPairedAtMs", integer(row.last_ms)?),
                ("pairings", integer(row.pairings)?),
            ])?);
        }
        object(vec![
            ("schema", text(DEVICES_SCHEMA)?),
            ("devices", Value::array(devices)?),
            ("evidence", text(EVIDENCE)?),
        ])
    }
}
