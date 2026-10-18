// SPDX-License-Identifier: AGPL-3.0-or-later
//! Sender admission precedes message opening; refusal facts carry no authority.

pub(crate) mod refusal_audit;
pub(crate) mod refused;
use refused::settle_refused;
#[cfg(test)]
pub(crate) use refused::{remember_refused, REFUSED_ENVELOPE_CAP, RETRY_LIMIT};

use canon::{
    alg::AlgorithmId,
    authority::{AuthorityTxn, FactKind, FactRecord, Kind, Phase},
    digest::Digest32,
    health::{Cell, HealthEvidence, HealthReason, OrganId, HEALTH_FORMAT_VERSION},
    json::{SafeInteger, Value, ValueView, MAX_SAFE_INTEGER},
    Refusal, Result,
};
use nostr::{Event, EventId, PublicKey, TransportEnvelope, TransportKind};
use rusqlite::{params, Connection, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::{Messaging, MAX_MESSAGE_BYTES};

pub const REFUSAL_SCHEMA: &str = "aukora:messaging-refusal:v1";
pub const COUNTS_SCHEMA: &str = "aukora:messaging-refusal-counts:v1";

/// Refusal classes have fixed cardinality; identities cannot add buckets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusalReason {
    Envelope,
    Signature,
    Recipient,
    Stranger,
    Replay,
    Payload,
    StaleContact,
}

impl RefusalReason {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Envelope => "messaging:envelope",
            Self::Signature => "messaging:signature",
            Self::Recipient => "messaging:recipient",
            Self::Stranger => "messaging:stranger",
            Self::Replay => "messaging:replay",
            Self::Payload => "messaging:payload",
            Self::StaleContact => "messaging:stale-contact",
        }
    }
}

/// No message text or unbounded sender map is retained in these observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefusalObservation {
    pub ingress_digest: Digest32,
    pub envelope_id: Option<EventId>,
    pub transport: TransportKind,
    pub reason: RefusalReason,
    pub observed_at_ms: u64,
}

/// Totals aggregate committed refusal facts, never permissions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefusalCounts {
    pub envelope: u64,
    pub signature: u64,
    pub recipient: u64,
    pub stranger: u64,
    pub replay: u64,
    pub payload: u64,
    pub stale_contact: u64,
    pub total: u64,
    pub last_aura_sequence: u64,
}

/// Construction follows the host's durable, observation-only Aura commit.
#[derive(Debug)]
pub struct CountedRefusal {
    observation: RefusalObservation,
    sequence: u64,
}

struct PendingRefusal {
    attempt: [u8; 16],
    observation: RefusalObservation,
    prior: RefusalCounts,
}

impl CountedRefusal {
    pub const fn observation(&self) -> &RefusalObservation {
        &self.observation
    }
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// Only the supervisor can stamp Source::Contact from this ingress channel.
/// Text, embedded roles and signatures cannot convert these data into owner input.
#[derive(Debug)]
pub struct ContactData {
    sender: PublicKey,
    event: EventId,
    text: String,
    transport: TransportKind,
    contact_receipt: Digest32,
}

impl ContactData {
    pub const fn sender(&self) -> PublicKey {
        self.sender
    }
    pub const fn event(&self) -> EventId {
        self.event
    }
    pub fn text(&self) -> &str {
        &self.text
    }
    pub const fn transport(&self) -> TransportKind {
        self.transport
    }
    pub const fn contact_receipt(&self) -> Digest32 {
        self.contact_receipt
    }
    pub const fn is_owner(&self) -> bool {
        false
    }
    pub const fn data_only(&self) -> bool {
        true
    }
}

#[derive(Debug)]
pub enum IngressOutcome {
    Data(ContactData),
    Refused(CountedRefusal),
    /// Refused again for a reason that can clear, already counted `RETRY_LIMIT` times: not counted again, tried again
    /// on the next poll.
    Retrying(RefusalReason),
}

/// Uses the existing nonauthorizing boot.facts path, as posture observations do.
/// The versioned body identifies a refusal, not a boot or an owner action.
/// Adapters aggregate only this schema/actor in messaging.refusals/totals, from
/// committed signed Fact rows; each contributes exactly one named reason.
/// The messaging.refusals.attempt namespace maps retained attempt hex to exactly
/// {body,sequence}, from the same committed signed fact and no other row.
/// The messaging.refusals.fact namespace maps one-based decimal refusal ordinals
/// to those same {body,sequence} values in increasing Aura sequence order.
/// The commit hook must reject any transaction with staged authority changes.
pub fn append_refusal<T: AuthorityTxn + ?Sized>(
    txn: &mut T,
    observation: RefusalObservation,
) -> Result<CountedRefusal> {
    let mut attempt = [0; 16];
    getrandom::fill(&mut attempt).map_err(|_| refuse("random-unavailable"))?;
    let prior = read_counts(txn)?;
    append_refusal_attempt(txn, observation, attempt, prior)
}

fn append_refusal_attempt<T: AuthorityTxn + ?Sized>(
    txn: &mut T,
    observation: RefusalObservation,
    attempt: [u8; 16],
    prior: RefusalCounts,
) -> Result<CountedRefusal> {
    let body = observation_body(&observation, attempt)?;
    let expected = prior.increment(observation.reason)?;
    // Recovery retains the attempt id when Aura committed before the cache did.
    if let Some(committed) =
        txn.committed_observation_state("messaging.refusals.attempt", &hex::encode(attempt))?
    {
        if !matches!(committed.view(), ValueView::Object(fields) if fields.len() == 2) {
            return Err(refuse("refusal-record"));
        }
        let sequence = integer_field(&committed, "sequence")?;
        if committed.get("body") != Some(&body) || sequence == 0 {
            return Err(refuse("refusal-record"));
        }
        let after = read_counts(txn)?;
        if sequence <= prior.last_aura_sequence
            || sequence > after.last_aura_sequence
            || after.without_sequence() != expected.without_sequence()
        {
            return Err(refuse("refusal-count-mismatch"));
        }
        return Ok(CountedRefusal {
            observation,
            sequence,
        });
    }
    if read_counts(txn)? != prior {
        return Err(refuse("refusal-count-mismatch"));
    }
    let context = txn.observation_context()?;
    let sequence = context.authority.sequence;
    if sequence == 0
        || sequence > MAX_SAFE_INTEGER as u64
        || sequence <= prior.last_aura_sequence
        || context.at < 0
    {
        return Err(refuse("refusal-context"));
    }
    let record = txn.append_fact(FactRecord {
        v: 1,
        algorithm: AlgorithmId::Sha256,
        authority: context.authority,
        at: context.at,
        kind: FactKind::BootFacts,
        actor: "messaging".into(),
        body: body.clone(),
    })?;
    if record.v != 1
        || record.algorithm != AlgorithmId::Sha256
        || record.authority != context.authority
        || record.at != context.at
        || record.kind != Kind::BootFacts
        || record.phase != Phase::Fact
        || record.operation.is_some()
        || record.actor != "messaging"
        || !refusal_audit::record_body_matches(&record, &body)?
    {
        return Err(refuse("refusal-record"));
    }
    txn.commit_observations()?;
    let after = read_counts(txn)?;
    if after.last_aura_sequence != sequence
        || after.without_sequence() != expected.without_sequence()
    {
        return Err(refuse("refusal-count-mismatch"));
    }
    Ok(CountedRefusal {
        observation,
        sequence,
    })
}

pub(crate) fn initialize(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS messaging_seen(
            event BLOB PRIMARY KEY CHECK(length(event)=32),
            seal BLOB NOT NULL UNIQUE CHECK(length(seal)=32),
            envelope BLOB NOT NULL UNIQUE CHECK(length(envelope)=32),
            sender BLOB NOT NULL CHECK(length(sender)=32),
            receipt TEXT NOT NULL CHECK(length(receipt)=64),
            epoch INTEGER NOT NULL CHECK(epoch>=0),
            sequence INTEGER NOT NULL CHECK(sequence>0),
            transport TEXT NOT NULL CHECK(transport='nostr-relays'),
            provenance TEXT NOT NULL CHECK(provenance='contact'),
            instruction INTEGER NOT NULL CHECK(instruction=0),
            content_hash BLOB NOT NULL CHECK(length(content_hash)=32)
        );
        CREATE TRIGGER IF NOT EXISTS messaging_seen_no_update BEFORE UPDATE ON messaging_seen
            BEGIN SELECT RAISE(ABORT,'messaging:replay'); END;
        CREATE TRIGGER IF NOT EXISTS messaging_seen_no_delete BEFORE DELETE ON messaging_seen
            BEGIN SELECT RAISE(ABORT,'messaging:replay'); END;
        CREATE TABLE IF NOT EXISTS messaging_refusal_cache(
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            dirty INTEGER NOT NULL CHECK(dirty IN(0,1)),
            counts BLOB NOT NULL
        );
        INSERT OR IGNORE INTO messaging_refusal_cache VALUES(1,1,x'');
        -- Envelope ids (public relay event ids, nothing else) of wraps already refused and counted, so the relay
        -- worker's repeated snapshots never decrypt and count the same wrap again.
        CREATE TABLE IF NOT EXISTS messaging_refused_envelope(
            envelope BLOB PRIMARY KEY CHECK(length(envelope)=32)
        );
        CREATE TABLE IF NOT EXISTS messaging_retry_envelope(
            envelope BLOB PRIMARY KEY CHECK(length(envelope)=32),
            tries INTEGER NOT NULL CHECK(tries>=0)
        );
        CREATE TABLE IF NOT EXISTS messaging_pending_refusal(
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            attempt BLOB NOT NULL CHECK(length(attempt)=16),
            observation BLOB NOT NULL,
            prior_counts BLOB
        );
        UPDATE messaging_refusal_cache SET dirty=1 WHERE singleton=1;",
    )
    .map_err(|_| refuse("store-schema"))?;
    let has_prior: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('messaging_pending_refusal')
             WHERE name='prior_counts')",
            [],
            |row| row.get(0),
        )
        .map_err(|_| refuse("store-schema"))?;
    if !has_prior {
        db.execute_batch("ALTER TABLE messaging_pending_refusal ADD COLUMN prior_counts BLOB")
            .map_err(|_| refuse("store-schema"))?;
    }
    // Legacy attempts kept their pre-append counts in the dirty cache. Validate
    // that baseline before retaining it alongside the attempt on upgrade.
    let legacy: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM messaging_pending_refusal WHERE prior_counts IS NULL)",
            [],
            |row| row.get(0),
        )
        .map_err(|_| refuse("store-read"))?;
    if legacy {
        let bytes: Vec<u8> = db
            .query_row(
                "SELECT counts FROM messaging_refusal_cache WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| refuse("store-read"))?;
        counts_from_bytes(&bytes)?;
        db.execute(
            "UPDATE messaging_pending_refusal SET prior_counts=?1 WHERE prior_counts IS NULL",
            [bytes],
        )
        .map_err(|_| refuse("store-write"))?;
    }
    Ok(())
}

impl Messaging {
    /// The relay worker can skip an already admitted envelope in repeated relay
    /// snapshots. Explicit ingress attempts still pass through the replay fence.
    /// A wrap refused for a final reason (counted once) is skipped the same way; it is never retried, so a sender who was not
    /// yet an approved contact sends again after both owners have approved each other.
    pub fn seen_envelope(&self, envelope: EventId) -> Result<bool> {
        self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM messaging_seen WHERE envelope=?1)
             OR EXISTS(SELECT 1 FROM messaging_refused_envelope WHERE envelope=?1)",
            [envelope.as_bytes().as_slice()], |row| row.get(0),
        ).map_err(|_| refuse("store-read"))
    }

    /// Reads committed Aura state before admission; a missing adapter refuses.
    /// A restart leaves the local count cache dirty until it is reconciled.
    pub fn refresh_refusal_counts<T: AuthorityTxn + ?Sized>(
        &mut self,
        txn: &mut T,
    ) -> Result<RefusalCounts> {
        if self.pending_refusal()?.is_some() {
            return Err(refuse("refusal-recovery-required"));
        }
        let counts = read_counts(txn)?;
        let transaction = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| refuse("store-busy"))?;
        let previous: Vec<u8> = transaction
            .query_row(
                "SELECT counts FROM messaging_refusal_cache WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| refuse("store-read"))?;
        if !previous.is_empty() {
            let previous = counts_from_bytes(&previous)?;
            if counts.total < previous.total
                || counts.last_aura_sequence < previous.last_aura_sequence
                || (counts.total > previous.total
                    && counts.last_aura_sequence <= previous.last_aura_sequence)
                || counts
                    .buckets()
                    .iter()
                    .zip(previous.buckets())
                    .any(|(now, old)| *now < old)
                || (counts.total == previous.total && counts != previous)
            {
                return Err(refuse("refusal-rollback"));
            }
        }
        transaction
            .execute(
                "UPDATE messaging_refusal_cache SET dirty=0,counts=?1 WHERE singleton=1",
                [counts.to_value()?.canonical_bytes()],
            )
            .map_err(|_| refuse("store-write"))?;
        transaction.commit().map_err(|_| refuse("store-commit"))?;
        Ok(counts)
    }

    pub fn receive<T: AuthorityTxn + ?Sized>(
        &mut self,
        txn: &mut T,
        envelope: &TransportEnvelope,
        recipient_key: &nostr::SecretKey,
        transport: TransportKind,
        received_at_ms: u64,
    ) -> Result<IngressOutcome> {
        let prior = self.refresh_refusal_counts(txn)?;
        match self.admit(txn, envelope, recipient_key, transport, received_at_ms) {
            Ok(data) => {
                refused::forget_retry(&self.db, envelope.id.as_bytes())?;
                self.audit_message(txn, Digest32::from_bytes(*data.event().as_bytes()))?;
                Ok(IngressOutcome::Data(data))
            }
            Err((reason, retryable)) => {
                if retryable && refused::retry_exhausted(&self.db, envelope.id.as_bytes())? {
                    return Ok(IngressOutcome::Retrying(reason));
                }
                let context = txn.observation_context()?;
                let observed_at_ms =
                    u64::try_from(context.at).map_err(|_| refuse("refusal-context"))?;
                let observation = RefusalObservation {
                    ingress_digest: Digest32::from_bytes(Sha256::digest(&envelope.bytes).into()),
                    envelope_id: Some(envelope.id),
                    transport,
                    reason,
                    observed_at_ms,
                };
                let mut attempt = [0; 16];
                getrandom::fill(&mut attempt).map_err(|_| refuse("random-unavailable"))?;
                let transaction = self
                    .db
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(|_| refuse("store-busy"))?;
                transaction
                    .execute(
                        "UPDATE messaging_refusal_cache SET dirty=1 WHERE singleton=1",
                        [],
                    )
                    .map_err(|_| refuse("store-write"))?;
                transaction
                    .execute(
                        "INSERT INTO messaging_pending_refusal
                         (singleton,attempt,observation,prior_counts) VALUES(1,?1,?2,?3)",
                        params![
                            attempt.as_slice(),
                            observation_body(&observation, attempt)?.canonical_bytes(),
                            prior.to_value()?.canonical_bytes()
                        ],
                    )
                    .map_err(|_| refuse("store-write"))?;
                // Durable with the pending attempt: recovery counts this attempt once, and no later snapshot recounts it.
                // Only reasons that can never clear for these bytes are remembered: a payload refused for clock skew or a
                // contact approval that is catching up stays retryable on the next poll. Bounded: past the cap a wrap is
                // simply counted again on a later poll, never dropped.
                settle_refused(&transaction, envelope.id.as_bytes(), retryable)?;
                transaction.commit().map_err(|_| refuse("store-commit"))?;
                let counted = append_refusal_attempt(txn, observation, attempt, prior)?;
                self.db
                    .execute(
                        "DELETE FROM messaging_pending_refusal WHERE singleton=1",
                        [],
                    )
                    .map_err(|_| refuse("store-write"))?;
                self.refresh_refusal_counts(txn)?;
                Ok(IngressOutcome::Refused(counted))
            }
        }
    }

    /// Resolve a retained refusal before admitting another envelope. Reusing its
    /// attempt id cannot add a second count after an interrupted cache update.
    pub fn recover_refusal<T: AuthorityTxn + ?Sized>(
        &mut self,
        txn: &mut T,
    ) -> Result<Option<CountedRefusal>> {
        let Some(pending) = self.pending_refusal()? else {
            self.refresh_refusal_counts(txn)?;
            return Ok(None);
        };
        let counted =
            append_refusal_attempt(txn, pending.observation, pending.attempt, pending.prior)?;
        self.db
            .execute(
                "DELETE FROM messaging_pending_refusal WHERE singleton=1",
                [],
            )
            .map_err(|_| refuse("store-write"))?;
        self.refresh_refusal_counts(txn)?;
        Ok(Some(counted))
    }

    fn pending_refusal(&self) -> Result<Option<PendingRefusal>> {
        let mut statement = self
            .db
            .prepare("SELECT attempt,observation,prior_counts FROM messaging_pending_refusal WHERE singleton=1")
            .map_err(|_| refuse("store-read"))?;
        let mut rows = statement.query([]).map_err(|_| refuse("store-read"))?;
        let Some(row) = rows.next().map_err(|_| refuse("store-read"))? else {
            return Ok(None);
        };
        let attempt: Vec<u8> = row.get(0).map_err(|_| refuse("store-read"))?;
        let bytes: Vec<u8> = row.get(1).map_err(|_| refuse("store-read"))?;
        let prior: Vec<u8> = row.get(2).map_err(|_| refuse("store-read"))?;
        let attempt: [u8; 16] = attempt.try_into().map_err(|_| refuse("refusal-record"))?;
        Ok(Some(PendingRefusal {
            attempt,
            observation: decode_observation(&bytes, attempt)?,
            prior: counts_from_bytes(&prior)?,
        }))
    }

    fn admit<T: AuthorityTxn + ?Sized>(
        &mut self,
        txn: &mut T,
        envelope: &TransportEnvelope,
        recipient_key: &nostr::SecretKey,
        transport: TransportKind,
        received_at_ms: u64,
    ) -> core::result::Result<ContactData, (RefusalReason, bool)> {
        use RefusalReason as R;
        // Each refusal says whether it can clear for these same bytes (true: retried on a later poll, a bounded
        // number of times) or is final (remembered, never counted again): see `receive`.
        let fin = |reason: R| (reason, false);
        let retry = |reason: R| (reason, true);
        let timed = |error: &canon::Refusal| error.reason.ends_with("-time-invalid");
        if transport != TransportKind::NostrRelays {
            return Err(fin(R::Envelope));
        }
        if received_at_ms > MAX_SAFE_INTEGER as u64 {
            return Err(retry(R::Payload));
        }
        envelope
            .validate()
            .map_err(|error| fin(classify(error, R::Envelope)))?;
        let local = recipient_key.public_key().map_err(|_| fin(R::Recipient))?;
        if envelope.recipient != local {
            return Err(fin(R::Recipient));
        }
        let wrap = Event::decode(&envelope.bytes)
            .and_then(Event::verify)
            .map_err(|error| fin(classify(error, R::Signature)))?;
        let now = received_at_ms / 1000;
        let seal = nostr::nip59::authenticate_sender(&wrap, recipient_key, now)
            .map_err(|error| (classify(error, R::Envelope), timed(&error)))?;
        let sender = *seal.sender();
        let contact = self
            .current_contact(txn, sender)
            .map_err(|_| retry(R::StaleContact))?
            .ok_or(fin(R::Stranger))?;
        let context = txn.observation_context().map_err(|_| retry(R::StaleContact))?;
        if contact.authority().epoch != context.authority.epoch
            || contact.authority().sequence >= context.authority.sequence
        {
            return Err(retry(R::StaleContact));
        }
        let rumor = nostr::nip59::open_message(&seal, recipient_key, now)
            .map_err(|error| (classify(error, R::Payload), timed(&error)))?;
        let recipient = hex::encode(local.as_bytes());
        let nonce_valid = rumor.tags.len() == 1
            || (rumor.tags.len() == 2
                && rumor.tags[1].len() == 2
                && rumor.tags[1][0] == "nonce"
                && rumor.tags[1][1].len() == 32
                && rumor.tags[1][1].bytes().all(|byte|
                    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
        if !nonce_valid || rumor.tags[0] != ["p", recipient.as_str()] {
            return Err(fin(R::Recipient));
        }
        if rumor.content.is_empty() || rumor.content.len() > MAX_MESSAGE_BYTES {
            return Err(fin(R::Payload));
        }
        let transaction = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| retry(R::Payload))?;
        let duplicate: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM messaging_seen WHERE event=?1 OR seal=?2 OR envelope=?3)",
            params![rumor.id.as_bytes().as_slice(), seal.event().event().id.as_bytes().as_slice(),
                envelope.id.as_bytes().as_slice()], |row| row.get(0),
        ).map_err(|_| retry(R::Payload))?;
        if duplicate {
            return Err(fin(R::Replay));
        }
        transaction.execute(
            "INSERT INTO messaging_seen VALUES(?1,?2,?3,?4,?5,?6,?7,'nostr-relays','contact',0,?8)",
            params![rumor.id.as_bytes().as_slice(), seal.event().event().id.as_bytes().as_slice(),
                envelope.id.as_bytes().as_slice(), sender.as_bytes().as_slice(),
                contact.consumed_card().to_string(), contact.authority().epoch as i64,
                contact.authority().sequence as i64, Sha256::digest(rumor.content.as_bytes()).as_slice()],
        ).map_err(|_| retry(R::Payload))?;
        crate::history::stage(
            &transaction,
            Digest32::from_bytes(*rumor.id.as_bytes()),
            "incoming",
            sender,
            &rumor.content,
            rumor.created_at.checked_mul(1000).ok_or(fin(R::Payload))?,
            received_at_ms,
            envelope,
            contact.consumed_card(),
        ).map_err(|_| retry(R::Payload))?;
        transaction.commit().map_err(|_| retry(R::Payload))?;
        Ok(ContactData {
            sender,
            event: rumor.id,
            text: rumor.content,
            transport,
            contact_receipt: contact.consumed_card(),
        })
    }

    /// Dirty caches and unavailable Aura reconciliation return an error, never zero.
    pub fn refusal_counts(&self) -> Result<RefusalCounts> {
        let (dirty, bytes): (i64, Vec<u8>) = self
            .db
            .query_row(
                "SELECT dirty,counts FROM messaging_refusal_cache WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| refuse("store-read"))?;
        if dirty != 0 {
            return Err(refuse("refusal-counts-unreconciled"));
        }
        counts_from_bytes(&bytes)
    }

    /// Independent observations for row 135; the Network collector merges these
    /// registered ids with other organ-owned checks. Health never grants admission.
    pub fn ingress_health<T: AuthorityTxn + ?Sized>(
        &mut self,
        txn: &mut T,
        context: &nostr::health::HealthContext,
    ) -> Vec<HealthEvidence> {
        let aligned = txn.observation_context().is_ok_and(|observed| {
            observed.authority.epoch == context.epoch
                && observed.authority.sequence.checked_sub(1) == Some(context.sequence)
        });
        let counts = if aligned {
            self.refresh_refusal_counts(txn)
        } else {
            Err(refuse("health-context"))
        };
        let counters = counts
            .as_ref()
            .map_err(|error| *error)
            .and_then(|counts| refusal_audit::verify_facts(txn, counts, context.sequence));
        let accepted = self
            .db
            .query_row("SELECT count(*) FROM messaging_seen", [], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(|_| refuse("store-read"));
        let metadata: Result<()> = self
            .db
            .query_row(
                "SELECT count(*) FROM messaging_seen WHERE provenance!='contact' OR instruction!=0
                OR length(sender)!=32 OR length(receipt)!=64 OR sequence<=0",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| refuse("store-read"))
            .and_then(|invalid| {
                if invalid == 0 {
                    Ok(())
                } else {
                    Err(refuse("ingress-invariant"))
                }
            });
        let admission = match (&counts, &metadata, &accepted) {
            (Ok(counts), Ok(()), Ok(accepted)) if counts.stranger > 0 && *accepted > 0 => Ok(()),
            (Ok(_), Ok(()), Ok(_)) => Err(refuse("health-not-checked")),
            (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => Err(*error),
        };
        let provenance = metadata.and_then(|()| match accepted {
            Ok(0) => Err(refuse("health-not-checked")),
            Ok(_) => Ok(()),
            Err(error) => Err(error),
        });
        [
            nostr::health::INGRESS_ADMISSION,
            nostr::health::MESSAGE_PROVENANCE,
            nostr::health::REFUSAL_COUNTERS,
        ]
        .into_iter()
        .map(|spec| {
            let observed = if spec == nostr::health::REFUSAL_COUNTERS {
                &counters
            } else if spec == nostr::health::INGRESS_ADMISSION {
                &admission
            } else {
                &provenance
            };
            let (cell, reason) = if !aligned {
                (Cell::Undetermined, HealthReason::ContextMismatch)
            } else {
                match observed {
                    Ok(()) => (Cell::Verified, HealthReason::Satisfied),
                    Err(error)
                        if error.reason == "ingress-invariant"
                            || error.reason == "refusal-rollback"
                            || error.reason == "refusal-count-mismatch"
                            || error.reason == "refusal-count-schema"
                            || error.reason == "refusal-record" =>
                    {
                        (Cell::Failed, HealthReason::InvariantFailed)
                    }
                    Err(error) if error.reason == "health-not-checked" => {
                        (Cell::Undetermined, HealthReason::NotChecked)
                    }
                    Err(_) => (Cell::Undetermined, HealthReason::Unreachable),
                }
            };
            HealthEvidence {
                v: HEALTH_FORMAT_VERSION,
                algorithm: AlgorithmId::Sha256,
                check: spec.check,
                reporter: OrganId::Network,
                epoch: context.epoch,
                sequence: context.sequence,
                observed_at_ms: context.observed_at_ms,
                expires_at_ms: context.observed_at_ms.saturating_add(spec.freshness_ms),
                cell,
                reason,
                commitment: context.commitment,
            }
        })
        .collect()
    }
}

impl RefusalCounts {
    fn empty() -> Self {
        Self {
            envelope: 0,
            signature: 0,
            recipient: 0,
            stranger: 0,
            replay: 0,
            payload: 0,
            stale_contact: 0,
            total: 0,
            last_aura_sequence: 0,
        }
    }

    fn buckets(&self) -> [u64; 7] {
        [
            self.envelope,
            self.signature,
            self.recipient,
            self.stranger,
            self.replay,
            self.payload,
            self.stale_contact,
        ]
    }

    fn without_sequence(mut self) -> Self {
        self.last_aura_sequence = 0;
        self
    }

    fn increment(mut self, reason: RefusalReason) -> Result<Self> {
        if self.total >= MAX_SAFE_INTEGER as u64 {
            return Err(refuse("refusal-count-exhausted"));
        }
        let bucket = match reason {
            RefusalReason::Envelope => &mut self.envelope,
            RefusalReason::Signature => &mut self.signature,
            RefusalReason::Recipient => &mut self.recipient,
            RefusalReason::Stranger => &mut self.stranger,
            RefusalReason::Replay => &mut self.replay,
            RefusalReason::Payload => &mut self.payload,
            RefusalReason::StaleContact => &mut self.stale_contact,
        };
        *bucket += 1;
        self.total += 1;
        Ok(self)
    }

    pub fn to_value(&self) -> Result<Value> {
        let names = [
            "envelope",
            "signature",
            "recipient",
            "stranger",
            "replay",
            "payload",
            "stale_contact",
        ];
        let mut entries = vec![("schema".into(), text(COUNTS_SCHEMA)?)];
        for (key, value) in names.into_iter().zip(self.buckets()) {
            entries.push((key.into(), number(value)?));
        }
        entries.push(("total".into(), number(self.total)?));
        entries.push((
            "last_aura_sequence".into(),
            number(self.last_aura_sequence)?,
        ));
        Value::checked_object(entries)
    }

    fn from_value(value: &Value) -> Result<Self> {
        let ValueView::Object(members) = value.view() else {
            return Err(refuse("refusal-count-schema"));
        };
        if members.len() != 10
            || value
                .get("schema")
                .map(Value::view)
                .is_none_or(|v| !matches!(v, ValueView::Text(COUNTS_SCHEMA)))
        {
            return Err(refuse("refusal-count-schema"));
        }
        let get = |key| match value.get(key).map(Value::view) {
            Some(ValueView::Integer(integer)) if integer.get() >= 0 => Ok(integer.get() as u64),
            _ => Err(refuse("refusal-count-schema")),
        };
        let counts = Self {
            envelope: get("envelope")?,
            signature: get("signature")?,
            recipient: get("recipient")?,
            stranger: get("stranger")?,
            replay: get("replay")?,
            payload: get("payload")?,
            stale_contact: get("stale_contact")?,
            total: get("total")?,
            last_aura_sequence: get("last_aura_sequence")?,
        };
        let sum = counts
            .buckets()
            .into_iter()
            .try_fold(0_u64, u64::checked_add)
            .ok_or(refuse("refusal-count-mismatch"))?;
        if sum != counts.total
            || (sum == 0) != (counts.last_aura_sequence == 0)
            || sum > counts.last_aura_sequence
        {
            return Err(refuse("refusal-count-mismatch"));
        }
        Ok(counts)
    }
}

fn read_counts<T: AuthorityTxn + ?Sized>(txn: &mut T) -> Result<RefusalCounts> {
    match txn.committed_observation_state("messaging.refusals", "totals")? {
        Some(value) => RefusalCounts::from_value(&value),
        None => Ok(RefusalCounts::empty()),
    }
}

fn integer_field(value: &Value, key: &str) -> Result<u64> {
    match value.get(key).map(Value::view) {
        Some(ValueView::Integer(number)) if number.get() >= 0 => Ok(number.get() as u64),
        _ => Err(refuse("refusal-record")),
    }
}

fn decode_observation(bytes: &[u8], attempt: [u8; 16]) -> Result<RefusalObservation> {
    if bytes.len() > 2048 {
        return Err(refuse("refusal-record"));
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| refuse("refusal-record"))?;
    let string = |key: &str| {
        value
            .get(key)
            .and_then(serde_json::Value::as_str)
            .ok_or(refuse("refusal-record"))
    };
    let reason = [
        RefusalReason::Envelope,
        RefusalReason::Signature,
        RefusalReason::Recipient,
        RefusalReason::Stranger,
        RefusalReason::Replay,
        RefusalReason::Payload,
        RefusalReason::StaleContact,
    ]
    .into_iter()
    .find(|reason| Some(reason.code()) == value.get("code").and_then(serde_json::Value::as_str))
    .ok_or(refuse("refusal-record"))?;
    let transport = match string("transport")? {
        "nostr-relays" => TransportKind::NostrRelays,
        "bluetooth-mesh" => TransportKind::BluetoothMesh,
        "bitchat-adapter" => TransportKind::BitchatAdapter,
        _ => return Err(refuse("refusal-record")),
    };
    let envelope_id = match value.get("envelope_id") {
        Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(id)) => {
            Some(EventId::from_bytes(*Digest32::from_hex(id)?.as_bytes()))
        }
        _ => return Err(refuse("refusal-record")),
    };
    let observation = RefusalObservation {
        ingress_digest: Digest32::from_hex(string("ingress_sha256")?)?,
        envelope_id,
        transport,
        reason,
        observed_at_ms: value
            .get("observed_at_ms")
            .and_then(serde_json::Value::as_u64)
            .ok_or(refuse("refusal-record"))?,
    };
    if observation_body(&observation, attempt)?.canonical_bytes() != bytes {
        return Err(refuse("refusal-record"));
    }
    Ok(observation)
}

fn counts_from_bytes(bytes: &[u8]) -> Result<RefusalCounts> {
    // Only locally produced flat counter objects enter this bounded cache parser.
    if bytes.len() > 2048 {
        return Err(refuse("refusal-count-schema"));
    }
    let decoded: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| refuse("refusal-count-schema"))?;
    let object = decoded.as_object().ok_or(refuse("refusal-count-schema"))?;
    let mut fields = Vec::new();
    for (key, value) in object {
        let value = if let Some(number_value) = value.as_u64() {
            number(number_value)?
        } else if let Some(text_value) = value.as_str() {
            text(text_value)?
        } else {
            return Err(refuse("refusal-count-schema"));
        };
        fields.push((key.clone(), value));
    }
    let value = Value::checked_object(fields)?;
    if value.canonical_bytes() != bytes {
        return Err(refuse("refusal-count-schema"));
    }
    RefusalCounts::from_value(&value)
}

fn observation_body(observation: &RefusalObservation, attempt: [u8; 16]) -> Result<Value> {
    let transport = match observation.transport {
        TransportKind::NostrRelays => "nostr-relays",
        TransportKind::BluetoothMesh => "bluetooth-mesh",
        TransportKind::BitchatAdapter => "bitchat-adapter",
    };
    Value::checked_object(vec![
        ("schema".into(), text(REFUSAL_SCHEMA)?),
        ("attempt".into(), text(&hex::encode(attempt))?),
        (
            "ingress_sha256".into(),
            text(&observation.ingress_digest.to_string())?,
        ),
        (
            "envelope_id".into(),
            match observation.envelope_id {
                Some(id) => text(&hex::encode(id.as_bytes()))?,
                None => Value::null(),
            },
        ),
        ("transport".into(), text(transport)?),
        ("code".into(), text(observation.reason.code())?),
        ("observed_at_ms".into(), number(observation.observed_at_ms)?),
        ("count".into(), number(1)?),
    ])
}

fn classify(error: Refusal, fallback: RefusalReason) -> RefusalReason {
    match error.reason {
        "event-signature"
        | "event-id"
        | "event-signature-invalid"
        | "event-id-mismatch"
        | "rumor-id-mismatch"
        | "signature-invalid"
        | "sender-mismatch" => RefusalReason::Signature,
        "envelope-recipient" | "wrap-not-for-us" | "recipient-mismatch" => RefusalReason::Recipient,
        _ => fallback,
    }
}

fn text(value: &str) -> Result<Value> {
    Value::checked_text(value.into())
}
fn number(value: u64) -> Result<Value> {
    let value = i64::try_from(value).map_err(|_| refuse("integer-range"))?;
    Ok(Value::integer(SafeInteger::new(value)?))
}
fn refuse(reason: &'static str) -> Refusal {
    Refusal {
        organ: "messaging",
        reason,
    }
}
