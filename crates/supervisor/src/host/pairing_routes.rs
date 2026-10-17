// SPDX-License-Identifier: AGPL-3.0-or-later
//! Owner-origin routes for co-presence pairing (supervisor::pairing) and its Aura fact.
//!
//! Owner routes run inside the bound owner session; the phone's two routes carry their
//! own single-use token or pairing bearer and never touch an owner session.

use super::{json_response, now, Host};
use crate::adapters::HostLedger;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use canon::{
    alg::AlgorithmId,
    authority::{AuthorityTxn, FactKind, FactRecord, Kind, Phase},
    codes,
    ids::SubjectId,
    json::{Value, ValueView},
    Result,
};
use frontdoor::{ingress::AdmittedRequest, owner_origin::OwnerRoute, session::BoundSession};
use crate::pairing::{FactRecorder, Owner, Recorded, FACT_SCHEMA, MAX_RECEIPT_BYTES};
use supervisor::ingress::{BindingState, PrincipalScope};

/// The one Aura fact per spent receipt: a nonauthorizing `boot.facts` row whose actor is
/// `copresence` and whose body schema is `aukora:copresence-pairing:v1`.
pub(super) struct AuraFacts<'a>(pub &'a HostLedger);

/// Inside one Aura transaction: the copresence fact for `body.receipt` committed after
/// `since`, or a new one appended now. The lookup and the append share the writer lock,
/// so a retry after a crash finds the earlier commit instead of appending twice. The
/// lookup reads only copresence fact rows (an index read, one row per pairing), so it
/// has no record-count cap and a pending fact can always be recorded later.
pub(super) fn append_once(txn: &mut aura::LedgerTxn<'_>, body: &Value, since: u64) -> Result<Recorded> {
    let receipt = body.get("receipt").ok_or(codes::FRONTDOOR_BODY_INVALID)?;
    for sequence in txn.fact_sequences_after("boot.facts", "copresence", since)? {
        let record = txn
            .floor_record_at_sequence(sequence)?
            .ok_or(codes::AURA_UNVERIFIED)?;
        if record.kind != Kind::BootFacts
            || record.phase != Phase::Fact
            || record.operation.is_some()
            || record.actor != "copresence"
        {
            return Err(codes::AURA_UNVERIFIED);
        }
        let payload = aura::record::AuthorityBodyV1::parse(&record.body)?.payload;
        if matches!(payload.get("schema").map(Value::view), Some(ValueView::Text(FACT_SCHEMA)))
            && payload.get("receipt") == Some(receipt)
        {
            return Ok(Recorded {
                sequence: record.authority.sequence,
                entry: record.hash,
            });
        }
    }
    let context = txn.observation_context()?;
    let row = txn.append_fact(FactRecord {
        v: 1,
        algorithm: AlgorithmId::Sha256,
        authority: context.authority,
        at: context.at,
        kind: FactKind::BootFacts,
        actor: "copresence".into(),
        body: body.clone(),
    })?;
    Ok(Recorded {
        sequence: row.authority.sequence,
        entry: row.hash,
    })
}

impl FactRecorder for AuraFacts<'_> {
    fn frontier(&self) -> Result<u64> {
        self.0
            .transaction(|txn| Ok(txn.current_version()?.sequence.saturating_sub(1)))
    }

    // The fact names its owner and epoch; it was verified under that bound owner's session.
    // A later rebinding must not leave it unrecordable, so there is no current-owner check.
    fn record(&self, _subject: &SubjectId, body: &Value, since: u64) -> Result<Recorded> {
        self.0.transaction(|txn| append_once(txn, body, since))
    }
}

/// Pairing facts left pending by a crash or an Aura refusal are recorded at boot, 64 at a
/// time, until none are left or a pass makes no progress.
pub(super) fn sweep_at_boot(pairing: &crate::pairing::Pairing, ledger: &HostLedger) {
    let facts = AuraFacts(ledger);
    loop {
        match pairing.settle_pending(&facts) {
            Ok((_, 0)) => return,
            Ok((recorded, _)) if recorded > 0 => {}
            Ok((_, left)) => {
                eprintln!("copresence: {left} pairing facts still pending");
                return;
            }
            Err(refusal) => {
                eprintln!("copresence: pending facts not swept: {}:{}", refusal.organ, refusal.reason);
                return;
            }
        }
    }
}

fn exact<'a>(body: &'a Value, keys: &[&str]) -> Result<Vec<&'a str>> {
    let ValueView::Object(members) = body.view() else {
        return Err(codes::FRONTDOOR_BODY_INVALID);
    };
    if members.len() != keys.len() {
        return Err(codes::FRONTDOOR_BODY_INVALID);
    }
    keys.iter()
        .map(|key| match body.get(key).map(Value::view) {
            Some(ValueView::Text(text)) if text.len() <= 32_768 => Ok(text),
            _ => Err(codes::FRONTDOOR_BODY_INVALID),
        })
        .collect()
}

impl Host {
    fn pairing(&self) -> Result<&crate::pairing::Pairing> {
        self.pairing.as_deref().ok_or(canon::Refusal {
            organ: "copresence",
            reason: "pairing-unavailable",
        })
    }

    /// The phone: join with the token from the owner's screen, then poll with the bearer.
    pub(super) fn pairing_phone(
        &self,
        request: &AdmittedRequest,
        route: OwnerRoute,
    ) -> Result<http::Response<Vec<u8>>> {
        let pairing = self.pairing()?;
        let at = now()?;
        let value = match route {
            OwnerRoute::PairingJoin => {
                let fields = exact(request.body(), &["join", "deviceKey"])?;
                pairing.join(fields[0], fields[1], at)?
            }
            OwnerRoute::PairingPhone => {
                let fields = exact(request.body(), &["phone"])?;
                pairing.phone_status(fields[0], at)?
            }
            _ => return Err(codes::FRONTDOOR_UNKNOWN_ROUTE),
        };
        json_response(value)
    }

    /// The bound owner: only a live owner-frame session of the currently bound owner.
    pub(super) fn pairing_owner(
        &self,
        session: &BoundSession<'_>,
        route: OwnerRoute,
        body: &Value,
    ) -> Result<Value> {
        let pairing = self.pairing()?;
        let record = session.record();
        let subject = record.subject.ok_or(codes::AUMLOK_BINDING_REQUIRED)?;
        if self.ledger.binding()?
            != BindingState::Bound(PrincipalScope {
                subject,
                epoch: record.owner_epoch,
            })
        {
            return Err(codes::AUMLOK_BINDING_REQUIRED);
        }
        let owner = Owner {
            subject,
            epoch: record.owner_epoch,
            session: record.token_digest,
        };
        let facts = AuraFacts(&self.ledger);
        let at = now()?;
        match route {
            OwnerRoute::PairingStart => {
                let fields = exact(body, &["deviceKey"])?;
                pairing.start(&owner, fields[0], at, &facts)
            }
            OwnerRoute::PairingStatus => {
                let fields = exact(body, &["pairing"])?;
                pairing.owner_status(&owner, fields[0], at, &facts)
            }
            OwnerRoute::PairingReceipt => {
                let fields = exact(body, &["pairing", "receipt"])?;
                if fields[1].len() > MAX_RECEIPT_BYTES.div_ceil(3) * 4 {
                    return Err(codes::FRONTDOOR_BODY_INVALID);
                }
                let receipt = URL_SAFE_NO_PAD
                    .decode(fields[1])
                    .map_err(|_| codes::FRONTDOOR_BODY_INVALID)?;
                pairing.submit(&owner, fields[0], &receipt, at, &facts)
            }
            OwnerRoute::PairingDevices => {
                exact(body, &[])?;
                pairing.devices(&subject, &facts)
            }
            _ => Err(codes::FRONTDOOR_UNKNOWN_ROUTE),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use canon::alg::{PublicKey, Signature, Signatures};
    use ed25519_dalek::{Signer, SigningKey};
    use std::sync::Arc;

    struct TestSigner(SigningKey);
    impl aura::RecordSigner for TestSigner {
        fn public_keys(&self) -> Result<Vec<PublicKey>> {
            Ok(vec![PublicKey {
                v: 1,
                algorithm: AlgorithmId::Ed25519,
                bytes: self.0.verifying_key().to_bytes().to_vec(),
            }])
        }
        fn sign_entry_hash(&self, hash: canon::digest::Digest32) -> Result<Signatures> {
            Signatures::new(vec![Signature {
                v: 1,
                algorithm: AlgorithmId::Ed25519,
                bytes: self.0.sign(hash.as_bytes()).to_bytes().to_vec(),
            }])
        }
    }

    fn fact(receipt: &str) -> Value {
        Value::object(vec![
            ("schema".into(), Value::text(FACT_SCHEMA.into()).unwrap()),
            ("receipt".into(), Value::text(receipt.into()).unwrap()),
        ])
        .unwrap()
    }

    /// Against a real Aura ledger: the append commits, the acknowledgement is lost (a
    /// crash), and every retry from the stored floor returns the committed fact.
    #[test]
    fn a_retried_append_returns_the_committed_fact() {
        let directory = std::env::temp_dir().join(format!("copresence-aura-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let directory = std::fs::canonicalize(directory).unwrap();
        let ledger = HostLedger::open(
            &directory.join("aura.sqlite3"),
            Arc::new(TestSigner(SigningKey::from_bytes(&[7; 32]))),
            Arc::new(crate::adapters::HostClock),
        )
        .unwrap();
        let floor = ledger.transaction(|txn| Ok(txn.current_version()?.sequence - 1)).unwrap();
        let first = ledger.transaction(|txn| append_once(txn, &fact("aa"), floor)).unwrap();
        // Unrelated records arrive: another actor's fact (never read by the lookup) and
        // another receipt's fact.
        ledger
            .transaction(|txn| {
                let context = txn.observation_context()?;
                txn.append_fact(FactRecord {
                    v: 1,
                    algorithm: AlgorithmId::Sha256,
                    authority: context.authority,
                    at: context.at,
                    kind: FactKind::BootFacts,
                    actor: "supervisor".into(),
                    body: fact("aa"),
                })
            })
            .unwrap();
        let only_ours = ledger.transaction(|txn| txn.fact_sequences_after("boot.facts", "copresence", floor)).unwrap();
        assert_eq!(only_ours, vec![first.sequence]);
        let other = ledger.transaction(|txn| append_once(txn, &fact("bb"), floor)).unwrap();
        assert_ne!(other.sequence, first.sequence);
        for _ in 0..2 {
            let again = ledger.transaction(|txn| append_once(txn, &fact("aa"), floor)).unwrap();
            assert_eq!((again.sequence, again.entry), (first.sequence, first.entry));
        }
        let next = ledger.transaction(|txn| Ok(txn.current_version()?.sequence)).unwrap();
        assert_eq!(next, other.sequence + 1, "no record was appended by a retry");
        let _ = std::fs::remove_dir_all(&directory);
    }
}
