// SPDX-License-Identifier: AGPL-3.0-or-later
//! Real passkey registration, Aura records and gate contact-card consumption.

use super::*;
mod locking;
use aumlok::{
    ceremony::{
        possession_challenge, BeginCeremony, CeremonyConfig, CeremonyPurpose, CeremonyStore,
        ClaimSecret, EnrolmentIdentity, SqliteCeremonyStore,
    },
    webauthn::{OriginContext, RegistrationMaterial},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use canon::{
    alg::Signatures,
    authority::{
        ceremony::{CeremonyFinish, CeremonyKind},
        OwnerAssertion,
    },
    ids::{NodeId, SessionId, SubjectId},
};
use ed25519_dalek::{Signer, SigningKey as Ed25519Key};
use gate::{
    proposal::{ProposalRequest, SuggestionOrder},
    recovery::NoInjection,
    service::{scoped::ScopedGate, GateConfig},
    target::{ConfinedStore, TargetClass, TargetId, TargetSpec, TargetStore},
};
use std::{
    fs::{self, File},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::Arc,
};

const NOW: i64 = 1_800_000_000_000;
const RP: &str = "owner.example.invalid";
const ORIGIN: &str = "https://owner.example.invalid";
const TOP: &str = "https://example.invalid";

struct TestSigner(Ed25519Key);
impl aura::RecordSigner for TestSigner {
    fn public_keys(&self) -> Result<Vec<SigningKey>> {
        Ok(vec![SigningKey {
            v: 1,
            algorithm: AlgorithmId::Ed25519,
            bytes: self.0.verifying_key().to_bytes().to_vec(),
        }])
    }
    fn sign_entry_hash(&self, hash: Digest32) -> Result<Signatures> {
        Signatures::new(vec![Signature {
            v: 1,
            algorithm: AlgorithmId::Ed25519,
            bytes: self.0.sign(hash.as_bytes()).to_bytes().to_vec(),
        }])
    }
}
struct Clock;
impl aura::TrustedClock for Clock {
    fn now_ms(&self) -> Result<i64> {
        Ok(NOW)
    }
}

struct Rig {
    directory: PathBuf,
    ledger: Arc<HostLedger>,
    gate: Option<ScopedGate<ConfinedStore>>,
    owner: Ed25519Key,
    credential: CredentialId,
    scope: PrincipalScope,
}
impl Drop for Rig {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn rig() -> Result<Rig> {
    let mut nonce = [0; 16];
    getrandom::fill(&mut nonce).unwrap();
    let directory = std::env::temp_dir().join(format!("messaging-gate-{}", hex::encode(nonce)));
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(directory.join("targets")).unwrap();
    fs::set_permissions(directory.join("targets"), fs::Permissions::from_mode(0o700)).unwrap();
    let directory = fs::canonicalize(directory).unwrap();
    let path = directory.join("aura.sqlite3");
    let ledger = Arc::new(HostLedger::open(
        &path,
        Arc::new(TestSigner(Ed25519Key::from_bytes(&[81; 32]))),
        Arc::new(Clock),
    )?);
    let owner = Ed25519Key::from_bytes(&[82; 32]);
    let credential = CredentialId::new(vec![83; 32])?;
    let subject = SubjectId::from_digest(Digest32::sha256(b"messaging-test-owner"));
    let session = SessionId::from_bytes([84; 16]);
    let authority = ledger.transaction(|txn| txn.current_version())?;
    let mut ceremonies = SqliteCeremonyStore::open(
        &path,
        CeremonyConfig {
            origins: OriginContext {
                relying_party: RP.into(),
                owner_origin: ORIGIN.into(),
                expected_top_origin: Some(TOP.into()),
            },
            identity: EnrolmentIdentity {
                owner_id: "owner".into(),
                user_handle: vec![85; 16],
            },
            subject,
            authority,
            claim_digest: Some(Digest32::sha256(&[89; 32])),
            trusted_session: session,
        },
    )?;
    let fresh = ceremonies.begin(
        &BeginCeremony {
            purpose: CeremonyPurpose::Enrolment,
            session,
            credential: None,
        },
        NOW,
    )?;
    let reserved = ceremonies.reserve_enrolment(
        &fresh.id,
        &ClaimSecret(zeroize::Zeroizing::new(vec![89; 32])),
        NOW,
    )?;
    let registered = ceremonies.register_candidate(
        &fresh.id,
        &reserved.resume_secret,
        &registration(&owner, &credential, fresh.nonce),
        NOW,
    )?;
    let (client, authenticator, signature) =
        assertion_bytes(&owner, possession_challenge(&registered)?, 0);
    let assertion_json = serde_json::to_vec(&serde_json::json!({
        "kind":"passkey","credential_id":URL_SAFE_NO_PAD.encode(credential.as_bytes()),
        "client_data_json":URL_SAFE_NO_PAD.encode(client),
        "authenticator_data":URL_SAFE_NO_PAD.encode(authenticator),
        "signature":URL_SAFE_NO_PAD.encode(signature),"user_handle":null,
    }))
    .unwrap();
    let binding = OwnerBinding {
        v: 1,
        algorithm: AlgorithmId::Ed25519,
        credential_id: credential.clone(),
        public_key: SigningKey {
            v: 1,
            algorithm: AlgorithmId::Ed25519,
            bytes: owner.verifying_key().to_bytes().to_vec(),
        },
        epoch: 1,
        relying_party: RP.into(),
        owner_origin: ORIGIN.into(),
        top_origin: TOP.into(),
        sign_counter: 0,
    };
    ledger.transaction(|txn| {
        txn.finish_ceremony(CeremonyFinish {
            transaction_id: txn.transaction_id(),
            id: registered.id,
            kind: CeremonyKind::Enrolment,
            session,
            subject,
            authority,
            nonce: registered.nonce,
            expires_at_ms: registered.expires_at_ms,
            candidate_digest: registered.candidate_digest,
            binding: &binding,
            owner_id: "owner",
            user_handle: &[85; 16],
            backup_eligible: false,
            assertion_json: &assertion_json,
            now_ms: NOW,
        })
    })?;
    drop(ceremonies);
    let scope = PrincipalScope { subject, epoch: 1 };
    assert_eq!(
        ledger.binding()?,
        supervisor::ingress::BindingState::Bound(scope)
    );
    let targets = vec![TargetSpec {
        id: TargetId::new(messaging::CONTACT_TARGET.into())?,
        class: TargetClass::Content,
        risk: gate::RiskTier::Critical,
        max_bytes: 8192,
    }];
    let store = ConfinedStore::open(
        File::open(directory.join("targets")).unwrap(),
        targets.clone(),
    )?;
    let gate = ScopedGate::new(
        store,
        GateConfig {
            node: NodeId::from_bytes([86; 16]),
            targets,
            proposal_lifetime_ms: 300_000,
            ceremony_lifetime_ms: 300_000,
        },
    )?;
    Ok(Rig {
        directory,
        ledger,
        gate: Some(gate),
        owner,
        credential,
        scope,
    })
}

/// A normal none-attestation registration of a real Ed25519 WebAuthn key.
fn registration(
    owner: &Ed25519Key,
    credential: &CredentialId,
    challenge: [u8; 32],
) -> RegistrationMaterial {
    let client = serde_json::to_vec(&serde_json::json!({"type":"webauthn.create",
        "challenge":URL_SAFE_NO_PAD.encode(challenge),"origin":ORIGIN,
        "topOrigin":TOP,"crossOrigin":true}))
    .unwrap();
    let mut authenticator = Digest32::sha256(RP.as_bytes()).as_bytes().to_vec();
    authenticator.push(0x45); // UP, UV, attested credential data.
    authenticator.extend_from_slice(&[0; 4]);
    authenticator.extend_from_slice(&[0; 16]);
    authenticator.extend_from_slice(&(credential.as_bytes().len() as u16).to_be_bytes());
    authenticator.extend_from_slice(credential.as_bytes());
    // COSE OKP: kty=1, alg=-8, crv=6, x=32-byte Ed25519 public key.
    authenticator.extend_from_slice(b"\xa4\x01\x01\x03\x27\x20\x06\x21\x58\x20");
    authenticator.extend_from_slice(&owner.verifying_key().to_bytes());
    let mut attestation = b"\xa3\x63fmt\x64none\x68authData\x58".to_vec();
    attestation.push(authenticator.len() as u8);
    attestation.extend_from_slice(&authenticator);
    attestation.extend_from_slice(b"\x67attStmt\xa0");
    let id = URL_SAFE_NO_PAD.encode(credential.as_bytes());
    RegistrationMaterial {
        kind: "passkey-registration".into(),
        credential_type: "public-key".into(),
        id: id.clone(),
        raw_id: id,
        client_data_json: URL_SAFE_NO_PAD.encode(client),
        attestation_object: URL_SAFE_NO_PAD.encode(attestation),
        client_extension_results: serde_json::json!({}),
    }
}

fn assertion_bytes(
    owner: &Ed25519Key,
    challenge: [u8; 32],
    counter: u32,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let client = serde_json::to_vec(&serde_json::json!({"type":"webauthn.get",
        "challenge":URL_SAFE_NO_PAD.encode(challenge),"origin":ORIGIN,
        "topOrigin":TOP,"crossOrigin":true}))
    .unwrap();
    let mut authenticator = Digest32::sha256(RP.as_bytes()).as_bytes().to_vec();
    authenticator.push(5);
    authenticator.extend_from_slice(&counter.to_be_bytes());
    let mut signed = authenticator.clone();
    signed.extend_from_slice(Digest32::sha256(&client).as_bytes());
    (
        client,
        authenticator,
        owner.sign(&signed).to_bytes().to_vec(),
    )
}

fn contact_action(seed: u8, label: &str) -> OwnerAction {
    let key = nostr::SecretKey::import(zeroize::Zeroizing::new([seed; 32]))
        .unwrap()
        .public_key()
        .unwrap();
    OwnerAction::Contact(ContactChange::Add(messaging::ContactDraft {
        key,
        label: label.into(),
        pairing: None,
    }))
}

impl Rig {
    fn approve(&mut self, action: &OwnerAction, counter: u32) -> Result<ProposalId> {
        let target = TargetId::new(messaging::CONTACT_TARGET.into())?;
        let gate = self.gate.as_mut().unwrap();
        let base = gate.target_store().observe(&target)?.digest;
        let bytes = action.canonical_bytes()?;
        let proposal = self.ledger.scoped(self.scope, |txn| {
            gate.propose(
                txn,
                ProposalRequest {
                    target,
                    base,
                    new_bytes: bytes,
                    model_note: String::new(),
                    cell: None,
                    new_evidence: None,
                    suggestion: SuggestionOrder::Single,
                },
                &mut NoInjection,
            )
        })?;
        let review = self.ledger.scoped(self.scope, |txn| {
            gate.review(txn, proposal.id, OwnerOperation::Apply, &mut NoInjection)
        })?;
        assert_eq!(
            review.card.canonical_bytes(),
            action.card()?.canonical_bytes()?
        );
        assert!(self
            .ledger
            .messaging(self.scope, false, |txn| txn.contact_keys())?
            .is_empty());
        let (client_data_json, authenticator_data, bytes) =
            assertion_bytes(&self.owner, *review.passkey_challenge.as_bytes(), counter);
        let assertion = OwnerAssertion {
            v: 1,
            algorithm: AlgorithmId::Ed25519,
            credential_id: self.credential.clone(),
            authenticator_data,
            client_data_json,
            signature: Signature {
                v: 1,
                algorithm: AlgorithmId::Ed25519,
                bytes,
            },
        };
        let mut invalid = assertion.clone();
        invalid.signature.bytes[0] ^= 1;
        assert!(self
            .ledger
            .scoped(self.scope, |txn| gate.consume_apply(
                txn,
                proposal.id,
                invalid,
                &mut NoInjection
            ))
            .is_err());
        let consumed = self.ledger.scoped(self.scope, |txn| {
            gate.consume_apply(txn, proposal.id, assertion, &mut NoInjection)
        })?;
        assert!(self
            .ledger
            .messaging(self.scope, false, |txn| txn.contact_keys())?
            .is_empty());
        let outcome = self.ledger.scoped(self.scope, |txn| {
            gate.effect_once(txn, consumed, &mut NoInjection)
        })?;
        assert_eq!(outcome.state, gate::proposal::ProposalState::Applied);
        Ok(proposal.id)
    }
}

#[test]
fn one_real_contact_card_admits_owner_sends_and_verified_projection_survives_restart() -> Result<()>
{
    let mut rig = rig()?;
    let action = contact_action(87, "Owner B");
    let OwnerAction::Contact(ContactChange::Add(draft)) = &action else {
        unreachable!()
    };
    let proposal = rig.approve(&action, 1)?;
    let mut store = messaging::Messaging::open(
        &rig.directory.join("messaging"),
        NodeId::from_bytes([86; 16]),
    )?;
    let contact = rig
        .ledger
        .messaging(rig.scope, false, |txn| {
            store.synchronize_contact(txn, draft.key)
        })?
        .unwrap();
    assert_eq!(contact.proposal(), proposal);
    assert_eq!(contact.label(), "Owner B");
    assert_eq!(store.contacts(None, 10)?, vec![contact.clone()]);
    let sender = nostr::SecretKey::import(zeroize::Zeroizing::new([88; 32]))?;
    let send = messaging::SendDraft {
        recipient: draft.key,
        text: "A real ledger send".into(),
        disclosures: Vec::new(),
    };
    assert!(rig
        .ledger
        .messaging(rig.scope, false, |txn| store
            .queue_owner_send(txn, &send, &sender, NOW as u64))
        .is_err());
    rig.ledger.messaging(rig.scope, true, |txn| {
        store.queue_owner_send(txn, &send, &sender, NOW as u64)
    })?;
    rig.ledger.messaging(rig.scope, true, |txn| {
        store.queue_owner_send(txn, &send, &sender, NOW as u64)
    })?;
    assert_eq!(store.messages(Some(draft.key), None, 10)?.len(), 2);
    // Both sends were owner-session effects; the sole gate assertion was the contact card.
    let (consumes, facts) = rig.ledger.transaction(|txn| {
        let mut consumes = 0;
        let mut facts = 0;
        for sequence in 1..txn.current_version()?.sequence {
            let row = txn.floor_record_at_sequence(sequence)?.unwrap();
            if row.kind == Kind::GateConsume {
                consumes += 1;
            }
            if row.kind == Kind::BootFacts && row.actor == "messaging" {
                facts += 1;
            }
        }
        Ok((consumes, facts))
    })?;
    assert_eq!((consumes, facts), (1, 2));
    drop(store);
    let mut store = messaging::Messaging::open(
        &rig.directory.join("messaging"),
        NodeId::from_bytes([86; 16]),
    )?;
    let replayed = rig
        .ledger
        .messaging(rig.scope, false, |txn| {
            store.synchronize_contact(txn, draft.key)
        })?
        .unwrap();
    assert_eq!(contact, replayed);
    assert_eq!(store.messages(Some(draft.key), None, 10)?.len(), 2);
    assert_eq!(
        rig.ledger
            .messaging(rig.scope, false, |txn| txn.contact_keys())?,
        vec![draft.key]
    );
    use crate::faces::{
        live_network::LiveNetwork,
        network::{self, NetworkRead},
    };
    let identity = Arc::new(crate::nostr_identity::NodeIdentity::open(
        &File::open(&rig.directory).unwrap(),
    )?);
    let config = rig.gate.as_ref().unwrap().config().clone();
    drop(rig.gate.take()); // Release the target writer before starting its host worker.
    let gate = Arc::new(crate::adapters::GateAdapter::start(
        rig.directory.join("aura.sqlite3"),
        File::open(rig.directory.join("targets")).unwrap(),
        config,
        Arc::clone(&rig.ledger),
    )?);
    let network = LiveNetwork::new(Arc::clone(&rig.ledger), store, Arc::clone(&identity), gate);
    assert_eq!(network.node_npub()?.as_deref(), Some(identity.npub()));
    assert_eq!(network.contacts(rig.scope, None, 10)?.items[0], contact);
    let first = network.messages(rig.scope, Some(draft.key), None, 1)?;
    assert_eq!(first.items.len(), 1);
    assert_eq!(first.items[0].text, "A real ledger send");
    let second = network.messages(rig.scope, Some(draft.key), first.next.as_deref(), 1)?;
    assert_eq!(second.items.len(), 1);
    assert!(second.next.is_none());
    assert_ne!(first.items[0].id, second.items[0].id);
    let encoded = network::call(
        &network,
        rig.scope,
        "messages.list",
        &Value::object(vec![
            ("before".into(), Value::null()),
            ("limit".into(), number(10)?),
            ("npub".into(), text(draft.key.to_npub()?.as_str())?),
        ])?,
    )?;
    assert!(
        matches!(encoded.get("items").map(Value::view),Some(ValueView::Array(items)) if items.len()==2)
    );
    let encoded_contacts = network::call(
        &network,
        rig.scope,
        "contacts.list",
        &Value::object(vec![
            ("before".into(), Value::null()),
            ("limit".into(), number(10)?),
        ])?,
    )?;
    assert!(
        matches!(encoded_contacts.get("items").map(Value::view),Some(ValueView::Array(items))
        if items.len()==1 && string(&items[0],"label").ok()==Some("Owner B"))
    );
    let foreign = PrincipalScope {
        subject: SubjectId::from_digest(Digest32::sha256(b"foreign-owner")),
        epoch: rig.scope.epoch,
    };
    assert!(network.contacts(foreign, None, 10).is_err());
    assert!(network.messages(foreign, None, None, 10).is_err());
    assert!(network.messages(rig.scope, None, Some("0"), 10).is_err());
    // The owner's Add contact still raises its one card through the adapter (propose_owner_requested), while a guest
    // proposal to any messaging/ target is refused (adapters::gate::messaging_tests).
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let _entered = runtime.enter();
    let other = nostr::SecretKey::import(zeroize::Zeroizing::new([91; 32]))?.public_key()?;
    let raised = network.propose_contact(rig.scope, other.to_npub()?.as_str(), Some("Owner C"))?;
    assert_eq!(string(&raised, "state")?, "pending");
    assert!(network.propose_contact(foreign, other.to_npub()?.as_str(), None).is_err());
    assert!(network.propose_contact(rig.scope, identity.npub(), None).is_err(), "never yourself");
    Ok(())
}
