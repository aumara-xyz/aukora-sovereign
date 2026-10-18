// SPDX-License-Identifier: AGPL-3.0-or-later
//! The owner's slider controls contacts without granting any engine capability.

use super::{
    tests::{assertion_bytes, rig, Rig},
    *,
};
use crate::faces::{live_network::LiveNetwork, network::NetworkRead};
use canon::{
    alg::AlgorithmId,
    authority::{OwnerAssertion, OwnerOperation},
    ids::NodeId,
};
use gate::{
    recovery::NoInjection,
    target::{TargetId, TargetStore},
};
use laya::SliderSetting;
use std::{fs::File, sync::Arc};

fn contact(seed: u8) -> Result<OwnerAction> {
    Ok(OwnerAction::Contact(ContactChange::Add(
        messaging::ContactDraft {
            key: nostr::SecretKey::import(zeroize::Zeroizing::new([seed; 32]))?.public_key()?,
            label: "Owner contact".into(),
            pairing: None,
        },
    )))
}

fn contact_key(action: &OwnerAction) -> nostr::PublicKey {
    let OwnerAction::Contact(ContactChange::Add(draft)) = action else {
        unreachable!()
    };
    draft.key
}

fn select(rig: &mut Rig, setting: SliderSetting) -> Result<()> {
    let mut policy = laya::slider::starter()?;
    policy.setting = setting;
    if setting == SliderSetting::AskRisky {
        return Ok(());
    }
    if setting == SliderSetting::AskEverything {
        return rig.ledger.scoped(rig.scope, |txn| {
            let state = crate::adapters::slider::current_state(txn)?;
            crate::adapters::slider::tighten(txn, &state, setting)
        });
    }
    // A looser test policy is installed only by a real passkey assertion.
    let gate = rig.gate.as_mut().unwrap();
    let target = TargetId::new(laya::slider::POLICY_TARGET.into())?;
    let base = gate.target_store().observe(&target)?.digest;
    let proposed = rig.ledger.scoped(rig.scope, |txn| {
        gate.propose(txn, policy.proposal(base)?, &mut NoInjection)
    })?;
    let reviewed = rig.ledger.scoped(rig.scope, |txn| {
        gate.review(txn, proposed.id, OwnerOperation::Apply, &mut NoInjection)
    })?;
    let (client_data_json, authenticator_data, bytes) =
        assertion_bytes(&rig.owner, *reviewed.passkey_challenge.as_bytes(), 1);
    let assertion = OwnerAssertion {
        v: 1,
        algorithm: AlgorithmId::Ed25519,
        credential_id: rig.credential.clone(),
        authenticator_data,
        client_data_json,
        signature: Signature {
            v: 1,
            algorithm: AlgorithmId::Ed25519,
            bytes,
        },
    };
    let consumed = rig.ledger.scoped(rig.scope, |txn| {
        gate.consume_apply(txn, proposed.id, assertion, &mut NoInjection)
    })?;
    rig.ledger.scoped(rig.scope, |txn| {
        gate.effect_once(txn, consumed, &mut NoInjection)
    })?;
    Ok(())
}

fn network(rig: &mut Rig) -> Result<LiveNetwork> {
    let identity = Arc::new(crate::nostr_identity::NodeIdentity::open(
        &File::open(&rig.directory).unwrap(),
    )?);
    let store = messaging::Messaging::open(
        &rig.directory.join("messaging"),
        NodeId::from_bytes([86; 16]),
    )?;
    let config = rig.gate.as_ref().unwrap().config().clone();
    drop(rig.gate.take());
    let gate = Arc::new(crate::adapters::GateAdapter::start(
        rig.directory.join("aura.sqlite3"),
        File::open(rig.directory.join("targets")).unwrap(),
        config,
        Arc::clone(&rig.ledger),
    )?);
    Ok(LiveNetwork::new(
        Arc::clone(&rig.ledger),
        store,
        identity,
        gate,
    ))
}

fn counts(rig: &Rig) -> Result<(usize, usize, Vec<Digest32>)> {
    rig.ledger.transaction(|txn| {
        let mut proposals = 0;
        let mut consumes = 0;
        let mut owner_contacts = Vec::new();
        for sequence in 1..txn.current_version()?.sequence {
            let row = txn.floor_record_at_sequence(sequence)?.unwrap();
            proposals += usize::from(row.kind == Kind::GatePropose);
            consumes += usize::from(row.kind == Kind::GateConsume);
            let body = aura::record::AuthorityBodyV1::parse(&row.body)?.payload;
            if row.kind == Kind::BootFacts
                && row.phase == Phase::Fact
                && row.actor == "owner"
                && string(&body, "schema").ok() == Some(messaging::OWNER_CONTACT_SCHEMA)
            {
                owner_contacts.push(row.hash);
            }
        }
        Ok((proposals, consumes, owner_contacts))
    })
}

#[test]
fn every_other_slider_level_applies_owner_contacts_with_aura_and_no_card() -> Result<()> {
    for setting in [
        SliderSetting::AskRisky,
        SliderSetting::WithinTodayLimits,
        SliderSetting::Trusted,
    ] {
        let mut rig = rig()?;
        select(&mut rig, setting)?;
        let action = contact(92)?;
        let key = contact_key(&action);
        // A host adapter without the owner shell guard cannot take the direct path.
        let before = counts(&rig)?;
        assert_eq!(
            rig.ledger
                .messaging(rig.scope, false, |txn| txn.apply_owner_contact(&action))
                .unwrap_err()
                .reason,
            "owner-shell-session-required"
        );
        assert_eq!(counts(&rig)?, before);
        let network = network(&mut rig)?;
        let reply =
            network.propose_contact(rig.scope, key.to_npub()?.as_str(), Some("Owner contact"))?;
        assert_eq!(string(&reply, "state")?, "applied");
        assert!(reply.get("proposal_id").is_none());
        let after = counts(&rig)?;
        assert_eq!((after.0, after.1, after.2.len()), (before.0, before.1, 1));
        let added = network.contacts(rig.scope, None, 10)?.items.remove(0);
        assert_eq!(added.key(), key);
        assert_eq!(added.proposal(), None);
        assert_eq!(added.consumed_card(), None);
        assert_eq!(added.authorization_receipt(), after.2[0]);
        // The new authorization admits normal owner sends and survives a cache reopen.
        network.send(rig.scope, key.to_npub()?.as_str(), "A direct owner send")?;
        let reopened = messaging::Messaging::open(
            &rig.directory.join("messaging"),
            NodeId::from_bytes([86; 16]),
        )?;
        assert_eq!(reopened.contacts(None, 10)?, vec![added]);
        drop(reopened);
        let removed = network.remove_contact(rig.scope, key.to_npub()?.as_str())?;
        assert_eq!(string(&removed, "state")?, "applied");
        assert!(network.contacts(rig.scope, None, 10)?.items.is_empty());
        assert!(network
            .send(rig.scope, key.to_npub()?.as_str(), "No longer a contact")
            .is_err());
        let after = counts(&rig)?;
        assert_eq!((after.0, after.1, after.2.len()), (before.0, before.1, 2));
    }
    Ok(())
}

#[test]
fn ask_everything_raises_the_existing_contact_card_for_add_and_remove() -> Result<()> {
    for adding in [true, false] {
        let mut rig = rig()?;
        let existing = contact(93)?;
        rig.approve(&existing, 1)?;
        select(&mut rig, SliderSetting::AskEverything)?;
        let other = contact_key(&contact(94)?);
        let before = counts(&rig)?;
        let network = network(&mut rig)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _entered = runtime.enter();
        let reply = if adding {
            network.propose_contact(
                rig.scope,
                other.to_npub()?.as_str(),
                Some("Another contact"),
            )?
        } else {
            network.remove_contact(rig.scope, contact_key(&existing).to_npub()?.as_str())?
        };
        assert_eq!(string(&reply, "state")?, "pending");
        ProposalId::from_hex(string(&reply, "proposal_id")?)?;
        let contacts = network.contacts(rig.scope, None, 10)?.items;
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].key(), contact_key(&existing));
        let after = counts(&rig)?;
        assert_eq!(
            (after.0, after.1, after.2.len()),
            (before.0 + 1, before.1, 0)
        );
    }
    Ok(())
}

#[test]
fn predecessor_contact_cache_migrates_and_removed_contacts_cannot_return_on_restart() -> Result<()>
{
    let mut rig = rig()?;
    let action = contact(95)?;
    let key = contact_key(&action);
    rig.approve(&action, 1)?;
    let directory = rig.directory.join("messaging");
    let path = directory.join("messaging.sqlite3");
    let mut store = messaging::Messaging::open(&directory, NodeId::from_bytes([86; 16]))?;
    let original = rig
        .ledger
        .messaging(rig.scope, false, |txn| store.synchronize_contact(txn, key))?
        .unwrap();
    drop(store);
    // Reproduce a predecessor's cache: the card contact and v1 node pin remain,
    // while the independent owner-session extension has not been installed.
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch(
        "DROP TABLE messaging_owner_contacts; DROP TABLE messaging_owner_contacts_meta;",
    )
    .unwrap();
    drop(db);
    let network = network(&mut rig)?;
    assert_eq!(
        network.contacts(rig.scope, None, 10)?.items,
        vec![original.clone()]
    );
    assert_eq!(
        string(
            &network.propose_contact(rig.scope, key.to_npub()?.as_str(), Some("Owner contact"))?,
            "state"
        )?,
        "applied"
    );
    assert_eq!(
        string(
            &network.remove_contact(rig.scope, key.to_npub()?.as_str())?,
            "state"
        )?,
        "applied"
    );
    drop(network);
    // A stale predecessor card cache is not authority after the durable removal.
    let db = rusqlite::Connection::open(&path).unwrap();
    let version: i64 = db
        .query_row(
            "SELECT schema_version FROM messaging_owner_contacts_meta",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(version, 1);
    let authority = original.authority();
    db.execute("INSERT INTO messaging_contacts(key,action,epoch,sequence,previous_hash,proposal,consumed_card)
        VALUES(?1,?2,?3,?4,?5,?6,?7)", rusqlite::params![
        key.as_bytes().as_slice(), action.canonical_bytes()?, authority.epoch as i64,
        authority.sequence as i64, authority.previous_hash.map(|hash| hash.as_bytes().to_vec()),
        original.proposal().unwrap().as_bytes().as_slice(), original.consumed_card().unwrap().as_bytes().as_slice(),
    ]).unwrap();
    drop(db);
    let mut reopened = messaging::Messaging::open(&directory, NodeId::from_bytes([86; 16]))?;
    assert_eq!(reopened.contacts(None, 10)?, vec![original]);
    assert!(rig
        .ledger
        .messaging(rig.scope, false, |txn| reopened
            .synchronize_contact(txn, key))?
        .is_none());
    assert!(reopened.contacts(None, 10)?.is_empty());
    drop(reopened);
    // Unknown future extension versions fail closed rather than being rewritten.
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch("DROP TABLE messaging_owner_contacts_meta;
        CREATE TABLE messaging_owner_contacts_meta(singleton INTEGER PRIMARY KEY, schema_version INTEGER NOT NULL);
        INSERT INTO messaging_owner_contacts_meta VALUES(1,2);").unwrap();
    drop(db);
    let Err(error) = messaging::Messaging::open(&directory, NodeId::from_bytes([86; 16])) else {
        panic!("a future owner-contact cache schema must be refused");
    };
    assert_eq!(error.reason, "store-schema");
    Ok(())
}
