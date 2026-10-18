// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use crate::adapters::messaging::tests::{assertion_bytes, rig, Rig};
use canon::{alg::Signature, authority::OwnerAssertion};

fn adapter(rig: &mut Rig) -> GateAdapter {
    drop(rig.gate.take());
    GateAdapter::start(
        rig.directory.clone(),
        File::open(rig.directory.join("targets")).unwrap(),
        GateConfig {
            node: canon::ids::NodeId::from_bytes([86; 16]),
            targets: vec![
                TargetSpec {
                    id: TargetId::new(messaging::CONTACT_TARGET.into()).unwrap(),
                    class: gate::target::TargetClass::Content,
                    risk: gate::RiskTier::Critical,
                    max_bytes: 8192,
                },
                SliderPolicy::target_spec().unwrap(),
            ],
            proposal_lifetime_ms: 300_000,
            ceremony_lifetime_ms: 300_000,
        },
        rig.ledger.clone(),
    )
    .unwrap()
}

fn assertion(rig: &Rig, review: &OwnerReview, counter: u32) -> OwnerAssertion {
    let challenge = gate::card::passkey_challenge(&review.authorization).unwrap();
    let (client_data_json, authenticator_data, bytes) =
        assertion_bytes(&rig.owner, *challenge.as_bytes(), counter);
    OwnerAssertion {
        v: 1,
        algorithm: AlgorithmId::Ed25519,
        credential_id: rig.credential.clone(),
        client_data_json,
        authenticator_data,
        signature: Signature {
            v: 1,
            algorithm: AlgorithmId::Ed25519,
            bytes,
        },
    }
}

fn pending(value: SliderChange) -> ProposalId {
    match value {
        SliderChange::Pending { proposal, .. } => proposal,
        _ => panic!("a loosening must remain pending"),
    }
}

#[test]
fn tightening_is_immediate_and_loosening_needs_the_owners_passkey() -> Result<()> {
    let mut rig = rig()?;
    let adapter = adapter(&mut rig);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    assert_eq!(
        runtime.block_on(adapter.slider_policy())?.setting,
        SliderSetting::AskRisky
    );
    assert_eq!(
        runtime.block_on(adapter.set_slider(rig.scope, SliderSetting::AskEverything))?,
        SliderChange::Applied(SliderSetting::AskEverything)
    );
    let proposal =
        pending(runtime.block_on(adapter.set_slider(rig.scope, SliderSetting::WithinTodayLimits))?);
    assert_eq!(
        runtime.block_on(adapter.slider_policy())?.setting,
        SliderSetting::AskEverything
    );
    let review = runtime.block_on(adapter.review(rig.scope, proposal, OwnerOperation::Apply))?;
    let valid = assertion(&rig, &review, 1);
    let mut invalid = valid.clone();
    invalid.signature.bytes[0] ^= 1;
    assert!(runtime
        .block_on(adapter.owner_assertion(rig.scope, proposal, OwnerOperation::Apply, invalid))
        .is_err());
    assert_eq!(
        runtime.block_on(adapter.slider_policy())?.setting,
        SliderSetting::AskEverything
    );
    assert_eq!(
        runtime
            .block_on(adapter.owner_assertion(rig.scope, proposal, OwnerOperation::Apply, valid))?
            .state,
        OutcomeState::Applied
    );
    let approved = runtime.block_on(adapter.slider_policy())?;
    assert_eq!(approved.setting, SliderSetting::WithinTodayLimits);
    assert_eq!(approved.classes, laya::slider::starter()?.classes);
    runtime.block_on(adapter.set_slider(rig.scope, SliderSetting::AskRisky))?;
    assert_eq!(
        runtime.block_on(adapter.slider_policy())?.setting,
        SliderSetting::AskRisky
    );
    // Reopening Aura derives the setting again; the result is not an adapter cache.
    let mut reopened = aura::Ledger::open(&rig.directory.join("aura.sqlite3"))?;
    let mut txn = reopened.begin(rig.ledger.services())?;
    assert_eq!(
        super::super::super::slider::current_policy(&mut txn)?.setting,
        SliderSetting::AskRisky
    );
    Ok(())
}

#[test]
fn tightening_declines_stale_cards_and_same_bytes_still_need_a_fresh_passkey() -> Result<()> {
    let mut rig = rig()?;
    let adapter = adapter(&mut rig);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let first = pending(runtime.block_on(adapter.set_slider(rig.scope, SliderSetting::Trusted))?);
    let review = runtime.block_on(adapter.review(rig.scope, first, OwnerOperation::Apply))?;
    let stale = assertion(&rig, &review, 1);
    runtime.block_on(adapter.set_slider(rig.scope, SliderSetting::AskEverything))?;
    assert!(runtime
        .block_on(adapter.owner_assertion(rig.scope, first, OwnerOperation::Apply, stale))
        .is_err());
    assert_eq!(
        runtime.block_on(adapter.slider_policy())?.setting,
        SliderSetting::AskEverything
    );
    let fresh = pending(runtime.block_on(adapter.set_slider(rig.scope, SliderSetting::Trusted))?);
    assert_ne!(first, fresh);
    let review = runtime.block_on(adapter.review(rig.scope, fresh, OwnerOperation::Apply))?;
    runtime.block_on(adapter.owner_assertion(
        rig.scope,
        fresh,
        OwnerOperation::Apply,
        assertion(&rig, &review, 1),
    ))?;
    let before = rig.ledger.transaction(|txn| txn.current_version())?;
    assert_eq!(
        runtime.block_on(adapter.set_slider(rig.scope, SliderSetting::Trusted))?,
        SliderChange::Applied(SliderSetting::Trusted)
    );
    assert_eq!(before, rig.ledger.transaction(|txn| txn.current_version())?);
    runtime.block_on(adapter.set_slider(rig.scope, SliderSetting::AskEverything))?;
    // The target still contains trusted. Returning to those exact bytes raises a
    // fresh card rather than treating the old passkey as current authority.
    let repeated =
        pending(runtime.block_on(adapter.set_slider(rig.scope, SliderSetting::Trusted))?);
    assert_ne!(repeated, fresh);
    assert_eq!(
        runtime.block_on(adapter.slider_policy())?.setting,
        SliderSetting::AskEverything
    );
    let review = runtime.block_on(adapter.review(rig.scope, repeated, OwnerOperation::Apply))?;
    runtime.block_on(adapter.owner_assertion(
        rig.scope,
        repeated,
        OwnerOperation::Apply,
        assertion(&rig, &review, 2),
    ))?;
    assert_eq!(
        runtime.block_on(adapter.slider_policy())?.setting,
        SliderSetting::Trusted
    );
    Ok(())
}

#[test]
fn importing_an_existing_policy_preserves_its_rules_and_cannot_reset_the_slider() -> Result<()> {
    let mut rig = rig()?;
    let mut installed = laya::slider::starter()?;
    installed.setting = SliderSetting::WithinTodayLimits;
    installed
        .classes
        .iter_mut()
        .find(|rule| rule.class == laya::CrossingClass::Net)
        .unwrap()
        .per_day = 7;
    rig.ledger.initialize_slider(installed.clone())?;
    let adapter = adapter(&mut rig);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    assert_eq!(runtime.block_on(adapter.slider_policy())?, installed);
    runtime.block_on(adapter.set_slider(rig.scope, SliderSetting::AskRisky))?;
    // A changed configuration at restart is not authority to loosen or replace
    // the policy that the owner now controls.
    rig.ledger.initialize_slider(laya::slider::starter()?)?;
    let current = runtime.block_on(adapter.slider_policy())?;
    assert_eq!(current.setting, SliderSetting::AskRisky);
    assert_eq!(current.classes, installed.classes);
    let proposal =
        pending(runtime.block_on(adapter.set_slider(rig.scope, SliderSetting::Trusted))?);
    let review = runtime.block_on(adapter.review(rig.scope, proposal, OwnerOperation::Apply))?;
    runtime.block_on(adapter.owner_assertion(
        rig.scope,
        proposal,
        OwnerOperation::Apply,
        assertion(&rig, &review, 1),
    ))?;
    let current = runtime.block_on(adapter.slider_policy())?;
    assert_eq!(current.setting, SliderSetting::Trusted);
    assert_eq!(current.classes, installed.classes);
    Ok(())
}

#[test]
fn an_explicit_slider_retry_after_decline_gets_a_fresh_card() -> Result<()> {
    for reinstating in [false, true] {
        let mut rig = rig()?;
        let adapter = adapter(&mut rig);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let mut counter = 1;
        if reinstating {
            let proposal =
                pending(runtime.block_on(adapter.set_slider(rig.scope, SliderSetting::Trusted))?);
            let review =
                runtime.block_on(adapter.review(rig.scope, proposal, OwnerOperation::Apply))?;
            runtime.block_on(adapter.owner_assertion(
                rig.scope,
                proposal,
                OwnerOperation::Apply,
                assertion(&rig, &review, counter),
            ))?;
            counter += 1;
            runtime.block_on(adapter.set_slider(rig.scope, SliderSetting::AskEverything))?;
        }
        let previous = runtime.block_on(adapter.slider_policy())?.setting;
        let first =
            pending(runtime.block_on(adapter.set_slider(rig.scope, SliderSetting::Trusted))?);
        runtime.block_on(adapter.decline(rig.scope, first))?;
        let second =
            pending(runtime.block_on(adapter.set_slider(rig.scope, SliderSetting::Trusted))?);
        assert_ne!(first, second);
        runtime.block_on(adapter.decline(rig.scope, second))?;
        let third =
            pending(runtime.block_on(adapter.set_slider(rig.scope, SliderSetting::Trusted))?);
        assert_ne!(second, third);
        assert_eq!(runtime.block_on(adapter.slider_policy())?.setting, previous);
        let review = runtime.block_on(adapter.review(rig.scope, third, OwnerOperation::Apply))?;
        assert_eq!(
            runtime
                .block_on(adapter.owner_assertion(
                    rig.scope,
                    third,
                    OwnerOperation::Apply,
                    assertion(&rig, &review, counter)
                ))?
                .state,
            OutcomeState::Applied
        );
        assert_eq!(
            runtime.block_on(adapter.slider_policy())?.setting,
            SliderSetting::Trusted
        );
    }
    Ok(())
}

#[test]
fn an_expired_slider_card_neither_blocks_tightening_nor_an_explicit_retry() -> Result<()> {
    use std::sync::atomic::{AtomicI64, Ordering};
    struct Clock(AtomicI64);
    impl aura::TrustedClock for Clock {
        fn now_ms(&self) -> Result<i64> {
            Ok(self.0.load(Ordering::SeqCst))
        }
    }
    let mut rig = rig()?;
    let clock = Arc::new(Clock(AtomicI64::new(rig.ledger.clock.now_ms()?)));
    rig.ledger = Arc::new(HostLedger::open(
        &rig.directory.join("aura.sqlite3"),
        rig.ledger.signer.clone(),
        clock.clone(),
    )?);
    let adapter = adapter(&mut rig);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let expired = pending(runtime.block_on(adapter.set_slider(rig.scope, SliderSetting::Trusted))?);
    clock.0.fetch_add(300_001, Ordering::SeqCst);
    let fresh = pending(runtime.block_on(adapter.set_slider(rig.scope, SliderSetting::Trusted))?);
    assert_ne!(expired, fresh);
    assert_eq!(
        runtime.block_on(adapter.slider_policy())?.setting,
        SliderSetting::AskRisky
    );
    let review = runtime.block_on(adapter.review(rig.scope, fresh, OwnerOperation::Apply))?;
    runtime.block_on(adapter.owner_assertion(
        rig.scope,
        fresh,
        OwnerOperation::Apply,
        assertion(&rig, &review, 1),
    ))?;
    assert_eq!(
        runtime.block_on(adapter.slider_policy())?.setting,
        SliderSetting::Trusted
    );
    runtime.block_on(adapter.set_slider(rig.scope, SliderSetting::AskRisky))?;
    let _expired =
        pending(runtime.block_on(adapter.set_slider(rig.scope, SliderSetting::Trusted))?);
    clock.0.fetch_add(300_001, Ordering::SeqCst);
    assert_eq!(
        runtime.block_on(adapter.set_slider(rig.scope, SliderSetting::AskEverything))?,
        SliderChange::Applied(SliderSetting::AskEverything)
    );
    assert_eq!(
        runtime.block_on(adapter.slider_policy())?.setting,
        SliderSetting::AskEverything
    );
    Ok(())
}

#[test]
fn initial_policy_is_retained_before_owner_enrolment() -> Result<()> {
    let rig = rig()?;
    let fresh = HostLedger::open(
        &rig.directory.join("unbound.sqlite3"),
        rig.ledger.signer.clone(),
        rig.ledger.clock.clone(),
    )?;
    fresh.initialize_slider(laya::slider::starter()?)?;
    assert_eq!(fresh.transaction(super::super::super::slider::current_policy)?, laya::slider::starter()?);
    Ok(())
}
