// Core protections added after the three review lenses.
static FACT_CALL: AtomicUsize = AtomicUsize::new(0);
static FACT_CHANGE_AT: AtomicUsize = AtomicUsize::new(usize::MAX);
static FACT_TEST_LOCK: Mutex<()> = Mutex::new(());
fn review_facts(_old: Option<&[u8]>, _new: &[u8]) -> Result<Value> {
    let call = FACT_CALL.fetch_add(1, Ordering::SeqCst) + 1;
    Ok(json!({"from_to":"GATE FACT: reviewed release", "release_floor": if call>=FACT_CHANGE_AT.load(Ordering::SeqCst) {2} else {1}}))
}

#[test]
fn target_facts_are_rechecked_at_consume_final_guard_and_each_prewrite_guard() {
    let _lock = FACT_TEST_LOCK.lock().unwrap();
    for change_at in [3,4,5,6] {
        FACT_CALL.store(0,Ordering::SeqCst);
        FACT_CHANGE_AT.store(change_at,Ordering::SeqCst);
        let mut f=fixture();
        f.gate.targets.get_mut(TARGET).unwrap().review_facts=Some(review_facts);
        let p=f.gate.propose(proposal_request(NEW)).unwrap();
        let r=f.gate.review(&p.id).unwrap();
        let card:Value=serde_json::from_slice(&r.card_bytes).unwrap();
        assert_eq!(card["target_review"]["release_floor"],1);
        assert_eq!(card["from_to"]["summary"],"GATE FACT: reviewed release");
        if change_at<=4 {
            let error=f.gate.consume(consume_request(&r,Decision::Allow,0)).unwrap_err();
            assert_eq!(error.to_string(),if change_at==3 {"gate:display-mismatch"} else {"gate:review-facts-changed"},"missing consume facts guard {change_at}");
            assert_eq!(f.gate.state(&p.id).unwrap(),Some(State::Pending));
        } else {
            f.gate.consume(consume_request(&r,Decision::Allow,0)).unwrap();
            assert!(f.gate.apply(&p.id).is_err(),"missing prewrite facts guard {change_at}");
            assert_eq!(f.gate.state(&p.id).unwrap(),Some(State::Failed));
        }
        assert_eq!(f.store.write_count(),0);
        assert_eq!(f.store.read(TARGET).unwrap().unwrap(),BASE);
    }
}

#[test]
fn unavailable_target_facts_refuse_propose_and_review_before_ceremony() {
    let mut f=fixture();
    let p=f.gate.propose(proposal_request(NEW)).unwrap();
    f.gate.targets.get_mut(TARGET).unwrap().review_facts=Some(|_,_|Err(Error::Refused("gate:floor-unavailable")));
    assert!(f.gate.review(&p.id).is_err());
    assert_eq!(f.gate.db.query_row("SELECT count(*) FROM gate_reviews",[],|r|r.get::<_,i64>(0)).unwrap(),0);
    f.gate.reject(&p.id).unwrap();
    assert!(f.gate.propose(proposal_request(OTHER)).is_err());
    assert_eq!(f.gate.db.query_row("SELECT count(*) FROM gate_proposals",[],|r|r.get::<_,i64>(0)).unwrap(),1);
}

#[test]
fn null_floor_cannot_erase_actual_applied_history_when_target_is_deleted() {
    let mut f=fixture();
    let p=f.gate.propose(proposal_request(NEW)).unwrap();
    let r=f.gate.review(&p.id).unwrap();
    f.gate.consume(consume_request(&r,Decision::Allow,0)).unwrap();
    f.gate.apply(&p.id).unwrap();
    f.store.files.lock().unwrap().remove(TARGET);
    f.gate.targets.get_mut(TARGET).unwrap().review_facts=Some(|_,_|Ok(json!({"from_to":"GATE FACT: first release","release_floor":null})));
    let mut req=proposal_request(OTHER); req.base_sha256="absent".into();
    assert!(matches!(f.gate.propose(req),Err(Error::Refused("gate:review-floor-absent"))));
    assert_eq!(f.store.write_count(),1);
}

#[test]
fn guest_and_owner_handles_route_exact_bytes_and_finish_consumed_spend() {
    let mut f=fixture();
    assert_eq!(f.gate.guest().read(TARGET).unwrap().unwrap(),BASE);
    assert!(f.gate.guest().read("plugins/other/secret.md").is_err());
    let p=f.gate.guest().propose(proposal_request(NEW)).unwrap();
    assert_eq!(f.gate.guest().state(&p.id).unwrap(),Some(State::Pending));
    let r=f.gate.owner().review(&p.id).unwrap();
    assert_eq!(f.gate.owner().consume(consume_request(&r,Decision::Allow,0)).unwrap(),State::Applied);
    assert_eq!(f.store.write_count(),1);
    assert_eq!(f.gate.guest().read(TARGET).unwrap().unwrap(),NEW);
    assert!(f.gate.owner().consume(consume_request(&r,Decision::Allow,0)).is_err());
    assert_eq!(f.store.write_count(),1);
}

#[test]
fn production_fs_store_crash_suite_uses_exact_replacement_and_checks_receipt_drift() {
    let directory=tempfile::tempdir().unwrap();
    let root=directory.path().canonicalize().unwrap();
    let store=crate::fs_store::FsStore::new(&root).unwrap();
    store.write(TARGET,BASE,"abcd").unwrap();
    let db=Connection::open(root.join("production.db")).unwrap();
    initialize_test_ledger(&db);
    let clock=TestClock::new(); let proof=TestProof::new(&clock);
    let mut gate=Gate::open(db,Config{limits:permissive_limits(),..config()},vec![target_spec()],store,TestLedger::default(),proof,clock.clone()).unwrap();
    let p=gate.guest().propose(proposal_request(NEW)).unwrap();
    let r=gate.owner().review(&p.id).unwrap();
    assert_eq!(gate.owner().consume(consume_request(&r,Decision::Allow,0)).unwrap(),State::Applied);
    assert_eq!(gate.guest().read(TARGET).unwrap().unwrap(),NEW);
    drop(gate);
    // A process spawned by a parallel test may briefly hold a copy of the lock descriptor
    // until its exec closes it; the reopen waits that window out, bounded.
    let mut attempts=0;
    let gate=loop {
        let store=crate::fs_store::FsStore::new(&root).unwrap();
        let db=Connection::open(root.join("production.db")).unwrap();
        match Gate::open(db,Config{limits:permissive_limits(),..config()},vec![target_spec()],store,TestLedger::default(),TestProof::new(&clock),clock.clone()) {
            Err(Error::Refused("gate:writer-locked")) if attempts<100 => { attempts+=1; std::thread::sleep(std::time::Duration::from_millis(20)); }
            other=>break other.unwrap(),
        }
    };
    assert_eq!(gate.state(&p.id).unwrap(),Some(State::Applied));
}

#[test]
fn per_target_operator_ttl_controls_proposal_expiry_up_to_twenty_four_hours() {
    let mut f=review_regressions::operator_fixture(permissive_limits());
    let name="plugins/test/approval.json";
    f.gate.targets.get_mut(name).unwrap().ttl_ms=Some(86_400_000);
    let req=review_regressions::operator_request(&f,b"release");
    let p=f.gate.owner().raise(req).unwrap();
    assert_eq!(p.expires_at,START+86_400_000);
    f.clock.set(START+300_001);
    assert!(f.gate.owner().review(&p.id).is_ok());
    f.clock.set(p.expires_at);
    assert!(f.gate.owner().review(&p.id).is_err());
    assert_eq!(f.gate.state(&p.id).unwrap(),Some(State::Expired));
}

#[test]
fn guest_read_refuses_oversized_current_bytes() {
    let mut f=fixture();
    f.store.set(&vec![b'x';257]);
    assert!(f.gate.guest().read(TARGET).is_err());
}

#[test]
fn prior_applied_receipt_drift_remains_fenced_and_reconcilable_after_a_later_incomplete_write() {
    let mut f=fixture();
    let p=f.gate.propose(proposal_request(NEW)).unwrap();
    let r=f.gate.review(&p.id).unwrap();
    f.gate.consume(consume_request(&r,Decision::Allow,0)).unwrap();
    f.gate.apply(&p.id).unwrap();
    let mut req=proposal_request(OTHER); req.base_sha256=sha256(NEW);
    let p2=f.gate.propose(req).unwrap();
    let r2=f.gate.review(&p2.id).unwrap();
    f.gate.consume(consume_request(&r2,Decision::Allow,0)).unwrap();
    f.gate.db.execute("UPDATE gate_proposals SET write_claimed=1 WHERE id=?",[&p2.id]).unwrap();
    f.store.set(OTHER);
    let mut g=reopen(&mut f);
    assert_eq!(g.state(&p2.id).unwrap(),Some(State::Incomplete));
    let drift:Value=serde_json::from_str(&g.db.query_row("SELECT body FROM aura WHERE op=? AND kind='gate.recover'",[&p.id],|r|r.get::<_,String>(0)).unwrap()).unwrap();
    assert_eq!(drift["blocked_by"],p2.id);
    let auth=g.reconcile_authorization(&p2.id).unwrap();
    g.reconcile(&p2.id,&TestProof::sign(&auth,0)).unwrap();
    drop(g);
    let mut g=reopen(&mut f);
    let mut req=proposal_request(BASE);req.base_sha256=sha256(OTHER);
    assert!(g.propose(req).is_ok());
    assert_eq!(f.store.write_count(),1);
}

#[derive(Clone)]
struct ReadAdvancesClock {
    inner:MemoryStore,
    clock:TestClock,
    expire_at:Arc<AtomicI64>,
}
impl TargetStore for ReadAdvancesClock {
    fn read(&self,target:&str)->Result<Option<Vec<u8>>> {
        let at=self.expire_at.swap(0,Ordering::SeqCst);
        if at!=0 {self.clock.set(at);}
        self.inner.read(target)
    }
    fn write(&self,target:&str,bytes:&[u8],id:&str)->Result<()> {self.inner.write(target,bytes,id)}
}
#[test]
fn expiry_during_prewrite_callbacks_fails_without_a_write() {
    let directory=tempfile::tempdir().unwrap();
    let db=Connection::open(directory.path().join("clock.db")).unwrap();
    initialize_test_ledger(&db);
    let clock=TestClock::new();let memory=MemoryStore::new();
    let store=ReadAdvancesClock{inner:memory.clone(),clock:clock.clone(),expire_at:Arc::new(AtomicI64::new(0))};
    let mut gate=Gate::open(db,Config{limits:permissive_limits(),..config()},vec![target_spec()],store.clone(),TestLedger::default(),TestProof::new(&clock),clock).unwrap();
    let p=gate.propose(proposal_request(NEW)).unwrap();
    let r=gate.review(&p.id).unwrap();
    gate.consume(consume_request(&r,Decision::Allow,0)).unwrap();
    store.expire_at.store(r.expires_at,Ordering::SeqCst);
    assert!(matches!(gate.apply(&p.id),Err(Error::Refused("gate:apply-expired"))));
    assert_eq!(gate.state(&p.id).unwrap(),Some(State::Failed));
    assert_eq!(memory.write_count(),0);
    assert_eq!(memory.read(TARGET).unwrap().unwrap(),BASE);
}

static PREWRITE_CALLBACK_STORE:Mutex<Option<MemoryStore>>=Mutex::new(None);
static PREWRITE_CALLBACK_CALL:AtomicUsize=AtomicUsize::new(0);
fn facts_change_target_before_write(_old:Option<&[u8]>,_new:&[u8])->Result<Value> {
    if PREWRITE_CALLBACK_CALL.fetch_add(1,Ordering::SeqCst)+1==6 {
        PREWRITE_CALLBACK_STORE.lock().unwrap().as_ref().unwrap().set(OTHER);
    }
    Ok(json!({"from_to":"GATE FACT: stable facts","release_floor":1}))
}
#[test]
fn target_changed_by_final_review_facts_callback_is_never_overwritten() {
    let mut f=fixture();
    PREWRITE_CALLBACK_CALL.store(0,Ordering::SeqCst);
    *PREWRITE_CALLBACK_STORE.lock().unwrap()=Some(f.store.clone());
    f.gate.targets.get_mut(TARGET).unwrap().review_facts=Some(facts_change_target_before_write);
    let p=f.gate.propose(proposal_request(NEW)).unwrap();
    let r=f.gate.review(&p.id).unwrap();
    f.gate.consume(consume_request(&r,Decision::Allow,0)).unwrap();
    assert!(matches!(f.gate.apply(&p.id),Err(Error::Refused("gate:stale-after-spend"))));
    assert_eq!(f.gate.state(&p.id).unwrap(),Some(State::Failed));
    assert_eq!(f.store.read(TARGET).unwrap().unwrap(),OTHER);
    assert_eq!(f.store.write_count(),0);
    *PREWRITE_CALLBACK_STORE.lock().unwrap()=None;
}

#[test]
fn commit_error_with_a_durably_retained_spend_reconciles_instead_of_reporting_unaccepted() {
    let mut f=fixture();
    let p=f.gate.propose(proposal_request(NEW)).unwrap();
    let r=f.gate.review(&p.id).unwrap();
    CONSUME_COMMIT_ERROR.with(|flag|flag.set(true));
    assert!(f.gate.consume(consume_request(&r,Decision::Allow,1)).is_err());
    assert_eq!(f.gate.state(&p.id).unwrap(),Some(State::Failed));
    assert_eq!(f.gate.db.query_row("SELECT count(*) FROM gate_consumptions WHERE proposal_id=?",[&p.id],|r|r.get::<_,i64>(0)).unwrap(),1);
    assert_eq!(count_kind(&f.gate.db,&p.id,"gate.consume"),1);
    assert_eq!(count_kind(&f.gate.db,&p.id,"gate.refuse"),0);
    assert_eq!(terminal_rows(&f.gate.db,&p.id),1);
    assert_eq!(f.store.write_count(),0);
    assert!(f.gate.apply(&p.id).is_err());
    assert_eq!(f.store.write_count(),0);
}

#[test]
fn receipt_commit_error_after_durable_commit_preserves_original_error_and_never_rewrites() {
    let mut f=fixture();
    let p=f.gate.propose(proposal_request(NEW)).unwrap();
    let r=f.gate.review(&p.id).unwrap();
    f.gate.consume(consume_request(&r,Decision::Allow,0)).unwrap();
    RECEIPT_COMMIT_ERROR.with(|flag|flag.set(true));
    assert!(matches!(f.gate.apply(&p.id),Err(Error::Database(rusqlite::Error::InvalidQuery))));
    assert_eq!(f.gate.state(&p.id).unwrap(),Some(State::Applied));
    assert!(f.gate.receipt(&p.id).unwrap().is_some());
    assert_eq!(terminal_rows(&f.gate.db,&p.id),1);
    assert_eq!(f.store.read(TARGET).unwrap().unwrap(),NEW);
    assert_eq!(f.store.write_count(),1);
    assert!(f.gate.apply(&p.id).is_err());
    assert_eq!(f.store.write_count(),1);
}

#[test]
fn a_duplicated_lock_descriptor_does_not_keep_a_closed_gate_locked() {
    // A process forked elsewhere holds a copy of the descriptor until its exec.
    let mut f = fixture();
    let copy = f.gate._writer_lock.0.try_clone().unwrap();
    release_fixture_gate(&mut f);
    let db = Connection::open(f.directory.path().join("gate.db")).unwrap();
    let reopened = Gate::open(db, f.cfg.clone(), vec![target_spec()], f.store.clone(), f.ledger.clone(), f.proof.clone(), f.clock.clone());
    assert!(reopened.is_ok(), "{:?}", reopened.err());
    drop(copy);
}
