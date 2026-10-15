// SPDX-License-Identifier: AGPL-3.0-or-later
//! Broker admission and settlement remain in the broker and its Aura transaction.

use super::HostLedger;
use broker::{
    intake::ModelSlot,
    keystore::KeyInbox,
    service::{Broker, ReserveRequest},
};
use canon::{
    authority::AuthorityTxn,
    codes,
    fd3_payloads::{ModelCall, ModelReply},
    frame::FrameId,
    ids::{OperationId, RequestId, ReservationId},
    session::{ModelCancel, ModelEnd, ModelStart, ModelStarted},
    Result,
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use supervisor::{
    ingress::PrincipalScope,
    services::{BrokerEvent, BrokerService, ServiceFuture, StreamHandle},
};

type PendingCall = tokio::task::JoinHandle<Result<ModelReply>>;
struct Calls {
    closed: bool,
    draining: bool,
    disconnected: bool,
    drain_result: Option<Result<()>>,
    recovery: Result<()>,
    scope: Option<PrincipalScope>,
    entries: BTreeMap<RequestId, PendingCall>,
}
pub struct BrokerAdapter {
    pub keys: Arc<KeyInbox>,
    pub slot: Arc<ModelSlot>,
    ledger: Arc<HostLedger>,
    calls: Arc<Mutex<Calls>>,
}
impl BrokerAdapter {
    pub fn new(ledger: Arc<HostLedger>, keys: Arc<KeyInbox>, slot: Arc<ModelSlot>) -> Self {
        Self {
            keys,
            slot,
            ledger,
            calls: Arc::new(Mutex::new(Calls {
                closed: true,
                draining: false,
                disconnected: false,
                drain_result: None,
                recovery: Err(codes::BROKER_SETTLE_PENDING),
                scope: None,
                entries: BTreeMap::new(),
            })),
        }
    }
    /// Crash recovery settles retained reservations; it never resends model input.
    pub fn recover(&self) -> Result<()> {
        let mut calls = self.calls.lock().map_err(|_| codes::BROKER_STATE)?;
        self.recover_calls(&mut calls)
    }
    fn recover_calls(&self, calls: &mut Calls) -> Result<()> {
        if calls.draining {
            return Err(codes::BROKER_BUSY);
        }
        calls.closed = true;
        let result = (|| {
            if !calls.entries.is_empty() {
                return Err(codes::BROKER_BUSY);
            }
            for _ in 0..1024 {
                let recovered = self.ledger.transition(|txn| {
                    let now = u64::try_from(txn.observation_context()?.at)
                        .map_err(|_| codes::BROKER_STATE)?;
                    Broker::recover_pending(txn, now)
                })?;
                if recovered.is_empty() {
                    return Ok(());
                }
            }
            Err(codes::BROKER_SETTLE_PENDING)
        })();
        calls.recovery = result;
        if result.is_ok() {
            calls.closed = false;
            calls.disconnected = false;
            calls.drain_result = None;
            calls.scope = None;
        }
        result
    }
    pub fn recovery_state(&self) -> Result<()> {
        self.calls.lock().map_err(|_| codes::BROKER_STATE)?.recovery
    }
    /// Retry only recovery of retained reservations, never a provider request.
    fn ensure_recovered(&self) -> Result<()> {
        let mut calls = self.calls.lock().map_err(|_| codes::BROKER_STATE)?;
        if calls.disconnected || calls.draining {
            return Err(codes::BROKER_BUSY);
        }
        if calls.recovery.is_err() {
            self.recover_calls(&mut calls)?;
        }
        Ok(())
    }
}
impl BrokerService for BrokerAdapter {
    fn call<'a>(
        &'a self,
        scope: PrincipalScope,
        _: &'a FrameId,
        call: ModelCall,
    ) -> ServiceFuture<'a, ModelReply> {
        Box::pin(async move {
            self.ensure_recovered()?;
            let request_id = RequestId::from_bytes(random()?);
            let receiver = {
                let mut calls = self.calls.lock().map_err(|_| codes::BROKER_STATE)?;
                calls.recovery?;
                if calls.scope.is_some_and(|previous| previous != scope) {
                    return Err(codes::AUMLOK_BINDING_REQUIRED);
                }
                if calls.closed || calls.entries.len() >= 64 {
                    return Err(codes::BROKER_BUSY);
                }
                let reservation = self.ledger.transition(|txn| {
                    HostLedger::require_scope(txn, scope)?;
                    let now = u64::try_from(txn.observation_context()?.at)
                        .map_err(|_| codes::BROKER_STATE)?;
                    let request = ReserveRequest {
                        request_id,
                        reservation_id: ReservationId::from_bytes(random()?),
                        operation_id: OperationId::from_bytes(random()?),
                        prompt_token_bound: broker::provider::prompt_token_bound(&call)?,
                        key_generation: self.keys.state()?.generation,
                        now_ms: now,
                        call,
                    };
                    Broker::reserve(txn, request, &self.slot)
                })?;
                let host = Arc::clone(&self.ledger);
                let keys = Arc::clone(&self.keys);
                let slot = Arc::clone(&self.slot);
                let calls_state = Arc::clone(&self.calls);
                let (sender, receiver) = tokio::sync::oneshot::channel();
                let task = tokio::spawn(async move {
                    let result = match Broker::call(reservation, &keys, &slot).await {
                        Ok(pending) => {
                            host.transition(|txn| Broker::settle_completion(txn, pending))
                        }
                        Err(code) => Err(code),
                    };
                    {
                        let mut calls = calls_state.lock().map_err(|_| codes::BROKER_STATE)?;
                        if result.is_err() {
                            calls.closed = true;
                            calls.recovery = Err(codes::BROKER_SETTLE_PENDING);
                        }
                        // A dropped reply future must not retain a finished call forever.
                        calls.entries.remove(&request_id);
                    }
                    let _ = sender.send(result.clone());
                    result
                });
                calls.scope = Some(scope);
                calls.entries.insert(request_id, task);
                receiver
            };
            let result = receiver.await.map_err(|_| codes::BROKER_SETTLE_PENDING)?;
            self.calls
                .lock()
                .map_err(|_| codes::BROKER_STATE)?
                .entries
                .remove(&request_id);
            result
        })
    }
    fn streaming_ready(&self) -> Result<()> {
        Err(codes::BROKER_STREAMING_UNAVAILABLE)
    }
    fn start(&self, _: PrincipalScope, _: ModelStart) -> ServiceFuture<'_, ModelStarted> {
        Box::pin(async { Err(codes::BROKER_STREAMING_UNAVAILABLE) })
    }
    fn next(&self, _: PrincipalScope, _: StreamHandle) -> ServiceFuture<'_, BrokerEvent> {
        Box::pin(async { Err(codes::BROKER_STREAMING_UNAVAILABLE) })
    }
    fn poll(&self, _: PrincipalScope, _: StreamHandle) -> ServiceFuture<'_, Option<BrokerEvent>> {
        Box::pin(async { Err(codes::BROKER_STREAMING_UNAVAILABLE) })
    }
    fn delivered(&self, _: PrincipalScope, _: StreamHandle, _: u64) -> ServiceFuture<'_, ()> {
        Box::pin(async { Err(codes::BROKER_STREAMING_UNAVAILABLE) })
    }
    fn cancel(&self, _: PrincipalScope, _: ModelCancel) -> ServiceFuture<'_, ModelEnd> {
        Box::pin(async { Err(codes::BROKER_STREAMING_UNAVAILABLE) })
    }
    fn disconnect(&self, scope: PrincipalScope) -> ServiceFuture<'_, ()> {
        Box::pin(async move {
            let tasks = {
                let mut state = self.calls.lock().map_err(|_| codes::BROKER_STATE)?;
                if state.scope.is_some_and(|current| current != scope) {
                    return Err(codes::AUMLOK_BINDING_REQUIRED);
                }
                if state.draining {
                    return Err(codes::BROKER_BUSY);
                }
                if let Some(result) = state.drain_result {
                    return result;
                }
                state.closed = true;
                state.disconnected = true;
                state.draining = true;
                std::mem::take(&mut state.entries)
            };
            let calls = Arc::clone(&self.calls);
            let (send, receive) = tokio::sync::oneshot::channel();
            // Cleanup outlives a disconnected router dropping this reply future.
            tokio::spawn(async move {
                let mut failure = None;
                for (_, task) in tasks {
                    match task.await {
                        Ok(Ok(_)) => (),
                        Ok(Err(error)) => {
                            failure.get_or_insert(error);
                        }
                        Err(_) => {
                            failure.get_or_insert(codes::BROKER_SETTLE_PENDING);
                        }
                    }
                }
                let result = match calls.lock() {
                    Ok(mut state) => {
                        state.draining = false;
                        let result = failure.map_or(state.recovery, Err);
                        if result.is_err() {
                            state.recovery = Err(codes::BROKER_SETTLE_PENDING);
                        }
                        state.drain_result = Some(result);
                        result
                    }
                    Err(_) => Err(codes::BROKER_STATE),
                };
                let _ = send.send(result);
            });
            receive.await.map_err(|_| codes::BROKER_SETTLE_PENDING)?
        })
    }
}
fn random() -> Result<[u8; 16]> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).map_err(|_| codes::BROKER_STATE)?;
    Ok(bytes)
}

impl BrokerAdapter {
    /// Return only observed slot/key state and a ledger-proven empty grant/receipt history.
    pub fn model_report(&self, scope: PrincipalScope) -> Result<canon::json::Value> {
        self.ledger.scoped(scope, |txn| {
            if !txn.broker_history_empty()? {
                return Err(canon::Refusal {
                    organ: "supervisor",
                    reason: "model-settings-unavailable",
                });
            }
            crate::faces::model_settings::project(
                &self.slot,
                self.keys.state()?.present,
                None,
                None,
            )
        })
    }
}
