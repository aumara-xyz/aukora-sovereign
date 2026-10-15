// SPDX-License-Identifier: AGPL-3.0-or-later
//! Native organ evidence is collected on its own cadence and never admits an action.

mod wire;

use crate::{
    adapters::{GateAdapter, HostLedger},
    config::NodeConfig,
};
use canon::{
    codes,
    health::{HealthEvidence, OrganId},
    Result,
};
use immune::health::{BodyState, Context};
use std::{
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use supervisor::{
    observations::{self, ObservationContext, OrganObserver},
    services::ServiceFuture,
};

struct Cached {
    bytes: Vec<u8>,
    at: u64,
}

pub struct HealthCollector {
    ledger: Arc<HostLedger>,
    gate: Arc<GateAdapter>,
    config: NodeConfig,
    body: Mutex<BodyState>,
    cache: Mutex<Result<Option<Cached>>>,
    cadence: tokio::sync::Mutex<immune::mhc::Cadence>,
}

impl HealthCollector {
    pub fn new(ledger: Arc<HostLedger>, gate: Arc<GateAdapter>, config: NodeConfig) -> Self {
        Self {
            ledger,
            gate,
            config,
            body: Mutex::new(BodyState::default()),
            cache: Mutex::new(Ok(None)),
            cadence: tokio::sync::Mutex::new(immune::mhc::Cadence::new(0)),
        }
    }

    /// Preserve the actual contexts attached by owning runtime measurements.
    pub fn update_body(&self, state: BodyState) -> Result<()> {
        *self.body.lock().map_err(|_| codes::SUPERVISOR_STATE)? = state;
        Ok(())
    }

    pub async fn refresh(&self) -> Result<()> {
        let mut cadence = self.cadence.lock().await;
        let now = now_ms()?;
        if !cadence.due(now) {
            return Ok(());
        }
        cadence.sampled(now)?;
        let observed = self.sample(now).await;
        let result = observed.as_ref().map(|_| ()).map_err(|error| *error);
        *self.cache.lock().map_err(|_| codes::SUPERVISOR_STATE)? = observed.map(Some);
        result
    }

    /// Missed slots are skipped; a slow organ cannot create overlapping samples.
    pub async fn run(self: Arc<Self>) {
        let mut timer =
            tokio::time::interval(std::time::Duration::from_millis(immune::mhc::CADENCE_MS));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            timer.tick().await;
            // refresh retains the exact failure for the face reader.
            let _ = self.refresh().await;
        }
    }

    async fn sample(&self, now: u64) -> Result<Cached> {
        let context = self.ledger.transaction(|txn| {
            let version = txn.current_version()?;
            Ok(ObservationContext {
                epoch: version.epoch,
                sequence: version
                    .sequence
                    .checked_sub(1)
                    .ok_or(codes::SUPERVISOR_STATE)?,
                observed_at_ms: now,
                commitment: version.previous_hash.ok_or(codes::SUPERVISOR_NOT_READY)?,
            })
        })?;
        let body_context = context_for_body(context);
        let mut body = self
            .body
            .lock()
            .map_err(|_| codes::SUPERVISOR_STATE)?
            .clone();
        body.read_deploy(
            body_context,
            &self.config.release_state,
            &self.config.egress_status,
        );
        let aumlok = NativeObserver::Aumlok;
        let gate = NativeObserver::Gate(&self.gate);
        let kira = NativeObserver::Kira;
        let network = NativeObserver::Network;
        let body = NativeObserver::Body(&body);
        let collected =
            observations::collect(context, &[&aumlok, &gate, &kira, &network, &body]).await?;
        let reduced = immune::mhc::compute(body_context, collected.reports)?;
        Ok(Cached {
            bytes: wire::encode(&reduced)?,
            at: now,
        })
    }
}

impl crate::faces::health::HealthRead for HealthCollector {
    fn snapshot(&self) -> Result<Vec<u8>> {
        let cache = self.cache.lock().map_err(|_| codes::SUPERVISOR_STATE)?;
        let cached = cache
            .as_ref()
            .map_err(|error| *error)?
            .as_ref()
            .ok_or(codes::SUPERVISOR_NOT_READY)?;
        let now = now_ms()?;
        if now < cached.at || now - cached.at > immune::mhc::CADENCE_MS * 2 {
            return Err(canon::Refusal {
                organ: "supervisor",
                reason: "health-stale",
            });
        }
        Ok(cached.bytes.clone())
    }
}

enum NativeObserver<'a> {
    Aumlok,
    Gate(&'a GateAdapter),
    Kira,
    Network,
    Body(&'a BodyState),
}

impl OrganObserver for NativeObserver<'_> {
    fn organ(&self) -> OrganId {
        match self {
            Self::Aumlok => OrganId::Aumlok,
            Self::Gate(_) => OrganId::GateAura,
            Self::Kira => OrganId::Kira,
            Self::Network => OrganId::Network,
            Self::Body(_) => OrganId::Body,
        }
    }

    fn observe(&self, context: ObservationContext) -> ServiceFuture<'_, Vec<HealthEvidence>> {
        Box::pin(async move {
            let ObservationContext {
                epoch,
                sequence,
                observed_at_ms,
                commitment,
            } = context;
            match self {
                Self::Aumlok => Ok(aumlok::health::health(aumlok::health::HealthContext {
                    epoch,
                    sequence,
                    observed_at_ms,
                    commitment,
                })),
                Self::Gate(gate) => {
                    gate.observe_health(gate::health::ObservationContext {
                        epoch,
                        sequence,
                        observed_at_ms,
                        commitment,
                    })
                    .await
                }
                Self::Kira => Err(codes::KIRA_STORE_UNAVAILABLE),
                Self::Network => Ok(nostr::health::health(&nostr::health::HealthContext {
                    epoch,
                    sequence,
                    observed_at_ms,
                    commitment,
                })),
                Self::Body(state) => Ok(immune::health::evidence(context_for_body(context), state)),
            }
        })
    }
}

fn context_for_body(context: ObservationContext) -> Context {
    Context {
        epoch: context.epoch,
        sequence: context.sequence,
        observed_at_ms: context.observed_at_ms,
        commitment: context.commitment,
    }
}

fn now_ms() -> Result<u64> {
    let value = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| codes::SUPERVISOR_STATE)?
        .as_millis();
    u64::try_from(value)
        .ok()
        .filter(|value| *value <= canon::json::MAX_SAFE_INTEGER as u64)
        .ok_or(codes::SUPERVISOR_STATE)
}
