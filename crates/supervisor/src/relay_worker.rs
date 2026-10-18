// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded supervisor-only polling of the relays in the installed egress policy.

use crate::{config::NodeConfig, faces::live_network::LiveNetwork};
use canon::{digest::Digest32, Refusal, Result};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, OnceLock,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

static CLOCK: OnceLock<Instant> = OnceLock::new();
static CONFIG: OnceLock<NodeConfig> = OnceLock::new();
static STOPPED: AtomicBool = AtomicBool::new(false);

pub struct RelayWorker {
    stop: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl RelayWorker {
    pub fn start(config: NodeConfig, network: Arc<LiveNetwork>) -> Result<Self> {
        CLOCK
            .set(Instant::now())
            .map_err(|_| refuse("clock-already-set"))?;
        CONFIG
            .set(config.clone())
            .map_err(|_| refuse("egress-observer-already-set"))?;
        relay::client::install_monotonic_clock(monotonic_ms)?;
        relay::egress::install_policy_observer(observe_policy)?;
        let (stop, mut changed) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move {
            let mut backoff = 30u64;
            loop {
                if *changed.borrow() {
                    break;
                }
                let config = config.clone();
                let network = network.clone();
                // The relay crate is blocking. Nothing runs in Auma or on the async ingress executor.
                let result = tokio::task::spawn_blocking(move || poll(&config, &network)).await;
                match &result {
                    Ok(Err(code)) => eprintln!(
                        "messaging: relay cycle refused {}:{}",
                        code.organ, code.reason
                    ),
                    Err(_) => eprintln!("messaging: relay worker failed"),
                    _ => {}
                }
                let delay = match result {
                    Ok(Ok(())) => {
                        backoff = 30;
                        30
                    }
                    _ => {
                        let delay = backoff;
                        backoff = (backoff * 2).min(300);
                        delay
                    }
                };
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(delay)) => {},
                    _ = changed.changed() => { break; },
                }
            }
        });
        Ok(Self { stop, task })
    }

    pub async fn shutdown(self) {
        STOPPED.store(true, Ordering::Release);
        let _ = self.stop.send(true);
        let _ = self.task.await;
    }
}

fn poll(config: &NodeConfig, network: &LiveNetwork) -> Result<()> {
    let policy = config.current_relay_policy(wall_ms()?)?;
    if policy.relays.is_empty() {
        return Ok(());
    }
    let deadline = monotonic_ms().saturating_add(relay::client::MAX_OPERATION_MS);
    let mut pins = Vec::new();
    for rule in &policy.relays {
        if STOPPED.load(Ordering::Acquire) {
            return Ok(());
        }
        pins.push(relay::ValidatedRelay::from_policy(&policy, &rule.url)?);
    }
    // Independent connections share one total deadline. A stalled relay cannot
    // spend the other relay's opportunity to connect.
    let clients = std::thread::scope(|scope| {
        let jobs: Vec<_> = pins
            .into_iter()
            .map(|pin| scope.spawn(move || relay::Client::connect(pin, deadline)))
            .collect();
        jobs.into_iter()
            .filter_map(|job| job.join().ok().and_then(Result::ok))
            .collect::<Vec<_>>()
    });
    if clients.is_empty() {
        return Err(refuse("connect"));
    }
    let mut transport = relay::RelayTransport::new(clients)?;
    network.poll(
        &mut transport,
        wall_ms()? / 1000,
        monotonic_ms().saturating_add(relay::client::MAX_OPERATION_MS),
    )
}

pub(crate) fn monotonic_ms() -> u64 {
    CLOCK.get().map_or(0, |start| {
        u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
    })
}

fn wall_ms() -> Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| refuse("clock"))?
            .as_millis(),
    )
    .map_err(|_| refuse("clock"))
}

fn observe_policy() -> (u64, Digest32) {
    if !STOPPED.load(Ordering::Acquire) {
        if let Some(policy) = CONFIG.get().and_then(|config| {
            wall_ms()
                .ok()
                .and_then(|at| config.current_relay_policy(at).ok())
        }) {
            return (policy.epoch, policy.host_policy_digest);
        }
    }
    // A failed or stale host observation invalidates every existing connection.
    (0, Digest32::from_bytes([0; 32]))
}

fn refuse(reason: &'static str) -> Refusal {
    Refusal {
        organ: "relay",
        reason,
    }
}
