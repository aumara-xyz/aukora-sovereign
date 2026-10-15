// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::{node::Node, state};
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::sync::{Arc, Weak};
use std::time::Duration;

const INTERVAL: Duration = Duration::from_secs(600);

#[cfg(test)]
pub(crate) type TestPublish = (
    String,
    nostr::event::Event,
    tokio::sync::oneshot::Sender<relay::Result<relay::PublishResult>>,
);

#[derive(Default)]
pub(crate) struct State {
    accepted: usize,
    sequence: Option<u64>,
    at: Option<i64>,
    results: Vec<RelayResult>,
    last_accepted: Vec<Option<String>>,
}

struct RelayResult {
    relay: String,
    accepted: bool,
    code: &'static str,
}

impl State {
    pub(crate) fn accepted(&self) -> usize {
        self.accepted
    }

    pub(crate) fn public_json(&self, relays: &[String]) -> Value {
        let results: Vec<_> = self.results.iter().map(|result| {
            json!({"relay":result.relay,"accepted":result.accepted,"code":result.code})
        }).collect();
        json!({"relays":relays,"accepted":self.accepted,"sequence":self.sequence,"at":self.at,"results":results})
    }
}

pub(crate) fn start(node: &Arc<Node>) -> Option<tokio::task::JoinHandle<()>> {
    if node.config.nostr.relays.is_empty() {
        return None;
    }
    let weak = Arc::downgrade(node);
    Some(node.handle.spawn(run(weak)))
}

async fn run(weak: Weak<Node>) {
    loop {
        {
            let Some(node) = weak.upgrade() else { return };
            // Failures are retried on the next interval and never enter Aura.
            let _ = publish_head(&node).await;
        }
        tokio::time::sleep(INTERVAL).await;
    }
}

fn retained_head(node: &Node) -> Result<aura::merkle::RetainedHead> {
    let db = node.db.lock().map_err(|_| anyhow!("nostr:witness-lock"))?;
    let snapshot = db.unchecked_transaction()?;
    let head = snapshot.query_row("SELECT coalesce(max(seq),0) FROM main.aura", [], |row| {
        crate::node::sql_u64(row, 0)
    })?;
    let retained = aura::export_database(
        &snapshot,
        &node.signer.verifying_key(),
        usize::try_from(head)?,
    )?
    .0;
    drop(snapshot);
    Ok(retained)
}

async fn publish_head(node: &Arc<Node>) -> Result<()> {
    let head = retained_head(node)?;
    let content = head.to_json()?;
    let pending_relays: Vec<_> = {
        let status = node
            .witness
            .lock()
            .map_err(|_| anyhow!("nostr:witness-lock"))?;
        node.config
            .nostr
            .relays
            .iter()
            .cloned()
            .enumerate()
            .filter(|(index, _)| {
                status.last_accepted.get(*index).and_then(Option::as_ref) != Some(&content)
            })
            .collect()
    };
    if pending_relays.is_empty() {
        return Ok(());
    }
    let at = state::now_ms()?;
    let now = u64::try_from(at)? / 1000;
    let event = Arc::new(nostr::event::Event::sign(
        node.nostr.node_key(),
        now,
        30078,
        vec![vec!["d".into(), "aukora-aura-head".into()]],
        content.clone(),
    )?);
    let mut pending = tokio::task::JoinSet::new();
    for (index, url) in pending_relays {
        let node = node.clone();
        let event = event.clone();
        pending.spawn(async move {
            let (accepted, code) = match publish(&node, &url, &event, now).await {
                Ok(result) => (result.accepted, result.message_code),
                Err(error) => (false, error.code()),
            };
            (
                index,
                RelayResult {
                    relay: url,
                    accepted,
                    code,
                },
            )
        });
    }
    let mut results = Vec::new();
    while let Some(result) = pending.join_next().await {
        results.push(result.map_err(|_| anyhow!("nostr:witness-worker"))?);
    }
    results.sort_by_key(|(index, _)| *index);
    let mut status = node
        .witness
        .lock()
        .map_err(|_| anyhow!("nostr:witness-lock"))?;
    status
        .last_accepted
        .resize(node.config.nostr.relays.len(), None);
    if status.sequence != Some(head.sequence as u64) {
        status.results = node
            .config
            .nostr
            .relays
            .iter()
            .map(|url| RelayResult {
                relay: url.clone(),
                accepted: false,
                code: "relay:not-attempted",
            })
            .collect();
    }
    for (index, result) in results {
        if result.accepted {
            status.last_accepted[index] = Some(content.clone());
        }
        status.results[index] = result;
    }
    status.accepted = status
        .last_accepted
        .iter()
        .filter(|accepted| accepted.as_ref() == Some(&content))
        .count();
    status.sequence = Some(head.sequence as u64);
    status.at = Some(at);
    Ok(())
}

async fn publish(
    node: &Node,
    url: &str,
    event: &nostr::event::Event,
    now: u64,
) -> relay::Result<relay::PublishResult> {
    #[cfg(test)]
    {
        let transport = node.witness_transport.lock().unwrap().clone();
        if let Some(transport) = transport {
            let (tx, rx) = tokio::sync::oneshot::channel();
            transport.send((url.to_owned(), event.clone(), tx)).unwrap();
            return rx.await.unwrap();
        }
    }
    relay::publish(url, event, node.nostr.node_key(), now).await
}

#[cfg(test)]
#[path = "nostr_witness_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "organs_tests.rs"]
mod organs_tests;
