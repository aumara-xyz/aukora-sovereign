// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::node::{canon_bytes, signed_card, sql_u64, Node, ProductionGate};
use crate::{runtime::RuntimeDigests, state};
use anyhow::{anyhow, Result};
use gate::TargetStore;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

#[derive(Default)]
pub(crate) struct ReplayRetry {
    digest: String,
    failures: u32,
    pub(crate) next: Option<Instant>,
    pub(crate) last: Option<Instant>,
    requested: bool,
    in_progress: bool,
}
struct ReplayFlight<'a>(&'a Node);
impl Drop for ReplayFlight<'_> {
    fn drop(&mut self) {
        if let Ok(mut retry) = self.0.release_retry.lock() {
            retry.in_progress = false;
        }
    }
}
#[derive(Default)]
pub(crate) struct ImmuneCache {
    floor: Option<(u64, BTreeSet<String>)>,
    refusals: BTreeMap<String, (u64, Option<String>)>,
    pub(crate) walks: usize,
    pub(crate) review_cards: BTreeMap<(String, i64, String), Vec<u8>>,
}

fn ids(value: &Value) -> Result<BTreeSet<String>> {
    value
        .as_array()
        .ok_or_else(|| anyhow!("immune:floor-unavailable"))?
        .iter()
        .map(|id| {
            id.as_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("immune:floor-unavailable"))
        })
        .collect()
}
fn evidence(db: &Connection, id: &str) -> Result<Option<Value>> {
    let body: Option<String> = db.query_row(
        "SELECT body FROM main.aura WHERE kind='gate.propose' AND actor='supervisor' AND phase='fact'
         AND (json_extract(body,'$.release_proposal')=?1 OR op=?1) AND json_type(body,'$.immune_release')='object'
         ORDER BY seq DESC LIMIT 1", [id], |row| row.get(0)).optional()?;
    body.map(|body| Ok(serde_json::from_str::<Value>(&body)?["immune_release"].clone()))
        .transpose()
}
fn refusal_code(code: &str) -> String {
    let part = |text: &str| {
        text.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
            && text
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    };
    if code.len() <= 80
        && code
            .split_once(':')
            .is_some_and(|(organ, reason)| part(organ) && part(reason))
    {
        code.to_owned()
    } else {
        "immune:invalid-refusal-code".into()
    }
}

impl Node {
    pub(crate) fn has_release_evidence(&self, id: &str) -> Result<bool> {
        let db = self.db.lock().map_err(|_| anyhow!("supervisor:lock"))?;
        Ok(evidence(&db, id)?.is_some_and(|e| {
            e["supervisor_binary_sha256"] == self.binary_sha256 && e["proposal_id"] == id
        }))
    }
    pub(crate) fn restore_release_evidence(&self, gate: &mut ProductionGate) -> Result<()> {
        let db = self.db.lock().map_err(|_| anyhow!("supervisor:lock"))?;
        let snapshot = db.unchecked_transaction()?;
        aura::walk_database(&snapshot, &self.signer.verifying_key(), None)?;
        let mut statement =
            snapshot.prepare("SELECT id FROM gate_proposals WHERE target='release'")?;
        for id in statement.query_map([], |r| r.get::<_, String>(0))? {
            let id = id?;
            if let Some(e) = evidence(&snapshot, &id)? {
                if e["supervisor_binary_sha256"] == self.binary_sha256 && e["proposal_id"] == id {
                    gate.set_release_proposal_evidence(&id, &e)?;
                }
            }
        }
        Ok(())
    }
    pub(crate) fn antibody_floor(&self) -> Result<BTreeSet<String>> {
        let mut db = self.db.lock().map_err(|_| anyhow!("supervisor:lock"))?;
        let snapshot = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stamp: u64 = snapshot.query_row("SELECT coalesce(max(seq),0) FROM main.aura WHERE kind='floor.advance' OR (kind='gate.apply' AND phase='terminal' AND op IN (SELECT id FROM gate_proposals WHERE target='release'))", [], |r| sql_u64(r, 0))?;
        let mut cache = self
            .immune_cache
            .lock()
            .map_err(|_| anyhow!("supervisor:lock"))?;
        if let Some((at, floor)) = &cache.floor {
            if *at == stamp {
                return Ok(floor.clone());
            }
        }
        aura::walk_database(&snapshot, &self.signer.verifying_key(), None)?;
        cache.walks += 1;
        let mut floor = BTreeSet::new();
        let mut statement = snapshot.prepare("SELECT body FROM main.aura WHERE kind='floor.advance' AND phase='fact' AND actor='supervisor' ORDER BY seq")?;
        for body in statement.query_map([], |r| r.get::<_, String>(0))? {
            let body: Value = serde_json::from_str(&body?)?;
            if let Some(recorded) = body.get("antibody_ids") {
                floor.extend(ids(recorded)?);
            }
        }
        let releases: Vec<(String, Vec<u8>)> = {
            let mut statement = snapshot.prepare("SELECT p.id,b.bytes FROM gate_proposals p JOIN gate_blobs b ON p.new_sha256=b.sha256
             WHERE p.target='release' AND p.state='applied' AND NOT EXISTS(SELECT 1 FROM main.aura a WHERE a.op=p.id AND a.kind='floor.advance' AND a.phase='fact' AND json_type(a.body,'$.antibody_ids')='array') ORDER BY p.rowid")?;
            let rows = statement
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        for (id, bytes) in releases {
            let retained = if let Some(e) = evidence(&snapshot, &id)? {
                ids(&e["antibody_ids"])?
            } else {
                let card = signed_card(
                    &snapshot,
                    &self.signer.verifying_key(),
                    &id,
                    "release",
                    &bytes,
                )?;
                let pinned = &card["target_review"]["pinned"];
                if pinned.is_null() {
                    BTreeSet::new()
                } else {
                    ids(&pinned["antibody_ids"])?
                }
            };
            floor.extend(retained.iter().cloned());
            self.audit(
                &snapshot,
                "floor.advance",
                &id,
                "fact",
                json!({"antibody_ids":retained,"release_proposal":id}),
            )?;
        }
        drop(statement);
        let stamp = snapshot.query_row("SELECT coalesce(max(seq),0) FROM main.aura WHERE kind='floor.advance' OR (kind='gate.apply' AND phase='terminal' AND op IN (SELECT id FROM gate_proposals WHERE target='release'))", [], |r| sql_u64(r,0))?;
        snapshot.commit()?;
        cache.floor = Some((stamp, floor.clone()));
        Ok(floor)
    }
    pub(crate) fn record_antibody_floor(&self, id: &str, card: &Value) -> Result<()> {
        let mut db = self.db.lock().map_err(|_| anyhow!("supervisor:lock"))?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let retained = if let Some(e) = evidence(&tx, id)? {
            ids(&e["antibody_ids"])?
        } else {
            let pinned = &card["target_review"]["pinned"];
            if pinned.is_null() {
                BTreeSet::new()
            } else {
                ids(&pinned["antibody_ids"])?
            }
        };
        self.audit(&tx, "floor.advance", id, "fact", json!({"antibody_ids":retained,
            "antibody_corpus_sha256":card["target_review"]["pinned"]["antibody_corpus_sha256"],"release_proposal":id}))?;
        tx.execute(
            "INSERT OR IGNORE INTO supervisor_effects(proposal,target) VALUES(?,'release')",
            [id],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub(crate) fn release_immune_refusal(&self) -> Result<Option<String>> {
        let status = self
            .runtime
            .lock()
            .map_err(|_| anyhow!("supervisor:lock"))?
            .clone();
        let code = self.recorded_release_refusal(&status.current_digest)?;
        if let Some(code) = &code {
            let resolved = code == "gate:identical"
                || (status.agent == "running"
                    && status.approved_digest.as_ref() == Some(&status.current_digest));
            if resolved
                && crate::runtime::RuntimeBackend::approved_release(self)?
                    .is_some_and(|release| release.digest == status.current_digest)
            {
                return Ok(None);
            }
        }
        Ok(code)
    }
    pub(crate) fn recorded_release_refusal(&self, digest: &str) -> Result<Option<String>> {
        let db = self.db.lock().map_err(|_| anyhow!("supervisor:lock"))?;
        let snapshot = db.unchecked_transaction()?;
        // An applied release supersedes earlier replay refusals for its digest.
        let stamp: u64 = snapshot.query_row(
            "SELECT coalesce(max(a.seq),0) FROM main.aura a WHERE
             (a.actor='supervisor' AND a.phase='fact' AND a.kind IN ('gate.refuse','gate.propose')
              AND json_extract(a.body,'$.runtime_digest')=?1 AND json_type(a.body,'$.immune_release')='object')
             OR (a.kind='gate.apply' AND a.phase='terminal' AND json_extract(a.body,'$.receipt.target')='release'
              AND EXISTS(SELECT 1 FROM gate_proposals p JOIN gate_blobs b ON b.sha256=p.new_sha256
               WHERE p.id=a.op AND p.target='release' AND p.state='applied'
                AND p.new_sha256=json_extract(a.body,'$.receipt.new_sha256')
                AND json_extract(CAST(b.bytes AS TEXT),'$.digest')=?1))",
            [digest], |r| sql_u64(r, 0),
        )?;
        let mut cache = self
            .immune_cache
            .lock()
            .map_err(|_| anyhow!("supervisor:lock"))?;
        if let Some((at, code)) = cache.refusals.get(digest) {
            if *at == stamp {
                return Ok(code.clone());
            }
        }
        aura::walk_database(&snapshot, &self.signer.verifying_key(), None)?;
        cache.walks += 1;
        let code = if stamp == 0 {
            None
        } else {
            let entry = aura::read_entry(&snapshot, stamp)?
                .ok_or_else(|| anyhow!("immune:evidence-unavailable"))?;
            let body: Value = serde_json::from_slice(&canon::canonical_json(&entry.body)?)?;
            body["code"].as_str().map(refusal_code)
        };
        cache
            .refusals
            .insert(digest.to_owned(), (stamp, code.clone()));
        Ok(code)
    }
    fn record_release_refusal(&self, digest: &str, code: &str, evidence: &Value) -> Result<()> {
        let mut db = self.db.lock().map_err(|_| anyhow!("supervisor:lock"))?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.audit(&tx, "gate.refuse", "", "fact", json!({"code":code,"runtime_digest":digest,
            "immune_release":evidence,"missing_ids":evidence["missing_ids"],"failed_ids":evidence["failed_ids"],
            "next":"Retry antibodies; reviewed proposals require owner retirement before replacement"}))?;
        tx.commit()?;
        Ok(())
    }
    pub(crate) fn propose_immune_release(
        &self,
        digests: &RuntimeDigests,
        report: &::immune::Report,
    ) -> Result<bool> {
        let record = json!({"v":1,"digest":digests.digest,"components":digests.components});
        let bytes = canon_bytes(&record)?;
        // A floor failure cannot require approval of bytes already approved locally.
        if self.approved_bytes("release")?.as_deref() == Some(bytes.as_slice()) {
            return Ok(false);
        }
        let hash = gate::sha256(&bytes);
        let supplied: BTreeSet<_> = report.ids.iter().cloned().collect();
        let missing: Vec<_> = self
            .antibody_floor()?
            .difference(&supplied)
            .cloned()
            .collect();
        let refusal = if missing.is_empty() {
            report.refusal_code()
        } else {
            Some("immune:corpus-regressed")
        };
        let mut e = json!({"new_sha256":hash,"supervisor_binary_sha256":self.binary_sha256,
            "antibody_corpus_sha256":report.root,"antibody_pass_count":report.passed,"antibody_total":report.total,
            "antibody_ids":report.ids,"failed_ids":report.failures.iter().map(|f| &f.id).collect::<Vec<_>>(),
            "missing_ids":missing,"refusal_code":refusal});
        if let Some(code) = refusal {
            self.record_release_refusal(&digests.digest, code, &e)?;
        }
        let mut guard = self.gate.lock().map_err(|_| anyhow!("supervisor:lock"))?;
        let gate = guard
            .as_mut()
            .ok_or_else(|| anyhow!("aumlok:binding-required"))?;
        let pending: Option<String> = self.db.lock().map_err(|_| anyhow!("supervisor:lock"))?
            .query_row("SELECT id FROM gate_proposals WHERE target='release' AND new_sha256=? AND state='pending' AND expires_at>? ORDER BY rowid DESC LIMIT 1", params![hash,state::now_ms()?], |r| r.get(0)).optional()?;
        let result = (|| -> gate::Result<String> {
            let pending = if let Some(id) = pending {
                // A failed recovery withdraws the evidence-less proposal before raising its warning card.
                if refusal.is_some()
                    && !self
                        .has_release_evidence(&id)
                        .map_err(|_| gate::Error::Refused("immune:evidence-unavailable"))?
                {
                    gate.owner().withdraw_unreviewed(&id)?;
                    None
                } else {
                    Some(id)
                }
            } else {
                None
            };
            let id = if let Some(id) = pending {
                id
            } else {
                gate.set_release_evidence(&hash, &e)?;
                let store = gate::fs_store::FsStore::new(self.config.state_dir.join("targets"))?;
                let base = store
                    .read("release")?
                    .map_or_else(|| "absent".into(), |b| gate::sha256(&b));
                gate.owner()
                    .raise(gate::ProposalRequest {
                        target: "release".into(),
                        base_sha256: base,
                        new_bytes: bytes,
                        note: String::new(),
                        idempotency_key: format!(
                            "release_{}_{}",
                            digests.digest,
                            state::random_id()
                                .map_err(|_| gate::Error::Refused("supervisor:random"))?
                        ),
                        cell: None,
                    })?
                    .id
            };
            e["proposal_id"] = json!(id);
            gate.set_release_proposal_evidence(&id, &e)?;
            Ok(id)
        })();
        let id = match result {
            Ok(id) => id,
            Err(gate::Error::Refused(code)) => {
                drop(guard);
                self.record_release_refusal(&digests.digest, code, &e)?;
                return Ok(false);
            }
            Err(error) => return Err(error.into()),
        };
        drop(guard);
        let mut db = self.db.lock().map_err(|_| anyhow!("supervisor:lock"))?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.audit(&tx, "gate.propose", "", "fact", json!({"release_proposal":id,"runtime_digest":digests.digest,"code":refusal,"immune_release":e}))?;
        tx.commit()?;
        Ok(true)
    }
    pub(crate) fn request_immune_retry(&self) -> Result<()> {
        *self
            .release_seen
            .lock()
            .map_err(|_| anyhow!("supervisor:lock"))? = None;
        let mut retry = self
            .release_retry
            .lock()
            .map_err(|_| anyhow!("supervisor:lock"))?;
        retry.requested = true;
        retry.next = Some(retry.last.map_or_else(Instant::now, |last| {
            (last + Duration::from_secs(5)).max(Instant::now())
        }));
        Ok(())
    }
    pub(crate) fn ensure_immune_release(&self, digests: &RuntimeDigests) -> Result<()> {
        self.ensure_immune_release_with(digests, |corpus| {
            crate::immune::replay(corpus, crate::immune::REPLAY_BUDGET, self.handle.clone())
        })
    }
    pub(crate) fn ensure_immune_release_with(
        &self,
        digests: &RuntimeDigests,
        replay: impl FnOnce(&::immune::Corpus) -> Result<::immune::Report>,
    ) -> Result<()> {
        let bytes =
            canon_bytes(&json!({"v":1,"digest":digests.digest,"components":digests.components}))?;
        if self.approved_bytes("release")?.as_deref() == Some(bytes.as_slice()) {
            return Ok(());
        }
        let mut seen = self
            .release_seen
            .lock()
            .map_err(|_| anyhow!("supervisor:lock"))?;
        let mut retry = self
            .release_retry
            .lock()
            .map_err(|_| anyhow!("supervisor:lock"))?;
        if retry.in_progress {
            return Ok(());
        }
        if retry.digest != digests.digest {
            *retry = ReplayRetry {
                digest: digests.digest.clone(),
                ..Default::default()
            };
        }
        if retry.next.is_some_and(|next| Instant::now() < next) {
            return Ok(());
        }
        if seen.as_ref() == Some(&digests.digest) && !retry.requested && retry.next.is_none() {
            return Ok(());
        }
        let force_replay = retry.requested || retry.next.is_some();
        retry.requested = false;
        retry.next = None;
        retry.in_progress = true;
        *seen = None;
        drop(retry);
        drop(seen);
        let _flight = ReplayFlight(self);
        let hash = gate::sha256(&bytes);
        let mut guard = self.gate.lock().map_err(|_| anyhow!("supervisor:lock"))?;
        let gate = guard
            .as_mut()
            .ok_or_else(|| anyhow!("aumlok:binding-required"))?;
        let releases: Vec<(String, String, bool)> = {
            let db = self.db.lock().map_err(|_| anyhow!("supervisor:lock"))?;
            let mut statement = db.prepare("SELECT id,new_sha256,reviewed OR EXISTS(SELECT 1 FROM gate_actions a WHERE a.proposal_id=gate_proposals.id) FROM gate_proposals WHERE target='release' AND state='pending' AND expires_at>? ORDER BY rowid")?;
            let rows = statement
                .query_map([state::now_ms()?], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        let mut healthy_pending = false;
        for (id, new, reviewed) in releases {
            let healthy = self.has_release_evidence(&id)?;
            if new == hash && healthy {
                healthy_pending = true;
                continue;
            }
            if new == hash && !healthy {
                continue;
            }
            if reviewed {
                drop(guard);
                self.record_release_refusal(
                    &digests.digest,
                    "gate:owner-retirement-required",
                    &json!({}),
                )?;
                *self
                    .release_seen
                    .lock()
                    .map_err(|_| anyhow!("supervisor:lock"))? = Some(digests.digest.clone());
                return Ok(());
            }
            if let Err(error) = gate.owner().withdraw_unreviewed(&id) {
                if let gate::Error::Refused(code) = error {
                    drop(guard);
                    self.record_release_refusal(&digests.digest, code, &json!({}))?;
                    *self
                        .release_seen
                        .lock()
                        .map_err(|_| anyhow!("supervisor:lock"))? = Some(digests.digest.clone());
                    return Ok(());
                }
                return Err(error.into());
            }
        }
        drop(guard);
        if !healthy_pending || force_replay {
            self.release_retry
                .lock()
                .map_err(|_| anyhow!("supervisor:lock"))?
                .last = Some(Instant::now());
            let corpus = ::immune::Corpus::embedded()?;
            let report = replay(&corpus).unwrap_or_else(|error| ::immune::Report {
                root: corpus.root().into(),
                ids: corpus.ids(),
                passed: 0,
                total: corpus.vectors().len(),
                failures: vec![::immune::Failure {
                    id: "runner".into(),
                    expected: "completed replay".into(),
                    observed: error.to_string(),
                }],
                budget_exhausted: false,
            });
            self.propose_immune_release(digests, &report)?;
            let mut retry = self
                .release_retry
                .lock()
                .map_err(|_| anyhow!("supervisor:lock"))?;
            if report.refusal_code() == Some("immune:replay-unavailable") {
                retry.failures = retry.failures.saturating_add(1);
                retry.next = Some(
                    Instant::now()
                        + Duration::from_secs(
                            5_u64.saturating_mul(1 << retry.failures.min(6)).min(300),
                        ),
                );
            } else {
                retry.failures = 0;
            }
        }
        *self
            .release_seen
            .lock()
            .map_err(|_| anyhow!("supervisor:lock"))? = Some(digests.digest.clone());
        Ok(())
    }
}
