// SPDX-License-Identifier: AGPL-3.0-or-later
//! Absence reads over the verified committed prefix. Existing broker authority needs its proof projection.

use super::*;
use canon::{
    ids::{GrantId, RequestId, ReservationId},
    json::Value,
};

impl LedgerTxn<'_> {
    pub(super) fn read_broker_absence(&self, namespace: &str, key: &str) -> Result<Option<Value>> {
        match namespace {
            "broker.grant" => {
                GrantId::from_hex(key)?;
            }
            "broker.request" => {
                RequestId::from_hex(key)?;
            }
            "broker.reservation" => {
                ReservationId::from_hex(key)?;
            }
            "broker.operation" => {
                OperationId::from_hex(key)?;
            }
            _ => return Err(refusal("authority-namespace-unavailable")),
        }
        self.check_unstaged_committed_prefix()?;
        let existing: bool = self
            .transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM aura WHERE seq<=?1 AND phase<>'fact'
             AND kind IN ('broker.grant','broker.revoke','broker.reserve','broker.settle'))",
                [self.retained.frontier.size() as i64],
                |row| row.get(0),
            )
            .map_err(sql)?;
        if existing {
            return Err(refusal("broker-projection-unavailable"));
        }
        Ok(None)
    }

    pub(super) fn read_empty_broker_pending(&self) -> Result<Vec<Value>> {
        self.check_unstaged_committed_prefix()?;
        let existing: bool = self
            .transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM aura WHERE seq<=?1 AND phase<>'fact'
             AND kind IN ('broker.reserve','broker.settle'))",
                [self.retained.frontier.size() as i64],
                |row| row.get(0),
            )
            .map_err(sql)?;
        if existing {
            return Err(refusal("broker-projection-unavailable"));
        }
        Ok(Vec::new())
    }

    fn check_unstaged_committed_prefix(&self) -> Result<()> {
        self.active()?;
        if self.state.next()? != self.retained.next()?
            || self.transaction.total_changes() != self.observation_start_changes
            || !self.counters.is_empty()
            || !self.consumptions.is_empty()
            || self.floor_obligation.is_some()
            || self.target_observation.is_some()
        {
            return Err(refusal("authority-read-staged"));
        }
        if let Some(hash) = self.retained.hash {
            let tail = io::record_at(&self.transaction, self.retained.frontier.size())?;
            crate::record::verify_record(&tail, &self.retained.keys)?;
            if tail.hash != hash || tail.authority.epoch != self.retained.epoch {
                return Err(refusal("authority-read-context"));
            }
        } else if self.retained.frontier.size() != 0 {
            return Err(refusal("authority-read-context"));
        }
        Ok(())
    }
}

impl LedgerTxn<'_> {
    /// Observe genuine absence before reporting that this node has no grant or broker receipt.
    /// A nonempty history needs the organ's proof-validating projection instead.
    pub fn broker_history_empty(&self) -> Result<bool> {
        self.check_unstaged_committed_prefix()?;
        let present: bool = self
            .transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM aura WHERE seq<=?1 AND phase<>'fact'
             AND kind IN ('broker.grant','broker.revoke','broker.reserve','broker.settle'))",
                [self.retained.frontier.size() as i64],
                |row| row.get(0),
            )
            .map_err(sql)?;
        Ok(!present)
    }
}
