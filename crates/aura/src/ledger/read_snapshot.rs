// SPDX-License-Identifier: AGPL-3.0-or-later
//! Authenticated read snapshots never reserve the SQLite writer or grant authority.
use super::*;
use canon::ids::{ProposalId, SubjectId};

/// A connection-bound generation captured before copying a detached snapshot.
pub struct ReadGeneration {
    pub(super) nonce: Digest32,
    pub(super) data_version: i64,
    pub(super) changes: u64,
    pub(super) retained: AuthorityVersion,
}

/// Only a complete authenticated detached snapshot can construct this token.
pub struct VerifiedRead {
    pub(super) state: io::Snapshot,
}

pub(super) fn nonce() -> Result<Digest32> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|_| refusal("randomness"))?;
    Ok(Digest32::from_bytes(bytes))
}

/// A verified SQLite read transaction with no mutation or commit surface.
pub struct ReadSnapshot<'a>(LedgerTxn<'a>);

impl Ledger {
    /// Capture using this exact connection, before starting the detached copy.
    pub fn read_generation(&self) -> Result<ReadGeneration> {
        Ok(ReadGeneration {
            nonce: self.snapshot_nonce,
            data_version: self
                .connection
                .query_row("PRAGMA data_version", [], |row| row.get(0))
                .map_err(sql)?,
            changes: self.connection.total_changes(),
            retained: self.verified.next()?,
        })
    }

    /// Copy, verify and inspect an independent read snapshot. The caller must
    /// compare its version with the live writer before recording any effects.
    pub fn read_snapshot<T>(
        path: &Path,
        services: TransactionServices<'_>,
        operation: impl FnOnce(&ReadSnapshot<'_>) -> Result<T>,
    ) -> Result<T> {
        let source = rusqlite::Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
                | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(sql)?;
        let mut connection = rusqlite::Connection::open_in_memory().map_err(sql)?;
        // The online backup releases the live database between small page copies.
        // Drop the source before signature verification and projection: even in
        // rollback-journal mode, expensive scans cannot delay a writer's commit.
        {
            use rusqlite::backup::{Backup, StepResult};
            let backup = Backup::new(&source, &mut connection).map_err(sql)?;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            loop {
                match backup.step(32).map_err(sql)? {
                    StepResult::Done => break,
                    StepResult::More if std::time::Instant::now() < deadline => {
                        std::thread::yield_now();
                    }
                    _ => return Err(refusal("snapshot-busy")),
                }
            }
        }
        drop(source);
        connection
            .execute_batch("PRAGMA trusted_schema=OFF; PRAGMA query_only=ON;")
            .map_err(sql)?;
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
            .map_err(sql)?;
        crate::schema::validate(&transaction)?;
        let mut retained = io::verify(&transaction)?;
        if !retained.keys.is_empty() && retained.keys != services.signer.public_keys()? {
            return Err(refusal("signer-changed"));
        }
        let state = retained.clone();
        let observation_start_changes = transaction.total_changes();
        let snapshot = ReadSnapshot(LedgerTxn {
            observation_start_changes,
            transaction,
            services,
            identity: Digest32::from_bytes([0; 32]),
            state,
            retained: &mut retained,
            poisoned: false,
            counters: BTreeMap::new(),
            consumptions: BTreeSet::new(),
            floor_obligation: None,
            target_observation: None,
        });
        operation(&snapshot)
    }
}

impl ReadSnapshot<'_> {
    pub fn verified(&self) -> VerifiedRead {
        VerifiedRead {
            state: self.0.state.clone(),
        }
    }
    pub fn observations(&self) -> Result<super::observations::ObservationProjection> {
        super::observations::project_all(&self.0.transaction, &self.0.state)
    }
    pub fn current_version(&self) -> Result<AuthorityVersion> {
        self.0.current_version()
    }
    pub fn owner_subject(&self) -> Result<SubjectId> {
        self.0.gate_owner_subject()
    }
    pub fn record_at_sequence(&self, sequence: u64) -> Result<Option<AuthorityRecord>> {
        self.0.floor_record_at_sequence(sequence)
    }
    pub fn proposal(&self, proposal: &ProposalId) -> Result<crate::storage::ProposalState> {
        self.0.proposal(proposal)
    }
    pub fn check_target_consumption(
        &self,
        proposal: ProposalId,
        approval: Digest32,
    ) -> Result<AuthorityRecord> {
        self.0.check_target_consumption(proposal, approval)
    }
}

#[cfg(test)]
mod tests;
