// SPDX-License-Identifier: AGPL-3.0-or-later
//! Private SQLite ownership; all authority service bodies remain closed in wave 0.

use std::path::Path;

use canon::{
    alg::{PublicKey, Signature, Signatures},
    authority::{
        AuthorityRecord, AuthorityTxn, AuthorityVersion, FactRecord, LifecycleRecord,
        OwnerAuthorization, OwnerBinding, OwnerOperation, PendingAuthorityRecord,
        StandingUseContext, VerifiedProof, VerifiedStandingUse,
    },
    digest::Digest32,
    ids::{CredentialId, OperationDigest, OperationId, ProposalId},
    Result,
};

use crate::{
    export::{ColdProofV1, ExportLimits},
    storage::{
        DeclinedProposal, OperationCoverage, ProposalState, RecoveryWork, StagedAuthorization,
    },
};

/// A signing service holds the key; Aura receives only public keys and signatures.
pub trait RecordSigner {
    fn public_keys(&self) -> Result<Vec<PublicKey>>;
    fn sign_entry_hash(&self, hash: Digest32) -> Result<Signatures>;
}

/// The supervisor supplies clock observations. Time never substitutes for sequence.
pub trait TrustedClock {
    fn now_ms(&self) -> Result<i64>;
}

#[derive(Clone, Copy)]
pub struct TransactionServices<'a> {
    pub signer: &'a dyn RecordSigner,
    pub clock: &'a dyn TrustedClock,
}

/// No public connection, unchecked constructor, generic SQL, or mutable raw handle.
pub struct Ledger {
    connection: rusqlite::Connection,
}

impl Ledger {
    /// Wave-1 contract: open the owner-selected file, verify schema and both arms,
    /// apply only admitted migrations, reject unknown schemas or damaged history.
    pub fn open(_path: &Path) -> Result<Self> {
        crate::unavailable()
    }

    /// Wave-1 contract: fresh unpredictable transaction identity and BEGIN IMMEDIATE.
    /// The signer is borrowed; Aura never takes custody of its secret key.
    pub fn begin<'a>(&'a mut self, _services: TransactionServices<'a>) -> Result<LedgerTxn<'a>> {
        let _ = &self.connection;
        crate::unavailable()
    }

    /// Read one authenticated snapshot, including full rows and their covering head.
    pub fn export_cold_proof(&self, _limits: ExportLimits) -> Result<ColdProofV1> {
        crate::unavailable()
    }
}

/// Drop rolls SQLite back. There is no public constructor or connection accessor.
/// A transaction can commit only after its counter/consumption/append obligations close.
pub struct LedgerTxn<'a> {
    transaction: rusqlite::Transaction<'a>,
    services: TransactionServices<'a>,
    identity: Digest32,
}

impl LedgerTxn<'_> {
    pub fn current_version(&self) -> Result<AuthorityVersion> {
        crate::unavailable()
    }

    /// Return only a retained row matching this exact epoch, sequence and predecessor.
    pub fn record_at(&self, _version: AuthorityVersion) -> Result<AuthorityRecord> {
        crate::unavailable()
    }

    /// Stage only Pending exact proposal bytes; reject occupied targets and declines
    /// with the same operation/evidence commitments. No approval is created here.
    pub fn stage_proposal(&mut self, _proposal: ProposalState) -> Result<()> {
        crate::unavailable()
    }

    pub fn proposal(&self, _proposal: &ProposalId) -> Result<ProposalState> {
        crate::unavailable()
    }

    /// Include interrupted unconsumed proposals so reconciliation can expire/refuse them.
    pub fn pending_proposals(&self, _limit: usize) -> Result<Vec<ProposalState>> {
        crate::unavailable()
    }

    /// Store exact card/auth bytes only after recomputing all commitments from storage.
    pub fn stage_authorization(&mut self, _authorization: StagedAuthorization) -> Result<()> {
        crate::unavailable()
    }

    pub fn last_decline(&self, _operation: OperationDigest) -> Result<Option<DeclinedProposal>> {
        crate::unavailable()
    }

    /// Store a nonauthorizing refusal terminal, release its target, retain its decline.
    /// A consumed approval cannot take this path; it must be reconciled.
    pub fn decline(
        &mut self,
        _proposal: &ProposalId,
        _row: LifecycleRecord,
    ) -> Result<AuthorityRecord> {
        crate::unavailable()
    }

    pub fn recovery_work(&self, _limit: usize) -> Result<Vec<RecoveryWork>> {
        crate::unavailable()
    }

    /// Release only after the recorded terminal is verified for this exact operation.
    /// Pending or consumed state without that terminal cannot release a reservation.
    pub fn release_reservation(&mut self, _proposal: &ProposalId) -> Result<()> {
        crate::unavailable()
    }

    pub fn operation_coverage(&self, _operation: &OperationId) -> Result<OperationCoverage> {
        crate::unavailable()
    }

    /// Floor owns the versioned protected-state format; Aura keeps its exact bytes.
    pub fn floor_state(&self) -> Result<Option<Vec<u8>>> {
        crate::unavailable()
    }

    /// Stage only under the same transaction's persisted, consumed Release proof.
    /// Compare the previous commitment; the next state's seven-key floor member
    /// must match C5's exact approved bytes. Derive high-water metadata from locked
    /// state, preserving spent approvals and rejecting any counter/epoch rollback.
    /// The corresponding signed floor.advance append must close this obligation.
    pub fn stage_floor(
        &mut self,
        _proof: &VerifiedProof,
        _expected_state_digest: Option<Digest32>,
        _next_state_bytes: &[u8],
    ) -> Result<()> {
        crate::unavailable()
    }

    /// All staged authority obligations must be satisfied; partial transitions refuse.
    pub fn commit(self) -> Result<()> {
        let _ = (&self.transaction, &self.services);
        crate::unavailable()
    }

    pub fn rollback(self) -> Result<()> {
        self.transaction
            .rollback()
            .map_err(|_| canon::codes::AURA_TRANSACTION)
    }
}

impl AuthorityTxn for LedgerTxn<'_> {
    fn transaction_id(&self) -> Digest32 {
        self.identity
    }

    fn owner_binding(&mut self, _credential: &CredentialId) -> Result<OwnerBinding> {
        crate::unavailable()
    }

    fn rebuild_authorization(
        &mut self,
        _proposal: &ProposalId,
        _action: OwnerOperation,
    ) -> Result<OwnerAuthorization> {
        crate::unavailable()
    }

    fn verify_signature(
        &mut self,
        _key: &PublicKey,
        _signed_bytes: &[u8],
        _signature: &Signature,
    ) -> Result<()> {
        crate::unavailable()
    }

    fn persist_counter(&mut self, _proof: &VerifiedProof) -> Result<()> {
        crate::unavailable()
    }

    fn consume(&mut self, _proof: &VerifiedProof) -> Result<()> {
        crate::unavailable()
    }

    fn append(
        &mut self,
        _proof: VerifiedProof,
        _record: PendingAuthorityRecord,
    ) -> Result<AuthorityRecord> {
        crate::unavailable()
    }

    fn check_standing_use(
        &mut self,
        _permission_id: &ProposalId,
        _permission_digest: Digest32,
        _proposal: &ProposalId,
        _action: OwnerOperation,
    ) -> Result<StandingUseContext> {
        crate::unavailable()
    }

    fn append_standing(
        &mut self,
        _usage: VerifiedStandingUse,
        _record: PendingAuthorityRecord,
    ) -> Result<AuthorityRecord> {
        crate::unavailable()
    }

    fn append_lifecycle(&mut self, _observation: LifecycleRecord) -> Result<AuthorityRecord> {
        crate::unavailable()
    }

    fn append_fact(&mut self, _fact: FactRecord) -> Result<AuthorityRecord> {
        crate::unavailable()
    }
}
