// SPDX-License-Identifier: AGPL-3.0-or-later
//! Host and gate Aura connections share one process writer lock.

use canon::{
    alg::AlgorithmId,
    authority::{AuthorityTxn, FactRecord},
    codes, Result,
};
use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use supervisor::{
    ingress::{BindingState, PrincipalScope},
    services::{BindingService, ServiceFuture},
};

pub struct HostClock;
impl aura::TrustedClock for HostClock {
    fn now_ms(&self) -> Result<i64> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| codes::SUPERVISOR_NOT_READY)?;
        let millis = i64::try_from(elapsed.as_millis()).map_err(|_| codes::SUPERVISOR_NOT_READY)?;
        if millis > canon::json::MAX_SAFE_INTEGER {
            return Err(codes::SUPERVISOR_NOT_READY);
        }
        Ok(millis)
    }
}

pub struct HostLedger {
    ledger: Mutex<aura::Ledger>,
    pub(super) release_approval: Mutex<Option<crate::release::ReleaseApproval>>,
    pub signer: Arc<dyn aura::RecordSigner + Send + Sync>,
    pub clock: Arc<dyn aura::TrustedClock + Send + Sync>,
}
/// A scoped view of the host connection while a gate job holds the writer lock.
pub struct GateLedger<'a> {
    host: &'a HostLedger,
    ledger: &'a mut aura::Ledger,
    scope: PrincipalScope,
}
impl GateLedger<'_> {
    pub fn transaction<T>(
        &mut self,
        operation: impl FnOnce(&mut aura::LedgerTxn<'_>) -> Result<T>,
    ) -> Result<T> {
        self.host.on_connection(self.ledger, true, |txn| {
            HostLedger::require_scope(txn, self.scope)?;
            operation(txn)
        })
    }
}
impl HostLedger {
    /// Borrow the host connection for observations while retaining its writer lock.
    pub fn with_read_ledger<T>(
        &self,
        operation: impl FnOnce(&aura::Ledger) -> Result<T>,
    ) -> Result<T> {
        let ledger = self.ledger.lock().map_err(|_| codes::SUPERVISOR_NOT_READY)?;
        operation(&ledger)
    }

    pub fn open(
        path: &Path,
        signer: Arc<dyn aura::RecordSigner + Send + Sync>,
        clock: Arc<dyn aura::TrustedClock + Send + Sync>,
    ) -> Result<Self> {
        Ok(Self {
            ledger: Mutex::new(aura::Ledger::open(path)?),
            release_approval: Mutex::new(None),
            signer,
            clock,
        })
    }
    pub fn services(&self) -> aura::TransactionServices<'_> {
        aura::TransactionServices {
            signer: &*self.signer,
            clock: &*self.clock,
        }
    }
    pub fn transaction<T>(
        &self,
        operation: impl FnOnce(&mut aura::LedgerTxn<'_>) -> Result<T>,
    ) -> Result<T> {
        self.with_transaction(true, operation)
    }
    /// The organ method ends its own transaction only after a durable transition.
    pub fn transition<T>(
        &self,
        operation: impl FnOnce(&mut aura::LedgerTxn<'_>) -> Result<T>,
    ) -> Result<T> {
        self.with_transaction(false, operation)
    }
    fn with_transaction<T>(
        &self,
        commit: bool,
        operation: impl FnOnce(&mut aura::LedgerTxn<'_>) -> Result<T>,
    ) -> Result<T> {
        let mut ledger = self
            .ledger
            .lock()
            .map_err(|_| codes::SUPERVISOR_NOT_READY)?;
        self.on_connection(&mut ledger, commit, operation)
    }
    fn on_connection<T>(
        &self,
        ledger: &mut aura::Ledger,
        commit: bool,
        operation: impl FnOnce(&mut aura::LedgerTxn<'_>) -> Result<T>,
    ) -> Result<T> {
        struct TransactionClock(i64);
        impl aura::TrustedClock for TransactionClock {
            fn now_ms(&self) -> Result<i64> {
                Ok(self.0)
            }
        }
        let clock = TransactionClock(self.clock.now_ms()?);
        let services = aura::TransactionServices {
            signer: &*self.signer,
            clock: &clock,
        };
        let mut transaction = ledger.begin(services)?;
        let result = operation(&mut transaction)?;
        if commit {
            transaction.commit()?;
        }
        Ok(result)
    }
    /// Gate owns its connection, but cannot use it while a host transaction runs.
    pub fn serialize_gate<T>(&self, operation: impl FnOnce() -> Result<T>) -> Result<T> {
        let _writer = self
            .ledger
            .lock()
            .map_err(|_| codes::SUPERVISOR_NOT_READY)?;
        operation()
    }
    /// Serialize nonauthorizing gate work against this process's host writes.
    /// Scope reads here do not cover transactions on the gate's connection.
    pub fn gate_scoped<T>(
        &self,
        scope: PrincipalScope,
        operation: impl FnOnce(&mut GateLedger<'_>) -> Result<T>,
    ) -> Result<T> {
        let mut ledger = self
            .ledger
            .lock()
            .map_err(|_| codes::SUPERVISOR_NOT_READY)?;
        let mut connection = GateLedger {
            host: self,
            ledger: &mut ledger,
            scope,
        };
        connection.transaction(|_| Ok(()))?;
        let result = operation(&mut connection)?;
        connection.transaction(|_| Ok(()))?;
        Ok(result)
    }
    pub fn binding(&self) -> Result<BindingState> {
        self.transaction(|txn| {
            let version = txn.current_version()?;
            if version.epoch == 0 {
                return Ok(BindingState::Unbound);
            }
            Ok(BindingState::Bound(PrincipalScope {
                subject: txn.gate_owner_subject()?,
                epoch: version.epoch,
            }))
        })
    }
    pub fn require_scope(txn: &aura::LedgerTxn<'_>, scope: PrincipalScope) -> Result<()> {
        if txn.current_version()?.epoch != scope.epoch || txn.gate_owner_subject()? != scope.subject
        {
            return Err(codes::AUMLOK_BINDING_REQUIRED);
        }
        Ok(())
    }
    pub fn scoped<T>(
        &self,
        scope: PrincipalScope,
        operation: impl FnOnce(&mut aura::LedgerTxn<'_>) -> Result<T>,
    ) -> Result<T> {
        self.transaction(|txn| {
            Self::require_scope(txn, scope)?;
            operation(txn)
        })
    }
    pub fn record_host_boot(
        &self,
        facts: &launcher::boot::HostBootFacts,
    ) -> Result<launcher::boot::BootReceipt> {
        self.boot(facts.kind(), facts.to_body()?)
    }
    pub fn record_guest_boot(
        &self,
        facts: &launcher::boot::BootFacts,
    ) -> Result<launcher::boot::BootReceipt> {
        self.boot(facts.kind(), facts.to_body()?)
    }
    pub fn record_scoped_guest_boot(
        &self,
        scope: PrincipalScope,
        facts: &launcher::boot::BootFacts,
    ) -> Result<launcher::boot::BootReceipt> {
        let body = facts.to_body()?;
        self.scoped(scope, |txn| Self::append_boot(txn, facts.kind(), body))
    }
    fn boot(
        &self,
        kind: canon::authority::FactKind,
        body: canon::json::Value,
    ) -> Result<launcher::boot::BootReceipt> {
        self.transaction(|txn| Self::append_boot(txn, kind, body))
    }
    fn append_boot(
        txn: &mut aura::LedgerTxn<'_>,
        kind: canon::authority::FactKind,
        body: canon::json::Value,
    ) -> Result<launcher::boot::BootReceipt> {
        let context = txn.observation_context()?;
        let row = txn.append_fact(FactRecord {
            v: 1,
            algorithm: AlgorithmId::Sha256,
            authority: context.authority,
            at: context.at,
            kind,
            actor: "supervisor".into(),
            body,
        })?;
        Ok(launcher::boot::BootReceipt {
            sequence: row.authority.sequence,
            entry_sha256: row.hash,
        })
    }
}
impl BindingService for HostLedger {
    fn current(&self) -> ServiceFuture<'_, BindingState> {
        Box::pin(async { self.binding() })
    }
}
impl supervisor::runtime::BootFactService for HostLedger {
    fn append_host_boot_facts(
        &mut self,
        facts: &launcher::boot::HostBootFacts,
    ) -> Result<launcher::boot::BootReceipt> {
        self.boot(facts.kind(), facts.to_body()?)
    }
    fn append_boot_facts(
        &mut self,
        facts: &launcher::boot::BootFacts,
    ) -> Result<launcher::boot::BootReceipt> {
        self.boot(facts.kind(), facts.to_body()?)
    }
}
