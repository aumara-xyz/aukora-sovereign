// SPDX-License-Identifier: AGPL-3.0-or-later
//! Principal-scoped reads from the live Messaging store and its owning Aura projections.
use super::{
    network::{Message, NetworkRead, Page},
    refuse,
};
use crate::adapters::HostLedger;
use canon::Result;
use std::sync::{Arc, Mutex};
use supervisor::ingress::PrincipalScope;

pub struct LiveNetwork {
    ledger: Arc<HostLedger>,
    store: Mutex<messaging::Messaging>,
}
impl LiveNetwork {
    pub fn new(ledger: Arc<HostLedger>, store: messaging::Messaging) -> Self {
        Self {
            ledger,
            store: Mutex::new(store),
        }
    }
}
impl NetworkRead for LiveNetwork {
    fn contacts(
        &self,
        scope: PrincipalScope,
        before: Option<&str>,
        _limit: usize,
    ) -> Result<Page<messaging::ApprovedContact>> {
        before.map(nostr::PublicKey::from_npub).transpose()?;
        self.ledger
            .scoped(scope, |_| Err(refuse("contact-projection-unavailable")))
    }
    fn messages(
        &self,
        scope: PrincipalScope,
        _before: Option<&str>,
        _limit: usize,
    ) -> Result<Page<Message>> {
        self.ledger
            .scoped(scope, |_| Err(refuse("message-history-unavailable")))
    }
    fn refusals(&self, scope: PrincipalScope) -> Result<messaging::RefusalCounts> {
        self.ledger.scoped(scope, |txn| {
            self.store
                .lock()
                .map_err(|_| refuse("network-store-unavailable"))?
                .refresh_refusal_counts(txn)
        })
    }
}
