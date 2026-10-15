// SPDX-License-Identifier: AGPL-3.0-or-later
//! Approved shell reads mapped to the same organ instances used by the supervisor.
use super::{
    documents,
    health::HealthRead,
    network::NetworkRead,
    refuse,
    settings::{self, SettingsRead},
    FaceServices,
};
use crate::adapters::{BrokerAdapter, HostLedger};
use canon::{codes, json::Value, Result};
use frontdoor::{
    api::service_reads::AuthorizedRead,
    documents::DocumentRoot,
    session::{BoundSession, SessionScope},
};
use std::{sync::Arc, time::Duration};
use supervisor::{
    ingress::{BindingState, PrincipalScope},
    services::KiraService,
    session::SessionStore,
};

pub struct HostFaces {
    ledger: Arc<HostLedger>,
    sessions: Arc<dyn SessionStore>,
    health: Arc<dyn HealthRead>,
    broker: Arc<BrokerAdapter>,
    kira: Option<Arc<dyn KiraService>>,
    network: Option<Arc<dyn NetworkRead>>,
}
impl HostFaces {
    pub fn new(
        ledger: Arc<HostLedger>,
        sessions: Arc<dyn SessionStore>,
        health: Arc<dyn HealthRead>,
        broker: Arc<BrokerAdapter>,
    ) -> Self {
        Self {
            ledger,
            sessions,
            health,
            broker,
            kira: None,
            network: None,
        }
    }
    pub fn with_kira(mut self, kira: Arc<dyn KiraService>) -> Self {
        self.kira = Some(kira);
        self
    }
    pub fn with_network(mut self, network: Arc<dyn NetworkRead>) -> Self {
        self.network = Some(network);
        self
    }

    /// Called on the host's blocking request task while its live-session lock is held.
    pub fn dispatch(
        &self,
        session: &BoundSession<'_>,
        read: &AuthorizedRead,
        root: &DocumentRoot,
    ) -> Result<Value> {
        let record = session.record();
        let scope = PrincipalScope {
            subject: record.subject.ok_or(codes::AUMLOK_BINDING_REQUIRED)?,
            epoch: record.owner_epoch,
        };
        if record.scope != SessionScope::Shell
            || self.ledger.binding()? != BindingState::Bound(scope)
        {
            return Err(codes::AUMLOK_BINDING_REQUIRED);
        }
        if read.service() == "kira" && matches!(read.method(), "documents.list" | "documents.read")
        {
            let value = documents::call(root, session, read.method(), read.params())?;
            self.recheck(scope)?;
            return Ok(value);
        }
        let settings = LiveSettings {
            read,
            broker: &self.broker,
        };
        let services = FaceServices {
            binding: self.ledger.as_ref(),
            sessions: Some(self.sessions.as_ref()),
            health: Some(self.health.as_ref()),
            settings: Some(&settings),
            kira: self.kira.as_deref(),
            network: self.network.as_deref(),
        };
        let value = tokio::runtime::Handle::try_current()
            .map_err(|_| refuse("face-runtime-unavailable"))?
            .block_on(async {
                tokio::time::timeout(
                    Duration::from_secs(5),
                    services.call(scope, read.service(), read.method(), read.params().clone()),
                )
                .await
                .map_err(|_| refuse("face-read-deadline"))?
            })?;
        self.recheck(scope)?;
        Ok(value)
    }

    fn recheck(&self, scope: PrincipalScope) -> Result<()> {
        if self.ledger.binding()? != BindingState::Bound(scope) {
            return Err(codes::AUMLOK_BINDING_REQUIRED);
        }
        Ok(())
    }
}

struct LiveSettings<'a> {
    read: &'a AuthorizedRead,
    broker: &'a BrokerAdapter,
}
impl SettingsRead for LiveSettings<'_> {
    fn read(&self, scope: PrincipalScope, method: &str) -> Result<Value> {
        match method {
            "settings.general" => settings::release(self.read.manifest(), self.read.assets()),
            "settings.models" => self.broker.model_report(scope),
            "settings.plugins" => Err(refuse("shell-plugin-state-unavailable")),
            "settings.presets" => Err(refuse("harness-presets-unavailable")),
            _ => Err(refuse("face-operation-unknown")),
        }
    }
}
