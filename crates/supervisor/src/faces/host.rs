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

    /// Requires the host's `spawn_blocking` request task with its live-session lock held.
    /// The entered Tokio runtime drives organ futures; a runtime worker must not call
    /// this synchronous method because its `Handle::block_on` would panic.
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

impl HostFaces {
    /// Additional read-only views retain the shell session and the binding epoch.
    pub fn dispatch_extended(
        &self,
        session: &BoundSession<'_>,
        read: &AuthorizedRead,
        root: &DocumentRoot,
    ) -> Result<Value> {
        use super::wire;
        use canon::authority::{AuthorityTxn, Kind};

        if !matches!(
            (read.service(), read.method()),
            ("aumlok", "status" | "identity") | ("gate-aura", "head")
        ) {
            return self.dispatch(session, read, root);
        }
        wire::exact(read.params(), &[])?;
        let record = session.record();
        let scope = PrincipalScope {
            subject: record.subject.ok_or(codes::AUMLOK_BINDING_REQUIRED)?,
            epoch: record.owner_epoch,
        };
        if record.scope != SessionScope::Shell {
            return Err(codes::AUMLOK_BINDING_REQUIRED);
        }
        self.recheck(scope)?;
        let value = match (read.service(), read.method()) {
            ("gate-aura", "head") => self.ledger.with_read_ledger(|ledger| {
                wire::object([("head", wire::text(ledger.retained_head()?.root.to_string())?)])
            })?,
            ("aumlok", "status") => return Err(refuse("aumlok-status-unavailable")),
            ("aumlok", "identity") => self.ledger.scoped(scope, |txn| {
                let owner = txn
                    .bound_owner_identity()?
                    .ok_or(codes::AUMLOK_BINDING_REQUIRED)?;
                if owner.subject != scope.subject {
                    return Err(codes::AUMLOK_BINDING_REQUIRED);
                }
                let version = txn.current_version()?;
                for sequence in 1..version.sequence {
                    let row = txn
                        .floor_record_at_sequence(sequence)?
                        .ok_or(codes::AURA_UNVERIFIED)?;
                    if row.kind == Kind::NostrBind {
                        return Err(refuse("identity-network-projection-unavailable"));
                    }
                }
                let label = owner.credential.owner_id;
                if label.trim() != label
                    || label.is_empty()
                    || label.chars().count() > 64
                    || label.chars().any(|character| {
                        character.is_control()
                            || matches!(character, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}'
                                | '\u{2060}'..='\u{2069}' | '\u{feff}')
                    })
                {
                    return Err(refuse("identity-label-invalid"));
                }
                wire::object([
                    ("agent_npub", Value::null()),
                    ("contact_code", Value::null()),
                    ("label", wire::text(label)?),
                    ("node_npub", Value::null()),
                    ("safety", Value::array(Vec::new())?),
                    ("subject", wire::text(owner.subject.to_string())?),
                ])
            })?,
            _ => return Err(refuse("face-operation-unknown")),
        };
        self.recheck(scope)?;
        wire::bounded(value)
    }
}
