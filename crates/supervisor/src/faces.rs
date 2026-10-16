// SPDX-License-Identifier: AGPL-3.0-or-later
//! Versioned face projections. These reads confer no authority.

use canon::{json::Value, Refusal};
use supervisor::{
    ingress::{BindingState, PrincipalScope},
    services::{BindingService, KiraService, ServiceFuture},
    session::SessionStore,
};

pub mod documents;
pub mod events;
pub mod health;
pub mod host;
pub mod live_network;
pub mod model_settings;
pub mod network;
pub mod settings;
mod wire;

pub const CONTRACT: &str = "aukora-face-services-v1";
pub const MAX_REPLY_BYTES: usize = 60_000;

/// The host supplies live stores; an absent source is unavailable, never an empty report.
pub struct FaceServices<'a> {
    pub binding: &'a dyn BindingService,
    pub kira: Option<&'a dyn KiraService>,
    pub sessions: Option<&'a dyn SessionStore>,
    pub network: Option<&'a dyn network::NetworkRead>,
    pub settings: Option<&'a dyn settings::SettingsRead>,
    pub health: Option<&'a dyn health::HealthRead>,
}

impl FaceServices<'_> {
    pub fn call<'a>(
        &'a self,
        scope: PrincipalScope,
        service: &'a str,
        method: &'a str,
        params: Value,
    ) -> ServiceFuture<'a, Value> {
        Box::pin(async move {
            if self.binding.current().await? != BindingState::Bound(scope) {
                return Err(canon::codes::AUMLOK_BINDING_REQUIRED);
            }
            let value = match (service, method) {
                ("kira", "memory.list" | "memory.recall") => {
                    let kira = self.kira.ok_or(refuse("memory-unavailable"))?;
                    let request = wire::request(method, params)?;
                    let reply = match request {
                        canon::fd3::Request::MemoryList(request) => {
                            canon::fd3::Reply::MemoryListReply(kira.list(scope, request).await?)
                        }
                        canon::fd3::Request::MemoryRecall(request) => {
                            canon::fd3::Reply::Recall(kira.recall(scope, request).await?)
                        }
                        _ => return Err(refuse("face-operation-unknown")),
                    };
                    wire::reply(reply)?
                }
                ("body", "session.list" | "session.open") => {
                    let sessions = self.sessions.ok_or(refuse("sessions-unavailable"))?;
                    let request = wire::command(method, params)?;
                    let event = match request {
                        canon::fd4::ChatCommand::ListSessions(request) => {
                            canon::fd4::SessionEvent::Listed(sessions.list(scope, request).await?)
                        }
                        canon::fd4::ChatCommand::OpenSession(request) => {
                            canon::fd4::SessionEvent::Opened(sessions.open(scope, request).await?)
                        }
                        _ => return Err(refuse("face-operation-unknown")),
                    };
                    wire::owner_event(event)?
                }
                ("network", "contacts.list" | "messages.list" | "refusals.counts") => {
                    network::call(
                        self.network.ok_or(refuse("network-unavailable"))?,
                        scope,
                        method,
                        &params,
                    )?
                }
                (
                    "body",
                    "settings.general" | "settings.models" | "settings.plugins"
                    | "settings.presets",
                ) => {
                    wire::exact(&params, &[])?;
                    settings::call(
                        self.settings.ok_or(refuse("settings-unavailable"))?,
                        scope,
                        method,
                    )?
                }
                ("body", "health.snapshot" | "health.snapshot.page.v2") => health::call(
                    self.health.ok_or(refuse("health-unavailable"))?,
                    method,
                    &params,
                )?,
                _ => return Err(refuse("face-operation-unknown")),
            };
            wire::bounded(value)
        })
    }
}

pub(crate) const fn refuse(reason: &'static str) -> Refusal {
    Refusal {
        organ: "supervisor",
        reason,
    }
}
