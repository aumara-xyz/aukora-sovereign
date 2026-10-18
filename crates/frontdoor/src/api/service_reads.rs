// SPDX-License-Identifier: AGPL-3.0-or-later
//! Versioned shell reads with a closed capability table and an approved-release identity.

use crate::{
    assets::{ApprovedRelease, AssetKind, AssetSurface},
    ingress::{AdmittedRequest, HostRole, Method},
};
use canon::{
    digest::Digest32,
    json::{Value, ValueView},
    Refusal, Result,
};

pub const PATH: &str = "/api/faces/read";
pub const SCHEMA: &str = "aukora-face-read-v1";

/// Created only after the release contains the face and this read is in its fixed grant table.
pub struct AuthorizedRead {
    face: String,
    service: String,
    method: String,
    params: Value,
    manifest: Digest32,
    assets: usize,
}
impl AuthorizedRead {
    pub fn face(&self) -> &str {
        &self.face
    }
    pub fn service(&self) -> &str {
        &self.service
    }
    pub fn method(&self) -> &str {
        &self.method
    }
    pub fn params(&self) -> &Value {
        &self.params
    }
    pub const fn manifest(&self) -> Digest32 {
        self.manifest
    }
    pub const fn assets(&self) -> usize {
        self.assets
    }
}

pub fn resolve(role: HostRole, method: Method, path: &str) -> Result<()> {
    if role != HostRole::Shell {
        return Err(canon::codes::FRONTDOOR_HOST_REFUSED);
    }
    crate::ingress::validate_path(path)?;
    if method != Method::Post || path != PATH {
        return Err(canon::codes::FRONTDOOR_UNKNOWN_ROUTE);
    }
    Ok(())
}

/// The host must revalidate the release's current floor approval before calling this function.
/// Authentication is separate: retain the live BoundSession guard through the read itself.
pub fn authorize(release: &ApprovedRelease, request: &AdmittedRequest) -> Result<AuthorizedRead> {
    resolve(request.role(), request.method(), request.path())?;
    let value = request.body();
    let ValueView::Object(fields) = value.view() else {
        return Err(invalid());
    };
    let names = ["schema", "face", "service", "method", "params"];
    if fields.len() != names.len() || fields.iter().any(|(key, _)| !names.contains(&key.as_str())) {
        return Err(invalid());
    }
    if text(value, "schema")? != SCHEMA {
        return Err(invalid());
    }
    let face = text(value, "face")?;
    let service = text(value, "service")?;
    let method = text(value, "method")?;
    if !permitted(face, service, method) {
        return Err(denied());
    }
    let expected = format!("app/faces/{face}/index.html");
    if release
        .entries()
        .iter()
        .filter(|entry| {
            entry.surface == AssetSurface::Face
                && entry.kind == AssetKind::Html
                && entry.path == expected
        })
        .count()
        != 1
    {
        return Err(denied());
    }
    let params = value.get("params").ok_or_else(invalid)?;
    if !matches!(params.view(), ValueView::Object(_)) {
        return Err(invalid());
    }
    Ok(AuthorizedRead {
        face: face.to_owned(),
        service: service.to_owned(),
        method: method.to_owned(),
        params: params.clone(),
        manifest: release.manifest_sha256(),
        assets: release.entries().len(),
    })
}

fn permitted(face: &str, service: &str, method: &str) -> bool {
    matches!(
        (face, service, method),
        ("aumlok", "aumlok", "status")
            | ("identity", "aumlok", "identity")
            | ("messages", "aumlok", "identity")
            | ("coherence", "gate-aura", "head")
            | ("documents", "kira", "documents.list" | "documents.read")
            | ("memory", "kira", "memory.list" | "memory.recall")
            | ("humangraph", "network", "contacts.list")
            | (
                "messages",
                "network",
                "contacts.list" | "messages.list" | "refusals.counts" | "contact.propose" | "send"
            )
            | (
                "threads" | "sidebar" | "archived",
                "body",
                "session.list" | "session.open"
            )
            | ("general", "body", "settings.general")
            | ("models", "body", "settings.models")
            | ("models", "broker", "model.report")
            | ("plugins", "body", "settings.plugins")
            | ("presets", "body", "settings.presets")
            | (
                "coherence",
                "body",
                "health.snapshot" | "health.snapshot.page.v2"
            )
    )
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    match value.get(key).map(Value::view) {
        Some(ValueView::Text(value)) => Ok(value),
        _ => Err(invalid()),
    }
}
const fn invalid() -> Refusal {
    Refusal {
        organ: "frontdoor",
        reason: "body-invalid",
    }
}
const fn denied() -> Refusal {
    Refusal {
        organ: "frontdoor",
        reason: "capability-denied",
    }
}

/// Authorizes the version 3 FD 4 read body against the approved face inventory.
/// The host retains its shell session and floor guards while performing the read.
pub fn authorize_data(release: &ApprovedRelease, value: &Value) -> Result<AuthorizedRead> {
    let ValueView::Object(fields) = value.view() else {
        return Err(invalid());
    };
    let names = ["schema", "face", "service", "method", "params"];
    if fields.len() != names.len() || fields.iter().any(|(key, _)| !names.contains(&key.as_str())) {
        return Err(invalid());
    }
    if text(value, "schema")? != "aukora:face-service:v3" {
        return Err(invalid());
    }
    let face = text(value, "face")?;
    let service = text(value, "service")?;
    let method = text(value, "method")?;
    if !permitted(face, service, method) {
        return Err(denied());
    }
    let expected = format!("app/faces/{face}/index.html");
    if release
        .entries()
        .iter()
        .filter(|entry| {
            entry.surface == AssetSurface::Face
                && entry.kind == AssetKind::Html
                && entry.path == expected
        })
        .count()
        != 1
    {
        return Err(denied());
    }
    let params = value.get("params").ok_or_else(invalid)?;
    if !matches!(params.view(), ValueView::Object(_)) {
        return Err(invalid());
    }
    Ok(AuthorizedRead {
        face: face.to_owned(),
        service: service.to_owned(),
        method: method.to_owned(),
        params: params.clone(),
        manifest: release.manifest_sha256(),
        assets: release.entries().len(),
    })
}

#[cfg(test)]
mod messaging_tests {
    use super::*;

    #[test]
    fn owner_shell_messages_has_writes_but_engine_origin_is_refused() {
        assert!(permitted("messages", "network", "contact.propose"));
        assert!(permitted("messages", "network", "send"));
        assert!(!permitted("humangraph", "network", "send"));
        assert!(!permitted("threads", "network", "send"));
        assert!(resolve(HostRole::Shell, Method::Post, PATH).is_ok());
        assert_eq!(
            resolve(HostRole::Owner, Method::Post, PATH),
            Err(canon::codes::FRONTDOOR_HOST_REFUSED)
        );
        let boundary = crate::tls::CaddyBoundary {
            shell: crate::tls::Origin::parse("https://node.example").unwrap(),
            owner: crate::tls::Origin::parse("https://owner.node.example").unwrap(),
            registered_site: crate::tls::Origin::parse("https://node.example").unwrap(),
            allowed_proxy_peers: vec!["127.0.0.1".parse().unwrap()],
        };
        assert!(matches!(boundary.admit(crate::tls::ProxyObservation {
            peer: "127.0.0.1".parse().unwrap(), forwarded_proto: vec!["https".into()],
            host: vec!["engine.node.example".into()],
        }), Err(code) if code == canon::codes::FRONTDOOR_HOST_REFUSED));
    }
}
