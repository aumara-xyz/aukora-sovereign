// SPDX-License-Identifier: AGPL-3.0-or-later
use super::{refuse, wire};
use canon::{json::Value, Result};
use supervisor::ingress::PrincipalScope;

pub struct Page<T> {
    pub items: Vec<T>,
    pub next: Option<String>,
}

pub struct Message {
    pub id: String,
    pub direction: Direction,
    pub contact: nostr::PublicKey,
    pub at: u64,
    pub text: String,
    pub state: Option<SendState>,
}
pub enum Direction {
    In,
    Out,
}
pub enum SendState {
    Queued,
    Published,
    Unconfirmed,
    Failed(canon::Refusal),
}

pub trait NetworkRead: Send + Sync {
    fn contacts(
        &self,
        scope: PrincipalScope,
        before: Option<&str>,
        limit: usize,
    ) -> Result<Page<messaging::ApprovedContact>>;
    fn messages(
        &self,
        scope: PrincipalScope,
        before: Option<&str>,
        limit: usize,
    ) -> Result<Page<Message>>;
    fn refusals(&self, scope: PrincipalScope) -> Result<messaging::RefusalCounts>;
}

pub fn call(
    source: &dyn NetworkRead,
    scope: PrincipalScope,
    method: &str,
    params: &Value,
) -> Result<Value> {
    if method == "refusals.counts" {
        wire::exact(params, &[])?;
        let counts = source.refusals(scope)?;
        let total = [
            counts.envelope,
            counts.signature,
            counts.recipient,
            counts.stranger,
            counts.replay,
            counts.payload,
            counts.stale_contact,
        ]
        .into_iter()
        .try_fold(0u64, |sum, value| sum.checked_add(value))
        .ok_or(refuse("face-counts-invalid"))?;
        if total != counts.total {
            return Err(refuse("face-counts-invalid"));
        }
        return wire::object([
            ("envelope", wire::number(counts.envelope)?),
            ("signature", wire::number(counts.signature)?),
            ("recipient", wire::number(counts.recipient)?),
            ("stranger", wire::number(counts.stranger)?),
            ("replay", wire::number(counts.replay)?),
            ("payload", wire::number(counts.payload)?),
            ("stale_contact", wire::number(counts.stale_contact)?),
            ("total", wire::number(counts.total)?),
            (
                "last_aura_sequence",
                wire::number(counts.last_aura_sequence)?,
            ),
        ]);
    }
    wire::exact(params, &["before", "limit"])?;
    let before = wire::optional_string(wire::field(params, "before")?)?;
    if before.is_some_and(|value| !cursor(value)) {
        return Err(refuse("face-page-invalid"));
    }
    let limit = wire::unsigned(wire::field(params, "limit")?)?;
    if !(1..=100).contains(&limit) {
        return Err(refuse("face-page-invalid"));
    }
    let (items, next) = match method {
        "contacts.list" => {
            let page = source.contacts(scope, before, limit as usize)?;
            (
                page.items.iter().map(contact).collect::<Result<Vec<_>>>()?,
                page.next,
            )
        }
        "messages.list" => {
            let page = source.messages(scope, before, limit as usize)?;
            (
                page.items.iter().map(message).collect::<Result<Vec<_>>>()?,
                page.next,
            )
        }
        _ => return Err(refuse("face-operation-unknown")),
    };
    if items.len() > limit as usize
        || next
            .as_deref()
            .is_some_and(|value| !cursor(value) || Some(value) == before)
    {
        return Err(refuse("face-page-invalid"));
    }
    wire::bounded(wire::object([
        ("items", Value::array(items)?),
        (
            "next",
            next.map(wire::text)
                .transpose()?
                .unwrap_or_else(Value::null),
        ),
    ])?)
}
fn cursor(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}
fn contact(contact: &messaging::ApprovedContact) -> Result<Value> {
    let key = contact.key().to_npub()?;
    let pairing = contact
        .pairing()
        .map(|pairing| {
            let method = match pairing.method() {
                messaging::PairingMethod::ScreenToScreen => "screen-to-screen",
                messaging::PairingMethod::Remote => "remote",
                messaging::PairingMethod::Relayed => "relayed",
                messaging::PairingMethod::Unknown => "unknown",
            };
            wire::object([
                ("method", wire::text(method)?),
                ("verified_at", wire::number(pairing.verified_at_ms())?),
                ("verified_at_ms", wire::number(pairing.verified_at_ms())?),
            ])
        })
        .transpose()?
        .unwrap_or_else(Value::null);
    wire::object([
        ("key", wire::text(key.as_str())?),
        ("npub", wire::text(key.as_str())?),
        ("label", wire::text(contact.label())?),
        ("pairing", pairing),
    ])
}
fn message(message: &Message) -> Result<Value> {
    if !cursor(&message.id)
        || message.text.is_empty()
        || message.text.len() > messaging::MAX_MESSAGE_BYTES
        || matches!(message.direction, Direction::In) != message.state.is_none()
    {
        return Err(refuse("face-message-invalid"));
    }
    let (state, code) = match message.state.as_ref() {
        None => (Value::null(), Value::null()),
        Some(SendState::Queued) => (wire::text("queued")?, Value::null()),
        Some(SendState::Published) => (wire::text("published")?, Value::null()),
        Some(SendState::Unconfirmed) => (wire::text("unconfirmed")?, Value::null()),
        Some(SendState::Failed(code)) => (
            wire::text("failed")?,
            wire::text(format!("{}:{}", code.organ, code.reason))?,
        ),
    };
    wire::object([
        ("id", wire::text(&message.id)?),
        (
            "direction",
            wire::text(match message.direction {
                Direction::In => "in",
                Direction::Out => "out",
            })?,
        ),
        ("contact", wire::text(message.contact.to_npub()?.as_str())?),
        ("at", wire::number(message.at)?),
        ("text", wire::text(&message.text)?),
        ("transport", wire::text("nostr-relays")?),
        ("state", state),
        ("code", code),
    ])
}
