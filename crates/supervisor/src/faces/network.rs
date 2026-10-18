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
    fn node_npub(&self) -> Result<Option<String>> {
        Ok(None)
    }
    fn contacts(
        &self,
        scope: PrincipalScope,
        before: Option<&str>,
        limit: usize,
    ) -> Result<Page<messaging::ApprovedContact>>;
    fn messages(
        &self,
        scope: PrincipalScope,
        contact: Option<nostr::PublicKey>,
        before: Option<&str>,
        limit: usize,
    ) -> Result<Page<Message>>;
    fn refusals(&self, scope: PrincipalScope) -> Result<messaging::RefusalCounts>;
    fn propose_contact(
        &self,
        _scope: PrincipalScope,
        _npub: &str,
        _label: Option<&str>,
    ) -> Result<Value> {
        Err(refuse("network-owner-actions-unavailable"))
    }
    fn remove_contact(&self, _scope: PrincipalScope, _npub: &str) -> Result<Value> {
        Err(refuse("network-owner-actions-unavailable"))
    }
    fn send(&self, _scope: PrincipalScope, _npub: &str, _text: &str) -> Result<Value> {
        Err(refuse("network-owner-actions-unavailable"))
    }
    /// The owner's pinned and archived marks on conversations (view state, never sent to a contact).
    fn conversation_marks(
        &self,
        _scope: PrincipalScope,
    ) -> Result<Vec<messaging::ConversationMark>> {
        Err(refuse("network-unavailable"))
    }
    fn mark_conversation(
        &self,
        _scope: PrincipalScope,
        _mark: messaging::ConversationMark,
    ) -> Result<()> {
        Err(refuse("network-owner-actions-unavailable"))
    }
}

pub fn call(
    source: &dyn NetworkRead,
    scope: PrincipalScope,
    method: &str,
    params: &Value,
) -> Result<Value> {
    if method == "contact.propose" {
        if params.get("label").is_some() {
            wire::exact(params, &["npub", "label"])?;
        } else {
            wire::exact(params, &["npub"])?;
        }
        let npub = wire::string(wire::field(params, "npub")?)?;
        let label = params
            .get("label")
            .map(wire::optional_string)
            .transpose()?
            .flatten();
        return source.propose_contact(scope, npub, label);
    }
    if method == "contact.remove" {
        wire::exact(params, &["npub"])?;
        return source.remove_contact(scope, wire::string(wire::field(params, "npub")?)?);
    }
    if method == "send" {
        wire::exact(params, &["npub", "text"])?;
        return source.send(
            scope,
            wire::string(wire::field(params, "npub")?)?,
            wire::string(wire::field(params, "text")?)?,
        );
    }
    if method == "conversation.mark" {
        wire::exact(params, &["archived", "npub", "pinned"])?;
        let npub = wire::string(wire::field(params, "npub")?)?;
        source.mark_conversation(
            scope,
            messaging::ConversationMark {
                contact: nostr::PublicKey::from_npub(npub)?,
                pinned: wire::boolean(wire::field(params, "pinned")?)?,
                archived: wire::boolean(wire::field(params, "archived")?)?,
            },
        )?;
        return wire::object([]);
    }
    if method == "conversations.marks" {
        wire::exact(params, &[])?;
        let items = source
            .conversation_marks(scope)?
            .iter()
            .map(|mark| {
                wire::object([
                    ("npub", wire::text(mark.contact.to_npub()?.as_str())?),
                    ("pinned", Value::boolean(mark.pinned)),
                    ("archived", Value::boolean(mark.archived)),
                ])
            })
            .collect::<Result<Vec<_>>>()?;
        return wire::bounded(wire::object([("items", Value::array(items)?)])?);
    }
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
    let contact_filter = if method == "messages.list" && params.get("npub").is_some() {
        wire::exact(params, &["before", "limit", "npub"])?;
        wire::optional_string(wire::field(params, "npub")?)?
            .map(nostr::PublicKey::from_npub)
            .transpose()?
    } else {
        wire::exact(params, &["before", "limit"])?;
        None
    };
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
            let page = source.messages(scope, contact_filter, before, limit as usize)?;
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
pub(super) fn message(message: &Message) -> Result<Value> {
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

#[cfg(test)]
mod contact_card_tests {
    use messaging::{ContactChange, ContactDraft, OwnerAction};

    #[test]
    fn gate_contact_card_is_the_exact_messaging_c6_for_add_and_remove() {
        let key = nostr::SecretKey::import(zeroize::Zeroizing::new([21; 32]))
            .unwrap()
            .public_key()
            .unwrap();
        for change in [
            ContactChange::Add(ContactDraft {
                key,
                label: "Owner B".into(),
                pairing: None,
            }),
            ContactChange::Remove { key },
        ] {
            let action = OwnerAction::Contact(change);
            let bytes = action.canonical_bytes().unwrap();
            let card = gate::messaging::contact_card(&bytes).unwrap();
            assert_eq!(
                card.canonical_bytes().unwrap(),
                action.card().unwrap().canonical_bytes().unwrap()
            );
            assert!(card.model_note.is_empty());
            assert_eq!(card.risk, canon::authority::CardRisk::Critical);
            // The owner compares this npub with the other person; the card names it, not a hex form alone.
            assert!(
                card.says.contains(key.to_npub().unwrap().as_str()),
                "{}",
                card.says
            );
        }
        let add = OwnerAction::Contact(ContactChange::Add(ContactDraft {
            key,
            label: "Owner B".into(),
            pairing: None,
        }));
        let says = add.card().unwrap().says;
        assert!(
            says.contains("This approves the ID, not the person."),
            "{says}"
        );
        assert!(says.contains("in person or on a call you trust"), "{says}");
        assert!(gate::messaging::contact_card(b"{}").is_err());
    }
}

#[cfg(test)]
mod conversation_mark_tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Marks(Mutex<Vec<messaging::ConversationMark>>);
    impl NetworkRead for Marks {
        fn contacts(
            &self,
            _: PrincipalScope,
            _: Option<&str>,
            _: usize,
        ) -> Result<Page<messaging::ApprovedContact>> {
            unreachable!()
        }
        fn messages(
            &self,
            _: PrincipalScope,
            _: Option<nostr::PublicKey>,
            _: Option<&str>,
            _: usize,
        ) -> Result<Page<Message>> {
            unreachable!()
        }
        fn refusals(&self, _: PrincipalScope) -> Result<messaging::RefusalCounts> {
            unreachable!()
        }
        fn conversation_marks(
            &self,
            _: PrincipalScope,
        ) -> Result<Vec<messaging::ConversationMark>> {
            Ok(self.0.lock().unwrap().clone())
        }
        fn mark_conversation(
            &self,
            _: PrincipalScope,
            mark: messaging::ConversationMark,
        ) -> Result<()> {
            self.0.lock().unwrap().push(mark);
            Ok(())
        }
    }

    #[test]
    fn a_conversation_mark_is_exact_booleans_for_one_npub_and_reads_back() {
        let scope = PrincipalScope {
            subject: canon::ids::SubjectId::from_digest(canon::digest::Digest32::from_bytes(
                [7; 32],
            )),
            epoch: 1,
        };
        let npub = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";
        let source = Marks::default();
        let params = |text: &str| canon::json::parse_strict(text.as_bytes()).unwrap();
        let set = format!(r#"{{"archived":false,"npub":"{npub}","pinned":true}}"#);
        assert_eq!(
            call(&source, scope, "conversation.mark", &params(&set)).unwrap(),
            wire::object([]).unwrap()
        );
        // Extra keys, a missing mark or a non-boolean are refused before the store sees them.
        for bad in [
            format!(r#"{{"archived":false,"npub":"{npub}","pinned":true,"label":"x"}}"#),
            format!(r#"{{"npub":"{npub}","pinned":true}}"#),
            format!(r#"{{"archived":0,"npub":"{npub}","pinned":true}}"#),
            r#"{"archived":false,"npub":"npub1nope","pinned":true}"#.to_owned(),
        ] {
            assert!(
                call(&source, scope, "conversation.mark", &params(&bad)).is_err(),
                "{bad}"
            );
        }
        let read = call(&source, scope, "conversations.marks", &params("{}")).unwrap();
        assert_eq!(
            String::from_utf8(read.canonical_bytes()).unwrap(),
            format!(r#"{{"items":[{{"archived":false,"npub":"{npub}","pinned":true}}]}}"#)
        );
    }

    #[test]
    fn the_largest_mark_list_fits_one_face_reply() {
        let scope = PrincipalScope {
            subject: canon::ids::SubjectId::from_digest(canon::digest::Digest32::from_bytes(
                [7; 32],
            )),
            epoch: 1,
        };
        let source = Marks::default();
        for n in 0..messaging::MAX_MARKS {
            let mut bytes = [0; 32];
            bytes[..8].copy_from_slice(&(n as u64 + 1).to_be_bytes());
            let key = nostr::SecretKey::import(zeroize::Zeroizing::new(bytes))
                .unwrap()
                .public_key()
                .unwrap();
            // "archived":false is the longer boolean; every row at its largest.
            source.0.lock().unwrap().push(messaging::ConversationMark {
                contact: key,
                pinned: false,
                archived: false,
            });
        }
        let read = call(&source, scope, "conversations.marks", &canon::json::parse_strict(b"{}").unwrap()).unwrap();
        assert!(read.canonical_bytes().len() <= crate::faces::MAX_REPLY_BYTES);
    }
}
