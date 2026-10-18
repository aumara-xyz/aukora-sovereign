// SPDX-License-Identifier: AGPL-3.0-or-later
//! Exact contact cards used by the supervisor's owner approval flow.
use canon::{
    authority::{Card, CardRisk},
    json::{Value, ValueView},
    Result,
};

pub const CONTACT_TARGET: &str = "messaging/contacts.json";
pub const SEND_TARGET: &str = "messaging/send.json";

/// This closed card has the same C6 bytes as `messaging::OwnerAction::card`.
/// Co-presence claims are unavailable until the host can verify that ceremony.
pub fn contact_card(bytes: &[u8]) -> Result<Card> {
    let invalid = crate::refuse("contact-action-invalid");
    if bytes.len() > 8192 {
        return Err(invalid);
    }
    let value = canon::json::parse_strict(bytes).map_err(|_| invalid)?;
    let ValueView::Object(fields) = value.view() else {
        return Err(invalid);
    };
    let text = |name| match value.get(name).map(Value::view) {
        Some(ValueView::Text(text)) => Ok(text),
        _ => Err(invalid),
    };
    if value.canonical_bytes() != bytes || text("schema")? != "aukora:messaging-action:v1" {
        return Err(invalid);
    }
    let (names, says) = match text("op")? {
        "contact.add" => {
            let label = text("label")?;
            if label.is_empty()
                || label.len() > 160
                || label.chars().any(char::is_control)
                || !matches!(value.get("pairing").map(Value::view), Some(ValueView::Null))
            {
                return Err(invalid);
            }
            (
                &["schema", "op", "key", "label", "pairing"][..],
                "Add an approved contact",
            )
        }
        "contact.remove" => (&["schema", "op", "key"][..], "Remove an approved contact"),
        _ => return Err(invalid),
    };
    let key = text("key")?;
    if fields.len() != names.len()
        || names.iter().any(|name| value.get(name).is_none())
        || key.len() != 64
        || !key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid);
    }
    Ok(Card {
        v: 1,
        risk: CardRisk::Critical,
        says: says.into(),
        facts: fields.to_vec(),
        from_to: vec![("contact".into(), Value::text(key.into())?)],
        model_note: String::new(),
    })
}
