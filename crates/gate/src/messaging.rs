// SPDX-License-Identifier: AGPL-3.0-or-later
//! Exact contact cards used by the supervisor's owner approval flow.
use canon::{
    authority::{Card, CardRisk},
    json::{Value, ValueView},
    Result,
};

pub const CONTACT_TARGET: &str = "messaging/contacts.json";

/// A character a contact label may not hold: controls, and the invisible and bidirectional formatting characters that
/// could reorder or hide the npub printed beside the label on the owner's card. Shared with `messaging`.
pub fn label_char_refused(c: char) -> bool {
    c.is_control()
        || crate::card::hidden_category(c).is_some()
        || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2028}' | '\u{2029}' | '\u{2060}'..='\u{2069}')
}

/// The one line a contact card says, shared with `messaging::OwnerAction::card` so both build the same C6 bytes.
/// It names the exact Aukora ID (the npub) being approved, says that this approves an ID and not a person, and asks
/// the owner to compare the ID with the other person through a channel they already trust before approving.
pub fn contact_says(add: bool, key: [u8; 32]) -> String {
    let npub = canon::provenance::Npub::from_key_bytes(key);
    if add {
        format!(
            "Approve this exact Aukora ID as a contact: {}. This approves the ID, not the person. Before you \
             approve, compare it with them in person or on a call you trust.",
            npub.as_str()
        )
    } else {
        format!("Remove this Aukora ID from your approved contacts: {}.", npub.as_str())
    }
}

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
    let (names, add) = match text("op")? {
        "contact.add" => {
            let label = text("label")?;
            if label.is_empty()
                || label.len() > 160
                || label.chars().any(label_char_refused)
                || !matches!(value.get("pairing").map(Value::view), Some(ValueView::Null))
            {
                return Err(invalid);
            }
            (&["schema", "op", "key", "label", "pairing"][..], true)
        }
        "contact.remove" => (&["schema", "op", "key"][..], false),
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
    let mut bytes = [0; 32];
    hex::decode_to_slice(key, &mut bytes).map_err(|_| invalid)?;
    Ok(Card {
        v: 1,
        risk: CardRisk::Critical,
        says: contact_says(add, bytes),
        facts: fields.to_vec(),
        from_to: vec![("contact".into(), Value::text(key.into())?)],
        model_note: String::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action(op: &str, key: &str) -> Vec<u8> {
        let tail = if op == "contact.add" { r#","label":"Mira","op":"contact.add","pairing":null"# } else { r#","op":"contact.remove""# };
        format!(r#"{{"key":"{key}"{tail},"schema":"aukora:messaging-action:v1"}}"#).into_bytes()
    }

    #[test]
    fn a_contact_card_names_the_exact_aukora_id_and_approves_an_id_not_a_person() {
        // The NIP-19 example key: npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6.
        let key = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
        let npub = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";
        let add = contact_card(&action("contact.add", key)).unwrap();
        assert!(add.says.contains(npub), "{}", add.says);
        assert!(add.says.contains("This approves the ID, not the person."));
        assert!(add.says.contains("compare it with them in person or on a call you trust"));
        assert!(!add.says.contains('\n'));
        add.canonical_bytes().unwrap();
        let remove = contact_card(&action("contact.remove", key)).unwrap();
        assert_eq!(remove.says, format!("Remove this Aukora ID from your approved contacts: {npub}."));
        // A label cannot reorder or hide the npub the owner compares (a plain non-ASCII label still passes).
        let good = format!(r#"{{"key":"{key}","label":"Mira 雪","op":"contact.add","pairing":null,"schema":"aukora:messaging-action:v1"}}"#);
        assert!(contact_card(good.as_bytes()).is_ok());
        for bad in ["\u{202E}lim", "Mi\u{200F}ra", "a\u{2066}b", "\u{FEFF}x", "x\u{2028}y", "\u{061C}Mira", "Pay \u{FFF9}",
            "a\u{00AD}b", "x\u{FE0F}", "t\u{E0041}g", "p\u{E000}u"] {
            let bytes = format!(r#"{{"key":"{key}","label":"{bad}","op":"contact.add","pairing":null,"schema":"aukora:messaging-action:v1"}}"#);
            assert!(contact_card(bytes.as_bytes()).is_err(), "{bad:?}");
        }
        // A key that is not lowercase hex never reaches the wording.
        assert!(contact_card(&action("contact.add", &key.to_uppercase())).is_err());
    }
}
