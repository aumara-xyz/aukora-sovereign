// SPDX-License-Identifier: AGPL-3.0-or-later
//! The published action/card vectors replay through the code that builds the owner's cards.
use crate::OwnerAction;
use canon::digest::Digest32;

const VECTORS: &str = include_str!("../vectors/action-card-v1.json");

#[test]
fn action_card_vectors_replay_byte_for_byte() {
    let vectors: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let accept = vectors["accept"].as_array().unwrap();
    assert_eq!(accept.len(), 5);
    for vector in accept {
        let name = vector["name"].as_str().unwrap();
        let action_bytes = vector["action_utf8"].as_str().unwrap().as_bytes();
        let action = OwnerAction::decode(action_bytes).unwrap();
        assert_eq!(action.canonical_bytes().unwrap(), action_bytes, "{name}");
        let card = action.card().unwrap().canonical_bytes().unwrap();
        assert_eq!(String::from_utf8(card.clone()).unwrap(), vector["card_utf8"].as_str().unwrap(), "{name}");
        assert_eq!(Digest32::sha256(&card).to_string(), vector["display_sha256"].as_str().unwrap(), "{name}");
        if matches!(action, OwnerAction::Contact(crate::ContactChange::Add(_))) {
            // The exact npub the owner compares out of band, and a key rather than a person.
            let says = vector["card"]["says"].as_str().unwrap();
            assert!(says.contains("npub1") && says.contains("This approves the key, not the person."), "{name}");
        }
    }
    for vector in vectors["refuse"].as_array().unwrap() {
        let name = vector["name"].as_str().unwrap();
        let refused = OwnerAction::decode(vector["action_utf8"].as_str().unwrap().as_bytes()).and_then(|action| action.card());
        let code = refused.err().map(|refusal| format!("{}:{}", refusal.organ, refusal.reason));
        assert_eq!(code.as_deref(), vector["code"].as_str(), "{name}");
    }
}

#[test]
fn a_contact_label_cannot_hold_bidi_or_invisible_formatting() {
    let key = nostr::SecretKey::import(zeroize::Zeroizing::new([5; 32])).unwrap().public_key().unwrap();
    let add = |label: &str| {
        OwnerAction::Contact(crate::ContactChange::Add(crate::ContactDraft { key, label: label.into(), pairing: None }))
    };
    assert!(add("Mira 雪").canonical_bytes().is_ok());
    for bad in ["\u{202E}lim", "Mi\u{200F}ra", "a\u{2066}b", "\u{FEFF}x", "x\u{200B}y", "tab\there", "\u{061C}Mira",
        "Pay \u{FFF9}", "a\u{00AD}b", "x\u{FE0F}", "t\u{E0041}g"] {
        assert!(add(bad).canonical_bytes().is_err(), "{bad:?}");
        assert!(add(bad).card().is_err(), "{bad:?}");
    }
}
