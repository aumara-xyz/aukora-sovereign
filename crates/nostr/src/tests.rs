// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{
    event::{self, Event, Rumor},
    hex_decode, hex_encode, nip44, nip59, npub_decode, npub_encode, verify, SecretKey,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    ChaCha20,
};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn fixture_key(number: u8) -> SecretKey {
    let mut secret = [0; 32];
    secret[31] = number;
    SecretKey::from_bytes(secret).unwrap()
}

fn vector_hex<const N: usize>(value: &Value, name: &str) -> [u8; N] {
    hex_decode(value[name].as_str().unwrap()).unwrap()
}

fn nip44_vectors() -> Value {
    serde_json::from_str(include_str!("../tests/vectors/nip44.vectors.json")).unwrap()
}

fn prime_vectors() -> Value {
    serde_json::from_str(include_str!("../tests/vectors/prime-vectors.json")).unwrap()
}

fn test_event() -> Event {
    Event::sign(
        &fixture_key(1),
        1_700_000_000,
        1,
        vec![vec!["subject".into(), "雪".into()]],
        "hello".into(),
    )
    .unwrap()
}

#[test]
fn antibody_official_nip44_vector_file_digest() {
    assert_eq!(
        hex_encode(&Sha256::digest(include_bytes!(
            "../tests/vectors/nip44.vectors.json"
        ))),
        "269ed0f69e4c192512cc779e78c555090cebc7c785b609e338a62afc3ce25040"
    );
}

#[test]
fn antibody_official_bip340_every_signing_and_verification_row() {
    let mut count = 0;
    for line in include_str!("../tests/vectors/bip340-test-vectors.csv")
        .lines()
        .skip(1)
    {
        let fields: Vec<_> = line.split(',').collect();
        let public = hex_decode(&fields[2].to_lowercase()).unwrap();
        let message: Vec<u8> = fields[4]
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        let signature = hex_decode(&fields[5].to_lowercase()).unwrap();
        assert_eq!(
            verify(&public, &message, &signature).is_ok(),
            fields[6] == "TRUE",
            "verify vector {}",
            fields[0]
        );
        if !fields[1].is_empty() {
            let key =
                SecretKey::from_bytes(hex_decode(&fields[1].to_lowercase()).unwrap()).unwrap();
            assert_eq!(key.public_key(), public, "key vector {}", fields[0]);
            let auxiliary = hex_decode(&fields[3].to_lowercase()).unwrap();
            assert_eq!(
                key.sign_with_aux(&message, &auxiliary).unwrap(),
                signature,
                "sign vector {}",
                fields[0]
            );
        }
        count += 1;
    }
    assert_eq!(count, 19);
}

#[test]
fn antibody_key_scalars_are_valid_and_signatures_use_fresh_auxiliary_randomness() {
    assert!(SecretKey::from_bytes([0; 32]).is_err());
    assert!(SecretKey::from_bytes([255; 32]).is_err());
    let key = SecretKey::generate().unwrap();
    assert_ne!(
        key.public_key(),
        SecretKey::generate().unwrap().public_key()
    );
    let first = key.sign(b"same message").unwrap();
    let second = key.sign(b"same message").unwrap();
    assert_ne!(first, second);
    verify(&key.public_key(), b"same message", &first).unwrap();
    verify(&key.public_key(), b"same message", &second).unwrap();
    assert!(verify(&key.public_key(), b"other message", &first).is_err());
}

#[test]
fn antibody_npub_checksum_kind_hrp_and_length_are_checked() {
    let key = fixture_key(1).public_key();
    let npub = npub_encode(&key).unwrap();
    assert_eq!(npub_decode(&npub).unwrap(), key);
    let mut corrupted = npub.clone().into_bytes();
    let last = corrupted.len() - 1;
    corrupted[last] = if corrupted[last] == b'q' { b'p' } else { b'q' };
    assert!(npub_decode(std::str::from_utf8(&corrupted).unwrap()).is_err());
    for encoded in [
        bech32::encode::<bech32::Bech32m>(bech32::Hrp::parse("npub").unwrap(), &key).unwrap(),
        bech32::encode::<bech32::Bech32>(bech32::Hrp::parse("nsec").unwrap(), &key).unwrap(),
        bech32::encode::<bech32::Bech32>(bech32::Hrp::parse("npub").unwrap(), &key[..31]).unwrap(),
    ] {
        assert!(npub_decode(&encoded).is_err());
    }
    assert!(npub_decode(&format!("N{}", &npub[1..])).is_err());
}

#[test]
fn antibody_official_nip44_conversation_keys_and_invalid_points() {
    let vectors = nip44_vectors();
    for value in vectors["v2"]["valid"]["get_conversation_key"]
        .as_array()
        .unwrap()
    {
        let key = SecretKey::from_bytes(vector_hex(value, "sec1")).unwrap();
        assert_eq!(
            *nip44::get_conversation_key(&key, &vector_hex(value, "pub2")).unwrap(),
            vector_hex::<32>(value, "conversation_key")
        );
    }
    for value in vectors["v2"]["invalid"]["get_conversation_key"]
        .as_array()
        .unwrap()
    {
        let result = SecretKey::from_bytes(vector_hex(value, "sec1"))
            .and_then(|key| nip44::get_conversation_key(&key, &vector_hex(value, "pub2")));
        assert!(result.is_err(), "{}", value["note"]);
    }
}

#[test]
fn antibody_official_nip44_message_keys_and_padding_boundaries() {
    let vectors = nip44_vectors();
    {
        let group = &vectors["v2"]["valid"]["get_message_keys"];
        let conversation_key = vector_hex(group, "conversation_key");
        for value in group["keys"].as_array().unwrap() {
            nip44::assert_message_keys(
                &conversation_key,
                &vector_hex(value, "nonce"),
                &vector_hex(value, "chacha_key"),
                &vector_hex(value, "chacha_nonce"),
                &vector_hex(value, "hmac_key"),
            );
        }
    }
    for value in vectors["v2"]["valid"]["calc_padded_len"]
        .as_array()
        .unwrap()
    {
        assert_eq!(
            nip44::calc_padded_len(value[0].as_u64().unwrap() as usize).unwrap(),
            value[1].as_u64().unwrap() as usize
        );
    }
    assert!(nip44::calc_padded_len(0).is_err());
    assert!(nip44::calc_padded_len(usize::MAX).is_err());
}

#[test]
fn antibody_official_nip44_encrypt_decrypt_and_long_messages() {
    let vectors = nip44_vectors();
    for value in vectors["v2"]["valid"]["encrypt_decrypt"]
        .as_array()
        .unwrap()
    {
        let sender = SecretKey::from_bytes(vector_hex(value, "sec1")).unwrap();
        let receiver = SecretKey::from_bytes(vector_hex(value, "sec2")).unwrap();
        let conversation = nip44::get_conversation_key(&sender, &receiver.public_key()).unwrap();
        assert_eq!(*conversation, vector_hex::<32>(value, "conversation_key"));
        let reverse = nip44::get_conversation_key(&receiver, &sender.public_key()).unwrap();
        assert_eq!(conversation, reverse);
        let text = value["plaintext"].as_str().unwrap();
        let payload =
            nip44::encrypt_with_nonce(text, &conversation, &vector_hex(value, "nonce")).unwrap();
        assert_eq!(payload, value["payload"].as_str().unwrap());
        assert_eq!(nip44::decrypt(&payload, &reverse).unwrap(), text);
    }
    for value in vectors["v2"]["valid"]["encrypt_decrypt_long_msg"]
        .as_array()
        .unwrap()
    {
        let text = value["pattern"]
            .as_str()
            .unwrap()
            .repeat(value["repeat"].as_u64().unwrap() as usize);
        let conversation = vector_hex(value, "conversation_key");
        assert_eq!(
            hex_encode(&Sha256::digest(text.as_bytes())),
            value["plaintext_sha256"]
        );
        let payload =
            nip44::encrypt_with_nonce(&text, &conversation, &vector_hex(value, "nonce")).unwrap();
        assert_eq!(
            hex_encode(&Sha256::digest(payload.as_bytes())),
            value["payload_sha256"]
        );
        assert_eq!(nip44::decrypt(&payload, &conversation).unwrap(), text);
    }
}

#[test]
fn antibody_official_nip44_invalid_lengths_payloads_mac_and_padding() {
    let vectors = nip44_vectors();
    for value in vectors["v2"]["invalid"]["encrypt_msg_lengths"]
        .as_array()
        .unwrap()
    {
        assert!(nip44::encrypt_with_nonce(
            &"x".repeat(value.as_u64().unwrap() as usize),
            &[1; 32],
            &[2; 32]
        )
        .is_err());
    }
    for value in vectors["v2"]["invalid"]["decrypt"].as_array().unwrap() {
        assert!(
            nip44::decrypt(
                value["payload"].as_str().unwrap(),
                &vector_hex(value, "conversation_key")
            )
            .is_err(),
            "{}",
            value["note"]
        );
    }
}

fn raw_nip44_payload(mut padded: Vec<u8>, conversation: &[u8; 32]) -> String {
    let nonce = [11; 32];
    let mut expanded = [0; 76];
    hkdf::Hkdf::<Sha256>::from_prk(conversation)
        .unwrap()
        .expand(&nonce, &mut expanded)
        .unwrap();
    ChaCha20::new_from_slices(&expanded[..32], &expanded[32..44])
        .unwrap()
        .apply_keystream(&mut padded);
    let mut mac = Hmac::<Sha256>::new_from_slice(&expanded[44..]).unwrap();
    mac.update(&nonce);
    mac.update(&padded);
    let mut payload = vec![2];
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&padded);
    payload.extend_from_slice(&mac.finalize().into_bytes());
    STANDARD.encode(payload)
}

#[test]
fn antibody_nip44_rejects_nonzero_padding_bad_utf8_and_oversized_payload_before_returning_plaintext(
) {
    let conversation = [42; 32];
    let mut padded = vec![0; 34];
    padded[..3].copy_from_slice(&[0, 1, b'a']);
    padded[33] = 1;
    assert_eq!(
        nip44::decrypt(
            &raw_nip44_payload(padded.clone(), &conversation),
            &conversation
        )
        .unwrap_err()
        .code(),
        "nip44:padding-invalid"
    );
    padded[33] = 0;
    padded[2] = 255;
    assert_eq!(
        nip44::decrypt(&raw_nip44_payload(padded, &conversation), &conversation)
            .unwrap_err()
            .code(),
        "nip44:plaintext-not-utf8"
    );
    let oversized = STANDARD.encode(vec![2; 1 + 32 + 2 + 65_536 + 32 + 1]);
    assert_eq!(
        nip44::decrypt(&oversized, &conversation)
            .unwrap_err()
            .code(),
        "nip44:payload-length"
    );
    let mut payload = STANDARD
        .decode(nip44::encrypt_with_nonce("hi", &conversation, &[3; 32]).unwrap())
        .unwrap();
    payload[40] ^= 1;
    assert_eq!(
        nip44::decrypt(&STANDARD.encode(payload), &conversation)
            .unwrap_err()
            .code(),
        "nip44:mac-invalid"
    );
}

#[test]
fn antibody_nip01_escaping_is_literal_except_the_seven_required_escapes() {
    let content = "\n\"\\\r\t\u{08}\u{0c}雪\u{2028}\u{2029}\u{7f}\u{01}";
    let serialized = event::serialize_for_id(&[0; 32], 0, 0, &[], content).unwrap();
    let expected = format!(
        "[0,\"{}\",0,0,[],\"\\n\\\"\\\\\\r\\t\\b\\f雪\u{2028}\u{2029}\u{7f}\u{01}\"]",
        "0".repeat(64)
    );
    assert_eq!(serialized, expected.as_bytes());
    assert!(!String::from_utf8(serialized).unwrap().contains("\\u0001"));
}

#[test]
fn antibody_signing_refuses_every_unlisted_control_in_content_and_tags() {
    for number in 0..32 {
        let character = char::from_u32(number).unwrap().to_string();
        let allowed = matches!(number, 8 | 9 | 10 | 12 | 13);
        assert_eq!(
            Event::sign(&fixture_key(1), 0, 0, vec![], character.clone()).is_ok(),
            allowed,
            "content {number}"
        );
        assert_eq!(
            Event::sign(
                &fixture_key(1),
                0,
                0,
                vec![vec![character.clone()]],
                "ok".into()
            )
            .is_ok(),
            allowed,
            "tag {number}"
        );
        assert_eq!(
            Rumor::new(fixture_key(1).public_key(), 0, 0, vec![], character).is_ok(),
            allowed,
            "rumor {number}"
        );
    }
}

#[test]
fn antibody_event_parser_checks_id_and_signature_before_returning() {
    let event = test_event();
    assert_eq!(Event::parse(event.to_json().as_bytes()).unwrap(), event);
    let mut value: Value = serde_json::from_str(&event.to_json()).unwrap();
    value["id"] = json!("00".repeat(32));
    assert_eq!(
        Event::parse(value.to_string().as_bytes())
            .unwrap_err()
            .code(),
        "nostr:event-id-mismatch"
    );
    value["id"] = json!(hex_encode(&event.id));
    value["sig"] = json!("00".repeat(64));
    assert_eq!(
        Event::parse(value.to_string().as_bytes())
            .unwrap_err()
            .code(),
        "nostr:event-signature-invalid"
    );
}

#[test]
fn antibody_event_parser_refuses_duplicate_unknown_missing_and_oversized_fields() {
    let event = test_event();
    let encoded = event.to_json();
    let duplicate = format!("{{\"kind\":1,{}", &encoded[1..]);
    assert!(Event::parse(duplicate.as_bytes()).is_err());
    let mut value: Value = serde_json::from_str(&encoded).unwrap();
    value["extra"] = json!(false);
    assert!(Event::parse(value.to_string().as_bytes()).is_err());
    value.as_object_mut().unwrap().remove("extra");
    for name in [
        "id",
        "pubkey",
        "created_at",
        "kind",
        "tags",
        "content",
        "sig",
    ] {
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove(name);
        assert!(
            Event::parse(missing.to_string().as_bytes()).is_err(),
            "missing {name}"
        );
    }
    let oversized = format!("{}{}", " ".repeat(event::MAX_EVENT_BYTES), encoded);
    assert_eq!(
        Event::parse(oversized.as_bytes()).unwrap_err().code(),
        "nostr:event-too-large"
    );
}

#[test]
fn antibody_event_parser_refuses_noninteger_fields_bad_hex_and_tag_shapes() {
    let event = test_event();
    let value: Value = serde_json::from_str(&event.to_json()).unwrap();
    for name in ["id", "pubkey", "sig"] {
        for bad in [
            value[name].as_str().unwrap().to_uppercase(),
            "aa".into(),
            "gg".repeat(if name == "sig" { 64 } else { 32 }),
        ] {
            let mut malformed = value.clone();
            malformed[name] = json!(bad);
            assert!(
                Event::parse(malformed.to_string().as_bytes()).is_err(),
                "hex {name}"
            );
        }
    }
    for name in ["created_at", "kind"] {
        for bad in [
            json!(1.0),
            json!(-1),
            json!("1"),
            json!(true),
            json!(9_007_199_254_740_992_u64),
        ] {
            let mut malformed = value.clone();
            malformed[name] = bad;
            assert!(
                Event::parse(malformed.to_string().as_bytes()).is_err(),
                "integer {name}"
            );
        }
    }
    for bad in [json!([[]]), json!([["p", 1]]), json!(["p"]), json!({})] {
        let mut malformed = value.clone();
        malformed["tags"] = bad;
        assert!(Event::parse(malformed.to_string().as_bytes()).is_err());
    }
    assert!(Event::sign(&fixture_key(1), 0, 0, vec![vec![]], "x".into()).is_err());
    assert!(Event::sign(&fixture_key(1), u64::MAX, 0, vec![], "x".into()).is_err());
    assert!(Event::sign(&fixture_key(1), 0, u64::MAX, vec![], "x".into()).is_err());
}

#[test]
fn antibody_prime_js_event_npub_nip44_and_giftwrap_vectors() {
    let vectors = prime_vectors();
    for value in vectors["public_keys"].as_array().unwrap() {
        let public = vector_hex(value, "pubkey");
        assert_eq!(npub_encode(&public).unwrap(), value["npub"]);
        assert_eq!(
            npub_decode(value["npub"].as_str().unwrap()).unwrap(),
            public
        );
    }
    let event = Event::parse(vectors["event"].to_string().as_bytes()).unwrap();
    assert_eq!(
        event::serialize_for_id(
            &event.pubkey,
            event.created_at,
            event.kind,
            &event.tags,
            &event.content
        )
        .unwrap(),
        vectors["serialized_event"].as_str().unwrap().as_bytes()
    );
    let payload = &vectors["nip44"];
    let conversation =
        nip44::get_conversation_key(&fixture_key(1), &fixture_key(2).public_key()).unwrap();
    assert_eq!(*conversation, vector_hex::<32>(payload, "conversation_key"));
    assert_eq!(
        nip44::encrypt_with_nonce(
            payload["plaintext"].as_str().unwrap(),
            &conversation,
            &vector_hex(payload, "nonce")
        )
        .unwrap(),
        payload["payload"]
    );
    assert_eq!(
        nip44::decrypt(payload["payload"].as_str().unwrap(), &conversation).unwrap(),
        payload["plaintext"]
    );
    let wrap = Event::parse(vectors["wrap"].to_string().as_bytes()).unwrap();
    let opened = nip59::unwrap(&wrap, &fixture_key(2), 1_700_000_000).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&opened.rumor.to_json()).unwrap(),
        vectors["rumor"]
    );
    assert_eq!(
        serde_json::from_str::<Value>(&opened.seal.to_json()).unwrap(),
        vectors["seal"]
    );
}

fn raw_wrap(seal: &Event, recipient: &SecretKey) -> Event {
    let ephemeral = fixture_key(3);
    let conversation = nip44::get_conversation_key(&ephemeral, &recipient.public_key()).unwrap();
    Event::sign(
        &ephemeral,
        1_699_999_999,
        nip59::GIFT_WRAP_KIND,
        vec![vec!["p".into(), hex_encode(&recipient.public_key())]],
        nip44::encrypt(&seal.to_json(), &conversation).unwrap(),
    )
    .unwrap()
}

fn raw_seal(
    rumor: &Rumor,
    sender: &SecretKey,
    recipient: &SecretKey,
    kind: u64,
    tags: Vec<Vec<String>>,
) -> Event {
    let conversation = nip44::get_conversation_key(sender, &recipient.public_key()).unwrap();
    Event::sign(
        sender,
        1_699_999_999,
        kind,
        tags,
        nip44::encrypt(&rumor.to_json(), &conversation).unwrap(),
    )
    .unwrap()
}

#[test]
fn antibody_giftwrap_unwrap_seal_authenticates_without_reading_rumor() {
    let sender = fixture_key(1);
    let recipient = fixture_key(2);
    let now = 1_700_000_000;
    let seal = Event::sign(&sender, now, 13, vec![], "unread-rumor".into()).unwrap();
    let wrap = raw_wrap(&seal, &recipient);
    let authenticated = nip59::unwrap_seal(&wrap, &recipient, now).unwrap();
    assert_eq!(authenticated, seal);
    assert!(nip59::open_seal(&authenticated, &recipient, now).is_err());

    let mut tampered = seal;
    tampered.sig[10] ^= 1;
    assert_eq!(
        nip59::unwrap_seal(&raw_wrap(&tampered, &recipient), &recipient, now)
            .unwrap_err()
            .code(),
        "nostr:event-signature-invalid"
    );
}

#[test]
fn antibody_giftwrap_open_seal_reauthenticates_and_binds_rumor_sender() {
    let sender = fixture_key(1);
    let recipient = fixture_key(2);
    let now = 1_700_000_000;
    let rumor = Rumor::new(sender.public_key(), now, 14, vec![], "private".into()).unwrap();
    let seal = raw_seal(&rumor, &sender, &recipient, 13, vec![]);
    assert_eq!(nip59::open_seal(&seal, &recipient, now).unwrap(), rumor);

    let mut tampered = seal.clone();
    tampered.sig[10] ^= 1;
    assert_eq!(
        nip59::open_seal(&tampered, &recipient, now)
            .unwrap_err()
            .code(),
        "nostr:event-signature-invalid"
    );
    for (kind, tags, expected) in [
        (1, vec![], "nostr:seal-kind-invalid"),
        (13, vec![vec!["leak".into()]], "nostr:seal-tags-invalid"),
    ] {
        let invalid = raw_seal(&rumor, &sender, &recipient, kind, tags);
        assert_eq!(
            nip59::open_seal(&invalid, &recipient, now)
                .unwrap_err()
                .code(),
            expected
        );
    }
    let future = Event::sign(&sender, now + 1, 13, vec![], seal.content).unwrap();
    assert_eq!(
        nip59::open_seal(&future, &recipient, now)
            .unwrap_err()
            .code(),
        "nostr:seal-time-invalid"
    );

    let impersonated = Rumor::new(
        fixture_key(3).public_key(),
        now,
        14,
        vec![],
        "impersonated".into(),
    )
    .unwrap();
    let forged = raw_seal(&impersonated, &sender, &recipient, 13, vec![]);
    assert_eq!(
        nip59::open_seal(&forged, &recipient, now)
            .unwrap_err()
            .code(),
        "nostr:sender-mismatch"
    );
}

#[test]
fn antibody_giftwrap_roundtrip_uses_one_time_key_and_randomized_past_times() {
    let sender = fixture_key(1);
    let recipient = fixture_key(2);
    let now = 1_700_000_000;
    let rumor = Rumor::new(sender.public_key(), now, 14, vec![], "private".into()).unwrap();
    let mut wrap_keys = std::collections::BTreeSet::new();
    let mut seal_times = std::collections::BTreeSet::new();
    let mut wrap_times = std::collections::BTreeSet::new();
    for _ in 0..8 {
        let wrap = nip59::gift_wrap(&rumor, &sender, &recipient.public_key(), now).unwrap();
        assert_ne!(wrap.pubkey, sender.public_key());
        assert!(wrap_keys.insert(wrap.pubkey));
        assert!((now - 172_800..=now).contains(&wrap.created_at));
        wrap_times.insert(wrap.created_at);
        let opened = nip59::unwrap(&wrap, &recipient, now).unwrap();
        assert_eq!(opened.rumor, rumor);
        assert!((now - 172_800..=now).contains(&opened.seal.created_at));
        seal_times.insert(opened.seal.created_at);
    }
    assert!(seal_times.len() > 1);
    assert!(wrap_times.len() > 1);
}

#[test]
fn antibody_giftwrap_rejects_rumor_sender_impersonation_and_changed_rumor_id() {
    let sender = fixture_key(1);
    let recipient = fixture_key(2);
    let mut rumor = Rumor::new(
        recipient.public_key(),
        1_700_000_000,
        14,
        vec![],
        "forged author".into(),
    )
    .unwrap();
    assert_eq!(
        nip59::seal(&rumor, &sender, &recipient.public_key(), 1_700_000_000)
            .unwrap_err()
            .code(),
        "nostr:sender-mismatch"
    );
    let seal = raw_seal(&rumor, &sender, &recipient, 13, vec![]);
    assert_eq!(
        nip59::unwrap(&raw_wrap(&seal, &recipient), &recipient, 1_700_000_000)
            .unwrap_err()
            .code(),
        "nostr:sender-mismatch"
    );
    rumor.pubkey = sender.public_key();
    rumor.id = [0; 32];
    let seal = raw_seal(&rumor, &sender, &recipient, 13, vec![]);
    assert_eq!(
        nip59::unwrap(&raw_wrap(&seal, &recipient), &recipient, 1_700_000_000)
            .unwrap_err()
            .code(),
        "nostr:rumor-id-mismatch"
    );
}

#[test]
fn antibody_giftwrap_rejects_wrap_and_seal_signature_tampering() {
    let vectors = prime_vectors();
    let recipient = fixture_key(2);
    let mut wrap = Event::parse(vectors["wrap"].to_string().as_bytes()).unwrap();
    wrap.sig[10] ^= 1;
    assert_eq!(
        nip59::unwrap(&wrap, &recipient, 1_700_000_000)
            .unwrap_err()
            .code(),
        "nostr:event-signature-invalid"
    );
    let mut seal = Event::parse(vectors["seal"].to_string().as_bytes()).unwrap();
    seal.sig[10] ^= 1;
    assert_eq!(
        nip59::unwrap(&raw_wrap(&seal, &recipient), &recipient, 1_700_000_000)
            .unwrap_err()
            .code(),
        "nostr:event-signature-invalid"
    );
    assert_eq!(
        nip59::wrap(&seal, &recipient.public_key(), 1_700_000_000)
            .unwrap_err()
            .code(),
        "nostr:event-signature-invalid"
    );
}

#[test]
fn antibody_giftwrap_refuses_wrong_kinds_seal_tags_and_recipient_routing() {
    let sender = fixture_key(1);
    let recipient = fixture_key(2);
    let rumor = Rumor::new(
        sender.public_key(),
        1_700_000_000,
        14,
        vec![],
        "private".into(),
    )
    .unwrap();
    for (kind, tags, expected) in [
        (1, vec![], "nostr:seal-kind-invalid"),
        (13, vec![vec!["leak".into()]], "nostr:seal-tags-invalid"),
    ] {
        let seal = raw_seal(&rumor, &sender, &recipient, kind, tags);
        assert_eq!(
            nip59::unwrap(&raw_wrap(&seal, &recipient), &recipient, 1_700_000_000)
                .unwrap_err()
                .code(),
            expected
        );
        assert_eq!(
            nip59::wrap(&seal, &recipient.public_key(), 1_700_000_000)
                .unwrap_err()
                .code(),
            expected
        );
    }
    let seal = raw_seal(&rumor, &sender, &recipient, 13, vec![]);
    let wrap = raw_wrap(&seal, &recipient);
    let wrong_kind = Event::sign(
        &fixture_key(3),
        wrap.created_at,
        1,
        wrap.tags.clone(),
        wrap.content.clone(),
    )
    .unwrap();
    assert_eq!(
        nip59::unwrap(&wrong_kind, &recipient, 1_700_000_000)
            .unwrap_err()
            .code(),
        "nostr:wrap-kind-invalid"
    );
    let wrong_recipient = Event::sign(
        &fixture_key(3),
        wrap.created_at,
        wrap.kind,
        vec![vec!["p".into(), hex_encode(&sender.public_key())]],
        wrap.content,
    )
    .unwrap();
    assert_eq!(
        nip59::unwrap(&wrong_recipient, &recipient, 1_700_000_000)
            .unwrap_err()
            .code(),
        "nostr:wrap-not-for-us"
    );
}

#[test]
fn antibody_giftwrap_refuses_future_wrap_seal_and_rumor_times() {
    let sender = fixture_key(1);
    let recipient = fixture_key(2);
    let now = 1_700_000_000;
    let rumor = Rumor::new(sender.public_key(), now + 1, 14, vec![], "private".into()).unwrap();
    assert_eq!(
        nip59::seal(&rumor, &sender, &recipient.public_key(), now)
            .unwrap_err()
            .code(),
        "nostr:rumor-time-invalid"
    );
    let seal = raw_seal(&rumor, &sender, &recipient, 13, vec![]);
    assert_eq!(
        nip59::unwrap(&raw_wrap(&seal, &recipient), &recipient, now)
            .unwrap_err()
            .code(),
        "nostr:rumor-time-invalid"
    );
    let future_seal = Event::sign(
        &sender,
        now + 1,
        seal.kind,
        seal.tags.clone(),
        seal.content.clone(),
    )
    .unwrap();
    assert_eq!(
        nip59::unwrap(&raw_wrap(&future_seal, &recipient), &recipient, now)
            .unwrap_err()
            .code(),
        "nostr:seal-time-invalid"
    );
    let wrap = raw_wrap(&seal, &recipient);
    let future_wrap =
        Event::sign(&fixture_key(3), now + 1, wrap.kind, wrap.tags, wrap.content).unwrap();
    assert_eq!(
        nip59::unwrap(&future_wrap, &recipient, now)
            .unwrap_err()
            .code(),
        "nostr:wrap-time-invalid"
    );
}

#[test]
fn antibody_secret_key_drop_zeroizes_its_storage() {
    let mut storage = std::mem::MaybeUninit::new(fixture_key(3));
    let key = storage.as_mut_ptr();
    // SAFETY: storage holds an initialized SecretKey until drop_in_place below.
    let secret_bytes = unsafe { (*key).0.as_ptr() };
    // SAFETY: the initialized key is dropped exactly once; MaybeUninit does not drop it again.
    unsafe { std::ptr::drop_in_place(key) };
    // SAFETY: storage remains allocated; the scalar's initialized bytes have no destructor or padding.
    let wiped = unsafe { std::slice::from_raw_parts(secret_bytes, 32) };
    assert_eq!(wiped, &[0; 32]);
}

#[test]
fn antibody_npub_rejects_uppercase_and_noncanonical_padding_with_valid_checksums() {
    use bech32::{ByteIterExt, Fe32IterExt};
    let public = fixture_key(1).public_key();
    let npub = npub_encode(&public).unwrap();
    assert!(npub_decode(&npub.to_uppercase()).is_err());
    let hrp = bech32::Hrp::parse("npub").unwrap();
    let mut data: Vec<_> = public.iter().copied().bytes_to_fes().collect();
    let last = data.len() - 1;
    data[last] = bech32::Fe32::try_from(data[last].to_u8() | 1).unwrap();
    let nonzero_padding: String = data
        .clone()
        .into_iter()
        .with_checksum::<bech32::Bech32>(&hrp)
        .chars()
        .collect();
    assert!(
        bech32::primitives::decode::CheckedHrpstring::new::<bech32::Bech32>(&nonzero_padding)
            .is_ok()
    );
    assert!(npub_decode(&nonzero_padding).is_err());
    data[last] = bech32::Fe32::try_from(data[last].to_u8() & !15).unwrap();
    data.push(bech32::Fe32::Q);
    let excess_padding: String = data
        .into_iter()
        .with_checksum::<bech32::Bech32>(&hrp)
        .chars()
        .collect();
    assert!(npub_decode(&excess_padding).is_err());
}

#[test]
fn antibody_hex_helpers_enforce_lowercase_and_exact_lengths() {
    assert_eq!(hex_decode::<2>("00af").unwrap(), [0, 175]);
    for text in ["00AF", "0", "", "00af00", "xxaf"] {
        assert!(hex_decode::<2>(text).is_err());
    }
}

#[test]
fn antibody_nip44_encrypt_uses_fresh_nonce_and_rejects_hash_version_marker_first() {
    let first = nip44::encrypt("same plaintext", &[42; 32]).unwrap();
    let second = nip44::encrypt("same plaintext", &[42; 32]).unwrap();
    assert_ne!(first, second);
    assert_ne!(
        &STANDARD.decode(first).unwrap()[1..33],
        &STANDARD.decode(second).unwrap()[1..33]
    );
    assert_eq!(
        nip44::decrypt("#", &[42; 32]).unwrap_err().code(),
        "nip44:unsupported-version"
    );
}

#[test]
fn antibody_rumor_parser_refuses_signatures_and_requires_its_id() {
    let rumor = Rumor::new(
        fixture_key(1).public_key(),
        0,
        14,
        vec![],
        "unsigned".into(),
    )
    .unwrap();
    let mut value: Value = serde_json::from_str(&rumor.to_json()).unwrap();
    value["sig"] = json!("00".repeat(64));
    assert!(Rumor::parse(value.to_string().as_bytes()).is_err());
    value.as_object_mut().unwrap().remove("sig");
    value["id"] = json!("00".repeat(32));
    assert_eq!(
        Rumor::parse(value.to_string().as_bytes())
            .unwrap_err()
            .code(),
        "nostr:rumor-id-mismatch"
    );
    value.as_object_mut().unwrap().remove("id");
    assert!(Rumor::parse(value.to_string().as_bytes()).is_err());
}
