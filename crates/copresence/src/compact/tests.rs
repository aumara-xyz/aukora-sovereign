// SPDX-License-Identifier: AGPL-3.0-or-later
//! The shared vectors (`vectors/compact-frames-v1.json`, written by `tests/copresence/make-compact-vectors.mjs` from the TypeScript
//! engine with WebCrypto signatures) must decode, re-encode to the same bytes, verify, and carry the digests `v1` computes.

use super::*;
use crate::{
    receipt_json::{read_hardened, Value, HARDENED_LIMITS},
    v1::{
        codec::{get, string},
        crypto as v1_crypto, ChannelCommitments, Context, CoreInput,
    },
};

const VECTORS: &str = include_str!("../../vectors/compact-frames-v1.json");

fn vectors() -> Value {
    read_hardened(VECTORS.as_bytes(), HARDENED_LIMITS).expect("vectors parse")
}
fn text(value: &Value, key: &str) -> String {
    string(get(value, key).expect("field")).expect("text")
}
fn bytes_of(value: &Value, key: &str) -> Vec<u8> {
    hex::decode(text(value, key)).expect("hex")
}
fn integer(value: &Value, key: &str) -> u64 {
    match get(value, key).expect("field") {
        Value::Integer(n) => *n,
        _ => panic!("{key} is not an integer"),
    }
}
fn items<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    match get(value, key).expect("field") {
        Value::Array(items) => items,
        _ => panic!("{key} is not an array"),
    }
}
fn key_of(root: &Value, side: &str, form: &str) -> Vec<u8> {
    bytes_of(get(get(root, "keys").unwrap(), side).unwrap(), form)
}
fn public(root: &Value, side: &str) -> PublicKeyBytes {
    PublicKeyBytes(
        key_of(root, side, "uncompressed")
            .try_into()
            .expect("65 bytes"),
    )
}
fn participant(root: &Value, side: &str) -> Participant {
    let value = get(get(root, "participants").unwrap(), side).unwrap();
    Participant {
        node: NodeId::from_bytes(bytes_of(value, "node").try_into().expect("16 bytes")),
        device_key: public(root, side),
        device_epoch: integer(value, "device_epoch"),
        session_id: bytes_of(value, "session_id").try_into().expect("16 bytes"),
        attempt_sequence: integer(value, "attempt_sequence"),
    }
}
fn digest(value: &Value, key: &str) -> Digest32 {
    Digest32::from_bytes(bytes_of(value, key).try_into().expect("32 bytes"))
}
fn signature(value: &Value, key: &str) -> SignatureBytes {
    SignatureBytes(bytes_of(value, key).try_into().expect("64 bytes"))
}
fn frame_bytes(entry: &Value) -> Vec<u8> {
    bytes_of(entry, "frame")
}

#[test]
fn keys_compress_and_decompress_exactly() {
    let root = vectors();
    for side in ["a", "b"] {
        let uncompressed = public(&root, side);
        let compressed: [u8; 33] = key_of(&root, side, "compressed").try_into().unwrap();
        assert_eq!(compress_key(&uncompressed).unwrap(), compressed);
        assert_eq!(decompress_key(&compressed).unwrap(), uncompressed);
    }
    for bad in items(&root, "invalid_keys") {
        let name = text(bad, "name");
        let compressed: [u8; 33] = bytes_of(bad, "compressed").try_into().unwrap();
        assert!(
            decompress_key(&compressed).is_err(),
            "{name} must be refused"
        );
    }
}

#[test]
fn every_vector_frame_round_trips_and_verifies() {
    let root = vectors();
    let a = participant(&root, "a");
    let b = participant(&root, "b");
    for entry in items(&root, "frames") {
        let name = text(entry, "name");
        let raw = frame_bytes(entry);
        let frame = decode(&raw).unwrap_or_else(|reason| panic!("{name}: {reason:?}"));
        assert_eq!(
            encode(&frame).unwrap(),
            raw,
            "{name} re-encodes to the same bytes"
        );
        let fields = get(entry, "fields").unwrap();
        let (t, index) = (integer(fields, "t_seconds"), integer(fields, "frame_index"));
        match (&frame.body, name.as_str()) {
            (CompactBody::Face(face), n) => {
                assert_eq!(
                    face.participant,
                    if n == "face-a" { a.clone() } else { b.clone() },
                    "{name}"
                );
                assert_eq!(face.nonce_commitment, digest(fields, "nonce_commitment"));
                assert_eq!(face.method, Method::ScreenToScreen);
                assert_eq!(
                    face.required_layers,
                    RequiredLayers {
                        sound: false,
                        motion: false,
                        intent_ack: false
                    }
                );
                assert_eq!(
                    (u64::from(face.t_seconds), u64::from(face.frame_index)),
                    (t, index)
                );
            }
            (CompactBody::SeenYou(seen), n) => {
                assert_eq!(
                    seen.sender,
                    if n == "seenyou-a" { Side::A } else { Side::B }
                );
                assert_eq!(seen.context_digest, digest(fields, "context_digest"));
                assert_eq!(
                    (seen.face_a, seen.face_b),
                    (digest(fields, "face_a"), digest(fields, "face_b"))
                );
                assert_eq!(seen.nonce.to_vec(), bytes_of(fields, "nonce"));
                assert_eq!(
                    (u64::from(seen.t_seconds), u64::from(seen.frame_index)),
                    (t, index)
                );
            }
            (CompactBody::Handshake(handshake), _) => {
                assert_eq!(handshake.core_digest, digest(fields, "core_digest"));
                assert_eq!(handshake.sig_b, signature(fields, "sig_b"));
                assert_eq!(
                    (
                        u64::from(handshake.t_seconds),
                        u64::from(handshake.frame_index)
                    ),
                    (t, index)
                );
            }
            (CompactBody::Bloom(bloom), n) => {
                assert_eq!(bloom.core_digest, digest(fields, "core_digest"));
                assert_eq!(bloom.sig_a, signature(fields, "sig_a"));
                assert_eq!(bloom.intent_sig.is_some(), n == "bloom-a-with-intent");
                if let Some(intent) = &bloom.intent_sig {
                    assert_eq!(*intent, signature(fields, "intent_sig"));
                }
                assert_eq!(
                    (u64::from(bloom.t_seconds), u64::from(bloom.frame_index)),
                    (t, index)
                );
            }
        }
        let signer = text(entry, "signer");
        let body = &raw[..raw.len() - 64];
        assert_eq!(frame_digest(body), digest(entry, "digest"), "{name} digest");
        verify_frame(&raw, public(&root, &signer))
            .unwrap_or_else(|reason| panic!("{name}: {reason:?}"));
        let other = if signer == "a" { "b" } else { "a" };
        assert!(
            verify_frame(&raw, public(&root, other)).is_err(),
            "{name} must not verify under the other key"
        );
        assert_eq!(
            base45_encode(&raw),
            text(entry, "qr_text"),
            "{name} QR text"
        );
        assert_eq!(base45_decode(&text(entry, "qr_text")).unwrap(), raw);
        assert!(raw.len() <= 233, "{name} is {} bytes", raw.len());
    }
}

#[test]
fn malformed_and_tampered_frames_are_refused() {
    let root = vectors();
    for bad in items(&root, "invalid") {
        let name = text(bad, "name");
        let raw = if text(bad, "frame").is_empty() {
            Vec::new()
        } else {
            frame_bytes(bad)
        };
        assert!(decode(&raw).is_err(), "{name} must be refused");
    }
    for bad in items(&root, "tampered") {
        let name = text(bad, "name");
        let signer = text(bad, "signer");
        assert!(
            verify_frame(&frame_bytes(bad), public(&root, &signer)).is_err(),
            "{name} must not verify"
        );
    }
}

#[test]
fn base45_matches_the_vectors_and_refuses_bad_text() {
    let root = vectors();
    for item in items(&root, "base45") {
        let raw = hex::decode(text(item, "bytes")).unwrap();
        assert_eq!(base45_encode(&raw), text(item, "text"));
        assert_eq!(base45_decode(&text(item, "text")).unwrap(), raw);
    }
    assert_eq!(base45_encode(b"Hello!!"), "%69 VD92EX0");
    assert_eq!(base45_encode(b"ietf!"), "QED8WEX0");
    for bad in ["GGW", "!!", "A", "ZZZZ"] {
        assert!(base45_decode(bad).is_err(), "{bad:?} must be refused");
    }
}

/// The digests the compact frames carry are `v1`'s own: context, core and transcript are computed by the unchanged functions.
#[test]
fn carried_digests_are_the_v1_digests() {
    let root = vectors();
    let context = Context {
        a: participant(&root, "a"),
        b: participant(&root, "b"),
        method: Method::ScreenToScreen,
        required_layers: RequiredLayers {
            sound: false,
            motion: false,
            intent_ack: false,
        },
        purpose: text(get(&root, "context").unwrap(), "purpose"),
        intent: None,
    };
    assert_eq!(
        v1_crypto::context(&context).unwrap(),
        digest(get(&root, "context").unwrap(), "digest")
    );
    let frames: Vec<Vec<u8>> = ["face-a", "face-b", "seenyou-a", "seenyou-b"]
        .iter()
        .map(|name| {
            frame_bytes(
                items(&root, "frames")
                    .iter()
                    .find(|entry| text(entry, "name") == *name)
                    .expect("frame"),
            )
        })
        .collect();
    let transcript = v1_crypto::transcript([&frames[0], &frames[1], &frames[2], &frames[3]]);
    let core = get(&root, "core").unwrap();
    assert_eq!(transcript, digest(core, "transcript"));
    let input = CoreInput {
        context,
        nonce_a: bytes_of(core, "nonce_a").try_into().unwrap(),
        nonce_b: bytes_of(core, "nonce_b").try_into().unwrap(),
        t_a_seconds: integer(core, "t_a_seconds"),
        t_b_seconds: integer(core, "t_b_seconds"),
        transcript,
        channels: ChannelCommitments {
            sound: None,
            motion: None,
        },
    };
    assert_eq!(v1_crypto::core(&input).unwrap(), digest(core, "digest"));
}
