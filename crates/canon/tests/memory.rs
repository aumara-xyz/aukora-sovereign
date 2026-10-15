// SPDX-License-Identifier: AGPL-3.0-or-later

use canon::{
    codes, decode_frame, encode_frame, parse, Direction, Frame, FrameBody, MemoryList,
    MemoryListItem, MemoryListReply, MemoryTier, Value,
};

const VECTORS: &[u8] = include_bytes!("../vectors/memory.json");

fn text(value: &Value) -> &str {
    match value {
        Value::String(text) => text,
        _ => panic!("expected string"),
    }
}

#[test]
fn memory_shared_vectors_and_direction_round_trip() {
    let Value::Array(vectors) = parse(VECTORS).unwrap() else {
        panic!("expected vectors");
    };
    for vector in vectors {
        let name = text(vector.get("name").unwrap());
        let direction = match text(vector.get("frame_direction").unwrap()) {
            "guest" => Direction::Guest,
            "supervisor" => Direction::Supervisor,
            _ => panic!("expected direction"),
        };
        let decoded = decode_frame(text(vector.get("input").unwrap()).as_bytes(), direction);
        if let Some(code) = vector.get("frame_refusal") {
            assert_eq!(decoded.unwrap_err().code(), text(code), "{name}");
        } else {
            assert_eq!(
                encode_frame(&decoded.unwrap()).unwrap(),
                text(vector.get("canonical").unwrap()).as_bytes(),
                "{name}"
            );
        }
    }
}

fn reply() -> Frame {
    Frame {
        v: 1,
        id: "memory_constructed".into(),
        body: FrameBody::MemoryListReply(MemoryListReply {
            tier: MemoryTier::Remembered,
            items: vec![MemoryListItem {
                note_id: "note".into(),
                category: "personal".into(),
                at: 0,
                cite_seq: 1,
                text: Some("remembered".into()),
                demoted_at: None,
                demoted_seq: None,
            }],
            next: None,
        }),
    }
}

#[test]
fn memory_encoder_refuses_constructed_disclosure_and_invalid_fields() {
    let mut frame = reply();
    let FrameBody::MemoryListReply(body) = &mut frame.body else {
        unreachable!()
    };
    body.tier = MemoryTier::Forgotten;
    body.items[0].demoted_at = Some(0);
    body.items[0].demoted_seq = Some(2);
    assert_eq!(
        encode_frame(&frame).unwrap_err().code(),
        codes::FRAME_INVALID_FIELD
    );
    let FrameBody::MemoryListReply(body) = &mut frame.body else {
        unreachable!()
    };
    body.items[0].text = None;
    assert_eq!(
        decode_frame(&encode_frame(&frame).unwrap(), Direction::Supervisor).unwrap(),
        frame
    );
    let FrameBody::MemoryListReply(body) = &mut frame.body else {
        unreachable!()
    };
    body.items[0].demoted_seq = Some(1);
    assert_eq!(
        encode_frame(&frame).unwrap_err().code(),
        codes::FRAME_INVALID_FIELD
    );
    let frame = Frame {
        v: 1,
        id: "memory_constructed".into(),
        body: FrameBody::MemoryList(MemoryList {
            tier: MemoryTier::Remembered,
            before: Some(String::new()),
        }),
    };
    assert_eq!(
        encode_frame(&frame).unwrap_err().code(),
        codes::FRAME_INVALID_FIELD
    );
}
