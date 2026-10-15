// SPDX-License-Identifier: AGPL-3.0-or-later

use canon::{
    codes, encode_frame, read_frame, write_frame, Direction, Frame, FrameBody, Read as ReadBody,
    Status,
};
use std::io::{self, Cursor, Read, Write};

fn frame() -> Frame {
    Frame {
        v: 1,
        id: "a".into(),
        body: FrameBody::Status(Status),
    }
}
fn prefix(payload: &[u8]) -> Vec<u8> {
    let mut bytes = (payload.len() as u32).to_be_bytes().to_vec();
    bytes.extend_from_slice(payload);
    bytes
}
struct Partial<T>(T);
impl<T: Read> Read for Partial<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let end = buf.len().min(3);
        self.0.read(&mut buf[..end])
    }
}
impl<T: Write> Write for Partial<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(&buf[..buf.len().min(3)])
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

#[test]
fn framing_is_big_endian_and_partial_reads_and_writes_preserve_multiple_frames() {
    let f = frame();
    let json = encode_frame(&f).unwrap();
    let expected = prefix(&json);
    let mut output = Partial(Vec::new());
    write_frame(&mut output, &f).unwrap();
    write_frame(&mut output, &f).unwrap();
    assert_eq!(output.0, [expected.clone(), expected].concat());
    let mut input = Partial(Cursor::new(output.0));
    assert_eq!(read_frame(&mut input, Direction::Guest).unwrap(), f);
    assert_eq!(read_frame(&mut input, Direction::Guest).unwrap(), f);
}

#[test]
fn zero_oversize_and_short_reads_are_fatal_without_resynchronization() {
    for (bytes, code) in [
        (vec![0, 0, 0, 0], codes::FRAME_ZERO_LENGTH),
        (65_537_u32.to_be_bytes().to_vec(), codes::FRAME_TOO_LARGE),
        (vec![], codes::FRAME_SHORT_READ),
        (vec![0], codes::FRAME_SHORT_READ),
        (vec![0, 0], codes::FRAME_SHORT_READ),
        (vec![0, 0, 0], codes::FRAME_SHORT_READ),
        (vec![0, 0, 0, 3, b'{', b'}'], codes::FRAME_SHORT_READ),
    ] {
        let error = read_frame(&mut Cursor::new(bytes), Direction::Guest).unwrap_err();
        assert_eq!(error.code(), code);
        assert!(error.is_fatal());
    }
    let mut bytes = 65_537_u32.to_be_bytes().to_vec();
    bytes.extend(prefix(&encode_frame(&frame()).unwrap()));
    let mut input = Cursor::new(bytes);
    assert!(read_frame(&mut input, Direction::Guest)
        .unwrap_err()
        .is_fatal());
    assert_eq!(
        input.position(),
        4,
        "oversize payload must not be allocated or consumed"
    );
}

#[test]
fn exact_maximum_length_frame_round_trips() {
    let empty = Frame {
        v: 1,
        id: "a".into(),
        body: FrameBody::Read(ReadBody {
            target: String::new(),
        }),
    };
    let base = encode_frame(&empty).unwrap().len();
    let exact = Frame {
        body: FrameBody::Read(ReadBody {
            target: "x".repeat(65_536 - base),
        }),
        ..empty
    };
    assert_eq!(encode_frame(&exact).unwrap().len(), 65_536);
    let mut output = Vec::new();
    write_frame(&mut output, &exact).unwrap();
    assert_eq!(&output[..4], &65_536_u32.to_be_bytes());
    assert_eq!(
        read_frame(&mut Partial(Cursor::new(output)), Direction::Guest).unwrap(),
        exact
    );
}

#[test]
fn semantic_refusal_preserves_next_frame_and_encoding_never_writes_invalid_body() {
    let mut input = Cursor::new(
        [
            prefix(br#"{"body":{},"id":"a","kind":"accepted","v":1}"#),
            prefix(&encode_frame(&frame()).unwrap()),
        ]
        .concat(),
    );
    let error = read_frame(&mut input, Direction::Guest).unwrap_err();
    assert_eq!(error.code(), codes::FRAME_UNKNOWN_KIND);
    assert!(!error.is_fatal());
    assert_eq!(read_frame(&mut input, Direction::Guest).unwrap(), frame());
    let invalid = Frame { v: 2, ..frame() };
    let mut output = Vec::new();
    let error = write_frame(&mut output, &invalid).unwrap_err();
    assert_eq!(error.code(), codes::FRAME_UNSUPPORTED_VERSION);
    assert!(!error.is_fatal());
    assert!(output.is_empty());
}

struct Broken;
impl Read for Broken {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
    }
}
impl Write for Broken {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn actual_io_errors_are_fatal_and_report_the_reason() {
    let error = read_frame(&mut Broken, Direction::Guest).unwrap_err();
    assert_eq!(error.code(), codes::FRAME_IO);
    assert!(error.is_fatal());
    assert!(error.to_string().contains("closed"));
    let error = write_frame(&mut Broken, &frame()).unwrap_err();
    assert_eq!(error.code(), codes::FRAME_IO);
    assert!(error.is_fatal());
}
