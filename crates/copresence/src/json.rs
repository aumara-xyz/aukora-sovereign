// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Index;

static NULL: Value = Value::Null;

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Value {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    UnpairedString(Vec<u16>),
    Array(Vec<Value>),
    Object(BTreeMap<Vec<u16>, Value>),
}

impl Drop for Value {
    fn drop(&mut self) {
        fn drain(value: &mut Value, pending: &mut Vec<Value>) {
            match value {
                Value::Array(values) => pending.extend(std::mem::take(values)),
                Value::Object(values) => {
                    pending.extend(std::mem::take(values).into_values());
                }
                _ => {}
            }
        }

        let mut pending = Vec::new();
        drain(self, &mut pending);
        while let Some(mut value) = pending.pop() {
            drain(&mut value, &mut pending);
        }
    }
}

impl Value {
    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Number(value) => Some(*value),
            _ => None,
        }
    }

    pub(crate) fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    pub(crate) fn is_number(&self) -> bool {
        matches!(self, Self::Number(_))
    }

    pub(crate) fn is_boolean(&self) -> bool {
        matches!(self, Self::Bool(_))
    }

    pub(crate) fn is_object(&self) -> bool {
        matches!(self, Self::Object(_))
    }

    pub(crate) fn is_array(&self) -> bool {
        matches!(self, Self::Array(_))
    }

    pub(crate) fn is_string(&self) -> bool {
        matches!(self, Self::String(_) | Self::UnpairedString(_))
    }

    pub(crate) fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Object(values) => values.get(&key.encode_utf16().collect::<Vec<_>>()),
            _ => None,
        }
    }
}

impl Index<&str> for Value {
    type Output = Value;

    fn index(&self, key: &str) -> &Self::Output {
        self.get(key).unwrap_or(&NULL)
    }
}

impl Index<String> for Value {
    type Output = Value;

    fn index(&self, key: String) -> &Self::Output {
        &self[key.as_str()]
    }
}

impl From<i32> for Value {
    fn from(value: i32) -> Self {
        Self::Number(f64::from(value))
    }
}

impl From<&str> for Value {
    fn from(value: &str) -> Self {
        Self::String(value.into())
    }
}

impl fmt::Display for Value {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => formatter.write_str("null"),
            Self::Bool(value) => value.fmt(formatter),
            Self::Number(value) if value.is_infinite() => {
                formatter.write_str(if value.is_sign_negative() {
                    "-Infinity"
                } else {
                    "Infinity"
                })
            }
            Self::Number(value) if *value == 0.0 => formatter.write_str("0"),
            Self::Number(value) => value.fmt(formatter),
            Self::String(value) => formatter.write_str(value),
            Self::UnpairedString(value) => formatter.write_str(&String::from_utf16_lossy(value)),
            Self::Array(_) => formatter.write_str(""),
            Self::Object(_) => formatter.write_str("[object Object]"),
        }
    }
}

#[derive(Clone, Copy)]
enum ArrayState {
    First,
    Value,
    Separator,
}

#[derive(Clone, Copy)]
enum ObjectState {
    First,
    Key,
    Colon,
    Value,
    Separator,
}

enum Frame {
    Array(Vec<Value>, ArrayState),
    Object(BTreeMap<Vec<u16>, Value>, ObjectState, Option<Vec<u16>>),
}

enum Start {
    Value(Value),
    Frame(Frame),
}

enum Action {
    Value,
    Key,
    Colon,
    ArraySeparator,
    ObjectSeparator,
    Close,
}

struct Parser<'a> {
    source: &'a str,
    position: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.source.as_bytes().get(self.position).copied()
    }

    fn whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.position += 1;
        }
    }

    fn expect(&mut self, expected: u8) -> Result<(), ()> {
        if self.peek() != Some(expected) {
            return Err(());
        }
        self.position += 1;
        Ok(())
    }

    fn literal(&mut self, literal: &str, value: Value) -> Result<Start, ()> {
        if !self.source[self.position..].starts_with(literal) {
            return Err(());
        }
        self.position += literal.len();
        Ok(Start::Value(value))
    }

    fn start(&mut self) -> Result<Start, ()> {
        match self.peek() {
            Some(b'n') => self.literal("null", Value::Null),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'"') => {
                let units = self.string()?;
                Ok(Start::Value(match String::from_utf16(&units) {
                    Ok(value) => Value::String(value),
                    Err(_) => Value::UnpairedString(units),
                }))
            }
            Some(b'[') => {
                self.position += 1;
                Ok(Start::Frame(Frame::Array(Vec::new(), ArrayState::First)))
            }
            Some(b'{') => {
                self.position += 1;
                Ok(Start::Frame(Frame::Object(
                    BTreeMap::new(),
                    ObjectState::First,
                    None,
                )))
            }
            Some(b'-' | b'0'..=b'9') => Ok(Start::Value(Value::Number(self.number()?))),
            _ => Err(()),
        }
    }

    fn digits(&mut self) -> Result<(), ()> {
        let start = self.position;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.position += 1;
        }
        if self.position == start {
            Err(())
        } else {
            Ok(())
        }
    }

    fn number(&mut self) -> Result<f64, ()> {
        let start = self.position;
        if self.peek() == Some(b'-') {
            self.position += 1;
        }
        match self.peek() {
            Some(b'0') => self.position += 1,
            Some(b'1'..=b'9') => self.digits()?,
            _ => return Err(()),
        }
        if self.peek() == Some(b'.') {
            self.position += 1;
            self.digits()?;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.position += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.position += 1;
            }
            self.digits()?;
        }
        self.source[start..self.position].parse().map_err(|_| ())
    }

    fn hex_unit(&mut self) -> Result<u16, ()> {
        let mut value = 0;
        for _ in 0..4 {
            let digit = match self.peek() {
                Some(byte @ b'0'..=b'9') => byte - b'0',
                Some(byte @ b'a'..=b'f') => byte - b'a' + 10,
                Some(byte @ b'A'..=b'F') => byte - b'A' + 10,
                _ => return Err(()),
            };
            value = (value << 4) | u16::from(digit);
            self.position += 1;
        }
        Ok(value)
    }

    fn string(&mut self) -> Result<Vec<u16>, ()> {
        self.expect(b'"')?;
        let mut value = Vec::new();
        loop {
            match self.peek() {
                None | Some(0..=0x1f) => return Err(()),
                Some(b'"') => {
                    self.position += 1;
                    return Ok(value);
                }
                Some(b'\\') => {
                    self.position += 1;
                    let escaped = self.peek().ok_or(())?;
                    self.position += 1;
                    value.push(match escaped {
                        b'"' => u16::from(b'"'),
                        b'\\' => u16::from(b'\\'),
                        b'/' => u16::from(b'/'),
                        b'b' => 0x08,
                        b'f' => 0x0c,
                        b'n' => 0x0a,
                        b'r' => 0x0d,
                        b't' => 0x09,
                        b'u' => self.hex_unit()?,
                        _ => return Err(()),
                    });
                }
                Some(byte @ 0x20..=0x7f) => {
                    value.push(u16::from(byte));
                    self.position += 1;
                }
                Some(_) => {
                    let character = self.source[self.position..].chars().next().ok_or(())?;
                    let mut units = [0; 2];
                    value.extend_from_slice(character.encode_utf16(&mut units));
                    self.position += character.len_utf8();
                }
            }
        }
    }
}

fn close(frame: Frame) -> Value {
    match frame {
        Frame::Array(values, _) => Value::Array(values),
        Frame::Object(values, _, _) => Value::Object(values),
    }
}

pub(crate) fn parse(source: &str) -> Result<Value, ()> {
    let mut parser = Parser {
        source,
        position: 0,
    };
    let mut frames = Vec::new();
    let mut completed = None;
    loop {
        if let Some(value) = completed.take() {
            match frames.last_mut() {
                Some(Frame::Array(values, state)) => {
                    values.push(value);
                    *state = ArrayState::Separator;
                }
                Some(Frame::Object(values, state, key)) => {
                    values.insert(key.take().ok_or(())?, value);
                    *state = ObjectState::Separator;
                }
                None => {
                    parser.whitespace();
                    return if parser.peek().is_none() {
                        Ok(value)
                    } else {
                        Err(())
                    };
                }
            }
            continue;
        }
        parser.whitespace();
        let action = match frames.last() {
            None => Action::Value,
            Some(Frame::Array(_, ArrayState::First)) if parser.peek() == Some(b']') => {
                Action::Close
            }
            Some(Frame::Array(_, ArrayState::First | ArrayState::Value)) => Action::Value,
            Some(Frame::Array(_, ArrayState::Separator)) => Action::ArraySeparator,
            Some(Frame::Object(_, ObjectState::First, _)) if parser.peek() == Some(b'}') => {
                Action::Close
            }
            Some(Frame::Object(_, ObjectState::First | ObjectState::Key, _)) => Action::Key,
            Some(Frame::Object(_, ObjectState::Colon, _)) => Action::Colon,
            Some(Frame::Object(_, ObjectState::Value, _)) => Action::Value,
            Some(Frame::Object(_, ObjectState::Separator, _)) => Action::ObjectSeparator,
        };
        match action {
            Action::Value => match parser.start()? {
                Start::Value(value) => completed = Some(value),
                Start::Frame(frame) => frames.push(frame),
            },
            Action::Key => {
                let key = parser.string()?;
                if let Some(Frame::Object(_, state, pending)) = frames.last_mut() {
                    *pending = Some(key);
                    *state = ObjectState::Colon;
                }
            }
            Action::Colon => {
                parser.expect(b':')?;
                if let Some(Frame::Object(_, state, _)) = frames.last_mut() {
                    *state = ObjectState::Value;
                }
            }
            Action::ArraySeparator => match parser.peek() {
                Some(b',') => {
                    parser.position += 1;
                    if let Some(Frame::Array(_, state)) = frames.last_mut() {
                        *state = ArrayState::Value;
                    }
                }
                Some(b']') => {
                    parser.position += 1;
                    completed = Some(close(frames.pop().ok_or(())?));
                }
                _ => return Err(()),
            },
            Action::ObjectSeparator => match parser.peek() {
                Some(b',') => {
                    parser.position += 1;
                    if let Some(Frame::Object(_, state, _)) = frames.last_mut() {
                        *state = ObjectState::Key;
                    }
                }
                Some(b'}') => {
                    parser.position += 1;
                    completed = Some(close(frames.pop().ok_or(())?));
                }
                _ => return Err(()),
            },
            Action::Close => {
                parser.position += 1;
                completed = Some(close(frames.pop().ok_or(())?));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn antibody_json_grammar_refuses_malformed_tokens_and_separators() {
        for source in [
            "",
            " ",
            "+1",
            "01",
            "-01",
            "-",
            "-.1",
            ".1",
            "1.",
            "1e",
            "1e+",
            "1e-",
            "NaN",
            "Infinity",
            "TRUE",
            "nul",
            "null x",
            "null null",
            "[",
            "[1,]",
            "[,1]",
            "[1 2]",
            "{",
            "{\"a\"}",
            "{a:1}",
            "{\"a\"x1}",
            "{\"a\":}",
            "{\"a\":1,}",
            "{\"a\":1 \"b\":2}",
            "\"",
            "\"\\x20\"",
            "\"\\u000\"",
            "\"\\u00gg\"",
            "\"raw\nline\"",
            "\"\0\"",
            "\u{feff}null",
            "null\u{00a0}",
        ] {
            assert!(parse(source).is_err(), "{source:?}");
        }
    }

    #[test]
    fn json_numbers_keep_js_overflow_rounding_and_signed_zero() {
        for (source, expected) in [
            ("1e400", f64::INFINITY),
            ("-1e400", f64::NEG_INFINITY),
            ("1e-400", 0.0),
            ("9007199254740993", 9_007_199_254_740_992.0),
            ("1.25E+2", 125.0),
            ("-0.25e-2", -0.0025),
        ] {
            assert_eq!(parse(source).unwrap().as_f64(), Some(expected), "{source}");
        }
        assert!(parse("-0").unwrap().as_f64().unwrap().is_sign_negative());
    }

    #[test]
    fn json_strings_preserve_unpaired_units_and_pair_valid_surrogates() {
        assert_eq!(
            parse(r#""\ud800""#).unwrap(),
            Value::UnpairedString(vec![0xd800])
        );
        assert_eq!(
            parse(r#""\udfff""#).unwrap(),
            Value::UnpairedString(vec![0xdfff])
        );
        assert_eq!(
            parse(r#""\ud800\ud800\udc00""#).unwrap(),
            Value::UnpairedString(vec![0xd800, 0xd800, 0xdc00])
        );
        assert_eq!(parse(r#""\ud83d\ude00""#).unwrap().as_str(), Some("😀"));
        assert_eq!(
            parse("\"雪😀\u{2028}\u{2029}\"").unwrap().as_str(),
            Some("雪😀\u{2028}\u{2029}")
        );
        assert_eq!(
            parse(r#""\"\\\/\b\f\n\r\t\u0000""#).unwrap().as_str(),
            Some("\"\\/\u{8}\u{c}\n\r\t\0")
        );
    }

    #[test]
    fn json_objects_keep_last_duplicate_and_exact_utf16_keys() {
        let value = parse(r#"{"v":1,"v":0,"\ud800":1,"�":2,"\ud83d\ude00":3,"😀":4}"#).unwrap();
        assert_eq!(value["v"].as_f64(), Some(0.0));
        assert_eq!(value["�"].as_f64(), Some(2.0));
        assert_eq!(value["😀"].as_f64(), Some(4.0));
        let Value::Object(values) = &value else {
            panic!()
        };
        assert_eq!(values.len(), 4);
        assert_eq!(values.get(&vec![0xd800]).unwrap().as_f64(), Some(1.0));
    }

    #[test]
    fn json_containers_and_indexing_follow_values_without_depth_cap() {
        let value =
            parse(" \n {\"a\":[1,{\"b\":false},null],\"empty\":{},\"s\":\"\"} \t\r").unwrap();
        assert!(value.is_object());
        assert!(value["a"].is_array());
        assert!(value["empty"].is_object());
        assert_eq!(value["s"].as_str(), Some(""));
        assert_eq!(value["missing"], Value::Null);
        assert_eq!(Value::Null["missing"], Value::Null);
        assert_eq!(Value::from(15).as_f64(), Some(15.0));
        assert!(Value::Bool(false).is_boolean());
        assert!(Value::UnpairedString(vec![0xd800]).is_string());

        let depth = 2_000;
        let source = "[".repeat(depth) + "null" + &"]".repeat(depth);
        let mut value = parse(&source).unwrap();
        for _ in 0..depth {
            let Value::Array(values) = &mut value else {
                panic!()
            };
            assert_eq!(values.len(), 1);
            value = values.pop().unwrap();
        }
        assert_eq!(value, Value::Null);
    }

    #[test]
    fn antibody_deep_unknown_json_drops_without_recursive_stack_growth() {
        const WORKER: &str = "AUKORA_COPRESENCE_DEEP_JSON_WORKER";
        if std::env::var_os(WORKER).is_none() {
            let thread = std::thread::current();
            let test = thread.name().unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", test, "--nocapture"])
                .env(WORKER, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "deep JSON worker failed: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(|| {
                let depth = 30_000;
                let source = "[".repeat(depth) + "null" + &"]".repeat(depth);
                let value = parse(&source).unwrap();
                assert!(value.is_array());
                drop(value);
                let source = "{\"a\":".repeat(depth) + "null" + &"}".repeat(depth);
                let value = parse(&source).unwrap();
                assert!(value.is_object());
                drop(value);
            })
            .unwrap()
            .join()
            .unwrap();
    }
}
