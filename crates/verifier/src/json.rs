use std::collections::BTreeMap;

pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
const MAX_DEPTH: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    String(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}

pub fn parse(input: &[u8]) -> Result<Value, String> {
    if input.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err("verifier:json-bom".into());
    }
    let input = std::str::from_utf8(input).map_err(|_| "verifier:json-utf8".to_owned())?;
    let mut parser = Parser { input, pos: 0 };
    let value = parser.value(0)?;
    parser.whitespace();
    if parser.pos != input.len() {
        return Err("verifier:json-trailing".into());
    }
    Ok(value)
}

pub fn parse_canonical(input: &[u8]) -> Result<Value, String> {
    let value = parse(input)?;
    if canonical(&value) != input {
        return Err("verifier:json-not-canonical".into());
    }
    Ok(value)
}

pub fn canonical(value: &Value) -> Vec<u8> {
    let mut result = String::new();
    serialize(value, &mut result);
    result.into_bytes()
}

fn serialize(value: &Value, output: &mut String) {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(true) => output.push_str("true"),
        Value::Bool(false) => output.push_str("false"),
        Value::Int(value) => output.push_str(&value.to_string()),
        Value::String(value) => serialize_string(value, output),
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                serialize(value, output);
            }
            output.push(']');
        }
        Value::Object(values) => {
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort_by(|left, right| left.encode_utf16().cmp(right.encode_utf16()));
            output.push('{');
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                serialize_string(key, output);
                output.push(':');
                serialize(&values[key], output);
            }
            output.push('}');
        }
    }
}

fn serialize_string(value: &str, output: &mut String) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{0008}' => output.push_str("\\b"),
            '\u{000c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character < '\u{0020}' => {
                let code = character as usize;
                output.push_str("\\u00");
                output.push(char::from(HEX[code >> 4]));
                output.push(char::from(HEX[code & 15]));
            }
            character => output.push(character),
        }
    }
    output.push('"');
}

struct Parser<'a> {
    input: &'a str,
    pos: usize,
}

impl Parser<'_> {
    fn byte(&self) -> Option<u8> {
        self.input.as_bytes().get(self.pos).copied()
    }

    fn whitespace(&mut self) {
        while matches!(self.byte(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.pos += 1;
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, String> {
        self.whitespace();
        match self.byte() {
            Some(b'n') => self.literal("null", Value::Null),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'"') => self.string().map(Value::String),
            Some(b'-' | b'0'..=b'9') => self.integer(),
            Some(b'[' | b'{') if depth >= MAX_DEPTH => Err("verifier:json-depth".into()),
            Some(b'[') => self.array(depth + 1),
            Some(b'{') => self.object(depth + 1),
            _ => Err("verifier:json-value".into()),
        }
    }

    fn literal(&mut self, text: &str, value: Value) -> Result<Value, String> {
        if !self.input[self.pos..].starts_with(text) {
            return Err("verifier:json-literal".into());
        }
        self.pos += text.len();
        Ok(value)
    }

    fn integer(&mut self) -> Result<Value, String> {
        let start = self.pos;
        if self.byte() == Some(b'-') {
            self.pos += 1;
        }
        let digits = self.pos;
        while matches!(self.byte(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        let text = &self.input[start..self.pos];
        if self.pos == digits
            || (self.input.as_bytes()[digits] == b'0' && self.pos - digits != 1)
            || text == "-0"
            || matches!(self.byte(), Some(b'.' | b'e' | b'E'))
        {
            return Err("verifier:json-number".into());
        }
        let integer: i64 = text
            .parse()
            .map_err(|_| "verifier:json-number".to_owned())?;
        if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&integer) {
            return Err("verifier:json-number-range".into());
        }
        Ok(Value::Int(integer))
    }

    fn string(&mut self) -> Result<String, String> {
        self.pos += 1;
        let mut result = String::new();
        loop {
            let character = self.input[self.pos..]
                .chars()
                .next()
                .ok_or_else(|| "verifier:json-string".to_owned())?;
            self.pos += character.len_utf8();
            match character {
                '"' => return Ok(result),
                '\\' => result.push(self.escape()?),
                character if character < '\u{0020}' => {
                    return Err("verifier:json-string-control".into());
                }
                character => result.push(character),
            }
        }
    }

    fn escape(&mut self) -> Result<char, String> {
        let byte = self
            .byte()
            .ok_or_else(|| "verifier:json-escape".to_owned())?;
        self.pos += 1;
        match byte {
            b'"' => Ok('"'),
            b'\\' => Ok('\\'),
            b'/' => Ok('/'),
            b'b' => Ok('\u{0008}'),
            b'f' => Ok('\u{000c}'),
            b'n' => Ok('\n'),
            b'r' => Ok('\r'),
            b't' => Ok('\t'),
            b'u' => {
                let first = self.hex4()?;
                let scalar = if (0xd800..=0xdbff).contains(&first) {
                    if !self.input[self.pos..].starts_with("\\u") {
                        return Err("verifier:json-surrogate".into());
                    }
                    self.pos += 2;
                    let second = self.hex4()?;
                    if !(0xdc00..=0xdfff).contains(&second) {
                        return Err("verifier:json-surrogate".into());
                    }
                    0x10000 + (u32::from(first) - 0xd800) * 0x400 + u32::from(second) - 0xdc00
                } else if (0xdc00..=0xdfff).contains(&first) {
                    return Err("verifier:json-surrogate".into());
                } else {
                    u32::from(first)
                };
                char::from_u32(scalar).ok_or_else(|| "verifier:json-surrogate".to_owned())
            }
            _ => Err("verifier:json-escape".into()),
        }
    }

    fn hex4(&mut self) -> Result<u16, String> {
        let mut result = 0_u16;
        for _ in 0..4 {
            let byte = self
                .byte()
                .ok_or_else(|| "verifier:json-escape".to_owned())?;
            let value = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => return Err("verifier:json-escape".into()),
            };
            self.pos += 1;
            result = result * 16 + u16::from(value);
        }
        Ok(result)
    }

    fn array(&mut self, depth: usize) -> Result<Value, String> {
        self.pos += 1;
        self.whitespace();
        let mut values = Vec::new();
        if self.byte() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(values));
        }
        loop {
            values.push(self.value(depth)?);
            self.whitespace();
            match self.byte() {
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Value::Array(values));
                }
                Some(b',') => self.pos += 1,
                _ => return Err("verifier:json-array".into()),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, String> {
        self.pos += 1;
        self.whitespace();
        let mut values = BTreeMap::new();
        if self.byte() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Object(values));
        }
        loop {
            self.whitespace();
            if self.byte() != Some(b'"') {
                return Err("verifier:json-object-key".into());
            }
            let key = self.string()?;
            self.whitespace();
            if self.byte() != Some(b':') {
                return Err("verifier:json-object-colon".into());
            }
            self.pos += 1;
            let value = self.value(depth)?;
            if values.insert(key, value).is_some() {
                return Err("verifier:json-duplicate-key".into());
            }
            self.whitespace();
            match self.byte() {
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Value::Object(values));
                }
                Some(b',') => self.pos += 1,
                _ => return Err("verifier:json-object".into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_json_refuses_invalid_utf8_and_bom() {
        assert_eq!(parse(&[b'"', 0xff, b'"']), Err("verifier:json-utf8".into()));
        assert_eq!(parse(&[0xff]), Err("verifier:json-utf8".into()));
        assert_eq!(parse(b"\xef\xbb\xbfnull"), Err("verifier:json-bom".into()));
    }

    #[test]
    fn strict_json_refuses_duplicate_decoded_keys() {
        assert_eq!(
            parse(br#"{"a":1,"\u0061":2}"#),
            Err("verifier:json-duplicate-key".into())
        );
        assert!(parse(br#"{"a":1,"nested":{"a":2}}"#).is_ok());
    }

    #[test]
    fn strict_json_refuses_noncanonical_integer_lexemes() {
        for input in ["-", "+1", "01", "-01", "-0", "1.0", "1e0", "1E0", "NaN"] {
            assert!(parse(input.as_bytes()).is_err(), "accepted {input}");
        }
        for input in ["0", "1", "-1", "9007199254740991", "-9007199254740991"] {
            assert_eq!(
                canonical(&parse(input.as_bytes()).unwrap()),
                input.as_bytes()
            );
        }
    }

    #[test]
    fn strict_json_refuses_integer_overflow_and_unsafe_range() {
        for input in [
            "9007199254740992",
            "-9007199254740992",
            "9223372036854775808",
            "-9223372036854775809",
        ] {
            assert!(parse(input.as_bytes()).is_err(), "accepted {input}");
        }
    }

    #[test]
    fn strict_json_refuses_lone_surrogates() {
        for input in [
            r#""\ud800""#,
            r#""\udbff""#,
            r#""\udc00""#,
            r#""\udfff""#,
            r#""\ud800\u0000""#,
            r#""\ud800\ud800""#,
        ] {
            assert!(parse(input.as_bytes()).is_err(), "accepted {input}");
        }
        assert_eq!(
            parse(br#""\ud800\udc00""#),
            Ok(Value::String("\u{10000}".into()))
        );
        assert_eq!(
            parse(br#""\uDBFF\uDFFF""#),
            Ok(Value::String("\u{10ffff}".into()))
        );
    }

    #[test]
    fn strict_json_refuses_depth_above_64() {
        let nested = |depth| format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
        assert!(parse(nested(64).as_bytes()).is_ok());
        assert_eq!(
            parse(nested(65).as_bytes()),
            Err("verifier:json-depth".into())
        );
        let nested_objects = format!("{}null{}", "{\"a\":".repeat(65), "}".repeat(65));
        assert_eq!(
            parse(nested_objects.as_bytes()),
            Err("verifier:json-depth".into())
        );
    }

    #[test]
    fn strict_json_refuses_trailing_values_and_bad_grammar() {
        for input in [
            "null true",
            "truex",
            "[1,]",
            "{\"a\":1,}",
            "{a:1}",
            "[",
            "{",
            "{\"a\" 1}",
            "[1 2]",
            "nul",
            "False",
        ] {
            assert!(parse(input.as_bytes()).is_err(), "accepted {input}");
        }
    }

    #[test]
    fn strict_json_refuses_invalid_string_controls_and_escapes() {
        for input in [
            "\"\n\"",
            "\"\u{0000}\"",
            r#""\x20""#,
            r#""\uZZZZ""#,
            r#""\u123""#,
            "\"unfinished",
            "\"unfinished\\",
        ] {
            assert!(parse(input.as_bytes()).is_err(), "accepted {input}");
        }
    }

    #[test]
    fn canonical_json_requires_exact_bytes() {
        for input in [
            " null",
            "null\n",
            "{\"b\":1,\"a\":2}",
            "[1, 2]",
            r#""\u0061""#,
            r#""\/""#,
        ] {
            assert_eq!(
                parse_canonical(input.as_bytes()),
                Err("verifier:json-not-canonical".into()),
                "accepted {input}"
            );
        }
        assert!(parse_canonical(br#"{"a":[true,false,null,-1],"b":{}}"#).is_ok());
    }

    #[test]
    fn canonical_json_uses_javascript_utf16_key_order() {
        let value = parse("{\"\u{e000}\":1,\"\u{10000}\":2}".as_bytes()).unwrap();
        assert_eq!(
            canonical(&value),
            "{\"\u{10000}\":2,\"\u{e000}\":1}".as_bytes()
        );
    }

    #[test]
    fn canonical_json_uses_javascript_string_escaping() {
        let text = "\"\\\u{0008}\u{000c}\n\r\t\u{0000}\u{001f}/\u{007f}\u{2028}\u{2029}🙂";
        let expected = "\"\\\"\\\\\\b\\f\\n\\r\\t\\u0000\\u001f/\u{007f}\u{2028}\u{2029}🙂\"";
        assert_eq!(canonical(&Value::String(text.into())), expected.as_bytes());
        assert_eq!(parse(expected.as_bytes()), Ok(Value::String(text.into())));
    }
}
