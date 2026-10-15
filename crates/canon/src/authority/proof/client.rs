// SPDX-License-Identifier: AGPL-3.0-or-later
//! WebAuthn JSON parsing independent of the C1 integer-only codec.

use crate::{codes, Result};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::fmt;

struct JsonValue(usize);

impl<'de> DeserializeSeed<'de> for JsonValue {
    type Value = Value;

    fn deserialize<D: de::Deserializer<'de>>(
        self,
        decoder: D,
    ) -> core::result::Result<Value, D::Error> {
        decoder.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for JsonValue {
    type Value = Value;

    fn expecting(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str("bounded WebAuthn JSON")
    }

    fn visit_unit<E: de::Error>(self) -> core::result::Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_bool<E: de::Error>(self, value: bool) -> core::result::Result<Value, E> {
        Ok(value.into())
    }
    fn visit_str<E: de::Error>(self, value: &str) -> core::result::Result<Value, E> {
        Ok(value.into())
    }
    fn visit_string<E: de::Error>(self, value: String) -> core::result::Result<Value, E> {
        Ok(value.into())
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> core::result::Result<Value, E> {
        if value > crate::json::MAX_SAFE_INTEGER as u64 {
            return Err(E::custom("integer range"));
        }
        Ok(value.into())
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> core::result::Result<Value, E> {
        if !(-crate::json::MAX_SAFE_INTEGER..=crate::json::MAX_SAFE_INTEGER).contains(&value) {
            return Err(E::custom("integer range"));
        }
        Ok(value.into())
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> core::result::Result<Value, E> {
        if value.fract() == 0.0 && value.abs() > crate::json::MAX_SAFE_INTEGER as f64 {
            return Err(E::custom("integer range"));
        }
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("finite number"))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> core::result::Result<Value, A::Error> {
        if self.0 >= 512 {
            return Err(de::Error::custom("nesting limit"));
        }
        let mut values = Vec::new();
        while let Some(value) = access.next_element_seed(JsonValue(self.0 + 1))? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> core::result::Result<Value, A::Error> {
        if self.0 >= 512 {
            return Err(de::Error::custom("nesting limit"));
        }
        let mut fields = Map::new();
        while let Some(name) = access.next_key::<String>()? {
            if fields.contains_key(&name) {
                return Err(de::Error::custom("duplicate field"));
            }
            let value = access.next_value_seed(JsonValue(self.0 + 1))?;
            fields.insert(name, value);
        }
        Ok(Value::Object(fields))
    }
}

pub(super) fn parse(bytes: &[u8]) -> Result<Map<String, Value>> {
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    let mut parser = serde_json::Deserializer::from_slice(bytes);
    parser.disable_recursion_limit();
    let value = JsonValue(0)
        .deserialize(&mut parser)
        .map_err(|_| codes::GATE_PROOF_INVALID)?;
    parser.end().map_err(|_| codes::GATE_PROOF_INVALID)?;
    match value {
        Value::Object(fields) => Ok(fields),
        _ => Err(codes::GATE_PROOF_INVALID),
    }
}
