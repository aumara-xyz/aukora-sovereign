// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{
    codes,
    digest::Digest32,
    json::{SafeInteger, Value, ValueView},
    Result,
};
use base64::Engine;

pub(crate) const MAX: u64 = crate::json::MAX_SAFE_INTEGER as u64;

pub(crate) struct Object<'a>(&'a Value);
impl<'a> Object<'a> {
    pub(crate) fn new(value: &'a Value, required: &[&str], optional: &[&str]) -> Result<Self> {
        let ValueView::Object(fields) = value.view() else {
            return Err(codes::FRAME_NOT_OBJECT);
        };
        if fields
            .iter()
            .any(|(key, _)| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
        {
            return Err(codes::FRAME_UNKNOWN_FIELD);
        }
        if required.iter().any(|key| value.get(key).is_none()) {
            return Err(codes::FRAME_MISSING_FIELD);
        }
        Ok(Self(value))
    }
    pub(crate) fn get(&self, key: &str) -> Result<&'a Value> {
        self.0.get(key).ok_or(codes::FRAME_MISSING_FIELD)
    }
    pub(crate) fn optional(&self, key: &str) -> Option<&'a Value> {
        self.0.get(key)
    }
    pub(crate) fn text(&self, key: &str) -> Result<String> {
        Ok(text(self.get(key)?)?.to_owned())
    }
    pub(crate) fn count(&self, key: &str, min: u64, max: u64) -> Result<u64> {
        count(self.get(key)?, min, max)
    }
    pub(crate) fn boolean(&self, key: &str) -> Result<bool> {
        boolean(self.get(key)?)
    }
    pub(crate) fn digest(&self, key: &str) -> Result<Digest32> {
        digest(self.get(key)?)
    }
}

pub(crate) fn text(value: &Value) -> Result<&str> {
    match value.view() {
        ValueView::Text(s) => Ok(s),
        _ => Err(codes::FRAME_INVALID_FIELD),
    }
}
pub(crate) fn boolean(value: &Value) -> Result<bool> {
    match value.view() {
        ValueView::Boolean(b) => Ok(b),
        _ => Err(codes::FRAME_INVALID_FIELD),
    }
}
pub(crate) fn count(value: &Value, min: u64, max: u64) -> Result<u64> {
    match value.view() {
        ValueView::Integer(n) if n.get() >= 0 && (min..=max).contains(&(n.get() as u64)) => {
            Ok(n.get() as u64)
        }
        _ => Err(codes::FRAME_INVALID_FIELD),
    }
}
pub(crate) fn digest(value: &Value) -> Result<Digest32> {
    Digest32::from_hex(text(value)?).map_err(|_| codes::FRAME_INVALID_FIELD)
}
pub(crate) fn bounded(value: &Value, min: usize, max: usize) -> Result<String> {
    let s = text(value)?;
    if !(min..=max).contains(&s.len()) {
        return Err(codes::FRAME_INVALID_FIELD);
    }
    Ok(s.to_owned())
}
pub(crate) fn nullable<T>(
    value: &Value,
    decode: impl FnOnce(&Value) -> Result<T>,
) -> Result<Option<T>> {
    if matches!(value.view(), ValueView::Null) {
        Ok(None)
    } else {
        decode(value).map(Some)
    }
}
pub(crate) fn strings(value: &Value) -> Result<Option<String>> {
    nullable(value, |v| Ok(text(v)?.to_owned()))
}
pub(crate) fn list<T>(
    value: &Value,
    mut decode: impl FnMut(&Value) -> Result<T>,
) -> Result<Vec<T>> {
    let ValueView::Array(values) = value.view() else {
        return Err(codes::FRAME_INVALID_FIELD);
    };
    values.iter().map(&mut decode).collect()
}
pub(crate) fn b64(value: &Value) -> Result<String> {
    let s = text(value)?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|_| codes::FRAME_INVALID_FIELD)?;
    if decoded.len() > 65_536 {
        return Err(codes::FRAME_INVALID_FIELD);
    }
    Ok(s.to_owned())
}
pub(crate) fn object(fields: Vec<(&str, Value)>) -> Result<Value> {
    Value::object(
        fields
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}
pub(crate) fn s(value: impl ToString) -> Value {
    Value::checked_text(value.to_string()).expect("text has no additional C1 constraints")
}
pub(crate) fn n(value: u64) -> Result<Value> {
    let signed = i64::try_from(value).map_err(|_| codes::FRAME_INVALID_FIELD)?;
    Ok(Value::integer(
        SafeInteger::new(signed).map_err(|_| codes::FRAME_INVALID_FIELD)?,
    ))
}
pub(crate) fn maybe<T>(
    value: Option<&T>,
    encode: impl FnOnce(&T) -> Result<Value>,
) -> Result<Value> {
    value.map(encode).unwrap_or_else(|| Ok(Value::null()))
}
pub(crate) fn array<T>(items: &[T], encode: impl FnMut(&T) -> Result<Value>) -> Result<Value> {
    Value::array(items.iter().map(encode).collect::<Result<_>>()?)
}
