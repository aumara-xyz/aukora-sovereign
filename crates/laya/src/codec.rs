// SPDX-License-Identifier: AGPL-3.0-or-later
//! Strict C1 reading shared by the grant and slider-policy codecs: one canonical document, exact keys, no extras.

use canon::json::{self, SafeInteger, Value, ValueView};

/// Parse one C1 document and require the input to be its own canonical form.
pub(crate) fn canonical(bytes: &[u8], max: usize) -> Option<Value> {
    if bytes.is_empty() || bytes.len() > max {
        return None;
    }
    let value = json::parse_strict(bytes).ok()?;
    (value.canonical_bytes() == bytes).then_some(value)
}

/// The object's members when its keys are exactly `keys` (any order).
pub(crate) fn exact<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a [(String, Value)]> {
    let ValueView::Object(members) = value.view() else { return None };
    (members.len() == keys.len() && keys.iter().all(|key| members.iter().any(|(name, _)| name == key))).then_some(members)
}

pub(crate) fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    match value.get(key)?.view() {
        ValueView::Text(text) => Some(text),
        _ => None,
    }
}

pub(crate) fn int(value: &Value, key: &str) -> Option<i64> {
    match value.get(key)?.view() {
        ValueView::Integer(number) => Some(number.get()),
        _ => None,
    }
}

pub(crate) fn array<'a>(value: &'a Value, key: &str) -> Option<&'a [Value]> {
    match value.get(key)?.view() {
        ValueView::Array(items) => Some(items),
        _ => None,
    }
}

pub(crate) fn strings(items: &[Value]) -> Option<Vec<String>> {
    items
        .iter()
        .map(|item| match item.view() {
            ValueView::Text(text) => Some(text.to_owned()),
            _ => None,
        })
        .collect()
}

pub(crate) fn number(value: i64) -> Option<Value> {
    SafeInteger::new(value).ok().map(Value::integer)
}

pub(crate) fn string(value: &str) -> Option<Value> {
    Value::checked_text(value.to_owned()).ok()
}

pub(crate) fn string_array(values: &[String]) -> Option<Value> {
    let items: Option<Vec<Value>> = values.iter().map(|value| string(value)).collect();
    Value::checked_array(items?).ok()
}
