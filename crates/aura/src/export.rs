// SPDX-License-Identifier: AGPL-3.0-or-later
//! Frozen cold-proof-v1 data; no field grants authority or independent trust.

use canon::{
    authority::{Kind, Phase},
    digest::Digest32,
    ids::OperationId,
    json::{self, SafeInteger, Value, ValueView},
    Result,
};

pub const COLD_PROOF_SCHEMA: &str = "aukora-aura-cold-proof-v1";
pub const RETAINED_HEAD_SCHEMA: &str = "aukora-aura-retained-head-v1";
pub const PRESENTED_HEAD_SCHEMA: &str = "aukora-aura-presented-head-v1";
pub const LEAF_CONVENTION: &str = canon::domain::RFC6962_LEAF_CONVENTION;

/// The ten C3 wire keys are seq,prev,hash,sig,at,kind,actor,op,phase,body.
/// Previous None represents the domain sentinel; absent operation represents "".
/// The signature remains one standard padded-base64 Ed25519 signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RowV1 {
    pub sequence: u64,
    pub previous: Option<Digest32>,
    pub hash: Digest32,
    pub signature: [u8; 64],
    pub at: i64,
    pub kind: Kind,
    pub actor: String,
    pub operation: Option<OperationId>,
    pub phase: Phase,
    pub body: Value,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedHeadV1 {
    pub sequence: u64,
    pub hash: Digest32,
    pub tree_size: u64,
    pub root: Digest32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresentedHeadV1 {
    pub tree_size: u64,
    pub root: Digest32,
    pub retained_tree_size: u64,
    pub proof_from_previous: Vec<Digest32>,
}

/// Wire keys are exactly head,publicKey,rows,schema. The embedded key is untrusted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ColdProofV1 {
    pub head: RetainedHeadV1,
    pub public_key: [u8; 32],
    pub rows: Vec<RowV1>,
}

/// Explicit caller limits bound parsing and output before allocating row bodies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExportLimits {
    pub max_bytes: usize,
    pub max_rows: usize,
}

impl ColdProofV1 {
    /// Strict C1 input with exact v1 keys, encodings and caller-selected limits.
    pub fn parse(bytes: &[u8], limits: ExportLimits) -> Result<Self> {
        if bytes.len() > limits.max_bytes {
            return Err(BAD);
        }
        preflight_rows(bytes, limits.max_rows)?;
        let document = json::parse_strict(bytes)?;
        exact_keys(&document, &["head", "publicKey", "rows", "schema"])?;
        require_text(&document, "schema", COLD_PROOF_SCHEMA)?;
        let raw_rows = array(member(&document, "rows")?)?;
        if raw_rows.is_empty() || raw_rows.len() > limits.max_rows {
            return Err(BAD);
        }
        let rows = raw_rows.iter().map(parse_row).collect::<Result<Vec<_>>>()?;
        let proof = Self {
            head: parse_head(member(&document, "head")?)?,
            public_key: *digest(member(&document, "publicKey")?)?.as_bytes(),
            rows,
        };
        proof.verify()?;
        Ok(proof)
    }

    /// Verify both arms and signatures. The embedded key remains an untrusted claim.
    pub fn verify(&self) -> Result<()> {
        use ed25519_dalek::{Signature, VerifyingKey};
        use std::collections::BTreeSet;
        validate_head(&self.head)?;
        if self.rows.len() as u64 != self.head.sequence {
            return Err(BAD);
        }
        let key = VerifyingKey::from_bytes(&self.public_key).map_err(|_| BAD)?;
        let mut tree = crate::merkle::Frontier::default();
        let mut previous = None;
        let mut terminal = BTreeSet::new();
        for row in &self.rows {
            let sequence = tree.size().checked_add(1).ok_or(BAD)?;
            if row.sequence != sequence
                || row.previous != previous
                || crate::record::entry_hash_v1(row)? != row.hash
            {
                return Err(BAD);
            }
            key.verify_strict(row.hash.as_bytes(), &Signature::from_bytes(&row.signature))
                .map_err(|_| BAD)?;
            if row.phase == Phase::Terminal && !terminal.insert(row.operation.ok_or(BAD)?) {
                return Err(BAD);
            }
            tree.push(row.hash)?;
            previous = Some(row.hash);
        }
        if previous != Some(self.head.hash) || tree.root() != self.head.root {
            return Err(BAD);
        }
        Ok(())
    }

    /// Independently retained trust is supplied by the caller, never by this file.
    pub fn verify_against(&self, trusted_key: &[u8; 32], retained: &RetainedHeadV1) -> Result<()> {
        if &self.public_key != trusted_key {
            return Err(BAD);
        }
        self.verify()?;
        validate_head(retained)?;
        if retained.sequence > self.head.sequence {
            return Err(BAD);
        }
        let mut prefix = crate::merkle::Frontier::default();
        for row in self.rows.iter().take(retained.sequence as usize) {
            prefix.push(row.hash)?;
            if row.sequence == retained.sequence && row.hash != retained.hash {
                return Err(BAD);
            }
        }
        if prefix.root() != retained.root {
            return Err(BAD);
        }
        Ok(())
    }

    /// Verify the whole snapshot before emitting bytes; no fixed transport cap.
    pub fn canonical_bytes(&self, limits: ExportLimits) -> Result<Vec<u8>> {
        if self.rows.len() > limits.max_rows {
            return Err(BAD);
        }
        self.verify()?;
        let mut output = Vec::new();
        append(&mut output, b"{\"head\":", limits.max_bytes)?;
        append(&mut output, &self.head.canonical_bytes()?, limits.max_bytes)?;
        append(&mut output, b",\"publicKey\":\"", limits.max_bytes)?;
        append(
            &mut output,
            Digest32::from_bytes(self.public_key).to_string().as_bytes(),
            limits.max_bytes,
        )?;
        append(&mut output, b"\",\"rows\":[", limits.max_bytes)?;
        for (index, row) in self.rows.iter().enumerate() {
            if index != 0 {
                append(&mut output, b",", limits.max_bytes)?;
            }
            check_depth(&row.body, 3)?;
            let remaining = limits.max_bytes.checked_sub(output.len()).ok_or(BAD)?;
            if encoded_len(&row.body)? > remaining {
                return Err(BAD);
            }
            let value = row_value(row)?;
            if encoded_len(&value)? > remaining {
                return Err(BAD);
            }
            append(&mut output, &value.canonical_bytes(), limits.max_bytes)?;
        }
        append(&mut output, b"],\"schema\":\"", limits.max_bytes)?;
        append(&mut output, COLD_PROOF_SCHEMA.as_bytes(), limits.max_bytes)?;
        append(&mut output, b"\"}", limits.max_bytes)?;
        Ok(output)
    }
}

impl RetainedHeadV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        validate_head(self)?;
        Ok(object(vec![
            ("schema", text(RETAINED_HEAD_SCHEMA)?),
            ("leafConvention", text(LEAF_CONVENTION)?),
            ("sequence", unsigned(self.sequence)?),
            ("treeSize", unsigned(self.tree_size)?),
            ("hash", text(&self.hash.to_string())?),
            ("root", text(&self.root.to_string())?),
        ])?
        .canonical_bytes())
    }
}

impl PresentedHeadV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        if self.retained_tree_size == 0
            || self.retained_tree_size > self.tree_size
            || self.proof_from_previous.len() > 65
            || (self.retained_tree_size == self.tree_size && !self.proof_from_previous.is_empty())
        {
            return Err(BAD);
        }
        let proof = self
            .proof_from_previous
            .iter()
            .map(|hash| text(&hash.to_string()))
            .collect::<Result<Vec<_>>>()?;
        Ok(object(vec![
            ("schema", text(PRESENTED_HEAD_SCHEMA)?),
            ("leafConvention", text(LEAF_CONVENTION)?),
            ("treeSize", unsigned(self.tree_size)?),
            ("root", text(&self.root.to_string())?),
            ("retainedTreeSize", unsigned(self.retained_tree_size)?),
            ("proofFromPrevious", Value::array(proof)?),
        ])?
        .canonical_bytes())
    }
}

const BAD: canon::refusal::Refusal = canon::codes::AURA_UNVERIFIED;

fn validate_head(head: &RetainedHeadV1) -> Result<()> {
    if head.sequence == 0
        || head.sequence != head.tree_size
        || head.sequence > json::MAX_SAFE_INTEGER as u64
    {
        return Err(BAD);
    }
    Ok(())
}

fn parse_head(value: &Value) -> Result<RetainedHeadV1> {
    exact_keys(
        value,
        &[
            "hash",
            "leafConvention",
            "root",
            "schema",
            "sequence",
            "treeSize",
        ],
    )?;
    require_text(value, "schema", RETAINED_HEAD_SCHEMA)?;
    require_text(value, "leafConvention", LEAF_CONVENTION)?;
    let head = RetainedHeadV1 {
        sequence: number(member(value, "sequence")?)?,
        tree_size: number(member(value, "treeSize")?)?,
        hash: digest(member(value, "hash")?)?,
        root: digest(member(value, "root")?)?,
    };
    validate_head(&head)?;
    Ok(head)
}

pub(crate) fn parse_row(value: &Value) -> Result<RowV1> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    exact_keys(
        value,
        &[
            "seq", "prev", "hash", "sig", "at", "kind", "actor", "op", "phase", "body",
        ],
    )?;
    let previous = string(member(value, "prev")?)?;
    let operation = string(member(value, "op")?)?;
    let signature_text = string(member(value, "sig")?)?;
    let signature = STANDARD.decode(signature_text).map_err(|_| BAD)?;
    let signature: [u8; 64] = signature.try_into().map_err(|_| BAD)?;
    if STANDARD.encode(signature) != signature_text {
        return Err(BAD);
    }
    let at = match member(value, "at")?.view() {
        ValueView::Integer(at) => at.get(),
        _ => return Err(BAD),
    };
    Ok(RowV1 {
        sequence: number(member(value, "seq")?)?,
        previous: if previous == canon::domain::AURA_RECORD_DOMAIN {
            None
        } else {
            Some(Digest32::from_hex(previous).map_err(|_| BAD)?)
        },
        hash: digest(member(value, "hash")?)?,
        signature,
        at,
        kind: crate::record::kind_from_wire(string(member(value, "kind")?)?)?,
        actor: string(member(value, "actor")?)?.to_owned(),
        operation: if operation.is_empty() {
            None
        } else {
            Some(OperationId::from_hex(operation).map_err(|_| BAD)?)
        },
        phase: Phase::from_wire(string(member(value, "phase")?)?).map_err(|_| BAD)?,
        body: member(value, "body")?.clone(),
    })
}

pub(crate) fn row_value(row: &RowV1) -> Result<Value> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    object(vec![
        ("seq", unsigned(row.sequence)?),
        (
            "prev",
            text(
                &row.previous
                    .map(|hash| hash.to_string())
                    .unwrap_or_else(|| canon::domain::AURA_RECORD_DOMAIN.to_owned()),
            )?,
        ),
        ("hash", text(&row.hash.to_string())?),
        ("sig", text(&STANDARD.encode(row.signature))?),
        ("at", Value::integer(SafeInteger::new(row.at)?)),
        ("kind", text(row.kind.wire_name())?),
        ("actor", text(&row.actor)?),
        (
            "op",
            text(&row.operation.map(|id| id.to_string()).unwrap_or_default())?,
        ),
        ("phase", text(row.phase.wire_name())?),
        ("body", row.body.clone()),
    ])
}

fn exact_keys(value: &Value, expected: &[&str]) -> Result<()> {
    match value.view() {
        ValueView::Object(members)
            if members.len() == expected.len()
                && members
                    .iter()
                    .all(|(key, _)| expected.contains(&key.as_str())) =>
        {
            Ok(())
        }
        _ => Err(BAD),
    }
}

fn member<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    value.get(key).ok_or(BAD)
}
fn string(value: &Value) -> Result<&str> {
    match value.view() {
        ValueView::Text(text) => Ok(text),
        _ => Err(BAD),
    }
}
fn array(value: &Value) -> Result<&[Value]> {
    match value.view() {
        ValueView::Array(values) => Ok(values),
        _ => Err(BAD),
    }
}
fn number(value: &Value) -> Result<u64> {
    match value.view() {
        ValueView::Integer(value) => u64::try_from(value.get()).map_err(|_| BAD),
        _ => Err(BAD),
    }
}
fn digest(value: &Value) -> Result<Digest32> {
    Digest32::from_hex(string(value)?).map_err(|_| BAD)
}
fn require_text(value: &Value, key: &str, expected: &str) -> Result<()> {
    if string(member(value, key)?)? == expected {
        Ok(())
    } else {
        Err(BAD)
    }
}
fn text(value: &str) -> Result<Value> {
    Value::text(value.to_owned())
}
fn unsigned(value: u64) -> Result<Value> {
    Ok(Value::integer(SafeInteger::new(
        i64::try_from(value).map_err(|_| BAD)?,
    )?))
}
fn object(values: Vec<(&str, Value)>) -> Result<Value> {
    Value::object(
        values
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}
fn append(output: &mut Vec<u8>, bytes: &[u8], limit: usize) -> Result<()> {
    if output.len().checked_add(bytes.len()).ok_or(BAD)? > limit {
        return Err(BAD);
    }
    output.try_reserve(bytes.len()).map_err(|_| BAD)?;
    output.extend_from_slice(bytes);
    Ok(())
}

fn check_depth(value: &Value, depth: usize) -> Result<()> {
    match value.view() {
        ValueView::Array(values) => {
            if depth >= json::MAX_DEPTH {
                return Err(BAD);
            }
            for value in values {
                check_depth(value, depth + 1)?;
            }
        }
        ValueView::Object(values) => {
            if depth >= json::MAX_DEPTH {
                return Err(BAD);
            }
            for (_, value) in values {
                check_depth(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn encoded_len(value: &Value) -> Result<usize> {
    fn text_len(text: &str) -> Result<usize> {
        text.bytes().try_fold(2_usize, |total, byte| {
            let width = match byte {
                b'"' | b'\\' | 8 | 9 | 10 | 12 | 13 => 2,
                0..=31 => 6,
                _ => 1,
            };
            total.checked_add(width).ok_or(BAD)
        })
    }
    match value.view() {
        ValueView::Null => Ok(4),
        ValueView::Boolean(value) => Ok(if value { 4 } else { 5 }),
        ValueView::Integer(value) => Ok(value.get().to_string().len()),
        ValueView::Text(value) => text_len(value),
        ValueView::Array(values) => values
            .iter()
            .try_fold(2 + values.len().saturating_sub(1), |total, value| {
                total.checked_add(encoded_len(value)?).ok_or(BAD)
            }),
        ValueView::Object(values) => {
            values
                .iter()
                .try_fold(2 + values.len().saturating_sub(1), |total, (key, value)| {
                    let field_len = text_len(key)?
                        .checked_add(1)
                        .and_then(|n| n.checked_add(encoded_len(value).ok()?))
                        .ok_or(BAD)?;
                    total.checked_add(field_len).ok_or(BAD)
                })
        }
    }
}

// Scan only container boundaries before C1 parsing allocates row bodies.
fn preflight_rows(bytes: &[u8], max_rows: usize) -> Result<()> {
    let mut cursor = 0;
    skip_space(bytes, &mut cursor);
    if bytes.get(cursor) != Some(&b'{') {
        return Err(BAD);
    }
    cursor += 1;
    loop {
        skip_space(bytes, &mut cursor);
        if bytes.get(cursor) == Some(&b'}') {
            return Ok(());
        }
        if bytes.get(cursor) != Some(&b'"') {
            return Err(BAD);
        }
        let key_end = value_end(bytes, cursor)?;
        let key = json::parse_strict(&bytes[cursor..key_end])?;
        cursor = key_end;
        skip_space(bytes, &mut cursor);
        if bytes.get(cursor) != Some(&b':') {
            return Err(BAD);
        }
        cursor += 1;
        skip_space(bytes, &mut cursor);
        if string(&key)? == "rows" {
            if bytes.get(cursor) != Some(&b'[') {
                return Err(BAD);
            }
            cursor += 1;
            let mut count = 0_usize;
            loop {
                skip_space(bytes, &mut cursor);
                if bytes.get(cursor) == Some(&b']') {
                    cursor += 1;
                    break;
                }
                count = count.checked_add(1).ok_or(BAD)?;
                if count > max_rows {
                    return Err(BAD);
                }
                cursor = value_end(bytes, cursor)?;
                skip_space(bytes, &mut cursor);
                if bytes.get(cursor) == Some(&b']') {
                    cursor += 1;
                    break;
                }
                if bytes.get(cursor) != Some(&b',') {
                    return Err(BAD);
                }
                cursor += 1;
            }
        } else {
            cursor = value_end(bytes, cursor)?;
        }
        skip_space(bytes, &mut cursor);
        match bytes.get(cursor) {
            Some(b',') => cursor += 1,
            Some(b'}') => return Ok(()),
            _ => return Err(BAD),
        }
    }
}

fn skip_space(bytes: &[u8], cursor: &mut usize) {
    while matches!(bytes.get(*cursor), Some(b' ' | b'\n' | b'\t')) {
        *cursor += 1;
    }
}

fn value_end(bytes: &[u8], start: usize) -> Result<usize> {
    let mut depth = 0_usize;
    let mut quoted = false;
    let mut escaped = false;
    for (offset, byte) in bytes.get(start..).ok_or(BAD)?.iter().copied().enumerate() {
        let index = start + offset;
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
                if depth == 0 {
                    return Ok(index + 1);
                }
            }
        } else {
            match byte {
                b'"' => quoted = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > json::MAX_DEPTH {
                        return Err(BAD);
                    }
                }
                b'}' | b']' => {
                    if depth == 0 {
                        return if index > start { Ok(index) } else { Err(BAD) };
                    }
                    depth -= 1;
                    if depth == 0 {
                        return Ok(index + 1);
                    }
                }
                b',' | b' ' | b'\n' | b'\t' if depth == 0 => {
                    return if index > start { Ok(index) } else { Err(BAD) };
                }
                _ => {}
            }
        }
    }
    if !quoted && depth == 0 && start < bytes.len() {
        Ok(bytes.len())
    } else {
        Err(BAD)
    }
}
