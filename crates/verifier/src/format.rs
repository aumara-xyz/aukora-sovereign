// SPDX-License-Identifier: AGPL-3.0-or-later
//! Version selection for the frozen export formats.

use canon::{alg::AlgorithmId, Result};

/// The four-key pinned cold bundle schema.
pub const COLD_PROOF_V1: &str = "aukora-aura-cold-proof-v1";
/// A closed wrapper retaining v1 alongside complete C5 owner assertions.
pub const COLD_PROOF_V2: &str = "aukora-aura-cold-proof-v2";
/// The six-key C3 retained observation schema.
pub const RETAINED_HEAD_V1: &str = "aukora-aura-retained-head-v1";
/// The six-key C3 presentation schema.
pub const PRESENTED_HEAD_V1: &str = "aukora-aura-presented-head-v1";

/// No future version is silently interpreted as a v1 bundle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportVersion {
    /// Frozen C3 keys; algorithm and epoch are never added to these outer objects.
    ColdProofV1,
    /// Owner assertion evidence wraps the unchanged v1 ledger proof.
    ColdProofV2,
}

impl ExportVersion {
    /// Recognizes the two closed schemas and refuses every other string.
    pub fn from_schema(schema: &str) -> Result<Self> {
        match schema {
            COLD_PROOF_V1 => Ok(Self::ColdProofV1),
            COLD_PROOF_V2 => Ok(Self::ColdProofV2),
            _ => Err(crate::UNSUPPORTED_SCHEMA),
        }
    }

    /// Returns the exact format discriminator.
    pub const fn schema(self) -> &'static str {
        match self {
            Self::ColdProofV1 => COLD_PROOF_V1,
            Self::ColdProofV2 => COLD_PROOF_V2,
        }
    }

    /// V1 fixes Ed25519 by schema instead of adding an algorithm field to its rows.
    pub const fn signature_algorithm(self) -> AlgorithmId {
        match self {
            Self::ColdProofV1 | Self::ColdProofV2 => AlgorithmId::Ed25519,
        }
    }
}

use canon::json::{SafeInteger, Value, ValueView};
use canon::Refusal;
use sha2::{Digest, Sha256};

pub(crate) const fn refusal(reason: &'static str) -> Refusal {
    Refusal {
        organ: "verifier",
        reason,
    }
}

pub(crate) fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value> {
    value.get(name).ok_or(refusal("missing-field"))
}

pub(crate) fn text(value: &Value) -> Result<&str> {
    match value.view() {
        ValueView::Text(s) => Ok(s),
        _ => Err(refusal("text")),
    }
}

pub(crate) fn uint(value: &Value) -> Result<u64> {
    match value.view() {
        ValueView::Integer(n) => u64::try_from(n.get()).map_err(|_| refusal("integer")),
        _ => Err(refusal("integer")),
    }
}

pub(crate) fn array(value: &Value) -> Result<&[Value]> {
    match value.view() {
        ValueView::Array(a) => Ok(a),
        _ => Err(refusal("array")),
    }
}

pub(crate) fn keys(value: &Value, wanted: &[&str]) -> Result<()> {
    match value.view() {
        ValueView::Object(members)
            if members.len() == wanted.len()
                && wanted.iter().all(|name| value.get(name).is_some()) =>
        {
            Ok(())
        }
        _ => Err(refusal("keys")),
    }
}

pub(crate) fn hex32(s: &str) -> Result<[u8; 32]> {
    hex_bytes(s)
}

pub(crate) fn hex_bytes<const N: usize>(s: &str) -> Result<[u8; N]> {
    if s.len() != N * 2
        || !s
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(refusal("hex"));
    }
    let mut bytes = [0; N];
    hex::decode_to_slice(s, &mut bytes).map_err(|_| refusal("hex"))?;
    Ok(bytes)
}

pub(crate) fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub(crate) fn object(members: Vec<(&str, Value)>) -> Result<Value> {
    Value::checked_object(
        members
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect(),
    )
}

pub(crate) fn string(s: &str) -> Result<Value> {
    Value::checked_text(s.to_owned())
}

/// C1 parsing is local so the stranger does not depend on node codecs being installed.
pub(crate) fn parse(bytes: &[u8]) -> Result<Value> {
    if bytes.len() > 8_388_608 {
        return Err(refusal("input-too-large"));
    }
    let source = std::str::from_utf8(bytes).map_err(|_| refusal("utf8"))?;
    if source.starts_with('\u{feff}') {
        return Err(refusal("bom"));
    }
    let mut reader = Reader { bytes, offset: 0 };
    let value = reader.value(0)?;
    reader.whitespace();
    if reader.offset != bytes.len() {
        return Err(refusal("trailing"));
    }
    Ok(value)
}

pub(crate) fn canonical(bytes: &[u8]) -> Result<Value> {
    let value = parse(bytes)?;
    if value.canonical_bytes() != bytes {
        return Err(refusal("not-canonical"));
    }
    Ok(value)
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Reader<'_> {
    fn whitespace(&mut self) {
        while self
            .bytes
            .get(self.offset)
            .is_some_and(|b| matches!(b, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.offset += 1;
        }
    }

    fn take(&mut self, byte: u8) -> bool {
        if self.bytes.get(self.offset) == Some(&byte) {
            self.offset += 1;
            true
        } else {
            false
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value> {
        self.whitespace();
        match self.bytes.get(self.offset).copied() {
            Some(b'"') => Value::checked_text(self.quoted()?),
            Some(b'{') => {
                if depth >= 64 {
                    return Err(refusal("depth"));
                }
                self.offset += 1;
                self.whitespace();
                let mut members = Vec::new();
                let mut seen = std::collections::BTreeSet::new();
                if !self.take(b'}') {
                    loop {
                        self.whitespace();
                        let key = self.quoted()?;
                        if !seen.insert(key.clone()) {
                            return Err(refusal("duplicate-key"));
                        }
                        self.whitespace();
                        if !self.take(b':') {
                            return Err(refusal("json"));
                        }
                        members.push((key, self.value(depth + 1)?));
                        self.whitespace();
                        if self.take(b'}') {
                            break;
                        }
                        if !self.take(b',') {
                            return Err(refusal("json"));
                        }
                    }
                }
                Value::checked_object(members)
            }
            Some(b'[') => {
                if depth >= 64 {
                    return Err(refusal("depth"));
                }
                self.offset += 1;
                self.whitespace();
                let mut values = Vec::new();
                if !self.take(b']') {
                    loop {
                        values.push(self.value(depth + 1)?);
                        self.whitespace();
                        if self.take(b']') {
                            break;
                        }
                        if !self.take(b',') {
                            return Err(refusal("json"));
                        }
                    }
                }
                Value::checked_array(values)
            }
            Some(b't') => {
                self.literal(b"true")?;
                Ok(Value::boolean(true))
            }
            Some(b'f') => {
                self.literal(b"false")?;
                Ok(Value::boolean(false))
            }
            Some(b'n') => {
                self.literal(b"null")?;
                Ok(Value::null())
            }
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(refusal("json")),
        }
    }

    fn literal(&mut self, expected: &[u8]) -> Result<()> {
        if self.bytes.get(self.offset..self.offset + expected.len()) != Some(expected) {
            return Err(refusal("json"));
        }
        self.offset += expected.len();
        Ok(())
    }

    fn number(&mut self) -> Result<Value> {
        let start = self.offset;
        self.take(b'-');
        let digits = self.offset;
        while self.bytes.get(self.offset).is_some_and(u8::is_ascii_digit) {
            self.offset += 1;
        }
        let raw = &self.bytes[start..self.offset];
        if digits == self.offset
            || raw == b"-0"
            || (self.bytes.get(digits) == Some(&b'0') && self.offset - digits > 1)
            || self
                .bytes
                .get(self.offset)
                .is_some_and(|c| matches!(c, b'.' | b'e' | b'E'))
        {
            return Err(refusal("integer"));
        }
        let n = std::str::from_utf8(raw)
            .map_err(|_| refusal("integer"))?
            .parse::<i64>()
            .map_err(|_| refusal("integer"))?;
        Ok(Value::integer(SafeInteger::new(n)?))
    }

    fn hex_unit(&mut self) -> Result<u16> {
        let bytes = self
            .bytes
            .get(self.offset..self.offset + 4)
            .ok_or(refusal("json"))?;
        let mut unit = 0u16;
        for b in bytes {
            let digit = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => return Err(refusal("json")),
            };
            unit = unit * 16 + u16::from(digit);
        }
        self.offset += 4;
        Ok(unit)
    }

    fn quoted(&mut self) -> Result<String> {
        if !self.take(b'"') {
            return Err(refusal("json"));
        }
        let mut out = String::new();
        loop {
            let b = *self.bytes.get(self.offset).ok_or(refusal("json"))?;
            self.offset += 1;
            match b {
                b'"' => return Ok(out),
                b'\\' => {
                    let escape = *self.bytes.get(self.offset).ok_or(refusal("json"))?;
                    self.offset += 1;
                    out.push(match escape {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let first = self.hex_unit()?;
                            let scalar = if (0xd800..=0xdbff).contains(&first) {
                                if !self.take(b'\\') || !self.take(b'u') {
                                    return Err(refusal("surrogate"));
                                }
                                let second = self.hex_unit()?;
                                if !(0xdc00..=0xdfff).contains(&second) {
                                    return Err(refusal("surrogate"));
                                }
                                0x10000 + ((u32::from(first) - 0xd800) << 10) + u32::from(second)
                                    - 0xdc00
                            } else {
                                u32::from(first)
                            };
                            char::from_u32(scalar).ok_or(refusal("surrogate"))?
                        }
                        _ => return Err(refusal("json")),
                    });
                }
                0..=31 => return Err(refusal("json")),
                _ => {
                    self.offset -= 1;
                    let width = if b < 0x80 {
                        1
                    } else if b < 0xe0 {
                        2
                    } else if b < 0xf0 {
                        3
                    } else {
                        4
                    };
                    let scalar = self
                        .bytes
                        .get(self.offset..self.offset + width)
                        .ok_or(refusal("utf8"))?;
                    let ch = std::str::from_utf8(scalar)
                        .map_err(|_| refusal("utf8"))?
                        .chars()
                        .next()
                        .ok_or(refusal("json"))?;
                    out.push(ch);
                    self.offset += ch.len_utf8();
                }
            }
        }
    }
}

fn schnorr_signature(
    public: &[u8; 32],
    message: &[u8; 32],
    signature: &str,
    reason: &'static str,
) -> Result<()> {
    let signature_bytes = hex_bytes::<64>(signature).map_err(|_| refusal(reason))?;
    let key = k256::schnorr::VerifyingKey::from_slice(public).map_err(|_| refusal(reason))?;
    let signature =
        k256::schnorr::Signature::from_slice(&signature_bytes).map_err(|_| refusal(reason))?;
    key.verify_raw(message, &signature)
        .map_err(|_| refusal(reason))
}

fn npub(public: &[u8; 32]) -> Result<String> {
    canon::provenance::Npub::encode_key_bytes(*public)
        .map(|address| address.as_str().to_owned())
        .map_err(|_| refusal("nostr-npub"))
}

fn bound_identity(value: &Value) -> Result<[u8; 32]> {
    keys(value, &["pubkey", "npub"]).map_err(|_| refusal("nostr-binding-shape"))?;
    let public = hex32(text(field(value, "pubkey")?)?)?;
    if text(field(value, "npub")?)? != npub(&public)? {
        return Err(refusal("nostr-npub"));
    }
    Ok(public)
}

pub(crate) fn nostr_binding(row: &Value, aura_key: &[u8; 32]) -> Result<()> {
    let body = field(row, "body")?;
    keys(
        body,
        &[
            "schema",
            "node",
            "agent",
            "aura_key",
            "statement_sha256",
            "node_sig",
            "agent_sig",
        ],
    )
    .map_err(|_| refusal("nostr-binding-shape"))?;
    if text(field(row, "phase")?)? != "fact"
        || text(field(body, "schema")?)? != "aukora-nostr-bind-v1"
    {
        return Err(refusal("nostr-binding-shape"));
    }
    if hex32(text(field(body, "aura_key")?)?)? != *aura_key {
        return Err(refusal("nostr-aura-key"));
    }
    let node = bound_identity(field(body, "node")?)?;
    let agent = bound_identity(field(body, "agent")?)?;
    let statement = object(vec![
        ("domain", string("aukora:nostr-identity-binding:v1")?),
        ("aura_key", field(body, "aura_key")?.clone()),
        ("node", string(&hex::encode(node))?),
        ("agent", string(&hex::encode(agent))?),
    ])?;
    let commitment = digest(&statement.canonical_bytes());
    if commitment != hex32(text(field(body, "statement_sha256")?)?)? {
        return Err(refusal("nostr-statement"));
    }
    schnorr_signature(
        &node,
        &commitment,
        text(field(body, "node_sig")?)?,
        "nostr-node-signature",
    )?;
    schnorr_signature(
        &agent,
        &commitment,
        text(field(body, "agent_sig")?)?,
        "nostr-agent-signature",
    )
}

struct DetachedEvent {
    signer: [u8; 32],
    content: String,
}

fn detached_event(bytes: &[u8]) -> Result<DetachedEvent> {
    if bytes.len() > 65_536 {
        return Err(refusal("witness-malformed"));
    }
    let value = parse(bytes)?;
    keys(
        &value,
        &[
            "id",
            "pubkey",
            "created_at",
            "kind",
            "tags",
            "content",
            "sig",
        ],
    )?;
    let public = hex32(text(field(&value, "pubkey")?)?)?;
    let id = hex32(text(field(&value, "id")?)?)?;
    // The timestamp is retained in NIP-01 seconds without a millisecond conversion.
    uint(field(&value, "created_at")?)?;
    if uint(field(&value, "kind")?)? != 30078 {
        return Err(refusal("witness-malformed"));
    }
    let tags = array(field(&value, "tags")?)?;
    if tags.len() != 1 {
        return Err(refusal("witness-malformed"));
    }
    let identifier = array(&tags[0])?;
    if identifier.len() != 2
        || text(&identifier[0])? != "d"
        || text(&identifier[1])? != "aukora-aura-head"
    {
        return Err(refusal("witness-malformed"));
    }
    let content = text(field(&value, "content")?)?;
    let preimage = Value::checked_array(vec![
        Value::integer(SafeInteger::new(0)?),
        field(&value, "pubkey")?.clone(),
        field(&value, "created_at")?.clone(),
        field(&value, "kind")?.clone(),
        field(&value, "tags")?.clone(),
        field(&value, "content")?.clone(),
    ])?;
    if digest(&preimage.canonical_bytes()) != id {
        return Err(refusal("witness-malformed"));
    }
    schnorr_signature(
        &public,
        &id,
        text(field(&value, "sig")?)?,
        "witness-malformed",
    )?;
    Ok(DetachedEvent {
        signer: public,
        content: content.to_owned(),
    })
}

pub(crate) fn witness(inputs: crate::WitnessInputs<'_>) -> Result<crate::VerificationReport> {
    witness_with_owner_pin(inputs, None)
}

pub(crate) fn witness_with_owner_pin(
    inputs: crate::WitnessInputs<'_>,
    owner_key: Option<&[u8]>,
) -> Result<crate::VerificationReport> {
    let event = detached_event(inputs.event).map_err(|_| refusal("witness-malformed"))?;
    let content = canonical(event.content.as_bytes()).map_err(|_| refusal("witness-malformed"))?;
    if !matches!(content.view(), ValueView::Object(_)) {
        return Err(refusal("witness-malformed"));
    }
    let witnessed_size = (|| {
        let sequence = uint(field(&content, "sequence")?)?;
        let size = uint(field(&content, "treeSize")?)?;
        if size == 0 || sequence != size {
            return Err(refusal("witness-size"));
        }
        Ok(size)
    })()
    .map_err(|_| refusal("witness-size"))?;
    let head = crate::consistency::retained(event.content.as_bytes())
        .map_err(|_| refusal("witness-malformed"))?;
    let wrapper = canonical(inputs.export.bundle).map_err(|_| refusal("witness-proof"))?;
    let (bundle, _) = crate::owner::unpack(&wrapper).map_err(|_| refusal("witness-proof"))?;
    let rows = field(&bundle, "rows")
        .and_then(array)
        .map_err(|_| refusal("witness-proof"))?;
    let mut binding = None;
    for row in rows {
        if row.get("kind").and_then(|kind| text(kind).ok()) == Some("nostr.bind")
            && binding.replace(row).is_some()
        {
            return Err(refusal("witness-binding"));
        }
    }
    let binding = binding.ok_or(refusal("witness-binding"))?;
    let binding_sequence = field(binding, "seq")
        .and_then(uint)
        .map_err(|_| refusal("witness-binding"))?;
    if binding_sequence == 0 {
        return Err(refusal("witness-binding"));
    }
    let node = (|| {
        let body = field(binding, "body")?;
        let identity = field(body, "node")?;
        hex32(text(field(identity, "pubkey")?)?)
    })()
    .map_err(|_| refusal("witness-binding"))?;
    if node != event.signer {
        return Err(refusal("witness-signer"));
    }
    let aura_key = field(&bundle, "publicKey")
        .and_then(text)
        .and_then(hex32)
        .map_err(|_| refusal("witness-proof"))?;
    nostr_binding(binding, &aura_key).map_err(|_| refusal("witness-proof"))?;
    let report = crate::verify_bundle_with_owner_pin(inputs.export, owner_key)
        .map_err(|_| refusal("witness-proof"))?;
    let integrity = report.integrity();
    if !matches!(
        report.verdict(),
        crate::Verdict::Verified | crate::Verdict::Unchecked
    ) || integrity.signatures != crate::Scope::Checked
        || integrity.chain != crate::Scope::Checked
        || integrity.tree_root != crate::Scope::Checked
    {
        return Err(refusal("witness-proof"));
    }
    let prefix_length = usize::try_from(witnessed_size).map_err(|_| refusal("witness-size"))?;
    let prefix = rows.get(..prefix_length).ok_or(refusal("witness-size"))?;
    let hashes = prefix
        .iter()
        .map(|row| hex32(text(field(row, "hash")?)?))
        .collect::<Result<Vec<_>>>()
        .map_err(|_| refusal("witness-proof"))?;
    if crate::consistency::root(&hashes) != head.root || hashes.last() != Some(&head.hash) {
        return Err(refusal("witness-fork"));
    }
    Ok(report)
}
