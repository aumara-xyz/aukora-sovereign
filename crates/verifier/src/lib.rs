//! Independent cold verification of C1–C5 exports.

mod json;
mod merkle;
mod nostr_binding;
mod path0;
mod witness;

pub use witness::{verify_witness, WitnessReport};

use ed25519_dalek::{Signature, VerifyingKey};
use json::{canonical, Value};
use merkle::Hash;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const DOMAIN: &str = "aukora:aura-record:v1";
const LEAF_CONVENTION: &str = "rfc6962-leaf-sha256-0x00-prefixed-v1";
const KINDS: &[&str] = &[
    "boot.facts",
    "gate.propose",
    "gate.review",
    "gate.consume",
    "gate.apply",
    "gate.retire",
    "gate.refuse",
    "gate.expire",
    "gate.recover",
    "floor.advance",
    "aumlok.enrol",
    "aumlok.bind",
    "aumlok.signin",
    "broker.grant",
    "broker.reserve",
    "broker.settle",
    "broker.revoke",
    "kira.save",
    "kira.demote",
    "kira.permission",
    "sandbox.start",
    "sandbox.exit",
    "nostr.bind",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Verified,
    Rewritten(usize),
    Forged(usize),
    KeyMismatch,
    InvalidInput,
    Unchecked,
}

impl Verdict {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Verified => 0,
            Self::Rewritten(_) | Self::Forged(_) | Self::KeyMismatch => 2,
            Self::InvalidInput => 64,
            Self::Unchecked => 1,
        }
    }
}

#[derive(Debug)]
pub struct Report {
    pub findings: Vec<String>,
    pub verdict: Verdict,
    pub rows: usize,
    pub consistency_from: Option<usize>,
    pub first_bad_exact: bool,
}

impl Report {
    pub fn final_line(&self) -> String {
        match self.verdict {
            Verdict::Verified => format!(
                "VERIFIED rows 1..{}, signatures, consistency from {}, owner bindings, completeness through retained checkpoint {}",
                self.rows, self.consistency_from.unwrap_or(0), self.rows
            ),
            Verdict::Rewritten(seq) if self.first_bad_exact => format!("REWRITTEN first bad seq {seq}"),
            Verdict::Rewritten(seq) => format!("REWRITTEN first bad seq unknown; changed entry at or before {seq} (retain rows to locate it)"),
            Verdict::Forged(seq) => format!("FORGED bad signature at seq {seq}"),
            Verdict::KeyMismatch => "FORGED key mismatch".into(),
            Verdict::InvalidInput => "UNCHECKED invalid input; see findings".into(),
            Verdict::Unchecked => format!("UNCHECKED rows 1..{}; see findings for unchecked scope", self.rows),
        }
    }
}

pub struct Inputs<'a> {
    pub key_hex: &'a [u8],
    pub rows: &'a [u8],
    pub retained: Option<&'a [u8]>,
    pub presented: Option<&'a [u8]>,
    pub prefix: Option<&'a [u8]>,
    pub checkpoint: Option<&'a [u8]>,
}

pub struct BundleInputs<'a> {
    pub bundle: &'a [u8],
    pub pinned_key: Option<&'a [u8]>,
    pub checkpoint: Option<&'a [u8]>,
}

/// Checks a self-contained export without treating its included head as a witness.
pub fn verify_bundle(inputs: BundleInputs<'_>) -> Report {
    let mut report = Report {
        findings: Vec::new(),
        verdict: Verdict::Verified,
        rows: 0,
        consistency_from: None,
        first_bad_exact: true,
    };
    let parsed = (|| -> Result<_, String> {
        let value = json::parse_canonical(inputs.bundle)?;
        let map = object(&value)?;
        if !exact_keys(map, &["schema", "publicKey", "head", "rows"])
            || string(field(map, "schema")?)? != "aukora-aura-cold-proof-v1"
        {
            return Err("verifier:bundle-format".into());
        }
        let embedded = digest(field(map, "publicKey")?)?;
        let key_hex = hex::encode(embedded).into_bytes();
        let embedded_key = key(&key_hex)?;
        if let Some(pin) = inputs.pinned_key {
            if key(pin)? != embedded_key {
                return Err("verifier:bundle-key-mismatch".into());
            }
        }
        let head_bytes = canonical(field(map, "head")?);
        let retained = head(&head_bytes)?;
        let Value::Array(values) = field(map, "rows")? else {
            return Err("verifier:bundle-rows".into());
        };
        if let Some(checkpoint) = inputs.checkpoint {
            head(checkpoint)?;
        }
        Ok((key_hex, head_bytes, retained, values.clone()))
    })();
    let (key_hex, head_bytes, retained, values) = match parsed {
        Ok(parsed) => parsed,
        Err(code) => {
            if code == "verifier:bundle-key-mismatch" {
                report.findings.push(format!("FORGED {code}"));
                report.verdict = Verdict::KeyMismatch;
            } else {
                invalid_input(&mut report, &code);
            }
            return report;
        }
    };
    let row_count = values.len();
    let mut rows = Vec::new();
    for (index, value) in values.iter().enumerate() {
        let bytes = canonical(value);
        let admitted = read_row(&bytes, index + 1).and_then(|row| {
            if row.semantic_ok {
                Ok(())
            } else {
                Err("verifier:bundle-row-schema".into())
            }
        });
        if let Err(code) = admitted {
            report = verify(Inputs {
                key_hex: &key_hex,
                rows: &rows,
                retained: None,
                presented: None,
                prefix: None,
                checkpoint: None,
            });
            failure(&mut report, index + 1, &code, false);
            return report;
        }
        rows.extend(bytes);
        rows.push(b'\n');
    }
    let presented = Value::Object(
        [
            (
                "schema",
                Value::String("aukora-aura-presented-head-v1".into()),
            ),
            ("leafConvention", Value::String(LEAF_CONVENTION.into())),
            ("treeSize", Value::Int(retained.size as i64)),
            ("root", Value::String(hex::encode(retained.root))),
            ("retainedTreeSize", Value::Int(retained.size as i64)),
            ("proofFromPrevious", Value::Array(Vec::new())),
        ]
        .into_iter()
        .map(|(name, value)| (name.into(), value))
        .collect(),
    );
    let presented_bytes = canonical(&presented);
    report = verify(Inputs {
        key_hex: &key_hex,
        rows: &rows,
        retained: Some(&head_bytes),
        presented: Some(&presented_bytes),
        prefix: None,
        checkpoint: inputs.checkpoint,
    });
    if row_count != retained.size {
        failure(
            &mut report,
            row_count.min(retained.size) + 1,
            "verifier:bundle-tail-size",
            false,
        );
    }
    report.findings.push("BUNDLE checked signatures, chain, root and exact exported tail; embedded head is not an independent witness".into());
    if inputs.pinned_key.is_none() {
        unchecked(
            &mut report,
            "verifier:identity-no-pinned-key (embedded public key is not independent identity)",
        );
        for finding in &mut report.findings {
            *finding = finding.replace("pinned-key signatures", "bundle-key signatures");
        }
    }
    let independent_cover = inputs
        .checkpoint
        .and_then(|bytes| head(bytes).ok())
        .is_some_and(|checkpoint| checkpoint.size == row_count);
    if !independent_cover {
        unchecked(&mut report, "verifier:completeness-no-covering-checkpoint (a valid earlier prefix cannot prove a later tail is complete)");
    }
    report
}

fn sha256(bytes: &[u8]) -> Hash {
    Sha256::digest(bytes).into()
}

fn digest(value: &Value) -> Result<Hash, String> {
    let text = string(value)?;
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("verifier:bad-digest".into());
    }
    hex::decode(text)
        .map_err(|_| "verifier:bad-digest".to_owned())?
        .try_into()
        .map_err(|_| "verifier:bad-digest".into())
}

fn string(value: &Value) -> Result<&str, String> {
    match value {
        Value::String(s) => Ok(s),
        _ => Err("verifier:expected-string".into()),
    }
}

fn integer(value: &Value) -> Result<i64, String> {
    match value {
        Value::Int(n) => Ok(*n),
        _ => Err("verifier:expected-integer".into()),
    }
}

fn object(value: &Value) -> Result<&BTreeMap<String, Value>, String> {
    match value {
        Value::Object(o) => Ok(o),
        _ => Err("verifier:expected-object".into()),
    }
}

fn field<'a>(map: &'a BTreeMap<String, Value>, name: &str) -> Result<&'a Value, String> {
    map.get(name)
        .ok_or_else(|| format!("verifier:missing-field-{name}"))
}

fn exact_keys(map: &BTreeMap<String, Value>, keys: &[&str]) -> bool {
    map.len() == keys.len() && keys.iter().all(|key| map.contains_key(*key))
}

// Signatures use the standard padded alphabet and canonical padding bits.
fn signature(text: &str) -> Option<Signature> {
    if text.len() != 88 || !text.ends_with("==") {
        return None;
    }
    let mut bytes = Vec::with_capacity(64);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for b in text.bytes().take(86) {
        let n = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(n);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if acc != 0 || bytes.len() != 64 {
        return None;
    }
    Some(Signature::from_bytes(&bytes.try_into().ok()?))
}

struct Row {
    value: Value,
    hash: Hash,
    seq: usize,
    semantic_ok: bool,
}

fn read_row(bytes: &[u8], position: usize) -> Result<Row, String> {
    let value = json::parse_canonical(bytes)?;
    let map = object(&value)?;
    if !exact_keys(
        map,
        &[
            "seq", "prev", "hash", "sig", "at", "kind", "actor", "op", "phase", "body",
        ],
    ) {
        return Err("verifier:row-columns".into());
    }
    let seq = usize::try_from(integer(field(map, "seq")?)?).map_err(|_| "verifier:sequence")?;
    if seq != position {
        return Err("verifier:sequence".into());
    }
    let hash = digest(field(map, "hash")?)?;
    let semantic_ok = integer(field(map, "at")?).is_ok()
        && ["prev", "sig", "actor", "op"]
            .iter()
            .all(|name| string(field(map, name).expect("validated columns")).is_ok())
        && string(field(map, "kind")?).is_ok_and(|kind| KINDS.contains(&kind))
        && string(field(map, "phase")?)
            .is_ok_and(|phase| ["intent", "settle", "terminal", "fact"].contains(&phase))
        && matches!(field(map, "body")?, Value::Object(_));
    Ok(Row {
        value,
        hash,
        seq,
        semantic_ok,
    })
}

fn entry_hash(row: &Row) -> Hash {
    let Value::Object(map) = &row.value else {
        unreachable!()
    };
    let mut fields = map.clone();
    fields.remove("hash");
    fields.remove("sig");
    let sequence = fields.remove("seq").expect("validated row");
    fields.insert("sequence".into(), sequence);
    fields.insert("domain".into(), Value::String(DOMAIN.into()));
    sha256(&canonical(&Value::Object(fields)))
}

fn parse_rows(bytes: &[u8]) -> Result<Vec<Row>, (usize, String)> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if !bytes.ends_with(b"\n") {
        return Err((
            bytes.split(|b| *b == b'\n').count(),
            "verifier:rows-truncated".into(),
        ));
    }
    let lines = bytes.split(|b| *b == b'\n').collect::<Vec<_>>();
    let mut rows = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if index + 1 == lines.len() && line.is_empty() {
            break;
        }
        rows.push(read_row(line, index + 1).map_err(|e| (index + 1, e))?);
    }
    Ok(rows)
}

fn key(bytes: &[u8]) -> Result<VerifyingKey, String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "verifier:key-encoding")?
        .trim();
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("verifier:key-encoding".into());
    }
    let bytes: [u8; 32] = hex::decode(text)
        .map_err(|_| "verifier:key-encoding")?
        .try_into()
        .map_err(|_| "verifier:key-encoding")?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| "verifier:key-invalid")?;
    if key.is_weak() {
        return Err("verifier:key-weak".into());
    }
    Ok(key)
}

struct Head {
    size: usize,
    hash: Hash,
    root: Hash,
}
struct Presented {
    size: usize,
    retained: usize,
    root: Hash,
    proof: Vec<Hash>,
}

fn size(value: &Value) -> Result<usize, String> {
    let n = usize::try_from(integer(value)?).map_err(|_| "verifier:head-size")?;
    if n == 0 {
        return Err("verifier:head-size".into());
    }
    Ok(n)
}

fn head(bytes: &[u8]) -> Result<Head, String> {
    let value = json::parse(bytes)?;
    let map = object(&value)?;
    if !exact_keys(
        map,
        &[
            "schema",
            "leafConvention",
            "sequence",
            "hash",
            "treeSize",
            "root",
        ],
    ) || string(field(map, "schema")?)? != "aukora-aura-retained-head-v1"
        || string(field(map, "leafConvention")?)? != LEAF_CONVENTION
    {
        return Err("verifier:retained-format".into());
    }
    let n = size(field(map, "treeSize")?)?;
    if size(field(map, "sequence")?)? != n {
        return Err("verifier:head-sequence".into());
    }
    Ok(Head {
        size: n,
        hash: digest(field(map, "hash")?)?,
        root: digest(field(map, "root")?)?,
    })
}

fn presented(bytes: &[u8]) -> Result<Presented, String> {
    let value = json::parse(bytes)?;
    let map = object(&value)?;
    let required = [
        "schema",
        "leafConvention",
        "treeSize",
        "root",
        "retainedTreeSize",
        "proofFromPrevious",
    ];
    if !exact_keys(map, &required)
        || string(field(map, "schema")?)? != "aukora-aura-presented-head-v1"
        || string(field(map, "leafConvention")?)? != LEAF_CONVENTION
    {
        return Err("verifier:presented-format".into());
    }
    let Value::Array(proof) = field(map, "proofFromPrevious")? else {
        return Err("verifier:proof-format".into());
    };
    if proof.len() > 64 {
        return Err("verifier:proof-length".into());
    }
    Ok(Presented {
        size: size(field(map, "treeSize")?)?,
        retained: size(field(map, "retainedTreeSize")?)?,
        root: digest(field(map, "root")?)?,
        proof: proof.iter().map(digest).collect::<Result<_, _>>()?,
    })
}

fn auth_shape(auth: &Value) -> bool {
    let Ok(map) = object(auth) else {
        return false;
    };
    let required = [
        "v",
        "node",
        "subject",
        "op",
        "proposal",
        "target",
        "new_sha256",
        "cell",
        "display_sha256",
        "challenge",
        "expires_at",
    ];
    if !required.iter().all(|k| map.contains_key(*k))
        || map
            .keys()
            .any(|k| !required.contains(&k.as_str()) && k != "base_sha256")
    {
        return false;
    }
    let text = |name: &str| map.get(name).and_then(|v| string(v).ok());
    let hex_len = |name: &str, len: usize| {
        text(name).is_some_and(|s| {
            s.len() == len
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    };
    map.get("v") == Some(&Value::Int(1))
        && hex_len("node", 32)
        && hex_len("proposal", 32)
        && hex_len("challenge", 32)
        && text("subject").is_some_and(|s| {
            s.strip_prefix("aukora:1:").is_some_and(|h| {
                h.len() == 64
                    && h.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        })
        && text("op")
            .is_some_and(|s| ["apply", "retire", "release", "grant", "permission"].contains(&s))
        && text("target").is_some()
        && hex_len("new_sha256", 64)
        && hex_len("display_sha256", 64)
        && (!map.contains_key("base_sha256") || hex_len("base_sha256", 64))
        && matches!(map.get("cell"), Some(Value::Null | Value::Object(_)))
        && map.get("expires_at").is_some_and(|v| integer(v).is_ok())
}

fn owner_binding(row: &Row) -> Result<bool, String> {
    let map = object(&row.value)?;
    let kind = string(field(map, "kind")?)?;
    if kind != "gate.consume" && kind != "gate.apply" {
        return Ok(true);
    }
    let Ok(body) = object(field(map, "body")?) else {
        return Ok(false);
    };
    let Some(auth) = body.get("auth") else {
        return Ok(false);
    };
    if !auth_shape(auth) {
        return Ok(false);
    }
    let Some(recorded) = body.get("authorization_digest") else {
        return Ok(false);
    };
    let expected = digest(recorded)?;
    let mut bytes = b"aukora:owner-authorization:v1\0".to_vec();
    bytes.extend(canonical(auth));
    if sha256(&bytes) != expected {
        return Err("verifier:authorization-digest".into());
    }
    Ok(true)
}

fn failure(report: &mut Report, seq: usize, code: &str, forged: bool) {
    report.findings.push(format!(
        "{} seq={seq} {code}",
        if forged { "FORGED" } else { "REWRITTEN" }
    ));
    let old_seq = match report.verdict {
        Verdict::Rewritten(n) | Verdict::Forged(n) => n,
        _ => usize::MAX,
    };
    if seq < old_seq || (seq == old_seq && !report.first_bad_exact) {
        report.first_bad_exact = true;
        report.verdict = if forged {
            Verdict::Forged(seq)
        } else {
            Verdict::Rewritten(seq)
        };
    }
}

fn bounded_failure(report: &mut Report, bound: usize, code: &str) {
    report
        .findings
        .push(format!("REWRITTEN seq={bound} {code}"));
    if matches!(report.verdict, Verdict::Verified | Verdict::Unchecked)
        || matches!(report.verdict, Verdict::Rewritten(n) | Verdict::Forged(n) if bound < n)
    {
        report.verdict = Verdict::Rewritten(bound);
        report.first_bad_exact = false;
    }
}

fn invalid_input(report: &mut Report, code: &str) {
    report.findings.push(format!("UNCHECKED {code}"));
    report.verdict = Verdict::InvalidInput;
}

fn unchecked(report: &mut Report, code: &str) {
    report.findings.push(format!("UNCHECKED {code}"));
    if report.verdict == Verdict::Verified {
        report.verdict = Verdict::Unchecked;
    }
}

fn anchored(head: &Head, rows: &[Row], leaves: &[Hash], report: &mut Report, label: &str) -> bool {
    if rows.len() < head.size {
        failure(
            report,
            rows.len() + 1,
            "verifier:shorter-than-checkpoint",
            false,
        );
        return false;
    }
    if rows[head.size - 1].hash != head.hash || merkle::root(&leaves[..head.size]) != head.root {
        bounded_failure(report, head.size, "verifier:checkpoint-mismatch (first changed entry at or before this seq; prefix required to locate it)");
        return false;
    }
    report
        .findings
        .push(format!("CHECKPOINT VERIFIED {label} rows=1..{}", head.size));
    true
}

pub fn verify(inputs: Inputs<'_>) -> Report {
    let mut report = Report {
        findings: Vec::new(),
        verdict: Verdict::Verified,
        rows: 0,
        consistency_from: None,
        first_bad_exact: true,
    };
    let key = match key(inputs.key_hex) {
        Ok(key) => key,
        Err(e) => {
            invalid_input(&mut report, &e);
            return report;
        }
    };
    let rows = match parse_rows(inputs.rows) {
        Ok(rows) => rows,
        Err((seq, e)) => {
            let prefix_len: usize = inputs
                .rows
                .split_inclusive(|b| *b == b'\n')
                .take(seq - 1)
                .map(<[u8]>::len)
                .sum();
            let mut partial = verify(Inputs {
                key_hex: inputs.key_hex,
                rows: &inputs.rows[..prefix_len],
                retained: None,
                presented: None,
                prefix: None,
                checkpoint: None,
            });
            failure(&mut partial, seq, &e, false);
            return partial;
        }
    };
    report.rows = rows.len();
    if rows.is_empty() {
        unchecked(&mut report, "verifier:no-rows");
    }
    let mut previous = DOMAIN.to_owned();
    let mut terminal = BTreeMap::new();
    let mut nostr_bindings = 0;
    for row in &rows {
        let map = object(&row.value).expect("validated row");
        let mut intact = true;
        if string(field(map, "prev").expect("validated row")).ok() != Some(previous.as_str()) {
            failure(&mut report, row.seq, "verifier:prev-link", false);
            intact = false;
        }
        if entry_hash(row) != row.hash {
            failure(&mut report, row.seq, "verifier:entry-hash", false);
            intact = false;
        }
        let sig_ok = string(field(map, "sig").expect("validated row"))
            .ok()
            .and_then(signature)
            .is_some_and(|sig| key.verify_strict(&row.hash, &sig).is_ok());
        if !sig_ok {
            failure(&mut report, row.seq, "verifier:signature", true);
            intact = false;
        }
        if !row.semantic_ok {
            unchecked(&mut report, &format!("verifier:row-schema seq={}", row.seq));
        }
        let kind = string(field(map, "kind").expect("validated row")).unwrap_or("");
        if kind == "nostr.bind" {
            nostr_bindings += 1;
            if nostr_bindings > 1 {
                failure(&mut report, row.seq, "verifier:nostr-second-binding", false);
            }
            match nostr_binding::check(map, &key.to_bytes()) {
                Ok(()) if intact && row.semantic_ok => report
                    .findings
                    .push(format!("NOSTR_BINDING VERIFIED seq={}", row.seq)),
                Ok(()) => {}
                Err(code) => failure(&mut report, row.seq, &code, code.ends_with("signature")),
            }
        }
        if ["gate.consume", "gate.apply"].contains(&kind) {
            match if path0::has_evidence(row) {
                path0::owner_binding(&rows, row)
            } else {
                unchecked(
                    &mut report,
                    &format!("verifier:owner-provenance seq={}", row.seq),
                );
                owner_binding(row)
            } {
                Ok(true) if intact && row.semantic_ok => report.findings.push(format!(
                    "OWNER_BINDING VERIFIED seq={} signed chain content; passkey signature and effect independently UNCHECKED",
                    row.seq
                )),
                Ok(_) => unchecked(
                    &mut report,
                    &format!("verifier:owner-binding seq={}", row.seq),
                ),
                Err(e) => failure(&mut report, row.seq, &e, false),
            }
        }
        let op = string(field(map, "op").expect("validated row")).unwrap_or("");
        if row.semantic_ok && !op.is_empty() {
            let count = terminal.entry(op.to_owned()).or_insert(0);
            if field(map, "phase").expect("validated row") == &Value::String("terminal".into()) {
                *count += 1;
            }
        }
        previous = hex::encode(row.hash);
    }
    for (op, count) in terminal {
        if count != 1 {
            unchecked(
                &mut report,
                &format!("verifier:terminal-count op={op:?} count={count}"),
            );
        }
    }
    report.findings.push(format!(
        "ROWS checked count={} chain and pinned-key signatures",
        rows.len()
    ));
    let leaves = rows
        .iter()
        .map(|row| merkle::leaf(&row.hash))
        .collect::<Vec<_>>();
    let mut covered = false;
    if let Some(bytes) = inputs.prefix {
        let prefix_report = verify(Inputs {
            key_hex: inputs.key_hex,
            rows: bytes,
            retained: None,
            presented: None,
            prefix: None,
            checkpoint: None,
        });
        match prefix_report.verdict {
            Verdict::Rewritten(_) | Verdict::Forged(_) => {
                unchecked(&mut report, "verifier:invalid-retained-prefix")
            }
            _ => match parse_rows(bytes) {
                Ok(prefix) if !prefix.is_empty() && prefix.iter().all(|row| row.semantic_ok) => {
                    for (index, row) in prefix.iter().enumerate() {
                        if rows
                            .get(index)
                            .is_none_or(|present| present.value != row.value)
                        {
                            failure(
                                &mut report,
                                index + 1,
                                "verifier:retained-prefix-differs",
                                false,
                            );
                            break;
                        }
                    }
                    covered |= prefix.len() == rows.len()
                        && prefix.iter().zip(&rows).all(|(a, b)| a.value == b.value);
                    report
                        .findings
                        .push(format!("PREFIX checked rows=1..{}", prefix.len()));
                }
                _ => unchecked(&mut report, "verifier:invalid-retained-prefix"),
            },
        }
    }
    let retained = inputs.retained.map(head);
    let retained = match retained {
        Some(Ok(head)) => {
            if anchored(&head, &rows, &leaves, &mut report, "retained") {
                covered |= head.size == rows.len();
            }
            Some(head)
        }
        Some(Err(e)) => {
            unchecked(&mut report, &e);
            None
        }
        None => {
            unchecked(&mut report, "verifier:missing-retained-head");
            None
        }
    };
    if let Some(bytes) = inputs.checkpoint {
        match head(bytes) {
            Ok(head) => {
                if anchored(&head, &rows, &leaves, &mut report, "covering") {
                    covered |= head.size == rows.len();
                }
            }
            Err(e) => unchecked(&mut report, &e),
        }
    }
    match inputs.presented.map(presented) {
        Some(Ok(pres)) => {
            if pres.size != rows.len() {
                failure(
                    &mut report,
                    pres.size.min(rows.len()) + 1,
                    "verifier:presented-size",
                    false,
                );
            } else if pres.root != merkle::root(&leaves) {
                bounded_failure(
                    &mut report,
                    pres.size,
                    "verifier:presented-root (root alone cannot locate first changed row)",
                );
            }
            if let Some(retained) = retained {
                if pres.retained != retained.size {
                    unchecked(&mut report, "verifier:retained-proof-size");
                } else if !merkle::verify_consistency(
                    retained.size,
                    pres.size,
                    retained.root,
                    pres.root,
                    &pres.proof,
                ) {
                    unchecked(&mut report, "verifier:consistency-proof");
                } else {
                    report.consistency_from = Some(retained.size);
                    report.findings.push(format!(
                        "CONSISTENCY VERIFIED from {} to {}",
                        retained.size, pres.size
                    ));
                }
            }
        }
        Some(Err(e)) => unchecked(&mut report, &e),
        None => unchecked(&mut report, "verifier:missing-presented-head"),
    }
    if !covered {
        unchecked(&mut report, "verifier:completeness-no-covering-checkpoint (a valid earlier prefix cannot prove a later tail is complete)");
    }
    report
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn text(value: impl Into<String>) -> Value {
        Value::String(value.into())
    }

    fn valid_auth() -> BTreeMap<String, Value> {
        [
            ("v", Value::Int(1)),
            ("node", text("12".repeat(16))),
            ("subject", text(format!("aukora:1:{}", "34".repeat(32)))),
            ("op", text("apply")),
            ("proposal", text("56".repeat(16))),
            ("target", text("notes/review.txt")),
            ("new_sha256", text("78".repeat(32))),
            ("cell", Value::Null),
            ("display_sha256", text("90".repeat(32))),
            ("challenge", text("ab".repeat(16))),
            ("expires_at", Value::Int(1_760_000_000_000)),
        ]
        .into_iter()
        .map(|(name, value)| (name.into(), value))
        .collect()
    }

    #[test]
    fn digests_require_lowercase_hex_32_bytes() {
        assert_eq!(digest(&text("ab".repeat(32))).unwrap(), [0xab; 32]);
        for bad in [
            text("AB".repeat(32)),
            text("ag".repeat(32)),
            text("a".repeat(63)),
            text("a".repeat(65)),
            text(" a".repeat(32)),
            Value::Int(1),
            Value::Null,
        ] {
            assert!(digest(&bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn pinned_key_requires_hex_encoding_and_32_bytes() {
        let expected = SigningKey::from_bytes(&[7; 32]).verifying_key();
        let valid = hex::encode(expected.to_bytes());
        assert_eq!(key(valid.as_bytes()).unwrap(), expected);
        assert_eq!(key(valid.to_uppercase().as_bytes()).unwrap(), expected);
        assert_eq!(key(format!("{valid}\n").as_bytes()).unwrap(), expected);
        for bad in [
            vec![0xff],
            b"g".repeat(64),
            b"1".repeat(63),
            b"1".repeat(65),
            [valid.as_bytes(), b" trailing"].concat(),
        ] {
            assert!(key(&bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn pinned_key_refuses_small_order_points() {
        let mut identity = [0; 32];
        identity[0] = 1;
        assert!(VerifyingKey::from_bytes(&identity).unwrap().is_weak());
        assert!(key(hex::encode(identity).as_bytes()).is_err());
        assert!(key(hex::encode([0; 32]).as_bytes()).is_err());
    }

    #[test]
    fn signature_encoding_requires_standard_padding_and_zero_unused_bits() {
        let valid = format!("{}==", "A".repeat(86));
        assert!(signature(&valid).is_some());
        for bad in [
            "A".repeat(86),
            format!("{}=", "A".repeat(86)),
            format!("{}===", "A".repeat(86)),
            format!("{}B==", "A".repeat(85)),
            format!("-{}==", "A".repeat(85)),
            format!("_{}==", "A".repeat(85)),
            format!("{valid}\n"),
        ] {
            assert!(signature(&bad).is_none(), "accepted {bad:?}");
        }
    }

    #[test]
    fn owner_authorization_requires_all_c5_fields_and_closed_shape() {
        let original = valid_auth();
        assert!(auth_shape(&Value::Object(original.clone())));
        for name in original.keys() {
            let mut omitted = original.clone();
            omitted.remove(name);
            assert!(!auth_shape(&Value::Object(omitted)), "omitted {name}");
        }
        let mut extra = original.clone();
        extra.insert("unexpected".into(), Value::Null);
        assert!(!auth_shape(&Value::Object(extra)));
        assert!(!auth_shape(&Value::Null));
        assert!(!auth_shape(&Value::Array(vec![])));
        let mut optional = original;
        optional.insert("base_sha256".into(), text("cd".repeat(32)));
        optional.insert("cell".into(), Value::Object(BTreeMap::new()));
        assert!(auth_shape(&Value::Object(optional.clone())));
        optional.insert("base_sha256".into(), Value::Null);
        assert!(!auth_shape(&Value::Object(optional)));
    }

    #[test]
    fn owner_authorization_refuses_wrong_version_and_typed_fields() {
        for (name, replacement) in [
            ("v", Value::Int(2)),
            ("v", text("1")),
            ("node", text("1".repeat(31))),
            ("node", text("GG".repeat(16))),
            ("subject", text(format!("other:1:{}", "34".repeat(32)))),
            ("subject", text(format!("aukora:1:{}", "GG".repeat(32)))),
            ("op", text("unknown")),
            ("proposal", text("56".repeat(15))),
            ("target", Value::Null),
            ("new_sha256", text("78".repeat(31))),
            ("display_sha256", text("90".repeat(31))),
            ("challenge", text("ab".repeat(15))),
            ("cell", text("object")),
            ("expires_at", text("1760000000000")),
        ] {
            let mut auth = valid_auth();
            auth.insert(name.into(), replacement);
            assert!(!auth_shape(&Value::Object(auth)), "accepted invalid {name}");
        }
        for op in ["apply", "retire", "release", "grant", "permission"] {
            let mut auth = valid_auth();
            auth.insert("op".into(), text(op));
            assert!(auth_shape(&Value::Object(auth)), "refused {op}");
        }
    }

    #[test]
    fn verdict_bounds_prevent_later_errors_claiming_an_exact_first_seq() {
        let fresh = || Report {
            findings: Vec::new(),
            verdict: Verdict::Verified,
            rows: 9,
            consistency_from: Some(4),
            first_bad_exact: true,
        };
        for exact_first in [false, true] {
            for forged in [false, true] {
                let mut report = fresh();
                if exact_first {
                    failure(&mut report, 9, "verifier:test-exact", forged);
                    bounded_failure(&mut report, 4, "verifier:test-bound");
                } else {
                    bounded_failure(&mut report, 4, "verifier:test-bound");
                    failure(&mut report, 9, "verifier:test-exact", forged);
                }
                assert_eq!(report.verdict, Verdict::Rewritten(4));
                assert!(!report.first_bad_exact);
                assert!(report.final_line().contains("first bad seq unknown"));
                assert!(report.final_line().contains("at or before 4"));
            }
            for exact in [3, 4] {
                let mut report = fresh();
                if exact_first {
                    failure(&mut report, exact, "verifier:test-exact", false);
                    bounded_failure(&mut report, 4, "verifier:test-bound");
                } else {
                    bounded_failure(&mut report, 4, "verifier:test-bound");
                    failure(&mut report, exact, "verifier:test-exact", false);
                }
                assert_eq!(report.verdict, Verdict::Rewritten(exact));
                assert!(report.first_bad_exact);
                assert_eq!(
                    report.final_line(),
                    format!("REWRITTEN first bad seq {exact}")
                );
            }
        }
        let mut report = fresh();
        bounded_failure(&mut report, 8, "verifier:test-bound");
        bounded_failure(&mut report, 4, "verifier:test-earlier-bound");
        bounded_failure(&mut report, 6, "verifier:test-later-bound");
        unchecked(&mut report, "verifier:test-unchecked");
        assert_eq!(report.verdict, Verdict::Rewritten(4));
        assert!(!report.first_bad_exact);
        failure(&mut report, 3, "verifier:test-earlier-forgery", true);
        bounded_failure(&mut report, 4, "verifier:test-later-bound");
        assert_eq!(report.verdict, Verdict::Forged(3));
        assert!(report.first_bad_exact);
        assert_eq!(report.final_line(), "FORGED bad signature at seq 3");
    }

    #[test]
    fn head_documents_require_exact_c3_shape() {
        let retained: BTreeMap<String, Value> = [
            ("schema", text("aukora-aura-retained-head-v1")),
            ("leafConvention", text(LEAF_CONVENTION)),
            ("sequence", Value::Int(1)),
            ("hash", text("ab".repeat(32))),
            ("treeSize", Value::Int(1)),
            ("root", text("cd".repeat(32))),
        ]
        .into_iter()
        .map(|(name, value)| (name.into(), value))
        .collect();
        let shown: BTreeMap<String, Value> = [
            ("schema", text("aukora-aura-presented-head-v1")),
            ("leafConvention", text(LEAF_CONVENTION)),
            ("treeSize", Value::Int(2)),
            ("root", text("cd".repeat(32))),
            ("retainedTreeSize", Value::Int(1)),
            (
                "proofFromPrevious",
                Value::Array(vec![text("ef".repeat(32))]),
            ),
        ]
        .into_iter()
        .map(|(name, value)| (name.into(), value))
        .collect();
        let retained_bytes = |map| canonical(&Value::Object(map));
        let shown_bytes = |map| canonical(&Value::Object(map));
        assert!(head(&retained_bytes(retained.clone())).is_ok());
        assert!(presented(&shown_bytes(shown.clone())).is_ok());
        for name in retained.keys() {
            let mut missing = retained.clone();
            missing.remove(name);
            assert!(
                head(&retained_bytes(missing)).is_err(),
                "missing retained {name}"
            );
        }
        for name in shown.keys() {
            let mut missing = shown.clone();
            missing.remove(name);
            assert!(
                presented(&shown_bytes(missing)).is_err(),
                "missing presented {name}"
            );
        }
        for (name, replacement) in [
            ("extra", Value::Null),
            ("schema", text("aukora-aura-retained-head-v2")),
            ("leafConvention", text("sha256-unprefixed")),
            ("sequence", Value::Int(2)),
        ] {
            let mut malformed = retained.clone();
            malformed.insert(name.into(), replacement);
            assert!(head(&retained_bytes(malformed)).is_err(), "retained {name}");
        }
        let mut zero = retained.clone();
        zero.insert("sequence".into(), Value::Int(0));
        zero.insert("treeSize".into(), Value::Int(0));
        assert!(head(&retained_bytes(zero)).is_err());
        for (name, replacement) in [
            ("extra", Value::Null),
            ("schema", text("aukora-aura-presented-head-v2")),
            ("leafConvention", text("sha256-unprefixed")),
            ("treeSize", Value::Int(0)),
            ("retainedTreeSize", Value::Int(0)),
            ("proofFromPrevious", Value::Null),
            ("proofFromPrevious", Value::Object(BTreeMap::new())),
            (
                "proofFromPrevious",
                Value::Array(vec![text("ef".repeat(32)); 65]),
            ),
        ] {
            let mut malformed = shown.clone();
            malformed.insert(name.into(), replacement);
            assert!(
                presented(&shown_bytes(malformed)).is_err(),
                "presented {name}"
            );
        }
        let mut at_limit = shown;
        at_limit.insert(
            "proofFromPrevious".into(),
            Value::Array(vec![text("ef".repeat(32)); 64]),
        );
        assert!(presented(&shown_bytes(at_limit)).is_ok());
        assert!(size(&Value::Int(1)).is_ok());
        assert!(size(&Value::Int(0)).is_err());
        assert!(size(&Value::Int(-1)).is_err());
        assert!(size(&Value::Null).is_err());
    }
}
