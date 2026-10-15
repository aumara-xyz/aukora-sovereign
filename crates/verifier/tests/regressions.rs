use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

const DOMAIN: &str = "aukora:aura-record:v1";
const LEAF_CONVENTION: &str = "rfc6962-leaf-sha256-0x00-prefixed-v1";
#[path = "../../../tests/support/node.rs"]
mod test_node;
#[path = "../../../tests/support/prime.rs"]
mod test_prime;
static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);
#[path = "standing/mod.rs"]
mod standing;

// The writer is test-only and does not use the verifier, canon, or aura.
#[derive(Clone)]
enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

impl Value {
    fn canonical(&self) -> String {
        match self {
            Self::Null => "null".into(),
            Self::Bool(value) => value.to_string(),
            Self::Int(value) => value.to_string(),
            Self::Str(value) => quote(value),
            Self::Array(values) => format!(
                "[{}]",
                values
                    .iter()
                    .map(Self::canonical)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            Self::Object(values) => {
                let mut values = values.iter().collect::<Vec<_>>();
                values.sort_by(|left, right| left.0.encode_utf16().cmp(right.0.encode_utf16()));
                format!(
                    "{{{}}}",
                    values
                        .into_iter()
                        .map(|(key, value)| format!("{}:{}", quote(key), value.canonical()))
                        .collect::<Vec<_>>()
                        .join(",")
                )
            }
        }
    }

    fn get(&self, key: &str) -> Value {
        let Self::Object(values) = self else {
            panic!("fixture object required")
        };
        values
            .iter()
            .find(|(name, _)| name == key)
            .unwrap()
            .1
            .clone()
    }

    fn set(&mut self, key: &str, replacement: Value) {
        let Self::Object(values) = self else {
            panic!("test fixture must be an object")
        };
        match values.iter_mut().find(|(candidate, _)| candidate == key) {
            Some((_, value)) => *value = replacement,
            None => values.push((key.into(), replacement)),
        }
    }
}

fn string(value: impl Into<String>) -> Value {
    Value::Str(value.into())
}

fn object(values: &[(&str, Value)]) -> Value {
    Value::Object(
        values
            .iter()
            .map(|(key, value)| ((*key).into(), value.clone()))
            .collect(),
    )
}

fn quote(value: &str) -> String {
    let mut output = String::from("\"");
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{8}' => output.push_str("\\b"),
            '\u{c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            value if value < '\u{20}' => output.push_str(&format!("\\u{:04x}", value as u32)),
            value => output.push(value),
        }
    }
    output.push('"');
    output
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let bits = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        output.push(ALPHABET[((bits >> 18) & 63) as usize] as char);
        output.push(ALPHABET[((bits >> 12) & 63) as usize] as char);
        output.push(if chunk.len() > 1 {
            ALPHABET[((bits >> 6) & 63) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            ALPHABET[(bits & 63) as usize] as char
        } else {
            '='
        });
    }
    output
}

#[derive(Clone)]
struct Row {
    seq: i64,
    prev: String,
    hash: [u8; 32],
    signature: String,
    at: i64,
    kind: String,
    actor: String,
    op: String,
    phase: String,
    body: Value,
}

impl Row {
    fn fields(&self) -> Value {
        object(&[
            ("sequence", Value::Int(self.seq)),
            ("at", Value::Int(self.at)),
            ("kind", string(&self.kind)),
            ("actor", string(&self.actor)),
            ("op", string(&self.op)),
            ("phase", string(&self.phase)),
            ("body", self.body.clone()),
        ])
    }

    fn sign(&mut self, key: &SigningKey) {
        let mut preimage = self.fields();
        preimage.set("prev", string(&self.prev));
        preimage.set("domain", string(DOMAIN));
        self.hash = hash(preimage.canonical().as_bytes());
        self.signature = base64(&key.sign(&self.hash).to_bytes());
    }

    fn value(&self) -> Value {
        object(&[
            ("seq", Value::Int(self.seq)),
            ("prev", string(&self.prev)),
            ("hash", string(hex::encode(self.hash))),
            ("sig", string(&self.signature)),
            ("at", Value::Int(self.at)),
            ("kind", string(&self.kind)),
            ("actor", string(&self.actor)),
            ("op", string(&self.op)),
            ("phase", string(&self.phase)),
            ("body", self.body.clone()),
        ])
    }
}

struct Writer {
    key: SigningKey,
    rows: Vec<Row>,
}

impl Writer {
    fn new() -> Self {
        Self {
            key: SigningKey::from_bytes(&[7; 32]),
            rows: vec![],
        }
    }

    fn append(&mut self, kind: &str, phase: &str, op: &str, body: Value) {
        let mut row = Row {
            seq: self.rows.len() as i64 + 1,
            prev: self
                .rows
                .last()
                .map(|row| hex::encode(row.hash))
                .unwrap_or_else(|| DOMAIN.into()),
            hash: [0; 32],
            signature: String::new(),
            at: 1_760_000_000_000 + self.rows.len() as i64,
            kind: kind.into(),
            actor: "owner".into(),
            op: op.into(),
            phase: phase.into(),
            body,
        };
        row.sign(&self.key);
        self.rows.push(row);
    }

    fn facts(count: usize) -> Self {
        let mut writer = Self::new();
        for index in 0..count {
            writer.append(
                "boot.facts",
                "fact",
                "",
                object(&[("index", Value::Int(index as i64))]),
            );
        }
        writer
    }

    fn resign_from(&mut self, position: usize) {
        for index in position..self.rows.len() {
            self.rows[index].prev = if index == 0 {
                DOMAIN.into()
            } else {
                hex::encode(self.rows[index - 1].hash)
            };
            self.rows[index].sign(&self.key);
        }
    }

    fn text(&self) -> String {
        lines(&self.rows)
    }

    fn head(&self, size: usize) -> Value {
        object(&[
            ("schema", string("aukora-aura-retained-head-v1")),
            ("leafConvention", string(LEAF_CONVENTION)),
            ("sequence", Value::Int(size as i64)),
            ("hash", string(hex::encode(self.rows[size - 1].hash))),
            ("treeSize", Value::Int(size as i64)),
            ("root", string(hex::encode(tree(&self.leaves()[..size])))),
        ])
    }

    fn presented(&self, retained: usize) -> Value {
        let leaves = self.leaves();
        object(&[
            ("schema", string("aukora-aura-presented-head-v1")),
            ("leafConvention", string(LEAF_CONVENTION)),
            ("treeSize", Value::Int(leaves.len() as i64)),
            ("root", string(hex::encode(tree(&leaves)))),
            ("retainedTreeSize", Value::Int(retained as i64)),
            (
                "proofFromPrevious",
                Value::Array(
                    proof(retained, &leaves, true)
                        .into_iter()
                        .map(|digest| string(hex::encode(digest)))
                        .collect(),
                ),
            ),
        ])
    }

    fn leaves(&self) -> Vec<[u8; 32]> {
        self.rows
            .iter()
            .map(|row| hash(&[&[0], &row.hash[..]].concat()))
            .collect()
    }
}

fn lines(rows: &[Row]) -> String {
    rows.iter()
        .map(|row| format!("{}\n", row.value().canonical()))
        .collect()
}

fn split(size: usize) -> usize {
    let mut result = 1;
    while result * 2 < size {
        result *= 2;
    }
    result
}

fn tree(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.len() == 1 {
        return leaves[0];
    }
    let at = split(leaves.len());
    let left = tree(&leaves[..at]);
    let right = tree(&leaves[at..]);
    hash(&[&[1], &left[..], &right[..]].concat())
}

fn proof(retained: usize, leaves: &[[u8; 32]], complete: bool) -> Vec<[u8; 32]> {
    if retained == leaves.len() {
        return if complete { vec![] } else { vec![tree(leaves)] };
    }
    let at = split(leaves.len());
    if retained <= at {
        let mut nodes = proof(retained, &leaves[..at], complete);
        nodes.push(tree(&leaves[at..]));
        nodes
    } else {
        let mut nodes = proof(retained - at, &leaves[at..], false);
        nodes.push(tree(&leaves[..at]));
        nodes
    }
}

fn authorization(index: usize) -> Value {
    object(&[
        ("v", Value::Int(1)),
        ("node", string("12".repeat(16))),
        ("subject", string(format!("aukora:1:{}", "34".repeat(32)))),
        ("op", string("apply")),
        ("proposal", string(format!("{index:032x}"))),
        ("target", string(format!("notes/target-{index}.txt"))),
        (
            "base_sha256",
            string(hex::encode(hash(format!("base-{index}").as_bytes()))),
        ),
        (
            "new_sha256",
            string(hex::encode(hash(format!("payload-{index}").as_bytes()))),
        ),
        ("cell", Value::Null),
        (
            "display_sha256",
            string(hex::encode(hash(format!("card-{index}").as_bytes()))),
        ),
        ("challenge", string(format!("{index:032x}"))),
        ("expires_at", Value::Int(1_760_000_100_000 + index as i64)),
    ])
}

fn authorization_body(auth: Value) -> Value {
    let digest = hash(
        &[
            b"aukora:owner-authorization:v1\0".as_slice(),
            auth.canonical().as_bytes(),
        ]
        .concat(),
    );
    object(&[
        ("auth", auth),
        ("authorization_digest", string(hex::encode(digest))),
    ])
}

fn path0_writer(mutation: Option<&str>) -> Writer {
    let mut writer = Writer::new();
    let op = format!("{:032x}", 1);
    let effect_input = object(&[
        ("key", string("owner:note")),
        ("value", string("approved bytes")),
    ])
    .canonical();
    let effect = format!("{effect_input}\n");
    let mut cell = object(&[
        (
            "module_sha256",
            string("34ce6cab618b626243e876befb49ccf8a6780dc836e757484886b34ae977a438"),
        ),
        (
            "input_sha256",
            string(hex::encode(hash(effect_input.as_bytes()))),
        ),
        (
            "effect_sha256",
            string(hex::encode(hash(effect.as_bytes()))),
        ),
    ]);
    match mutation {
        Some("cell-module") => cell.set("module_sha256", string("ab".repeat(32))),
        Some("cell-input") => cell.set("input_sha256", string("ab".repeat(32))),
        Some("cell-effect") => cell.set("effect_sha256", string("ab".repeat(32))),
        _ => (),
    }
    let from_to = object(&[("base", Value::Null), ("new", string(&effect))]);
    let mut card = object(&[
        ("v", Value::Int(1)),
        ("risk", string("routine")),
        ("says", string("Apply exact bytes")),
        ("facts", Value::Array(vec![])),
        ("from_to", from_to),
        ("model_note", string("untrusted note")),
    ]);
    let mut auth = object(&[
        ("v", Value::Int(1)),
        ("node", string("12".repeat(16))),
        ("subject", string(format!("aukora:1:{}", "34".repeat(32)))),
        ("op", string("apply")),
        ("proposal", string(&op)),
        ("target", string("owner/note")),
        ("base_sha256", string("absent")),
        ("new_sha256", string(hex::encode(hash(effect.as_bytes())))),
        (
            "cell",
            if mutation == Some("new-bytes") {
                Value::Null
            } else {
                cell
            },
        ),
        (
            "display_sha256",
            string(hex::encode(hash(card.canonical().as_bytes()))),
        ),
        ("challenge", string("ab".repeat(32))),
        ("expires_at", Value::Int(1_760_000_100_000)),
        ("epoch", Value::Int(1)),
    ]);
    let content = object(
        &["v", "node", "target", "base_sha256", "new_sha256", "cell"]
            .map(|name| (name, auth.get(name))),
    );
    let operation = hash(
        &[
            b"aukora:operation-content:v1\0".as_slice(),
            content.canonical().as_bytes(),
        ]
        .concat(),
    );
    auth.set("operation", string(hex::encode(operation)));
    match mutation {
        Some("operation") => auth.set("operation", string("ab".repeat(32))),
        Some("epoch") => auth.set("epoch", Value::Int(0)),
        Some("challenge") => auth.set("challenge", string("ab".repeat(16))),
        Some("retire-as-apply") => auth.set("op", string("retire")),
        _ => (),
    }
    if mutation == Some("new-bytes") {
        card.set(
            "from_to",
            object(&[("base", Value::Null), ("new", string("different bytes"))]),
        );
        auth.set(
            "display_sha256",
            string(hex::encode(hash(card.canonical().as_bytes()))),
        );
    }
    if mutation == Some("review-card") {
        card.set("model_note", string("changed after card digest"));
    }
    let owner = object(&[
        ("subject", auth.get("subject")),
        ("epoch", auth.get("epoch")),
        ("binding_sha256", string("cd".repeat(32))),
    ]);
    writer.append(
        "gate.propose",
        if mutation == Some("proposal-phase") {
            "fact"
        } else {
            "intent"
        },
        &op,
        object(&[
            ("target", auth.get("target")),
            ("base_sha256", auth.get("base_sha256")),
            ("new_sha256", auth.get("new_sha256")),
            ("digest", auth.get("operation")),
        ]),
    );
    if mutation == Some("immune-evidence") {
        // A release proposal also carries the immune organ's evidence as a
        // gate.propose fact with the same op (release_immune.rs).
        writer.append(
            "gate.propose",
            "fact",
            &op,
            object(&[
                ("immune_release", object(&[("pass_count", Value::Int(20))])),
                ("runtime_digest", string("ef".repeat(32))),
            ]),
        );
    }
    let mut review_auth = auth.clone();
    if mutation == Some("review-auth") {
        review_auth.set("challenge", string("cd".repeat(32)));
    }
    writer.append(
        "gate.review",
        "fact",
        &op,
        object(&[
            ("authorization", review_auth),
            ("owner_state", owner.clone()),
            ("card", card),
        ]),
    );
    let review_seq = writer.rows.len();
    let mut review_reference = object(&[
        ("seq", Value::Int(review_seq as i64)),
        (
            "hash",
            string(hex::encode(writer.rows[review_seq - 1].hash)),
        ),
    ]);
    if mutation == Some("review-reference") {
        review_reference.set("hash", string("ab".repeat(32)));
    }
    let authorization_hash = hash(
        &[
            b"aukora:owner-authorization:v1\0".as_slice(),
            auth.canonical().as_bytes(),
        ]
        .concat(),
    );
    let proof = b"disposable proof bytes; passkey verified at live gate";
    let proof_hash = string(hex::encode(hash(proof)));
    let mut consumed = object(&[
        ("authorization", auth.clone()),
        (
            "authorization_sha256",
            string(hex::encode(authorization_hash)),
        ),
        ("proof_hex", string(hex::encode(proof))),
        ("proof_sha256", proof_hash.clone()),
        ("owner_state", owner),
        ("review_issue", review_reference.clone()),
        ("spent", Value::Bool(true)),
    ]);
    if mutation == Some("proof") {
        consumed.set("proof_hex", string("00"));
    }
    if mutation == Some("spent") {
        consumed.set("spent", Value::Bool(false));
    }
    writer.append("gate.consume", "settle", &op, consumed.clone());
    let consume_seq = writer.rows.len();
    let mut consume_reference = object(&[
        ("seq", Value::Int(consume_seq as i64)),
        (
            "hash",
            string(hex::encode(writer.rows[consume_seq - 1].hash)),
        ),
        ("review_issue", review_reference),
    ]);
    if mutation == Some("consume-reference") {
        consume_reference.set("hash", string("ab".repeat(32)));
    }
    if mutation == Some("duplicate-consume") {
        writer.append("gate.consume", "settle", &op, consumed);
    }
    let mut authority = object(&[
        ("version", Value::Int(1)),
        ("kind", string("aukora-owner-authorization-ref/v1")),
        ("authorization_id", string(hex::encode(authorization_hash))),
        (
            "authorization_sha256",
            string(hex::encode(authorization_hash)),
        ),
        ("proof_sha256", proof_hash),
    ]);
    if mutation == Some("receipt-authority") {
        authority.set("authorization_sha256", string("ab".repeat(32)));
    }
    let mut receipt = object(&[
        ("v", Value::Int(3)),
        ("kind", string("change")),
        ("proposal", string(&op)),
        ("target", auth.get("target")),
        ("node", auth.get("node")),
        ("base_sha256", auth.get("base_sha256")),
        ("new_sha256", auth.get("new_sha256")),
        ("approver", auth.get("subject")),
        ("owner_consumption", consume_reference),
        ("owner_authorization", authority),
    ]);
    if mutation == Some("receipt-bytes") {
        receipt.set("new_sha256", string("ab".repeat(32)));
    }
    writer.append(
        "gate.apply",
        "terminal",
        &op,
        object(&[("receipt", receipt)]),
    );
    writer
}

fn path0_report(writer: &Writer) -> verifier::Report {
    let key = hex::encode(writer.key.verifying_key().to_bytes());
    let rows = writer.text();
    let retained = writer.head(writer.rows.len()).canonical();
    let presented = writer.presented(writer.rows.len()).canonical();
    verifier::verify(verifier::Inputs {
        key_hex: key.as_bytes(),
        rows: rows.as_bytes(),
        retained: Some(retained.as_bytes()),
        presented: Some(presented.as_bytes()),
        prefix: None,
        checkpoint: None,
    })
}

#[test]
fn antibody_path0_signed_proposal_review_consume_apply_verify_cold() {
    let report = path0_report(&path0_writer(None));
    assert_eq!(
        report.verdict,
        verifier::Verdict::Verified,
        "{:?}",
        report.findings
    );
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.starts_with("OWNER_BINDING VERIFIED seq=4")));
}

#[test]
fn antibody_path0_release_with_immune_evidence_fact_verifies() {
    // Found live on S2 (2026-10-15): every release proposal since the immune organ
    // also has a gate.propose fact for the same op, and the verifier called it REWRITTEN.
    let report = path0_report(&path0_writer(Some("immune-evidence")));
    assert_eq!(
        report.verdict,
        verifier::Verdict::Verified,
        "{:?}",
        report.findings
    );
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.starts_with("OWNER_BINDING VERIFIED")));
}

#[test]
fn antibody_path0_rejects_old_or_uncommitted_authorization() {
    for mutation in ["epoch", "challenge", "operation", "retire-as-apply"] {
        let report = path0_report(&path0_writer(Some(mutation)));
        assert_ne!(
            report.verdict,
            verifier::Verdict::Verified,
            "{mutation}: {:?}",
            report.findings
        );
    }
}

#[test]
fn antibody_path0_requires_exact_review_bytes_and_consumed_proof() {
    for mutation in ["review-card", "new-bytes", "review-auth", "proof", "spent"] {
        let report = path0_report(&path0_writer(Some(mutation)));
        assert_ne!(
            report.verdict,
            verifier::Verdict::Verified,
            "{mutation}: {:?}",
            report.findings
        );
    }
}

#[test]
fn antibody_path0_requires_pinned_cell_and_exact_input_effect() {
    for mutation in ["cell-module", "cell-input", "cell-effect"] {
        let report = path0_report(&path0_writer(Some(mutation)));
        assert_ne!(
            report.verdict,
            verifier::Verdict::Verified,
            "{mutation}: {:?}",
            report.findings
        );
    }
}

#[test]
fn antibody_path0_receipt_requires_unique_consumption_and_references() {
    for mutation in [
        "review-reference",
        "consume-reference",
        "receipt-authority",
        "receipt-bytes",
        "duplicate-consume",
        "proposal-phase",
    ] {
        let report = path0_report(&path0_writer(Some(mutation)));
        assert_ne!(
            report.verdict,
            verifier::Verdict::Verified,
            "{mutation}: {:?}",
            report.findings
        );
    }
}

#[test]
fn antibody_legacy_digest_without_gate_provenance_is_unchecked() {
    let mut writer = Writer::new();
    writer.append(
        "gate.apply",
        "terminal",
        &format!("{:032x}", 1),
        authorization_body(authorization(1)),
    );
    let report = path0_report(&writer);
    assert_eq!(report.verdict, verifier::Verdict::Unchecked);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.contains("verifier:owner-provenance")));
}

struct Fixture {
    path: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join(".scratch")
            .join(format!(
                "{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn write(&self, name: &str, contents: impl AsRef<[u8]>) -> PathBuf {
        let path = self.path.join(name);
        fs::write(&path, contents).unwrap();
        path
    }

    fn run(&self, writer: &Writer, text: &str, flags: &[(&str, &Path)]) -> Output {
        let key = self.write(
            "key.hex",
            hex::encode(writer.key.verifying_key().to_bytes()),
        );
        let rows = self.write("rows.jsonl", text);
        let mut command = Command::new(env!("CARGO_BIN_EXE_aukora-verify"));
        command.arg("--key").arg(key).arg("--rows").arg(rows);
        for (flag, path) in flags {
            command.arg(flag).arg(path);
        }
        command.output().unwrap()
    }

    fn anchored(&self, writer: &Writer, text: &str) -> Output {
        let checkpoint = self.write(
            "checkpoint.json",
            writer.head(writer.rows.len()).canonical(),
        );
        let retained_size = 1;
        let retained = self.write("retained.json", writer.head(retained_size).canonical());
        let presented = self.write(
            "presented.json",
            writer.presented(retained_size).canonical(),
        );
        self.run(
            writer,
            text,
            &[
                ("--checkpoint", &checkpoint),
                ("--retained", &retained),
                ("--presented", &presented),
            ],
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
        if let Some(parent) = self.path.parent() {
            let _ = fs::remove_dir(parent);
        }
    }
}

fn output_text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_verdict(output: &Output, code: i32, verdict: &str) {
    let text = output_text(output);
    assert_eq!(output.status.code(), Some(code), "{text}");
    let final_line = String::from_utf8_lossy(&output.stdout)
        .lines()
        .last()
        .unwrap_or("")
        .to_string();
    assert!(
        final_line.starts_with(verdict),
        "last line {final_line:?}; output {text}"
    );
}

fn assert_bad_sequence(output: &Output, verdict: &str, position: usize) {
    assert_verdict(output, 2, verdict);
    assert!(
        output_text(output).contains(&format!("seq={position}")),
        "{}",
        output_text(output)
    );
}

#[test]
fn anchored_rows_verify_and_identify_the_executable() {
    let fixture = Fixture::new();
    let writer = Writer::facts(3);
    let output = fixture.anchored(&writer, &writer.text());
    assert_verdict(&output, 0, "VERIFIED");
    let expected = hex::encode(hash(
        &fs::read(env!("CARGO_BIN_EXE_aukora-verify")).unwrap(),
    ));
    assert!(output_text(&output).contains(&format!("VERIFY_EXECUTABLE_SHA256 {expected}")));
    assert!(output_text(&output).contains("rows 1..3"));
    assert!(output_text(&output).contains("signatures"));
}

#[test]
fn unanchored_signed_prefix_is_never_complete() {
    let fixture = Fixture::new();
    let writer = Writer::facts(9);
    assert_verdict(
        &fixture.run(&writer, &lines(&writer.rows[..8]), &[]),
        1,
        "UNCHECKED",
    );
}

#[test]
fn truncating_a_covered_export_names_the_first_missing_sequence() {
    let fixture = Fixture::new();
    let writer = Writer::facts(9);
    assert_bad_sequence(
        &fixture.anchored(&writer, &lines(&writer.rows[..8])),
        "REWRITTEN",
        9,
    );
}

#[test]
fn export_without_final_newline_is_rewritten() {
    let fixture = Fixture::new();
    let writer = Writer::facts(3);
    assert_bad_sequence(
        &fixture.anchored(&writer, writer.text().trim_end_matches('\n')),
        "REWRITTEN",
        3,
    );
}

#[test]
fn flipped_body_is_rewritten() {
    let fixture = Fixture::new();
    let mut writer = Writer::facts(4);
    let checkpoint = fixture.write("checkpoint.json", writer.head(4).canonical());
    writer.rows[1].body.set("index", Value::Int(99));
    assert_bad_sequence(
        &fixture.run(&writer, &writer.text(), &[("--checkpoint", &checkpoint)]),
        "REWRITTEN",
        2,
    );
}

#[test]
fn a_signed_wrong_previous_link_is_rewritten() {
    let fixture = Fixture::new();
    let mut writer = Writer::facts(4);
    writer.rows[1].prev = "ab".repeat(32);
    writer.rows[1].sign(&writer.key);
    assert_bad_sequence(&fixture.anchored(&writer, &writer.text()), "REWRITTEN", 2);
}

#[test]
fn a_signed_wrong_genesis_is_rewritten() {
    let fixture = Fixture::new();
    let mut writer = Writer::facts(2);
    writer.rows[0].prev = "ab".repeat(32);
    writer.rows[0].sign(&writer.key);
    writer.resign_from(1);
    assert_bad_sequence(&fixture.anchored(&writer, &writer.text()), "REWRITTEN", 1);
}

#[test]
fn reordered_rows_are_rewritten() {
    let fixture = Fixture::new();
    let writer = Writer::facts(4);
    let mut rows = writer.rows.clone();
    rows.swap(1, 2);
    assert_bad_sequence(&fixture.anchored(&writer, &lines(&rows)), "REWRITTEN", 2);
}

#[test]
fn a_signed_sequence_gap_is_rewritten() {
    let fixture = Fixture::new();
    let mut writer = Writer::facts(4);
    writer.rows[1].seq = 3;
    writer.resign_from(1);
    assert_bad_sequence(&fixture.anchored(&writer, &writer.text()), "REWRITTEN", 2);
}

#[test]
fn a_signed_duplicate_sequence_is_rewritten() {
    let fixture = Fixture::new();
    let mut writer = Writer::facts(4);
    writer.rows[1].seq = 1;
    writer.resign_from(1);
    assert_bad_sequence(&fixture.anchored(&writer, &writer.text()), "REWRITTEN", 2);
}

#[test]
fn another_signing_key_is_forged() {
    let fixture = Fixture::new();
    let mut writer = Writer::facts(3);
    writer.rows[1].signature = base64(
        &SigningKey::from_bytes(&[8; 32])
            .sign(&writer.rows[1].hash)
            .to_bytes(),
    );
    assert_bad_sequence(&fixture.anchored(&writer, &writer.text()), "FORGED", 2);
}

#[test]
fn malformed_signature_is_never_verified() {
    let fixture = Fixture::new();
    let mut writer = Writer::facts(2);
    writer.rows[1].signature = "AAAA".into();
    assert_ne!(
        fixture.anchored(&writer, &writer.text()).status.code(),
        Some(0)
    );
}

#[test]
fn retained_prefix_names_the_first_signed_fork() {
    let fixture = Fixture::new();
    let mut writer = Writer::facts(9);
    let prefix = fixture.write("prefix.jsonl", lines(&writer.rows[..8]));
    writer.rows[2].body.set("index", Value::Int(333));
    writer.resign_from(2);
    assert_bad_sequence(
        &fixture.run(&writer, &writer.text(), &[("--prefix", &prefix)]),
        "REWRITTEN",
        3,
    );
}

#[test]
fn a_covering_retained_prefix_verifies() {
    let fixture = Fixture::new();
    let writer = Writer::facts(7);
    let prefix = fixture.write("prefix.jsonl", writer.text());
    let retained = fixture.write("retained.json", writer.head(2).canonical());
    let presented = fixture.write("presented.json", writer.presented(2).canonical());
    assert_verdict(
        &fixture.run(
            &writer,
            &writer.text(),
            &[
                ("--prefix", &prefix),
                ("--retained", &retained),
                ("--presented", &presented),
            ],
        ),
        0,
        "VERIFIED",
    );
}

#[test]
fn an_earlier_retained_prefix_does_not_cover_the_tail() {
    let fixture = Fixture::new();
    let writer = Writer::facts(7);
    let prefix = fixture.write("prefix.jsonl", lines(&writer.rows[..4]));
    assert_verdict(
        &fixture.run(&writer, &writer.text(), &[("--prefix", &prefix)]),
        1,
        "UNCHECKED",
    );
}

#[test]
fn a_retained_head_detects_a_signed_fork_without_claiming_its_first_entry() {
    let fixture = Fixture::new();
    let mut writer = Writer::facts(9);
    let retained = fixture.write("retained.json", writer.head(8).canonical());
    writer.rows[2].body.set("index", Value::Int(333));
    writer.resign_from(2);
    let presented = fixture.write("presented.json", writer.presented(8).canonical());
    let output = fixture.run(
        &writer,
        &writer.text(),
        &[("--retained", &retained), ("--presented", &presented)],
    );
    assert_verdict(&output, 2, "REWRITTEN");
    assert!(output_text(&output).contains("first bad seq unknown"));
    assert!(output_text(&output).contains("at or before 8"));
}

#[test]
fn a_retained_root_only_mismatch_is_rewritten() {
    let fixture = Fixture::new();
    let writer = Writer::facts(9);
    let mut retained = writer.head(3);
    retained.set("root", string("ab".repeat(32)));
    let retained = fixture.write("retained.json", retained.canonical());
    let presented = fixture.write("presented.json", writer.presented(3).canonical());
    let checkpoint = fixture.write("checkpoint.json", writer.head(9).canonical());
    let output = fixture.run(
        &writer,
        &writer.text(),
        &[
            ("--retained", &retained),
            ("--presented", &presented),
            ("--checkpoint", &checkpoint),
        ],
    );
    assert_verdict(&output, 2, "REWRITTEN");
    assert!(output_text(&output).contains("first bad seq unknown"));
    assert!(output_text(&output).contains("at or before 3"));
}

#[test]
fn a_checkpoint_hash_only_mismatch_is_rewritten() {
    let fixture = Fixture::new();
    let writer = Writer::facts(9);
    let retained = fixture.write("retained.json", writer.head(3).canonical());
    let presented = fixture.write("presented.json", writer.presented(3).canonical());
    let mut checkpoint = writer.head(9);
    checkpoint.set("hash", string("ab".repeat(32)));
    let checkpoint = fixture.write("checkpoint.json", checkpoint.canonical());
    let output = fixture.run(
        &writer,
        &writer.text(),
        &[
            ("--retained", &retained),
            ("--presented", &presented),
            ("--checkpoint", &checkpoint),
        ],
    );
    assert_verdict(&output, 2, "REWRITTEN");
    assert!(output_text(&output).contains("first bad seq unknown"));
    assert!(output_text(&output).contains("at or before 9"));
}

#[test]
fn a_truncated_export_with_a_rebuilt_presented_head_cannot_evade_a_covering_checkpoint() {
    let fixture = Fixture::new();
    let mut writer = Writer::facts(9);
    let checkpoint = fixture.write("checkpoint.json", writer.head(9).canonical());
    writer.rows.truncate(8);
    let retained = fixture.write("retained.json", writer.head(1).canonical());
    let presented = fixture.write("presented.json", writer.presented(1).canonical());
    assert_bad_sequence(
        &fixture.run(
            &writer,
            &writer.text(),
            &[
                ("--retained", &retained),
                ("--presented", &presented),
                ("--checkpoint", &checkpoint),
            ],
        ),
        "REWRITTEN",
        9,
    );
}

#[test]
fn consistency_vectors_cover_power_of_two_and_non_power_of_two_heads() {
    let fixture = Fixture::new();
    let writer = Writer::facts(40);
    let checkpoint = fixture.write("checkpoint.json", writer.head(40).canonical());
    for retained_size in [1, 2, 3, 4, 5, 8, 16, 31, 32, 40] {
        let retained = fixture.write("retained.json", writer.head(retained_size).canonical());
        let presented = fixture.write(
            "presented.json",
            writer.presented(retained_size).canonical(),
        );
        let output = fixture.run(
            &writer,
            &writer.text(),
            &[
                ("--retained", &retained),
                ("--presented", &presented),
                ("--checkpoint", &checkpoint),
            ],
        );
        assert_verdict(&output, 0, "VERIFIED");
        assert!(
            output_text(&output).contains(&format!("consistency from {retained_size}")),
            "{}",
            output_text(&output)
        );
    }
}

#[test]
fn presented_head_alone_does_not_prove_completeness() {
    let fixture = Fixture::new();
    let writer = Writer::facts(9);
    let retained = fixture.write("retained.json", writer.head(4).canonical());
    let presented = fixture.write("presented.json", writer.presented(4).canonical());
    assert_verdict(
        &fixture.run(
            &writer,
            &writer.text(),
            &[("--retained", &retained), ("--presented", &presented)],
        ),
        1,
        "UNCHECKED",
    );
}

#[test]
fn checkpoint_alone_leaves_consistency_unchecked() {
    let fixture = Fixture::new();
    let writer = Writer::facts(3);
    let checkpoint = fixture.write("checkpoint.json", writer.head(3).canonical());
    assert_verdict(
        &fixture.run(&writer, &writer.text(), &[("--checkpoint", &checkpoint)]),
        1,
        "UNCHECKED",
    );
}

#[test]
fn covering_retained_and_presented_heads_need_no_extra_checkpoint() {
    let fixture = Fixture::new();
    let writer = Writer::facts(3);
    let retained = fixture.write("retained.json", writer.head(3).canonical());
    let presented = fixture.write("presented.json", writer.presented(3).canonical());
    assert_verdict(
        &fixture.run(
            &writer,
            &writer.text(),
            &[("--retained", &retained), ("--presented", &presented)],
        ),
        0,
        "VERIFIED",
    );
}

#[test]
fn inadmissible_heads_never_verify() {
    let fixture = Fixture::new();
    let writer = Writer::facts(9);
    let checkpoint = fixture.write("checkpoint.json", writer.head(9).canonical());
    for (is_retained, field, replacement) in [
        (true, "schema", string("aukora-aura-retained-head-v2")),
        (true, "leafConvention", string("sha256-unprefixed")),
        (true, "sequence", Value::Int(2)),
        (true, "hash", string("AB".repeat(32))),
        (false, "schema", string("aukora-aura-presented-head-v2")),
        (false, "leafConvention", string("sha256-unprefixed")),
        (false, "retainedTreeSize", Value::Int(2)),
        (false, "treeSize", Value::Int(8)),
    ] {
        let mut retained = writer.head(3);
        let mut presented = writer.presented(3);
        if is_retained {
            retained.set(field, replacement);
        } else {
            presented.set(field, replacement);
        }
        let retained = fixture.write("retained.json", retained.canonical());
        let presented = fixture.write("presented.json", presented.canonical());
        assert_ne!(
            fixture
                .run(
                    &writer,
                    &writer.text(),
                    &[
                        ("--retained", &retained),
                        ("--presented", &presented),
                        ("--checkpoint", &checkpoint)
                    ]
                )
                .status
                .code(),
            Some(0),
            "head field {field}"
        );
    }
}

#[test]
fn operations_require_exactly_one_terminal_row() {
    let fixture = Fixture::new();
    let op = format!("{:032x}", 7);
    for duplicate in [false, true] {
        let mut writer = Writer::new();
        writer.append(
            "gate.consume",
            "settle",
            &op,
            authorization_body(authorization(7)),
        );
        if duplicate {
            writer.append(
                "gate.apply",
                "terminal",
                &op,
                authorization_body(authorization(7)),
            );
            writer.append(
                "gate.apply",
                "terminal",
                &op,
                authorization_body(authorization(7)),
            );
        }
        assert_verdict(&fixture.anchored(&writer, &writer.text()), 1, "UNCHECKED");
    }
}

#[test]
fn authorization_shape_is_checked_before_its_matching_digest_is_trusted() {
    let fixture = Fixture::new();
    for (field, replacement) in [
        ("v", Value::Int(2)),
        ("node", string("12")),
        ("subject", string("owner")),
        ("op", string("execute")),
        ("proposal", string("12")),
        ("new_sha256", string("AB".repeat(32))),
        ("display_sha256", string("AB".repeat(32))),
        ("challenge", string("12")),
        ("cell", Value::Int(1)),
        ("unexpected", Value::Null),
    ] {
        let mut writer = Writer::new();
        let mut auth = authorization(1);
        auth.set(field, replacement);
        writer.append(
            "gate.apply",
            "terminal",
            &format!("{:032x}", 1),
            authorization_body(auth),
        );
        let output = fixture.anchored(&writer, &writer.text());
        assert_ne!(
            output.status.code(),
            Some(0),
            "{field}: {}",
            output_text(&output)
        );
        assert!(
            !output_text(&output).contains("OWNER_BINDING VERIFIED"),
            "{field}: {}",
            output_text(&output)
        );
    }
}

#[test]
fn missing_owner_authorization_is_explicitly_unchecked() {
    let fixture = Fixture::new();
    let mut writer = Writer::new();
    writer.append(
        "gate.apply",
        "terminal",
        &format!("{:032x}", 1),
        object(&[]),
    );
    assert_verdict(&fixture.anchored(&writer, &writer.text()), 1, "UNCHECKED");
}

#[test]
fn base64_nonzero_padding_bits_do_not_alias_a_valid_signature() {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let fixture = Fixture::new();
    let mut writer = Writer::facts(1);
    let mut signature = writer.rows[0].signature.as_bytes().to_vec();
    let index = ALPHABET
        .iter()
        .position(|character| *character == signature[85])
        .unwrap();
    signature[85] = ALPHABET[index + 1];
    writer.rows[0].signature = String::from_utf8(signature).unwrap();
    assert_ne!(
        fixture.anchored(&writer, &writer.text()).status.code(),
        Some(0)
    );
}

#[test]
fn a_wrong_presented_root_is_rewritten() {
    let fixture = Fixture::new();
    let writer = Writer::facts(9);
    let retained = fixture.write("retained.json", writer.head(4).canonical());
    let mut presented = writer.presented(4);
    presented.set("root", string("ab".repeat(32)));
    let presented = fixture.write("presented.json", presented.canonical());
    assert_verdict(
        &fixture.run(
            &writer,
            &writer.text(),
            &[("--retained", &retained), ("--presented", &presented)],
        ),
        2,
        "REWRITTEN",
    );
}

#[test]
fn presented_size_mismatch_reports_first_missing_seq() {
    let fixture = Fixture::new();
    let writer = Writer::facts(9);
    let retained = fixture.write("retained.json", writer.head(3).canonical());
    let mut presented = writer.presented(3);
    presented.set("treeSize", Value::Int(8));
    let presented = fixture.write("presented.json", presented.canonical());
    let checkpoint = fixture.write("checkpoint.json", writer.head(9).canonical());
    let output = fixture.run(
        &writer,
        &writer.text(),
        &[
            ("--retained", &retained),
            ("--presented", &presented),
            ("--checkpoint", &checkpoint),
        ],
    );
    assert_bad_sequence(&output, "REWRITTEN", 9);
    assert!(output_text(&output).contains("verifier:presented-size"));
}

#[test]
fn altered_truncated_and_extra_consistency_proofs_are_rejected() {
    let fixture = Fixture::new();
    let writer = Writer::facts(9);
    let retained = fixture.write("retained.json", writer.head(3).canonical());
    let checkpoint = fixture.write("checkpoint.json", writer.head(9).canonical());
    let nodes = proof(3, &writer.leaves(), true);
    for changed in [
        vec![[0xab; 32]; nodes.len()],
        nodes[..nodes.len() - 1].to_vec(),
        [nodes.clone(), vec![[0xab; 32]]].concat(),
    ] {
        let mut presented = writer.presented(3);
        presented.set(
            "proofFromPrevious",
            Value::Array(
                changed
                    .into_iter()
                    .map(|node| string(hex::encode(node)))
                    .collect(),
            ),
        );
        let presented = fixture.write("presented.json", presented.canonical());
        assert_verdict(
            &fixture.run(
                &writer,
                &writer.text(),
                &[
                    ("--retained", &retained),
                    ("--presented", &presented),
                    ("--checkpoint", &checkpoint),
                ],
            ),
            1,
            "UNCHECKED",
        );
    }
}

#[test]
fn same_size_heads_require_an_empty_consistency_proof() {
    let fixture = Fixture::new();
    let writer = Writer::facts(9);
    let retained = fixture.write("retained.json", writer.head(9).canonical());
    let mut presented = writer.presented(9);
    presented.set(
        "proofFromPrevious",
        Value::Array(vec![string("ab".repeat(32))]),
    );
    let presented = fixture.write("presented.json", presented.canonical());
    assert_verdict(
        &fixture.run(
            &writer,
            &writer.text(),
            &[("--retained", &retained), ("--presented", &presented)],
        ),
        1,
        "UNCHECKED",
    );
}

#[test]
fn wrong_owner_authorization_digest_is_rewritten_at_its_row() {
    let fixture = Fixture::new();
    for kind in ["gate.consume", "gate.apply"] {
        let mut writer = Writer::facts(1);
        let mut body = authorization_body(authorization(1));
        body.set("authorization_digest", string("ab".repeat(32)));
        writer.append(kind, "terminal", &format!("{:032x}", 1), body);
        assert_bad_sequence(&fixture.anchored(&writer, &writer.text()), "REWRITTEN", 2);
    }
}

#[test]
fn unknown_kind_and_nonobject_body_do_not_poison_another_owner_binding() {
    let fixture = Fixture::new();
    for (kind, body) in [("junk.kind", object(&[])), ("boot.facts", Value::Null)] {
        let mut writer = Writer::new();
        writer.append(
            "gate.consume",
            "intent",
            &format!("{:032x}", 1),
            authorization_body(authorization(1)),
        );
        writer.append(kind, "fact", "", body);
        writer.append(
            "gate.apply",
            "terminal",
            &format!("{:032x}", 1),
            authorization_body(authorization(1)),
        );
        let output = fixture.anchored(&writer, &writer.text());
        assert_verdict(&output, 1, "UNCHECKED");
        let text = output_text(&output);
        assert!(text.contains("OWNER_BINDING VERIFIED seq=1"), "{text}");
        assert!(text.contains("OWNER_BINDING VERIFIED seq=3"), "{text}");
    }
}

#[test]
fn a_signed_integer_kind_does_not_poison_another_owner_binding() {
    let fixture = Fixture::new();
    let mut writer = Writer::new();
    let op = format!("{:032x}", 1);
    writer.append(
        "gate.consume",
        "settle",
        &op,
        authorization_body(authorization(1)),
    );
    writer.append("boot.facts", "fact", "", object(&[]));
    writer.append(
        "gate.apply",
        "terminal",
        &op,
        authorization_body(authorization(1)),
    );
    let mut preimage = writer.rows[1].fields();
    preimage.set("kind", Value::Int(12));
    preimage.set("prev", string(&writer.rows[1].prev));
    preimage.set("domain", string(DOMAIN));
    writer.rows[1].hash = hash(preimage.canonical().as_bytes());
    writer.rows[1].signature = base64(&writer.key.sign(&writer.rows[1].hash).to_bytes());
    writer.resign_from(2);
    let text: String = writer
        .rows
        .iter()
        .enumerate()
        .map(|(index, row)| {
            let mut value = row.value();
            if index == 1 {
                value.set("kind", Value::Int(12));
            }
            format!("{}\n", value.canonical())
        })
        .collect();
    let output = fixture.anchored(&writer, &text);
    assert_verdict(&output, 1, "UNCHECKED");
    assert!(output_text(&output).contains("OWNER_BINDING VERIFIED seq=1"));
    assert!(output_text(&output).contains("OWNER_BINDING VERIFIED seq=3"));
}

#[test]
fn signed_schema_variants_do_not_poison_another_owner_binding() {
    let fixture = Fixture::new();
    for (field, replacement) in [
        ("at", Value::Null),
        ("actor", Value::Int(12)),
        ("op", Value::Null),
        ("phase", string("unknown")),
        ("phase", Value::Int(12)),
    ] {
        let mut writer = Writer::new();
        let op = format!("{:032x}", 1);
        writer.append(
            "gate.consume",
            "settle",
            &op,
            authorization_body(authorization(1)),
        );
        writer.append("boot.facts", "fact", "", object(&[]));
        writer.append(
            "gate.apply",
            "terminal",
            &op,
            authorization_body(authorization(1)),
        );
        let mut preimage = writer.rows[1].fields();
        preimage.set(field, replacement.clone());
        preimage.set("prev", string(&writer.rows[1].prev));
        preimage.set("domain", string(DOMAIN));
        writer.rows[1].hash = hash(preimage.canonical().as_bytes());
        writer.rows[1].signature = base64(&writer.key.sign(&writer.rows[1].hash).to_bytes());
        writer.resign_from(2);
        let text: String = writer
            .rows
            .iter()
            .enumerate()
            .map(|(index, row)| {
                let mut value = row.value();
                if index == 1 {
                    value.set(field, replacement.clone());
                }
                format!("{}\n", value.canonical())
            })
            .collect();
        let output = fixture.anchored(&writer, &text);
        assert_verdict(&output, 1, "UNCHECKED");
        assert!(
            output_text(&output).contains("OWNER_BINDING VERIFIED seq=1"),
            "{field}: {}",
            output_text(&output)
        );
        assert!(
            output_text(&output).contains("OWNER_BINDING VERIFIED seq=3"),
            "{field}: {}",
            output_text(&output)
        );
    }
}

#[test]
fn one_hundred_distinct_digest_bindings_remain_unchecked_across_process_restarts() {
    let fixture = Fixture::new();
    let mut clean = Writer::new();
    let mut with_junk = Writer::new();
    for index in 1..=100 {
        let auth = authorization(index);
        let body = authorization_body(auth);
        let op = format!("{index:032x}");
        clean.append("gate.consume", "intent", &op, body.clone());
        clean.append("gate.apply", "terminal", &op, body.clone());
        with_junk.append("gate.consume", "intent", &op, body.clone());
        with_junk.append(
            "junk.kind",
            "fact",
            "",
            object(&[("index", Value::Int(index as i64))]),
        );
        with_junk.append("gate.apply", "terminal", &op, body);
        assert_verdict(&fixture.anchored(&clean, &clean.text()), 1, "UNCHECKED");
        let injected = fixture.anchored(&with_junk, &with_junk.text());
        assert_verdict(&injected, 1, "UNCHECKED");
        let text = output_text(&injected);
        assert!(
            text.contains(&format!("OWNER_BINDING VERIFIED seq={}", index * 3 - 2)),
            "{text}"
        );
        assert!(
            text.contains(&format!("OWNER_BINDING VERIFIED seq={}", index * 3)),
            "{text}"
        );
    }
}

#[test]
fn noncanonical_and_extra_column_rows_are_never_verified() {
    let fixture = Fixture::new();
    let writer = Writer::facts(1);
    let canonical = writer.rows[0].value().canonical();
    let mut extra = writer.rows[0].value();
    extra.set("domain", string(DOMAIN));
    for text in [
        format!(" {canonical}\n"),
        format!("{}\n", extra.canonical()),
        format!("{}\n", canonical.replacen("\"at\":", "\"at\":0,\"at\":", 1)),
        format!("\u{feff}{canonical}\n"),
    ] {
        assert_ne!(fixture.anchored(&writer, &text).status.code(), Some(0));
    }
}

#[test]
fn usage_and_missing_inputs_are_reported_separately() {
    let output = Command::new(env!("CARGO_BIN_EXE_aukora-verify"))
        .arg("--unknown")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(64), "{}", output_text(&output));
    let fixture = Fixture::new();
    let writer = Writer::facts(1);
    let missing = fixture.path.join("missing.json");
    assert_verdict(
        &fixture.run(&writer, &writer.text(), &[("--retained", &missing)]),
        64,
        "UNCHECKED",
    );
}

#[test]
fn a_missing_configured_node_fails_prime_parity() {
    let fixture = Fixture::new();
    assert_prerequisite_failure(
        "prime_restatement_matches_independent_writer_bytes_with_unicode",
        "AUKORA_NODE",
        &fixture.path.join("missing-node"),
        "AUKORA_NODE",
    );
}

#[test]
fn a_missing_prime_reference_fails_node_and_python_parity() {
    let fixture = Fixture::new();
    for test in [
        "prime_restatement_matches_independent_writer_bytes_with_unicode",
        "external_python_verdict_is_reported_beside_the_independent_verdict",
    ] {
        assert_prerequisite_failure(
            test,
            "AUKORA_PRIME",
            &fixture.path.join("missing-prime"),
            "AUKORA_PRIME",
        );
    }
}

#[test]
fn a_missing_python_fails_external_parity() {
    assert_prerequisite_failure(
        "external_python_verdict_is_reported_beside_the_independent_verdict",
        "PATH",
        Path::new(""),
        "python3 must be available on PATH",
    );
}

fn assert_prerequisite_failure(test: &str, variable: &str, value: &Path, diagnostic: &str) {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env(variable, value)
        .output()
        .unwrap();
    let text = output_text(&output);
    assert!(!output.status.success(), "{test} must fail: {text}");
    assert!(text.contains(diagnostic), "{test}: {text}");
}

#[test]
fn prime_restatement_matches_independent_writer_bytes_with_unicode() {
    let prime = test_prime::prime_file("scripts/aura/verify-append-only.mjs");
    let mut writer = Writer::new();
    let body = object(&[
        ("\u{e000}", string("literal \u{2028}\u{2029}\u{7f}")),
        ("\u{10000}", string("quotes \" \\ \n \u{1}")),
        (
            "a",
            Value::Array(vec![Value::Int(-9_007_199_254_740_991), Value::Null]),
        ),
    ]);
    writer.append("boot.facts", "fact", "", body);
    let row = &writer.rows[0];
    let script = r#"
const fs = require('node:fs');
const { createHash, createPrivateKey, createPublicKey, sign } = require('node:crypto');
const source = fs.readFileSync(process.argv[1], 'utf8');
const restatement = source.slice(source.indexOf('function canonical('), source.indexOf('function readLog('));
const DOMAIN = 'aukora:aura-record:v1';
const sha256 = bytes => createHash('sha256').update(bytes).digest();
const hex = bytes => bytes.toString('hex');
const { canonical, entryHash } = new Function('DOMAIN', 'sha256', 'hex', restatement + '; return {canonical,entryHash};')(DOMAIN, sha256, hex);
const fields = JSON.parse(process.argv[2]);
const digest = entryHash(DOMAIN, fields);
const key = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 7)]), format: 'der', type: 'pkcs8' });
const row = {seq: fields.sequence, prev: DOMAIN, hash: digest, sig: sign(null, Buffer.from(digest, 'hex'), key).toString('base64'), at: fields.at, kind: fields.kind, actor: fields.actor, op: fields.op, phase: fields.phase, body: fields.body};
const publicHex = createPublicKey(key).export({format: 'der', type: 'spki'}).subarray(-32).toString('hex');
process.stdout.write(canonical(fields) + '\n' + digest + '\n' + canonical(row) + '\n' + publicHex + '\n');
"#;
    let output = Command::new(test_node::node())
        .arg("-e")
        .arg(script)
        .arg(prime)
        .arg(row.fields().canonical())
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", output_text(&output));
    let node_text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        node_text,
        format!(
            "{}\n{}\n{}\n{}\n",
            row.fields().canonical(),
            hex::encode(row.hash),
            row.value().canonical(),
            hex::encode(writer.key.verifying_key().to_bytes())
        )
    );
    let node_rows = format!("{}\n", node_text.lines().nth(2).unwrap());
    let fixture = Fixture::new();
    assert_verdict(&fixture.anchored(&writer, &node_rows), 0, "VERIFIED");
}

#[test]
fn external_python_verdict_is_reported_beside_the_independent_verdict() {
    let script = test_prime::prime_file("vendor/append-only/verify.py");
    Command::new("python3")
        .arg("--version")
        .output()
        .expect("python3 must be available on PATH for external Python parity");
    let fixture = Fixture::new();
    let writer = Writer::facts(9);
    let retained = fixture.write("retained.json", writer.head(3).canonical());
    let presented = fixture.write("presented.json", writer.presented(3).canonical());
    let checkpoint = fixture.write("checkpoint.json", writer.head(9).canonical());
    let output = fixture.run(
        &writer,
        &writer.text(),
        &[
            ("--retained", &retained),
            ("--presented", &presented),
            ("--checkpoint", &checkpoint),
            ("--python3", Path::new("python3")),
            ("--verify-py", &script),
        ],
    );
    assert_verdict(&output, 0, "VERIFIED");
    assert!(
        output_text(&output).contains("PYTHON_VERDICT APPEND_ONLY"),
        "{}",
        output_text(&output)
    );
}

#[test]
fn a_failing_python_process_cannot_claim_a_checked_verdict() {
    let fixture = Fixture::new();
    let writer = Writer::facts(3);
    let retained = fixture.write("retained.json", writer.head(3).canonical());
    let presented = fixture.write("presented.json", writer.presented(3).canonical());
    let script = fixture.write(
        "fails.py",
        "print('VERDICT: APPEND_ONLY')\nraise SystemExit(2)\n",
    );
    let output = fixture.run(
        &writer,
        &writer.text(),
        &[
            ("--retained", &retained),
            ("--presented", &presented),
            ("--python3", Path::new("python3")),
            ("--verify-py", &script),
        ],
    );
    assert_verdict(&output, 1, "UNCHECKED");
    assert!(
        output_text(&output).contains("PYTHON_VERDICT APPEND_ONLY"),
        "{}",
        output_text(&output)
    );
    assert!(
        output_text(&output).contains("exit=2"),
        "{}",
        output_text(&output)
    );
}

#[test]
fn a_later_malformed_row_does_not_hide_an_earlier_forged_signature() {
    let fixture = Fixture::new();
    let mut writer = Writer::facts(3);
    writer.rows[0].signature = base64(
        &SigningKey::from_bytes(&[8; 32])
            .sign(&writer.rows[0].hash)
            .to_bytes(),
    );
    writer.rows[2].seq = 2;
    writer.rows[2].sign(&writer.key);
    let output = fixture.anchored(&writer, &writer.text());
    assert_bad_sequence(&output, "FORGED", 1);
    assert!(output_text(&output).contains("bad signature at seq 1"));
}

fn cold_bundle(writer: &Writer) -> Value {
    object(&[
        ("schema", string("aukora-aura-cold-proof-v1")),
        (
            "publicKey",
            string(hex::encode(writer.key.verifying_key().to_bytes())),
        ),
        ("head", writer.head(writer.rows.len())),
        (
            "rows",
            Value::Array(writer.rows.iter().map(Row::value).collect()),
        ),
    ])
}

fn cold_engines(
    fixture: &Fixture,
    bundle: &str,
    pin: Option<&str>,
    checkpoint: Option<&str>,
) -> Vec<Output> {
    let bundle = fixture.write("cold-proof.json", bundle);
    let pin = pin.map(|value| fixture.write("cold-key.hex", value));
    let checkpoint = checkpoint.map(|value| fixture.write("cold-checkpoint.json", value));
    let empty = fixture.path.join("empty");
    fs::create_dir_all(&empty).unwrap();
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/verify.py");
    let mut native = Command::new(env!("CARGO_BIN_EXE_aukora-verify"));
    let mut python = Command::new("python3");
    python.arg("-B").arg(script);
    [&mut native, &mut python]
        .into_iter()
        .map(|command| {
            command.current_dir(&empty).arg("--bundle").arg(&bundle);
            if let Some(pin) = &pin {
                command.arg("--key").arg(pin);
            }
            if let Some(checkpoint) = &checkpoint {
                command.arg("--checkpoint").arg(checkpoint);
            }
            command.output().unwrap()
        })
        .collect()
}

fn cold_refused(fixture: &Fixture, bundle: Value, code: &str) {
    let expected = if ["verifier:bundle-format", "verifier:key-weak"].contains(&code) {
        64
    } else {
        2
    };
    for output in cold_engines(fixture, &bundle.canonical(), None, None) {
        assert_eq!(
            output.status.code(),
            Some(expected),
            "{}",
            output_text(&output)
        );
        assert!(
            output_text(&output).contains(code),
            "{}",
            output_text(&output)
        );
    }
}

#[test]
fn antibody_cold_proof_verifies_producer_bytes_from_empty_folder() {
    let fixture = Fixture::new();
    let source = include_str!("../../aura/tests/vectors/cold-proof-v1.json");
    for output in cold_engines(&fixture, source, None, None) {
        assert_verdict(&output, 1, "UNCHECKED");
        assert!(
            output_text(&output).contains("rows=1..4") || output_text(&output).contains("count=4"),
            "{}",
            output_text(&output)
        );
    }
    let writer = Writer::facts(4);
    let pin = hex::encode(writer.key.verifying_key().to_bytes());
    let head = writer.head(4).canonical();
    for output in cold_engines(
        &fixture,
        &cold_bundle(&writer).canonical(),
        Some(&pin),
        Some(&head),
    ) {
        assert_verdict(&output, 0, "VERIFIED");
    }
}

#[test]
fn antibody_cold_proof_embedded_claims_are_not_independent_witnesses() {
    let fixture = Fixture::new();
    let writer = Writer::facts(4);
    let pin = hex::encode(writer.key.verifying_key().to_bytes());
    let head = writer.head(4).canonical();
    for (pin, checkpoint) in [
        (None, None),
        (Some(pin.as_str()), None),
        (None, Some(head.as_str())),
    ] {
        for output in cold_engines(&fixture, &cold_bundle(&writer).canonical(), pin, checkpoint) {
            assert_verdict(&output, 1, "UNCHECKED");
            if pin.is_none() {
                assert!(output_text(&output).contains("verifier:identity-no-pinned-key"));
            }
            if checkpoint.is_none() {
                assert!(
                    output_text(&output).contains("verifier:completeness-no-covering-checkpoint")
                );
            }
        }
    }
}

#[test]
fn antibody_cold_proof_rejects_forged_embedded_key() {
    let fixture = Fixture::new();
    let writer = Writer::facts(4);
    let mut bundle = cold_bundle(&writer);
    bundle.set(
        "publicKey",
        string(hex::encode(
            SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes(),
        )),
    );
    cold_refused(&fixture, bundle, "verifier:signature");
}

#[test]
fn antibody_cold_proof_pinned_key_rejects_resigned_replacement() {
    let fixture = Fixture::new();
    let mut writer = Writer::facts(4);
    let pin = hex::encode(writer.key.verifying_key().to_bytes());
    writer.key = SigningKey::from_bytes(&[8; 32]);
    writer.resign_from(0);
    for output in cold_engines(
        &fixture,
        &cold_bundle(&writer).canonical(),
        Some(&pin),
        None,
    ) {
        assert_verdict(&output, 2, "FORGED");
        assert!(output_text(&output).contains("verifier:bundle-key-mismatch"));
    }
}

#[test]
fn antibody_cold_proof_rejects_edited_row() {
    let fixture = Fixture::new();
    let mut writer = Writer::facts(4);
    writer.rows[1].body.set("index", Value::Int(99));
    cold_refused(&fixture, cold_bundle(&writer), "verifier:entry-hash");
}

#[test]
fn antibody_cold_proof_rejects_dropped_tail() {
    let fixture = Fixture::new();
    let writer = Writer::facts(4);
    let mut bundle = cold_bundle(&writer);
    bundle.set(
        "rows",
        Value::Array(writer.rows[..3].iter().map(Row::value).collect()),
    );
    cold_refused(&fixture, bundle, "verifier:bundle-tail-size");
}

#[test]
fn antibody_cold_proof_rejects_rewritten_root() {
    let fixture = Fixture::new();
    let writer = Writer::facts(4);
    let mut bundle = cold_bundle(&writer);
    let mut head = writer.head(4);
    head.set("root", string("00".repeat(32)));
    bundle.set("head", head);
    cold_refused(&fixture, bundle, "verifier:checkpoint-mismatch");
}

#[test]
fn antibody_cold_proof_rejects_signed_broken_chain() {
    let fixture = Fixture::new();
    let mut writer = Writer::facts(4);
    writer.rows[1].prev = "00".repeat(32);
    writer.rows[1].sign(&writer.key);
    writer.resign_from(2);
    cold_refused(&fixture, cold_bundle(&writer), "verifier:prev-link");
}

#[test]
fn antibody_cold_proof_checkpoint_rejects_coherent_prefix_truncation() {
    let fixture = Fixture::new();
    let mut writer = Writer::facts(4);
    let checkpoint = writer.head(4).canonical();
    writer.rows.pop();
    for output in cold_engines(
        &fixture,
        &cold_bundle(&writer).canonical(),
        None,
        Some(&checkpoint),
    ) {
        assert_verdict(&output, 2, "REWRITTEN");
        assert!(output_text(&output).contains("verifier:shorter-than-checkpoint"));
    }
}

#[test]
fn antibody_cold_proof_refuses_ambiguous_or_open_shapes() {
    let fixture = Fixture::new();
    let writer = Writer::facts(4);
    let mut bundle = cold_bundle(&writer);
    bundle.set("extra", Value::Null);
    cold_refused(&fixture, bundle, "verifier:bundle-format");
    let original = cold_bundle(&writer).canonical();
    for bad in [
        format!("{original}\n"),
        original.replacen("{", "{\"schema\":\"duplicate\",", 1),
    ] {
        for output in cold_engines(&fixture, &bad, None, None) {
            assert_eq!(output.status.code(), Some(64), "{}", output_text(&output));
        }
    }
    let mut malformed = writer.rows[0].value();
    malformed.set("actor", Value::Int(2));
    let mut bundle = cold_bundle(&writer);
    bundle.set(
        "rows",
        Value::Array(
            std::iter::once(malformed)
                .chain(writer.rows[1..].iter().map(Row::value))
                .collect(),
        ),
    );
    cold_refused(&fixture, bundle, "verifier:bundle-row-schema");
}

#[test]
fn antibody_cold_proof_rejects_weak_keys_and_noncanonical_signatures() {
    let fixture = Fixture::new();
    let writer = Writer::facts(4);
    let mut weak = cold_bundle(&writer);
    weak.set("publicKey", string(format!("01{}", "00".repeat(31))));
    cold_refused(&fixture, weak, "verifier:key-weak");
    for variant in 0..4 {
        let mut writer = Writer::facts(4);
        let mut sig = writer.key.sign(&writer.rows[0].hash).to_bytes();
        if variant == 0 {
            sig[63] |= 0x80;
        }
        if variant == 1 {
            sig[..32].fill(0);
            sig[0] = 1;
        }
        if variant == 3 {
            let order =
                hex::decode("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
                    .unwrap();
            let mut carry = 0_u16;
            for (index, byte) in order.into_iter().enumerate() {
                let sum = u16::from(sig[32 + index]) + u16::from(byte) + carry;
                sig[32 + index] = sum as u8;
                carry = sum >> 8;
            }
        }
        let text = if variant == 2 {
            let mut encoded = base64(&sig);
            encoded.truncate(86);
            encoded
        } else {
            base64(&sig)
        };
        writer.rows[0].signature = text;
        cold_refused(&fixture, cold_bundle(&writer), "verifier:signature");
    }
}

#[test]
fn antibody_cold_proof_preserves_owner_binding_and_terminal_checks() {
    let fixture = Fixture::new();
    let mut writer = Writer::facts(1);
    let mut body = authorization_body(authorization(1));
    body.set("authorization_digest", string("00".repeat(32)));
    writer.append("gate.consume", "terminal", "op1", body);
    cold_refused(
        &fixture,
        cold_bundle(&writer),
        "verifier:authorization-digest",
    );
    let mut writer = Writer::facts(1);
    writer.append("gate.consume", "terminal", "op1", object(&[]));
    let pin = hex::encode(writer.key.verifying_key().to_bytes());
    let head = writer.head(2).canonical();
    for output in cold_engines(
        &fixture,
        &cold_bundle(&writer).canonical(),
        Some(&pin),
        Some(&head),
    ) {
        assert_verdict(&output, 1, "UNCHECKED");
    }
    let mut writer = Writer::facts(1);
    writer.append("boot.facts", "terminal", "op1", object(&[]));
    writer.append("boot.facts", "terminal", "op1", object(&[]));
    let head = writer.head(3).canonical();
    for output in cold_engines(
        &fixture,
        &cold_bundle(&writer).canonical(),
        Some(&pin),
        Some(&head),
    ) {
        assert_verdict(&output, 1, "UNCHECKED");
    }
}

fn nostr_binding_body(writer: &Writer) -> Value {
    nostr_binding_for_key(hex::encode(writer.key.verifying_key().to_bytes()))
}

fn nostr_binding_for_key(aura_key: String) -> Value {
    let node = nostr::SecretKey::from_bytes([1; 32]).unwrap();
    let agent = nostr::SecretKey::from_bytes([2; 32]).unwrap();
    let node_hex = hex::encode(node.public_key());
    let agent_hex = hex::encode(agent.public_key());
    let statement = object(&[
        ("domain", string("aukora:nostr-identity-binding:v1")),
        ("aura_key", string(&aura_key)),
        ("node", string(&node_hex)),
        ("agent", string(&agent_hex)),
    ]);
    let digest = hash(statement.canonical().as_bytes());
    object(&[
        ("schema", string("aukora-nostr-bind-v1")),
        (
            "node",
            object(&[
                ("pubkey", string(node_hex)),
                (
                    "npub",
                    string(nostr::npub_encode(&node.public_key()).unwrap()),
                ),
            ]),
        ),
        (
            "agent",
            object(&[
                ("pubkey", string(agent_hex)),
                (
                    "npub",
                    string(nostr::npub_encode(&agent.public_key()).unwrap()),
                ),
            ]),
        ),
        ("aura_key", string(aura_key)),
        ("statement_sha256", string(hex::encode(digest))),
        ("node_sig", string(hex::encode(node.sign(&digest).unwrap()))),
        (
            "agent_sig",
            string(hex::encode(agent.sign(&digest).unwrap())),
        ),
    ])
}

fn nostr_writer() -> Writer {
    let mut writer = Writer::facts(1);
    writer.append("nostr.bind", "fact", "", nostr_binding_body(&writer));
    writer
}

#[test]
fn antibody_nostr_cold_verifiers_accept_bound_identities() {
    let fixture = Fixture::new();
    let writer = nostr_writer();
    let pin = hex::encode(writer.key.verifying_key().to_bytes());
    let head = writer.head(2).canonical();
    for output in cold_engines(
        &fixture,
        &cold_bundle(&writer).canonical(),
        Some(&pin),
        Some(&head),
    ) {
        assert_verdict(&output, 0, "VERIFIED");
    }
}

#[test]
fn antibody_nostr_cold_verifiers_refuse_second_binding() {
    let fixture = Fixture::new();
    let mut writer = nostr_writer();
    writer.append("nostr.bind", "fact", "", nostr_binding_body(&writer));
    cold_refused(
        &fixture,
        cold_bundle(&writer),
        "verifier:nostr-second-binding",
    );
}

#[test]
fn antibody_nostr_cold_verifiers_refuse_wrong_aura_key() {
    let fixture = Fixture::new();
    let mut writer = nostr_writer();
    writer.rows[1].body = nostr_binding_for_key("00".repeat(32));
    writer.resign_from(1);
    cold_refused(&fixture, cold_bundle(&writer), "verifier:nostr-aura-key");
}

#[test]
fn antibody_nostr_cold_verifiers_refuse_node_signature() {
    let fixture = Fixture::new();
    let mut writer = nostr_writer();
    writer.rows[1].body.set("node_sig", string("00".repeat(64)));
    writer.resign_from(1);
    cold_refused(
        &fixture,
        cold_bundle(&writer),
        "verifier:nostr-node-signature",
    );
}

#[test]
fn antibody_nostr_cold_verifiers_refuse_agent_signature() {
    let fixture = Fixture::new();
    let mut writer = nostr_writer();
    writer.rows[1]
        .body
        .set("agent_sig", string("00".repeat(64)));
    writer.resign_from(1);
    cold_refused(
        &fixture,
        cold_bundle(&writer),
        "verifier:nostr-agent-signature",
    );
}

#[test]
fn antibody_nostr_cold_verifiers_recompute_statement() {
    let fixture = Fixture::new();
    let mut writer = nostr_writer();
    writer.rows[1]
        .body
        .set("statement_sha256", string("00".repeat(32)));
    writer.resign_from(1);
    cold_refused(&fixture, cold_bundle(&writer), "verifier:nostr-statement");
}

#[test]
fn antibody_nostr_cold_verifiers_refuse_mismatched_npub() {
    let fixture = Fixture::new();
    for role in ["node", "agent"] {
        let mut writer = nostr_writer();
        let Value::Object(body) = &mut writer.rows[1].body else {
            panic!("binding fixture body")
        };
        body.iter_mut()
            .find(|(key, _)| key == role)
            .unwrap()
            .1
            .set("npub", string("npub1wrong"));
        writer.resign_from(1);
        cold_refused(&fixture, cold_bundle(&writer), "verifier:nostr-npub");
    }
}

#[test]
fn antibody_nostr_cold_verifiers_refuse_binding_shape() {
    let fixture = Fixture::new();
    for variant in 0..4 {
        let mut writer = nostr_writer();
        match variant {
            0 => writer.rows[1].phase = "intent".into(),
            1 => writer.rows[1].body.set("schema", string("unknown-v2")),
            2 => writer.rows[1].body.set("extra", Value::Null),
            _ => {
                let Value::Object(body) = &mut writer.rows[1].body else {
                    panic!("binding fixture body")
                };
                body.iter_mut()
                    .find(|(key, _)| key == "node")
                    .unwrap()
                    .1
                    .set("extra", Value::Null);
            }
        }
        writer.resign_from(1);
        cold_refused(
            &fixture,
            cold_bundle(&writer),
            "verifier:nostr-binding-shape",
        );
    }
}

#[test]
fn antibody_nostr_cold_verifiers_refuse_noncanonical_encodings() {
    let fixture = Fixture::new();
    for role in ["node", "agent"] {
        for variant in 0..3 {
            let mut writer = nostr_writer();
            let Value::Object(body) = &mut writer.rows[1].body else {
                panic!("binding fixture body")
            };
            let signature = &mut body
                .iter_mut()
                .find(|(key, _)| key == &format!("{role}_sig"))
                .unwrap()
                .1;
            let Value::Str(text) = signature else {
                panic!("binding fixture signature")
            };
            match variant {
                0 => *text = text.to_uppercase(),
                1 => text.truncate(126),
                _ => text.push_str("00"),
            }
            writer.resign_from(1);
            cold_refused(
                &fixture,
                cold_bundle(&writer),
                &format!("verifier:nostr-{role}-signature"),
            );
        }
    }
    for name in ["aura_key", "statement_sha256"] {
        let mut writer = nostr_writer();
        let Value::Object(body) = &mut writer.rows[1].body else {
            panic!("binding fixture body")
        };
        let Value::Str(text) = &mut body.iter_mut().find(|(key, _)| key == name).unwrap().1 else {
            panic!("binding fixture digest")
        };
        *text = text.to_uppercase();
        writer.resign_from(1);
        cold_refused(&fixture, cold_bundle(&writer), "verifier:bad-digest");
    }
}

#[test]
fn antibody_nostr_python_passes_every_bip340_verification_vector() {
    let output = Command::new("python3")
        .arg("-B")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/nostr_python.py"))
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(
        output_text(&output).contains("BIP340 verification vectors: 19 passed"),
        "{}",
        output_text(&output)
    );
}

#[test]
fn antibody_cold_proof_accepts_large_canonical_unicode_and_signed_integers() {
    let fixture = Fixture::new();
    let mut writer = Writer::new();
    writer.append(
        "boot.facts",
        "fact",
        "",
        object(&[
            ("negative", Value::Int(-9_007_199_254_740_991)),
            (
                "unicode",
                object(&[
                    ("\u{e000}", string("\u{2028}\u{2029}\u{007f}")),
                    ("\u{10000}", string("🙂")),
                ]),
            ),
            ("padding", string("a".repeat(1_100_000))),
        ]),
    );
    let pin = hex::encode(writer.key.verifying_key().to_bytes());
    let head = writer.head(1).canonical();
    for output in cold_engines(
        &fixture,
        &cold_bundle(&writer).canonical(),
        Some(&pin),
        Some(&head),
    ) {
        assert_verdict(&output, 0, "VERIFIED");
    }
}

#[test]
fn antibody_cold_proof_cli_rejects_ambiguous_options() {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/verify.py");
    for args in [
        vec!["--bundle", "proof", "--rows", "rows"],
        vec!["--bundle", "proof", "--bundle", "other"],
        vec!["--bundle", "--key"],
        vec!["--bundle", "proof", "--unknown", "other"],
    ] {
        let native = Command::new(env!("CARGO_BIN_EXE_aukora-verify"))
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(native.status.code(), Some(64), "{}", output_text(&native));
        assert!(output_text(&native).contains("verifier:usage"));
        let python = Command::new("python3")
            .arg("-B")
            .arg(&script)
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(python.status.code(), Some(64), "{}", output_text(&python));
        assert!(
            output_text(&python).contains("verifier:usage"),
            "{}",
            output_text(&python)
        );
    }
}

fn witness_event(key: [u8; 32], kind: u64, tags: Vec<Vec<String>>, content: String) -> String {
    nostr::event::Event::sign(
        &nostr::SecretKey::from_bytes(key).unwrap(),
        1_760_000_000,
        kind,
        tags,
        content,
    )
    .unwrap()
    .to_json()
}

fn witness(head: &Value) -> String {
    witness_event(
        [1; 32],
        30078,
        vec![vec!["d".into(), "aukora-aura-head".into()]],
        head.canonical(),
    )
}

fn witness_check(proof: &str, event: &str, expected: Option<&str>) {
    let result = verifier::verify_witness(proof.as_bytes(), event.as_bytes());
    match expected {
        Some(code) => assert_eq!(result.unwrap_err(), code),
        None => assert!(result.is_ok(), "{result:?}"),
    }
    let fixture = Fixture::new();
    let proof = fixture.write("proof.json", proof);
    let event = fixture.write("event.json", event);
    let native = Command::new(env!("CARGO_BIN_EXE_aukora-verify"))
        .arg("witness")
        .arg(&proof)
        .arg(&event)
        .output()
        .unwrap();
    let python = Command::new("python3")
        .arg("-B")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/verify.py"))
        .arg("witness")
        .arg(&proof)
        .arg(&event)
        .output()
        .unwrap();
    assert_eq!(
        native.status.code(),
        Some(if expected.is_some() { 2 } else { 0 }),
        "{}",
        output_text(&native)
    );
    assert_eq!(
        native.status.code(),
        python.status.code(),
        "{}",
        output_text(&python)
    );
    assert_eq!(output_text(&native), output_text(&python));
}

#[test]
fn antibody_witness_accepts_matching_and_extended_proof_with_python_parity() {
    let mut writer = nostr_writer();
    let event = witness(&writer.head(2));
    witness_check(&cold_bundle(&writer).canonical(), &event, None);
    for index in 0..31 {
        writer.append(
            "boot.facts",
            "fact",
            "",
            object(&[("index", Value::Int(index))]),
        );
    }
    witness_check(&cold_bundle(&writer).canonical(), &event, None);
    for size in [1, 2, 3, 4, 8, 16, 32, 33] {
        witness_check(
            &cold_bundle(&writer).canonical(),
            &witness(&writer.head(size)),
            None,
        );
    }
}

#[test]
fn antibody_witness_refuses_fork_root_and_hash_with_python_parity() {
    let writer = nostr_writer();
    for name in ["root", "hash"] {
        let mut head = writer.head(2);
        head.set(name, string("00".repeat(32)));
        witness_check(
            &cold_bundle(&writer).canonical(),
            &witness(&head),
            Some("verifier:witness-fork"),
        );
    }
    let event = witness(&writer.head(2));
    let mut fork = writer;
    fork.rows[0].body = object(&[("fork", Value::Bool(true))]);
    fork.resign_from(0);
    witness_check(
        &cold_bundle(&fork).canonical(),
        &event,
        Some("verifier:witness-fork"),
    );
}

#[test]
fn antibody_witness_refuses_size_mismatch_with_python_parity() {
    let mut writer = nostr_writer();
    let mut head = writer.head(2);
    head.set("sequence", Value::Int(1));
    witness_check(
        &cold_bundle(&writer).canonical(),
        &witness(&head),
        Some("verifier:witness-size"),
    );
    for size in [0, -1] {
        head.set("sequence", Value::Int(size));
        head.set("treeSize", Value::Int(size));
        witness_check(
            &cold_bundle(&writer).canonical(),
            &witness(&head),
            Some("verifier:witness-size"),
        );
    }
    let original = cold_bundle(&writer).canonical();
    writer.append("boot.facts", "fact", "", object(&[]));
    witness_check(
        &original,
        &witness(&writer.head(3)),
        Some("verifier:witness-size"),
    );
}

#[test]
fn antibody_witness_refuses_wrong_signer_with_python_parity() {
    let writer = nostr_writer();
    for key in [[2; 32], [3; 32]] {
        let event = witness_event(
            key,
            30078,
            vec![vec!["d".into(), "aukora-aura-head".into()]],
            writer.head(2).canonical(),
        );
        witness_check(
            &cold_bundle(&writer).canonical(),
            &event,
            Some("verifier:witness-signer"),
        );
    }
}

#[test]
fn antibody_witness_requires_single_binding_with_python_parity() {
    let mut writer = Writer::facts(1);
    witness_check(
        &cold_bundle(&writer).canonical(),
        &witness(&writer.head(1)),
        Some("verifier:witness-binding"),
    );
    writer = nostr_writer();
    writer.append("nostr.bind", "fact", "", nostr_binding_body(&writer));
    witness_check(
        &cold_bundle(&writer).canonical(),
        &witness(&writer.head(3)),
        Some("verifier:witness-binding"),
    );
}

#[test]
fn antibody_witness_authenticates_proof_with_python_parity() {
    let mut writer = nostr_writer();
    let event = witness(&writer.head(2));
    writer.rows[0].body = object(&[("edited", Value::Bool(true))]);
    witness_check(
        &cold_bundle(&writer).canonical(),
        &event,
        Some("verifier:witness-proof"),
    );
    witness_check("{}", &event, Some("verifier:witness-proof"));
}

#[test]
fn antibody_witness_authenticates_event_id_and_signature_with_python_parity() {
    let writer = nostr_writer();
    let proof = cold_bundle(&writer).canonical();
    let event = nostr::event::Event::parse(witness(&writer.head(2)).as_bytes()).unwrap();
    let mut invalid_id = event.clone();
    invalid_id.id[0] ^= 1;
    invalid_id.sig = nostr::SecretKey::from_bytes([1; 32])
        .unwrap()
        .sign(&invalid_id.id)
        .unwrap();
    witness_check(
        &proof,
        &invalid_id.to_json(),
        Some("verifier:witness-malformed"),
    );
    let mut invalid_signature = event;
    invalid_signature.sig[0] ^= 1;
    witness_check(
        &proof,
        &invalid_signature.to_json(),
        Some("verifier:witness-malformed"),
    );
}

#[test]
fn antibody_witness_refuses_wrong_kind_or_tag_with_python_parity() {
    let writer = nostr_writer();
    for (kind, tags) in [
        (30079, vec![vec!["d".into(), "aukora-aura-head".into()]]),
        (30078, vec![vec!["d".into(), "other".into()]]),
        (30078, vec![]),
        (
            30078,
            vec![
                vec!["d".into(), "aukora-aura-head".into()],
                vec!["d".into(), "other".into()],
            ],
        ),
    ] {
        let event = witness_event([1; 32], kind, tags, writer.head(2).canonical());
        witness_check(
            &cold_bundle(&writer).canonical(),
            &event,
            Some("verifier:witness-malformed"),
        );
    }
}

#[test]
fn antibody_witness_refuses_malformed_inputs_with_python_parity() {
    let writer = nostr_writer();
    let proof = cold_bundle(&writer).canonical();
    for event in ["{}", "null", "{", "{\"id\":0,\"id\":0}"] {
        witness_check(&proof, event, Some("verifier:witness-malformed"));
    }
    let event = witness(&writer.head(2));
    let extra_field = format!("{},\"extra\":true}}", &event[..event.len() - 1]);
    witness_check(&proof, &extra_field, Some("verifier:witness-malformed"));
    let oversize = format!("{}{}", " ".repeat(65_536), event);
    witness_check(&proof, &oversize, Some("verifier:witness-malformed"));
    for (content, code) in [
        ("{}".to_owned(), "verifier:witness-size"),
        ("null".to_owned(), "verifier:witness-malformed"),
        ("{".to_owned(), "verifier:witness-malformed"),
        (
            format!(" {}", writer.head(2).canonical()),
            "verifier:witness-malformed",
        ),
    ] {
        let event = witness_event(
            [1; 32],
            30078,
            vec![vec!["d".into(), "aukora-aura-head".into()]],
            content,
        );
        witness_check(&proof, &event, Some(code));
    }
    let mut head = writer.head(2);
    head.set("schema", string("wrong"));
    witness_check(&proof, &witness(&head), Some("verifier:witness-malformed"));
}

fn witness_path_outputs(proof: &Path, event: &Path) -> Vec<Output> {
    use std::process::Stdio;
    use std::time::{Duration, Instant};
    let mut native = Command::new(env!("CARGO_BIN_EXE_aukora-verify"));
    let mut python = Command::new("python3");
    python
        .arg("-B")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/verify.py"));
    [&mut native, &mut python]
        .into_iter()
        .map(|command| {
            let mut child = command
                .arg("witness")
                .arg(proof)
                .arg(event)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let start = Instant::now();
            while child.try_wait().unwrap().is_none() {
                if start.elapsed() > Duration::from_secs(3) {
                    child.kill().unwrap();
                    child.wait().unwrap();
                    panic!("witness CLI blocked on input admission");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            child.wait_with_output().unwrap()
        })
        .collect()
}

#[test]
fn antibody_witness_cli_refuses_nonregular_and_oversize_with_python_parity() {
    let fixture = Fixture::new();
    let writer = nostr_writer();
    let proof = fixture.write("proof.json", cold_bundle(&writer).canonical());
    let event = fixture.write("event.json", witness(&writer.head(2)));
    let too_large_proof = fixture.path.join("oversize-proof.json");
    fs::File::create(&too_large_proof)
        .unwrap()
        .set_len(8_388_609)
        .unwrap();
    let too_large_event = fixture.path.join("oversize-event.json");
    fs::File::create(&too_large_event)
        .unwrap()
        .set_len(65_537)
        .unwrap();
    let missing = fixture.path.join("missing.json");
    let mut cases = vec![
        (
            fixture.path.clone(),
            event.clone(),
            "verifier:witness-unreadable",
        ),
        (
            proof.clone(),
            fixture.path.clone(),
            "verifier:witness-unreadable",
        ),
        (
            missing.clone(),
            event.clone(),
            "verifier:witness-unreadable",
        ),
        (proof.clone(), missing, "verifier:witness-unreadable"),
        (
            too_large_proof,
            event.clone(),
            "verifier:witness-unreadable",
        ),
        (proof.clone(), too_large_event, "verifier:witness-malformed"),
    ];
    #[cfg(unix)]
    {
        let fifo = fixture.path.join("input.fifo");
        assert!(Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        cases.push((fifo.clone(), event.clone(), "verifier:witness-unreadable"));
        cases.push((proof.clone(), fifo, "verifier:witness-unreadable"));
        cases.push((
            PathBuf::from("/dev/null"),
            event,
            "verifier:witness-unreadable",
        ));
        cases.push((
            proof,
            PathBuf::from("/dev/null"),
            "verifier:witness-unreadable",
        ));
    }
    for (proof, event, code) in cases {
        let outputs = witness_path_outputs(&proof, &event);
        for output in &outputs {
            assert_eq!(output.status.code(), Some(2), "{}", output_text(output));
            assert_eq!(output_text(output), format!("REFUSED {code}\n"));
        }
    }
}

fn cold_cli_outputs(arguments: &[PathBuf]) -> Vec<Output> {
    let mut native = Command::new(env!("CARGO_BIN_EXE_aukora-verify"));
    let mut python = Command::new("python3");
    python
        .arg("-B")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/verify.py"));
    [&mut native, &mut python]
        .into_iter()
        .map(|command| command.args(arguments).output().unwrap())
        .collect()
}

// #55: Admission errors retain their actual row and preserve earlier evidence failures.
#[test]
fn antibody_issue55_bundle_admission_reports_actual_row_with_python_parity() {
    let fixture = Fixture::new();
    for (field, replacement, code) in [
        ("extra", Value::Null, "verifier:row-columns"),
        ("seq", Value::Int(2), "verifier:sequence"),
        ("hash", string("bad"), "verifier:bad-digest"),
        ("actor", Value::Int(2), "verifier:bundle-row-schema"),
        ("kind", Value::Int(2), "verifier:bundle-row-schema"),
        ("kind", string("unknown.kind"), "verifier:bundle-row-schema"),
        ("phase", Value::Array(vec![]), "verifier:bundle-row-schema"),
    ] {
        let writer = Writer::facts(4);
        let mut rows: Vec<Value> = writer.rows.iter().map(Row::value).collect();
        rows[2].set(field, replacement);
        let mut bundle = cold_bundle(&writer);
        bundle.set("rows", Value::Array(rows));
        for output in cold_engines(&fixture, &bundle.canonical(), None, None) {
            assert_bad_sequence(&output, "REWRITTEN", 3);
            let text = output_text(&output);
            assert!(text.contains("REWRITTEN first bad seq 3"), "{text}");
            assert!(text.contains(code), "{text}");
            assert!(!text.contains("FORGED"), "{text}");
        }
    }
    let mut writer = Writer::facts(4);
    writer.rows[0].signature = base64(&[0; 64]);
    let mut rows: Vec<Value> = writer.rows.iter().map(Row::value).collect();
    rows[2].set("extra", Value::Null);
    let mut bundle = cold_bundle(&writer);
    bundle.set("rows", Value::Array(rows));
    for output in cold_engines(&fixture, &bundle.canonical(), None, None) {
        assert_bad_sequence(&output, "FORGED", 1);
    }
}

// #55: Operator input failures cannot accuse a signer or identify a rewritten row.
#[test]
fn antibody_issue55_operator_errors_are_unchecked64_with_python_parity() {
    let fixture = Fixture::new();
    let writer = Writer::facts(4);
    let bundle = fixture.write("valid.json", cold_bundle(&writer).canonical());
    let missing = fixture.path.join("missing");
    let mut cases = vec![
        vec![],
        vec!["--unknown".into()],
        vec!["--bundle".into()],
        vec!["--bundle".into(), missing.clone()],
        vec!["--bundle".into(), fixture.path.clone()],
        vec![
            "--bundle".into(),
            bundle.clone(),
            "--key".into(),
            missing.clone(),
        ],
        vec![
            "--bundle".into(),
            bundle.clone(),
            "--checkpoint".into(),
            missing,
        ],
    ];
    for (index, raw) in [
        b"invalid".as_slice(),
        b"00",
        b"gggg",
        b"\xff",
        b"0100000000000000000000000000000000000000000000000000000000000000",
        b"0200000000000000000000000000000000000000000000000000000000000000",
    ]
    .into_iter()
    .enumerate()
    {
        let pin = fixture.write(&format!("pin-{index}"), raw);
        cases.push(vec!["--bundle".into(), bundle.clone(), "--key".into(), pin]);
    }
    for (index, raw) in [
        b"\xff".as_slice(),
        b"{",
        b"{}",
        b"null",
        b"[]",
        b"{\"schema\":0,\"schema\":0}",
    ]
    .into_iter()
    .enumerate()
    {
        let invalid = fixture.write(&format!("bundle-{index}"), raw);
        cases.push(vec!["--bundle".into(), invalid]);
        let invalid = fixture.write(&format!("checkpoint-{index}"), raw);
        cases.push(vec![
            "--bundle".into(),
            bundle.clone(),
            "--checkpoint".into(),
            invalid,
        ]);
    }
    for arguments in cases {
        for output in cold_cli_outputs(&arguments) {
            assert_verdict(&output, 64, "UNCHECKED");
            let text = output_text(&output);
            assert!(
                !text.contains("FORGED") && !text.contains("REWRITTEN"),
                "args={arguments:?}: {text}"
            );
        }
    }
}

// #55: Only actual key and signature mismatches earn a forgery verdict.
#[test]
fn antibody_issue55_forgery_names_key_or_signature_with_python_parity() {
    let fixture = Fixture::new();
    let mut writer = Writer::facts(4);
    let wrong = hex::encode(SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes());
    for output in cold_engines(
        &fixture,
        &cold_bundle(&writer).canonical(),
        Some(&wrong),
        None,
    ) {
        assert_verdict(&output, 2, "FORGED key mismatch");
        let text = output_text(&output);
        assert!(text.contains("verifier:bundle-key-mismatch"), "{text}");
        assert!(
            !text.contains("bad signature") && !text.contains("seq="),
            "{text}"
        );
    }
    writer.rows[2].signature = base64(&[0; 64]);
    for output in cold_engines(&fixture, &cold_bundle(&writer).canonical(), None, None) {
        assert_bad_sequence(&output, "FORGED", 3);
        assert!(output_text(&output).contains("FORGED bad signature at seq 3"));
    }
}
