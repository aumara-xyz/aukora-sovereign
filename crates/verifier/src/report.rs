// SPDX-License-Identifier: AGPL-3.0-or-later
//! Reports separate arithmetic integrity from independently retained observations.

use canon::Refusal;

/// An observation about the supplied bytes, never authorization to execute them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verdict {
    /// All required checks, including independent key and covering checkpoint, passed.
    Verified,
    /// A retained observation conflicts with the supplied chain.
    Rewritten,
    /// A row signature fails cryptographic verification.
    Forged,
    /// The supplied independent key differs from the export's claimed key.
    KeyMismatch,
    /// The bytes cannot be admitted under the selected schema.
    InvalidInput,
    /// Required checks or independent observations are missing.
    Unchecked,
}

impl Verdict {
    /// Only complete verification can yield the success exit code.
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::Verified => 0,
            Self::Unchecked => 1,
            Self::Rewritten | Self::Forged | Self::KeyMismatch => 2,
            Self::InvalidInput => 64,
        }
    }
}

/// Missing scope is represented explicitly and cannot be inferred from other checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scope {
    /// This property was not established from the supplied bytes.
    Unchecked,
    /// This property was established within the report's supplied observations.
    Checked,
}

/// Integrity properties, without independent identity or completeness claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntegrityScope {
    /// Node signature verification over each entry's raw hash bytes.
    pub signatures: Scope,
    /// Contiguous sequences, predecessor links and recomputed entry hashes.
    pub chain: Scope,
    /// The recomputed RFC 6962 root and the export's claimed tail.
    pub tree_root: Scope,
    /// C5 owner authorization binding data contained in the rows.
    pub owner_bindings: Scope,
}

/// Claims about observations supplied independently from the export.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservationScope {
    /// The export key matched the caller's retained key.
    pub pinned_identity: Scope,
    /// An independently retained head covered the complete claimed tail.
    pub covering_checkpoint: Scope,
    /// The earlier and later observations were consistent.
    pub consistency: Scope,
}

/// A stable refusal and optional row location, with no executable content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Finding {
    /// The verifier or underlying codec refusal.
    pub code: Refusal,
    /// A one-based row number, when attributable to a row.
    pub sequence: Option<u64>,
    /// False means the first changed row was not located from retained rows.
    pub exact_location: bool,
}

/// No public constructor can manufacture a positive verifier result.
#[derive(Clone, Debug)]
pub struct VerificationReport {
    verdict: Verdict,
    rows: u64,
    integrity: IntegrityScope,
    observations: ObservationScope,
    findings: Vec<Finding>,
}

impl VerificationReport {
    /// Overall verification outcome; an embedded head alone never fills missing scope.
    pub const fn verdict(&self) -> Verdict {
        self.verdict
    }

    /// Number of rows covered by this report.
    pub const fn rows(&self) -> u64 {
        self.rows
    }

    /// Scope for node signatures, chain links, tree root and owner binding data.
    pub const fn integrity(&self) -> IntegrityScope {
        self.integrity
    }

    /// Scope for independently pinned identity, covering checkpoint and consistency.
    pub const fn observations(&self) -> ObservationScope {
        self.observations
    }

    /// Findings are returned as data; they do not become authority.
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }
}

impl VerificationReport {
    pub(crate) fn new(rows: u64) -> Self {
        Self {
            verdict: Verdict::Unchecked,
            rows,
            integrity: IntegrityScope {
                signatures: Scope::Unchecked,
                chain: Scope::Unchecked,
                tree_root: Scope::Unchecked,
                owner_bindings: Scope::Unchecked,
            },
            observations: ObservationScope {
                pinned_identity: Scope::Unchecked,
                covering_checkpoint: Scope::Unchecked,
                consistency: Scope::Unchecked,
            },
            findings: Vec::new(),
        }
    }

    pub(crate) fn scopes(&mut self, integrity: IntegrityScope, observations: ObservationScope) {
        self.integrity = integrity;
        self.observations = observations;
        if !matches!(self.verdict, Verdict::Verified | Verdict::Unchecked) {
            return;
        }
        self.verdict = if integrity.signatures == Scope::Checked
            && integrity.chain == Scope::Checked
            && integrity.tree_root == Scope::Checked
            && integrity.owner_bindings == Scope::Checked
            && observations.pinned_identity == Scope::Checked
            && observations.covering_checkpoint == Scope::Checked
            && self.findings.is_empty()
        {
            Verdict::Verified
        } else {
            Verdict::Unchecked
        };
    }

    pub(crate) fn finding(
        &mut self,
        verdict: Verdict,
        code: Refusal,
        sequence: Option<u64>,
        exact_location: bool,
    ) {
        self.findings.push(Finding {
            code,
            sequence,
            exact_location,
        });
        let rank = |v| match v {
            Verdict::Verified => 0,
            Verdict::Unchecked => 1,
            Verdict::Rewritten => 2,
            Verdict::Forged => 3,
            Verdict::KeyMismatch => 4,
            Verdict::InvalidInput => 5,
        };
        if rank(verdict) > rank(self.verdict) {
            self.verdict = verdict;
        }
    }
}

use crate::{
    format::{
        array, canonical, digest, field, hex32, hex_bytes, keys, object, refusal, text, uint,
    },
    Row,
};
use canon::{
    json::{Value, ValueView},
    Result,
};

pub(crate) fn owner_binding(rows: &[Row], row: &Value) -> Result<bool> {
    let body = field(row, "body")?;
    if let Some(auth) = body.get("auth") {
        owner_authorization(auth, false)?;
        if let Some(recorded) = body.get("authorization_digest") {
            owner_require(
                owner_digest(auth) == hex32(text(recorded)?)?,
                "authorization-digest",
            )?;
        }
        return Ok(false);
    }
    if text(field(row, "kind")?)? == "gate.consume" {
        if body.get("authorization").is_none() {
            return Ok(false);
        }
        return owner_consumption(rows, row).map(|(_, semantic)| semantic);
    }
    let Some(receipt) = body.get("receipt") else {
        return Ok(false);
    };
    owner_require(text(field(row, "phase")?)? == "terminal", "gate-evidence")?;
    let operation = text(field(row, "op")?)?;
    let reference = field(receipt, "owner_consumption")?;
    let consumed = owner_reference(
        rows,
        reference,
        uint(field(row, "seq")?)?,
        "gate.consume",
        operation,
    )?;
    let (auth, semantic) = owner_consumption(rows, consumed)?;
    let consumed_body = field(consumed, "body")?;
    owner_require(
        uint(field(receipt, "v")?)? == 3 && text(field(receipt, "kind")?)? == "change",
        "gate-evidence",
    )?;
    for name in ["proposal", "target", "node", "base_sha256", "new_sha256"] {
        owner_require(field(receipt, name)? == field(auth, name)?, "gate-evidence")?;
    }
    owner_require(
        field(receipt, "approver")? == field(auth, "subject")?,
        "gate-evidence",
    )?;
    let review = owner_reference(
        rows,
        field(reference, "review_issue")?,
        uint(field(consumed, "seq")?)?,
        "gate.review",
        operation,
    )?;
    let consumed_review = field(consumed_body, "review_issue")?;
    for name in ["seq", "hash"] {
        owner_require(
            field(review, name)? == field(consumed_review, name)?,
            "gate-evidence",
        )?;
    }
    let authority = field(receipt, "owner_authorization")?;
    owner_require(
        uint(field(authority, "version")?)? == 1
            && text(field(authority, "kind")?)? == "aukora-owner-authorization-ref/v1"
            && field(authority, "proof_sha256")? == field(consumed_body, "proof_sha256")?,
        "gate-evidence",
    )?;
    let authority_digest = if consumed_body.get("standing_permission").is_some() {
        owner_require(
            receipt.get("standing_permission") == consumed_body.get("standing_permission")
                && field(receipt, "applied_at")? == field(row, "at")?,
            "gate-evidence",
        )?;
        owner_standing(
            rows,
            consumed,
            uint(field(row, "at")?)?,
            uint(field(row, "seq")?)?,
        )?
    } else {
        owner_require(
            receipt
                .get("standing_permission")
                .is_none_or(|v| matches!(v.view(), ValueView::Null)),
            "gate-evidence",
        )?;
        field(consumed_body, "authorization_sha256")?
    };
    for name in ["authorization_id", "authorization_sha256"] {
        owner_require(field(authority, name)? == authority_digest, "gate-evidence")?;
    }
    Ok(semantic)
}

fn owner_require(condition: bool, reason: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(refusal(reason))
    }
}

fn owner_digest(auth: &Value) -> [u8; 32] {
    let mut input = b"aukora:owner-authorization:v1\0".to_vec();
    input.extend(auth.canonical_bytes());
    digest(&input)
}

fn owner_authorization(auth: &Value, current: bool) -> Result<()> {
    let required = [
        "v",
        "node",
        "subject",
        "op",
        "proposal",
        "target",
        "base_sha256",
        "new_sha256",
        "cell",
        "display_sha256",
        "challenge",
        "expires_at",
    ];
    let metadata = [
        "epoch",
        "operation",
        "owner_epoch",
        "owner_root_id",
        "binding_sha256",
        "issued_at",
        "issued_at_ms",
        "gate",
        "pubkey_fp",
    ];
    let ValueView::Object(members) = auth.view() else {
        return Err(refusal("authorization-shape"));
    };
    owner_require(
        required.iter().all(|name| auth.get(name).is_some())
            && members.iter().all(|(name, _)| {
                required.contains(&name.as_str()) || metadata.contains(&name.as_str())
            })
            && (!current || auth.get("epoch").is_some() && auth.get("operation").is_some())
            && auth.get("epoch").is_some() == auth.get("operation").is_some(),
        "authorization-shape",
    )?;
    owner_require(uint(field(auth, "v")?)? == 1, "authorization-shape")?;
    for name in ["node", "proposal", "challenge"] {
        hex_bytes::<16>(text(field(auth, name)?)?)?;
    }
    hex32(
        text(field(auth, "subject")?)?
            .strip_prefix("aukora:1:")
            .ok_or(refusal("authorization-shape"))?,
    )?;
    owner_require(
        ["apply", "retire", "release", "grant", "permission"].contains(&text(field(auth, "op")?)?)
            && !text(field(auth, "target")?)?.is_empty(),
        "authorization-shape",
    )?;
    for name in ["new_sha256", "display_sha256"] {
        hex32(text(field(auth, name)?)?)?;
    }
    let base = text(field(auth, "base_sha256")?)?;
    if base != "absent" {
        hex32(base)?;
    }
    let expiry = uint(field(auth, "expires_at")?)?;
    owner_require(expiry > 0, "authorization-shape")?;
    let cell = field(auth, "cell")?;
    if !matches!(cell.view(), ValueView::Null) {
        keys(cell, &["module_sha256", "input_sha256", "effect_sha256"])?;
        for name in ["module_sha256", "input_sha256", "effect_sha256"] {
            hex32(text(field(cell, name)?)?)?;
        }
    }
    if let Some(epoch) = auth.get("epoch") {
        owner_require(uint(epoch)? > 0, "authorization-shape")?;
        if let Some(retained) = auth.get("owner_epoch") {
            owner_require(retained == epoch, "gate-evidence")?;
        }
        let fields = ["v", "node", "target", "base_sha256", "new_sha256", "cell"];
        let members = fields
            .iter()
            .map(|name| Ok((*name, field(auth, name)?.clone())))
            .collect::<Result<Vec<_>>>()?;
        let mut content = b"aukora:operation-content:v1\0".to_vec();
        content.extend(object(members)?.canonical_bytes());
        owner_require(
            digest(&content) == hex32(text(field(auth, "operation")?)?)?,
            "operation-digest",
        )?;
    }
    for name in ["owner_root_id", "binding_sha256", "gate"] {
        if let Some(value) = auth.get(name) {
            hex32(text(value)?)?;
        }
    }
    if let (Some(root), Some(binding)) = (auth.get("owner_root_id"), auth.get("binding_sha256")) {
        owner_require(root == binding, "gate-evidence")?;
    }
    for name in ["issued_at", "issued_at_ms"] {
        if let Some(value) = auth.get(name) {
            owner_require(uint(value)? > 0 && uint(value)? < expiry, "gate-evidence")?;
        }
    }
    if let (Some(first), Some(second)) = (auth.get("issued_at"), auth.get("issued_at_ms")) {
        owner_require(first == second, "gate-evidence")?;
    }
    if let Some(fingerprint) = auth.get("pubkey_fp") {
        owner_require(
            text(fingerprint)? == &text(field(auth, "gate")?)?[..16],
            "gate-evidence",
        )?;
    }
    Ok(())
}

fn owner_reference<'a>(
    rows: &'a [Row],
    reference: &Value,
    before: u64,
    kind: &str,
    operation: &str,
) -> Result<&'a Value> {
    let sequence = uint(field(reference, "seq")?)?;
    owner_require(sequence > 0 && sequence < before, "gate-reference")?;
    let position = usize::try_from(sequence - 1).map_err(|_| refusal("gate-reference"))?;
    let found = &rows.get(position).ok_or(refusal("gate-reference"))?.value;
    owner_require(
        uint(field(found, "seq")?)? == sequence
            && field(found, "hash")? == field(reference, "hash")?
            && text(field(found, "kind")?)? == kind
            && text(field(found, "op")?)? == operation,
        "gate-evidence",
    )?;
    for (alias, name) in [("ledger_seq", "seq"), ("ledger_hash", "hash")] {
        if let Some(value) = reference.get(alias) {
            owner_require(value == field(found, name)?, "gate-evidence")?;
        }
    }
    Ok(found)
}

fn owner_consumption<'a>(rows: &'a [Row], row: &'a Value) -> Result<(&'a Value, bool)> {
    owner_require(text(field(row, "phase")?)? == "settle", "gate-evidence")?;
    let body = field(row, "body")?;
    let auth = field(body, "authorization")?;
    owner_authorization(auth, true)?;
    let operation = text(field(row, "op")?)?;
    owner_require(
        ["apply", "release", "grant", "permission"].contains(&text(field(auth, "op")?)?)
            && text(field(auth, "proposal")?)? == operation
            && matches!(field(body, "spent")?.view(), ValueView::Boolean(true)),
        "gate-evidence",
    )?;
    owner_require(
        owner_digest(auth) == hex32(text(field(body, "authorization_sha256")?)?)?,
        "authorization-digest",
    )?;
    let standing = body.get("standing_permission").is_some();
    if !standing {
        let proof = text(field(body, "proof_hex")?)?;
        owner_require(
            !proof.is_empty()
                && proof.len().is_multiple_of(2)
                && proof
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "gate-evidence",
        )?;
        let bytes = hex::decode(proof).map_err(|_| refusal("gate-evidence"))?;
        owner_require(
            digest(&bytes) == hex32(text(field(body, "proof_sha256")?)?)?,
            "gate-evidence",
        )?;
    }
    let review = owner_reference(
        rows,
        field(body, "review_issue")?,
        uint(field(row, "seq")?)?,
        "gate.review",
        operation,
    )?;
    let reviewed = field(review, "body")?;
    owner_require(
        text(field(review, "phase")?)? == "fact"
            && field(reviewed, "authorization")? == auth
            && field(reviewed, "owner_state")? == field(body, "owner_state")?,
        "gate-evidence",
    )?;
    let owner = field(reviewed, "owner_state")?;
    owner_require(
        field(owner, "subject")? == field(auth, "subject")?
            && field(owner, "epoch")? == field(auth, "epoch")?,
        "gate-evidence",
    )?;
    if let Some(binding) = auth.get("binding_sha256") {
        owner_require(field(owner, "binding_sha256")? == binding, "gate-evidence")?;
    }
    owner_card(auth, field(reviewed, "card")?)?;
    let mut proposal = None;
    let mut consumptions = 0;
    let review_sequence = uint(field(review, "seq")?)?;
    for entry in rows {
        let value = &entry.value;
        if text(field(value, "op")?)? != operation {
            continue;
        }
        let kind = text(field(value, "kind")?)?;
        if kind == "gate.consume" {
            consumptions += 1;
        }
        if kind == "gate.propose"
            && text(field(value, "phase")?)? == "intent"
            && uint(field(value, "seq")?)? < review_sequence
        {
            owner_require(proposal.is_none(), "gate-evidence")?;
            proposal = Some(field(value, "body")?);
        }
    }
    owner_require(consumptions == 1, "gate-evidence")?;
    let proposed = proposal.ok_or(refusal("gate-evidence"))?;
    for name in ["target", "base_sha256", "new_sha256"] {
        owner_require(
            field(proposed, name)? == field(auth, name)?,
            "gate-evidence",
        )?;
    }
    owner_require(
        field(proposed, "digest")? == field(auth, "operation")?,
        "gate-evidence",
    )?;
    if standing {
        owner_standing(
            rows,
            row,
            uint(field(row, "at")?)?,
            uint(field(row, "seq")?)?,
        )?;
    }
    // These relations establish signed ledger evidence, never a passkey capability.
    Ok((auth, true))
}

fn owner_standing<'a>(
    rows: &'a [Row],
    consumed: &'a Value,
    at: u64,
    before: u64,
) -> Result<&'a Value> {
    let body = field(consumed, "body")?;
    let auth = field(body, "authorization")?;
    let reference = field(body, "standing_permission")?;
    keys(
        reference,
        &[
            "v",
            "proposal",
            "authorization_sha256",
            "proof_sha256",
            "consume",
            "kind",
        ],
    )
    .map_err(|_| refusal("standing-reference"))?;
    owner_require(
        uint(field(reference, "v")?)? == 1 && body.get("proof_hex").is_none(),
        "standing-reference",
    )?;
    let proposal = text(field(reference, "proposal")?)?;
    let sequence = uint(field(consumed, "seq")?)?;
    let original = owner_reference(
        rows,
        field(reference, "consume")?,
        sequence,
        "gate.consume",
        proposal,
    )
    .map_err(|_| refusal("standing-reference"))?;
    let approved = field(original, "body")?;
    let original_auth = field(approved, "authorization")?;
    owner_require(
        approved.get("standing_permission").is_none()
            && text(field(original_auth, "target")?)? == "gate/permission"
            && text(field(original_auth, "op")?)? == "permission",
        "standing-permission",
    )?;
    let (permission_auth, checked) = owner_consumption(rows, original)?;
    owner_require(
        checked
            && field(reference, "authorization_sha256")?
                == field(approved, "authorization_sha256")?
            && field(reference, "proof_sha256")? == field(approved, "proof_sha256")?
            && field(body, "proof_sha256")? == field(approved, "proof_sha256")?,
        "standing-reference",
    )?;
    owner_require(
        field(body, "owner_state")? == field(approved, "owner_state")?
            && field(auth, "node")? == field(permission_auth, "node")?,
        "standing-owner",
    )?;
    let original_sequence = uint(field(original, "seq")?)?;
    let mut application = None;
    let mut latest_permission = None;
    let mut uses = 0;
    for entry in rows {
        let row = &entry.value;
        let number = uint(field(row, "seq")?)?;
        let kind = text(field(row, "kind")?)?;
        if kind == "gate.apply"
            && text(field(row, "op")?)? == proposal
            && number > original_sequence
            && number < sequence
        {
            owner_require(application.is_none(), "standing-permission")?;
            application = Some(row);
        }
        if kind == "gate.consume" {
            let record = field(row, "body")?;
            if number < before
                && record
                    .get("authorization")
                    .and_then(|v| v.get("target"))
                    .is_some_and(|v| text(v).is_ok_and(|s| s == "gate/permission"))
            {
                latest_permission = Some(number);
            }
            if number <= sequence
                && record
                    .get("standing_permission")
                    .and_then(|v| v.get("proposal"))
                    == reference.get("proposal")
            {
                uses += 1;
            }
        }
    }
    owner_require(
        owner_binding(rows, application.ok_or(refusal("standing-permission"))?)?,
        "standing-permission",
    )?;
    owner_require(
        latest_permission == Some(original_sequence),
        "standing-revoked",
    )?;
    let review = owner_reference(
        rows,
        field(approved, "review_issue")?,
        original_sequence,
        "gate.review",
        proposal,
    )?;
    let permission_bytes = text(field(
        field(field(field(review, "body")?, "card")?, "from_to")?,
        "new",
    )?)?
    .as_bytes();
    let permission =
        owner_permission(permission_bytes).map_err(|_| refusal("standing-permission"))?;
    owner_require(
        text(field(&permission, "mode")?)? != "ask"
            && text(field(auth, "op")?)? == "apply"
            && array(field(&permission, "targets")?)?
                .iter()
                .any(|target| Some(target) == auth.get("target"))
            && text(field(reference, "kind")?)? == "put",
        "standing-scope",
    )?;
    let expiry = uint(field(&permission, "expires_at")?)?;
    owner_require(
        at < expiry
            && at < uint(field(auth, "expires_at")?)?
            && uint(field(auth, "expires_at")?)? <= expiry,
        "standing-expired",
    )?;
    owner_require(
        uses <= uint(field(&permission, "max_count")?)?,
        "standing-count",
    )?;
    let current_review = owner_reference(
        rows,
        field(body, "review_issue")?,
        sequence,
        "gate.review",
        text(field(consumed, "op")?)?,
    )?;
    let card = field(field(current_review, "body")?, "card")?;
    let base = field(field(card, "from_to")?, "base")?;
    owner_require(
        text(field(card, "risk")?)? == "routine"
            && (matches!(base.view(), ValueView::Null)
                || text(base).is_ok_and(|s| s.len() <= 65_536)),
        "standing-scope",
    )?;
    field(reference, "authorization_sha256")
}

fn owner_permission(bytes: &[u8]) -> Result<Value> {
    owner_require(
        bytes.len() <= 4096 && bytes.iter().all(|byte| (0x20..=0x7e).contains(byte)),
        "standing-permission",
    )?;
    let value = canonical(bytes)?;
    keys(
        &value,
        &[
            "v",
            "mode",
            "targets",
            "kinds",
            "max_count",
            "expires_at",
            "nonce",
        ],
    )?;
    let targets = array(field(&value, "targets")?)?;
    let kinds = array(field(&value, "kinds")?)?;
    let mode = text(field(&value, "mode")?)?;
    let count = uint(field(&value, "max_count")?)?;
    owner_require(
        uint(field(&value, "v")?)? == 1
            && ["ask", "risky", "limits"].contains(&mode)
            && targets.len() <= 32
            && kinds.len() == 1
            && text(&kinds[0])? == "put"
            && count <= 1_000_000
            && uint(field(&value, "expires_at")?)? > 0,
        "standing-permission",
    )?;
    hex_bytes::<16>(text(field(&value, "nonce")?)?)?;
    owner_require(
        if mode == "ask" {
            targets.is_empty() && count == 0
        } else {
            !targets.is_empty() && count > 0
        },
        "standing-permission",
    )?;
    for target in targets {
        let target = text(target)?;
        let parts = target.split('/').collect::<Vec<_>>();
        let lower = target.to_ascii_lowercase();
        let protected = [
            "release",
            "broker",
            "grant",
            "floor",
            "identity",
            "aumlok",
            "gate",
            "slider",
            "permission",
        ];
        let extensions = ["js", "mjs", "cjs", "ts", "sh", "py", "node", "so"];
        owner_require(
            target.encode_utf16().count() <= 200
                && !target.contains('\\')
                && target.chars().all(|c| c > '\u{1f}' && c != '\u{7f}')
                && parts.len() >= 3
                && parts[0] == "plugins"
                && parts
                    .iter()
                    .all(|part| !part.is_empty() && *part != "." && *part != "..")
                && !lower
                    .split(['/', '.', '_', '-'])
                    .any(|part| protected.contains(&part))
                && !extensions.contains(&lower.rsplit('.').next().unwrap_or("")),
            "standing-permission",
        )?;
    }
    Ok(value)
}

fn owner_card(auth: &Value, card: &Value) -> Result<()> {
    keys(
        card,
        &["v", "risk", "says", "facts", "from_to", "model_note"],
    )?;
    owner_require(
        uint(field(card, "v")?)? == 1
            && ["routine", "critical"].contains(&text(field(card, "risk")?)?)
            && !text(field(card, "says")?)?.contains(['\r', '\n']),
        "gate-evidence",
    )?;
    text(field(card, "model_note")?)?;
    for fact in array(field(card, "facts")?)? {
        let pair = array(fact)?;
        owner_require(pair.len() == 2, "gate-evidence")?;
        text(&pair[0])?;
    }
    owner_require(
        digest(&card.canonical_bytes()) == hex32(text(field(auth, "display_sha256")?)?)?,
        "gate-evidence",
    )?;
    let change = field(card, "from_to")?;
    let replacement = text(field(change, "new")?)?.as_bytes();
    owner_require(
        digest(replacement) == hex32(text(field(auth, "new_sha256")?)?)?,
        "gate-evidence",
    )?;
    let base = field(change, "base")?;
    let expected_base = text(field(auth, "base_sha256")?)?;
    match base.view() {
        ValueView::Null => owner_require(expected_base == "absent", "gate-evidence")?,
        ValueView::Text(bytes) => owner_require(
            digest(bytes.as_bytes()) == hex32(expected_base)?,
            "gate-evidence",
        )?,
        _ => return Err(refusal("gate-evidence")),
    }
    let cell = field(auth, "cell")?;
    if !matches!(cell.view(), ValueView::Null) {
        owner_require(
            text(field(cell, "module_sha256")?)?
                == "34ce6cab618b626243e876befb49ccf8a6780dc836e757484886b34ae977a438"
                && digest(replacement) == hex32(text(field(cell, "effect_sha256")?)?)?,
            "cell-effect",
        )?;
        let input = replacement
            .strip_suffix(b"\n")
            .ok_or(refusal("cell-effect"))?;
        owner_require(
            digest(input) == hex32(text(field(cell, "input_sha256")?)?)?,
            "cell-effect",
        )?;
        let arguments = canonical(input).map_err(|_| refusal("cell-effect"))?;
        keys(&arguments, &["key", "value"]).map_err(|_| refusal("cell-effect"))?;
        let key = text(field(&arguments, "key")?)?.as_bytes();
        owner_require(
            !key.is_empty()
                && key.len() <= 128
                && key[0].is_ascii_alphanumeric()
                && key[1..]
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(b))
                && key.len() + field(&arguments, "value")?.canonical_bytes().len() <= 65_536,
            "cell-effect",
        )?;
    }
    Ok(())
}
