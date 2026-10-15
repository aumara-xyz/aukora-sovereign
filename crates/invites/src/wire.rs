// SPDX-License-Identifier: AGPL-3.0-or-later
//! Closed, canonical content schemas and bounded signed ancestry.

use super::*;
use std::collections::BTreeSet;

/// Original archive content, retained as signed evidence only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyStatement {
    pub schema: String,
    pub root: PublicKey,
    pub inviter_npub: String,
    pub invitee_label: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub code: [u8; 16],
    pub claim_sha256: Digest32,
}

impl LegacyStatement {
    pub fn decode(event: &Event) -> Result<Self> {
        let body = event_body(event, INVITE_KIND)?;
        fields(
            &body,
            &[
                "schema",
                "root",
                "inviter_npub",
                "invitee_label",
                "issued_at",
                "expires_at",
                "code",
                "claim_sha256",
            ],
        )?;
        let root = PublicKey::from_npub(string(&body, "root")?)?;
        let result = Self {
            schema: string(&body, "schema")?.into(),
            root,
            inviter_npub: string(&body, "inviter_npub")?.into(),
            invitee_label: string(&body, "invitee_label")?.into(),
            issued_at: number(&body, "issued_at")?,
            expires_at: number(&body, "expires_at")?,
            code: code(&body, "code")?,
            claim_sha256: digest(&body, "claim_sha256")?,
        };
        if result.schema != "aukora-node-invite-v1"
            || PublicKey::from_npub(&result.inviter_npub)? != event.pubkey
            || result.invitee_label.is_empty()
            || result.invitee_label.len() > 128
            || result.invitee_label.chars().any(char::is_control)
            || result.issued_at != event.created_at
            || expiry(result.issued_at)? != result.expires_at
            || event.tags != vec![vec!["d".into(), hex::encode(result.code)]]
        {
            return Err(refusal("legacy-shape"));
        }
        Ok(result)
    }

    pub fn projection(&self) -> LegacyInviteBody {
        LegacyInviteBody {
            network: self.root,
            code_id: self.code,
            issued_at_seconds: self.issued_at,
            expires_at_seconds: self.expires_at,
        }
    }
}

impl ConservedInviteBody {
    pub fn decode(event: &Event) -> Result<Self> {
        let body = event_body(event, INVITE_KIND)?;
        fields(
            &body,
            &[
                "schema",
                "algorithm",
                "network",
                "code_id",
                "issued_at_seconds",
                "expires_at_seconds",
                "issuer_subject",
                "reservation",
                "owner_receipt",
                "transfer",
            ],
        )?;
        schema(&body, CONSERVED_INVITE_SCHEMA)?;
        let result = Self {
            schema: CONSERVED_INVITE_SCHEMA.into(),
            algorithm: AlgorithmId::Secp256k1Schnorr,
            network: key(&body, "network")?,
            code_id: code(&body, "code_id")?,
            issued_at_seconds: number(&body, "issued_at_seconds")?,
            expires_at_seconds: number(&body, "expires_at_seconds")?,
            issuer_subject: subject(&body, "issuer_subject")?,
            reservation: digest(&body, "reservation")?,
            owner_receipt: digest(&body, "owner_receipt")?,
            transfer: read_transfer(&body["transfer"])?,
        };
        if event.created_at != result.issued_at_seconds
            || expiry(result.issued_at_seconds)? != result.expires_at_seconds
            || event.tags != vec![vec!["d".into(), hex::encode(result.code_id)]]
        {
            return Err(refusal("invite-shape"));
        }
        result.content()?;
        Ok(result)
    }

    pub(crate) fn content(&self) -> Result<String> {
        if self.schema != CONSERVED_INVITE_SCHEMA
            || self.algorithm != AlgorithmId::Secp256k1Schnorr
            || expiry(self.issued_at_seconds)? != self.expires_at_seconds
            || self.transfer.child_units > MAX_LIFETIME_REDEMPTIONS
        {
            return Err(refusal("invite-shape"));
        }
        self.transfer.expected.validate()?;
        nonzero(self.reservation)?;
        nonzero(self.owner_receipt)?;
        content(
            json!({"schema":self.schema,"algorithm":self.algorithm.wire_name(),
            "network":hex::encode(self.network.as_bytes()),"code_id":hex::encode(self.code_id),
            "issued_at_seconds":self.issued_at_seconds,"expires_at_seconds":self.expires_at_seconds,
            "issuer_subject":self.issuer_subject.to_string(),"reservation":self.reservation.to_string(),
            "owner_receipt":self.owner_receipt.to_string(),"transfer":transfer_json(self.transfer)}),
        )
    }
}

impl ConservedRedemptionBody {
    pub fn decode(event: &Event) -> Result<Self> {
        let body = event_body(event, REDEMPTION_KIND)?;
        fields(
            &body,
            &[
                "schema",
                "algorithm",
                "network",
                "invite_id",
                "reservation",
                "node",
                "subject",
            ],
        )?;
        schema(&body, CONSERVED_REDEMPTION_SCHEMA)?;
        let result = Self {
            schema: CONSERVED_REDEMPTION_SCHEMA.into(),
            algorithm: AlgorithmId::Secp256k1Schnorr,
            network: key(&body, "network")?,
            invite_id: event_id(&body, "invite_id")?,
            reservation: digest(&body, "reservation")?,
            node: NodeId::from_hex(string(&body, "node")?)?,
            subject: subject(&body, "subject")?,
        };
        if event.tags != event_tags(result.invite_id.digest()) {
            return Err(refusal("redemption-shape"));
        }
        result.content()?;
        Ok(result)
    }

    pub(crate) fn content(&self) -> Result<String> {
        if self.schema != CONSERVED_REDEMPTION_SCHEMA
            || self.algorithm != AlgorithmId::Secp256k1Schnorr
        {
            return Err(refusal("redemption-shape"));
        }
        nonzero(self.reservation)?;
        content(
            json!({"schema":self.schema,"algorithm":self.algorithm.wire_name(),
            "network":hex::encode(self.network.as_bytes()),"invite_id":hex::encode(self.invite_id.as_bytes()),
            "reservation":self.reservation.to_string(),"node":self.node.to_string(),"subject":self.subject.to_string()}),
        )
    }
}

impl ConservedAdmissionBody {
    pub fn decode(event: &Event) -> Result<Self> {
        let body = event_body(event, ADMISSION_KIND)?;
        fields(
            &body,
            &[
                "schema",
                "algorithm",
                "network",
                "invite_id",
                "redemption_id",
                "reservation",
                "ancestry_digest",
                "before",
                "after",
            ],
        )?;
        schema(&body, CONSERVED_ADMISSION_SCHEMA)?;
        let result = Self {
            schema: CONSERVED_ADMISSION_SCHEMA.into(),
            algorithm: AlgorithmId::Secp256k1Schnorr,
            network: key(&body, "network")?,
            invite_id: event_id(&body, "invite_id")?,
            redemption_id: event_id(&body, "redemption_id")?,
            reservation: digest(&body, "reservation")?,
            ancestry_digest: digest(&body, "ancestry_digest")?,
            before: read_version(&body["before"])?,
            after: read_version(&body["after"])?,
        };
        if event.pubkey != result.network || event.tags != event_tags(result.invite_id.digest()) {
            return Err(refusal("confirmation-shape"));
        }
        result.content()?;
        Ok(result)
    }

    pub(crate) fn content(&self) -> Result<String> {
        if self.schema != CONSERVED_ADMISSION_SCHEMA
            || self.algorithm != AlgorithmId::Secp256k1Schnorr
        {
            return Err(refusal("confirmation-shape"));
        }
        self.before.validate()?;
        self.after.validate()?;
        if self.after.epoch != self.before.epoch
            || self.before.sequence.checked_add(1) != Some(self.after.sequence)
            || self.after.previous != self.ancestry_digest
        {
            return Err(refusal("allowance-version"));
        }
        nonzero(self.reservation)?;
        nonzero(self.ancestry_digest)?;
        content(
            json!({"schema":self.schema,"algorithm":self.algorithm.wire_name(),
            "network":hex::encode(self.network.as_bytes()),"invite_id":hex::encode(self.invite_id.as_bytes()),
            "redemption_id":hex::encode(self.redemption_id.as_bytes()),"reservation":self.reservation.to_string(),
            "ancestry_digest":self.ancestry_digest.to_string(),"before":version_json(self.before),"after":version_json(self.after)}),
        )
    }
}

/// The root accounting signer confirms one exact chain under its host's lock.
/// This creates evidence only; `admit` still checks the authoritative transaction.
pub fn sign_admission_confirmation(
    key: &SecretKey,
    ancestors: &[AdmissionLink],
    invite: &Event,
    redemption: &Redemption,
    before: AllowanceVersion,
    now_seconds: u64,
) -> Result<AdmissionLink> {
    let offer = verify_offer(
        InviteOffer {
            invite: invite.clone(),
            ancestors: ancestors.to_vec(),
        },
        now_seconds,
    )?;
    let body = ConservedInviteBody::decode(invite)?;
    if key.public_key()? != body.network {
        return Err(refusal("confirmation-signer"));
    }
    check_redemption(invite, &body, redemption)?;
    let ancestry_digest = ancestry_digest(ancestors, invite, &redemption.event)?;
    let after = AllowanceVersion {
        epoch: before.epoch,
        sequence: before
            .sequence
            .checked_add(1)
            .ok_or(refusal("allowance-overflow"))?,
        previous: ancestry_digest,
    };
    let confirmation = ConservedAdmissionBody {
        schema: CONSERVED_ADMISSION_SCHEMA.into(),
        algorithm: AlgorithmId::Secp256k1Schnorr,
        network: body.network,
        invite_id: invite.id,
        redemption_id: redemption.event.id,
        reservation: body.reservation,
        ancestry_digest,
        before,
        after,
    };
    if now_seconds < redemption.event.created_at {
        return Err(refusal("invite-time"));
    }
    let event = Event::sign(
        key,
        now_seconds,
        ADMISSION_KIND,
        event_tags(offer.invite_id.digest()),
        confirmation.content()?,
    )?
    .event()
    .clone();
    Ok(AdmissionLink {
        invite: invite.clone(),
        redemption: redemption.event.clone(),
        confirmation: event,
    })
}

impl AdmittedMember {
    /// Reconstruct a confirmed record for a trusted host store. A root-signed
    /// confirmation is evidence of accounting, never permission to create a node.
    pub fn from_record(
        record: Vec<AdmissionLink>,
        network: PublicKey,
        node: NodeId,
        subject: SubjectId,
    ) -> Result<Self> {
        let first_record = verify_admission_record(&record, network, node, subject)?;
        Ok(Self {
            record,
            first_record,
        })
    }
}

pub(crate) fn check_redemption(
    invite: &Event,
    body: &ConservedInviteBody,
    redemption: &Redemption,
) -> Result<()> {
    let signed = ConservedRedemptionBody::decode(&redemption.event)?;
    if signed.network != body.network
        || signed.invite_id != invite.id
        || signed.reservation != body.reservation
        || signed.node != redemption.joining_node
        || signed.subject != redemption.joining_subject
        || redemption.event.pubkey == invite.pubkey
        || signed.subject == body.issuer_subject
    {
        return Err(refusal("redemption-context"));
    }
    live(
        body.issued_at_seconds,
        body.expires_at_seconds,
        redemption.event.created_at,
    )
}

pub(crate) fn check_record(record: &[AdmissionLink], network: PublicKey) -> Result<()> {
    if record.len() > MAX_ANCESTORS {
        return Err(refusal("ancestry-bound"));
    }
    let mut bytes = 0usize;
    let mut members = BTreeSet::new();
    members.insert(network);
    let mut subjects = BTreeSet::new();
    let mut nodes = BTreeSet::new();
    let mut invites = BTreeSet::new();
    let mut reservations = BTreeSet::new();
    for (index, link) in record.iter().enumerate() {
        for event in [&link.invite, &link.redemption, &link.confirmation] {
            bytes = bytes
                .checked_add(event.encode()?.len())
                .ok_or(refusal("ancestry-bound"))?;
            if bytes > MAX_ADMISSION_RECORD_BYTES {
                return Err(refusal("ancestry-bound"));
            }
        }
        let invite = ConservedInviteBody::decode(&link.invite)?;
        let redeem = ConservedRedemptionBody::decode(&link.redemption)?;
        let confirmation = ConservedAdmissionBody::decode(&link.confirmation)?;
        check_parent(&record[..index], &link.invite, &invite)?;
        check_redemption(
            &link.invite,
            &invite,
            &Redemption {
                event: link.redemption.clone(),
                joining_node: redeem.node,
                joining_subject: redeem.subject,
            },
        )?;
        if invite.network != network
            || confirmation.network != network
            || confirmation.invite_id != link.invite.id
            || confirmation.redemption_id != link.redemption.id
            || confirmation.reservation != invite.reservation
            || confirmation.ancestry_digest
                != ancestry_digest(&record[..index], &link.invite, &link.redemption)?
            || confirmation.before.epoch != invite.transfer.expected.epoch
            || confirmation.before.sequence <= invite.transfer.expected.sequence
            || link.confirmation.created_at < link.redemption.created_at
            || link.confirmation.created_at >= invite.expires_at_seconds
            || !members.insert(link.redemption.pubkey)
            || !nodes.insert(redeem.node)
            || !subjects.insert(redeem.subject)
            || !invites.insert(link.invite.id)
            || !reservations.insert(invite.reservation)
        {
            return Err(refusal("admission-record"));
        }
    }
    Ok(())
}

pub(crate) fn check_parent(
    ancestors: &[AdmissionLink],
    event: &Event,
    body: &ConservedInviteBody,
) -> Result<()> {
    if let Some(parent) = ancestors.last() {
        let parent_invite = ConservedInviteBody::decode(&parent.invite)?;
        let joining = ConservedRedemptionBody::decode(&parent.redemption)?;
        let confirmation = ConservedAdmissionBody::decode(&parent.confirmation)?;
        if parent_invite.network != body.network
            || parent.redemption.pubkey != event.pubkey
            || joining.subject != body.issuer_subject
            || u64::from(parent_invite.transfer.child_units)
                < 1 + u64::from(body.transfer.child_units)
            || event.created_at < parent.confirmation.created_at
            || confirmation.after.epoch != body.transfer.expected.epoch
            || confirmation.after.sequence > body.transfer.expected.sequence
        {
            return Err(refusal("ancestry-parent"));
        }
    } else if event.pubkey != body.network {
        return Err(refusal("ancestry-root"));
    }
    Ok(())
}

pub(crate) fn match_reservation(
    reserved: &ReservedInvite,
    event: &Event,
    body: &ConservedInviteBody,
) -> Result<()> {
    let draft = reserved.draft();
    if draft.network != body.network
        || draft.issuer != event.pubkey
        || draft.issuer_subject != body.issuer_subject
        || draft.code_id != body.code_id
        || draft.issued_at_seconds != body.issued_at_seconds
        || draft.transfer != body.transfer
        || reserved.reservation() != body.reservation
        || reserved.owner_receipt() != body.owner_receipt
    {
        return Err(refusal("reservation-context"));
    }
    Ok(())
}

pub(crate) fn validate_result(
    admitted: &AdmittedMember,
    offer: &VerifiedOffer,
    redemption: &Redemption,
) -> Result<()> {
    let record = admitted.record();
    let tail = record.last().ok_or(refusal("admission-record"))?;
    let network = ConservedInviteBody::decode(&offer.offer.invite)?.network;
    if record.len() != offer.offer.ancestors.len() + 1
        || tail.invite != offer.offer.invite
        || tail.redemption != redemption.event
        || record[..record.len() - 1] != offer.offer.ancestors
        || verify_admission_record(
            record,
            network,
            redemption.joining_node,
            redemption.joining_subject,
        )? != admitted.first_record
    {
        return Err(refusal("admission-record"));
    }
    Ok(())
}

pub(crate) fn ancestry_digest(
    ancestors: &[AdmissionLink],
    invite: &Event,
    redemption: &Event,
) -> Result<Digest32> {
    let mut links = Vec::with_capacity(ancestors.len() + 1);
    for link in ancestors {
        links.push(json!({"invite":event_json(&link.invite)?,
        "redemption":event_json(&link.redemption)?,"confirmation":event_json(&link.confirmation)?}));
    }
    links.push(json!({"invite":event_json(invite)?,"redemption":event_json(redemption)?}));
    let bytes = canonical(Json::Array(links))?;
    if bytes.len() > MAX_ADMISSION_RECORD_BYTES {
        return Err(refusal("ancestry-bound"));
    }
    let mut preimage = b"aukora:invite-ancestry:v1\0".to_vec();
    preimage.extend_from_slice(&bytes);
    Ok(Digest32::sha256(&preimage))
}

pub(crate) fn bounded_offer(offer: &InviteOffer) -> Result<()> {
    if offer.ancestors.len() >= MAX_ANCESTORS {
        return Err(refusal("ancestry-bound"));
    }
    let mut size = offer.invite.encode()?.len();
    for link in &offer.ancestors {
        for event in [&link.invite, &link.redemption, &link.confirmation] {
            size = size
                .checked_add(event.encode()?.len())
                .ok_or(refusal("ancestry-bound"))?;
        }
    }
    if size > MAX_ADMISSION_RECORD_BYTES {
        return Err(refusal("ancestry-bound"));
    }
    Ok(())
}

pub(crate) fn reservation_body(draft: &InviteDraft) -> Result<Value> {
    canon::json::parse_strict(&draft.canonical_bytes()?)
}
pub(crate) const fn refusal(reason: &'static str) -> Refusal {
    Refusal {
        organ: "invites",
        reason,
    }
}
pub(crate) fn expiry(issued: u64) -> Result<u64> {
    issued
        .checked_add(INVITE_TTL_SECONDS)
        .filter(|expiry| *expiry <= canon::json::MAX_SAFE_INTEGER as u64)
        .ok_or(refusal("invite-time"))
}
pub(crate) fn live(issued: u64, expires: u64, now: u64) -> Result<()> {
    if expiry(issued)? != expires || now < issued || now >= expires {
        return Err(refusal("invite-expired"));
    }
    Ok(())
}
pub(crate) fn nonzero(hash: Digest32) -> Result<()> {
    if hash.as_bytes() == &[0; 32] {
        return Err(refusal("commitment-invalid"));
    }
    Ok(())
}
pub(crate) fn event_tags(id: Digest32) -> Vec<Vec<String>> {
    vec![vec!["d".into(), id.to_string()]]
}
pub(crate) fn version_json(version: AllowanceVersion) -> Json {
    json!({"epoch":version.epoch,"sequence":version.sequence,"previous":version.previous.to_string()})
}
pub(crate) fn transfer_json(transfer: AllowanceTransfer) -> Json {
    json!({"expected":version_json(transfer.expected),"child_units":transfer.child_units})
}
pub(crate) fn read_version(body: &Json) -> Result<AllowanceVersion> {
    fields(body, &["epoch", "sequence", "previous"])?;
    let version = AllowanceVersion {
        epoch: number(body, "epoch")?,
        sequence: number(body, "sequence")?,
        previous: digest(body, "previous")?,
    };
    version.validate()?;
    Ok(version)
}
pub(crate) fn read_transfer(body: &Json) -> Result<AllowanceTransfer> {
    fields(body, &["expected", "child_units"])?;
    let child_units =
        u8::try_from(number(body, "child_units")?).map_err(|_| refusal("allowance-headroom"))?;
    if child_units > MAX_LIFETIME_REDEMPTIONS {
        return Err(refusal("allowance-headroom"));
    }
    Ok(AllowanceTransfer {
        expected: read_version(&body["expected"])?,
        child_units,
    })
}
pub(crate) fn canon_value(body: Json) -> Result<Value> {
    let bytes = serde_json::to_vec(&body).map_err(|_| refusal("body-invalid"))?;
    canon::json::parse_strict(&bytes)
}
pub(crate) fn canonical(body: Json) -> Result<Vec<u8>> {
    Ok(canon_value(body)?.canonical_bytes())
}
fn content(body: Json) -> Result<String> {
    let bytes = canonical(body)?;
    if bytes.len() > MAX_INVITE_EVENT_BYTES {
        return Err(refusal("invite-bound"));
    }
    String::from_utf8(bytes).map_err(|_| refusal("body-invalid"))
}
pub(crate) fn read_json(bytes: &[u8], limit: usize) -> Result<Json> {
    if bytes.len() > limit {
        return Err(refusal("invite-bound"));
    }
    let value = canon::json::parse_strict(bytes)?;
    if value.canonical_bytes() != bytes {
        return Err(refusal("not-canonical"));
    }
    serde_json::from_slice(bytes).map_err(|_| refusal("body-invalid"))
}
fn event_body(event: &Event, kind: u16) -> Result<Json> {
    if event.kind != kind {
        return Err(refusal("unknown-operation"));
    }
    if event.encode()?.len() > MAX_INVITE_EVENT_BYTES {
        return Err(refusal("invite-bound"));
    }
    event.clone().verify()?;
    read_json(event.content.as_bytes(), MAX_INVITE_EVENT_BYTES)
}
fn event_json(event: &Event) -> Result<Json> {
    serde_json::from_slice(&event.encode()?).map_err(|_| refusal("body-invalid"))
}
pub(crate) fn fields(body: &Json, names: &[&str]) -> Result<()> {
    let object = body.as_object().ok_or(refusal("body-invalid"))?;
    if object.len() != names.len() || names.iter().any(|key| !object.contains_key(*key)) {
        return Err(refusal("body-invalid"));
    }
    Ok(())
}
fn schema(body: &Json, expected: &str) -> Result<()> {
    if string(body, "schema")? != expected {
        return Err(refusal("unknown-operation"));
    }
    if string(body, "algorithm")? != AlgorithmId::Secp256k1Schnorr.wire_name() {
        return Err(refusal("algorithm-unsupported"));
    }
    Ok(())
}
pub(crate) fn string<'a>(body: &'a Json, name: &str) -> Result<&'a str> {
    body.get(name)
        .and_then(Json::as_str)
        .ok_or(refusal("body-invalid"))
}
pub(crate) fn number(body: &Json, name: &str) -> Result<u64> {
    body.get(name)
        .and_then(Json::as_u64)
        .filter(|number| *number <= canon::json::MAX_SAFE_INTEGER as u64)
        .ok_or(refusal("body-invalid"))
}
pub(crate) fn key(body: &Json, name: &str) -> Result<PublicKey> {
    PublicKey::from_hex(string(body, name)?)
}
pub(crate) fn digest(body: &Json, name: &str) -> Result<Digest32> {
    Digest32::from_hex(string(body, name)?)
}
pub(crate) fn event_id(body: &Json, name: &str) -> Result<EventId> {
    Ok(EventId::from_bytes(*digest(body, name)?.as_bytes()))
}
pub(crate) fn subject(body: &Json, name: &str) -> Result<SubjectId> {
    SubjectId::parse(string(body, name)?)
}
pub(crate) fn code(body: &Json, name: &str) -> Result<[u8; 16]> {
    Ok(*ProposalId::from_hex(string(body, name)?)?.as_bytes())
}
