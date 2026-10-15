// SPDX-License-Identifier: AGPL-3.0-or-later
//! Grant admission and model production use separate, durable reservation handles.

use crate::{
    grant::{GrantTerms, GrantUsage, MAX_SAFE},
    identity::{ModelIdentity, VerifiedIdentity},
    intake::ModelSlot,
    keystore::KeyInbox,
    provider::{self, ModelSource, ProviderReply, ProviderStream},
    receipt::{CommittedReceipt, ReceiptBody, SettlementOutcome},
};
use canon::{
    alg::AlgorithmId,
    authority::{
        AuthorityRecord, AuthorityTxn, BaseDigest, Kind, OwnerOperation, PendingAuthorityRecord,
        Phase, VerifiedProof,
    },
    codes,
    digest::Digest32,
    fd3_payloads::{ModelCall, ModelReply, Usage},
    ids::{GrantId, OperationId, RequestId, ReservationId},
    json::{SafeInteger, Value, ValueView},
    session::{Items, ModelCancel, ModelStart, ModelStarted, Text, MAX_PENDING_CHUNKS},
    Result,
};

const RESERVATION_SCHEMA: &str = "aukora-broker-reservation-v2";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReserveRequest {
    pub request_id: RequestId,
    pub reservation_id: ReservationId,
    pub operation_id: OperationId,
    pub call: ModelCall,
    pub prompt_token_bound: u64,
    pub key_generation: u64,
    pub now_ms: u64,
}

#[derive(Debug)]
pub struct Reservation {
    request: ReserveRequest,
    grant_id: GrantId,
    reserved_microusd: u64,
    aura_sequence: u64,
    terms: GrantTerms,
    settlement_commitment: Option<Digest32>,
}

impl Reservation {
    pub fn request(&self) -> &ReserveRequest {
        &self.request
    }
    pub const fn grant_id(&self) -> GrantId {
        self.grant_id
    }
    pub const fn reserved_microusd(&self) -> u64 {
        self.reserved_microusd
    }
    pub const fn aura_sequence(&self) -> u64 {
        self.aura_sequence
    }

    fn receipt(&self, outcome: SettlementOutcome, refusal: Option<canon::Refusal>) -> ReceiptBody {
        let unknown = matches!(
            outcome,
            SettlementOutcome::Unknown | SettlementOutcome::Cancelled
        );
        let charged = if unknown { self.reserved_microusd } else { 0 };
        ReceiptBody {
            v: 2,
            algorithm: AlgorithmId::Sha256,
            grant_id: self.grant_id,
            request_id: self.request.request_id,
            reservation_id: self.request.reservation_id,
            operation_id: self.request.operation_id,
            identity: ModelIdentity {
                requested: self.terms.model.clone(),
                reported: None,
                verified: VerifiedIdentity::Unverified,
            },
            source: self.terms.source.clone(),
            intake_commitment: self.terms.intake_commitment,
            slot_generation: self.terms.slot_generation,
            key_generation: self.terms.key_generation,
            usage: Usage {
                prompt_tokens: 0,
                completion_tokens: 0,
                cost_microusd: charged,
            },
            reserved_microusd: self.reserved_microusd,
            charged_microusd: charged,
            cost_unknown: unknown,
            reservation_exceeded: false,
            grant_frozen: unknown,
            outcome,
            refusal,
        }
    }
}

pub struct Broker;

impl Broker {
    pub fn install_grant<T: AuthorityTxn>(
        txn: &mut T,
        proof: VerifiedProof,
        terms: GrantTerms,
        model: &ModelSlot,
        now_ms: u64,
    ) -> Result<AuthorityRecord> {
        terms.validate(now_ms)?;
        model.check_grant(&terms)?;
        let body = canon::json::parse_strict(&terms.canonical_bytes()?)?;
        let auth = proof.authorization();
        if auth.op != OwnerOperation::Grant
            || auth.target != terms.target()
            || auth.base_sha256 != BaseDigest::Absent
            || auth.cell.is_some()
            || auth.new_sha256 != Digest32::sha256(&terms.canonical_bytes()?)
            || proof.transaction_id() != txn.transaction_id()
            || txn
                .authority_state("broker.grant", &terms.grant_id.to_string())?
                .is_some()
        {
            return Err(codes::BROKER_GRANT_MISMATCH);
        }
        let context = txn.authority_append_context(&proof)?;
        if context.authority.epoch != auth.epoch || context.at < 0 || now_ms != context.at as u64 {
            return Err(codes::BROKER_INVALID_GRANT);
        }
        let row = PendingAuthorityRecord {
            v: 1,
            algorithm: AlgorithmId::Sha256,
            authority: context.authority,
            at: context.at,
            kind: Kind::BrokerGrant,
            actor: "owner".into(),
            operation: Some(context.operation_id),
            phase: Phase::Terminal,
            body,
        };
        txn.persist_counter(&proof)?;
        txn.consume(&proof)?;
        txn.append(proof, row)
    }

    pub fn revoke_grant<T: AuthorityTxn>(
        txn: &mut T,
        proof: VerifiedProof,
        grant_id: GrantId,
    ) -> Result<AuthorityRecord> {
        let state = grant_state(txn, grant_id)?;
        let auth = proof.authorization();
        let bytes = state.terms.canonical_bytes()?;
        let body = Value::object(vec![
            ("schema".into(), text("aukora-broker-revoke-v2")?),
            (
                "body".into(),
                Value::object(vec![
                    ("grant_id".into(), text(&grant_id.to_string())?),
                    (
                        "grant_commitment".into(),
                        text(&state.terms.commitment()?.to_string())?,
                    ),
                    ("revoked".into(), Value::boolean(true)),
                ])?,
            ),
        ])?;
        if auth.op != OwnerOperation::Grant
            || auth.target != state.terms.target()
            || auth.base_sha256 != BaseDigest::Present(Digest32::sha256(&bytes))
            || auth.new_sha256 != Digest32::sha256(&canon::json::to_canonical(&body))
            || auth.cell.is_some()
            || proof.transaction_id() != txn.transaction_id()
        {
            return Err(codes::BROKER_GRANT_MISMATCH);
        }
        let context = txn.authority_append_context(&proof)?;
        if context.authority.epoch != state.epoch || auth.epoch != state.epoch {
            return Err(codes::BROKER_GRANT_MISMATCH);
        }
        let row = PendingAuthorityRecord {
            v: 1,
            algorithm: AlgorithmId::Sha256,
            authority: context.authority,
            at: context.at,
            kind: Kind::BrokerRevoke,
            actor: "owner".into(),
            operation: Some(context.operation_id),
            phase: Phase::Terminal,
            body,
        };
        txn.persist_counter(&proof)?;
        txn.consume(&proof)?;
        txn.append(proof, row)
    }

    pub fn grant_usage<T: AuthorityTxn>(txn: &mut T, grant_id: GrantId) -> Result<GrantUsage> {
        Ok(grant_state(txn, grant_id)?.usage)
    }

    pub fn reserve<T: AuthorityTxn>(
        txn: &mut T,
        request: ReserveRequest,
        model: &ModelSlot,
    ) -> Result<Reservation> {
        provider::validate_call(&request.call)?;
        let grant_id =
            GrantId::from_hex(&request.call.grant_id).map_err(|_| codes::BROKER_INVALID_REQUEST)?;
        let state = grant_state(txn, grant_id)?;
        if state.revoked {
            return Err(codes::BROKER_GRANT_REVOKED);
        }
        if state.frozen {
            return Err(codes::BROKER_GRANT_FROZEN);
        }
        let context = txn.observation_context()?;
        if context.at < 0
            || request.now_ms != context.at as u64
            || context.authority.epoch != state.epoch
        {
            return Err(codes::BROKER_GRANT_MISMATCH);
        }
        if request.now_ms >= state.terms.expires_at_ms {
            return Err(codes::BROKER_GRANT_EXPIRED);
        }
        model.check_grant(&state.terms)?;
        if request.call.model != state.terms.model.as_str()
            || request.key_generation != state.terms.key_generation
        {
            return Err(codes::BROKER_GRANT_MISMATCH);
        }
        let bound = provider::prompt_token_bound(&request.call)?;
        if request.prompt_token_bound < bound || request.prompt_token_bound > 32_768 {
            return Err(codes::BROKER_PRICE_UNBOUNDED);
        }
        for (namespace, id) in [
            ("broker.request", request.request_id.to_string()),
            ("broker.reservation", request.reservation_id.to_string()),
            ("broker.operation", request.operation_id.to_string()),
        ] {
            if txn.authority_state(namespace, &id)?.is_some() {
                return Err(codes::BROKER_REQUEST_REUSED);
            }
        }
        let reserved_microusd = state
            .terms
            .reserve_amount(request.prompt_token_bound, request.call.max_output_tokens)?;
        state.usage.admit(&state.terms, reserved_microusd)?;
        let mut reservation = Reservation {
            request,
            grant_id,
            reserved_microusd,
            aura_sequence: 0,
            terms: state.terms,
            settlement_commitment: None,
        };
        let body = reservation_body(&reservation)?;
        let expected = PendingAuthorityRecord {
            v: 1,
            algorithm: AlgorithmId::Sha256,
            authority: context.authority,
            at: context.at,
            kind: Kind::BrokerReserve,
            actor: "Auma".into(),
            operation: Some(reservation.request.operation_id),
            phase: Phase::Intent,
            body,
        };
        let record = txn.commit_broker_transition(expected.clone())?;
        check_record(&record, &expected)?;
        reservation.aura_sequence = record.authority.sequence;
        Ok(reservation)
    }

    pub fn settle<T: AuthorityTxn>(
        txn: &mut T,
        reservation: Reservation,
        receipt: ReceiptBody,
    ) -> Result<CommittedReceipt> {
        if reservation.settlement_commitment != Some(receipt.commitment()?) {
            return Err(codes::BROKER_STATE);
        }
        check_receipt(&reservation, &receipt)?;
        commit_receipt(txn, receipt)
    }

    pub fn recover_pending<T: AuthorityTxn>(
        txn: &mut T,
        now_ms: u64,
    ) -> Result<Vec<CommittedReceipt>> {
        let context = txn.observation_context()?;
        if context.at < 0 || context.at as u64 != now_ms {
            return Err(codes::BROKER_STATE);
        }
        // Each transition ends its transaction, so recovery advances one per call.
        let pending = txn.pending_broker_reservations()?;
        let Some(body) = pending.first() else {
            return Ok(Vec::new());
        };
        let body = field(body, "body")?;
        let receipt = ReceiptBody::from_canonical_bytes(&canon::json::to_canonical(field(
            body,
            "unknown_receipt",
        )?))?;
        if receipt.outcome != SettlementOutcome::Unknown || !receipt.cost_unknown {
            return Err(codes::BROKER_STATE);
        }
        Ok(vec![commit_receipt(txn, receipt)?])
    }

    pub async fn call(
        mut reservation: Reservation,
        keys: &KeyInbox,
        slot: &ModelSlot,
    ) -> Result<PendingCompletion> {
        let (mut reply, mut receipt) = match prepare_route(&reservation, keys, slot) {
            Ok((provider, key)) => completion(
                &reservation,
                provider::dispatch(provider, &reservation.request.call, &key).await,
                keys,
            )?,
            Err(code) => (
                None,
                reservation.receipt(SettlementOutcome::Refused, Some(code)),
            ),
        };
        if let Some(raw) = &reply {
            let frame = canon::frame::Frame {
                v: 1,
                id: canon::frame::FrameId::new("x".repeat(64))?,
                provenance: canon::provenance::Provenance {
                    source: canon::provenance::Source::Auma,
                },
                body: canon::fd3::Reply::ModelReply(ModelReply {
                    content: raw.content.clone(),
                    tool_calls: raw.tool_calls.clone(),
                    finish_reason: raw.finish_reason.clone(),
                    usage: receipt.usage.clone(),
                    receipt_seq: MAX_SAFE,
                }),
            };
            if canon::fd3::encode_reply(&frame).is_err() {
                receipt.outcome = SettlementOutcome::Refused;
                receipt.refusal = Some(codes::BROKER_REPLY_TOO_LARGE);
                reply = None;
            }
        }
        reservation.settlement_commitment = Some(receipt.commitment()?);
        Ok(PendingCompletion {
            content: None,
            tool_calls: Vec::new(),
            finish_reason: None,
            settlement: receipt.clone(),
            reservation,
            reply,
            sealed_receipt: receipt,
        })
    }

    /// Release non-streaming output only after the exact settlement durably commits.
    pub fn settle_completion<T: AuthorityTxn>(
        txn: &mut T,
        pending: PendingCompletion,
    ) -> Result<ModelReply> {
        if pending.settlement != pending.sealed_receipt {
            return Err(codes::BROKER_STATE);
        }
        let receipt = Self::settle(txn, pending.reservation, pending.sealed_receipt)?;
        let reply = pending.reply.ok_or(
            receipt
                .body
                .refusal
                .unwrap_or(codes::BROKER_PROVIDER_UNAVAILABLE),
        )?;
        Ok(ModelReply {
            content: reply.content,
            tool_calls: reply.tool_calls,
            finish_reason: reply.finish_reason,
            usage: receipt.body.usage,
            receipt_seq: receipt.aura_sequence,
        })
    }

    pub async fn start(
        reservation: Reservation,
        request: ModelStart,
        keys: &KeyInbox,
        slot: &ModelSlot,
    ) -> Result<ActiveStream> {
        let invalid = request.request_id != reservation.request.request_id
            || request.reservation_id != reservation.request.reservation_id
            || request.call != reservation.request.call
            || !(1..=MAX_PENDING_CHUNKS).contains(&request.max_pending_chunks);
        let started = ModelStarted {
            request_id: reservation.request.request_id,
            reservation_id: reservation.request.reservation_id,
            max_pending_chunks: if invalid {
                1
            } else {
                request.max_pending_chunks
            },
        };
        let buffer = crate::stream::StreamBuffer::new(started.clone())?;
        let prepared = if invalid {
            Err(codes::BROKER_INVALID_REQUEST)
        } else {
            prepare_route(&reservation, keys, slot)
        };
        let preflight_failed = prepared.is_err();
        let production = match prepared {
            Ok((provider, key)) => provider::start_stream(provider, &request.call, key).await,
            Err(code) => Err(code),
        };
        let (producer, settlement) = match production {
            Ok(producer) => (Some(producer), None),
            Err(code) => (
                None,
                Some(reservation.receipt(
                    if preflight_failed {
                        SettlementOutcome::Refused
                    } else {
                        SettlementOutcome::Unknown
                    },
                    Some(code),
                )),
            ),
        };
        Ok(ActiveStream {
            started,
            buffer,
            producer,
            reservation: Some(reservation),
            settlement,
            finish_reason: None,
            echo_tail: zeroize::Zeroizing::new(String::new()),
        })
    }

    pub async fn cancel(stream: &mut ActiveStream, request: ModelCancel) -> Result<()> {
        if stream.settlement.is_some() {
            return Err(codes::BROKER_STATE);
        }
        let reservation = stream.reservation.as_ref().ok_or(codes::BROKER_STATE)?;
        let receipt = interrupted_receipt(
            reservation,
            stream.producer.as_ref(),
            SettlementOutcome::Cancelled,
            None,
        );
        stream.buffer.request_cancel(&request)?;
        if let Some(producer) = &mut stream.producer {
            producer.cancel();
        }
        stream.producer = None;
        stream.settlement = Some(receipt);
        Ok(())
    }

    /// Poll at most one provider delta; a full guest window leaves HTTP unread.
    pub async fn poll_stream(stream: &mut ActiveStream, keys: &KeyInbox) -> Result<bool> {
        if stream.settlement.is_some() {
            return Ok(false);
        }
        let reservation = stream.reservation.as_ref().ok_or(codes::BROKER_STATE)?;
        if let Some(code) = stream.buffer.production_refusal() {
            if code == codes::BROKER_BUSY {
                return Ok(false);
            }
            let receipt = interrupted_receipt(
                reservation,
                stream.producer.as_ref(),
                SettlementOutcome::Unknown,
                Some(code),
            );
            if let Some(producer) = &mut stream.producer {
                producer.cancel();
            }
            stream.producer = None;
            stream.settlement = Some(receipt);
            return Ok(false);
        }
        let next = async {
            keys.key_for_generation(reservation.terms.key_generation)?;
            let producer = stream.producer.as_mut().ok_or(codes::BROKER_STATE)?;
            producer.next().await
        }
        .await;
        match next {
            Ok(Some(delta)) => {
                let result = (|| {
                    if let Some(content) = &delta.content {
                        stream.echo_tail.push_str(content);
                        keys.reject_echo(stream.echo_tail.as_bytes())?;
                    }
                    for call in &delta.tool_calls {
                        keys.reject_echo(call.id.as_bytes())?;
                        keys.reject_echo(call.name.as_bytes())?;
                        keys.reject_echo(call.arguments.as_bytes())?;
                    }
                    let content = delta.content.map(Text::new).transpose()?;
                    stream.buffer.push(content, Items::new(delta.tool_calls)?)
                })();
                if let Err(code) = result {
                    let receipt = interrupted_receipt(
                        reservation,
                        stream.producer.as_ref(),
                        SettlementOutcome::Unknown,
                        Some(code),
                    );
                    if let Some(producer) = &mut stream.producer {
                        producer.cancel();
                    }
                    stream.producer = None;
                    stream.settlement = Some(receipt);
                    return Ok(false);
                }
                if stream.echo_tail.len() > crate::keystore::MAX_KEY_BYTES {
                    let mut boundary = stream.echo_tail.len() - crate::keystore::MAX_KEY_BYTES;
                    while !stream.echo_tail.is_char_boundary(boundary) {
                        boundary += 1;
                    }
                    stream.echo_tail.drain(..boundary);
                }
                Ok(true)
            }
            Ok(None) => {
                let reply = stream
                    .producer
                    .as_ref()
                    .ok_or(codes::BROKER_STATE)?
                    .completion();
                let (reply, receipt) = completion(reservation, reply, keys)?;
                stream.finish_reason = reply.and_then(|r| r.finish_reason);
                stream.settlement = Some(receipt);
                stream.producer = None;
                Ok(false)
            }
            Err(code) => {
                let receipt = interrupted_receipt(
                    reservation,
                    stream.producer.as_ref(),
                    SettlementOutcome::Unknown,
                    Some(code),
                );
                if let Some(producer) = &mut stream.producer {
                    producer.cancel();
                }
                stream.producer = None;
                stream.settlement = Some(receipt);
                Ok(false)
            }
        }
    }

    /// Durably settle before exposing any end, error or cancellation frame.
    pub fn finish_stream<T: AuthorityTxn>(txn: &mut T, stream: &mut ActiveStream) -> Result<()> {
        let receipt = stream
            .settlement
            .as_ref()
            .ok_or(codes::BROKER_SETTLE_PENDING)?
            .clone();
        let reservation = stream.reservation.as_ref().ok_or(codes::BROKER_STATE)?;
        check_receipt(reservation, &receipt)?;
        let finish_reason = stream.finish_reason.clone().map(Text::new).transpose()?;
        let committed = commit_receipt(txn, receipt)?;
        stream.buffer.finish(&committed, finish_reason)?;
        stream.reservation = None;
        stream.settlement = None;
        Ok(())
    }
}

pub struct PendingCompletion {
    /// Output stays sealed until `Broker::settle_completion` returns its receipt.
    pub content: Option<String>,
    pub tool_calls: Vec<canon::fd3_payloads::ToolCall>,
    pub finish_reason: Option<String>,
    pub settlement: ReceiptBody,
    reservation: Reservation,
    reply: Option<ProviderReply>,
    sealed_receipt: ReceiptBody,
}

pub struct ActiveStream {
    started: ModelStarted,
    buffer: crate::stream::StreamBuffer,
    producer: Option<ProviderStream>,
    reservation: Option<Reservation>,
    settlement: Option<ReceiptBody>,
    finish_reason: Option<String>,
    echo_tail: zeroize::Zeroizing<String>,
}

impl ActiveStream {
    pub fn started(&self) -> &ModelStarted {
        &self.started
    }
    pub fn buffer(&self) -> &crate::stream::StreamBuffer {
        &self.buffer
    }
    pub fn acknowledge_delivery(&mut self, index: u64) -> Result<()> {
        self.buffer.acknowledge_delivery(index)
    }
    pub fn take_terminal(&mut self) -> Option<crate::stream::Terminal> {
        self.buffer.take_terminal()
    }
    pub fn needs_settlement(&self) -> bool {
        self.settlement.is_some()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Call,
    Start,
    Cancel,
}
impl Operation {
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "model.call" => Ok(Self::Call),
            "model.start" => Ok(Self::Start),
            "model.cancel" => Ok(Self::Cancel),
            _ => Err(codes::BROKER_INVALID_REQUEST),
        }
    }
}

struct GrantState {
    terms: GrantTerms,
    usage: GrantUsage,
    epoch: u64,
    revoked: bool,
    frozen: bool,
}
fn prepare_route(
    reservation: &Reservation,
    keys: &KeyInbox,
    slot: &ModelSlot,
) -> Result<(provider::HostedProvider, zeroize::Zeroizing<String>)> {
    slot.check_grant(&reservation.terms)?;
    let ModelSource::Hosted(provider) = reservation.terms.source else {
        return Err(codes::BROKER_PROVIDER_UNAVAILABLE);
    };
    Ok((
        provider,
        keys.key_for_generation(reservation.terms.key_generation)?,
    ))
}
fn grant_state<T: AuthorityTxn>(txn: &mut T, id: GrantId) -> Result<GrantState> {
    let value = txn
        .authority_state("broker.grant", &id.to_string())?
        .ok_or(codes::BROKER_GRANT_UNKNOWN)?;
    let terms = GrantTerms::from_value(field(&value, "terms")?)?;
    if terms.grant_id != id {
        return Err(codes::BROKER_GRANT_MISMATCH);
    }
    Ok(GrantState {
        terms,
        usage: GrantUsage::from_value(field(&value, "usage")?)?,
        epoch: uint(field(&value, "epoch")?)?,
        revoked: boolean(field(&value, "revoked")?)?,
        frozen: boolean(field(&value, "frozen")?)?,
    })
}

fn reservation_body(reservation: &Reservation) -> Result<Value> {
    Value::object(vec![
        ("schema".into(), text(RESERVATION_SCHEMA)?),
        (
            "body".into(),
            Value::object(vec![
                (
                    "terms".into(),
                    canon::json::parse_strict(&reservation.terms.canonical_bytes()?)?,
                ),
                (
                    "request_id".into(),
                    text(&reservation.request.request_id.to_string())?,
                ),
                (
                    "reservation_id".into(),
                    text(&reservation.request.reservation_id.to_string())?,
                ),
                (
                    "operation_id".into(),
                    text(&reservation.request.operation_id.to_string())?,
                ),
                (
                    "prompt_token_bound".into(),
                    number(reservation.request.prompt_token_bound)?,
                ),
                (
                    "completion_token_bound".into(),
                    number(reservation.request.call.max_output_tokens.into())?,
                ),
                (
                    "reserved_microusd".into(),
                    number(reservation.reserved_microusd)?,
                ),
                (
                    "call_sha256".into(),
                    text(&call_digest(&reservation.request.call)?.to_string())?,
                ),
                (
                    "unknown_receipt".into(),
                    reservation
                        .receipt(
                            SettlementOutcome::Unknown,
                            Some(codes::BROKER_PROVIDER_UNAVAILABLE),
                        )
                        .canonical_body()?,
                ),
            ])?,
        ),
    ])
}

fn call_digest(call: &ModelCall) -> Result<Digest32> {
    let frame = canon::frame::Frame {
        v: 1,
        id: canon::frame::FrameId::new("broker".into())?,
        provenance: canon::provenance::Provenance {
            source: canon::provenance::Source::Auma,
        },
        body: canon::fd3::Request::ModelCall(call.clone()),
    };
    let frame = canon::fd3::encode_request(&frame)?;
    Ok(Digest32::sha256(&frame))
}

fn completion(
    reservation: &Reservation,
    result: Result<ProviderReply>,
    keys: &KeyInbox,
) -> Result<(Option<ProviderReply>, ReceiptBody)> {
    match evaluate_completion(reservation, result, keys) {
        Err(code) => Ok((
            None,
            reservation.receipt(SettlementOutcome::Unknown, Some(code)),
        )),
        result => result,
    }
}

fn interrupted_receipt(
    reservation: &Reservation,
    producer: Option<&ProviderStream>,
    outcome: SettlementOutcome,
    refusal: Option<canon::Refusal>,
) -> ReceiptBody {
    let mut receipt = reservation.receipt(outcome, refusal);
    if let Some(producer) = producer {
        receipt.identity = producer.observed_identity();
    }
    if let Some(evidence) = producer.and_then(ProviderStream::cancellation_evidence) {
        let prices = reservation.terms.prices;
        let calculated = u128::from(evidence.usage.prompt_tokens)
            * u128::from(prices.prompt_microusd_per_token)
            + u128::from(evidence.usage.completion_tokens)
                * u128::from(prices.completion_microusd_per_token);
        receipt.identity = evidence.identity;
        receipt.usage = evidence.usage;
        receipt.usage.cost_microusd = receipt
            .usage
            .cost_microusd
            .max(calculated.min(u128::from(MAX_SAFE)) as u64);
        receipt.charged_microusd = receipt.reserved_microusd.max(receipt.usage.cost_microusd);
        receipt.reservation_exceeded = receipt.charged_microusd > receipt.reserved_microusd;
        if receipt.reservation_exceeded {
            receipt.outcome = SettlementOutcome::Refused;
            receipt.refusal = Some(codes::BROKER_RESERVATION_EXCEEDED);
        }
    }
    receipt
}

fn evaluate_completion(
    reservation: &Reservation,
    result: Result<ProviderReply>,
    keys: &KeyInbox,
) -> Result<(Option<ProviderReply>, ReceiptBody)> {
    if matches!(reservation.terms.source, ModelSource::Hosted(_)) {
        if let Err(code) = keys.key_for_generation(reservation.terms.key_generation) {
            return Ok((
                None,
                reservation.receipt(SettlementOutcome::Unknown, Some(code)),
            ));
        }
    }
    let reply = match result {
        Ok(reply) => reply,
        Err(code) => {
            return Ok((
                None,
                reservation.receipt(SettlementOutcome::Unknown, Some(code)),
            ))
        }
    };
    let guarded = (|| {
        if let Some(value) = &reply.content {
            keys.reject_echo(value.as_bytes())?;
        }
        if let Some(value) = &reply.finish_reason {
            keys.reject_echo(value.as_bytes())?;
        }
        if let Some(value) = &reply.identity.reported {
            keys.reject_echo(value.as_str().as_bytes())?;
        }
        for call in &reply.tool_calls {
            for value in [&call.id, &call.name, &call.arguments] {
                keys.reject_echo(value.as_bytes())?;
            }
        }
        Ok(())
    })();
    if let Err(code) = guarded {
        return Ok((
            None,
            reservation.receipt(SettlementOutcome::Unknown, Some(code)),
        ));
    }
    let mut receipt = reservation.receipt(SettlementOutcome::Completed, None);
    receipt.identity = reply.identity.clone();
    receipt.usage = reply.usage.clone();
    let calculated = u64::from(reply.usage.prompt_tokens)
        .checked_mul(reservation.terms.prices.prompt_microusd_per_token)
        .and_then(|p| {
            u64::from(reply.usage.completion_tokens)
                .checked_mul(reservation.terms.prices.completion_microusd_per_token)
                .and_then(|c| p.checked_add(c))
        })
        .filter(|v| *v <= MAX_SAFE)
        .ok_or(codes::BROKER_PRICE_UNBOUNDED)?;
    receipt.usage.cost_microusd = if reply.cost_unknown {
        calculated
    } else {
        reply.usage.cost_microusd.max(calculated)
    };
    receipt.cost_unknown = reply.cost_unknown;
    receipt.charged_microusd = if reply.cost_unknown {
        receipt.reserved_microusd.max(receipt.usage.cost_microusd)
    } else {
        receipt.usage.cost_microusd
    };
    receipt.grant_frozen = reply.cost_unknown;
    receipt.reservation_exceeded = receipt.charged_microusd > receipt.reserved_microusd;
    if receipt.reservation_exceeded
        || u64::from(receipt.usage.prompt_tokens) > reservation.request.prompt_token_bound
        || receipt.usage.completion_tokens > reservation.request.call.max_output_tokens
    {
        receipt.grant_frozen = true;
        receipt.outcome = SettlementOutcome::Refused;
        receipt.refusal = Some(codes::BROKER_RESERVATION_EXCEEDED);
        receipt.validate()?;
        return Ok((None, receipt));
    }
    receipt.validate()?;
    Ok((Some(reply), receipt))
}

fn check_receipt(reservation: &Reservation, receipt: &ReceiptBody) -> Result<()> {
    receipt.validate()?;
    let minimum_cost = u64::from(receipt.usage.prompt_tokens)
        .checked_mul(reservation.terms.prices.prompt_microusd_per_token)
        .and_then(|p| {
            u64::from(receipt.usage.completion_tokens)
                .checked_mul(reservation.terms.prices.completion_microusd_per_token)
                .and_then(|c| p.checked_add(c))
        })
        .filter(|v| *v <= MAX_SAFE)
        .ok_or(codes::BROKER_PRICE_UNBOUNDED)?;
    if receipt.grant_id != reservation.grant_id
        || receipt.request_id != reservation.request.request_id
        || receipt.reservation_id != reservation.request.reservation_id
        || receipt.operation_id != reservation.request.operation_id
        || receipt.identity.requested != reservation.terms.model
        || receipt.source != reservation.terms.source
        || receipt.intake_commitment != reservation.terms.intake_commitment
        || receipt.slot_generation != reservation.terms.slot_generation
        || receipt.key_generation != reservation.terms.key_generation
        || receipt.reserved_microusd != reservation.reserved_microusd
        || receipt.charged_microusd < minimum_cost
        || receipt.usage.cost_microusd < minimum_cost
        || ((u64::from(receipt.usage.prompt_tokens) > reservation.request.prompt_token_bound
            || receipt.usage.completion_tokens > reservation.request.call.max_output_tokens)
            && (!receipt.grant_frozen || receipt.outcome == SettlementOutcome::Completed))
    {
        return Err(codes::BROKER_GRANT_MISMATCH);
    }
    Ok(())
}

fn commit_receipt<T: AuthorityTxn>(txn: &mut T, receipt: ReceiptBody) -> Result<CommittedReceipt> {
    receipt.validate()?;
    let context = txn.observation_context()?;
    let expected = PendingAuthorityRecord {
        v: 1,
        algorithm: AlgorithmId::Sha256,
        authority: context.authority,
        at: context.at,
        kind: Kind::BrokerSettle,
        actor: "broker".into(),
        operation: Some(receipt.operation_id),
        phase: Phase::Terminal,
        body: receipt.canonical_body()?,
    };
    let record = txn.commit_broker_transition(expected.clone())?;
    check_record(&record, &expected)?;
    let committed = CommittedReceipt {
        body: receipt,
        aura_sequence: record.authority.sequence,
        aura_hash: record.hash,
    };
    committed.validate()?;
    Ok(committed)
}
fn check_record(record: &AuthorityRecord, expected: &PendingAuthorityRecord) -> Result<()> {
    if record.v != expected.v
        || record.algorithm != expected.algorithm
        || record.authority != expected.authority
        || record.at != expected.at
        || record.kind != expected.kind
        || record.actor != expected.actor
        || record.operation != expected.operation
        || record.phase != expected.phase
        || record.body != expected.body
        || record.authority.sequence == 0
        || record.authority.sequence > MAX_SAFE
    {
        return Err(codes::BROKER_STATE);
    }
    Ok(())
}
fn field<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    value.get(key).ok_or(codes::BROKER_STATE)
}
fn uint(value: &Value) -> Result<u64> {
    match value.view() {
        ValueView::Integer(v) => u64::try_from(v.get()).map_err(|_| codes::BROKER_STATE),
        _ => Err(codes::BROKER_STATE),
    }
}
fn boolean(value: &Value) -> Result<bool> {
    match value.view() {
        ValueView::Boolean(v) => Ok(v),
        _ => Err(codes::BROKER_STATE),
    }
}
fn text(value: &str) -> Result<Value> {
    Value::text(value.to_owned())
}
fn number(value: u64) -> Result<Value> {
    Ok(Value::integer(SafeInteger::new(
        i64::try_from(value).map_err(|_| codes::BROKER_STATE)?,
    )?))
}
