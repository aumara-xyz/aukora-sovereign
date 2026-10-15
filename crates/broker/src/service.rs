// SPDX-License-Identifier: AGPL-3.0-or-later
//! Transaction entry points for worker 24. No method below dispatches or installs authority.

use crate::{
    grant::{GrantTerms, GrantUsage},
    intake::ModelSlot,
    receipt::{CommittedReceipt, ReceiptBody},
};
use canon::{
    authority::{AuthorityRecord, AuthorityTxn, VerifiedProof},
    fd3_payloads::ModelCall,
    ids::{GrantId, OperationId, RequestId, ReservationId},
    session::{ModelCancel, ModelStart, ModelStarted},
    Result,
};

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
}

pub struct Broker;

impl Broker {
    pub fn install_grant<T: AuthorityTxn>(
        _txn: &mut T,
        _proof: VerifiedProof,
        _terms: GrantTerms,
        _model: &ModelSlot,
        _now_ms: u64,
    ) -> Result<AuthorityRecord> {
        todo!("row 24: exact grant bytes, counter, consume and append in one Aura transaction")
    }

    pub fn revoke_grant<T: AuthorityTxn>(
        _txn: &mut T,
        _proof: VerifiedProof,
        _grant_id: GrantId,
    ) -> Result<AuthorityRecord> {
        todo!("row 24: owner-authorized revocation in the existing transaction")
    }

    pub fn grant_usage<T: AuthorityTxn>(_txn: &mut T, _grant_id: GrantId) -> Result<GrantUsage> {
        todo!("row 24: read locked durable grant usage")
    }

    pub fn reserve<T: AuthorityTxn>(
        _txn: &mut T,
        _request: ReserveRequest,
        _model: &ModelSlot,
    ) -> Result<Reservation> {
        todo!("row 24: canon lacks a grant-derived reservation append contract")
    }

    pub fn settle<T: AuthorityTxn>(
        _txn: &mut T,
        _reservation: Reservation,
        _receipt: ReceiptBody,
    ) -> Result<CommittedReceipt> {
        todo!("row 24: canon lacks a grant-derived unique terminal append contract")
    }

    pub fn recover_pending<T: AuthorityTxn>(
        _txn: &mut T,
        _now_ms: u64,
    ) -> Result<Vec<CommittedReceipt>> {
        todo!("row 24: settle durable pending reservations as unknown without redispatch")
    }

    pub async fn call(
        _reservation: Reservation,
        _keys: &crate::keystore::KeyInbox,
        _slot: &ModelSlot,
    ) -> Result<PendingCompletion> {
        todo!("row 24: dispatch once, keep key outside model payload, settle before delivery")
    }

    pub async fn start(
        _reservation: Reservation,
        _request: ModelStart,
        _keys: &crate::keystore::KeyInbox,
        _slot: &ModelSlot,
    ) -> Result<ActiveStream> {
        todo!("row 24: bind request to reservation and start bounded provider production")
    }

    pub async fn cancel(_stream: &mut ActiveStream, _request: ModelCancel) -> Result<()> {
        todo!("row 24: stop production and settle before emitting the cancellation receipt")
    }
}

pub struct PendingCompletion {
    pub content: Option<String>,
    pub tool_calls: Vec<canon::fd3_payloads::ToolCall>,
    pub finish_reason: Option<String>,
    pub settlement: ReceiptBody,
}

pub struct ActiveStream {
    started: ModelStarted,
    buffer: crate::stream::StreamBuffer,
}

impl ActiveStream {
    pub fn started(&self) -> &ModelStarted {
        &self.started
    }
    pub fn buffer(&self) -> &crate::stream::StreamBuffer {
        &self.buffer
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
            _ => Err(canon::codes::BROKER_INVALID_REQUEST),
        }
    }
}
