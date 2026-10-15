// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::http::StatusCode;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub type BackendFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
pub type OwnerSessionEffect<'a> = Box<dyn FnOnce() -> Result<(), ApiError> + Send + 'a>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootstrapState {
    ClaimOpen,
    Enrolled,
    Bound,
    Released,
}

impl BootstrapState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClaimOpen => "claim-open",
            Self::Enrolled => "enrolled",
            Self::Bound => "bound",
            Self::Released => "released",
        }
    }

    pub const fn is_bound(self) -> bool {
        matches!(self, Self::Bound | Self::Released)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerState {
    pub state: BootstrapState,
    pub subject: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    EnrolStart,
    EnrolFinish,
    BindingPrepare,
    BindingConfirm,
    BindingCancel,
    BindingRefresh,
    BindingRefreshPrepare,
    BindingRefreshResume,
    BindingRefreshConfirm,
    BindingRefreshCancel,
    LogoutEverywhereStart,
    LogoutEverywhereFinish,
    Approvals,
    Slider,
    SliderPropose,
    ApprovalChallenge,
    ApprovalDespiteChallenge,
    ApprovalDespiteDecide,
    ReleaseRetry,
    ApprovalDecide,
    ApprovalRetireChallenge,
    ApprovalRetire,
    ApprovalReconcileChallenge,
    ApprovalReconcile,
    AuraHead,
    AuraRecent,
    AuraRetained,
    AuraExport,
    Nostr,
    NostrContacts,
    NostrContactPropose,
    NostrSendPropose,
    NostrSendPreview,
    NostrInbox,
    MemoryRecall,
    MemoryDemote,
    SigninStart,
    SigninFinish,
    Broker,
    BrokerKeyPropose,
    BrokerKeyRedeem,
    BrokerGrantPropose,
    Release,
    MemoryPermissionPropose,
    BindingEnvelope,
    BindingBackupStart,
    BindingBackupFinish,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub position: Option<u8>,
    pub expires_at: Option<i64>,
}

impl ApiError {
    pub const fn new(status: StatusCode, code: &'static str) -> Self {
        Self {
            status,
            code,
            position: None,
            expires_at: None,
        }
    }

    pub const fn with_position(status: StatusCode, code: &'static str, position: u8) -> Self {
        Self {
            status,
            code,
            position: Some(position),
            expires_at: None,
        }
    }

    pub const fn with_expires_at(status: StatusCode, code: &'static str, expires_at: i64) -> Self {
        Self {
            status,
            code,
            position: None,
            expires_at: Some(expires_at),
        }
    }

    pub const fn invalid_body() -> Self {
        Self::new(StatusCode::BAD_REQUEST, "frontdoor:invalid-body")
    }
}

/// Implementations hold durable ceremonies, owner binding and passkey verification.
/// The principal is the stable owner of this node, not a disposable session ID.
/// An authorized replacement session can resume kept bootstrap ceremonies.
/// Refresh calls use a session principal so phrase guesses cannot lock other sessions.
pub trait Backend: Send + Sync {
    fn state(&self) -> BackendFuture<'_, Result<OwnerState, ApiError>>;

    /// Atomically spend the digest durably; restart must never reopen a claim.
    fn consume_claim(&self, digest: [u8; 32]) -> BackendFuture<'_, Result<(), ApiError>>;

    fn consume_claim_session(
        &self,
        digest: [u8; 32],
        _session: [u8; 32],
        _expires_at: i64,
    ) -> BackendFuture<'_, Result<(), ApiError>> {
        self.consume_claim(digest)
    }

    fn consume_invited_claim_session(
        &self,
        _digest: [u8; 32],
        _handover: [u8; 32],
        _session: [u8; 32],
        _expires_at: i64,
    ) -> BackendFuture<'_, Result<(), ApiError>> {
        Box::pin(async {
            Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "invites:handover-required",
            ))
        })
    }

    /// Verify and spend sign-in with the durable session before issuing its cookie.
    fn signin_session<'a>(
        &'a self,
        _principal: &'a str,
        _body: Value,
        _session: [u8; 32],
        _expires_at: i64,
    ) -> BackendFuture<'a, Result<Value, ApiError>> {
        Box::pin(async {
            Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "frontdoor:session-unavailable",
            ))
        })
    }

    fn session_valid(
        &self,
        _digest: [u8; 32],
        _now: i64,
    ) -> BackendFuture<'_, Result<bool, ApiError>> {
        Box::pin(async { Ok(false) })
    }

    /// Stored sessions require atomic admission in call_owner and with_owner_session.
    fn durable_sessions(&self) -> bool {
        false
    }

    /// Persist only digests, admitting creation against the live parent session.
    fn create_chat_session(
        &self,
        _owner: [u8; 32],
        _session: [u8; 32],
        _expires_at: i64,
    ) -> BackendFuture<'_, Result<(), ApiError>> {
        Box::pin(async {
            Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "frontdoor:session-unavailable",
            ))
        })
    }

    fn chat_session_valid(
        &self,
        _digest: [u8; 32],
        _now: i64,
    ) -> BackendFuture<'_, Result<bool, ApiError>> {
        Box::pin(async { Ok(false) })
    }

    fn revoke_chat_session(&self, _digest: [u8; 32]) -> BackendFuture<'_, Result<(), ApiError>> {
        Box::pin(async {
            Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "frontdoor:session-unavailable",
            ))
        })
    }

    fn revoke_session(&self, _digest: [u8; 32]) -> BackendFuture<'_, Result<(), ApiError>> {
        Box::pin(async { Ok(()) })
    }

    /// Hold the revocation critical section from session validation through the effect.
    fn call_owner<'a>(
        &'a self,
        _session: [u8; 32],
        principal: &'a str,
        operation: Operation,
        body: Value,
    ) -> BackendFuture<'a, Result<Value, ApiError>> {
        if self.durable_sessions() {
            return Box::pin(async {
                Err(ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "frontdoor:session-unavailable",
                ))
            });
        }
        self.call(principal, operation, body)
    }

    /// Run a synchronous front-door effect inside the session revocation critical section.
    fn with_owner_session<'a>(
        &'a self,
        _session: [u8; 32],
        effect: OwnerSessionEffect<'a>,
    ) -> BackendFuture<'a, Result<(), ApiError>> {
        Box::pin(async move {
            if self.durable_sessions() {
                return Err(ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "frontdoor:session-unavailable",
                ));
            }
            effect()
        })
    }

    fn call(
        &self,
        principal: &str,
        operation: Operation,
        body: Value,
    ) -> BackendFuture<'_, Result<Value, ApiError>>;
}

pub fn validate_operation(operation: Operation, body: &Value) -> Result<(), ApiError> {
    validate_values(body, 0)?;
    let fields = object(body)?;
    match operation {
        Operation::EnrolStart
        | Operation::BindingPrepare
        | Operation::BindingRefresh
        | Operation::BindingBackupStart
        | Operation::LogoutEverywhereStart
        | Operation::Slider
        | Operation::Approvals
        | Operation::AuraRetained
        | Operation::AuraExport
        | Operation::Nostr
        | Operation::NostrContacts
        | Operation::NostrInbox
        | Operation::SigninStart
        | Operation::Broker
        | Operation::Release
        | Operation::ReleaseRetry
        | Operation::MemoryPermissionPropose
        | Operation::BindingEnvelope => keys(fields, &[], &[]),
        Operation::EnrolFinish if fields.contains_key("assertion") => {
            keys(fields, &["enrolment_id", "assertion"], &[])?;
            hex_field(fields, "enrolment_id", 32)?;
            validate_assertion(&fields["assertion"])
        }
        Operation::EnrolFinish => {
            keys(fields, &["enrolment_id", "attestation"], &[])?;
            hex_field(fields, "enrolment_id", 32)?;
            let attestation = object(&fields["attestation"])?;
            keys(
                attestation,
                &[
                    "kind",
                    "id",
                    "raw_id",
                    "client_data_json",
                    "attestation_object",
                    "client_extension_results",
                ],
                &[],
            )?;
            literal(attestation, "kind", "passkey-registration")?;
            for name in ["id", "raw_id", "client_data_json", "attestation_object"] {
                binary_field(attestation, name)?;
            }
            if attestation["id"] != attestation["raw_id"] {
                return Err(ApiError::invalid_body());
            }
            object(&attestation["client_extension_results"])?;
            Ok(())
        }
        Operation::BindingConfirm | Operation::BindingRefreshConfirm => {
            if operation == Operation::BindingRefreshConfirm {
                keys(fields, &["ceremony_id", "current_phrase", "words"], &[])?;
                current_phrase(fields)?;
            } else {
                keys(fields, &["ceremony_id", "words"], &[])?;
            }
            hex_field(fields, "ceremony_id", 32)?;
            let words = fields["words"]
                .as_array()
                .filter(|words| words.len() == 7)
                .ok_or_else(ApiError::invalid_body)?;
            if words.iter().any(|word| {
                word.as_str()
                    .is_none_or(|word| word.is_empty() || word.len() > 128)
            }) {
                return Err(ApiError::invalid_body());
            }
            Ok(())
        }
        Operation::BindingCancel | Operation::BindingRefreshCancel => {
            keys(fields, &["ceremony_id"], &[])?;
            hex_field(fields, "ceremony_id", 32)
        }
        Operation::BindingBackupFinish => {
            keys(
                fields,
                &["backup_id", "current_phrase", "assertion", "prf_output"],
                &[],
            )?;
            hex_field(fields, "backup_id", 32)?;
            current_phrase(fields)?;
            binary_field(fields, "prf_output")?;
            if string_field(fields, "prf_output")?.len() != 43 {
                return Err(ApiError::invalid_body());
            }
            validate_assertion(&body["assertion"])
        }
        Operation::LogoutEverywhereFinish => {
            keys(fields, &["ceremony_id", "assertion"], &[])?;
            hex_field(fields, "ceremony_id", 32)?;
            validate_assertion(&body["assertion"])
        }
        Operation::BindingRefreshPrepare => {
            keys(fields, &["ceremony_id", "current_phrase"], &["assertion"])?;
            hex_field(fields, "ceremony_id", 32)?;
            current_phrase(fields)?;
            validate_assertion(&body["assertion"])
        }
        Operation::BindingRefreshResume => {
            keys(fields, &["ceremony_id", "current_phrase"], &[])?;
            hex_field(fields, "ceremony_id", 32)?;
            current_phrase(fields)
        }
        Operation::ApprovalChallenge
        | Operation::ApprovalDespiteChallenge
        | Operation::ApprovalRetireChallenge
        | Operation::ApprovalReconcileChallenge => {
            keys(fields, &["id"], &[])?;
            hex_field(fields, "id", 32)
        }
        Operation::ApprovalDespiteDecide
        | Operation::ApprovalRetire
        | Operation::ApprovalReconcile => {
            keys(fields, &["id"], &["assertion"])?;
            hex_field(fields, "id", 32)?;
            validate_assertion(&body["assertion"])
        }
        Operation::ApprovalDecide => {
            let approve = fields
                .get("approve")
                .and_then(Value::as_bool)
                .ok_or_else(ApiError::invalid_body)?;
            hex_field(fields, "id", 32)?;
            if !approve {
                return keys(fields, &["id", "approve"], &[]);
            }
            let refused =
                || ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "aumlok:assertion-refused");
            keys(fields, &["id", "approve", "assertion"], &[]).map_err(|_| refused())?;
            let assertion = object(&fields["assertion"]).map_err(|_| refused())?;
            keys(
                assertion,
                &[
                    "kind",
                    "credential_id",
                    "client_data_json",
                    "authenticator_data",
                    "signature",
                ],
                &["user_handle"],
            )
            .map_err(|_| refused())?;
            literal(assertion, "kind", "passkey").map_err(|_| refused())?;
            for name in [
                "credential_id",
                "client_data_json",
                "authenticator_data",
                "signature",
            ] {
                binary_field(assertion, name).map_err(|_| refused())?;
            }
            if let Some(handle) = assertion.get("user_handle") {
                if !handle.is_null() {
                    binary_field(assertion, "user_handle").map_err(|_| refused())?;
                }
            }
            Ok(())
        }
        Operation::SigninFinish => {
            keys(fields, &["ceremony_id", "assertion"], &[])?;
            hex_field(fields, "ceremony_id", 32)?;
            validate_assertion(&fields["assertion"])
        }
        Operation::NostrContactPropose => {
            keys(fields, &["npub", "label", "action"], &[])?;
            npub_field(fields)?;
            let label = string_field(fields, "label")?;
            if label.trim().is_empty() || label.len() > 128 || label.chars().any(char::is_control) {
                return Err(ApiError::invalid_body());
            }
            if !matches!(string_field(fields, "action")?, "add" | "remove") {
                return Err(ApiError::invalid_body());
            }
            Ok(())
        }
        Operation::NostrSendPropose => {
            keys(fields, &["npub", "content"], &[])?;
            npub_field(fields)?;
            let content = string_field(fields, "content")?;
            if content.is_empty() || content.len() > 1024 {
                return Err(ApiError::invalid_body());
            }
            Ok(())
        }
        Operation::NostrSendPreview => {
            keys(fields, &["id"], &[])?;
            hex_field(fields, "id", 32)
        }
        Operation::BrokerKeyPropose => {
            keys(fields, &["key_sha256"], &[])?;
            hex_field(fields, "key_sha256", 64)
        }
        Operation::BrokerKeyRedeem => {
            // Without an id the supervisor delivers to the applied record matching the key.
            keys(fields, &["key"], &["id"])?;
            if fields.contains_key("id") {
                hex_field(fields, "id", 32)?;
            }
            let key = string_field(fields, "key")?;
            if key.is_empty() || key.len() > 4096 || key.contains(['\r', '\n', '\0']) {
                return Err(ApiError::invalid_body());
            }
            Ok(())
        }
        Operation::SliderPropose => {
            keys(fields, &["mode", "targets", "max_count", "hours"], &[])?;
            if !["ask", "risky", "limits"].contains(&string_field(fields, "mode")?) {
                return Err(ApiError::invalid_body());
            }
            let targets = fields["targets"]
                .as_array()
                .ok_or_else(ApiError::invalid_body)?;
            if targets.len() > 32
                || targets.iter().any(|target| {
                    !target
                        .as_str()
                        .is_some_and(|text| !text.is_empty() && text.len() <= 200)
                })
            {
                return Err(ApiError::invalid_body());
            }
            integer(fields, "max_count", 0, 1_000_000)?;
            integer(fields, "hours", 1, 24)
        }
        Operation::BrokerGrantPropose => {
            let refused =
                || ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "broker:invalid-grant");
            keys(
                fields,
                &[
                    "model",
                    "cap_microusd",
                    "per_request_cap_microusd",
                    "max_requests",
                    "hours",
                ],
                &[],
            )
            .map_err(|_| refused())?;
            if string_field(fields, "model")
                .map_err(|_| refused())?
                .is_empty()
            {
                return Err(refused());
            }
            for field in ["cap_microusd", "per_request_cap_microusd", "max_requests"] {
                integer(fields, field, 1, canon::MAX_SAFE_INTEGER as u64).map_err(|_| refused())?;
            }
            integer(fields, "hours", 1, 24).map_err(|_| refused())?;
            if fields["per_request_cap_microusd"].as_u64() > fields["cap_microusd"].as_u64() {
                return Err(refused());
            }
            Ok(())
        }
        Operation::AuraHead => {
            keys(fields, &[], &["since"])?;
            optional_integer(fields, "since", 0, canon::MAX_SAFE_INTEGER as u64)
        }
        Operation::AuraRecent => {
            keys(fields, &[], &["limit"])?;
            optional_integer(fields, "limit", 1, 100)
        }
        Operation::MemoryRecall => {
            keys(fields, &["query", "limit"], &[])?;
            string_field(fields, "query")?;
            integer(fields, "limit", 1, canon::MAX_SAFE_INTEGER as u64)
        }
        Operation::MemoryDemote => {
            keys(fields, &["note_id", "reason"], &[])?;
            hex_field(fields, "note_id", 32)?;
            string_field(fields, "reason").map(|_| ())
        }
    }
}

fn validate_assertion(value: &Value) -> Result<(), ApiError> {
    let refused = || ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "aumlok:assertion-refused");
    let assertion = object(value).map_err(|_| refused())?;
    keys(
        assertion,
        &[
            "kind",
            "credential_id",
            "client_data_json",
            "authenticator_data",
            "signature",
        ],
        &["user_handle"],
    )
    .map_err(|_| refused())?;
    literal(assertion, "kind", "passkey").map_err(|_| refused())?;
    for name in [
        "credential_id",
        "client_data_json",
        "authenticator_data",
        "signature",
    ] {
        binary_field(assertion, name).map_err(|_| refused())?;
    }
    if assertion
        .get("user_handle")
        .is_some_and(|handle| !handle.is_null())
    {
        binary_field(assertion, "user_handle").map_err(|_| refused())?;
    }
    Ok(())
}

fn validate_values(value: &Value, depth: usize) -> Result<(), ApiError> {
    if depth > 64 {
        return Err(ApiError::invalid_body());
    }
    match value {
        Value::Object(fields) => {
            if fields.contains_key("dev_bypass") {
                return Err(ApiError::invalid_body());
            }
            for value in fields.values() {
                validate_values(value, depth + 1)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                validate_values(value, depth + 1)?;
            }
        }
        Value::Number(number)
            if number.as_i64().is_none_or(|n| {
                !(-canon::MAX_SAFE_INTEGER..=canon::MAX_SAFE_INTEGER).contains(&n)
            }) =>
        {
            return Err(ApiError::invalid_body());
        }
        _ => {}
    }
    Ok(())
}

fn object(body: &Value) -> Result<&Map<String, Value>, ApiError> {
    body.as_object().ok_or_else(ApiError::invalid_body)
}

fn keys(fields: &Map<String, Value>, required: &[&str], optional: &[&str]) -> Result<(), ApiError> {
    if required.iter().any(|name| !fields.contains_key(*name))
        || fields
            .keys()
            .any(|name| !required.contains(&name.as_str()) && !optional.contains(&name.as_str()))
    {
        return Err(ApiError::invalid_body());
    }
    Ok(())
}

fn string_field<'a>(fields: &'a Map<String, Value>, name: &str) -> Result<&'a str, ApiError> {
    fields
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(ApiError::invalid_body)
}

fn npub_field(fields: &Map<String, Value>) -> Result<(), ApiError> {
    let npub = string_field(fields, "npub")?;
    let Some(data) = npub.strip_prefix("npub1") else {
        return Err(ApiError::invalid_body());
    };
    if data.len() != 58
        || !data
            .bytes()
            .all(|byte| b"023456789acdefghjklmnpqrstuvwxyz".contains(&byte))
    {
        return Err(ApiError::invalid_body());
    }
    Ok(())
}

fn current_phrase(fields: &Map<String, Value>) -> Result<(), ApiError> {
    let phrase = string_field(fields, "current_phrase")?;
    if phrase.is_empty() || phrase.len() > 1024 {
        return Err(ApiError::invalid_body());
    }
    Ok(())
}

fn literal(fields: &Map<String, Value>, name: &str, expected: &str) -> Result<(), ApiError> {
    if string_field(fields, name)? != expected {
        return Err(ApiError::invalid_body());
    }
    Ok(())
}

fn hex_field(fields: &Map<String, Value>, name: &str, len: usize) -> Result<(), ApiError> {
    let value = string_field(fields, name)?;
    if value.len() != len
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ApiError::invalid_body());
    }
    Ok(())
}

fn binary_field(fields: &Map<String, Value>, name: &str) -> Result<(), ApiError> {
    let value = string_field(fields, name)?;
    if value.is_empty() || value.len() > 65_536 || value.len() % 4 == 1 {
        return Err(ApiError::invalid_body());
    }
    let mut final_digit = 0;
    for byte in value.bytes() {
        final_digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return Err(ApiError::invalid_body()),
        };
    }
    if (value.len() % 4 == 2 && final_digit & 15 != 0)
        || (value.len() % 4 == 3 && final_digit & 3 != 0)
    {
        return Err(ApiError::invalid_body());
    }
    Ok(())
}

fn integer(fields: &Map<String, Value>, name: &str, min: u64, max: u64) -> Result<(), ApiError> {
    if fields
        .get(name)
        .and_then(Value::as_u64)
        .is_none_or(|value| !(min..=max).contains(&value))
    {
        return Err(ApiError::invalid_body());
    }
    Ok(())
}

fn optional_integer(
    fields: &Map<String, Value>,
    name: &str,
    min: u64,
    max: u64,
) -> Result<(), ApiError> {
    if fields.contains_key(name) {
        integer(fields, name, min, max)?;
    }
    Ok(())
}

pub const TEST_PROPOSAL_ID: &str = "11111111111111111111111111111111";
pub const TEST_NOTE_ID: &str = "22222222222222222222222222222222";
const TEST_SUBJECT: &str =
    "aukora:1:0000000000000000000000000000000000000000000000000000000000000001";
const TEST_WORDS: [&str; 7] = [
    "planet",
    "pine",
    "linden",
    "accord",
    "neighbor",
    "eclipse",
    "terraform",
];
const TEST_REFRESH_WORDS: [&str; 7] = [
    "planet",
    "pebble",
    "lagoon",
    "alliance",
    "neighbor",
    "ether",
    "telescope",
];
const CEREMONY_LIFETIME: Duration = Duration::from_secs(600);

/// Process-local fixtures only; this backend performs no cryptographic verification.
pub struct InMemoryTestBackend {
    node: String,
    owner_host: String,
    inner: Mutex<TestState>,
}

struct TestState {
    state: BootstrapState,
    claims: BTreeMap<[u8; 32], TestClaim>,
    enrolment: Option<TestCeremony>,
    binding: Option<TestCeremony>,
    refresh_challenge: Option<TestChallenge>,
    refresh: Option<TestCeremony>,
    words: Vec<String>,
    next_id: u64,
    pending: bool,
    challenge: Option<TestChallenge>,
    fenced: Option<&'static str>,
    actions: BTreeMap<&'static str, TestChallenge>,
    note_demoted: bool,
    rows: Vec<Value>,
    hashes: Vec<[u8; 32]>,
}

struct TestClaim {
    expires: Instant,
    spent: bool,
}

struct TestCeremony {
    id: String,
    principal: String,
    expires: Instant,
    response: Value,
}

struct TestChallenge {
    principal: String,
    expires: Instant,
    assertion: Value,
    response: Value,
}

impl InMemoryTestBackend {
    pub fn new(node: impl Into<String>, owner_host: impl Into<String>) -> Self {
        Self::with_state(node, owner_host, BootstrapState::ClaimOpen)
    }

    pub fn with_state(
        node: impl Into<String>,
        owner_host: impl Into<String>,
        state: BootstrapState,
    ) -> Self {
        let mut inner = TestState {
            state,
            claims: BTreeMap::new(),
            enrolment: None,
            binding: None,
            refresh_challenge: None,
            refresh: None,
            words: TEST_WORDS.iter().map(|word| (*word).to_owned()).collect(),
            next_id: 1,
            pending: true,
            challenge: None,
            fenced: None,
            actions: BTreeMap::new(),
            note_demoted: false,
            rows: Vec::new(),
            hashes: Vec::new(),
        };
        inner.append("boot.facts", "supervisor", "fact");
        Self {
            node: node.into(),
            owner_host: owner_host.into(),
            inner: Mutex::new(inner),
        }
    }

    pub fn register_claim(&self, token: &str, ttl: Duration) {
        let digest = Sha256::digest(token.as_bytes()).into();
        self.inner
            .lock()
            .expect("test backend mutex poisoned")
            .claims
            .entry(digest)
            .or_insert(TestClaim {
                expires: Instant::now() + ttl,
                spent: false,
            });
    }

    pub fn attestation_fixture() -> Value {
        json!({
            "kind": "passkey-registration",
            "id": "dGVzdC1jcmVkZW50aWFs",
            "raw_id": "dGVzdC1jcmVkZW50aWFs",
            "client_data_json": "dGVzdC1jbGllbnQtZGF0YQ",
            "attestation_object": "dGVzdC1hdHRlc3RhdGlvbg",
            "client_extension_results": {}
        })
    }

    pub fn assertion_fixture(&self, id: &str) -> Result<Value, ApiError> {
        if id != TEST_PROPOSAL_ID {
            return Err(ApiError::new(
                StatusCode::NOT_FOUND,
                "gate:unknown-proposal",
            ));
        }
        self.inner
            .lock()
            .expect("test backend mutex poisoned")
            .challenge
            .as_ref()
            .map(|challenge| challenge.assertion.clone())
            .ok_or_else(|| ApiError::new(StatusCode::GONE, "gate:challenge-expired"))
    }

    pub fn action_assertion_fixture(&self, id: &str, action: &str) -> Result<Value, ApiError> {
        if id != TEST_PROPOSAL_ID {
            return Err(ApiError::new(
                StatusCode::NOT_FOUND,
                "gate:unknown-proposal",
            ));
        }
        self.inner
            .lock()
            .expect("test backend mutex poisoned")
            .actions
            .get(action)
            .map(|challenge| challenge.assertion.clone())
            .ok_or_else(|| ApiError::new(StatusCode::GONE, "gate:challenge-expired"))
    }

    pub fn refresh_assertion_fixture(&self, id: &str) -> Result<Value, ApiError> {
        self.inner
            .lock()
            .expect("test backend mutex poisoned")
            .refresh_challenge
            .as_ref()
            .filter(|challenge| challenge.response["ceremony_id"] == id)
            .map(|challenge| challenge.assertion.clone())
            .ok_or_else(|| ApiError::new(StatusCode::FORBIDDEN, "aumlok:ceremony-unknown"))
    }

    #[cfg(test)]
    pub(crate) fn fence_proposal(&self, state: &'static str) {
        assert!(matches!(state, "incomplete" | "conflict"));
        let mut inner = self.inner.lock().expect("test backend mutex poisoned");
        inner.pending = false;
        inner.challenge = None;
        inner.fenced = Some(state);
    }

    pub(crate) fn execute(
        &self,
        principal: &str,
        operation: Operation,
        body: Value,
    ) -> Result<Value, ApiError> {
        validate_operation(operation, &body)?;
        if principal.is_empty() {
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "frontdoor:session-required",
            ));
        }
        let mut inner = self.inner.lock().expect("test backend mutex poisoned");
        if !inner.state.is_bound()
            && !matches!(
                operation,
                Operation::EnrolStart
                    | Operation::EnrolFinish
                    | Operation::BindingPrepare
                    | Operation::BindingConfirm
                    | Operation::BindingCancel
            )
        {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "aumlok:binding-required",
            ));
        }
        match operation {
            Operation::LogoutEverywhereStart | Operation::LogoutEverywhereFinish => {
                Err(ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "frontdoor:session-unavailable",
                ))
            }
            Operation::EnrolStart => {
                if inner.state != BootstrapState::ClaimOpen {
                    return Err(ApiError::new(
                        StatusCode::CONFLICT,
                        "aumlok:enrolment-closed",
                    ));
                }
                if let Some(ceremony) = inner.enrolment.as_ref() {
                    ceremony.check(principal, &ceremony.id, "aumlok:enrolment-unknown")?;
                    return Ok(ceremony.response.clone());
                }
                let id = inner.id();
                let challenge = base64url(&Sha256::digest(id.as_bytes()));
                let response = json!({"enrolment_id": id, "public_key": {
                    "challenge": challenge,
                    "rp": {"name": "Aukora test fixture", "id": self.owner_host},
                    "user": {"id": base64url(self.node.as_bytes()), "name": "owner", "displayName": "Owner"},
                    "pubKeyCredParams": [{"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -8}],
                    "authenticatorSelection": {"residentKey": "required", "userVerification": "required"},
                    "attestation": "none", "timeout": 60000
                }});
                inner.enrolment = Some(TestCeremony::new(id, principal, response.clone()));
                Ok(response)
            }
            Operation::EnrolFinish => {
                if inner.state != BootstrapState::ClaimOpen {
                    return Err(ApiError::new(
                        StatusCode::CONFLICT,
                        "aumlok:enrolment-closed",
                    ));
                }
                inner
                    .enrolment
                    .as_ref()
                    .ok_or_else(|| {
                        ApiError::new(StatusCode::FORBIDDEN, "aumlok:enrolment-unknown")
                    })?
                    .check(
                        principal,
                        string(&body, "enrolment_id"),
                        "aumlok:enrolment-unknown",
                    )?;
                if body["attestation"] != Self::attestation_fixture() {
                    return Err(ApiError::new(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "aumlok:attestation-refused",
                    ));
                }
                inner.enrolment = None;
                inner.state = BootstrapState::Enrolled;
                inner.append("aumlok.enrol", "owner", "terminal");
                Ok(json!({"ok": true, "state": "enrolled"}))
            }
            Operation::BindingPrepare => {
                if inner.state.is_bound() {
                    return Err(ApiError::new(StatusCode::CONFLICT, "aumlok:already-bound"));
                }
                if inner.state != BootstrapState::Enrolled {
                    return Err(ApiError::new(
                        StatusCode::FORBIDDEN,
                        "aumlok:enrolment-required",
                    ));
                }
                if let Some(ceremony) = inner.binding.as_ref() {
                    ceremony.check(principal, &ceremony.id, "aumlok:ceremony-unknown")?;
                    return Ok(ceremony.response.clone());
                }
                let id = inner.id();
                let response = json!({"ceremony_id": id, "words": TEST_WORDS,
                    "entropy_bits": 0, "expires_at": expiry_ms(CEREMONY_LIFETIME)});
                inner.binding = Some(TestCeremony::new(id, principal, response.clone()));
                Ok(response)
            }
            Operation::BindingConfirm => {
                let ceremony = inner.binding.as_ref().ok_or_else(|| {
                    ApiError::new(StatusCode::FORBIDDEN, "aumlok:ceremony-unknown")
                })?;
                ceremony.check(
                    principal,
                    string(&body, "ceremony_id"),
                    "aumlok:ceremony-unknown",
                )?;
                for (index, expected) in TEST_WORDS.iter().enumerate() {
                    if body["words"][index].as_str() != Some(*expected) {
                        return Err(ApiError::with_position(
                            StatusCode::UNPROCESSABLE_ENTITY,
                            "aumlok:word-mismatch",
                            (index + 1) as u8,
                        ));
                    }
                }
                inner.binding = None;
                inner.state = BootstrapState::Bound;
                inner.append("aumlok.bind", "owner", "terminal");
                Ok(json!({"ok": true, "state": "bound", "subject": TEST_SUBJECT}))
            }
            Operation::BindingCancel => {
                inner
                    .binding
                    .as_ref()
                    .ok_or_else(|| ApiError::new(StatusCode::FORBIDDEN, "aumlok:ceremony-unknown"))?
                    .check(
                        principal,
                        string(&body, "ceremony_id"),
                        "aumlok:ceremony-unknown",
                    )?;
                inner.binding = None;
                Ok(json!({"ok": true}))
            }
            Operation::BindingRefresh => {
                let id = inner.id();
                let card = json!({"v": 1, "risk": "critical", "says": "Replace the binding phrase.",
                    "facts": [["Identity", TEST_SUBJECT]], "from_to": {}, "model_note": ""});
                let display = hex(&Sha256::digest(canonical(&card)?));
                let content = json!({"v": 1, "node": self.node, "target": "aumlok/binding/refresh",
                    "base_sha256": hex(&Sha256::digest(b"synthetic binding envelope")),
                    "new_sha256": hex(&Sha256::digest(canonical(&json!({"v": 1, "ceremony_id": id}))?)),
                    "cell": null});
                let mut operation_bytes = b"aukora:operation-content:v1\0".to_vec();
                operation_bytes.extend(canonical(&content)?);
                let auth = json!({"v": 1, "node": self.node, "subject": TEST_SUBJECT,
                    "op": "permission", "proposal": id, "target": content["target"],
                    "base_sha256": content["base_sha256"], "new_sha256": content["new_sha256"],
                    "cell": null, "display_sha256": display,
                    "challenge": hex(&Sha256::digest(inner.id().as_bytes())), "expires_at": expiry_ms(CEREMONY_LIFETIME),
                    "epoch": 1, "operation": hex(&Sha256::digest(operation_bytes))});
                let mut authorization = b"aukora:owner-authorization:v1\0".to_vec();
                authorization.extend(canonical(&auth)?);
                let challenge = base64url(&Sha256::digest(authorization));
                let client_data = json!({"type": "webauthn.get", "challenge": challenge,
                    "origin": format!("https://{}", self.owner_host)});
                let assertion = json!({"kind": "passkey", "credential_id": "dGVzdC1jcmVkZW50aWFs",
                    "client_data_json": base64url(&canonical(&client_data)?), "authenticator_data": "AA",
                    "signature": "dGVzdC1zaWduYXR1cmU", "user_handle": null});
                let response = json!({"ceremony_id": id, "display_sha256": display, "auth": auth,
                    "card": card, "public_key": {"challenge": challenge, "rpId": self.owner_host,
                        "allowCredentials": [{"type": "public-key", "id": "dGVzdC1jcmVkZW50aWFs"}],
                        "userVerification": "required", "timeout": 60000}});
                inner.refresh_challenge = Some(TestChallenge {
                    principal: principal.to_owned(),
                    expires: Instant::now() + CEREMONY_LIFETIME,
                    assertion,
                    response: response.clone(),
                });
                Ok(response)
            }
            Operation::BindingRefreshPrepare => {
                // A refused current phrase cannot reuse this assertion.
                let challenge = inner.refresh_challenge.take().ok_or_else(|| {
                    ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "aumlok:assertion-refused")
                })?;
                if challenge.response["ceremony_id"] != body["ceremony_id"]
                    || Instant::now() >= challenge.expires
                    || challenge.principal != principal
                {
                    return Err(ApiError::new(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "aumlok:assertion-refused",
                    ));
                }
                let mut assertion = body["assertion"].clone();
                assertion
                    .as_object_mut()
                    .expect("operation validated assertion")
                    .entry("user_handle")
                    .or_insert(Value::Null);
                if assertion != challenge.assertion {
                    return Err(ApiError::new(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "aumlok:assertion-refused",
                    ));
                }
                if string(&body, "current_phrase") != inner.words.join(" ") {
                    return Err(ApiError::new(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "aumlok:current-phrase",
                    ));
                }
                if inner.refresh.is_some() {
                    return Err(ApiError::new(StatusCode::CONFLICT, "aumlok:refresh-live"));
                }
                let id = inner.id();
                let replacement = if inner.words == TEST_REFRESH_WORDS {
                    TEST_WORDS
                } else {
                    TEST_REFRESH_WORDS
                };
                let response = json!({"ceremony_id": id, "words": replacement,
                    "entropy_bits": 0, "expires_at": expiry_ms(CEREMONY_LIFETIME)});
                inner.refresh = Some(TestCeremony::new(id, principal, response.clone()));
                inner.append("aumlok.bind", "owner", "fact");
                Ok(response)
            }
            Operation::BindingRefreshCancel => {
                let ceremony = inner.refresh.as_ref().ok_or_else(|| {
                    ApiError::new(StatusCode::FORBIDDEN, "aumlok:ceremony-unknown")
                })?;
                ceremony.check(
                    principal,
                    string(&body, "ceremony_id"),
                    "aumlok:ceremony-unknown",
                )?;
                inner.refresh = None;
                Ok(json!({"ok":true}))
            }
            Operation::BindingRefreshResume | Operation::BindingRefreshConfirm => {
                let ceremony = inner.refresh.as_ref().ok_or_else(|| {
                    ApiError::new(StatusCode::FORBIDDEN, "aumlok:ceremony-unknown")
                })?;
                ceremony.check(
                    principal,
                    string(&body, "ceremony_id"),
                    "aumlok:ceremony-unknown",
                )?;
                if string(&body, "current_phrase") != inner.words.join(" ") {
                    return Err(ApiError::new(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "aumlok:current-phrase",
                    ));
                }
                if operation == Operation::BindingRefreshResume {
                    return Ok(ceremony.response.clone());
                }
                for (index, expected) in ceremony.response["words"]
                    .as_array()
                    .expect("fixture words array")
                    .iter()
                    .enumerate()
                {
                    if body["words"][index] != *expected {
                        return Err(ApiError::with_position(
                            StatusCode::UNPROCESSABLE_ENTITY,
                            "aumlok:word-mismatch",
                            (index + 1) as u8,
                        ));
                    }
                }
                inner.words = ceremony.response["words"]
                    .as_array()
                    .expect("fixture words array")
                    .iter()
                    .map(|word| word.as_str().expect("fixture word string").to_owned())
                    .collect();
                inner.refresh = None;
                inner.append("aumlok.bind", "owner", "terminal");
                Ok(json!({"ok": true, "state": "bound", "subject": TEST_SUBJECT}))
            }
            Operation::Approvals => {
                let pending = if inner.pending || inner.fenced.is_some() {
                    vec![
                        json!({"id": TEST_PROPOSAL_ID, "state": inner.fenced.unwrap_or("pending"),
                            "operator_only": false, "reviewed": inner.challenge.is_some(),
                            "display_sha256": display_hash()?, "card": test_card()}),
                    ]
                } else {
                    Vec::new()
                };
                Ok(json!({"pending": pending}))
            }
            Operation::ApprovalDespiteChallenge
            | Operation::ApprovalDespiteDecide
            | Operation::ReleaseRetry => Err(ApiError::new(
                StatusCode::CONFLICT,
                "immune:release-unavailable",
            )),
            Operation::ApprovalChallenge => {
                inner.check_proposal(string(&body, "id"))?;
                if let Some(challenge) = inner.challenge.as_ref() {
                    if challenge.principal == principal && Instant::now() < challenge.expires {
                        return Ok(challenge.response.clone());
                    }
                    return Err(ApiError::new(StatusCode::GONE, "gate:challenge-expired"));
                }
                let display = display_hash()?;
                let content = json!({"v": 1, "node": self.node, "target": "workspace/note.txt",
                    "base_sha256": "absent", "new_sha256": hex(&Sha256::digest(b"test note\n")), "cell": null});
                let mut operation_bytes = b"aukora:operation-content:v1\0".to_vec();
                operation_bytes.extend(canonical(&content)?);
                let auth = json!({"v": 1, "node": self.node, "subject": TEST_SUBJECT,
                    "op": "apply", "proposal": TEST_PROPOSAL_ID, "target": content["target"],
                    "base_sha256": content["base_sha256"], "new_sha256": content["new_sha256"],
                    "cell": null, "display_sha256": display,
                    "challenge": hex(&Sha256::digest(inner.id().as_bytes())), "expires_at": expiry_ms(CEREMONY_LIFETIME),
                    "epoch": 1, "operation": hex(&Sha256::digest(operation_bytes))});
                let mut authorization = b"aukora:owner-authorization:v1\0".to_vec();
                authorization.extend(canonical(&auth)?);
                let challenge = base64url(&Sha256::digest(authorization));
                let client_data = json!({"type": "webauthn.get", "challenge": challenge,
                    "origin": format!("https://{}", self.owner_host)});
                let assertion = json!({"kind": "passkey", "credential_id": "dGVzdC1jcmVkZW50aWFs",
                    "client_data_json": base64url(&canonical(&client_data)?), "authenticator_data": "AA",
                    "signature": "dGVzdC1zaWduYXR1cmU", "user_handle": null});
                let response = json!({"id": TEST_PROPOSAL_ID, "display_sha256": display, "auth": auth,
                    "public_key": {"challenge": challenge, "rpId": self.owner_host,
                        "allowCredentials": [{"type": "public-key", "id": "dGVzdC1jcmVkZW50aWFs"}],
                        "userVerification": "required", "timeout": 60000}});
                inner.challenge = Some(TestChallenge {
                    principal: principal.to_owned(),
                    expires: Instant::now() + CEREMONY_LIFETIME,
                    assertion,
                    response: response.clone(),
                });
                Ok(response)
            }
            Operation::ApprovalDecide => {
                inner.check_proposal(string(&body, "id"))?;
                if body["approve"] == false {
                    if inner.challenge.is_some() {
                        return Err(ApiError::new(
                            StatusCode::CONFLICT,
                            "gate:owner-retirement-required",
                        ));
                    }
                    inner.pending = false;
                    inner.challenge = None;
                    inner.append("gate.refuse", "owner", "terminal");
                    return Ok(json!({"ok": true, "state": "refused"}));
                }
                let challenge = inner
                    .challenge
                    .take()
                    .ok_or_else(|| ApiError::new(StatusCode::GONE, "gate:challenge-expired"))?;
                if Instant::now() >= challenge.expires {
                    return Err(ApiError::new(StatusCode::GONE, "gate:challenge-expired"));
                }
                let mut assertion = body["assertion"].clone();
                assertion
                    .as_object_mut()
                    .expect("operation validated assertion")
                    .entry("user_handle")
                    .or_insert(Value::Null);
                if challenge.principal != principal || challenge.assertion != assertion {
                    return Err(ApiError::new(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "aumlok:assertion-refused",
                    ));
                }
                inner.pending = false;
                let seq = inner.append("gate.apply", "owner", "terminal");
                Ok(json!({"ok": true, "state": "applied", "seq": seq}))
            }
            Operation::ApprovalRetireChallenge | Operation::ApprovalReconcileChallenge => {
                let action = if operation == Operation::ApprovalRetireChallenge {
                    "retire"
                } else {
                    "reconcile"
                };
                inner.check_action(string(&body, "id"), action)?;
                let card = json!({"v": 1, "risk": "critical", "says": if action == "retire" {
                    "Retire this pending proposal without applying it."
                } else {
                    "Close this observed outcome without retrying it; adopt the current target hash as the new base."
                }, "facts": [["operation", action], ["proposal", TEST_PROPOSAL_ID]],
                    "from_to": {"state": inner.fenced.unwrap_or("pending"), "operation": action},
                    "model_note": ""});
                let display = hex(&Sha256::digest(canonical(&card)?));
                let content = json!({"v": 1, "node": self.node, "target": "workspace/note.txt",
                    "base_sha256": "absent", "new_sha256": hex(&Sha256::digest(b"test note\n")), "cell": null});
                let mut operation_bytes = b"aukora:operation-content:v1\0".to_vec();
                operation_bytes.extend(canonical(&content)?);
                let auth = json!({"v": 1, "node": self.node, "subject": TEST_SUBJECT,
                    "op": action, "proposal": TEST_PROPOSAL_ID, "target": content["target"],
                    "base_sha256": content["base_sha256"], "new_sha256": content["new_sha256"],
                    "cell": null, "display_sha256": display,
                    "challenge": hex(&Sha256::digest(inner.id().as_bytes())), "expires_at": expiry_ms(CEREMONY_LIFETIME),
                    "epoch": 1, "operation": hex(&Sha256::digest(operation_bytes))});
                let mut authorization = b"aukora:owner-authorization:v1\0".to_vec();
                authorization.extend(canonical(&auth)?);
                let challenge = base64url(&Sha256::digest(authorization));
                let client_data = json!({"type": "webauthn.get", "challenge": challenge,
                    "origin": format!("https://{}", self.owner_host)});
                let assertion = json!({"kind": "passkey", "credential_id": "dGVzdC1jcmVkZW50aWFs",
                    "client_data_json": base64url(&canonical(&client_data)?), "authenticator_data": "AA",
                    "signature": "dGVzdC1zaWduYXR1cmU", "user_handle": null});
                let response = json!({"id": TEST_PROPOSAL_ID, "display_sha256": display, "auth": auth,
                    "card": card, "public_key": {"challenge": challenge, "rpId": self.owner_host,
                        "allowCredentials": [{"type": "public-key", "id": "dGVzdC1jcmVkZW50aWFs"}],
                        "userVerification": "required", "timeout": 60000}});
                inner.actions.insert(
                    action,
                    TestChallenge {
                        principal: principal.to_owned(),
                        expires: Instant::now() + CEREMONY_LIFETIME,
                        assertion,
                        response: response.clone(),
                    },
                );
                Ok(response)
            }
            Operation::ApprovalRetire | Operation::ApprovalReconcile => {
                let action = if operation == Operation::ApprovalRetire {
                    "retire"
                } else {
                    "reconcile"
                };
                inner.check_action(string(&body, "id"), action)?;
                let challenge = inner
                    .actions
                    .remove(action)
                    .ok_or_else(|| ApiError::new(StatusCode::GONE, "gate:challenge-expired"))?;
                if Instant::now() >= challenge.expires {
                    return Err(ApiError::new(StatusCode::GONE, "gate:challenge-expired"));
                }
                let mut assertion = body["assertion"].clone();
                assertion
                    .as_object_mut()
                    .expect("operation validated assertion")
                    .entry("user_handle")
                    .or_insert(Value::Null);
                if challenge.principal != principal || challenge.assertion != assertion {
                    return Err(ApiError::new(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "aumlok:assertion-refused",
                    ));
                }
                if action == "retire" {
                    inner.pending = false;
                    inner.challenge = None;
                    let seq = inner.append("gate.retire", "owner", "terminal");
                    Ok(json!({"ok": true, "state": "retired", "seq": seq}))
                } else {
                    inner.fenced.take().expect("action checked fenced state");
                    let seq = inner.append("gate.recover", "owner", "fact");
                    Ok(json!({"ok": true, "state": "reconciled", "seq": seq}))
                }
            }
            Operation::AuraHead => {
                let n = inner.hashes.len();
                let since = body
                    .get("since")
                    .and_then(Value::as_u64)
                    .unwrap_or(n as u64);
                if since > n as u64 {
                    return Err(ApiError::invalid_body());
                }
                Ok(inner.presented_head(since as usize))
            }
            Operation::AuraRecent => {
                let limit = body.get("limit").and_then(Value::as_u64).unwrap_or(20) as usize;
                let rows = inner
                    .rows
                    .iter()
                    .rev()
                    .take(limit)
                    .cloned()
                    .collect::<Vec<_>>();
                Ok(json!({"rows": rows, "head_seq": inner.rows.len()}))
            }
            Operation::AuraRetained => Ok(inner.retained_head()),
            Operation::Nostr
            | Operation::NostrContacts
            | Operation::NostrContactPropose
            | Operation::NostrSendPropose
            | Operation::NostrSendPreview
            | Operation::NostrInbox => Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "nostr:identity-unavailable",
            )),
            // Production supplies a full authenticated snapshot through this operation.
            Operation::AuraExport => Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "aura:export-unavailable",
            )),
            Operation::MemoryRecall => {
                let query = string(&body, "query").to_lowercase();
                let text = "An explicitly synthetic owner note.";
                if inner.note_demoted || !text.to_lowercase().contains(&query) {
                    return Ok(json!({"result": "empty", "items": []}));
                }
                Ok(
                    json!({"result": "found", "items": [{"note_id": TEST_NOTE_ID,
                    "text": text, "cite_seq": 1, "tier": "owner"}]}),
                )
            }
            Operation::SigninStart
            | Operation::SigninFinish
            | Operation::Broker
            | Operation::BrokerKeyPropose
            | Operation::BrokerKeyRedeem
            | Operation::Slider
            | Operation::SliderPropose
            | Operation::BrokerGrantPropose
            | Operation::Release
            | Operation::MemoryPermissionPropose
            | Operation::BindingEnvelope
            | Operation::BindingBackupStart
            | Operation::BindingBackupFinish => Err(ApiError::new(
                StatusCode::NOT_IMPLEMENTED,
                "frontdoor:test-route-unavailable",
            )),
            Operation::MemoryDemote => {
                if string(&body, "note_id") != TEST_NOTE_ID {
                    return Err(ApiError::new(StatusCode::NOT_FOUND, "kira:unknown-note"));
                }
                if inner.note_demoted {
                    return Err(ApiError::new(StatusCode::CONFLICT, "kira:already-demoted"));
                }
                inner.note_demoted = true;
                let seq = inner.append("kira.demote", "owner", "terminal");
                Ok(json!({"ok": true, "seq": seq}))
            }
        }
    }
}

impl Backend for InMemoryTestBackend {
    fn state(&self) -> BackendFuture<'_, Result<OwnerState, ApiError>> {
        Box::pin(async move {
            let state = self
                .inner
                .lock()
                .expect("test backend mutex poisoned")
                .state;
            Ok(OwnerState {
                state,
                subject: state.is_bound().then(|| TEST_SUBJECT.to_owned()),
            })
        })
    }

    fn consume_claim(&self, digest: [u8; 32]) -> BackendFuture<'_, Result<(), ApiError>> {
        Box::pin(async move {
            let mut inner = self.inner.lock().expect("test backend mutex poisoned");
            let claim = inner
                .claims
                .get_mut(&digest)
                .ok_or_else(|| ApiError::new(StatusCode::FORBIDDEN, "aumlok:claim-unknown"))?;
            if claim.spent {
                return Err(ApiError::new(StatusCode::FORBIDDEN, "aumlok:claim-spent"));
            }
            if Instant::now() >= claim.expires {
                return Err(ApiError::new(StatusCode::GONE, "aumlok:claim-expired"));
            }
            claim.spent = true;
            Ok(())
        })
    }

    fn call(
        &self,
        principal: &str,
        operation: Operation,
        body: Value,
    ) -> BackendFuture<'_, Result<Value, ApiError>> {
        let principal = principal.to_owned();
        Box::pin(async move { self.execute(&principal, operation, body) })
    }
}

impl TestCeremony {
    fn new(id: String, principal: &str, response: Value) -> Self {
        Self {
            id,
            principal: principal.to_owned(),
            expires: Instant::now() + CEREMONY_LIFETIME,
            response,
        }
    }

    fn check(&self, principal: &str, id: &str, unknown: &'static str) -> Result<(), ApiError> {
        if self.id != id || self.principal != principal {
            return Err(ApiError::new(StatusCode::FORBIDDEN, unknown));
        }
        if Instant::now() >= self.expires {
            return Err(ApiError::new(StatusCode::GONE, "aumlok:ceremony-expired"));
        }
        Ok(())
    }
}

impl TestState {
    fn id(&mut self) -> String {
        let id = format!("{:032x}", self.next_id);
        self.next_id += 1;
        id
    }

    fn append(&mut self, kind: &str, actor: &str, phase: &str) -> u64 {
        let seq = self.rows.len() as u64 + 1;
        let hash: [u8; 32] = Sha256::digest(format!("frontdoor-test-row:{seq}:{kind}")).into();
        self.rows.push(json!({"seq": seq, "at": 0, "kind": kind,
            "actor": actor, "phase": phase, "hash": hex(&hash)}));
        self.hashes.push(hash);
        seq
    }

    fn check_proposal(&self, id: &str) -> Result<(), ApiError> {
        if id != TEST_PROPOSAL_ID {
            return Err(ApiError::new(
                StatusCode::NOT_FOUND,
                "gate:unknown-proposal",
            ));
        }
        if !self.pending {
            return Err(ApiError::new(StatusCode::CONFLICT, "gate:not-pending"));
        }
        Ok(())
    }

    fn check_action(&self, id: &str, action: &str) -> Result<(), ApiError> {
        if id != TEST_PROPOSAL_ID {
            return Err(ApiError::new(
                StatusCode::NOT_FOUND,
                "gate:unknown-proposal",
            ));
        }
        if action == "retire" && !self.pending {
            return Err(ApiError::new(StatusCode::CONFLICT, "gate:not-retirable"));
        }
        if action == "reconcile" && self.fenced.is_none() {
            return Err(ApiError::new(StatusCode::CONFLICT, "gate:not-reconcilable"));
        }
        Ok(())
    }

    fn leaves(&self) -> Vec<[u8; 32]> {
        self.hashes
            .iter()
            .map(|hash| {
                let mut bytes = vec![0];
                bytes.extend(hash);
                Sha256::digest(bytes).into()
            })
            .collect()
    }

    fn presented_head(&self, since: usize) -> Value {
        let leaves = self.leaves();
        let proof = if since == 0 {
            Vec::new()
        } else {
            subproof(since, &leaves, true)
                .iter()
                .map(|hash| hex(hash))
                .collect()
        };
        json!({"schema": "aukora-aura-presented-head-v1",
            "leafConvention": "rfc6962-leaf-sha256-0x00-prefixed-v1", "treeSize": leaves.len(),
            "root": hex(&tree_head(&leaves)), "sequence": leaves.len(),
            "hash": hex(self.hashes.last().expect("fixture has boot row")),
            "sig": standard_base64(&[0; 64]), "retainedTreeSize": since, "proofFromPrevious": proof})
    }

    fn retained_head(&self) -> Value {
        let head = self.presented_head(self.rows.len());
        json!({"schema": "aukora-aura-retained-head-v1", "leafConvention": head["leafConvention"],
            "sequence": head["sequence"], "hash": head["hash"], "treeSize": head["treeSize"],
            "root": head["root"], "sig": head["sig"]})
    }
}

fn string<'a>(body: &'a Value, name: &str) -> &'a str {
    body[name].as_str().expect("operation validated string")
}

fn expiry_ms(duration: Duration) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("fixture clock before epoch")
        .as_millis() as u64;
    now + duration.as_millis() as u64
}

fn canonical(value: &Value) -> Result<Vec<u8>, ApiError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ApiError::invalid_body())?;
    let parsed = canon::parse(&bytes).map_err(|_| ApiError::invalid_body())?;
    canon::canonical_json(&parsed).map_err(|_| ApiError::invalid_body())
}

fn test_card() -> Value {
    json!({"v": 1, "risk": "routine", "says": "Write the fixture note",
        "facts": [["target", "workspace/note.txt"], ["base", "absent"]],
        "from_to": {"workspace/note.txt": {"from": "", "to": "test note\n"}},
        "model_note": "Synthetic untrusted note <script>fixture</script>."})
}

fn display_hash() -> Result<String, ApiError> {
    Ok(hex(&Sha256::digest(canonical(&test_card())?)))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 15) as usize] as char);
    }
    out
}

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        out.push(ALPHABET[(a >> 2) as usize] as char);
        out.push(ALPHABET[((a & 3) << 4 | b >> 4) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((b & 15) << 2 | c >> 6) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(c & 63) as usize] as char);
        }
    }
    out
}

fn standard_base64(bytes: &[u8]) -> String {
    let mut out = base64url(bytes).replace('-', "+").replace('_', "/");
    while out.len() % 4 != 0 {
        out.push('=');
    }
    out
}

fn split(size: usize) -> usize {
    let mut k = 1;
    while k * 2 < size {
        k *= 2;
    }
    k
}

fn tree_head(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.len() == 1 {
        return leaves[0];
    }
    let k = split(leaves.len());
    let mut bytes = vec![1];
    bytes.extend(tree_head(&leaves[..k]));
    bytes.extend(tree_head(&leaves[k..]));
    Sha256::digest(bytes).into()
}

fn subproof(m: usize, leaves: &[[u8; 32]], complete: bool) -> Vec<[u8; 32]> {
    if m == leaves.len() {
        return if complete {
            Vec::new()
        } else {
            vec![tree_head(leaves)]
        };
    }
    let k = split(leaves.len());
    if m <= k {
        let mut proof = subproof(m, &leaves[..k], complete);
        proof.push(tree_head(&leaves[k..]));
        proof
    } else {
        let mut proof = subproof(m - k, &leaves[k..], false);
        proof.push(tree_head(&leaves[..k]));
        proof
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NODE: &str = "00000000000000000000000000000001";
    const HOST: &str = "owner-test.example";

    #[test]
    fn validators_require_exact_keys_and_canonical_values() {
        for body in [
            json!({"extra": 1}),
            json!({"dev_bypass": true}),
            json!(null),
        ] {
            assert!(validate_operation(Operation::EnrolStart, &body).is_err());
        }
        for body in [
            json!({"limit": 101}),
            json!({"limit": 0}),
            json!({"limit": 1.5}),
        ] {
            assert!(validate_operation(Operation::AuraRecent, &body).is_err());
        }
        assert!(validate_operation(
            Operation::AuraHead,
            &json!({"since": 9_007_199_254_740_992_u64})
        )
        .is_err());
        assert!(validate_operation(
            Operation::MemoryDemote,
            &json!({"note_id": "AA".repeat(16), "reason": ""})
        )
        .is_err());
        let mut attestation = InMemoryTestBackend::attestation_fixture();
        attestation["client_extension_results"] = json!({"number": 9_007_199_254_740_992_u64});
        assert!(validate_operation(
            Operation::EnrolFinish,
            &json!({"enrolment_id": TEST_PROPOSAL_ID, "attestation": attestation})
        )
        .is_err());
        attestation["client_extension_results"] = json!({"dev_bypass": true});
        assert!(validate_operation(
            Operation::EnrolFinish,
            &json!({"enrolment_id": TEST_PROPOSAL_ID, "attestation": attestation})
        )
        .is_err());
    }

    #[test]
    fn approval_requires_passkey_and_canonical_binary_fields() {
        let missing = json!({"id": TEST_PROPOSAL_ID, "approve": true});
        assert_eq!(
            validate_operation(Operation::ApprovalDecide, &missing)
                .unwrap_err()
                .code,
            "aumlok:assertion-refused"
        );
        let mut assertion = json!({"kind": "passkey", "credential_id": "AA", "client_data_json": "AA", "authenticator_data": "AA", "signature": "AA"});
        assert!(validate_operation(
            Operation::ApprovalDecide,
            &json!({"id": TEST_PROPOSAL_ID, "approve": true, "assertion": assertion})
        )
        .is_ok());
        for invalid in ["AB", "AAB", "A", "AA==", "!A", ""] {
            assertion["signature"] = json!(invalid);
            assert!(validate_operation(
                Operation::ApprovalDecide,
                &json!({"id": TEST_PROPOSAL_ID, "approve": true, "assertion": assertion})
            )
            .is_err());
        }
        assert!(validate_operation(
            Operation::ApprovalDecide,
            &json!({"id": TEST_PROPOSAL_ID, "approve": false, "assertion": null})
        )
        .is_err());
    }

    #[test]
    fn validators_refuse_malformed_ceremony_and_attestation_fields() {
        for words in [
            json!([]),
            json!(["a", "b", "c", "d", "e", "f"]),
            json!(["a", "b", "c", "d", "e", "f", 1]),
            json!(["a", "b", "c", "d", "e", "f", ""]),
        ] {
            assert!(validate_operation(
                Operation::BindingConfirm,
                &json!({"ceremony_id": TEST_PROPOSAL_ID, "words": words})
            )
            .is_err());
        }
        let mut attestation = InMemoryTestBackend::attestation_fixture();
        attestation["id"] = json!("AA");
        assert!(validate_operation(
            Operation::EnrolFinish,
            &json!({"enrolment_id": TEST_PROPOSAL_ID, "attestation": attestation})
        )
        .is_err());
        attestation = InMemoryTestBackend::attestation_fixture();
        attestation["client_extension_results"] = json!(null);
        assert!(validate_operation(
            Operation::EnrolFinish,
            &json!({"enrolment_id": TEST_PROPOSAL_ID, "attestation": attestation})
        )
        .is_err());
        attestation = InMemoryTestBackend::attestation_fixture();
        attestation["kind"] = json!("passkey");
        assert!(validate_operation(
            Operation::EnrolFinish,
            &json!({"enrolment_id": TEST_PROPOSAL_ID, "attestation": attestation})
        )
        .is_err());
        assert!(
            validate_operation(Operation::MemoryRecall, &json!({"query": 1, "limit": 20})).is_err()
        );
        assert!(
            validate_operation(Operation::MemoryRecall, &json!({"query": "", "limit": -1}))
                .is_err()
        );
        assert!(
            validate_operation(Operation::BindingCancel, &json!({"ceremony_id": "0"})).is_err()
        );
        assert!(validate_operation(Operation::ApprovalChallenge, &json!({"id": 1})).is_err());
    }

    #[tokio::test]
    async fn test_claims_are_atomic_spent_and_digest_only() {
        let backend = InMemoryTestBackend::new(NODE, HOST);
        let token = "disposable-owner-fixture";
        backend.register_claim(token, Duration::from_secs(60));
        let digest = Sha256::digest(token.as_bytes()).into();
        let (first, second) =
            tokio::join!(backend.consume_claim(digest), backend.consume_claim(digest));
        assert!(first.is_ok());
        assert_eq!(second.unwrap_err().code, "aumlok:claim-spent");
        backend.register_claim(token, Duration::from_secs(60));
        assert_eq!(
            backend.consume_claim(digest).await.unwrap_err().code,
            "aumlok:claim-spent"
        );
        assert_eq!(
            backend.consume_claim([0; 32]).await.unwrap_err().code,
            "aumlok:claim-unknown"
        );
        backend.register_claim("expired-fixture", Duration::ZERO);
        assert_eq!(
            backend
                .consume_claim(Sha256::digest(b"expired-fixture").into())
                .await
                .unwrap_err()
                .code,
            "aumlok:claim-expired"
        );
    }

    #[tokio::test]
    async fn test_bootstrap_is_ordered_first_only_and_resumes() {
        let backend = InMemoryTestBackend::new(NODE, HOST);
        assert_eq!(
            backend
                .call("owner", Operation::BindingPrepare, json!({}))
                .await
                .unwrap_err()
                .code,
            "aumlok:enrolment-required"
        );
        assert_eq!(
            backend
                .call("owner", Operation::Approvals, json!({}))
                .await
                .unwrap_err()
                .code,
            "aumlok:binding-required"
        );
        let start = backend
            .call("owner", Operation::EnrolStart, json!({}))
            .await
            .unwrap();
        assert_eq!(
            backend
                .call("owner", Operation::EnrolStart, json!({}))
                .await
                .unwrap(),
            start
        );
        let mut finish = json!({"enrolment_id": start["enrolment_id"], "attestation": InMemoryTestBackend::attestation_fixture()});
        assert_eq!(
            backend
                .call("other", Operation::EnrolFinish, finish.clone())
                .await
                .unwrap_err()
                .code,
            "aumlok:enrolment-unknown"
        );
        finish["attestation"]["attestation_object"] = json!("AA");
        assert_eq!(
            backend
                .call("owner", Operation::EnrolFinish, finish.clone())
                .await
                .unwrap_err()
                .code,
            "aumlok:attestation-refused"
        );
        finish["attestation"] = InMemoryTestBackend::attestation_fixture();
        backend
            .call("owner", Operation::EnrolFinish, finish)
            .await
            .unwrap();
        assert_eq!(
            backend
                .call("owner", Operation::EnrolStart, json!({}))
                .await
                .unwrap_err()
                .code,
            "aumlok:enrolment-closed"
        );
        let prepare = backend
            .call("owner", Operation::BindingPrepare, json!({}))
            .await
            .unwrap();
        assert_eq!(
            backend
                .call("owner", Operation::BindingPrepare, json!({}))
                .await
                .unwrap(),
            prepare
        );
        let mut confirm = json!({"ceremony_id": prepare["ceremony_id"], "words": prepare["words"]});
        confirm["words"][3] = json!("wrong");
        assert_eq!(
            backend
                .call("owner", Operation::BindingConfirm, confirm.clone())
                .await
                .unwrap_err()
                .position,
            Some(4)
        );
        confirm["words"] = prepare["words"].clone();
        backend
            .call("owner", Operation::BindingConfirm, confirm.clone())
            .await
            .unwrap();
        assert_eq!(backend.state().await.unwrap().state, BootstrapState::Bound);
        assert_eq!(
            backend
                .call("owner", Operation::BindingConfirm, confirm)
                .await
                .unwrap_err()
                .code,
            "aumlok:ceremony-unknown"
        );
        assert_eq!(
            backend
                .call("owner", Operation::BindingPrepare, json!({}))
                .await
                .unwrap_err()
                .code,
            "aumlok:already-bound"
        );
    }

    #[tokio::test]
    async fn test_approval_fixture_is_challenge_bound_and_single_use() {
        let backend = InMemoryTestBackend::with_state(NODE, HOST, BootstrapState::Bound);
        let challenge = backend
            .call(
                "owner",
                Operation::ApprovalChallenge,
                json!({"id": TEST_PROPOSAL_ID}),
            )
            .await
            .unwrap();
        assert!(challenge.get("dev_bypass").is_none());
        let mut assertion = backend.assertion_fixture(TEST_PROPOSAL_ID).unwrap();
        assertion.as_object_mut().unwrap().remove("user_handle");
        let decide = json!({"id": TEST_PROPOSAL_ID, "approve": true, "assertion": assertion});
        backend
            .call("owner", Operation::ApprovalDecide, decide.clone())
            .await
            .unwrap();
        assert_eq!(
            backend
                .call("owner", Operation::ApprovalDecide, decide)
                .await
                .unwrap_err()
                .code,
            "gate:not-pending"
        );
        let backend = InMemoryTestBackend::with_state(NODE, HOST, BootstrapState::Bound);
        backend
            .call(
                "owner",
                Operation::ApprovalChallenge,
                json!({"id": TEST_PROPOSAL_ID}),
            )
            .await
            .unwrap();
        let assertion = backend.assertion_fixture(TEST_PROPOSAL_ID).unwrap();
        assert_eq!(
            backend
                .call(
                    "other",
                    Operation::ApprovalDecide,
                    json!({"id": TEST_PROPOSAL_ID, "approve": true, "assertion": assertion})
                )
                .await
                .unwrap_err()
                .code,
            "aumlok:assertion-refused"
        );
        assert_eq!(
            backend
                .call(
                    "owner",
                    Operation::ApprovalDecide,
                    json!({"id": TEST_PROPOSAL_ID, "approve": true, "assertion": assertion})
                )
                .await
                .unwrap_err()
                .code,
            "gate:challenge-expired"
        );
    }

    #[tokio::test]
    async fn test_ceremony_expiry_and_cancellation_are_scoped() {
        let backend = InMemoryTestBackend::new(NODE, HOST);
        let start = backend
            .call("owner", Operation::EnrolStart, json!({}))
            .await
            .unwrap();
        backend
            .inner
            .lock()
            .unwrap()
            .enrolment
            .as_mut()
            .unwrap()
            .expires = Instant::now();
        let finish = json!({"enrolment_id": start["enrolment_id"], "attestation": InMemoryTestBackend::attestation_fixture()});
        assert_eq!(
            backend
                .call("owner", Operation::EnrolFinish, finish)
                .await
                .unwrap_err()
                .code,
            "aumlok:ceremony-expired"
        );

        let backend = InMemoryTestBackend::with_state(NODE, HOST, BootstrapState::Enrolled);
        let prepare = backend
            .call("owner", Operation::BindingPrepare, json!({}))
            .await
            .unwrap();
        let confirm = json!({"ceremony_id": prepare["ceremony_id"], "words": prepare["words"]});
        assert_eq!(
            backend
                .call("other", Operation::BindingConfirm, confirm.clone())
                .await
                .unwrap_err()
                .code,
            "aumlok:ceremony-unknown"
        );
        let cancel = json!({"ceremony_id": prepare["ceremony_id"]});
        assert_eq!(
            backend
                .call("other", Operation::BindingCancel, cancel.clone())
                .await
                .unwrap_err()
                .code,
            "aumlok:ceremony-unknown"
        );
        backend
            .call("owner", Operation::BindingCancel, cancel)
            .await
            .unwrap();
        assert_eq!(
            backend
                .call("owner", Operation::BindingConfirm, confirm)
                .await
                .unwrap_err()
                .code,
            "aumlok:ceremony-unknown"
        );
        let prepare = backend
            .call("owner", Operation::BindingPrepare, json!({}))
            .await
            .unwrap();
        backend
            .inner
            .lock()
            .unwrap()
            .binding
            .as_mut()
            .unwrap()
            .expires = Instant::now();
        assert_eq!(
            backend
                .call(
                    "owner",
                    Operation::BindingConfirm,
                    json!({"ceremony_id": prepare["ceremony_id"], "words": prepare["words"]})
                )
                .await
                .unwrap_err()
                .code,
            "aumlok:ceremony-expired"
        );
    }

    #[tokio::test]
    async fn test_modified_assertion_and_expired_challenge_never_apply() {
        let backend = InMemoryTestBackend::with_state(NODE, HOST, BootstrapState::Bound);
        backend
            .call(
                "owner",
                Operation::ApprovalChallenge,
                json!({"id": TEST_PROPOSAL_ID}),
            )
            .await
            .unwrap();
        let mut assertion = backend.assertion_fixture(TEST_PROPOSAL_ID).unwrap();
        assertion["signature"] = json!("AA");
        assert_eq!(
            backend
                .call(
                    "owner",
                    Operation::ApprovalDecide,
                    json!({"id": TEST_PROPOSAL_ID, "approve": true, "assertion": assertion})
                )
                .await
                .unwrap_err()
                .code,
            "aumlok:assertion-refused"
        );
        assert!(backend.inner.lock().unwrap().pending);

        let backend = InMemoryTestBackend::with_state(NODE, HOST, BootstrapState::Bound);
        backend
            .call(
                "owner",
                Operation::ApprovalChallenge,
                json!({"id": TEST_PROPOSAL_ID}),
            )
            .await
            .unwrap();
        let assertion = backend.assertion_fixture(TEST_PROPOSAL_ID).unwrap();
        backend
            .inner
            .lock()
            .unwrap()
            .challenge
            .as_mut()
            .unwrap()
            .expires = Instant::now();
        assert_eq!(
            backend
                .call(
                    "owner",
                    Operation::ApprovalDecide,
                    json!({"id": TEST_PROPOSAL_ID, "approve": true, "assertion": assertion})
                )
                .await
                .unwrap_err()
                .code,
            "gate:challenge-expired"
        );
        assert!(backend.inner.lock().unwrap().pending);
        assert_eq!(
            backend
                .call("", Operation::Approvals, json!({}))
                .await
                .unwrap_err()
                .code,
            "frontdoor:session-required"
        );
    }

    #[tokio::test]
    async fn antibody_owner_action_fixture_requires_live_challenge_and_eligible_state() {
        // Expected: gate:unknown-proposal, gate:not-retirable,
        // gate:not-reconcilable, gate:challenge-expired.
        let assertion_shape = json!({"kind": "passkey", "credential_id": "AA",
            "client_data_json": "AA", "authenticator_data": "AA", "signature": "AA"});
        for (challenge_op, finish_op, action) in [
            (
                Operation::ApprovalRetireChallenge,
                Operation::ApprovalRetire,
                "retire",
            ),
            (
                Operation::ApprovalReconcileChallenge,
                Operation::ApprovalReconcile,
                "reconcile",
            ),
        ] {
            let backend = InMemoryTestBackend::with_state(NODE, HOST, BootstrapState::Bound);
            for operation in [challenge_op, finish_op] {
                let body = if operation == challenge_op {
                    json!({"id": "00000000000000000000000000000000"})
                } else {
                    json!({"id": "00000000000000000000000000000000", "assertion": assertion_shape})
                };
                assert_eq!(
                    backend
                        .call("owner", operation, body)
                        .await
                        .unwrap_err()
                        .code,
                    "gate:unknown-proposal"
                );
            }
            if action == "reconcile" {
                backend.fence_proposal("conflict");
            }
            assert_eq!(
                backend
                    .call(
                        "owner",
                        finish_op,
                        json!({"id": TEST_PROPOSAL_ID, "assertion": assertion_shape})
                    )
                    .await
                    .unwrap_err()
                    .code,
                "gate:challenge-expired"
            );
            backend
                .call("owner", challenge_op, json!({"id": TEST_PROPOSAL_ID}))
                .await
                .unwrap();
            let assertion = backend
                .action_assertion_fixture(TEST_PROPOSAL_ID, action)
                .unwrap();
            backend
                .inner
                .lock()
                .unwrap()
                .actions
                .get_mut(action)
                .unwrap()
                .expires = Instant::now();
            assert_eq!(
                backend
                    .call(
                        "owner",
                        finish_op,
                        json!({"id": TEST_PROPOSAL_ID, "assertion": assertion})
                    )
                    .await
                    .unwrap_err()
                    .code,
                "gate:challenge-expired"
            );
            if action == "retire" {
                backend.fence_proposal("conflict");
            } else {
                backend.inner.lock().unwrap().fenced = None;
            }
            assert_eq!(
                backend
                    .call("owner", challenge_op, json!({"id": TEST_PROPOSAL_ID}))
                    .await
                    .unwrap_err()
                    .code,
                if action == "retire" {
                    "gate:not-retirable"
                } else {
                    "gate:not-reconcilable"
                }
            );
        }
    }

    #[tokio::test]
    async fn test_demoted_note_never_returns() {
        let backend = InMemoryTestBackend::with_state(NODE, HOST, BootstrapState::Bound);
        let recall = json!({"query": "", "limit": 20});
        assert_eq!(
            backend
                .call("owner", Operation::MemoryRecall, recall.clone())
                .await
                .unwrap()["result"],
            "found"
        );
        let demote = json!({"note_id": TEST_NOTE_ID, "reason": "owner request"});
        backend
            .call("owner", Operation::MemoryDemote, demote.clone())
            .await
            .unwrap();
        assert_eq!(
            backend
                .call("owner", Operation::MemoryRecall, recall)
                .await
                .unwrap()["result"],
            "empty"
        );
        assert_eq!(
            backend
                .call("owner", Operation::MemoryDemote, demote)
                .await
                .unwrap_err()
                .code,
            "kira:already-demoted"
        );
    }
}
