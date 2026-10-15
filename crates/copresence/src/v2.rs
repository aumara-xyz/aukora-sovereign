// SPDX-License-Identifier: AGPL-3.0-or-later
//! Complete pairing context in a new envelope; v1 objects retain their fields.

use crate::{
    receipt_json::{read_hardened, Value, HARDENED_LIMITS},
    v1::{self, codec, crypto, AttemptJournal, AttemptOutcome, AttemptTicket},
    Result, SignatureBytes,
};
use canon::{digest::Digest32, ids::SubjectId};

pub const RECEIPT_SCHEMA: &str = "aukora.copresence.hardened.v2";
pub const CONTEXT_DOMAIN: &str = "copresence.context.v2";
pub const CORE_DOMAIN: &str = "copresence.receipt.v2";
pub const INTENT_ACK_DOMAIN: &str = "copresence.intent-ack.v3";

/// These are expected local bindings, not permission grants or owner signatures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Context {
    pub exchange: v1::Context,
    pub owner_a: SubjectId,
    pub owner_b: SubjectId,
    pub scopes: Vec<String>,
    pub expires_at_seconds: u64,
}

/// Both device signatures bind the complete context and the original exchange core.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptBody {
    pub context: Context,
    pub exchange_receipt: v1::ReceiptBody,
    pub sig_a: SignatureBytes,
    pub sig_b: SignatureBytes,
    pub intent_ack: Option<v1::IntentAcknowledgement>,
}

#[derive(Clone, Debug)]
pub struct VerifiedReceipt {
    body: ReceiptBody,
    digest: Digest32,
    ticket: AttemptTicket,
}

impl VerifiedReceipt {
    pub const fn body(&self) -> &ReceiptBody {
        &self.body
    }

    pub const fn digest(&self) -> Digest32 {
        self.digest
    }

    pub const fn counted_attempt(&self) -> &AttemptTicket {
        &self.ticket
    }
}

fn validate_context(context: &Context) -> Result<()> {
    crypto::validate_context(&context.exchange)?;
    crypto::integer(context.expires_at_seconds)?;
    if context.scopes.is_empty()
        || context.scopes.len() > 32
        || context.scopes.iter().any(|scope| {
            scope.is_empty()
                || scope.len() > 128
                || !scope
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
        })
        || context.scopes.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(crypto::refusal("context-scopes"));
    }
    if context.expires_at_seconds == 0 {
        return Err(crypto::refusal("context-expired"));
    }
    Ok(())
}

fn context_value(context: &Context) -> Result<Value> {
    validate_context(context)?;
    Ok(codec::object([
        ("exchange", codec::context_value(&context.exchange)?),
        ("owner_a", codec::text(context.owner_a.to_string())),
        ("owner_b", codec::text(context.owner_b.to_string())),
        (
            "scopes",
            Value::Array(context.scopes.iter().map(codec::text).collect()),
        ),
        (
            "expires_at_seconds",
            codec::number(context.expires_at_seconds)?,
        ),
    ]))
}

pub fn context_digest(context: &Context) -> Result<Digest32> {
    let mut bytes = crypto::domain(CONTEXT_DOMAIN);
    bytes.extend_from_slice(&codec::canonical(&context_value(context)?)?);
    Ok(crypto::hash(&bytes))
}

/// Includes both owner subjects, device keys, scopes, expiry and both timestamps.
pub fn core_digest(body: &ReceiptBody) -> Result<Digest32> {
    if body.context.exchange != body.exchange_receipt.core.context {
        return Err(crypto::refusal("context-mismatch"));
    }
    if body.exchange_receipt.core.t_b_seconds >= body.context.expires_at_seconds {
        return Err(crypto::refusal("context-expired"));
    }
    let mut bytes = crypto::domain(CORE_DOMAIN);
    bytes.extend_from_slice(context_digest(&body.context)?.as_bytes());
    bytes.extend_from_slice(v1::core_digest(&body.exchange_receipt.core)?.as_bytes());
    Ok(crypto::hash(&bytes))
}

/// The extra intent acknowledgement uses the complete v2 context, not the v1 core alone.
pub fn intent_ack_digest(body: &ReceiptBody, by: crate::Side) -> Result<Digest32> {
    let intent = body
        .context
        .exchange
        .intent
        .ok_or(crypto::refusal("intent-required"))?;
    let mut bytes = crypto::domain(INTENT_ACK_DOMAIN);
    bytes.extend_from_slice(core_digest(body)?.as_bytes());
    bytes.extend_from_slice(context_digest(&body.context)?.as_bytes());
    bytes.extend_from_slice(intent.as_bytes());
    bytes.push(match by {
        crate::Side::A => 0,
        crate::Side::B => 1,
    });
    Ok(crypto::hash(&bytes))
}

fn ack_value(ack: &Option<v1::IntentAcknowledgement>) -> Value {
    match ack {
        None => Value::Null,
        Some(ack) => codec::object([
            (
                "by",
                codec::text(match ack.by {
                    crate::Side::A => "A",
                    crate::Side::B => "B",
                }),
            ),
            ("intent", codec::hex_value(ack.intent.as_bytes())),
            ("core", codec::hex_value(ack.core.as_bytes())),
            ("context", codec::hex_value(ack.context.as_bytes())),
            ("signature", codec::hex_value(&ack.signature.0)),
        ]),
    }
}

pub fn encode_receipt(body: &ReceiptBody) -> Result<Vec<u8>> {
    core_digest(body)?;
    let exchange = read_hardened(
        &codec::encode_receipt(&body.exchange_receipt)?,
        HARDENED_LIMITS,
    )?;
    codec::canonical(&codec::object([
        ("schema", codec::text(RECEIPT_SCHEMA)),
        (
            "body",
            codec::object([
                ("context", context_value(&body.context)?),
                ("exchange_receipt", exchange),
                ("sig_a", codec::hex_value(&body.sig_a.0)),
                ("sig_b", codec::hex_value(&body.sig_b.0)),
                ("intent_ack", ack_value(&body.intent_ack)),
            ]),
        ),
    ]))
}

fn parse_context(value: &Value) -> Result<Context> {
    codec::fields(
        value,
        &[
            "exchange",
            "owner_a",
            "owner_b",
            "scopes",
            "expires_at_seconds",
        ],
    )?;
    let Value::Array(scopes) = codec::get(value, "scopes")? else {
        return Err(crypto::refusal("field-type"));
    };
    let subject = |name| {
        SubjectId::parse(&codec::string(codec::get(value, name)?)?)
            .map_err(|_| crypto::refusal("context-owner"))
    };
    let context = Context {
        exchange: codec::context(codec::get(value, "exchange")?)?,
        owner_a: subject("owner_a")?,
        owner_b: subject("owner_b")?,
        scopes: scopes.iter().map(codec::string).collect::<Result<_>>()?,
        expires_at_seconds: codec::uint(codec::get(value, "expires_at_seconds")?)?,
    };
    validate_context(&context)?;
    Ok(context)
}

fn parse_ack(value: &Value) -> Result<Option<v1::IntentAcknowledgement>> {
    if value.is_null() {
        return Ok(None);
    }
    codec::fields(value, &["by", "intent", "core", "context", "signature"])?;
    let by = match codec::string(codec::get(value, "by")?)?.as_str() {
        "A" => crate::Side::A,
        "B" => crate::Side::B,
        _ => return Err(crypto::refusal("field-type")),
    };
    Ok(Some(v1::IntentAcknowledgement {
        by,
        intent: Digest32::from_bytes(codec::raw(codec::get(value, "intent")?)?),
        core: Digest32::from_bytes(codec::raw(codec::get(value, "core")?)?),
        context: Digest32::from_bytes(codec::raw(codec::get(value, "context")?)?),
        signature: SignatureBytes(codec::raw(codec::get(value, "signature")?)?),
    }))
}

fn read_receipt(bytes: &[u8]) -> Result<ReceiptBody> {
    let value = read_hardened(bytes, HARDENED_LIMITS)?;
    codec::fields(&value, &["schema", "body"])?;
    if codec::string(codec::get(&value, "schema")?)? != RECEIPT_SCHEMA {
        return Err(crypto::refusal("receipt-schema"));
    }
    let value = codec::get(&value, "body")?;
    codec::fields(
        value,
        &[
            "context",
            "exchange_receipt",
            "sig_a",
            "sig_b",
            "intent_ack",
        ],
    )?;
    let body = ReceiptBody {
        context: parse_context(codec::get(value, "context")?)?,
        exchange_receipt: codec::read_receipt(&codec::canonical(codec::get(
            value,
            "exchange_receipt",
        )?)?)?,
        sig_a: SignatureBytes(codec::raw(codec::get(value, "sig_a")?)?),
        sig_b: SignatureBytes(codec::raw(codec::get(value, "sig_b")?)?),
        intent_ack: parse_ack(codec::get(value, "intent_ack")?)?,
    };
    if encode_receipt(&body)? != bytes {
        return Err(crypto::refusal("receipt-not-canonical"));
    }
    Ok(body)
}

/// The supervisor supplies expected bindings; peer claims cannot choose them.
pub fn verify_receipt(
    bytes: &[u8],
    expected: &Context,
    now_seconds: u64,
    journal: &mut dyn AttemptJournal,
) -> Result<VerifiedReceipt> {
    let ticket = journal.begin(expected.exchange.a.session_id)?;
    let result = (|| {
        crypto::validate_ticket(&ticket, expected.exchange.a.session_id)?;
        validate_context(expected)?;
        crypto::integer(now_seconds)?;
        let body = read_receipt(bytes)?;
        if &body.context != expected {
            return Err(crypto::refusal("context-mismatch"));
        }
        if now_seconds >= expected.expires_at_seconds {
            return Err(crypto::refusal("context-expired"));
        }
        crypto::verify_body(&body.exchange_receipt, now_seconds)?;
        let digest = core_digest(&body)?;
        crypto::verify(expected.exchange.a.device_key, digest, body.sig_a)?;
        crypto::verify(expected.exchange.b.device_key, digest, body.sig_b)?;
        match &body.intent_ack {
            Some(ack) => {
                if ack.core != digest
                    || ack.context != context_digest(expected)?
                    || Some(ack.intent) != expected.exchange.intent
                {
                    return Err(crypto::refusal("intent-mismatch"));
                }
                let key = match ack.by {
                    crate::Side::A => expected.exchange.a.device_key,
                    crate::Side::B => expected.exchange.b.device_key,
                };
                crypto::verify(key, intent_ack_digest(&body, ack.by)?, ack.signature)?;
            }
            None if expected.exchange.required_layers.intent_ack => {
                return Err(crypto::refusal("intent-ack-required"));
            }
            None => {}
        }
        Ok((body, digest))
    })();
    match result {
        Ok((body, digest)) => {
            journal.finish(ticket.clone(), AttemptOutcome::Accepted { receipt: digest })?;
            Ok(VerifiedReceipt {
                body,
                digest,
                ticket,
            })
        }
        Err(reason) => {
            journal.finish(ticket, AttemptOutcome::Refused(reason))?;
            Err(reason)
        }
    }
}
