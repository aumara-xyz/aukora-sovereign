// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use crate::Side;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};

pub(crate) const MAX_INTEGER: u64 = 9_007_199_254_740_991;

pub(crate) const fn refusal(reason: &'static str) -> Refusal {
    Refusal {
        organ: "copresence",
        reason,
    }
}

pub(crate) fn hash(bytes: &[u8]) -> Digest32 {
    Digest32::from_bytes(Sha256::digest(bytes).into())
}

pub(crate) fn domain(tag: &str) -> Vec<u8> {
    let mut bytes = Vec::from(tag.as_bytes());
    bytes.push(0);
    bytes
}

pub(crate) fn integer(value: u64) -> Result<()> {
    if value > MAX_INTEGER {
        Err(refusal("integer-range"))
    } else {
        Ok(())
    }
}

pub(crate) fn validate_participant(value: &Participant) -> Result<()> {
    integer(value.device_epoch)?;
    integer(value.attempt_sequence)?;
    if value.attempt_sequence == 0 {
        return Err(refusal("participant-counter"));
    }
    if value.device_key.0[0] != 4 {
        return Err(refusal("public-key"));
    }
    VerifyingKey::from_sec1_bytes(&value.device_key.0).map_err(|_| refusal("public-key"))?;
    Ok(())
}

pub(crate) fn validate_context(value: &Context) -> Result<()> {
    validate_participant(&value.a)?;
    validate_participant(&value.b)?;
    if value.a.device_key == value.b.device_key || value.a.session_id == value.b.session_id {
        return Err(refusal("same-participant"));
    }
    if value.purpose.len() > 4_096 {
        return Err(refusal("purpose-length"));
    }
    if value.required_layers.intent_ack && value.intent.is_none() {
        return Err(refusal("intent-required"));
    }
    Ok(())
}

pub(crate) fn participant_bytes(value: &Participant, bytes: &mut Vec<u8>) {
    bytes.extend_from_slice(value.node.as_bytes());
    bytes.extend_from_slice(&value.device_key.0);
    bytes.extend_from_slice(&value.device_epoch.to_be_bytes());
    bytes.extend_from_slice(&value.session_id);
    bytes.extend_from_slice(&value.attempt_sequence.to_be_bytes());
}

pub(crate) const fn method(value: Method) -> u8 {
    match value {
        Method::ScreenToScreen => 0,
        Method::Remote => 1,
        Method::Relayed => 2,
    }
}

pub(crate) const fn layers(value: RequiredLayers) -> u8 {
    value.sound as u8 | ((value.motion as u8) << 1) | ((value.intent_ack as u8) << 2)
}

fn option(value: Option<Digest32>, bytes: &mut Vec<u8>) {
    bytes.push(u8::from(value.is_some()));
    if let Some(value) = value {
        bytes.extend_from_slice(value.as_bytes());
    }
}

pub(crate) fn context(value: &Context) -> Result<Digest32> {
    validate_context(value)?;
    let mut bytes = domain(CONTEXT_DOMAIN);
    participant_bytes(&value.a, &mut bytes);
    participant_bytes(&value.b, &mut bytes);
    bytes.push(method(value.method));
    bytes.push(layers(value.required_layers));
    bytes.extend_from_slice(&(value.purpose.len() as u32).to_be_bytes());
    bytes.extend_from_slice(value.purpose.as_bytes());
    option(value.intent, &mut bytes);
    Ok(hash(&bytes))
}

pub(crate) fn nonce(participant: &Participant, nonce: &[u8; 32]) -> Digest32 {
    let mut bytes = domain(NONCE_DOMAIN);
    participant_bytes(participant, &mut bytes);
    bytes.extend_from_slice(nonce);
    hash(&bytes)
}

pub(crate) fn core(value: &CoreInput) -> Result<Digest32> {
    integer(value.t_a_seconds)?;
    integer(value.t_b_seconds)?;
    let context = context(&value.context)?;
    let delta = value
        .t_b_seconds
        .checked_sub(value.t_a_seconds)
        .ok_or(refusal("negative-time-skew"))?;
    if delta > MAX_WINDOW_SECONDS {
        return Err(refusal("ceremony-window"));
    }
    let required = value.context.required_layers;
    if required.sound && value.channels.sound.is_none() {
        return Err(refusal("sound-required"));
    }
    if required.motion && value.channels.motion.is_none() {
        return Err(refusal("motion-required"));
    }
    let mut bytes = domain(CORE_DOMAIN);
    bytes.extend_from_slice(context.as_bytes());
    bytes.extend_from_slice(&value.nonce_a);
    bytes.extend_from_slice(&value.nonce_b);
    bytes.extend_from_slice(&value.t_a_seconds.to_be_bytes());
    bytes.extend_from_slice(&value.t_b_seconds.to_be_bytes());
    bytes.extend_from_slice(value.transcript.as_bytes());
    option(value.channels.sound, &mut bytes);
    option(value.channels.motion, &mut bytes);
    Ok(hash(&bytes))
}

pub(crate) fn verify(
    key: PublicKeyBytes,
    digest: Digest32,
    signature: SignatureBytes,
) -> Result<()> {
    let key = VerifyingKey::from_sec1_bytes(&key.0).map_err(|_| refusal("public-key"))?;
    let signature = Signature::from_slice(&signature.0).map_err(|_| refusal("signature"))?;
    key.verify(digest.as_bytes(), &signature)
        .map_err(|_| refusal("signature"))
}

pub(crate) fn frame(value: &FrameBody) -> Result<Digest32> {
    let encoded = codec::unsigned(value)?;
    let mut bytes = domain(FRAME_DOMAIN);
    bytes.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&encoded);
    Ok(hash(&bytes))
}

pub(crate) fn transcript(frames: [&[u8]; 4]) -> Digest32 {
    let mut bytes = domain(TRANSCRIPT_DOMAIN);
    bytes.extend_from_slice(&4_u32.to_be_bytes());
    for frame in frames {
        bytes.extend_from_slice(&(frame.len() as u32).to_be_bytes());
        bytes.extend_from_slice(frame);
    }
    hash(&bytes)
}

pub(crate) fn fresh(timestamp: u64, now: u64, maximum_age: u64) -> Result<()> {
    integer(timestamp)?;
    let age = now.checked_sub(timestamp).ok_or(refusal("future-frame"))?;
    if age > maximum_age {
        return Err(refusal("stale-frame"));
    }
    Ok(())
}

pub(crate) fn validate_ticket(ticket: &AttemptTicket, session: [u8; 16]) -> Result<()> {
    if ticket.sequence == 0 || ticket.local_session != session {
        Err(refusal("attempt-ticket"))
    } else {
        Ok(())
    }
}

pub(crate) fn verify_body(body: &ReceiptBody, now: u64) -> Result<Digest32> {
    let digest = core(&body.core)?;
    fresh(body.core.t_b_seconds, now, RECEIPT_FRESH_SECONDS)?;
    verify(body.core.context.b.device_key, digest, body.sig_b)?;
    verify(body.core.context.a.device_key, digest, body.sig_a)?;
    match &body.intent_ack {
        Some(ack) => {
            let expected_context = context(&body.core.context)?;
            if ack.core != digest
                || ack.context != expected_context
                || Some(ack.intent) != body.core.context.intent
            {
                return Err(refusal("intent-mismatch"));
            }
            let mut bytes = domain(INTENT_ACK_DOMAIN);
            bytes.extend_from_slice(digest.as_bytes());
            bytes.extend_from_slice(expected_context.as_bytes());
            bytes.extend_from_slice(ack.intent.as_bytes());
            bytes.push(match ack.by {
                Side::A => 0,
                Side::B => 1,
            });
            let participant = match ack.by {
                Side::A => &body.core.context.a,
                Side::B => &body.core.context.b,
            };
            verify(participant.device_key, hash(&bytes), ack.signature)?;
        }
        None if body.core.context.required_layers.intent_ack => {
            return Err(refusal("intent-ack-required"))
        }
        None => {}
    }
    Ok(digest)
}
