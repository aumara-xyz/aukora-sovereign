// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use crate::Side;

struct Observed<T> {
    value: T,
    bytes: Vec<u8>,
}

pub(super) struct State {
    local: Face,
    ticket: Option<AttemptTicket>,
    local_face: Option<Observed<Face>>,
    peer_face: Option<Observed<Face>>,
    context: Option<Context>,
    seen_a: Option<Observed<SeenYou>>,
    seen_b: Option<Observed<SeenYou>>,
    handshake: Option<Handshake>,
    last_local: Option<(u64, u64)>,
    last_peer: Option<(u64, u64)>,
    verified: Option<(Digest32, u64)>,
}

pub(super) fn begin(
    selected: LocalSelection,
    bytes: &[u8],
    now: u64,
    journal: &mut dyn AttemptJournal,
) -> Result<Exchange> {
    let ticket = journal.begin(selected.participant.session_id)?;
    let result = (|| {
        crypto::validate_ticket(&ticket, selected.participant.session_id)?;
        let signed = codec::read_frame(bytes)?;
        let FrameBody::Face(face) = &signed.body else {
            return Err(crypto::refusal("frame-order"));
        };
        if face.method != selected.method || face.required_layers != selected.required_layers {
            return Err(crypto::refusal("method-mismatch"));
        }
        if face.participant != selected.participant {
            return Err(crypto::refusal("local-face-mismatch"));
        }
        if ticket.sequence != face.participant.attempt_sequence {
            return Err(crypto::refusal("attempt-sequence"));
        }
        crypto::fresh(face.t_seconds, now, FRAME_FRESHNESS_SECONDS)?;
        crypto::verify(
            face.participant.device_key,
            crypto::frame(&signed.body)?,
            signed.signature,
        )?;
        Ok(face.clone())
    })();
    let face = match result {
        Ok(face) => face,
        Err(reason) => {
            journal.finish(ticket, AttemptOutcome::Refused(reason))?;
            return Err(reason);
        }
    };
    Ok(Exchange {
        method: selected.method,
        stage: Stage::Face,
        state: State {
            local: face.clone(),
            ticket: Some(ticket),
            local_face: Some(Observed {
                value: face.clone(),
                bytes: bytes.to_vec(),
            }),
            peer_face: None,
            context: None,
            seen_a: None,
            seen_b: None,
            handshake: None,
            last_local: Some((face.frame_index, face.t_seconds)),
            last_peer: None,
            verified: None,
        },
    })
}

pub(super) fn abandon(exchange: &mut Exchange, journal: &mut dyn AttemptJournal) -> Result<()> {
    exchange.stage = Stage::Refused;
    exchange.state.verified = None;
    if let Some(ticket) = exchange.state.ticket.take() {
        journal.finish(ticket, AttemptOutcome::Abandoned)?;
    }
    Ok(())
}

pub(super) fn observe(
    exchange: &mut Exchange,
    bytes: &[u8],
    now: u64,
    journal: &mut dyn AttemptJournal,
) -> Result<Stage> {
    let ticket = match journal.begin(exchange.state.local.participant.session_id) {
        Ok(ticket) => ticket,
        Err(reason) => {
            exchange.stage = Stage::Refused;
            exchange.state.verified = None;
            if let Some(initial) = exchange.state.ticket.take() {
                journal.finish(initial, AttemptOutcome::Refused(reason))?;
            }
            return Err(reason);
        }
    };
    let result = crypto::validate_ticket(&ticket, exchange.state.local.participant.session_id)
        .and_then(|()| apply(exchange, bytes, now));
    // Completing a frame observation does not accept a receipt. Intent evidence
    // is outside these frames; only verify_receipt consumes an accepted digest.
    let outcome = match &result {
        Ok(_) => AttemptOutcome::Abandoned,
        Err(reason) => AttemptOutcome::Refused(*reason),
    };
    if let Err(reason) = journal.finish(ticket, outcome) {
        exchange.stage = Stage::Refused;
        exchange.state.verified = None;
        if let Some(initial) = exchange.state.ticket.take() {
            journal.finish(initial, AttemptOutcome::Refused(reason))?;
        }
        return Err(reason);
    }
    match result {
        Ok(stage) => {
            if stage == Stage::Bloom {
                if let Some(ticket) = exchange.state.ticket.take() {
                    if let Err(reason) = journal.finish(ticket, AttemptOutcome::Abandoned) {
                        exchange.stage = Stage::Refused;
                        exchange.state.verified = None;
                        return Err(reason);
                    }
                }
            }
            Ok(stage)
        }
        Err(reason) => {
            exchange.stage = Stage::Refused;
            exchange.state.verified = None;
            if let Some(ticket) = exchange.state.ticket.take() {
                journal.finish(ticket, AttemptOutcome::Refused(reason))?;
            }
            Err(reason)
        }
    }
}

fn apply(exchange: &mut Exchange, bytes: &[u8], now: u64) -> Result<Stage> {
    if matches!(exchange.stage, Stage::Bloom | Stage::Refused) {
        return Err(crypto::refusal("exchange-closed"));
    }
    let frame = codec::read_frame(bytes)?;
    let digest = crypto::frame(&frame.body)?;
    let state = &mut exchange.state;
    match &frame.body {
        FrameBody::Face(face) => {
            if state.context.is_some() {
                return Err(crypto::refusal("frame-order"));
            }
            if face.method != exchange.method || face.required_layers != state.local.required_layers
            {
                return Err(crypto::refusal("method-mismatch"));
            }
            crypto::fresh(face.t_seconds, now, FRAME_FRESHNESS_SECONDS)?;
            crypto::verify(face.participant.device_key, digest, frame.signature)?;
            let is_local = face.participant == state.local.participant;
            if is_local {
                if face.nonce_commitment != state.local.nonce_commitment
                    || face.t_seconds < state.local.t_seconds
                    || face.frame_index < state.local.frame_index
                {
                    return Err(crypto::refusal("local-face-mismatch"));
                }
            } else {
                if face.participant.device_key == state.local.participant.device_key
                    || face.participant.session_id == state.local.participant.session_id
                {
                    return Err(crypto::refusal("same-participant"));
                }
                if state.peer_face.as_ref().is_some_and(|old| {
                    old.value.participant != face.participant
                        || old.value.nonce_commitment != face.nonce_commitment
                }) {
                    return Err(crypto::refusal("peer-mismatch"));
                }
            }
            advance(state, is_local, face.frame_index, face.t_seconds)?;
            let record = Some(Observed {
                value: face.clone(),
                bytes: bytes.to_vec(),
            });
            if is_local {
                state.local_face = record;
            } else {
                state.peer_face = record;
            }
        }
        FrameBody::SeenYou(seen) => {
            if state.handshake.is_some() {
                return Err(crypto::refusal("frame-order"));
            }
            let (face_a, face_b) = faces(state, &seen.context)?;
            if seen.face_a != crypto::hash(&face_a.bytes)
                || seen.face_b != crypto::hash(&face_b.bytes)
            {
                return Err(crypto::refusal("face-mismatch"));
            }
            let participant = match seen.sender {
                Side::A => &seen.context.a,
                Side::B => &seen.context.b,
            };
            let face = match seen.sender {
                Side::A => &face_a.value,
                Side::B => &face_b.value,
            };
            if crypto::nonce(participant, &seen.nonce) != face.nonce_commitment {
                return Err(crypto::refusal("nonce-commitment"));
            }
            if state
                .context
                .as_ref()
                .is_some_and(|context| context != &seen.context)
            {
                return Err(crypto::refusal("context-mismatch"));
            }
            if match seen.sender {
                Side::A => state.seen_a.is_some(),
                Side::B => state.seen_b.is_some(),
            } {
                return Err(crypto::refusal("frame-replay"));
            }
            crypto::fresh(seen.t_seconds, now, FRAME_FRESHNESS_SECONDS)?;
            crypto::verify(participant.device_key, digest, frame.signature)?;
            let is_local = participant == &state.local.participant;
            advance(state, is_local, seen.frame_index, seen.t_seconds)?;
            state.context = Some(seen.context.clone());
            let record = Some(Observed {
                value: seen.clone(),
                bytes: bytes.to_vec(),
            });
            match seen.sender {
                Side::A => state.seen_a = record,
                Side::B => state.seen_b = record,
            }
            exchange.stage = Stage::SeenYou;
        }
        FrameBody::Handshake(handshake) => {
            if state.handshake.is_some() {
                return Err(crypto::refusal("frame-replay"));
            }
            let a = state
                .seen_a
                .as_ref()
                .ok_or(crypto::refusal("frame-order"))?;
            let b = state
                .seen_b
                .as_ref()
                .ok_or(crypto::refusal("frame-order"))?;
            if state.context.as_ref() != Some(&handshake.core.context)
                || handshake.core.nonce_a != a.value.nonce
                || handshake.core.nonce_b != b.value.nonce
                || handshake.core.t_a_seconds != a.value.t_seconds
                || handshake.core.t_b_seconds != b.value.t_seconds
            {
                return Err(crypto::refusal("core-mismatch"));
            }
            let (face_a, face_b) = faces(state, &handshake.core.context)?;
            let transcript = crypto::transcript([&face_a.bytes, &face_b.bytes, &a.bytes, &b.bytes]);
            if handshake.core.transcript != transcript {
                return Err(crypto::refusal("transcript-mismatch"));
            }
            let core = crypto::core(&handshake.core)?;
            crypto::fresh(handshake.core.t_b_seconds, now, MAX_WINDOW_SECONDS)?;
            crypto::fresh(handshake.t_seconds, now, FRAME_FRESHNESS_SECONDS)?;
            let participant = &handshake.core.context.b;
            crypto::verify(participant.device_key, core, handshake.sig_b)?;
            crypto::verify(participant.device_key, digest, frame.signature)?;
            advance(
                state,
                participant == &state.local.participant,
                handshake.frame_index,
                handshake.t_seconds,
            )?;
            state.handshake = Some(handshake.clone());
            exchange.stage = Stage::Handshake;
        }
        FrameBody::Bloom(bloom) => {
            let handshake = state
                .handshake
                .as_ref()
                .ok_or(crypto::refusal("frame-order"))?;
            let core = crypto::core(&handshake.core)?;
            crypto::fresh(handshake.core.t_b_seconds, now, MAX_WINDOW_SECONDS)?;
            if bloom.core != core || bloom.context != crypto::context(&handshake.core.context)? {
                return Err(crypto::refusal("core-mismatch"));
            }
            crypto::fresh(bloom.t_seconds, now, FRAME_FRESHNESS_SECONDS)?;
            let participant = &handshake.core.context.a;
            let verified_at = handshake.core.t_b_seconds;
            crypto::verify(participant.device_key, core, bloom.sig_a)?;
            crypto::verify(participant.device_key, digest, frame.signature)?;
            advance(
                state,
                participant == &state.local.participant,
                bloom.frame_index,
                bloom.t_seconds,
            )?;
            state.verified = Some((core, verified_at));
            exchange.stage = Stage::Bloom;
        }
    }
    Ok(exchange.stage)
}

fn faces<'a>(
    state: &'a State,
    context: &Context,
) -> Result<(&'a Observed<Face>, &'a Observed<Face>)> {
    crypto::validate_context(context)?;
    if context.method != state.local.method
        || context.required_layers != state.local.required_layers
    {
        return Err(crypto::refusal("method-mismatch"));
    }
    let local = state
        .local_face
        .as_ref()
        .ok_or(crypto::refusal("frame-order"))?;
    let peer = state
        .peer_face
        .as_ref()
        .ok_or(crypto::refusal("frame-order"))?;
    if context.a == local.value.participant && context.b == peer.value.participant {
        Ok((local, peer))
    } else if context.a == peer.value.participant && context.b == local.value.participant {
        Ok((peer, local))
    } else {
        Err(crypto::refusal("peer-mismatch"))
    }
}

fn advance(state: &mut State, is_local: bool, index: u64, timestamp: u64) -> Result<()> {
    crypto::integer(index)?;
    let last = if is_local {
        &mut state.last_local
    } else {
        &mut state.last_peer
    };
    if last
        .is_some_and(|(old_index, old_timestamp)| index <= old_index || timestamp < old_timestamp)
    {
        return Err(crypto::refusal("frame-replay"));
    }
    *last = Some((index, timestamp));
    Ok(())
}

pub(super) fn verified(state: &State) -> Option<(Digest32, u64)> {
    state.verified
}
