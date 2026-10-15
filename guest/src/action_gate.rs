// SPDX-License-Identifier: AGPL-3.0-or-later
//! Every closed request is checked before dispatch; a local pass grants no effect.

use crate::presets::{BuiltinOperation, PresetId};
use canon::{
    codes,
    digest::Digest32,
    fd3::{self, Request},
    fd3_payloads::ModelCall,
    frame::{Frame, FrameId},
    provenance::{Provenance, Source},
    session::SessionMode,
    Result,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhiState {
    Verified,
    Undetermined,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalDisposition {
    DataRequest,
    PendingOwnerReview,
}

/// An exact logical target, never a filesystem location or a URL.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetName(String);

impl TargetName {
    pub fn new(value: String) -> Result<Self> {
        if value.is_empty()
            || value.len() > 256
            || value.split('/').any(|part| {
                part.is_empty()
                    || !part.as_bytes()[0].is_ascii_alphanumeric()
                    || !part.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                    })
            })
        {
            return Err(codes::FRAME_INVALID_FIELD);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Checks cover closed operation, preset/mode, target law and canonical payload.
/// The digest identifies a normalized validation frame, never owner authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhiAssessment {
    pub state: PhiState,
    pub checks_passed: u8,
    /// Hash of the minimum-version Auma frame with id `guard`, not a sent frame.
    pub request_sha256: Option<Digest32>,
}

#[derive(Clone, Debug)]
pub struct LocalGate {
    preset: PresetId,
    targets: Vec<TargetName>,
}

impl LocalGate {
    /// Assessments are computed from each request; callers supply no guard verdict.
    pub fn new(preset: PresetId, targets: Vec<TargetName>) -> Result<Self> {
        if targets.len() > 128
            || targets
                .iter()
                .enumerate()
                .any(|(index, target)| targets[..index].contains(target))
        {
            return Err(codes::FRAME_INVALID_FIELD);
        }
        Ok(Self { preset, targets })
    }

    /// Recomputes the guard from the actual closed target and argument payload.
    pub fn phi_guard(&self, request: &Request, mode: SessionMode) -> PhiAssessment {
        self.assess(request, mode).0
    }

    fn assess(
        &self,
        request: &Request,
        mode: SessionMode,
    ) -> (PhiAssessment, Option<canon::Refusal>) {
        let mut assessment = PhiAssessment {
            state: PhiState::Failed,
            checks_passed: 0,
            request_sha256: None,
        };
        let (operation, target, consequential) = classification(request);
        if !self.preset.permits(operation)
            || (consequential && mode != SessionMode::Build)
            || self.preset.mode() != mode
        {
            return (assessment, Some(codes::FRAME_UNKNOWN_KIND));
        }
        assessment.checks_passed += 2;
        if let Some(target) = target {
            let target = match TargetName::new(target.to_owned()) {
                Ok(target) => target,
                Err(refusal) => return (assessment, Some(refusal)),
            };
            if !self.targets.contains(&target) {
                return (assessment, Some(codes::FRAME_INVALID_FIELD));
            }
        }
        assessment.checks_passed += 1;
        let bytes = match checked_payload(request, self.preset, mode) {
            Ok(bytes) => bytes,
            Err(refusal) => return (assessment, Some(refusal)),
        };
        assessment.checks_passed += 1;
        assessment.request_sha256 = Some(Digest32::sha256(&bytes));
        assessment.state = PhiState::Verified;
        (assessment, None)
    }

    pub fn judge(&self, request: &Request, mode: SessionMode) -> Result<LocalDisposition> {
        let (assessment, refusal) = self.assess(request, mode);
        if let Some(refusal) = refusal {
            return Err(refusal);
        }
        if assessment.state != PhiState::Verified || assessment.checks_passed != 4 {
            return Err(codes::FRAME_INVALID_FIELD);
        }
        Ok(if classification(request).2 {
            LocalDisposition::PendingOwnerReview
        } else {
            LocalDisposition::DataRequest
        })
    }
}

fn classification(request: &Request) -> (BuiltinOperation, Option<&str>, bool) {
    match request {
        Request::Propose(proposal) => (
            BuiltinOperation::Proposals,
            Some(proposal.target.as_str()),
            true,
        ),
        Request::Read(read) => (
            BuiltinOperation::Proposals,
            Some(read.target.as_str()),
            false,
        ),
        Request::MemoryPut(_) => (BuiltinOperation::MemoryPropose, None, true),
        Request::MemoryRecall(_) | Request::MemoryList(_) => {
            (BuiltinOperation::MemoryRead, None, false)
        }
        Request::ModelCall(_) | Request::Status | Request::Organs => {
            (BuiltinOperation::Chat, None, false)
        }
        Request::ModelStart(_) | Request::ModelCancel(_) => {
            (BuiltinOperation::Streaming, None, false)
        }
        Request::SessionCreate(_)
        | Request::SessionOpen(_)
        | Request::SessionList(_)
        | Request::SessionAppend(_)
        | Request::SessionFlush(_) => (BuiltinOperation::Sessions, None, false),
    }
}

fn checked_payload(request: &Request, preset: PresetId, mode: SessionMode) -> Result<Vec<u8>> {
    match request {
        Request::ModelCall(call) => check_model_tools(call, preset, mode)?,
        Request::ModelStart(start) => check_model_tools(&start.call, preset, mode)?,
        Request::SessionAppend(append) => {
            crate::rails::validate_entry_origin(&append.entry)?;
            if append.entry.provenance.source != Source::Auma {
                return Err(codes::FRAME_PROVENANCE);
            }
        }
        _ => {}
    }
    // Canon revalidates manually constructed payloads against the exact wire schema.
    fd3::encode_request(&Frame {
        v: request.minimum_version(),
        id: FrameId::new("guard".into())?,
        body: request.clone(),
        provenance: Provenance {
            source: Source::Auma,
        },
    })
}

fn check_model_tools(call: &ModelCall, preset: PresetId, mode: SessionMode) -> Result<()> {
    if call.tools.len() > 5 {
        return Err(codes::FRAME_INVALID_FIELD);
    }
    for (index, tool) in call.tools.iter().enumerate() {
        let operation = match tool.name.as_str() {
            "propose" | "read" => BuiltinOperation::Proposals,
            "memory.put" => BuiltinOperation::MemoryPropose,
            "memory.recall" | "memory.list" => BuiltinOperation::MemoryRead,
            _ => return Err(codes::FRAME_UNKNOWN_KIND),
        };
        if !preset.permits(operation) || !PresetId::for_mode(mode).permits(operation) {
            return Err(codes::FRAME_UNKNOWN_KIND);
        }
        if call.tools[..index]
            .iter()
            .any(|previous| previous.name == tool.name)
        {
            return Err(codes::FRAME_INVALID_FIELD);
        }
    }
    Ok(())
}
