// SPDX-License-Identifier: AGPL-3.0-or-later
//! Local refusal checks narrow suggestions; they cannot authorize an effect.

use crate::presets::{BuiltinOperation, PresetId};
use canon::{codes, fd3::Request, session::SessionMode, Result};

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetName(String);

impl TargetName {
    /// Relative logical targets have no empty, dot, parent or platform-prefix components.
    pub fn new(value: String) -> Result<Self> {
        if value.is_empty()
            || value.len() > 256
            || value.contains(['\\', ':', '\0'])
            || value.chars().any(char::is_control)
            || value
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err(codes::FRAME_INVALID_FIELD);
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct LocalGate {
    preset: PresetId,
    targets: Vec<TargetName>,
    phi: PhiState,
}

impl LocalGate {
    pub fn new(preset: PresetId, targets: Vec<TargetName>, phi: PhiState) -> Result<Self> {
        if targets.len() > 128 {
            return Err(codes::FRAME_INVALID_FIELD);
        }
        Ok(Self {
            preset,
            targets,
            phi,
        })
    }

    pub fn judge(&self, request: &Request, mode: SessionMode) -> Result<LocalDisposition> {
        let (operation, target, consequential) = match request {
            Request::Propose(p) => (BuiltinOperation::Proposals, Some(p.target.as_str()), true),
            Request::Read(r) => (BuiltinOperation::Proposals, Some(r.target.as_str()), false),
            Request::MemoryPut(_) => (BuiltinOperation::MemoryPropose, None, true),
            Request::MemoryRecall(_) | Request::MemoryList(_) => {
                (BuiltinOperation::MemoryRead, None, false)
            }
            Request::ModelCall(_) | Request::ModelStart(_) | Request::ModelCancel(_) => {
                (BuiltinOperation::Chat, None, false)
            }
            Request::SessionCreate(_)
            | Request::SessionOpen(_)
            | Request::SessionList(_)
            | Request::SessionAppend(_)
            | Request::SessionFlush(_) => (BuiltinOperation::Sessions, None, false),
            Request::Status | Request::Organs => (BuiltinOperation::Chat, None, false),
        };
        if !self.preset.permits(operation) || (consequential && mode != SessionMode::Build) {
            return Err(codes::FRAME_UNKNOWN_KIND);
        }
        if let Some(target) = target {
            let target = TargetName::new(target.to_owned())?;
            if !self.targets.contains(&target) {
                return Err(codes::FRAME_INVALID_FIELD);
            }
        }
        if consequential && self.phi != PhiState::Verified {
            return Err(codes::FRAME_INVALID_FIELD);
        }
        Ok(if consequential {
            LocalDisposition::PendingOwnerReview
        } else {
            LocalDisposition::DataRequest
        })
    }
}
