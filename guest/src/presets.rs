// SPDX-License-Identifier: AGPL-3.0-or-later
//! Presets select compiled operations; no source text or package loader is present.

use canon::{codes, session::SessionMode, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuiltinOperation {
    Chat,
    Threads,
    Sessions,
    Streaming,
    Compaction,
    Proposals,
    MemoryRead,
    MemoryPropose,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresetId {
    Chat,
    Build,
}

impl PresetId {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "chat" => Ok(Self::Chat),
            "build" => Ok(Self::Build),
            _ => Err(codes::FRAME_UNKNOWN_KIND),
        }
    }

    pub const fn mode(self) -> SessionMode {
        match self {
            Self::Chat => SessionMode::Chat,
            Self::Build => SessionMode::Build,
        }
    }

    pub const fn permits(self, operation: BuiltinOperation) -> bool {
        match operation {
            BuiltinOperation::Proposals | BuiltinOperation::MemoryPropose => {
                matches!(self, Self::Build)
            }
            _ => true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Preset {
    pub id: PresetId,
    pub model: canon::session::Text<256>,
    pub max_output_tokens: u32,
}

impl Preset {
    pub fn validate(&self) -> Result<()> {
        if self.model.as_str().is_empty() || !(1..=32_768).contains(&self.max_output_tokens) {
            return Err(codes::FRAME_INVALID_FIELD);
        }
        Ok(())
    }
}

/// Preloading references only already compiled presets and bounded data assets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreloadFacts {
    pub release: canon::digest::Digest32,
    pub presets_loaded: u16,
    pub context_bytes_loaded: u32,
    pub elapsed_ms: Option<u64>,
}
