// SPDX-License-Identifier: AGPL-3.0-or-later
//! Presets select compiled operations; no source text or package loader is present.

use canon::{codes, session::SessionMode, Result};

pub const MAX_OUTPUT_TOKENS: u32 = 32_768;

const CHAT_OPERATIONS: &[BuiltinOperation] = &[
    BuiltinOperation::Chat,
    BuiltinOperation::Threads,
    BuiltinOperation::Sessions,
    BuiltinOperation::Streaming,
    BuiltinOperation::Compaction,
    BuiltinOperation::MemoryRead,
];
const BUILD_OPERATIONS: &[BuiltinOperation] = &[
    BuiltinOperation::Chat,
    BuiltinOperation::Threads,
    BuiltinOperation::Sessions,
    BuiltinOperation::Streaming,
    BuiltinOperation::Compaction,
    BuiltinOperation::Proposals,
    BuiltinOperation::MemoryRead,
    BuiltinOperation::MemoryPropose,
];

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

impl BuiltinOperation {
    /// Names select only the closed operations compiled into this harness.
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "chat" => Ok(Self::Chat),
            "threads" => Ok(Self::Threads),
            "sessions" => Ok(Self::Sessions),
            "streaming" => Ok(Self::Streaming),
            "compaction" => Ok(Self::Compaction),
            "proposals" => Ok(Self::Proposals),
            "memory.read" => Ok(Self::MemoryRead),
            "memory.propose" => Ok(Self::MemoryPropose),
            _ => Err(codes::FRAME_UNKNOWN_KIND),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Chat => "chat",
            Self::Threads => "threads",
            Self::Sessions => "sessions",
            Self::Streaming => "streaming",
            Self::Compaction => "compaction",
            Self::Proposals => "proposals",
            Self::MemoryRead => "memory.read",
            Self::MemoryPropose => "memory.propose",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresetId {
    Chat,
    Build,
}

impl PresetId {
    pub const ALL: [Self; 2] = [Self::Chat, Self::Build];

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

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Chat => "chat",
            Self::Build => "build",
        }
    }

    pub const fn for_mode(mode: SessionMode) -> Self {
        match mode {
            SessionMode::Chat => Self::Chat,
            SessionMode::Build => Self::Build,
        }
    }

    pub const fn operations(self) -> &'static [BuiltinOperation] {
        match self {
            Self::Chat => CHAT_OPERATIONS,
            Self::Build => BUILD_OPERATIONS,
        }
    }

    pub const fn permits(self, operation: BuiltinOperation) -> bool {
        match operation {
            BuiltinOperation::Proposals | BuiltinOperation::MemoryPropose => {
                matches!(self, Self::Build)
            }
            BuiltinOperation::Chat
            | BuiltinOperation::Threads
            | BuiltinOperation::Sessions
            | BuiltinOperation::Streaming
            | BuiltinOperation::Compaction
            | BuiltinOperation::MemoryRead => true,
        }
    }

    /// An unknown or unavailable operation refuses before any dispatch occurs.
    pub fn require(self, name: &str) -> Result<BuiltinOperation> {
        let operation = BuiltinOperation::parse(name)?;
        if !self.permits(operation) {
            return Err(codes::FRAME_UNKNOWN_KIND);
        }
        Ok(operation)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Preset {
    pub id: PresetId,
    pub model: canon::session::Text<256>,
    pub max_output_tokens: u32,
}

impl Preset {
    /// Model selection and token bounds are data; no source or package is resolved.
    pub fn new(id: PresetId, model: String, max_output_tokens: u32) -> Result<Self> {
        let preset = Self {
            id,
            model: canon::session::Text::new(model)?,
            max_output_tokens,
        };
        preset.validate()?;
        Ok(preset)
    }

    pub fn validate(&self) -> Result<()> {
        let model = self.model.as_str();
        if model.is_empty()
            || model.chars().any(|c| c.is_whitespace() || c.is_control())
            || !(1..=MAX_OUTPUT_TOKENS).contains(&self.max_output_tokens)
        {
            return Err(codes::FRAME_INVALID_FIELD);
        }
        Ok(())
    }

    /// Session mode limits the preset's proposal operations independently of its id.
    pub fn require(&self, mode: SessionMode, name: &str) -> Result<BuiltinOperation> {
        self.validate()?;
        let operation = self.id.require(name)?;
        if !PresetId::for_mode(mode).permits(operation) {
            return Err(codes::FRAME_UNKNOWN_KIND);
        }
        Ok(operation)
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
