// SPDX-License-Identifier: AGPL-3.0-or-later

use canon::digest::Digest32;
use core::fmt;
use std::num::NonZeroU16;

pub const MAX_QUERY_BYTES: usize = 1_536;
pub const MAX_DOCUMENT_BYTES: usize = 384;
pub const MAX_EMBEDDING_DIMENSIONS: usize = 8_192;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmbedError {
    Input,
    Model,
    Vector,
    Unavailable,
}

impl EmbedError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Input => "kira:embedding-input",
            Self::Model => "kira:embedding-model",
            Self::Vector => "kira:embedding-vector",
            Self::Unavailable => "kira:embedding-unavailable",
        }
    }
}

impl fmt::Display for EmbedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for EmbedError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalEndpoint {
    InProcess,
    Loopback(NonZeroU16),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalModel {
    digest: Digest32,
    dimensions: u16,
}

impl LocalModel {
    pub fn new(digest: Digest32, dimensions: u16) -> Result<Self, EmbedError> {
        if dimensions == 0 || usize::from(dimensions) > MAX_EMBEDDING_DIMENSIONS {
            return Err(EmbedError::Model);
        }
        Ok(Self { digest, dimensions })
    }

    pub const fn digest(self) -> Digest32 {
        self.digest
    }

    pub const fn dimensions(self) -> u16 {
        self.dimensions
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmbedPurpose {
    Query,
    Document,
}

#[derive(Clone, Copy)]
pub struct EmbedInput<'a> {
    purpose: EmbedPurpose,
    text: &'a str,
}

impl<'a> EmbedInput<'a> {
    pub fn new(purpose: EmbedPurpose, text: &'a str) -> Result<Self, EmbedError> {
        let limit = match purpose {
            EmbedPurpose::Query => MAX_QUERY_BYTES,
            EmbedPurpose::Document => MAX_DOCUMENT_BYTES,
        };
        if text.trim().is_empty() || text.len() > limit || text.contains('\0') {
            return Err(EmbedError::Input);
        }
        Ok(Self { purpose, text })
    }

    pub const fn purpose(self) -> EmbedPurpose {
        self.purpose
    }

    pub const fn text(self) -> &'a str {
        self.text
    }
}

impl fmt::Debug for EmbedInput<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmbedInput")
            .field("purpose", &self.purpose)
            .field("bytes", &self.text.len())
            .finish_non_exhaustive()
    }
}

pub struct Embedding {
    model: LocalModel,
    values: Vec<f32>,
}

impl Embedding {
    pub fn new(model: LocalModel, values: Vec<f32>) -> Result<Self, EmbedError> {
        if values.len() != usize::from(model.dimensions())
            || values.iter().any(|value| !value.is_finite())
            || values.iter().all(|value| *value == 0.0)
        {
            return Err(EmbedError::Vector);
        }
        Ok(Self { model, values })
    }

    pub const fn model(&self) -> LocalModel {
        self.model
    }

    pub fn values(&self) -> &[f32] {
        &self.values
    }
}

impl fmt::Debug for Embedding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Embedding")
            .field("model", &self.model)
            .finish_non_exhaustive()
    }
}

pub trait LocalEmbedder {
    fn endpoint(&self) -> LocalEndpoint;
    fn model(&self) -> LocalModel;
    fn embed(&mut self, input: EmbedInput<'_>) -> Result<Embedding, EmbedError>;
}
