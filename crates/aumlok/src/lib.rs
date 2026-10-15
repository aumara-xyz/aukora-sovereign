//! Acrostic phrases, random-root envelopes, durable identity binding, WebAuthn verification and passkey ceremonies.

pub mod ceremony;
pub mod webauthn;

pub mod binding;
pub mod envelope;
mod normalization;
pub mod phrase;
pub mod refresh;

pub use phrase::{Phrase, PhraseError};
