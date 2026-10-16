// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Refusal;

named_codes! {
    SESSION_SEQUENCE => ("session", "sequence", "The expected session sequence differs from durable storage."),
    SESSION_NOT_FOUND => ("session", "not-found", "The current principal has no such session."),
}
