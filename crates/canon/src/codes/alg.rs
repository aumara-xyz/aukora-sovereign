// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Refusal;

named_codes! {
    ALG_UNSUPPORTED => ("alg", "unsupported", "The algorithm identifier is not supported in this context."),
    ALG_EMPTY_SIGNATURES => ("alg", "empty-signatures", "A signed record requires at least one component signature."),
}
