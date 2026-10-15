// SPDX-License-Identifier: AGPL-3.0-or-later
//! Phrase data and owner-browser contracts. Secret-bearing APIs exist only on wasm32.

/// Seven words: one six-letter anchor and six themed acrostic words.
pub const WORD_COUNT: usize = 7;
/// Bound on the entered UTF-8 phrase before normalization.
pub const MAX_PHRASE_BYTES: usize = 1_024;

/// A position's vocabulary, without any entered phrase text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhraseTheme {
    /// Nature vocabulary for positions two and three.
    Root,
    /// People and connection vocabulary for positions four and five.
    Unite,
    /// Spirit, space and technology vocabulary for positions six and seven.
    Rise,
}

/// The six acrostic positions after the anchor.
pub const SLOT_THEMES: [PhraseTheme; 6] = [
    PhraseTheme::Root,
    PhraseTheme::Root,
    PhraseTheme::Unite,
    PhraseTheme::Unite,
    PhraseTheme::Rise,
    PhraseTheme::Rise,
];

/// Display statistics of the shipped lists, not an authorization criterion.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PhraseEntropy {
    /// Minimum entropy, rounded to the pinned display precision.
    pub minimum_bits: f64,
    /// Average entropy, rounded to the pinned display precision.
    pub average_bits: f64,
    /// Number of uniformly selected current anchors.
    pub anchor_count: usize,
}

/// Pinned list statistics; no 64-bit or 77-bit claim applies to this vocabulary.
pub const SHIPPED_ENTROPY: PhraseEntropy = PhraseEntropy {
    minimum_bits: 41.5,
    average_bits: 43.1,
    anchor_count: 92,
};

/// Owner-browser-only entry points; the native node has no phrase-taking function.
#[cfg(target_arch = "wasm32")]
pub mod owner {
    use canon::{Refusal, Result};
    use zeroize::Zeroizing;

    /// Current generation lists, retained as pinned data.
    pub const ROOT_WORDS: &str = include_str!("../data/ROOT.txt");
    /// Current generation lists, retained as pinned data.
    pub const UNITE_WORDS: &str = include_str!("../data/UNITE.txt");
    /// Current generation lists, retained as pinned data.
    pub const RISE_WORDS: &str = include_str!("../data/RISE.txt");
    /// Current six-letter anchors; legacy lists are not a draw source.
    pub const ANCHORS: &str = include_str!("../data/ANCHORS.txt");

    /// No caller-supplied origin string constructs a verified browser context.
    /// Wave 0 has no successful constructor.
    pub struct OwnerBrowser {
        owner_origin: String,
        shell_origin: String,
    }

    impl OwnerBrowser {
        /// Wave-0 refusal. Wave 1 must inspect the actual browser location and
        /// shell-created owner frame before admitting either expected origin.
        pub fn verify(_expected_owner: &str, _expected_shell: &str) -> Result<Self> {
            Err(Refusal {
                organ: "aumlok",
                reason: "not-implemented",
            })
        }

        /// Borrow the verified owner origin; unavailable before verification.
        pub fn owner_origin(&self) -> &str {
            &self.owner_origin
        }

        /// Borrow the verified shell origin; unavailable before verification.
        pub fn shell_origin(&self) -> &str {
            &self.shell_origin
        }
    }

    /// Phrase plaintext has no Debug, Display, Serialize or native-node API.
    pub struct OwnerPhrase(Zeroizing<String>);

    impl OwnerPhrase {
        /// Wave-0 refusal. The frozen parsing contract is NFKC, lowercase,
        /// whitespace normalization, seven words, membership and acrostic checks.
        /// Current and legacy vocabularies are accepted only for typed recovery.
        pub fn parse(_browser: &OwnerBrowser, _entered: &str) -> Result<Self> {
            Err(Refusal {
                organ: "aumlok",
                reason: "not-implemented",
            })
        }

        /// Wave-0 refusal. Generation requires unbiased independent selection
        /// from current anchors and their six current theme/letter buckets.
        pub fn draw(_browser: &OwnerBrowser) -> Result<Self> {
            Err(Refusal {
                organ: "aumlok",
                reason: "not-implemented",
            })
        }

        /// Explicit plaintext access for the owner screen and local KDF only.
        pub fn expose<'a>(&'a self, _browser: &OwnerBrowser) -> &'a str {
            self.0.as_str()
        }
    }
}
