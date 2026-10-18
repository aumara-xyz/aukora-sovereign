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

/// Owner-pane JavaScript bindings; root and wrapping-key bytes have no export.
#[cfg(target_arch = "wasm32")]
pub mod browser {
    use super::owner::{OwnerBrowser, OwnerPhrase};
    use crate::{
        backup::{
            owner::OwnerPrf, BackupDownload, BackupRequest, PrfBinding, PrfEvaluationRequest,
        },
        ceremony::CeremonyId,
        envelope::{owner::IdentityRoot, EnvelopeV1, KdfParameters},
        refresh::{owner::RefreshDraft, ProtectedRefreshPhrase},
    };
    use canon::{ids::CredentialId, Refusal};
    use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

    fn js_refusal(value: Refusal) -> JsValue {
        JsValue::from_str(&value.to_string())
    }

    fn missing(reason: &'static str) -> JsValue {
        js_refusal(Refusal {
            organ: "aumlok",
            reason,
        })
    }

    /// One owner-frame session, disposed by the pane after pending prompts settle.
    #[wasm_bindgen]
    pub struct OwnerPhraseSession {
        browser: OwnerBrowser,
        root: Option<IdentityRoot>,
        current_phrase: Option<OwnerPhrase>,
        draft: Option<RefreshDraft>,
        assertion: Option<String>,
    }

    impl OwnerPhraseSession {
        fn check_frame(&self) -> core::result::Result<(), JsValue> {
            OwnerBrowser::verify(self.browser.owner_origin(), self.browser.shell_origin())
                .map(|_| ())
                .map_err(js_refusal)
        }

        fn root(&self) -> core::result::Result<&IdentityRoot, JsValue> {
            self.root.as_ref().ok_or_else(|| missing("phrase-locked"))
        }

        fn current_phrase(&self) -> core::result::Result<&OwnerPhrase, JsValue> {
            self.current_phrase
                .as_ref()
                .ok_or_else(|| missing("phrase-locked"))
        }

        fn draft(&self) -> core::result::Result<&RefreshDraft, JsValue> {
            self.draft.as_ref().ok_or_else(|| missing("refresh-input"))
        }
    }

    #[wasm_bindgen]
    impl OwnerPhraseSession {
        /// Verify browser location, direct framing and the sole configured ancestor.
        pub fn verify(
            owner_origin: &str,
            shell_origin: &str,
        ) -> core::result::Result<Self, JsValue> {
            let browser = OwnerBrowser::verify(owner_origin, shell_origin).map_err(js_refusal)?;
            Ok(Self {
                browser,
                root: None,
                current_phrase: None,
                draft: None,
                assertion: None,
            })
        }

        /// Parse locally and authenticate the supplied ciphertext; returns public correspondence only.
        pub fn unlock(
            &mut self,
            envelope: &[u8],
            entered: &str,
        ) -> core::result::Result<String, JsValue> {
            self.check_frame()?;
            self.root = None;
            self.current_phrase = None;
            self.draft = None;
            self.assertion = None;
            let envelope = EnvelopeV1::from_canonical_bytes(envelope).map_err(js_refusal)?;
            let phrase = OwnerPhrase::parse(&self.browser, entered).map_err(js_refusal)?;
            let root = crate::envelope::owner::open(&self.browser, &envelope, &phrase)
                .map_err(js_refusal)?;
            let identity = root.public_identity(&self.browser).map_err(js_refusal)?;
            self.root = Some(root);
            self.current_phrase = Some(phrase);
            Ok(identity.subject.to_string())
        }

        /// Draw and seal a replacement locally using production KDF costs.
        pub fn prepare(&mut self, ceremony: &str) -> core::result::Result<(), JsValue> {
            self.check_frame()?;
            self.draft = None;
            let ceremony = CeremonyId::from_hex(ceremony).map_err(js_refusal)?;
            self.draft = Some(
                crate::refresh::owner::prepare(
                    &self.browser,
                    self.root()?,
                    &ceremony,
                    KdfParameters::PRODUCTION,
                )
                .map_err(js_refusal)?,
            );
            Ok(())
        }

        /// Authenticate both the resume capsule and the same-root replacement.
        pub fn resume(
            &mut self,
            ceremony: &str,
            nonce: &[u8],
            ciphertext: &[u8],
            replacement: &[u8],
        ) -> core::result::Result<(), JsValue> {
            self.check_frame()?;
            self.draft = None;
            let ceremony = CeremonyId::from_hex(ceremony).map_err(js_refusal)?;
            let nonce = nonce.try_into().map_err(|_| missing("refresh-input"))?;
            let protected = ProtectedRefreshPhrase::from_parts(nonce, ciphertext.to_vec())
                .map_err(js_refusal)?;
            let envelope = EnvelopeV1::from_canonical_bytes(replacement).map_err(js_refusal)?;
            self.draft = Some(
                crate::refresh::owner::resume_draft(
                    &self.browser,
                    self.root()?,
                    &ceremony,
                    protected,
                    envelope,
                )
                .map_err(js_refusal)?,
            );
            Ok(())
        }

        /// Explicit owner-only display of the draft phrase, or the unlocked current phrase.
        pub fn phrase(&self) -> core::result::Result<String, JsValue> {
            self.check_frame()?;
            let phrase = match &self.draft {
                Some(draft) => draft.phrase(),
                None => self.current_phrase()?,
            };
            Ok(phrase.expose(&self.browser).to_owned())
        }

        /// Encrypted replacement bytes for the authenticated owner transport.
        pub fn replacement_envelope(&self) -> core::result::Result<Vec<u8>, JsValue> {
            self.check_frame()?;
            Ok(self.draft()?.ciphertexts().0.canonical_bytes().to_vec())
        }

        /// Public capsule nonce; this exposes no phrase bytes.
        pub fn protected_nonce(&self) -> core::result::Result<Vec<u8>, JsValue> {
            self.check_frame()?;
            Ok(self.draft()?.ciphertexts().1.parts().0.to_vec())
        }

        /// Authenticated capsule ciphertext; the key stays inside this session.
        pub fn protected_ciphertext(&self) -> core::result::Result<Vec<u8>, JsValue> {
            self.check_frame()?;
            Ok(self.draft()?.ciphertexts().1.parts().1.to_vec())
        }

        /// Adopt a byte-identical replacement locally; this is not node-commit evidence.
        pub fn adopt_replacement(&mut self, envelope: &[u8]) -> core::result::Result<(), JsValue> {
            self.check_frame()?;
            if self.draft()?.ciphertexts().0.canonical_bytes() != envelope {
                return Err(missing("refresh-stale"));
            }
            let draft = self.draft.take().ok_or_else(|| missing("refresh-input"))?;
            self.current_phrase = Some(draft.into_phrase());
            self.assertion = None;
            Ok(())
        }

        /// Drop an uncommitted local draft while retaining the unlocked current root.
        pub fn discard_draft(&mut self) -> core::result::Result<(), JsValue> {
            self.check_frame()?;
            self.draft = None;
            Ok(())
        }

        /// Default download requires the same credential's PRF under the original RP.
        #[allow(clippy::too_many_arguments)]
        pub async fn backup_v2(
            &mut self,
            credential_id: Vec<u8>,
            original_rp_id: String,
            ceremony: String,
            challenge: Vec<u8>,
            expected_epoch: u64,
            expires_at_ms: i64,
            signal: JsValue,
        ) -> core::result::Result<Vec<u8>, JsValue> {
            self.assertion = None;
            self.check_frame()?;
            self.root()?;
            self.current_phrase()?;
            if self.draft.is_some() {
                return Err(missing("refresh-pending"));
            }
            let request = PrfEvaluationRequest {
                binding: PrfBinding::new(
                    CredentialId::new(credential_id).map_err(js_refusal)?,
                    original_rp_id,
                )
                .map_err(js_refusal)?,
                ceremony: CeremonyId::from_hex(&ceremony).map_err(js_refusal)?,
                challenge: challenge
                    .try_into()
                    .map_err(|_| missing("backup-prf-metadata"))?,
                expected_epoch,
                expires_at_ms,
            };
            let prf = OwnerPrf::evaluate_with_signal(&self.browser, &request, Some(&signal))
                .await
                .map_err(js_refusal)?;
            self.check_frame()?;
            let downloaded = crate::backup::owner::download(
                &self.browser,
                self.root()?,
                self.current_phrase()?,
                BackupRequest::PasskeyBoundV2,
                Some(&prf),
                KdfParameters::PRODUCTION,
            )
            .map_err(js_refusal)?;
            let BackupDownload::PasskeyBound(envelope) = downloaded else {
                return Err(missing("backup-prf-required"));
            };
            self.assertion = Some(
                serde_json::to_string(prf.assertion()).map_err(|_| missing("assertion-refused"))?,
            );
            Ok(envelope.canonical_bytes().to_vec())
        }

        /// Public assertion from the latest completed backup attempt, without PRF output.
        pub fn backup_assertion(&self) -> core::result::Result<String, JsValue> {
            self.check_frame()?;
            self.assertion
                .clone()
                .ok_or_else(|| missing("backup-prf-required"))
        }

        /// Phrase-only recovery copy; no fallback from a refused v2 request calls this.
        pub fn backup_v1(&self) -> core::result::Result<Vec<u8>, JsValue> {
            self.check_frame()?;
            if self.draft.is_some() {
                return Err(missing("refresh-pending"));
            }
            let envelope = crate::envelope::owner::seal(
                &self.browser,
                self.root()?,
                self.current_phrase()?,
                KdfParameters::PRODUCTION,
            )
            .map_err(js_refusal)?;
            Ok(envelope.canonical_bytes().to_vec())
        }
    }
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
    use icu_normalizer::ComposingNormalizer;
    use js_sys::{Object, Reflect};
    use std::sync::OnceLock;
    use wasm_bindgen::JsValue;
    use zeroize::Zeroizing;

    /// Current generation lists, retained as pinned data.
    pub const ROOT_WORDS: &str = include_str!("../data/ROOT.txt");
    /// Current generation lists, retained as pinned data.
    pub const UNITE_WORDS: &str = include_str!("../data/UNITE.txt");
    /// Current generation lists, retained as pinned data.
    pub const RISE_WORDS: &str = include_str!("../data/RISE.txt");
    /// Current six-letter anchors; legacy lists are not a draw source.
    pub const ANCHORS: &str = include_str!("../data/ANCHORS.txt");

    const LEGACY_ANCHORS: &str = include_str!("../data/legacy/ANCHORS.txt");
    const LEGACY_WORDS: [&str; 3] = [
        include_str!("../data/legacy/ROOT.txt"),
        include_str!("../data/legacy/UNITE.txt"),
        include_str!("../data/legacy/RISE.txt"),
    ];
    const CURRENT_WORDS: [&str; 3] = [ROOT_WORDS, UNITE_WORDS, RISE_WORDS];
    const THEMES: [usize; 6] = [0, 0, 1, 1, 2, 2];

    fn refusal(reason: &'static str) -> Refusal {
        Refusal {
            organ: "aumlok",
            reason,
        }
    }

    struct Vocabulary {
        anchors: Vec<&'static str>,
        current: [Vec<&'static str>; 3],
        legacy: [Vec<&'static str>; 3],
        legacy_anchors: Vec<&'static str>,
    }

    fn vocabulary() -> &'static Vocabulary {
        static DATA: OnceLock<Vocabulary> = OnceLock::new();
        DATA.get_or_init(|| Vocabulary {
            anchors: ANCHORS.lines().collect(),
            current: CURRENT_WORDS.map(|text| text.lines().collect()),
            legacy: LEGACY_WORDS.map(|text| text.lines().collect()),
            legacy_anchors: LEGACY_ANCHORS.lines().collect(),
        })
    }

    fn assigned_in_unicode_13(scalar: char) -> bool {
        static RANGES: OnceLock<Vec<(u32, u32)>> = OnceLock::new();
        let ranges = RANGES.get_or_init(|| {
            include_str!("../data/unicode-13-assigned-ranges.txt")
                .lines()
                .filter_map(|line| {
                    let (start, end) = line.split_once(' ')?;
                    Some((
                        u32::from_str_radix(start, 16).ok()?,
                        u32::from_str_radix(end, 16).ok()?,
                    ))
                })
                .collect()
        });
        let value = u32::from(scalar);
        let end = ranges.partition_point(|&(start, _)| start <= value);
        end > 0 && value <= ranges[end - 1].1
    }

    fn uniform_index(count: usize) -> Result<usize> {
        let bound = u32::try_from(count).map_err(|_| refusal("empty-bucket"))?;
        if bound == 0 {
            return Err(refusal("empty-bucket"));
        }
        let cutoff = bound.wrapping_neg() % bound;
        loop {
            let mut random = [0; 4];
            getrandom::fill(&mut random).map_err(|_| refusal("random-unavailable"))?;
            let value = u32::from_le_bytes(random);
            if value >= cutoff {
                return Ok((value % bound) as usize);
            }
        }
    }

    /// Browser location and its sole ancestor must match the configured origins.
    pub struct OwnerBrowser {
        owner_origin: String,
        shell_origin: String,
    }

    impl OwnerBrowser {
        /// Accept only a direct owner frame beneath the configured HTTPS shell.
        pub fn verify(expected_owner: &str, expected_shell: &str) -> Result<Self> {
            for origin in [expected_owner, expected_shell] {
                let parsed = url::Url::parse(origin).map_err(|_| refusal("owner-origin"))?;
                if parsed.scheme() != "https" || parsed.origin().ascii_serialization() != origin {
                    return Err(refusal("owner-origin"));
                }
            }
            if expected_owner == expected_shell {
                return Err(refusal("owner-origin"));
            }
            let window = web_sys::window().ok_or_else(|| refusal("owner-origin"))?;
            let location = window.location();
            if location.origin().map_err(|_| refusal("owner-origin"))? != expected_owner {
                return Err(refusal("owner-origin"));
            }
            let parent = window
                .parent()
                .map_err(|_| refusal("owner-frame"))?
                .ok_or_else(|| refusal("owner-frame"))?;
            let top = window
                .top()
                .map_err(|_| refusal("owner-frame"))?
                .ok_or_else(|| refusal("owner-frame"))?;
            if Object::is(parent.as_ref(), window.as_ref())
                || !Object::is(parent.as_ref(), top.as_ref())
            {
                return Err(refusal("owner-frame"));
            }
            let ancestors = Reflect::get(location.as_ref(), &JsValue::from_str("ancestorOrigins"))
                .map_err(|_| refusal("owner-frame"))?;
            let length = Reflect::get(&ancestors, &JsValue::from_str("length"))
                .map_err(|_| refusal("owner-frame"))?;
            let shell = Reflect::get(&ancestors, &JsValue::from_str("0"))
                .map_err(|_| refusal("owner-frame"))?;
            if length.as_f64() != Some(1.0) || shell.as_string().as_deref() != Some(expected_shell)
            {
                return Err(refusal("owner-frame"));
            }
            Ok(Self {
                owner_origin: expected_owner.to_owned(),
                shell_origin: expected_shell.to_owned(),
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
        /// The parsing contract is NFKC, lowercase,
        /// whitespace normalization, seven words, membership and acrostic checks.
        /// Current and legacy vocabularies are accepted only for typed recovery.
        pub fn parse(browser: &OwnerBrowser, entered: &str) -> Result<Self> {
            OwnerBrowser::verify(browser.owner_origin(), browser.shell_origin())?;
            if entered.len() > super::MAX_PHRASE_BYTES {
                return Err(refusal("phrase-too-long"));
            }
            // Later compatibility characters cannot acquire an older word spelling.
            if !entered.chars().all(assigned_in_unicode_13) {
                return Err(refusal("phrase-membership"));
            }
            let compatible = Zeroizing::new(
                ComposingNormalizer::new_nfkc()
                    .normalize(entered)
                    .into_owned(),
            );
            let lower = Zeroizing::new(compatible.to_lowercase());
            let words: Vec<&str> = lower.split_whitespace().collect();
            if words.len() != super::WORD_COUNT {
                return Err(refusal("phrase-word-count"));
            }
            let data = vocabulary();
            let anchor = words[0];
            if data.anchors.binary_search(&anchor).is_err()
                && data.legacy_anchors.binary_search(&anchor).is_err()
            {
                return Err(refusal("phrase-anchor"));
            }
            for (position, theme) in THEMES.into_iter().enumerate() {
                let word = words[position + 1];
                if data.current[theme].binary_search(&word).is_err()
                    && data.legacy[theme].binary_search(&word).is_err()
                {
                    return Err(refusal("phrase-membership"));
                }
                if word.as_bytes().first() != anchor.as_bytes().get(position) {
                    return Err(refusal("phrase-acrostic"));
                }
            }
            Ok(Self(Zeroizing::new(words.join(" "))))
        }

        /// Generation uses unbiased independent selection
        /// from current anchors and their six current theme/letter buckets.
        pub fn draw(browser: &OwnerBrowser) -> Result<Self> {
            OwnerBrowser::verify(browser.owner_origin(), browser.shell_origin())?;
            let data = vocabulary();
            let anchor = data.anchors[uniform_index(data.anchors.len())?];
            let mut phrase = Zeroizing::new(String::from(anchor));
            for (position, theme) in THEMES.into_iter().enumerate() {
                let bucket: Vec<&str> = data.current[theme]
                    .iter()
                    .copied()
                    .filter(|word| word.as_bytes().first() == anchor.as_bytes().get(position))
                    .collect();
                let word = bucket[uniform_index(bucket.len())?];
                phrase.push(' ');
                phrase.push_str(word);
            }
            Ok(Self(phrase))
        }

        /// Explicit plaintext access for the owner screen and local KDF only.
        pub fn expose<'a>(&'a self, _browser: &OwnerBrowser) -> &'a str {
            self.0.as_str()
        }
    }

    #[cfg(test)]
    mod write_tests {
        use super::*;
        use crate::{backup::BackupRequest, envelope::{owner::IdentityRoot, KdfParameters}};

        // Export only from a wasm test build. Node runs it with browser/random imports that throw, so a weak
        // write must refuse before either API consults the browser, obtains randomness or starts encryption.
        #[wasm_bindgen::prelude::wasm_bindgen]
        pub fn write_kdf_floor_probe() -> bool {
            let browser = OwnerBrowser { owner_origin: "https://owner.example".into(), shell_origin: "https://shell.example".into() };
            let phrase = OwnerPhrase(Zeroizing::new("disposable fixture phrase".into()));
            let root = IdentityRoot::from_secret(Zeroizing::new([0; 32]));
            for (memory_kib, time_cost) in [(32, 1), (65_535, 3), (262_144, 2)] {
                let costs = KdfParameters { memory_kib, time_cost, parallelism: 1 };
                let expected = refusal("envelope-kdf-weak");
                if crate::envelope::owner::seal(&browser, &root, &phrase, costs).err() != Some(expected) {
                    return false;
                }
                for choice in [BackupRequest::ExplicitPhraseOnlyV1, BackupRequest::PasskeyBoundV2] {
                    if crate::backup::owner::download(&browser, &root, &phrase, choice, None, costs).err() != Some(expected) {
                        return false;
                    }
                }
            }
            true
        }

        #[test]
        fn both_write_apis_refuse_weak_costs_before_encryption() {
            assert!(write_kdf_floor_probe());
        }
    }

}
