// SPDX-License-Identifier: AGPL-3.0-or-later
//! Static site bytes are prepared inside the cage and queued for owner review.

use crate::{
    action_gate::{LocalDisposition, LocalGate},
    dispatch::{DispatchItem, SuggestionDecoder, ToolName},
    fd3::SupervisorLink,
    presets::{BuiltinOperation, PresetId},
};
use canon::{
    authority::BaseDigest,
    codes,
    digest::Digest32,
    fd3::{self, Reply, Request},
    fd3_payloads::sites::{SiteBundle, SiteProposal},
    frame::{Frame, FrameError, FrameId},
    ids::ProposalId,
    json::{self, Value, ValueView},
    provenance::{Provenance, Source},
    session::SessionMode,
    Refusal, Result,
};

pub use canon::fd3_payloads::sites::SiteFile;

pub(crate) fn tool_spec() -> (&'static str, &'static str) {
    (
        "Build a static site from UTF-8 file contents and queue its exact bundle for owner review. Use base_sha256 absent for first publication or the digest of the existing bundle for replacement. Acceptance is pending; note is untrusted model text.",
        r#"{"type":"object","additionalProperties":false,"required":["host","files","base_sha256","note"],"properties":{"host":{"type":"string","maxLength":253},"files":{"type":"array","minItems":1,"maxItems":64,"items":{"type":"object","additionalProperties":false,"required":["path","content"],"properties":{"path":{"type":"string","maxLength":192},"content":{"type":"string","maxLength":32768}}}},"base_sha256":{"type":"string","pattern":"^(absent|[0-9a-f]{64})$"},"note":{"type":"string"}}}"#,
    )
}

/// Tool arguments are literal file data; only a closed v2 request leaves the cage.
pub(crate) fn decode_suggestion(arguments: &str) -> Result<Request> {
    if arguments.len() > canon::frame::MAX_FRAME_BYTES {
        return Err(codes::FRAME_TOO_LARGE);
    }
    let value = json::parse_strict(arguments.as_bytes())?;
    exact_fields(&value, &["host", "files", "base_sha256", "note"])?;
    let ValueView::Array(files) = field(&value, "files")?.view() else {
        return Err(codes::FRAME_INVALID_FIELD);
    };
    if files.is_empty() || files.len() > canon::fd3_payloads::sites::MAX_FILES {
        return Err(codes::CANON_SITE_BUNDLE_LIMIT);
    }
    let mut generated = Vec::with_capacity(files.len());
    for file in files {
        exact_fields(file, &["path", "content"])?;
        let path = text(field(file, "path")?)?;
        let media_type = canon::fd3_payloads::sites::media_type(path)?;
        if !matches!(
            media_type,
            "text/html" | "text/css" | "text/javascript" | "text/plain" | "application/json"
        ) {
            return Err(codes::CANON_SITE_MEDIA_INVALID);
        }
        generated.push(SiteFile {
            path: path.to_owned(),
            media_type: media_type.to_owned(),
            bytes: text(field(file, "content")?)?.as_bytes().to_vec(),
        });
    }
    let base_text = text(field(&value, "base_sha256")?)?;
    let request = Request::SitePropose(SiteProposal {
        bundle: SiteBundle::build(text(field(&value, "host")?)?, &generated)?,
        base: if base_text == "absent" {
            BaseDigest::Absent
        } else {
            BaseDigest::Present(
                Digest32::from_hex(base_text).map_err(|_| codes::CANON_SITE_BUNDLE_INVALID)?,
            )
        },
        note: text(field(&value, "note")?)?.to_owned(),
    });
    fd3::encode_request(&crate::fd3::request(
        FrameId::new("site-suggestion".into())?,
        request.clone(),
    ))?;
    Ok(request)
}

pub(crate) fn prepare_suggestion(
    suggestion: &canon::fd3_payloads::ToolCall,
    decoder: &mut impl SuggestionDecoder,
    gate: &LocalGate,
    mode: SessionMode,
) -> Result<DispatchItem> {
    if mode != SessionMode::Build {
        return Err(codes::FRAME_UNKNOWN_KIND);
    }
    let expected = decode_suggestion(&suggestion.arguments)?;
    let request = decoder.decode(ToolName::SitesPropose, &suggestion.arguments)?;
    if request != expected {
        return Err(codes::FRAME_INVALID_FIELD);
    }
    let disposition = gate.judge(&request, mode)?;
    if disposition != LocalDisposition::PendingOwnerReview {
        return Err(codes::FRAME_UNKNOWN_KIND);
    }
    Ok(DispatchItem {
        call_id: suggestion.id.clone(),
        request,
        disposition,
    })
}

pub(crate) fn check_model_tools_with_sites(
    call: &canon::fd3_payloads::ModelCall,
    preset: PresetId,
    mode: SessionMode,
) -> Result<()> {
    if call.tools.len() > 6 {
        return Err(codes::FRAME_INVALID_FIELD);
    }
    for (index, tool) in call.tools.iter().enumerate() {
        let operation = match tool.name.as_str() {
            "sites.propose" | "propose" | "read" => BuiltinOperation::Proposals,
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

fn field<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    value.get(key).ok_or(codes::FRAME_MISSING_FIELD)
}

fn text(value: &Value) -> Result<&str> {
    match value.view() {
        ValueView::Text(text) => Ok(text),
        _ => Err(codes::FRAME_INVALID_FIELD),
    }
}

fn exact_fields(value: &Value, expected: &[&str]) -> Result<()> {
    let ValueView::Object(fields) = value.view() else {
        return Err(codes::FRAME_NOT_OBJECT);
    };
    if fields.len() != expected.len()
        || fields
            .iter()
            .any(|(key, _)| !expected.contains(&key.as_str()))
    {
        return Err(codes::FRAME_INVALID_FIELD);
    }
    Ok(())
}

/// An immutable canonical bundle; constructing it runs no submitted content.
#[derive(Clone, Debug)]
pub struct SiteDraft {
    bundle: SiteBundle,
}

impl SiteDraft {
    /// Validate paths, MIME types, host, canonical encoding and the bundle budget.
    pub fn build(host: &str, files: &[SiteFile]) -> Result<Self> {
        Ok(Self {
            bundle: SiteBundle::build(host, files)?,
        })
    }

    /// Strictly decode a complete generated bundle rather than interpreting its content.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            bundle: SiteBundle::decode(bytes)?,
        })
    }

    pub fn bundle(&self) -> &SiteBundle {
        &self.bundle
    }

    /// Build mode and the local target allowlist both apply before a request is sent.
    /// The base is explicit: absence is distinct from an empty existing bundle.
    pub fn prepare(
        &self,
        id: FrameId,
        base: BaseDigest,
        note: String,
        gate: &LocalGate,
        mode: SessionMode,
    ) -> Result<PreparedSite> {
        let request = Request::SitePropose(SiteProposal {
            bundle: self.bundle.clone(),
            base,
            note,
        });
        if mode != SessionMode::Build
            || gate.judge(&request, mode)? != LocalDisposition::PendingOwnerReview
        {
            return Err(codes::FRAME_UNKNOWN_KIND);
        }
        let frame = Frame {
            v: fd3::V2,
            id,
            provenance: auma(),
            body: request,
        };
        let bytes = fd3::encode_request(&frame)?;
        Ok(PreparedSite {
            proposed_address: format!("https://{}/", self.bundle.host()),
            bundle_sha256: self.bundle.digest(),
            request_sha256: Digest32::sha256(&bytes),
            frame,
        })
    }
}

/// Exact bytes can be inspected before sending through an attached FD 3 link.
#[derive(Debug)]
pub struct PreparedSite {
    frame: Frame<Request>,
    proposed_address: String,
    bundle_sha256: Digest32,
    request_sha256: Digest32,
}

impl PreparedSite {
    pub fn request(&self) -> &Frame<Request> {
        &self.frame
    }

    /// Hash of the actual serialized request, including its correlation id.
    pub fn request_sha256(&self) -> Digest32 {
        self.request_sha256
    }

    pub fn bundle_sha256(&self) -> Digest32 {
        self.bundle_sha256
    }

    pub fn proposed_address(&self) -> &str {
        &self.proposed_address
    }

    /// Sends data only; successful delivery still has no approval or publication.
    pub fn send(
        self,
        link: &mut impl SupervisorLink,
    ) -> core::result::Result<PendingSite, FrameError> {
        let request_id = self.frame.id.clone();
        link.send(self.frame)?;
        Ok(PendingSite {
            request_id,
            proposed_address: self.proposed_address,
            bundle_sha256: self.bundle_sha256,
            progress: SiteProgress::AwaitingReceipt,
        })
    }
}

/// These states report matching receipts; none authorizes another effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SiteProgress {
    AwaitingReceipt,
    PendingOwner(ProposalId),
    Observed {
        proposal_id: ProposalId,
        state: canon::fd3_payloads::OutcomeState,
    },
    Refused(Refusal),
}

#[derive(Debug)]
pub struct PendingSite {
    request_id: FrameId,
    proposed_address: String,
    bundle_sha256: Digest32,
    progress: SiteProgress,
}

impl PendingSite {
    pub fn request_id(&self) -> &FrameId {
        &self.request_id
    }

    pub fn proposed_address(&self) -> &str {
        &self.proposed_address
    }

    pub fn bundle_sha256(&self) -> Digest32 {
        self.bundle_sha256
    }

    pub fn progress(&self) -> SiteProgress {
        self.progress
    }

    /// The link supplies channel-stamped replies; text never supplies a receipt.
    /// A mismatched, repeated or out-of-order reply leaves progress unchanged.
    pub fn observe(&mut self, reply: &Frame<Reply>) -> Result<SiteProgress> {
        fd3::encode_reply(reply)?;
        if reply.id != self.request_id {
            return Err(codes::FRAME_INVALID_ID);
        }
        if reply.v != fd3::V2 || reply.provenance != auma() {
            return Err(codes::FRAME_PROVENANCE);
        }
        let next = match (self.progress, &reply.body) {
            (SiteProgress::AwaitingReceipt, Reply::Accepted(accepted)) => {
                SiteProgress::PendingOwner(accepted.proposal_id)
            }
            (SiteProgress::PendingOwner(proposal_id), Reply::Outcome(outcome))
                if proposal_id == outcome.proposal_id =>
            {
                SiteProgress::Observed {
                    proposal_id,
                    state: outcome.state,
                }
            }
            (SiteProgress::AwaitingReceipt, Reply::Refusal(refusal)) => {
                SiteProgress::Refused(refusal.code)
            }
            _ => return Err(codes::FRAME_STREAM_ORDER),
        };
        self.progress = next;
        Ok(next)
    }
}

fn auma() -> Provenance {
    Provenance {
        source: Source::Auma,
    }
}
