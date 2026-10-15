// SPDX-License-Identifier: AGPL-3.0-or-later
//! A target is replaced in an owned memory clone before card preparation.
//! Shadow observations carry no owner proof or permission to apply live bytes.

use crate::hostile::{Limits, Usage};
use canon::{
    authority::{BaseDigest, CellCommitment},
    digest::Digest32,
    ids::{NodeId, OperationDigest, ProposalId},
    json::{self, SafeInteger, Value},
    Refusal, Result,
};
use std::time::{Duration, Instant};

const TARGET_BYTES: usize = 65_536;
const MAX_FINDINGS: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowRequest {
    pub proposal: ProposalId,
    pub operation: OperationDigest,
    pub target: String,
    pub base: BaseDigest,
    pub source_snapshot: Digest32,
    pub exact_proposed_bytes: Vec<u8>,
    pub release: Digest32,
    pub limits: Limits,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verdict {
    Clear,
    Refused,
    Undetermined,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShadowObservation {
    pub proposal: ProposalId,
    pub operation: OperationDigest,
    pub source_snapshot: Digest32,
    /// SHA-256 of the exact cloned target's replacement bytes.
    pub shadow_snapshot: Digest32,
    pub live_before: Digest32,
    pub live_after: Digest32,
    pub verdict: Verdict,
    pub findings: Vec<String>,
    pub budget_exhausted: bool,
}

pub trait ShadowDriver {
    fn inspect_shadow(&mut self, request: &ShadowRequest) -> Result<ShadowObservation>;
}

pub fn inspect(
    request: &ShadowRequest,
    driver: &mut impl ShadowDriver,
) -> Result<ShadowObservation> {
    request.validate()?;
    let began = Instant::now();
    let observation = driver.inspect_shadow(request)?;
    if observation.proposal != request.proposal
        || observation.operation != request.operation
        || observation.source_snapshot != request.source_snapshot
        || observation.shadow_snapshot != Digest32::sha256(&request.exact_proposed_bytes)
        || observation.live_before != request.source_snapshot
        || observation.live_before != observation.live_after
        || !findings_fit(&observation.findings, request.limits.output_bytes)
        || (observation.verdict == Verdict::Clear && !observation.findings.is_empty())
        || observation.budget_exhausted
        || began.elapsed() > Duration::from_millis(request.limits.wall_ms)
    {
        return Err(refusal("shadow-incomplete"));
    }
    Ok(observation)
}

impl ShadowRequest {
    pub fn validate(&self) -> Result<()> {
        self.limits.validate()?;
        if !target_valid(&self.target)
            || self.exact_proposed_bytes.len() > TARGET_BYTES
            || self.exact_proposed_bytes.capacity() as u64 > self.limits.memory_bytes
        {
            return Err(refusal("shadow-input"));
        }
        let source = match self.base {
            BaseDigest::Absent => Digest32::sha256(&[]),
            BaseDigest::Present(digest) => digest,
        };
        if self.source_snapshot != source {
            return Err(refusal("shadow-binding"));
        }
        Ok(())
    }
}

/// Calls the card builder only after a complete clear inspection. The builder
/// still owns C6 display bytes; its result is not an approval or an effect permit.
pub fn before_card<T>(
    request: &ShadowRequest,
    driver: &mut impl ShadowDriver,
    build: impl FnOnce(&ShadowObservation) -> Result<T>,
) -> Result<T> {
    let observation = inspect(request, driver)?;
    match observation.verdict {
        Verdict::Clear => build(&observation),
        Verdict::Refused => Err(refusal("shadow-refused")),
        Verdict::Undetermined => Err(refusal("shadow-undetermined")),
    }
}

/// A single target's captured bytes and its proposed replacement. Neither slice
/// is a filesystem handle, a command, or a live target adapter.
pub struct Candidate<'a> {
    pub target: &'a str,
    pub before: Option<&'a [u8]>,
    pub after: &'a [u8],
    pub release: Digest32,
}

/// An inspector supplies its own measured work and records incomplete checks.
/// TargetShadow reserves its buffers and target reads before assigning the
/// inspector's remaining memory and IO limits, then checks aggregate usage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Inspection {
    pub verdict: Verdict,
    pub findings: Vec<String>,
    pub usage: Usage,
    pub complete: bool,
}

/// Trusted host inspection over cloned data. A missing inspector cannot clear
/// a proposal. Host code must account for its work in the returned usage.
pub trait Inspector {
    fn inspect(&mut self, candidate: Candidate<'_>, limits: Limits) -> Result<Inspection>;
}

/// Read-only host port for the actual configured target, called at capture and
/// on both sides of inspection. It must resolve the live target each time.
pub trait TargetReader {
    fn read_target(&mut self, target: &str) -> Result<Option<Vec<u8>>>;
}

/// A host-supplied directory capability. Every component is reopened without
/// following symlinks; reads are bounded and no write descriptor is created.
#[cfg(unix)]
pub struct DirectoryReader {
    directory: std::fs::File,
}

#[cfg(unix)]
impl DirectoryReader {
    pub fn new(directory: std::fs::File) -> Result<Self> {
        if !directory
            .metadata()
            .map_err(|_| refusal("shadow-read"))?
            .is_dir()
        {
            return Err(refusal("shadow-input"));
        }
        Ok(Self { directory })
    }
}

#[cfg(unix)]
impl TargetReader for DirectoryReader {
    fn read_target(&mut self, target: &str) -> Result<Option<Vec<u8>>> {
        use rustix::fs::{openat, Mode, OFlags};
        use std::{fs::File, io::Read, os::unix::fs::MetadataExt};
        if !target_valid(target) {
            return Err(refusal("shadow-input"));
        }
        let mut directory = self
            .directory
            .try_clone()
            .map_err(|_| refusal("shadow-read"))?;
        let mut components = target.split('/').peekable();
        while let Some(component) = components.next() {
            let last = components.peek().is_none();
            let mut flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
            flags |= if last {
                OFlags::NONBLOCK
            } else {
                OFlags::DIRECTORY
            };
            let descriptor = match openat(&directory, component, flags, Mode::empty()) {
                Ok(descriptor) => descriptor,
                Err(rustix::io::Errno::NOENT) => return Ok(None),
                Err(_) => return Err(refusal("shadow-read")),
            };
            let file = File::from(descriptor);
            if !last {
                directory = file;
                continue;
            }
            let before = file.metadata().map_err(|_| refusal("shadow-read"))?;
            if !before.is_file() || before.len() > TARGET_BYTES as u64 {
                return Err(refusal("shadow-input"));
            }
            let mut bytes = Vec::with_capacity(before.len() as usize + 1);
            (&file)
                .take(before.len() + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| refusal("shadow-read"))?;
            let after = file.metadata().map_err(|_| refusal("shadow-read"))?;
            if bytes.len() > TARGET_BYTES
                || bytes.len() as u64 != before.len()
                || before.len() != after.len()
                || before.mtime() != after.mtime()
                || before.mtime_nsec() != after.mtime_nsec()
                || before.ctime() != after.ctime()
                || before.ctime_nsec() != after.ctime_nsec()
            {
                return Err(refusal("shadow-stale-source"));
            }
            return Ok(Some(bytes));
        }
        Err(refusal("shadow-input"))
    }
}

/// An in-memory shadow of one target, captured by the trusted host. Snapshot
/// digests are SHA-256 of the exact target bytes; absence uses the empty byte
/// digest and remains distinct from an empty target through `BaseDigest`.
/// This adapter checks target-local invariants; it does not clone a process,
/// database, or filesystem and cannot attest to invariants outside that target.
pub struct TargetShadow<R, I> {
    node: NodeId,
    release: Digest32,
    target: String,
    cell: Option<CellCommitment>,
    source: Option<Vec<u8>>,
    reader: R,
    inspector: I,
}

impl<R: TargetReader, I: Inspector> TargetShadow<R, I> {
    pub fn new(
        node: NodeId,
        release: Digest32,
        target: String,
        cell: Option<CellCommitment>,
        mut reader: R,
        inspector: I,
    ) -> Result<Self> {
        if !target_valid(&target) {
            return Err(refusal("shadow-input"));
        }
        let source = reader.read_target(&target)?;
        if source.as_ref().is_some_and(|s| s.len() > TARGET_BYTES) {
            return Err(refusal("shadow-input"));
        }
        Ok(Self {
            node,
            release,
            target,
            cell,
            source,
            reader,
            inspector,
        })
    }

    pub fn source_snapshot(&self) -> Digest32 {
        Digest32::sha256(self.source.as_deref().unwrap_or_default())
    }

    pub fn base(&self) -> BaseDigest {
        match &self.source {
            Some(bytes) => BaseDigest::Present(Digest32::sha256(bytes)),
            None => BaseDigest::Absent,
        }
    }

    /// The frozen C5 operation-content commitment, including the host's node and
    /// cell commitments. A claimed operation on another target cannot reuse it.
    pub fn operation(&self, proposed: &[u8]) -> Result<OperationDigest> {
        if proposed.len() > TARGET_BYTES {
            return Err(refusal("shadow-input"));
        }
        let cell = match self.cell {
            None => Value::null(),
            Some(cell) => Value::object(vec![
                ("module_sha256".into(), text(cell.module_sha256)?),
                ("input_sha256".into(), text(cell.input_sha256)?),
                ("effect_sha256".into(), text(cell.effect_sha256)?),
            ])?,
        };
        let base = match self.base() {
            BaseDigest::Absent => "absent".into(),
            BaseDigest::Present(digest) => digest.to_string(),
        };
        let content = Value::object(vec![
            ("v".into(), Value::integer(SafeInteger::new(1)?)),
            ("node".into(), text(self.node)?),
            ("target".into(), text(&self.target)?),
            ("base_sha256".into(), text(base)?),
            ("new_sha256".into(), text(Digest32::sha256(proposed))?),
            ("cell".into(), cell),
        ])?;
        let mut input = canon::domain::OPERATION_CONTENT_DOMAIN.as_bytes().to_vec();
        input.push(0);
        input.extend(json::to_canonical(&content));
        Ok(OperationDigest::from_digest(Digest32::sha256(&input)))
    }
}

impl<R: TargetReader, I: Inspector> ShadowDriver for TargetShadow<R, I> {
    fn inspect_shadow(&mut self, request: &ShadowRequest) -> Result<ShadowObservation> {
        request.validate()?;
        let began = Instant::now();
        let source_len = self.source.as_ref().map_or(0, Vec::len);
        let read_bytes = 2 * source_len as u64;
        if read_bytes > request.limits.io_bytes {
            return Err(refusal("attack-budget"));
        }
        let live = self.reader.read_target(&self.target)?;
        if live != self.source {
            return Err(refusal("shadow-stale-source"));
        }
        let before = self.source_snapshot();
        if request.target != self.target
            || request.release != self.release
            || request.source_snapshot != before
            || request.base != self.base()
            || request.operation != self.operation(&request.exact_proposed_bytes)?
        {
            return Err(refusal("shadow-binding"));
        }
        // Bound owned buffer capacity, including the request retained by the caller.
        let source_capacity = self.source.as_ref().map_or(0, Vec::capacity) as u64;
        let live_capacity = live.as_ref().map_or(0, Vec::capacity) as u64;
        let shadow_capacity = source_len.max(request.exact_proposed_bytes.len());
        let retained = source_capacity + request.exact_proposed_bytes.capacity() as u64;
        let mut resident = retained + live_capacity + shadow_capacity as u64;
        if resident > request.limits.memory_bytes
            || began.elapsed() > Duration::from_millis(request.limits.wall_ms)
        {
            return Err(refusal("attack-budget"));
        }
        let inspection_limits = Limits {
            memory_bytes: request.limits.memory_bytes - resident,
            io_bytes: request.limits.io_bytes - read_bytes,
            ..request.limits
        }
        .validate()?;
        let mut shadow = Vec::with_capacity(shadow_capacity);
        if let Some(source) = &self.source {
            shadow.extend_from_slice(source);
        }
        shadow.clear();
        shadow.extend_from_slice(&request.exact_proposed_bytes);
        let inspected = self.inspector.inspect(
            Candidate {
                target: &self.target,
                before: self.source.as_deref(),
                after: &shadow,
                release: self.release,
            },
            inspection_limits,
        )?;
        inspection_limits.permits(inspected.usage, inspected.usage.cases)?;
        drop(live);
        let after = self.reader.read_target(&self.target)?;
        if after != self.source {
            return Err(refusal("shadow-live-changed"));
        }
        resident = resident.max(
            retained + after.as_ref().map_or(0, Vec::capacity) as u64 + shadow.capacity() as u64,
        );
        let findings_bytes = inspected.findings.iter().try_fold(0_u32, |sum, finding| {
            sum.checked_add(u32::try_from(finding.len()).ok()?)
        });
        let findings_memory = inspected.findings.iter().try_fold(
            inspected.findings.capacity() as u64 * core::mem::size_of::<String>() as u64,
            |sum, finding| sum.checked_add(finding.capacity() as u64),
        );
        if !inspected.complete
            || inspected.usage.cases == 0
            || findings_bytes.is_none_or(|bytes| bytes > inspected.usage.output_bytes)
            || findings_memory.is_none_or(|bytes| bytes > inspected.usage.memory_bytes)
            || began.elapsed() > Duration::from_millis(request.limits.wall_ms)
            || !findings_fit(&inspected.findings, request.limits.output_bytes)
            || (inspected.verdict == Verdict::Clear && !inspected.findings.is_empty())
        {
            return Err(refusal("shadow-incomplete"));
        }
        let mut usage = inspected.usage;
        usage.memory_bytes = usage
            .memory_bytes
            .checked_add(resident)
            .ok_or(refusal("attack-budget"))?;
        usage.io_bytes = usage
            .io_bytes
            .checked_add(read_bytes)
            .ok_or(refusal("attack-budget"))?;
        request.limits.permits(usage, usage.cases)?;
        Ok(ShadowObservation {
            proposal: request.proposal,
            operation: request.operation,
            source_snapshot: before,
            shadow_snapshot: Digest32::sha256(&shadow),
            live_before: before,
            live_after: Digest32::sha256(after.as_deref().unwrap_or_default()),
            verdict: inspected.verdict,
            findings: inspected.findings,
            budget_exhausted: false,
        })
    }
}

fn target_valid(target: &str) -> bool {
    !target.is_empty()
        && target.len() <= 256
        && !target.starts_with('/')
        && target
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._:-".contains(&b))
        && target
            .split('/')
            .all(|segment| !matches!(segment, "" | "." | ".."))
}

fn findings_fit(findings: &[String], ceiling: u32) -> bool {
    findings.len() <= MAX_FINDINGS
        && findings
            .iter()
            .try_fold(0_u32, |total, finding| {
                total.checked_add(u32::try_from(finding.len()).ok()?)
            })
            .is_some_and(|total| total <= ceiling)
}

fn text(value: impl ToString) -> Result<Value> {
    Value::text(value.to_string())
}

const fn refusal(reason: &'static str) -> Refusal {
    Refusal {
        organ: "immune",
        reason,
    }
}
