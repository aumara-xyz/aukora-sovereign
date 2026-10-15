// SPDX-License-Identifier: AGPL-3.0-or-later
//! Closed cage profiles and inert disposable requests. Policy is owned by the gate.

use canon::{
    digest::Digest32,
    ids::AppId,
    json::{self, SafeInteger, Value, ValueView},
};
use std::num::{NonZeroU32, NonZeroU64};

use crate::{cage::Result, cgroup::ResourceLimits};

/// Names a fixed syscall and filesystem policy, never a caller-supplied filter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileKind {
    /// Static Auma harness: no filesystem, process creation or socket creation.
    Auma,
    /// Isolated application runtime: no network, exec or WASI imports.
    UserApp,
    /// A separate command cage; this profile is disabled by default.
    Disposable,
}

impl ProfileKind {
    /// Exact local policy spelling; an unknown name is refused.
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "auma" => Ok(Self::Auma),
            "user-app" => Ok(Self::UserApp),
            "disposable" => Ok(Self::Disposable),
            _ => Err(crate::cage::refusal("profile")),
        }
    }
}

/// Data selecting a closed profile. Construction does not start a process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CageProfile {
    /// The harness's two inherited data channels and no writable filesystem.
    Auma {
        /// Fixed resource ceilings for this instance.
        limits: ResourceLimits,
    },
    /// One application, isolated from Auma and from every other application.
    UserApp {
        /// Identity used for brokered application services, never an authority.
        app: AppId,
        /// Exact approved bundle commitment checked by the supervisor.
        bundle_sha256: Digest32,
        /// Fixed resource ceilings for this instance.
        limits: ResourceLimits,
    },
}

impl CageProfile {
    /// Resolve the closed policy without accepting arbitrary syscall rules.
    pub const fn kind(&self) -> ProfileKind {
        match self {
            Self::Auma { .. } => ProfileKind::Auma,
            Self::UserApp { .. } => ProfileKind::UserApp,
        }
    }

    /// Resource ceilings retained by this requested profile.
    pub const fn limits(&self) -> &ResourceLimits {
        match self {
            Self::Auma { limits } | Self::UserApp { limits, .. } => limits,
        }
    }
}

/// No public constructor can enable the disposable cage.
#[derive(Debug, Default)]
pub struct DisposableSwitch {
    enabled_policy: Option<ConsumedStandingPolicy>,
}

impl DisposableSwitch {
    /// A fresh process and a restored default both keep decision 9 off.
    pub const fn disabled() -> Self {
        Self {
            enabled_policy: None,
        }
    }

    /// Whether a consumed owner policy has been installed, never a health verdict.
    pub const fn enabled(&self) -> bool {
        self.enabled_policy.is_some()
    }

    /// Row 39: bind every decoded field to the exact policy bytes under the authority
    /// port, consume its passkey authorization durably, then retain its activation. The port
    /// belongs to the supervisor/gate; it must not be implemented by guest input.
    pub fn enable<A: DisposableAuthority + ?Sized>(
        &mut self,
        policy: &StandingPolicy,
        authority: &mut A,
    ) -> Result<()> {
        authority.consume_exact(policy)?;
        self.enabled_policy = Some(ConsumedStandingPolicy {
            _policy: policy.clone(),
        });
        Ok(())
    }

    pub(crate) fn policy(&self) -> Result<&StandingPolicy> {
        self.enabled_policy
            .as_ref()
            .map(|p| &p._policy)
            .ok_or(crate::cage::refusal("disposable-disabled"))
    }

    /// Disable future runs; running children still require explicit termination.
    pub fn disable(&mut self) {
        self.enabled_policy = None;
    }
}

/// A proposal for one standing disposable-cage rule, not an approval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandingPolicy {
    /// Exact canonical policy bytes presented to the owner; bounded to C4 size.
    canonical_bytes: Vec<u8>,
    /// Exact permitted directory identity supplied through the supervisor.
    directory_commitment: Digest32,
    /// Maximum number of commands covered by one consumed authorization.
    command_budget: u32,
    /// Resource ceilings applicable to every child in the disposable run.
    limits: ResourceLimits,
    commands: Vec<CommandDescriptor>,
}

impl StandingPolicy {
    /// Row 39: decode the versioned policy, deriving every field from its exact
    /// canonical bytes. Refuse unknown fields, unbounded commands or invalid limits.
    pub fn decode(canonical_bytes: Vec<u8>) -> Result<Self> {
        if canonical_bytes.is_empty() || canonical_bytes.len() > 65_536 {
            return Err(crate::cage::refusal("policy"));
        }
        let root = json::parse_strict(&canonical_bytes)?;
        if root.canonical_bytes() != canonical_bytes {
            return Err(crate::cage::refusal("policy"));
        }
        exact(&root, &["schema", "body"])?;
        if text(field(&root, "schema")?)? != "aukora-disposable-policy-v1" {
            return Err(crate::cage::refusal("policy"));
        }
        let body = field(&root, "body")?;
        exact(
            body,
            &[
                "directory_commitment",
                "command_budget",
                "commands",
                "limits",
            ],
        )?;
        let directory_commitment = Digest32::from_hex(text(field(body, "directory_commitment")?)?)?;
        let command_budget = u32::try_from(number(field(body, "command_budget")?)?)
            .ok()
            .filter(|n| (1..=1024).contains(n))
            .ok_or(crate::cage::refusal("policy"))?;
        let limits = decode_limits(field(body, "limits")?)?;
        let ValueView::Array(items) = field(body, "commands")?.view() else {
            return Err(crate::cage::refusal("policy"));
        };
        if items.is_empty() || items.len() > 1024 {
            return Err(crate::cage::refusal("policy"));
        }
        let mut commands = Vec::with_capacity(items.len());
        for item in items {
            exact(item, &["image_sha256", "arguments_hex"])?;
            let image = Digest32::from_hex(text(field(item, "image_sha256")?)?)?;
            let ValueView::Array(args) = field(item, "arguments_hex")?.view() else {
                return Err(crate::cage::refusal("policy"));
            };
            let arguments = args
                .iter()
                .map(|arg| unhex(text(arg)?))
                .collect::<Result<Vec<_>>>()?;
            let command = CommandDescriptor::new(image, arguments)?;
            if commands.contains(&command) {
                return Err(crate::cage::refusal("policy"));
            }
            commands.push(command);
        }
        Ok(Self {
            canonical_bytes,
            directory_commitment,
            command_budget,
            limits,
            commands,
        })
    }

    pub(crate) fn admit(
        &self,
        directory: Digest32,
        commands: &[CommandDescriptor],
        limits: ResourceLimits,
    ) -> Result<()> {
        if directory != self.directory_commitment
            || limits != self.limits
            || commands.is_empty()
            || commands.len() > self.command_budget as usize
            || commands.iter().any(|c| !self.commands.contains(c))
        {
            return Err(crate::cage::refusal("policy-mismatch"));
        }
        Ok(())
    }

    /// Exact bytes presented to and signed by the owner.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// The single subtree identity retained from the exact policy bytes.
    pub const fn directory_commitment(&self) -> Digest32 {
        self.directory_commitment
    }

    /// Total command budget retained from the exact policy bytes.
    pub const fn command_budget(&self) -> u32 {
        self.command_budget
    }

    /// Resource ceilings retained from the exact policy bytes.
    pub const fn limits(&self) -> ResourceLimits {
        self.limits
    }
}

/// Exact inert request built from the pinned directory and command descriptors.
/// Callers cannot supply unrelated fields alongside the commitment.
#[derive(Debug)]
pub struct DisposableRun {
    canonical_bytes: Vec<u8>,
}

impl DisposableRun {
    /// Encode only the pinned directory, ordered command descriptors and limits.
    /// Construction is inert; the authority port must still admit these exact bytes.
    pub fn new(
        directory: Digest32,
        commands: &[CommandDescriptor],
        limits: ResourceLimits,
    ) -> Result<Self> {
        limits.validate()?;
        if commands.is_empty() || commands.len() > 1024 {
            return Err(crate::cage::refusal("commands"));
        }
        let body = object(vec![
            ("directory_commitment", string(&directory.to_string())?),
            (
                "commands",
                Value::array(
                    commands
                        .iter()
                        .map(CommandDescriptor::value)
                        .collect::<Result<_>>()?,
                )?,
            ),
            ("limits", limits_value(limits)?),
        ])?;
        let canonical_bytes = object(vec![
            ("schema", string("aukora-disposable-run-v1")?),
            ("body", body),
        ])?
        .canonical_bytes();
        if canonical_bytes.len() > 65_536 {
            return Err(crate::cage::refusal("commands"));
        }
        Ok(Self { canonical_bytes })
    }

    /// The gate checks these bytes against the already signed standing rule.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

/// The supervisor-owned gate adapter checks exact bytes and consumes once.
/// It cannot obtain approval from a boot fact, a profile name or a model message.
pub trait DisposableAuthority {
    /// Verify the owner passkey and atomically consume this exact standing policy.
    /// Implementations also enforce current epoch, revocation and remaining budget.
    fn consume_exact(&mut self, policy: &StandingPolicy) -> Result<()>;

    /// Before every run, recheck owner epoch and revocation, compare the exact run
    /// with the signed folder, images, arguments and limits, and durably debit its
    /// command count. Invoke dispatch once under that admission scope; never invoke
    /// it on a refusal or before the debit commits. A failed child still spends the
    /// reserved count; retries require a new admission. Epoch/revocation changes
    /// must serialize with admission and dispatch, not occur in a check/use gap.
    fn with_authorized_run<T>(
        &mut self,
        policy: &StandingPolicy,
        run: &DisposableRun,
        dispatch: impl FnOnce() -> Result<T>,
    ) -> Result<T>;
}

#[derive(Debug)]
struct ConsumedStandingPolicy {
    _policy: StandingPolicy,
}

/// Exact executable commitment and literal argument bytes; this grants no execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandDescriptor {
    image_sha256: Digest32,
    arguments: Vec<Vec<u8>>,
}

impl CommandDescriptor {
    /// Bound argv and refuse NUL bytes before creating any operating-system request.
    pub fn new(image_sha256: Digest32, arguments: Vec<Vec<u8>>) -> Result<Self> {
        let bytes = arguments
            .iter()
            .try_fold(0usize, |n, arg| n.checked_add(arg.len() + 1));
        if arguments.is_empty()
            || arguments.len() > 256
            || arguments[0].is_empty()
            || arguments.iter().any(|arg| arg.contains(&0))
            || bytes.is_none_or(|n| n > 16_384)
        {
            return Err(crate::cage::refusal("arguments"));
        }
        Ok(Self {
            image_sha256,
            arguments,
        })
    }

    fn value(&self) -> Result<Value> {
        object(vec![
            ("image_sha256", string(&self.image_sha256.to_string())?),
            (
                "arguments_hex",
                Value::array(
                    self.arguments
                        .iter()
                        .map(|arg| string(&hex(arg)))
                        .collect::<Result<_>>()?,
                )?,
            ),
        ])
    }
}

fn exact(value: &Value, names: &[&str]) -> Result<()> {
    let ValueView::Object(fields) = value.view() else {
        return Err(crate::cage::refusal("policy"));
    };
    if fields.len() != names.len() || fields.iter().any(|(key, _)| !names.contains(&key.as_str())) {
        return Err(crate::cage::refusal("policy"));
    }
    Ok(())
}
fn field<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    value.get(key).ok_or(crate::cage::refusal("policy"))
}
fn text(value: &Value) -> Result<&str> {
    match value.view() {
        ValueView::Text(s) => Ok(s),
        _ => Err(crate::cage::refusal("policy")),
    }
}
fn number(value: &Value) -> Result<u64> {
    match value.view() {
        ValueView::Integer(n) if n.get() > 0 => Ok(n.get() as u64),
        _ => Err(crate::cage::refusal("limits")),
    }
}
fn string(value: &str) -> Result<Value> {
    Value::text(value.into())
}
fn integer(value: u64) -> Result<Value> {
    let n = i64::try_from(value).map_err(|_| crate::cage::refusal("limits"))?;
    Ok(Value::integer(SafeInteger::new(n)?))
}
fn object(fields: Vec<(&str, Value)>) -> Result<Value> {
    Value::object(fields.into_iter().map(|(k, v)| (k.into(), v)).collect())
}
fn limits_value(l: ResourceLimits) -> Result<Value> {
    object(vec![
        ("memory_bytes", integer(l.memory_bytes.get())?),
        ("tasks", integer(l.tasks.get().into())?),
        ("cpu_quota_us", integer(l.cpu_quota_us.get())?),
        ("cpu_period_us", integer(l.cpu_period_us.get())?),
        ("open_files", integer(l.open_files.get().into())?),
        ("file_bytes", integer(l.file_bytes.get())?),
    ])
}
fn decode_limits(v: &Value) -> Result<ResourceLimits> {
    exact(
        v,
        &[
            "memory_bytes",
            "tasks",
            "cpu_quota_us",
            "cpu_period_us",
            "open_files",
            "file_bytes",
        ],
    )?;
    let n64 = |key| -> Result<NonZeroU64> {
        NonZeroU64::new(number(field(v, key)?)?).ok_or(crate::cage::refusal("limits"))
    };
    let n32 = |key| -> Result<NonZeroU32> {
        u32::try_from(number(field(v, key)?)?)
            .ok()
            .and_then(NonZeroU32::new)
            .ok_or(crate::cage::refusal("limits"))
    };
    let l = ResourceLimits {
        memory_bytes: n64("memory_bytes")?,
        tasks: n32("tasks")?,
        cpu_quota_us: n64("cpu_quota_us")?,
        cpu_period_us: n64("cpu_period_us")?,
        open_files: n32("open_files")?,
        file_bytes: n64("file_bytes")?,
    };
    l.validate()?;
    Ok(l)
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 15) as usize] as char);
    }
    out
}
fn unhex(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 || s.len() > 32_768 {
        return Err(crate::cage::refusal("arguments"));
    }
    let digit = |b| match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(crate::cage::refusal("arguments")),
    };
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| Ok(digit(p[0])? * 16 + digit(p[1])?))
        .collect()
}
