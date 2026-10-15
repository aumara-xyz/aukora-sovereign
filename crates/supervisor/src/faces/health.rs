// SPDX-License-Identifier: AGPL-3.0-or-later
//! Opaque snapshot pages retain the existing canonical health bytes without changing v1.
use super::{refuse, wire};
use canon::{
    digest::Digest32,
    fd4::{OpaqueHealthSnapshot, SessionEvent},
    json::Value,
    Result,
};

pub const PAGE_BYTES: usize = 24_576;
pub const PAGE_SCHEMA: &str = "aukora-health-snapshot-page-v2";

pub trait HealthRead: Send + Sync {
    /// The source returns immune's complete current canonical snapshot.
    fn snapshot(&self) -> Result<Vec<u8>>;
}

pub fn call(source: &dyn HealthRead, method: &str, params: &Value) -> Result<Value> {
    match method {
        "health.snapshot" => {
            wire::exact(params, &[])?;
            let bytes = source.snapshot()?;
            wire::bounded(wire::event(SessionEvent::HealthSnapshot(
                OpaqueHealthSnapshot::new(bytes)?,
            ))?)
        }
        "health.snapshot.page.v2" => {
            wire::exact(params, &["offset", "snapshot_sha256"])?;
            let offset = usize::try_from(wire::unsigned(wire::field(params, "offset")?)?)
                .map_err(|_| refuse("health-page-invalid"))?;
            let expected = wire::optional_string(wire::field(params, "snapshot_sha256")?)?;
            if (offset == 0) != expected.is_none() || offset % PAGE_BYTES != 0 {
                return Err(refuse("health-page-invalid"));
            }
            let snapshot = OpaqueHealthSnapshot::new(source.snapshot()?)?;
            let bytes = snapshot.as_bytes();
            let digest = Digest32::sha256(bytes);
            if let Some(expected) = expected {
                if Digest32::from_hex(expected)? != digest {
                    return Err(refuse("health-snapshot-changed"));
                }
            }
            if offset >= bytes.len() {
                return Err(refuse("health-page-invalid"));
            }
            let end = (offset + PAGE_BYTES).min(bytes.len());
            let chunk = wire::event(SessionEvent::HealthSnapshot(OpaqueHealthSnapshot::new(
                bytes[offset..end].to_vec(),
            )?))?;
            wire::bounded(wire::object([
                ("schema", wire::text(PAGE_SCHEMA)?),
                ("snapshot_sha256", wire::text(digest.to_string())?),
                ("offset", wire::number(offset as u64)?),
                ("total_bytes", wire::number(bytes.len() as u64)?),
                ("chunk_b64", wire::field(&chunk, "snapshot_b64")?.clone()),
                (
                    "next_offset",
                    if end == bytes.len() {
                        Value::null()
                    } else {
                        wire::number(end as u64)?
                    },
                ),
            ])?)
        }
        _ => Err(refuse("face-operation-unknown")),
    }
}
