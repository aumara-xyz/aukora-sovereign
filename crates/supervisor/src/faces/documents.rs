// SPDX-License-Identifier: AGPL-3.0-or-later
use super::{refuse, wire};
use canon::{json::Value, Result};
use frontdoor::{
    documents::{DocumentPath, DocumentRoot, ListDocuments},
    session::BoundSession,
};

/// The caller retains the frontdoor session guard for the entire descriptor-relative read.
pub fn call(
    root: &DocumentRoot,
    session: &BoundSession<'_>,
    method: &str,
    params: &Value,
) -> Result<Value> {
    let reply = match method {
        "documents.list" => {
            wire::exact(params, &["directory", "after", "limit"])?;
            let path = |name| {
                wire::optional_string(wire::field(params, name)?)?
                    .map(DocumentPath::parse)
                    .transpose()
            };
            let limit = wire::unsigned(wire::field(params, "limit")?)?;
            if !(1..=100).contains(&limit) {
                return Err(refuse("face-page-invalid"));
            }
            let page = root.list(
                session,
                ListDocuments {
                    directory: path("directory")?,
                    after: path("after")?,
                    limit: limit as u16,
                },
            )?;
            let mut entries = Vec::with_capacity(page.entries.as_slice().len());
            for entry in page.entries.as_slice() {
                entries.push(wire::object([
                    ("path", wire::text(entry.path.as_str())?),
                    ("bytes", wire::number(entry.bytes)?),
                    ("directory", Value::boolean(entry.directory)),
                ])?);
            }
            wire::object([
                ("entries", Value::array(entries)?),
                (
                    "next",
                    page.next
                        .map(|path| wire::text(path.as_str()))
                        .transpose()?
                        .unwrap_or_else(Value::null),
                ),
            ])?
        }
        "documents.read" => {
            wire::exact(params, &["path"])?;
            let path = DocumentPath::parse(wire::string(wire::field(params, "path")?)?)?;
            let read = root.read(session, &path)?;
            wire::object([
                ("path", wire::text(read.path.as_str())?),
                ("text", wire::text(read.text.as_str())?),
                ("sha256", wire::text(read.sha256.to_string())?),
            ])?
        }
        _ => return Err(refuse("face-operation-unknown")),
    };
    wire::bounded(reply)
}
