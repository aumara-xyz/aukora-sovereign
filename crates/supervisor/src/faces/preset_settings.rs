// SPDX-License-Identifier: AGPL-3.0-or-later
//! Compiled harness limits paired with the broker's admitted model.
use super::{refuse, settings, wire};
use broker::intake::ModelSlot;
use canon::{codes, json::Value, session::presets::COMPILED_PRESETS, Result};

/// Token counts describe the compiled ceiling, not a session's requested limit.
pub fn project(slot: &ModelSlot) -> Result<Value> {
    let selected = slot.admitted().ok_or(codes::BROKER_PROVIDER_UNAVAILABLE)?;
    let model = selected.candidate().model.as_str();
    let mut presets = Vec::with_capacity(COMPILED_PRESETS.len());
    for preset in COMPILED_PRESETS {
        let mut operations = Vec::with_capacity(preset.operations.len());
        for operation in preset.operations {
            let name = match *operation {
                "chat" | "threads" | "sessions" | "streaming" | "compaction" | "proposals" => {
                    *operation
                }
                "memory.read" => "memory_read",
                "memory.propose" => "memory_propose",
                _ => return Err(refuse("settings-reply-invalid")),
            };
            operations.push(wire::text(name)?);
        }
        presets.push(wire::object([
            ("id", wire::text(preset.id)?),
            (
                "max_output_tokens",
                wire::number(u64::from(preset.max_output_tokens))?,
            ),
            ("model", wire::text(model)?),
            ("operations", Value::array(operations)?),
        ])?);
    }
    let value = wire::object([("presets", Value::array(presets)?)])?;
    settings::validate("settings.presets", &value)?;
    wire::bounded(value)
}
