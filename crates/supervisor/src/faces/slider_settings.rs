// SPDX-License-Identifier: AGPL-3.0-or-later
//! Owner-session slider replies; loosening remains a gate proposal.
use super::{refuse, wire};
use crate::adapters::{gate::slider::SliderChange, GateAdapter};
use canon::{json::Value, Result};
use supervisor::ingress::PrincipalScope;

pub fn call(
    gate: &GateAdapter,
    scope: PrincipalScope,
    method: &str,
    params: &Value,
) -> Result<Value> {
    let runtime =
        tokio::runtime::Handle::try_current().map_err(|_| refuse("face-runtime-unavailable"))?;
    match method {
        "slider.get" => {
            wire::exact(params, &[])?;
            let policy = runtime.block_on(gate.slider_policy())?;
            wire::object([("setting", wire::text(policy.setting.wire_name())?)])
        }
        "slider.set" => {
            wire::exact(params, &["setting"])?;
            let setting = laya::SliderSetting::from_policy_wire(wire::string(wire::field(
                params, "setting",
            )?)?)?;
            match runtime.block_on(gate.set_slider(scope, setting))? {
                SliderChange::Applied(setting) => wire::object([
                    ("state", wire::text("applied")?),
                    ("setting", wire::text(setting.wire_name())?),
                ]),
                SliderChange::Pending { setting, proposal } => wire::object([
                    ("state", wire::text("pending")?),
                    ("setting", wire::text(setting.wire_name())?),
                    ("proposal_id", wire::text(proposal.to_string())?),
                ]),
            }
        }
        _ => Err(refuse("face-operation-unknown")),
    }
}
