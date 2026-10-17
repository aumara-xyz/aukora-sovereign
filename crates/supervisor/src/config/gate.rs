// SPDX-License-Identifier: AGPL-3.0-or-later
//! Versioned host target inventory, separate from the frozen node configuration.

use super::{array, canonical, disk, exact, member, number, text, NodeConfig};
use canon::{codes, Result};
use gate::{
    target::{TargetClass, TargetId, TargetSpec},
    RiskTier,
};
use std::collections::BTreeSet;

const TARGET_LIMIT: usize = 128;

impl NodeConfig {
    /// Read the host-owned inventory once before the gate receives any request.
    /// If the entry exists at the initial absence check, the strict read follows:
    /// A missing inventory refuses startup; an explicit empty array disables targets.
    /// An initially absent entry in a verified directory instead selects no targets.
    pub fn gate_targets(&self) -> Result<Vec<TargetSpec>> {
        if self.gate_inventory_absent()? {
            return Ok(Vec::new());
        }
        let raw = disk::read_host_file(&self.directory.join("gate-targets-v1.json"), 65_536)?;
        let value = canonical(&raw)?;
        exact(&value, &["v", "kind", "node", "targets"])?;
        if number(&value, "v")? != 1 || text(&value, "kind")? != "aukora-gate-targets-v1" {
            return Err(codes::SUPERVISOR_GATE_TARGETS_VERSION);
        }
        if text(&value, "node")? != self.node {
            return Err(codes::SUPERVISOR_GATE_TARGETS_NODE);
        }
        let rows = array(member(&value, "targets")?)?;
        if rows.len() > TARGET_LIMIT {
            return Err(codes::SUPERVISOR_GATE_TARGETS_LIMIT);
        }
        let mut targets = Vec::with_capacity(rows.len());
        let mut names = BTreeSet::new();
        for row in rows {
            exact(row, &["id", "class", "risk", "max_bytes"])?;
            let id = TargetId::new(text(row, "id")?.to_owned())?;
            if id
                .as_str()
                .split('/')
                .any(|part| part.len() > 255 || part.starts_with(".aukora-gate-"))
                || !names.insert(id.as_str().to_owned())
            {
                return Err(codes::SUPERVISOR_GATE_TARGETS_NAME);
            }
            let class = match text(row, "class")? {
                "content" => TargetClass::Content,
                "release" => TargetClass::Release,
                "owner_binding" => TargetClass::OwnerBinding,
                "permission" => TargetClass::Permission,
                "spend_grant" => TargetClass::SpendGrant,
                "install" => TargetClass::Install,
                _ => return Err(codes::SUPERVISOR_GATE_TARGETS_CLASS),
            };
            let risk = match text(row, "risk")? {
                "routine" => RiskTier::Routine,
                "critical" => RiskTier::Critical,
                _ => return Err(codes::SUPERVISOR_GATE_TARGETS_RISK),
            };
            if class != TargetClass::Content && risk != RiskTier::Critical {
                return Err(codes::SUPERVISOR_GATE_TARGETS_RISK);
            }
            let max_bytes = usize::try_from(number(row, "max_bytes")?)
                .map_err(|_| codes::SUPERVISOR_GATE_TARGETS_SIZE)?;
            if !(1..=65_536).contains(&max_bytes) {
                return Err(codes::SUPERVISOR_GATE_TARGETS_SIZE);
            }
            targets.push(TargetSpec {
                id,
                class,
                risk,
                max_bytes,
            });
        }
        for name in &names {
            if name
                .match_indices('/')
                .any(|(index, _)| names.contains(&name[..index]))
            {
                return Err(codes::SUPERVISOR_GATE_TARGETS_NAME);
            }
        }
        Ok(targets)
    }

    /// The door's policy beside the inventory, read the same way (root-owned, not writable by others, no symlink).
    /// Absent means this node runs no door.
    pub fn door_policy_text(&self) -> Result<Option<String>> {
        self.optional_host_text("door-policy-v1.json")
    }

    /// The engine's settings beside the inventory (`engine-v1.json`), read like the door policy. Absent means this
    /// node runs no engine.
    pub fn engine_config_text(&self) -> Result<Option<String>> {
        self.optional_host_text("engine-v1.json")
    }

    /// A root-owned file in the config directory that may be absent; read like `gate-targets-v1.json`.
    fn optional_host_text(&self, name: &'static str) -> Result<Option<String>> {
        let directory = disk::open_host_directory(&self.directory)?;
        match rustix::fs::statat(&directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => {}
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(_) => return Err(super::refused("config-unreadable")),
        }
        let raw = disk::read_host_file(&self.directory.join(name), 65_536)?;
        String::from_utf8(raw)
            .map(Some)
            .map_err(|_| super::refused("config-unreadable"))
    }

    fn gate_inventory_absent(&self) -> Result<bool> {
        let directory = disk::open_host_directory(&self.directory)?;
        match rustix::fs::statat(
            &directory,
            "gate-targets-v1.json",
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(_) => Ok(false),
            Err(rustix::io::Errno::NOENT) => Ok(true),
            Err(_) => Err(super::refused("config-unreadable")),
        }
    }
}
