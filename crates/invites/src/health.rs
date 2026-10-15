// SPDX-License-Identifier: AGPL-3.0-or-later
//! Commitments to the complete allowance state inspected by invite health probes.

use canon::{digest::Digest32, Result};
use serde_json::{json, Value};

use crate::{
    allowance::{ConservedLedger, ReservationOutcome},
    wire::{canonical, read_json, version_json},
    MAX_INVITE_EVENT_BYTES,
};

impl ConservedLedger {
    /// SHA-256 of `aukora:invite-health:v1`, NUL, and canonical C1 state bytes.
    /// Commits to the network, all totals, members and retained reservations in
    /// their stored order, including drafts, receipts, versions and outcomes.
    /// This digest identifies an observation; it does not authorize an operation.
    pub fn health_commitment(&self) -> Result<Digest32> {
        let snapshot = self.snapshot();
        let members: Vec<Value> = self
            .members()
            .iter()
            .map(|member| {
                json!({
                    "member": hex::encode(member.member.as_bytes()),
                    "subject": member.subject.to_string(),
                    "version": version_json(member.version),
                    "available": member.available,
                    "reserved": member.reserved,
                    "outstanding_invites": member.outstanding_invites,
                    "lifetime_redeemed": member.lifetime_redeemed,
                })
            })
            .collect();
        let reservations: Vec<Value> = self
            .reservations()
            .iter()
            .map(|entry| {
                let reservation = &entry.reservation;
                let draft = read_json(
                    &reservation.draft().canonical_bytes()?,
                    MAX_INVITE_EVENT_BYTES,
                )?;
                let outcome = match entry.outcome {
                    ReservationOutcome::Active => json!({"state": "active"}),
                    ReservationOutcome::Released => json!({"state": "released"}),
                    ReservationOutcome::Consumed { member, subject } => json!({
                        "state": "consumed",
                        "member": hex::encode(member.as_bytes()),
                        "subject": subject.to_string(),
                    }),
                };
                Ok(json!({
                    "draft": draft,
                    "owner_receipt": reservation.owner_receipt().to_string(),
                    "owner_epoch": reservation.owner_epoch(),
                    "reservation": reservation.reservation().to_string(),
                    "version": version_json(reservation.version()),
                    "outcome": outcome,
                }))
            })
            .collect::<Result<_>>()?;
        let bytes = canonical(json!({
            "network": hex::encode(self.network().as_bytes()),
            "snapshot": {
                "version": version_json(snapshot.version),
                "issued": snapshot.issued,
                "available": snapshot.available,
                "reserved": snapshot.reserved,
                "consumed": snapshot.consumed,
            },
            "members": members,
            "reservations": reservations,
        }))?;
        let mut preimage = b"aukora:invite-health:v1\0".to_vec();
        preimage.extend_from_slice(&bytes);
        Ok(Digest32::sha256(&preimage))
    }
}
