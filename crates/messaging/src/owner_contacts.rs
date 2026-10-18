// SPDX-License-Identifier: AGPL-3.0-or-later
//! Additive cache of contacts authorized by the owner's signed-in shell session.

use crate::{
    exact_object, hex_bytes, refuse, retained_record, state_number, state_text, ApprovedContact,
    ContactChange, Messaging, OwnerAction,
};
use canon::{
    authority::{AuthorityTxn, AuthorityVersion},
    digest::Digest32,
    json::{Value, ValueView},
    Result,
};
use nostr::PublicKey;
use rusqlite::{params, OptionalExtension};

/// Existing Aura fact kind, with a distinct owner action payload; no card is claimed.
pub const OWNER_CONTACT_SCHEMA: &str = "aukora:messaging-owner-contact:v1";
pub(crate) const OWNER_CONTACT_STATE_SCHEMA: &str = "aukora:messaging-owner-contact-state:v1";

pub(crate) fn contact_from_owner_state(state: &Value, key: PublicKey) -> Result<ApprovedContact> {
    exact_object(
        state,
        &[
            "schema",
            "action",
            "epoch",
            "sequence",
            "previous_hash",
            "receipt",
            "record",
        ],
    )?;
    if state_text(state, "schema")? != OWNER_CONTACT_STATE_SCHEMA {
        return Err(refuse("state-schema"));
    }
    retained_record(state)?;
    let bytes = hex_bytes(state_text(state, "action")?, 8_192)?;
    let OwnerAction::Contact(ContactChange::Add(draft)) = OwnerAction::decode(&bytes)? else {
        return Err(refuse("state-contact"));
    };
    if draft.key != key || draft.pairing.is_some() {
        return Err(refuse("state-contact"));
    }
    let previous_hash = match state
        .get("previous_hash")
        .ok_or(refuse("state-field"))?
        .view()
    {
        ValueView::Null => None,
        ValueView::Text(value) => Some(Digest32::from_hex(value)?),
        _ => return Err(refuse("state-field")),
    };
    ApprovedContact::from_owner_session(
        draft,
        AuthorityVersion {
            epoch: state_number(state, "epoch")?,
            sequence: state_number(state, "sequence")?,
            previous_hash,
        },
        Digest32::from_hex(state_text(state, "receipt")?)?,
    )
}

impl Messaging {
    pub(crate) fn stored_owner_contact(&self, key: PublicKey) -> Result<Option<ApprovedContact>> {
        let bytes: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT state FROM messaging_owner_contacts WHERE key=?1",
                params![key.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| refuse("store-read"))?;
        bytes
            .map(|bytes| contact_from_owner_state(&canon::json::parse_strict(&bytes)?, key))
            .transpose()
    }

    pub(crate) fn cache_owner_contact<T: AuthorityTxn + ?Sized>(
        &self,
        txn: &mut T,
        key: PublicKey,
    ) -> Result<()> {
        let state = txn
            .committed_authority_state("messaging.contact", &hex::encode(key.as_bytes()))?
            .ok_or(refuse("store-contact"))?;
        contact_from_owner_state(&state, key)?;
        let tx = self
            .db
            .unchecked_transaction()
            .map_err(|_| refuse("store-busy"))?;
        tx.execute(
            "INSERT INTO messaging_owner_contacts(key,state) VALUES(?1,?2)
            ON CONFLICT(key) DO UPDATE SET state=excluded.state",
            params![key.as_bytes().as_slice(), state.canonical_bytes()],
        )
        .map_err(|_| refuse("store-write"))?;
        tx.execute(
            "DELETE FROM messaging_contacts WHERE key=?1",
            params![key.as_bytes().as_slice()],
        )
        .map_err(|_| refuse("store-write"))?;
        tx.commit().map_err(|_| refuse("store-commit"))
    }

    pub(crate) fn remove_owner_contact_cache(&self, key: PublicKey) -> Result<()> {
        self.db
            .execute(
                "DELETE FROM messaging_owner_contacts WHERE key=?1",
                params![key.as_bytes().as_slice()],
            )
            .map(|_| ())
            .map_err(|_| refuse("store-write"))
    }
}
