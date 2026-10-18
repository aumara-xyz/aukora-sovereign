// SPDX-License-Identifier: AGPL-3.0-or-later
//! The owner's own marks on a conversation: pinned, archived. Presentation state, not a committed fact: kept in the
//! private store beside the history, set only through the signed-in owner session, never sent to a contact. A
//! conversation with neither mark has no row.

use crate::{refuse, Messaging, OwnerSessionTxn};
use canon::Result;
use nostr::PublicKey;
use rusqlite::params;

/// At most this many marked conversations; a mark beyond it refuses rather than growing without bound.
// A full list must fit one face reply (60,000 bytes; a mark is about 105 bytes of canonical JSON).
pub const MAX_MARKS: usize = 500;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConversationMark {
    pub contact: PublicKey,
    pub pinned: bool,
    pub archived: bool,
}

impl Messaging {
    /// Every marked conversation, in key order. Marks of a contact since removed are left for the caller to skip.
    pub fn conversation_marks(&self) -> Result<Vec<ConversationMark>> {
        let mut statement = self
            .db
            .prepare(
                "SELECT contact,pinned,archived FROM messaging_marks ORDER BY contact LIMIT ?1",
            )
            .map_err(|_| refuse("store-read"))?;
        let rows = statement
            .query_map(params![MAX_MARKS as i64 + 1], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(|_| refuse("store-read"))?;
        let mut marks = Vec::new();
        for row in rows {
            let (contact, pinned, archived) = row.map_err(|_| refuse("store-read"))?;
            let contact: [u8; 32] = contact.try_into().map_err(|_| refuse("store-corrupt"))?;
            marks.push(ConversationMark {
                contact: PublicKey::from_bytes(contact)?,
                pinned: pinned == 1,
                archived: archived == 1,
            });
        }
        if marks.len() > MAX_MARKS {
            return Err(refuse("marks-limit"));
        }
        Ok(marks)
    }

    /// Set both marks of one approved contact's conversation, after the host checks the owner's shell session.
    pub fn set_conversation_mark<T: OwnerSessionTxn + ?Sized>(
        &mut self,
        txn: &mut T,
        mark: ConversationMark,
    ) -> Result<()> {
        txn.check_owner_session()?;
        let key = mark.contact.as_bytes().as_slice();
        // Clearing needs only the owner's session, so a mark left by a since-removed contact can always be cleared.
        if mark.pinned || mark.archived {
            self.current_contact(txn, mark.contact)?
                .ok_or(refuse("stranger"))?;
        }
        if !mark.pinned && !mark.archived {
            self.db
                .execute("DELETE FROM messaging_marks WHERE contact=?1", params![key])
                .map_err(|_| refuse("store-write"))?;
            return Ok(());
        }
        let others: i64 = self
            .db
            .query_row(
                "SELECT count(*) FROM messaging_marks WHERE contact<>?1",
                params![key],
                |row| row.get(0),
            )
            .map_err(|_| refuse("store-read"))?;
        if others >= MAX_MARKS as i64 {
            return Err(refuse("marks-limit"));
        }
        self.db
            .execute(
                "INSERT INTO messaging_marks(contact,pinned,archived) VALUES(?1,?2,?3)
                 ON CONFLICT(contact) DO UPDATE SET pinned=excluded.pinned,archived=excluded.archived",
                params![key, i64::from(mark.pinned), i64::from(mark.archived)],
            )
            .map_err(|_| refuse("store-write"))?;
        Ok(())
    }
}
