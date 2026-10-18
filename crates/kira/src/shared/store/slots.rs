// SPDX-License-Identifier: AGPL-3.0-or-later
//! A signed slot snapshot retires its predecessor, including snapshots written before this rule was enforced.

use super::*;

impl SharedStore {
    pub(super) fn slot_successor(&self, id_hex: &str) -> Result<Option<Correction>> {
        let row = self.db.query_row(&format!("{ROW} WHERE id = ?1 AND kind = ?2"), params![id_hex, NOTE_KIND], row_of)
            .optional().map_err(sql)?;
        let Some(row) = row else { return Ok(None) };
        let (event, _) = check_row(&row, &self.prev_link(row.seq)?, CHAIN_VERSION)?;
        let Some(slot) = NoteMeta::parse(&event.tags, &event.content)?.slot else { return Ok(None) };
        let mut stmt = self.db.prepare(&format!("{ROW} WHERE kind = ?1 AND slot = ?2 AND seq > ?3 ORDER BY seq")).map_err(sql)?;
        let rows = stmt.query_map(params![NOTE_KIND, slot, row.seq], row_of).map_err(sql)?
            .collect::<std::result::Result<Vec<_>, _>>().map_err(sql)?;
        for row in rows {
            let (event, _) = check_row(&row, &self.prev_link(row.seq)?, CHAIN_VERSION)?;
            let meta = NoteMeta::parse(&event.tags, &event.content)?;
            // Indexed columns find candidates; signed tags and the registered writer decide. A later quarantine
            // does not undo the snapshot's retirement and resurrect the old words.
            if meta.slot.as_deref() == Some(&slot)
                && self.agent(&row.pubkey)?.is_some_and(|a| may_write_slot(&slot, &a.name, a.owner))
            {
                return Ok(Some(Correction { event: row.id.clone(), at: row.seq, replacement: Some(row.id) }));
            }
        }
        Ok(None)
    }
}
