// SPDX-License-Identifier: AGPL-3.0-or-later
//! Undoing a failed append to one of the door's append-only files (the consumed-id segments, the asks log, the
//! approvals log). A write that fails part-way leaves a torn line; if the file is not cut back to its last acknowledged
//! length, the next line glues onto it, and after a restart a spent call id or a used approval can read as something
//! else and be replayed or reopened. So a failed cut-back is not ignored: the file is marked `dirty`, every further
//! append first tries the cut again, and while it cannot be done nothing is appended and the caller refuses (SCOUT,
//! the door's cut-back finding; the counts log has had the same rule since f65a6a7).

use std::fs::File;
use std::io::Write;

/// Append `line` (it carries its own newline) and make it durable.
pub(super) fn append(file: &mut File, line: &[u8]) -> std::io::Result<()> {
    #[cfg(test)]
    if fault::take_tear() {
        file.write_all(&line[..line.len() / 2])?;
        return Err(std::io::Error::other("torn append"));
    }
    file.write_all(line).and_then(|()| file.sync_data())
}

/// Cut the file back to `length` bytes, sync it and check it is that long.
fn cut_to(file: &File, length: u64) -> bool {
    #[cfg(test)]
    if fault::cuts_refused() {
        return false;
    }
    file.set_len(length).and_then(|()| file.sync_all()).is_ok() && file.metadata().is_ok_and(|meta| meta.len() == length)
}

/// Before an append: a file left dirty by an earlier failure is cut back first. `false` means it still cannot be, and
/// the append must be refused.
pub(super) fn ready(file: &File, length: u64, dirty: &mut bool) -> bool {
    if *dirty && !cut_to(file, length) {
        return false;
    }
    *dirty = false;
    true
}

/// After an append failed: undo it; if the cut fails the file stays dirty until `ready` can do it.
pub(super) fn failed(file: &File, length: u64, dirty: &mut bool) {
    *dirty = !cut_to(file, length);
}

/// A failing disk, for tests: per thread, so tests do not disturb each other.
#[cfg(test)]
pub(super) mod fault {
    use std::cell::Cell;

    thread_local! {
        static TEAR: Cell<bool> = const { Cell::new(false) };
        static REFUSE_CUT: Cell<bool> = const { Cell::new(false) };
    }

    /// The next append writes half its bytes and fails.
    pub fn tear_next_append() {
        TEAR.with(|cell| cell.set(true));
    }

    /// Cutting a file back fails (or works again).
    pub fn refuse_cuts(on: bool) {
        REFUSE_CUT.with(|cell| cell.set(on));
    }

    pub(super) fn take_tear() -> bool {
        TEAR.with(|cell| cell.replace(false))
    }

    pub(super) fn cuts_refused() -> bool {
        REFUSE_CUT.with(Cell::get)
    }
}
