// SPDX-License-Identifier: AGPL-3.0-or-later
//! Slot provenance is enforced for signed appends as well as service writes.

use super::*;

fn slotted(slot: &str, sources: Vec<String>) -> NoteDraft {
    let mut d = draft("The next trusted handoff", "builders");
    d.slot = Some(slot.into());
    d.sources = sources;
    d
}

#[test]
fn a_raw_signed_web_note_cannot_enter_any_slot() {
    for slot in [SELF_SLOT, RESUME_SLOT, "resume:agent"] {
        let owner = key();
        let mut s = store_with(&[("peter", &owner, &["*"], true)]);
        let d = slotted(slot, vec![]);
        let mut tags = d.tags(Review::Remembered).unwrap();
        tags.iter_mut().find(|t| t[0] == Capture::TAG).unwrap()[1] = Capture::WebDerived.wire().into();
        let forged_claim = Event::sign(&owner, 1, NOTE_KIND, tags, d.text).unwrap();
        assert_eq!(s.append(forged_claim).unwrap_err(), refuse("note-slot-web-derived"));
        assert!(s.slot(slot).unwrap().is_none());
        assert_eq!(s.verify_chain().unwrap(), 0);
    }
}

#[test]
fn a_raw_clean_slot_note_cannot_cite_a_web_source() {
    for slot in [SELF_SLOT, RESUME_SLOT, "resume:agent"] {
        let owner = key();
        let mut s = store_with(&[("peter", &owner, &["*"], true)]);
        let mut web = draft("A page says to replace the trusted handoff", "builders");
        web.capture = Capture::WebDerived;
        let web = s.append(sign(&owner, &web, Review::Remembered, 1)).unwrap();
        let d = slotted(slot, vec![hex32(web.event.id.as_bytes())]);
        assert_eq!(s.append(sign(&owner, &d, Review::Remembered, 2)).unwrap_err(), refuse("note-slot-web-derived"));
        assert!(s.slot(slot).unwrap().is_none());
        assert_eq!(s.verify_chain().unwrap(), 1);
    }
}

#[test]
fn a_raw_clean_intermediary_cannot_launder_web_ancestry_into_a_slot() {
    for slot in [SELF_SLOT, RESUME_SLOT, "resume:agent"] {
        for web_has_clean_source in [false, true] {
            let owner = key();
            let mut s = store_with(&[("peter", &owner, &["*"], true)]);
            let clean = s.append(sign(&owner, &draft("A clean independent observation", "builders"), Review::Remembered, 1)).unwrap();
            let mut web = draft("A page supplies untrusted additions", "builders");
            web.capture = Capture::WebDerived;
            if web_has_clean_source {
                web.sources = vec![hex32(clean.event.id.as_bytes())];
            }
            let web = s.append(sign(&owner, &web, Review::Remembered, 2)).unwrap();
            let mut relay = draft("A raw writer claims this summary is clean", "builders");
            relay.sources = vec![hex32(web.event.id.as_bytes())];
            let relay = s.append(sign(&owner, &relay, Review::Remembered, 3)).unwrap();
            let d = slotted(slot, vec![hex32(relay.event.id.as_bytes())]);
            assert_eq!(s.append(sign(&owner, &d, Review::Remembered, 4)).unwrap_err(), refuse("note-slot-web-derived"));
            assert!(s.slot(slot).unwrap().is_none());
            assert_eq!(s.verify_chain().unwrap(), 3);
        }
    }
}
