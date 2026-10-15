// SPDX-License-Identifier: AGPL-3.0-or-later
//! The owner page: every file of ui/owner served byte for byte (see build.rs).

pub(crate) const ASSETS: &[(&str, &str, &[u8])] =
    include!(concat!(env!("OUT_DIR"), "/owner_assets.rs"));

pub(crate) fn asset(path: &str) -> Option<(&'static str, &'static [u8])> {
    let path = if matches!(path, "/" | crate::OWNER_HANDOFF) {
        "/index.html"
    } else {
        path
    };
    ASSETS
        .iter()
        .find(|(name, _, _)| *name == path)
        .map(|(_, mime, bytes)| (*mime, *bytes))
}
