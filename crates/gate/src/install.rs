// SPDX-License-Identifier: AGPL-3.0-or-later
//! Reserved app-store boundary, row 120. No install operation is implemented.

use canon::{digest::Digest32, ids::AppId};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallRequest {
    pub app: AppId,
    pub package_digest: Digest32,
    pub manifest_bytes: Vec<u8>,
}

pub fn propose_install(_request: InstallRequest) -> crate::Result<crate::ProposalRequest> {
    Err(crate::refuse("install-unavailable"))
}
