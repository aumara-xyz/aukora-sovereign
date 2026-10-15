// SPDX-License-Identifier: AGPL-3.0-or-later
//! The release shell owns ceremony-frame creation. Faces have no such API.

use crate::{assets::ApprovedRelease, tls::Origin};
use canon::{ids::ProposalId, Result};

pub const SCRIPT_POLICY: &str = "script-src 'self'";
pub const FACE_SANDBOX: &str = "allow-scripts";
pub const OWNER_SANDBOX: &str = "allow-scripts allow-same-origin";
pub const OWNER_PERMISSION: &str = "publickey-credentials-create; publickey-credentials-get";

#[derive(Clone, Copy, Debug)]
pub enum Popup {
    Claim,
    Signin,
    Binding,
    Approval(ProposalId),
}

/// Created by the static-shell loader only, never by a face RPC or FD 4 event.
pub struct ShellHost {
    owner_origin: Origin,
}

pub struct OwnerFrame {
    origin: Origin,
    popup: Popup,
}

impl OwnerFrame {
    pub fn origin(&self) -> &Origin {
        &self.origin
    }
    pub fn popup(&self) -> Popup {
        self.popup
    }
}

impl ShellHost {
    /// Native configuration is fixed at approved-shell load, not supplied by a face.
    pub fn open(_release: &ApprovedRelease, _owner_origin: Origin) -> Result<Self> {
        todo!("rows 18, 109")
    }

    pub fn popup(&self, popup: Popup) -> OwnerFrame {
        OwnerFrame {
            origin: self.owner_origin.clone(),
            popup,
        }
    }
}

/// Both policies are generated from validated origins, never request or guest data.
pub struct ShellPolicies {
    pub shell_csp: String,
    pub owner_csp: String,
}

pub fn policies(shell: &Origin, owner: &Origin) -> ShellPolicies {
    ShellPolicies {
        shell_csp: format!("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-src 'self' {}; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'none'", owner.as_str()),
        owner_csp: format!("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-src 'none'; frame-ancestors {}; object-src 'none'; base-uri 'none'; form-action 'self'", shell.as_str()),
    }
}
