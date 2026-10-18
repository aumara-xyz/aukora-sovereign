// SPDX-License-Identifier: AGPL-3.0-or-later
//! Session families share durable revocation across independently opened browser-tab handles.

use super::*;
use crate::ingress::{HostRole, Method};
use std::{fs::DirBuilder, os::unix::fs::DirBuilderExt, path::PathBuf};

struct Directory {
    path: PathBuf,
    node: NodeId,
    shell: Origin,
    owner: Origin,
    subject: SubjectId,
}

impl Directory {
    fn new() -> (Self, DurableSessions) {
        let path = std::env::temp_dir().join(format!(
            "frontdoor-sessions-{}-{}",
            std::process::id(),
            SessionBearer::generate().unwrap().digest()
        ));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        let directory = Self {
            path,
            node: NodeId::from_bytes([1; 16]),
            shell: Origin::parse("https://shell.example").unwrap(),
            owner: Origin::parse("https://owner.shell.example").unwrap(),
            subject: SubjectId::from_digest(Digest32::sha256(b"owner")),
        };
        let mut sessions = DurableSessions::initialize(
            File::open(&directory.path).unwrap(),
            directory.node,
            directory.shell.clone(),
            directory.owner.clone(),
        )
        .unwrap();
        sessions
            .synchronize_binding(1, BindingState::Bound, Some(directory.subject))
            .unwrap();
        (directory, sessions)
    }

    fn open(&self) -> DurableSessions {
        DurableSessions::open(
            File::open(&self.path).unwrap(),
            self.node,
            self.shell.clone(),
            self.owner.clone(),
        )
        .unwrap()
    }

    fn record(&self, bearer: &SessionBearer, scope: SessionScope) -> SessionRecord {
        SessionRecord {
            token_digest: bearer.digest(),
            node: self.node,
            origin: if scope == SessionScope::Shell {
                self.shell.clone()
            } else {
                self.owner.clone()
            },
            subject: Some(self.subject),
            owner_epoch: 1,
            scope,
            expires_at_ms: 10_000,
            revoked: false,
        }
    }

    fn owner(&self, sessions: &mut DurableSessions) -> SessionBearer {
        let bearer = SessionBearer::generate().unwrap();
        sessions
            .insert_after_ceremony(self.record(&bearer, SessionScope::OwnerFrame), 1)
            .unwrap();
        bearer
    }

    fn shell(&self, sessions: &mut DurableSessions, owner: &SessionBearer) -> SessionBearer {
        let bearer = SessionBearer::generate().unwrap();
        sessions
            .derive_shell(owner.digest(), self.record(&bearer, SessionScope::Shell), 1)
            .unwrap();
        bearer
    }

    fn owner_request(
        &self,
        sessions: &mut DurableSessions,
        owner: &SessionBearer,
        route: OwnerRoute,
    ) -> Result<()> {
        with_owner_session(
            sessions,
            owner.as_bytes(),
            self.node,
            &self.owner,
            route,
            2,
            |_| Ok(()),
        )
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.path).unwrap();
    }
}

#[test]
fn shell_sign_out_revokes_owner_reads_and_actions_in_other_tabs_and_after_reopen() {
    let (directory, mut first_tab) = Directory::new();
    let owner = directory.owner(&mut first_tab);
    let shell = directory.shell(&mut first_tab, &owner);
    let sibling = directory.shell(&mut first_tab, &owner);
    let unrelated_owner = directory.owner(&mut first_tab);
    let unrelated_shell = directory.shell(&mut first_tab, &unrelated_owner);
    let mut second_tab = directory.open();
    let routes = [
        OwnerRoute::resolve(HostRole::Owner, Method::Get, "/api/approvals").unwrap(),
        OwnerRoute::resolve(HostRole::Owner, Method::Post, "/api/v1/approvals/decline").unwrap(),
        OwnerRoute::resolve(HostRole::Owner, Method::Post, "/api/v1/approvals/again").unwrap(),
    ];
    for route in routes {
        directory
            .owner_request(&mut second_tab, &owner, route)
            .unwrap();
    }

    first_tab.end_shell_session(shell.digest(), 2).unwrap();
    for route in routes {
        assert_eq!(
            directory.owner_request(&mut second_tab, &owner, route),
            Err(FRONTDOOR_SESSION_REQUIRED)
        );
    }
    for digest in [shell.digest(), sibling.digest()] {
        assert_eq!(
            second_tab.with_live_session(digest, 2, |_| Ok(())),
            Err(FRONTDOOR_SESSION_REQUIRED)
        );
    }
    directory
        .owner_request(&mut second_tab, &unrelated_owner, OwnerRoute::Approvals)
        .unwrap();
    second_tab
        .with_live_session(unrelated_shell.digest(), 2, |_| Ok(()))
        .unwrap();

    drop(first_tab);
    drop(second_tab);
    let mut reopened = directory.open();
    assert_eq!(
        directory.owner_request(&mut reopened, &owner, OwnerRoute::Approvals),
        Err(FRONTDOOR_SESSION_REQUIRED)
    );
    assert_eq!(
        reopened.with_live_session(sibling.digest(), 2, |_| Ok(())),
        Err(FRONTDOOR_SESSION_REQUIRED)
    );
    directory
        .owner_request(&mut reopened, &unrelated_owner, OwnerRoute::Approvals)
        .unwrap();
}

#[test]
fn shell_sign_out_requires_a_live_shell_without_revoking_another_family() {
    let (directory, mut sessions) = Directory::new();
    let owner = directory.owner(&mut sessions);
    let shell = directory.shell(&mut sessions, &owner);
    assert_eq!(
        sessions.end_shell_session(owner.digest(), 2),
        Err(FRONTDOOR_COOKIE_HOST_REFUSED)
    );
    assert_eq!(
        sessions.end_shell_session(shell.digest(), 10_000),
        Err(FRONTDOOR_SESSION_REQUIRED)
    );
    directory
        .owner_request(&mut sessions, &owner, OwnerRoute::Approvals)
        .unwrap();
}

#[test]
fn owner_cleanup_is_idempotent_after_shell_sign_out() {
    let (directory, mut sessions) = Directory::new();
    let owner = directory.owner(&mut sessions);
    let shell = directory.shell(&mut sessions, &owner);
    sessions.end_shell_session(shell.digest(), 2).unwrap();
    let mut owner_tab = directory.open();
    owner_tab.revoke(owner.digest()).unwrap();
    owner_tab.revoke(owner.digest()).unwrap();
    assert_eq!(
        directory.owner_request(&mut owner_tab, &owner, OwnerRoute::Approvals),
        Err(FRONTDOOR_SESSION_REQUIRED)
    );
}
