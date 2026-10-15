// SPDX-License-Identifier: AGPL-3.0-or-later
//! Owner-root document reads. Document contents remain data with Document provenance.

use crate::session::BoundSession;
use canon::{
    digest::Digest32,
    session::{Items, Text},
    Refusal, Result,
};
use std::os::fd::{AsFd, OwnedFd};

pub const MAX_DOCUMENT_BYTES: usize = 32_768;
pub const MAX_DOCUMENT_PAGE: usize = 100;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DocumentPath(String);

impl DocumentPath {
    pub fn parse(path: &str) -> Result<Self> {
        if path.is_empty()
            || path.len() > 1024
            || path.contains(['\\', '%', ':'])
            || path.chars().any(char::is_control)
            || path
                .split('/')
                .any(|part| part.is_empty() || matches!(part, "." | ".."))
        {
            return Err(Refusal {
                organ: "frontdoor",
                reason: "document-path-refused",
            });
        }
        Ok(Self(path.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct ListDocuments {
    pub directory: Option<DocumentPath>,
    pub after: Option<DocumentPath>,
    pub limit: u16,
}

#[derive(Clone, Debug)]
pub struct DocumentSummary {
    pub path: DocumentPath,
    pub bytes: u64,
    pub directory: bool,
}

#[derive(Clone, Debug)]
pub struct DocumentPage {
    pub entries: Items<DocumentSummary, MAX_DOCUMENT_PAGE>,
    pub next: Option<DocumentPath>,
}

#[derive(Clone, Debug)]
pub struct DocumentRead {
    pub path: DocumentPath,
    pub text: Text<MAX_DOCUMENT_BYTES>,
    pub sha256: Digest32,
}

/// Retains the opened root descriptor, not a path resolved again for each request.
pub struct DocumentRoot {
    directory: OwnedFd,
}

impl DocumentRoot {
    /// Takes a trusted, owner-configured directory descriptor after checking its kind.
    pub fn open(_directory: impl AsFd) -> Result<Self> {
        todo!("row 109 documents")
    }

    pub fn descriptor(&self) -> impl AsFd + '_ {
        &self.directory
    }

    /// Walk components with openat and O_NOFOLLOW; never canonicalize then reopen by path.
    /// Refuse symlinks, nonregular files, invalid UTF-8, oversize reads and directory escapes.
    pub fn read(&self, _session: &BoundSession<'_>, _path: &DocumentPath) -> Result<DocumentRead> {
        todo!("row 109 documents")
    }

    /// Descriptor-relative pagination with 1..=100 results, no symlink following and a byte cap.
    pub fn list(&self, _session: &BoundSession<'_>, _query: ListDocuments) -> Result<DocumentPage> {
        todo!("row 109 documents")
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DocumentFacts {
    pub root_device: u64,
    pub root_inode: u64,
    pub refused_escape_count: u64,
    pub refused_symlink_count: u64,
}
