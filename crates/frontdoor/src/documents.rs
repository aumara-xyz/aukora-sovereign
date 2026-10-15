// SPDX-License-Identifier: AGPL-3.0-or-later
//! Owner-root document reads. Document contents remain data with Document provenance.

use crate::session::BoundSession;
use canon::{
    digest::Digest32,
    session::{Items, Text},
    Refusal, Result,
};
use rustix::fs::{self, AtFlags, Dir, FileType, Mode, OFlags};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
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
    /// Entries with refused paths in the entire scanned directory, including before the cursor.
    pub hidden_count: usize,
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
    pub fn open(directory: impl AsFd) -> Result<Self> {
        let stat = fs::fstat(&directory).map_err(|_| refused("document-root-refused"))?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
            return Err(refused("document-root-refused"));
        }
        let directory = rustix::io::fcntl_dupfd_cloexec(directory, 0)
            .map_err(|_| refused("document-root-refused"))?;
        Ok(Self { directory })
    }

    pub fn descriptor(&self) -> impl AsFd + '_ {
        &self.directory
    }

    /// Walk components with openat and O_NOFOLLOW; never canonicalize then reopen by path.
    /// Refuse symlinks, nonregular files, invalid UTF-8, oversize reads and directory escapes.
    pub fn read(&self, session: &BoundSession<'_>, path: &DocumentPath) -> Result<DocumentRead> {
        self.observe()?.read(session, path)
    }

    /// Descriptor-relative pagination with 1..=100 results, no symlink following and a byte cap.
    pub fn list(&self, session: &BoundSession<'_>, query: ListDocuments) -> Result<DocumentPage> {
        self.observe()?.list(session, query)
    }

    /// Starts counters for operations subsequently performed through this observer.
    pub fn observe(&self) -> Result<DocumentObserver<'_>> {
        let stat = fs::fstat(&self.directory).map_err(|_| refused("document-root-refused"))?;
        Ok(DocumentObserver {
            root: self,
            facts: DocumentFacts {
                root_device: stat.st_dev as u64,
                root_inode: stat.st_ino as u64,
                refused_escape_count: 0,
                refused_symlink_count: 0,
            },
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DocumentFacts {
    pub root_device: u64,
    pub root_inode: u64,
    pub refused_escape_count: u64,
    pub refused_symlink_count: u64,
}

/// Root identity and refusal counts for this observer's operations only.
pub struct DocumentObserver<'a> {
    root: &'a DocumentRoot,
    facts: DocumentFacts,
}

const MAX_DIRECTORY_ENTRIES: usize = 4096;
const MAX_DIRECTORY_NAME_BYTES: usize = 1_048_576;
const MAX_PAGE_BYTES: usize = 56_000;

impl DocumentObserver<'_> {
    pub fn facts(&self) -> DocumentFacts {
        self.facts
    }

    pub fn read(
        &mut self,
        session: &BoundSession<'_>,
        path: &DocumentPath,
    ) -> Result<DocumentRead> {
        check_session(session)?;
        let (parent, name) = path
            .as_str()
            .rsplit_once('/')
            .unwrap_or(("", path.as_str()));
        let directory = self.directory(parent)?;
        let before = self.reject_symlink(&directory, name)?;
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile {
            return Err(refused("document-kind-refused"));
        }
        if before.st_size < 0 || before.st_size as u64 > MAX_DOCUMENT_BYTES as u64 {
            return Err(refused("document-too-large"));
        }
        let fd = fs::openat(
            &directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| self.open_error(error))?;
        let stat = fs::fstat(&fd).map_err(|_| refused("document-read-refused"))?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err(refused("document-kind-refused"));
        }
        if stat.st_size < 0 || stat.st_size as u64 > MAX_DOCUMENT_BYTES as u64 {
            return Err(refused("document-too-large"));
        }
        let mut bytes = Vec::with_capacity(stat.st_size as usize);
        std::fs::File::from(fd)
            .take(MAX_DOCUMENT_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| refused("document-read-refused"))?;
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(refused("document-too-large"));
        }
        let sha256 = Digest32::from_bytes(Sha256::digest(&bytes).into());
        let text = String::from_utf8(bytes).map_err(|_| refused("document-utf8-refused"))?;
        Ok(DocumentRead {
            path: path.clone(),
            text: Text::new(text)?,
            sha256,
        })
    }

    pub fn list(
        &mut self,
        session: &BoundSession<'_>,
        query: ListDocuments,
    ) -> Result<DocumentPage> {
        check_session(session)?;
        if query.limit == 0 || usize::from(query.limit) > MAX_DOCUMENT_PAGE {
            return Err(refused("document-page-refused"));
        }
        let parent = query.directory.as_ref().map_or("", DocumentPath::as_str);
        if let Some(after) = &query.after {
            let after_parent = after.as_str().rsplit_once('/').map_or("", |(p, _)| p);
            if after_parent != parent {
                self.facts.refused_escape_count = self.facts.refused_escape_count.saturating_add(1);
                return Err(refused("document-path-refused"));
            }
        }
        let directory = self.directory(parent)?;
        let mut stream =
            Dir::read_from(&directory).map_err(|_| refused("document-list-refused"))?;
        let mut candidates = BTreeMap::new();
        let mut scanned = 0usize;
        let mut name_bytes = 0usize;
        let mut hidden_count = 0usize;
        while let Some(entry) = stream.read() {
            let entry = entry.map_err(|_| refused("document-list-refused"))?;
            let name = entry
                .file_name()
                .to_str()
                .map_err(|_| refused("document-utf8-refused"))?;
            if matches!(name, "." | "..") {
                continue;
            }
            scanned += 1;
            name_bytes = name_bytes.saturating_add(name.len());
            if scanned > MAX_DIRECTORY_ENTRIES || name_bytes > MAX_DIRECTORY_NAME_BYTES {
                return Err(refused("document-directory-too-large"));
            }
            let Ok(path) = DocumentPath::parse(&if parent.is_empty() {
                name.to_owned()
            } else {
                format!("{parent}/{name}")
            }) else {
                hidden_count += 1;
                continue;
            };
            if query
                .after
                .as_ref()
                .is_some_and(|after| path.as_str() <= after.as_str())
            {
                continue;
            }
            let stat = fs::statat(&directory, name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| refused("document-list-refused"))?;
            let kind = FileType::from_raw_mode(stat.st_mode);
            if kind == FileType::Symlink {
                self.symlink_refused();
                return Err(refused("document-symlink-refused"));
            }
            if !matches!(kind, FileType::RegularFile | FileType::Directory) {
                continue;
            }
            if stat.st_size < 0 {
                return Err(refused("document-kind-refused"));
            }
            candidates.insert(
                path.as_str().to_owned(),
                DocumentSummary {
                    path,
                    bytes: stat.st_size as u64,
                    directory: kind == FileType::Directory,
                },
            );
            if candidates.len() > usize::from(query.limit) + 1 {
                candidates.pop_last();
            }
        }
        let mut entries = Vec::new();
        let mut page_bytes = 0usize;
        let mut more = false;
        for summary in candidates.into_values() {
            let item_bytes = summary.path.as_str().len() * 6 + 128;
            if entries.len() == usize::from(query.limit) || page_bytes + item_bytes > MAX_PAGE_BYTES
            {
                more = true;
                break;
            }
            page_bytes += item_bytes;
            entries.push(summary);
        }
        let next = if more {
            entries.last().map(|entry| entry.path.clone())
        } else {
            None
        };
        Ok(DocumentPage {
            entries: Items::new(entries)?,
            next,
            hidden_count,
        })
    }

    fn directory(&mut self, path: &str) -> Result<OwnedFd> {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut directory = fs::openat(&self.root.directory, ".", flags, Mode::empty())
            .map_err(|error| self.open_error(error))?;
        if !path.is_empty() {
            for component in path.split('/') {
                self.reject_symlink(&directory, component)?;
                directory = fs::openat(&directory, component, flags, Mode::empty())
                    .map_err(|error| self.open_error(error))?;
            }
        }
        Ok(directory)
    }

    fn reject_symlink(&mut self, directory: impl AsFd, name: &str) -> Result<fs::Stat> {
        let stat = fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| refused("document-read-refused"))?;
        if FileType::from_raw_mode(stat.st_mode) == FileType::Symlink {
            self.symlink_refused();
            return Err(refused("document-symlink-refused"));
        }
        Ok(stat)
    }

    fn symlink_refused(&mut self) {
        self.facts.refused_symlink_count = self.facts.refused_symlink_count.saturating_add(1);
    }

    fn open_error(&mut self, error: rustix::io::Errno) -> Refusal {
        if error == rustix::io::Errno::LOOP {
            self.symlink_refused();
            refused("document-symlink-refused")
        } else {
            refused("document-read-refused")
        }
    }
}

fn check_session(session: &BoundSession<'_>) -> Result<()> {
    let record = session.record();
    if record.revoked
        || record.subject.is_none()
        || record.scope != crate::session::SessionScope::Shell
    {
        return Err(refused("document-session-refused"));
    }
    Ok(())
}

fn refused(reason: &'static str) -> Refusal {
    Refusal {
        organ: "frontdoor",
        reason,
    }
}
