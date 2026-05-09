// SPDX-License-Identifier: AGPL-3.0-or-later

//! Playbook Repository module — external git-hosted playbook libraries.
//!
//! Mirrors [`crate::rule_repository`] but for markdown + slash-command
//! playbook files. Adds repositories by URL (allowlist-enforced), syncs
//! content via the GitHub Tree API, caches rows in `repository_playbooks`,
//! and supports importing into the main `playbooks` table either as
//! **linked** (auto-update on upstream change) or **forked** (detached copy).

pub mod error;
pub mod models;
pub mod repository;
pub mod service;

pub use error::PlaybookRepositoryError;
pub use models::{
    NewPlaybookRepository, PlaybookImport, PlaybookImportRequest, PlaybookImportResponse,
    PlaybookImportType, PlaybookRepository, PlaybookSyncResult, PlaybookSyncStatus,
    RepositoryPlaybook, RepositoryPlaybookFilter, UpdatePlaybookRepository,
};
pub use repository::{
    PlaybookImportsRepository, PlaybookImportsRepositoryError, PlaybookRepoRepository,
    PlaybookRepoRepositoryError, RepositoryPlaybooksRepository, RepositoryPlaybooksRepositoryError,
};
pub use service::{PlaybookRepositoryService, PlaybookRepositoryServiceConfig};
