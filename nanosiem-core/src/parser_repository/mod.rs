// SPDX-License-Identifier: AGPL-3.0-or-later

//! Parser Repository Module
//!
//! Provides functionality for syncing VRL parsers from external GitHub repositories.
//! Imported parsers become draft log sources ready for review and deployment.
//!
//! ## Features
//!
//! - **Repository Management**: Add, sync, and browse public GitHub repositories
//! - **Parser Import**: Import parsers as draft log sources (parser_only=true)
//! - **Linked vs Forked**: Track imported parsers with optional auto-updates
//! - **Upstream Diff**: Detect and review upstream parser changes

mod error;
mod models;
mod repository;
mod service;
mod yaml_parser;

pub use error::ParserRepositoryError;
pub use models::{
    ApplyUpstreamUpdateResult, BulkApplyUpstreamResult, BundleImportResult,
    NewParserRepository, ParserImport, ParserImportPreview, ParserImportRequest, ParserImportType,
    ParserRepository, ParserUpstreamUpdate, RepositoryParser, RepositoryParserFilter, SyncResult,
    SyncStatus, UpdateParserRepository, UpstreamParserDiff,
};
pub use repository::{
    ParserImportsRepository, ParserImportsRepositoryError, ParserRepositoryRepository,
    ParserRepositoryRepositoryError, RepositoryParsersRepository, RepositoryParsersRepositoryError,
};
pub use service::{ParserRepositoryService, ParserRepositoryServiceConfig};
pub use yaml_parser::{parse_parser_yaml, ParserYaml, ParserYamlError};
