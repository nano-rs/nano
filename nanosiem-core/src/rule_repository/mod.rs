// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rule Repository Module
//!
//! Provides functionality for syncing detection rules from external GitHub repositories.
//! Supports Sigma rule format with AI-powered conversion to nPL.
//!
//! ## Features
//!
//! - **Repository Management**: Add, sync, and browse public GitHub repositories
//! - **Sigma Conversion**: AI-powered conversion of Sigma rules to nPL queries
//! - **Linked vs Forked Rules**: Track imported rules with optional auto-updates
//! - **Coverage Analysis**: Analyze which rules can run based on available log sources
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────┐     ┌────────────────────┐
//! │  GitHub Repos   │────►│ RuleRepositoryService│
//! │  (public only)  │     └─────────┬──────────┘
//! └─────────────────┘               │
//!                                   ▼
//! ┌─────────────────┐     ┌────────────────────┐
//! │ Repository Rules│────►│ SigmaConverterAgent│
//! │ (cached YAML)   │     │ (AI conversion)    │
//! └─────────────────┘     └────────────────────┘
//!                                   │
//!                                   ▼
//!                         ┌────────────────────┐
//!                         │ Detection Rules    │
//!                         │ (linked/forked)    │
//!                         └────────────────────┘
//! ```

mod coverage;
mod error;
mod github_client;
mod models;
mod npl_parser;
mod repository;
mod service;
mod sigma_parser;

pub use coverage::{CoverageAnalyzer, CoverageAnalyzerError};
pub use error::RuleRepositoryError;
pub use github_client::{FileContent, GitHubClient, GitHubClientError, TreeEntry};
pub use models::{
    ConversionTriageHints, CoverageAnalysis, CoverageFilter, CoverageResult,
    FolderInfo, ImportOutcome, ImportPreview, ImportRequest, ImportType, NewRuleRepository,
    RepositoryRule, RepositoryRuleFilter, RuleBundleImportResult, RuleImport, RuleRepository,
    SourceTypeSuggestion, SyncResult, SyncStatus, UpdateRuleRepository, UpdatedRule, UpstreamDiff,
};
pub use npl_parser::{
    extract_source_types, parse_npl, validate_source_types, AiTriageHints, NplParseError, NplRule,
    SourceTypeValidation,
};
pub use repository::{
    RepositoryRulesRepository, RepositoryRulesRepositoryError, RuleImportsRepository,
    RuleImportsRepositoryError, RuleRepositoryRepository, RuleRepositoryRepositoryError,
};
pub use service::{RuleRepositoryService, RuleRepositoryServiceConfig};
pub use sigma_parser::{
    extract_mitre_tactics, extract_mitre_techniques, extract_required_fields,
    map_logsource_to_source_types, map_severity, parse_sigma, SigmaDetection, SigmaLogsource,
    SigmaParseError, SigmaRule, SigmaSelection,
};
