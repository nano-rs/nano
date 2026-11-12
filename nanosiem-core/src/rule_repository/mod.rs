// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rule Repository Module
//!
//! Provides functionality for syncing detection rules from nano's first-party
//! GitHub repository (native nPL rules).
//!
//! ## Features
//!
//! - **Repository Management**: Add, sync, and browse the first-party rule repository
//! - **Linked vs Forked Rules**: Track imported rules with optional auto-updates
//! - **Coverage Analysis**: Analyze which rules can run based on available log sources
//!
//! Sigma-format repositories (and Sigma → nPL conversion) were retired in
//! NAN-5272; a row still marked `rule_format = 'sigma'` is refused with
//! [`RuleRepositoryError::SigmaFormatUnsupported`].
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────┐     ┌──────────────────────┐
//! │  GitHub Repos   │────►│ RuleRepositoryService│
//! │ (first-party)   │     └─────────┬────────────┘
//! └─────────────────┘               │ (cached nPL YAML)
//!                                   ▼
//!                         ┌────────────────────┐
//!                         │ Detection Rules    │
//!                         │ (linked/forked)    │
//!                         └────────────────────┘
//! ```

mod coverage;
mod error;
mod field_census;
mod github_client;
mod models;
mod npl_parser;
mod repository;
mod service;

pub use coverage::{
    CoverageAnalyzer, CoverageAnalyzerError, LiveInventoryAccess, COVERAGE_STATUS_UNKNOWN,
};
pub use error::RuleRepositoryError;
pub use github_client::{FileContent, GitHubClient, GitHubClientError, TreeEntry};
pub use models::{
    CoverageAnalysis, CoverageFilter, CoverageResult,
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
pub use service::{
    RuleImportAction, RuleImportPlan, RuleRepositoryService, RuleRepositoryServiceConfig,
};
