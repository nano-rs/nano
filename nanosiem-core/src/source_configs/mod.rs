// SPDX-License-Identifier: AGPL-3.0-or-later

//! Source Configurations module
//!
//! Separates infrastructure (how data gets in) from parsing (what to do with data).
//! Source Configurations define connections with routing rules that determine source_type.
//! Log Sources become pure parsers activated by source_type match.

pub(crate) mod azure_event_hubs;
pub(crate) mod creds_backend;
pub(crate) mod isolation;
pub(crate) mod point_forward;
pub(crate) mod k8s_secret;
pub mod repository;
pub mod service;
pub mod types;

pub use repository::{SourceConfigRepository, SourceConfigRepositoryError};
pub use service::{
    CredentialRefresh, CredentialRefreshOutcome, SourceConfigService, SourceConfigServiceError,
};
pub use types::{
    // Deployment types
    DeploymentResult,
    ListParams,
    MatchFieldPreset,
    MatchType,
    NewRoutingRule,
    // Request types
    NewSourceConfiguration,
    RoutingRule,
    SourceConfigDeployment,
    SourceConfigType,
    SourceConfigTypeInfo,
    // Core types
    SourceConfiguration,
    SourceConfigurationWithRules,
    SourceDeployStatus,
    UpdateRoutingRule,
    UpdateSourceConfiguration,
};
