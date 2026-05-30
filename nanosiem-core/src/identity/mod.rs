// SPDX-License-Identifier: AGPL-3.0-or-later

//! Identity provider sync system
//!
//! Syncs user directories from identity providers (Entra ID, Google Workspace,
//! Active Directory) into a unified user registry for enriching SIEM events.

pub mod repository;
pub mod scheduler;
pub mod service;
pub mod sync;
pub mod types;

pub use repository::{IdentityRepository, IdentityRepositoryError};
pub use scheduler::{IdentitySyncScheduler, IdentitySyncSchedulerConfig};
pub use service::{IdentityServiceError, IdentitySyncService};
pub use types::{
    ConnectionTestResult, CreateIdentityProvider, IdentityProvider, IdentityProviderSummary,
    IdentityProviderType, IdentityStats, IdentitySyncResult, ListUsersParams, ProviderStatsSummary,
    UpdateIdentityProvider, UpdateIdentityProviderCredentials,
    UserListResponse, UserRecord, UserRecordUpsert,
};
