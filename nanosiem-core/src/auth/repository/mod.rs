// SPDX-License-Identifier: AGPL-3.0-or-later

//! Authentication repository implementations
//!
//! This module provides database access for authentication and RBAC entities.

pub mod api_keys;
pub mod groups;
pub mod integrity;
#[cfg(feature = "enterprise")]
pub mod oidc;
pub mod roles;
pub mod sessions;
pub mod users;

#[cfg(test)]
mod admin_retention_live_tests;

pub use api_keys::{ApiKeyRepository, ApiKeyRepositoryError};
pub use groups::{GroupRepository, GroupRepositoryError};
pub use integrity::DeleteIntegrityViolation;
#[cfg(feature = "enterprise")]
pub use oidc::{
    OidcAuthTransaction, OidcProviderUpdate, OidcRepository, OidcRepositoryError,
    ProviderWriteAuthority,
};
pub use roles::{RoleRepository, RoleRepositoryError};
pub use sessions::{SessionRepository, SessionRepositoryError};
pub use users::{revoke_credentials_in, PrincipalAction, UserRepository, UserRepositoryError};
