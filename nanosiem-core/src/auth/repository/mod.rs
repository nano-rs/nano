// SPDX-License-Identifier: AGPL-3.0-or-later

//! Authentication repository implementations
//!
//! This module provides database access for authentication and RBAC entities.

pub mod api_keys;
pub mod groups;
#[cfg(feature = "enterprise")]
pub mod oidc;
pub mod roles;
pub mod sessions;
pub mod users;

pub use api_keys::{ApiKeyRepository, ApiKeyRepositoryError};
pub use groups::{GroupRepository, GroupRepositoryError};
#[cfg(feature = "enterprise")]
pub use oidc::{OidcAuthTransaction, OidcRepository, OidcRepositoryError};
pub use roles::{RoleRepository, RoleRepositoryError};
pub use sessions::{SessionRepository, SessionRepositoryError};
pub use users::{revoke_credentials_in, PrincipalAction, UserRepository, UserRepositoryError};
