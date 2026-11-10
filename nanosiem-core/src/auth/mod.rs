// SPDX-License-Identifier: AGPL-3.0-or-later

//! Authentication and Role-Based Access Control (RBAC) module
//!
//! This module provides:
//! - Local user authentication with password hashing
//! - JWT token management with refresh token rotation
//! - OIDC/SSO integration for enterprise identity providers
//! - Role-based access control with flexible permissions
//! - Group management for organizing users
//! - API key management for service authentication
//! - Session management and audit logging

pub mod api_key;
pub mod artifact_provenance;
pub mod authz_generation;
pub mod content_repo;
pub mod credential_use;
pub mod first_admin;
#[cfg(feature = "enterprise")]
pub mod google_sso;
pub mod grant_authority;
pub mod login_throttle;
pub mod mfa;
#[cfg(feature = "enterprise")]
pub mod oidc;
pub mod oidc_trust;
pub mod password;
pub mod permission;
pub mod permission_cache;
pub mod permissions;
pub mod repository;
pub mod reserved_source_types;
pub mod route_policy;
pub mod scope;
pub mod service;
pub mod service_credential;
pub mod session;
pub mod sso_policy;
pub mod source_scope_resolver;
pub mod token;
pub mod types;
pub mod user_status_cache;
pub mod viewer_scope;

#[cfg(test)]
mod credential_hardening_tests;
#[cfg(test)]
mod first_admin_tests;
#[cfg(test)]
mod group_membership_tests;
#[cfg(test)]
mod service_credential_tests;
#[cfg(all(test, feature = "enterprise"))]
mod sso_admission_tests;
#[cfg(test)]
mod reserved_source_types_tests;
#[cfg(test)]
mod viewer_scope_tests;

pub use api_key::*;
pub use artifact_provenance::*;
pub use content_repo::{TargetEffect, TargetGrants};
pub use credential_use::CredentialUseGrant;
#[cfg(feature = "enterprise")]
pub use google_sso::*;
pub use grant_authority::*;
pub use mfa::*;
#[cfg(feature = "enterprise")]
pub use oidc::*;
pub use oidc_trust::OidcTrustChange;
pub use password::*;
pub use permission::*;
pub use permission_cache::*;
pub use permissions::*;
pub use repository::*;
pub use route_policy::*;
pub use scope::*;
pub use viewer_scope::{SystemReason, SystemScope, ViewerScope};
pub use service::*;
pub use session::*;
pub use sso_policy::*;
pub use source_scope_resolver::*;
pub use token::*;
pub use types::*;
pub use user_status_cache::*;
