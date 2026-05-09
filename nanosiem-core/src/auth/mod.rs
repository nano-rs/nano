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
pub mod mfa;
pub mod oidc;
pub mod password;
pub mod permission;
pub mod permission_cache;
pub mod permissions;
pub mod repository;
pub mod service;
pub mod session;
pub mod token;
pub mod types;

#[cfg(test)]
mod group_membership_tests;

pub use api_key::*;
pub use mfa::*;
pub use oidc::*;
pub use password::*;
pub use permission::*;
pub use permission_cache::*;
pub use permissions::*;
pub use repository::*;
pub use service::*;
pub use session::*;
pub use token::*;
pub use types::*;
