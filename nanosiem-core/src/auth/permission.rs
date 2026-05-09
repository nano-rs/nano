// SPDX-License-Identifier: AGPL-3.0-or-later

//! Permission Service
//!
//! Requirements: 5.2, 6.4
//!
//! This module provides permission checking and aggregation:
//! - get_user_permissions() aggregating from groups/roles
//! - has_permission(), has_any_permission()
//! - check_token_permission() for middleware

use thiserror::Error;
use uuid::Uuid;

use super::repository::{GroupRepository, GroupRepositoryError};
use super::types::TokenClaims;

/// Permission service errors
#[derive(Debug, Error)]
pub enum PermissionError {
    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("User not found: {0}")]
    UserNotFound(Uuid),
}

impl From<GroupRepositoryError> for PermissionError {
    fn from(err: GroupRepositoryError) -> Self {
        PermissionError::DatabaseError(err.to_string())
    }
}

/// Permission service for checking and aggregating user permissions
///
/// Requirements: 5.2, 6.4
/// - 5.2: Return 403 Forbidden when user lacks required permission
/// - 6.4: Combine permissions from all assigned roles (union)
#[derive(Clone)]
pub struct PermissionService {
    group_repo: GroupRepository,
}

impl PermissionService {
    /// Create a new permission service
    pub fn new(group_repo: GroupRepository) -> Self {
        Self { group_repo }
    }

    /// Get all permissions for a user (union of all role permissions)
    ///
    /// Requirements: 6.4 - Combine permissions from all assigned roles
    ///
    /// This aggregates permissions from all groups the user belongs to,
    /// and all roles assigned to those groups.
    pub async fn get_user_permissions(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<String>, PermissionError> {
        let permissions = self.group_repo.get_user_permissions(user_id).await?;
        Ok(permissions)
    }

    /// Get all role names for a user
    ///
    /// This returns the names of all roles the user has through their group memberships.
    pub async fn get_user_roles(&self, user_id: Uuid) -> Result<Vec<String>, PermissionError> {
        let roles = self.group_repo.get_user_roles(user_id).await?;
        Ok(roles)
    }

    /// Check if a user has a specific permission
    ///
    /// Requirements: 5.2 - Check permission for authorization
    pub async fn has_permission(
        &self,
        user_id: Uuid,
        permission: &str,
    ) -> Result<bool, PermissionError> {
        let permissions = self.get_user_permissions(user_id).await?;
        Ok(permissions.contains(&permission.to_string()))
    }

    /// Check if a user has any of the specified permissions
    ///
    /// Returns true if the user has at least one of the given permissions.
    pub async fn has_any_permission(
        &self,
        user_id: Uuid,
        permissions: &[&str],
    ) -> Result<bool, PermissionError> {
        let user_permissions = self.get_user_permissions(user_id).await?;
        Ok(permissions
            .iter()
            .any(|p| user_permissions.contains(&p.to_string())))
    }

    /// Check if a user has all of the specified permissions
    ///
    /// Returns true only if the user has all of the given permissions.
    pub async fn has_all_permissions(
        &self,
        user_id: Uuid,
        permissions: &[&str],
    ) -> Result<bool, PermissionError> {
        let user_permissions = self.get_user_permissions(user_id).await?;
        Ok(permissions
            .iter()
            .all(|p| user_permissions.contains(&p.to_string())))
    }

    /// Check if token claims contain a specific permission (no DB lookup)
    ///
    /// This is used by middleware for fast permission checking without
    /// hitting the database. The permissions are embedded in the JWT.
    ///
    /// Requirements: 5.2 - Enforce permissions on each endpoint
    #[inline]
    pub fn check_token_permission(claims: &TokenClaims, permission: &str) -> bool {
        claims.has_permission(permission)
    }

    /// Check if token claims contain any of the specified permissions (no DB lookup)
    #[inline]
    pub fn check_token_any_permission(claims: &TokenClaims, permissions: &[&str]) -> bool {
        claims.has_any_permission(permissions)
    }

    /// Check if token claims contain all of the specified permissions (no DB lookup)
    #[inline]
    pub fn check_token_all_permissions(claims: &TokenClaims, permissions: &[&str]) -> bool {
        claims.has_all_permissions(permissions)
    }
}

/// Permission check result for use in handlers
#[derive(Debug, Clone)]
pub enum PermissionCheckResult {
    /// Permission granted
    Allowed,
    /// Permission denied - user lacks required permission
    Denied {
        required: String,
        user_permissions: Vec<String>,
    },
}

impl PermissionCheckResult {
    /// Check if permission was granted
    pub fn is_allowed(&self) -> bool {
        matches!(self, PermissionCheckResult::Allowed)
    }

    /// Check if permission was denied
    pub fn is_denied(&self) -> bool {
        matches!(self, PermissionCheckResult::Denied { .. })
    }
}

/// Helper function to check a single permission from token claims
///
/// Returns a PermissionCheckResult that can be used for logging and error responses.
pub fn check_permission(claims: &TokenClaims, required: &str) -> PermissionCheckResult {
    if claims.has_permission(required) {
        PermissionCheckResult::Allowed
    } else {
        PermissionCheckResult::Denied {
            required: required.to_string(),
            user_permissions: claims.permissions.clone(),
        }
    }
}

/// Helper function to check any of multiple permissions from token claims
pub fn check_any_permission(claims: &TokenClaims, required: &[&str]) -> PermissionCheckResult {
    if claims.has_any_permission(required) {
        PermissionCheckResult::Allowed
    } else {
        PermissionCheckResult::Denied {
            required: required.join(" OR "),
            user_permissions: claims.permissions.clone(),
        }
    }
}

/// Helper function to check all of multiple permissions from token claims
pub fn check_all_permissions(claims: &TokenClaims, required: &[&str]) -> PermissionCheckResult {
    if claims.has_all_permissions(required) {
        PermissionCheckResult::Allowed
    } else {
        PermissionCheckResult::Denied {
            required: required.join(" AND "),
            user_permissions: claims.permissions.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn create_test_claims(permissions: Vec<&str>) -> TokenClaims {
        use crate::auth::token::{DEFAULT_TOKEN_AUDIENCE, DEFAULT_TOKEN_ISSUER};

        TokenClaims {
            iss: DEFAULT_TOKEN_ISSUER.to_string(),
            aud: DEFAULT_TOKEN_AUDIENCE.to_string(),
            sub: Uuid::now_v7(),
            roles: vec!["TestRole".to_string()],
            permissions: permissions.into_iter().map(String::from).collect(),
            exp: Utc::now().timestamp() + 3600,
            iat: Utc::now().timestamp(),
            jti: Uuid::now_v7(),
            purpose: "access".to_string(),
        }
    }

    #[test]
    fn test_check_token_permission() {
        let claims = create_test_claims(vec!["search:view", "search:execute", "dashboards:view"]);

        assert!(PermissionService::check_token_permission(
            &claims,
            "search:view"
        ));
        assert!(PermissionService::check_token_permission(
            &claims,
            "dashboards:view"
        ));
        assert!(!PermissionService::check_token_permission(
            &claims,
            "detections:create"
        ));
    }

    #[test]
    fn test_check_token_any_permission() {
        let claims = create_test_claims(vec!["search:view", "dashboards:view"]);

        // Has at least one
        assert!(PermissionService::check_token_any_permission(
            &claims,
            &["search:view", "detections:create"]
        ));

        // Has none
        assert!(!PermissionService::check_token_any_permission(
            &claims,
            &["detections:create", "alerts:view"]
        ));
    }

    #[test]
    fn test_check_token_all_permissions() {
        let claims = create_test_claims(vec!["search:view", "search:execute", "dashboards:view"]);

        // Has all
        assert!(PermissionService::check_token_all_permissions(
            &claims,
            &["search:view", "search:execute"]
        ));

        // Missing one
        assert!(!PermissionService::check_token_all_permissions(
            &claims,
            &["search:view", "detections:create"]
        ));
    }

    #[test]
    fn test_check_permission_result() {
        let claims = create_test_claims(vec!["search:view"]);

        let result = check_permission(&claims, "search:view");
        assert!(result.is_allowed());

        let result = check_permission(&claims, "detections:create");
        assert!(result.is_denied());

        if let PermissionCheckResult::Denied { required, .. } = result {
            assert_eq!(required, "detections:create");
        }
    }

    #[test]
    fn test_check_any_permission_result() {
        let claims = create_test_claims(vec!["search:view"]);

        let result = check_any_permission(&claims, &["search:view", "detections:create"]);
        assert!(result.is_allowed());

        let result = check_any_permission(&claims, &["detections:create", "alerts:view"]);
        assert!(result.is_denied());
    }

    #[test]
    fn test_check_all_permissions_result() {
        let claims = create_test_claims(vec!["search:view", "search:execute"]);

        let result = check_all_permissions(&claims, &["search:view", "search:execute"]);
        assert!(result.is_allowed());

        let result = check_all_permissions(&claims, &["search:view", "detections:create"]);
        assert!(result.is_denied());
    }

    #[test]
    fn test_empty_permissions() {
        let claims = create_test_claims(vec![]);

        assert!(!PermissionService::check_token_permission(
            &claims,
            "search:view"
        ));
        assert!(!PermissionService::check_token_any_permission(
            &claims,
            &["search:view"]
        ));
        assert!(!PermissionService::check_token_all_permissions(
            &claims,
            &["search:view"]
        ));
    }

    #[test]
    fn test_empty_required_permissions() {
        let claims = create_test_claims(vec!["search:view"]);

        // Empty required list for any - should return false (no permissions to match)
        assert!(!PermissionService::check_token_any_permission(&claims, &[]));
        // Empty required list for all - should return true (vacuously true)
        assert!(PermissionService::check_token_all_permissions(&claims, &[]));
    }
}
