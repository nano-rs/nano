//! Authentication context extracted from incoming requests, plus the
//! permission-check helpers handlers use to enforce RBAC.
//!
//! These types are shared between `nanosiem-api` (where the auth middleware
//! constructs them) and `nanosiem-enterprise` (where lifted handlers consume
//! them). The data shape mirrors the JWT/api-key payloads issued by
//! `nanosiem-core::auth`.

use axum::{http::StatusCode, Json};
use serde::Serialize;
use uuid::Uuid;

use crate::api_error::ApiError;
use nanosiem_core::auth::{ApiKeyInfo, TokenClaims};

/// Error response for authentication/authorization failures
#[derive(Debug, Serialize)]
pub struct AuthErrorResponse {
    pub error: String,
    pub message: String,
}

impl AuthErrorResponse {
    pub fn unauthorized(message: &str) -> Self {
        Self {
            error: "unauthorized".to_string(),
            message: message.to_string(),
        }
    }

    pub fn forbidden(message: &str) -> Self {
        Self {
            error: "forbidden".to_string(),
            message: message.to_string(),
        }
    }
}

/// Authentication context that can be extracted from requests
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// Token claims (from JWT or API key)
    pub claims: TokenClaims,
    /// Whether authentication was via API key
    pub is_api_key: bool,
    /// API key ID if authenticated via API key
    pub api_key_id: Option<Uuid>,
    /// API key display name if authenticated via API key
    pub api_key_name: Option<String>,
}

impl AuthContext {
    /// Create from JWT token claims
    pub fn from_jwt(claims: TokenClaims) -> Self {
        Self {
            claims,
            is_api_key: false,
            api_key_id: None,
            api_key_name: None,
        }
    }

    /// Create from API key info
    pub fn from_api_key(info: &ApiKeyInfo) -> Self {
        use nanosiem_core::auth::token::{DEFAULT_TOKEN_AUDIENCE, DEFAULT_TOKEN_ISSUER};

        // Use the key owner's user ID as subject so FK constraints work.
        // Fall back to the key's own ID for orphaned keys (owner deleted).
        let subject = info.user_id.unwrap_or(info.id);

        Self {
            claims: TokenClaims {
                iss: DEFAULT_TOKEN_ISSUER.to_string(),
                aud: DEFAULT_TOKEN_AUDIENCE.to_string(),
                sub: subject,
                roles: vec!["api_key".to_string()],
                permissions: info.permissions.clone(),
                exp: i64::MAX, // API keys don't expire via JWT
                iat: chrono::Utc::now().timestamp(),
                jti: Uuid::now_v7(),
                purpose: "access".to_string(),
            },
            is_api_key: true,
            api_key_id: Some(info.id),
            api_key_name: Some(info.name.clone()),
        }
    }

    /// Check if the context has a specific permission
    pub fn has_permission(&self, permission: &str) -> bool {
        self.claims.has_permission(permission)
    }

    /// Check if the context has any of the specified permissions
    pub fn has_any_permission(&self, permissions: &[&str]) -> bool {
        self.claims.has_any_permission(permissions)
    }

    /// Get the user ID (or API key ID for API key auth)
    pub fn user_id(&self) -> Uuid {
        self.claims.sub
    }
}

/// Helper function to check if a single permission is present.
///
/// Usage:
/// ```ignore
/// pub async fn my_handler(
///     Extension(auth): Extension<AuthContext>,
/// ) -> Result<impl IntoResponse, StatusCode> {
///     check_permission(&auth, permissions::SEARCH_EXECUTE)?;
///     // ... handler logic
/// }
/// ```
pub fn check_permission(
    auth: &AuthContext,
    permission: &str,
) -> Result<(), (StatusCode, Json<AuthErrorResponse>)> {
    if auth.has_permission(permission) {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(AuthErrorResponse::forbidden(&format!(
                "Missing required permission: {}",
                permission
            ))),
        ))
    }
}

/// Enforce a single permission, returning [`ApiError::Forbidden`] on failure.
///
/// This is the ergonomic, DRY counterpart to [`check_permission`] for the
/// pervasive handler shape that previously hand-rolled:
///
/// ```ignore
/// check_permission(&auth, permissions::SEARCH_VIEW)
///     .map_err(|_| ApiError::Forbidden("Missing permission: search:view".to_string()))?;
/// ```
///
/// The Forbidden message is derived from the permission string itself
/// (`format!("Missing permission: {permission}")`), so it stays in lock-step
/// with the permission constant and cannot drift from a hand-written literal.
/// For `permissions::*` constants this is byte-identical to the previous
/// per-site message, since each constant's value is exactly its
/// `"category:action"` string.
///
/// Named `ensure_permission` (not `require_permission`) to avoid colliding with
/// the pre-existing async axum guard middleware of that name in nanosiem-api.
///
/// Usage:
/// ```ignore
/// pub async fn my_handler(
///     Extension(auth): Extension<AuthContext>,
/// ) -> Result<impl IntoResponse, ApiError> {
///     ensure_permission(&auth, permissions::SEARCH_VIEW)?;
///     // ... handler logic
/// }
/// ```
pub fn ensure_permission(auth: &AuthContext, permission: &str) -> Result<(), ApiError> {
    check_permission(auth, permission)
        .map_err(|_| ApiError::Forbidden(format!("Missing permission: {}", permission)))
}

/// Reject api-key-authenticated callers.
///
/// Used on endpoints that are session-only — i.e. a human admin must perform
/// them through a browser session, not via a long-lived machine credential.
/// Prevents an api-key from delegating, escalating, or persisting itself by
/// minting/mutating other keys.
pub fn require_session_auth(
    auth: &AuthContext,
) -> Result<(), (StatusCode, Json<AuthErrorResponse>)> {
    if auth.is_api_key {
        Err((
            StatusCode::FORBIDDEN,
            Json(AuthErrorResponse::forbidden(
                "This action requires an interactive session. API keys cannot perform key management.",
            )),
        ))
    } else {
        Ok(())
    }
}

/// Reject api-key-authenticated callers unless they target their own key.
///
/// Allows machine-to-machine self-management (an api-key disabling, deleting,
/// or updating its own non-secret metadata) while blocking lateral or vertical
/// moves against any other key. Session-authenticated users are unaffected.
/// Endpoints that mint or return secret material (create, reset) must use
/// `require_session_auth` instead — self-rotation would let a stolen key
/// launder its secret value past external scanners.
pub fn require_session_or_self(
    auth: &AuthContext,
    target: Uuid,
) -> Result<(), (StatusCode, Json<AuthErrorResponse>)> {
    if auth.is_api_key && auth.api_key_id != Some(target) {
        Err((
            StatusCode::FORBIDDEN,
            Json(AuthErrorResponse::forbidden(
                "API keys may only manage themselves. Use a session to manage other keys.",
            )),
        ))
    } else {
        Ok(())
    }
}

/// Helper function to check any of multiple permissions
pub fn check_any_permission(
    auth: &AuthContext,
    perms: &[&str],
) -> Result<(), (StatusCode, Json<AuthErrorResponse>)> {
    if auth.has_any_permission(perms) {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(AuthErrorResponse::forbidden(&format!(
                "Missing required permission: one of {:?}",
                perms
            ))),
        ))
    }
}

/// Helper function to check all of multiple permissions
pub fn check_all_permissions(
    auth: &AuthContext,
    perms: &[&str],
) -> Result<(), (StatusCode, Json<AuthErrorResponse>)> {
    for perm in perms {
        if !auth.has_permission(perm) {
            return Err((
                StatusCode::FORBIDDEN,
                Json(AuthErrorResponse::forbidden(&format!(
                    "Missing required permission: {}",
                    perm
                ))),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nanosiem_core::auth::ApiKeyInfo;

    #[test]
    fn test_auth_context_from_api_key() {
        let user_id = Uuid::now_v7();
        let info = ApiKeyInfo {
            id: Uuid::now_v7(),
            name: "test-key".to_string(),
            permissions: vec!["search:view".to_string(), "search:execute".to_string()],
            user_id: Some(user_id),
        };

        let context = AuthContext::from_api_key(&info);

        assert!(context.is_api_key);
        assert_eq!(context.api_key_id, Some(info.id));
        assert_eq!(context.api_key_name.as_deref(), Some("test-key"));
        assert!(context.has_permission("search:view"));
        assert!(context.has_permission("search:execute"));
        assert!(!context.has_permission("detections:create"));
    }

    #[test]
    fn test_check_permission() {
        use nanosiem_core::auth::token::{DEFAULT_TOKEN_AUDIENCE, DEFAULT_TOKEN_ISSUER};

        let claims = TokenClaims {
            iss: DEFAULT_TOKEN_ISSUER.to_string(),
            aud: DEFAULT_TOKEN_AUDIENCE.to_string(),
            sub: Uuid::now_v7(),
            roles: vec!["Editor".to_string()],
            permissions: vec!["search:view".to_string(), "search:execute".to_string()],
            exp: chrono::Utc::now().timestamp() + 3600,
            iat: chrono::Utc::now().timestamp(),
            jti: Uuid::now_v7(),
            purpose: "access".to_string(),
        };

        let auth = AuthContext::from_jwt(claims);

        assert!(check_permission(&auth, "search:view").is_ok());
        assert!(check_permission(&auth, "search:execute").is_ok());
        assert!(check_permission(&auth, "detections:create").is_err());
    }

    #[test]
    fn test_check_any_permission() {
        use nanosiem_core::auth::token::{DEFAULT_TOKEN_AUDIENCE, DEFAULT_TOKEN_ISSUER};

        let claims = TokenClaims {
            iss: DEFAULT_TOKEN_ISSUER.to_string(),
            aud: DEFAULT_TOKEN_AUDIENCE.to_string(),
            sub: Uuid::now_v7(),
            roles: vec!["Editor".to_string()],
            permissions: vec!["search:view".to_string()],
            exp: chrono::Utc::now().timestamp() + 3600,
            iat: chrono::Utc::now().timestamp(),
            jti: Uuid::now_v7(),
            purpose: "access".to_string(),
        };

        let auth = AuthContext::from_jwt(claims);

        // Has at least one
        assert!(check_any_permission(&auth, &["search:view", "detections:create"]).is_ok());

        // Has none
        assert!(check_any_permission(&auth, &["detections:create", "alerts:view"]).is_err());
    }

    fn jwt_auth(perms: Vec<String>) -> AuthContext {
        use nanosiem_core::auth::token::{DEFAULT_TOKEN_AUDIENCE, DEFAULT_TOKEN_ISSUER};
        AuthContext::from_jwt(TokenClaims {
            iss: DEFAULT_TOKEN_ISSUER.to_string(),
            aud: DEFAULT_TOKEN_AUDIENCE.to_string(),
            sub: Uuid::now_v7(),
            roles: vec!["Admin".to_string()],
            permissions: perms,
            exp: chrono::Utc::now().timestamp() + 3600,
            iat: chrono::Utc::now().timestamp(),
            jti: Uuid::now_v7(),
            purpose: "access".to_string(),
        })
    }

    fn api_key_auth(id: Uuid, perms: Vec<String>) -> AuthContext {
        let info = ApiKeyInfo {
            id,
            name: "test-key".to_string(),
            permissions: perms,
            user_id: Some(Uuid::now_v7()),
        };
        AuthContext::from_api_key(&info)
    }

    #[test]
    fn require_session_auth_allows_jwt() {
        let auth = jwt_auth(vec!["apikeys:create".to_string()]);
        assert!(require_session_auth(&auth).is_ok());
    }

    #[test]
    fn require_session_auth_blocks_api_key() {
        let auth = api_key_auth(Uuid::now_v7(), vec!["apikeys:create".to_string()]);
        let err = require_session_auth(&auth).expect_err("api-key must be rejected");
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn require_session_or_self_allows_jwt_against_any_target() {
        let auth = jwt_auth(vec!["apikeys:edit".to_string()]);
        assert!(require_session_or_self(&auth, Uuid::now_v7()).is_ok());
    }

    #[test]
    fn require_session_or_self_allows_api_key_targeting_itself() {
        let id = Uuid::now_v7();
        let auth = api_key_auth(id, vec!["apikeys:edit".to_string()]);
        assert!(require_session_or_self(&auth, id).is_ok());
    }

    #[test]
    fn require_session_or_self_blocks_api_key_targeting_other_key() {
        let auth = api_key_auth(Uuid::now_v7(), vec!["apikeys:edit".to_string()]);
        let err = require_session_or_self(&auth, Uuid::now_v7())
            .expect_err("cross-key mutation must be rejected");
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }
}
