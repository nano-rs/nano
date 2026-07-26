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
    /// SOURCE-scope deny set for this caller (NAN-1799 / per-source RBAC).
    ///
    /// Populated by the auth middleware via `SourceScopeResolver::resolve`
    /// after authentication succeeds. Carries SOURCE scope ONLY — the `audit`
    /// source gate is NOT baked in here; handlers union it in from the
    /// `audit:view` permission when composing the effective deny set they pass
    /// to the search/detection services.
    ///
    /// Defaults to unrestricted (empty deny set) in the constructors below; the
    /// middleware overwrites it with the resolved scope. An unrestricted scope
    /// means "sees everything", so callers built outside the middleware (tests,
    /// internal SYSTEM paths) stay back-compatible.
    pub denied_sources: nanosiem_core::auth::ScopeSet,
}

impl AuthContext {
    /// Create from JWT token claims
    pub fn from_jwt(claims: TokenClaims) -> Self {
        Self {
            claims,
            is_api_key: false,
            api_key_id: None,
            api_key_name: None,
            denied_sources: nanosiem_core::auth::ScopeSet::default(),
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
            denied_sources: nanosiem_core::auth::ScopeSet::default(),
        }
    }

    /// Check if the context has a specific permission
    pub fn has_permission(&self, permission: &str) -> bool {
        self.claims.has_permission(permission)
    }

    /// NAN-1801: compose the caller's EFFECTIVE per-source deny set — the
    /// per-source RBAC deny set (NAN-1799, `denied_sources`) unioned with the
    /// `audit` source unless the caller holds `audit:view`. This is the same
    /// composition the gated handlers perform inline (alerts, fields,
    /// dashboard panel queries, detection stats, dry-resolve); side-door
    /// callers use this method so the audit gate cannot be forgotten.
    ///
    /// An unrestricted caller with `audit:view` yields an EMPTY deny set,
    /// keeping downstream SQL byte-identical to the pre-scoping form.
    ///
    /// The ADMIN / full-visibility bypass (NAN-1841, `source_scopes:view_all`) is
    /// applied UPSTREAM in `SourceScopeResolver::resolve`, so a bypass caller
    /// already arrives with an empty `denied_sources`. The `audit` gate here is
    /// intentionally SEPARATE: it stays keyed on `audit:view` (which the Admin
    /// role also holds), so it is not weakened by the source-scope bypass.
    pub fn effective_source_deny_set(&self) -> std::collections::BTreeSet<String> {
        let mut deny = self.denied_sources.deny_set().clone();
        if !self.has_permission(nanosiem_core::auth::permissions::AUDIT_VIEW) {
            deny.insert("audit".to_string());
        }
        deny
    }

    /// The same composition as [`effective_source_deny_set`](Self::effective_source_deny_set),
    /// wrapped in the [`ScopeSet`](nanosiem_core::auth::ScopeSet) that the
    /// search / detection / log-source services take.
    ///
    /// NAN-2055: this was hand-inlined identically in a growing number of
    /// handlers (alerts, detection testing, fields, log-source telemetry). One
    /// definition means a new log-reading surface cannot silently ship with the
    /// `audit` half of the composition forgotten — the failure mode that made
    /// `/api/source-types` return `audit` event counts to a caller without
    /// `audit:view`.
    ///
    /// An unrestricted caller holding `audit:view` yields an EMPTY deny set, so
    /// downstream SQL stays byte-identical to the pre-scoping form.
    pub fn effective_viewer_scope(&self) -> nanosiem_core::auth::ScopeSet {
        nanosiem_core::auth::ScopeSet::from_denied(self.effective_source_deny_set())
    }

    /// Check if the context has any of the specified permissions
    pub fn has_any_permission(&self, permissions: &[&str]) -> bool {
        self.claims.has_any_permission(permissions)
    }

    /// Get the user ID (or API key ID for API key auth)
    pub fn user_id(&self) -> Uuid {
        self.claims.sub
    }

    /// The principal identity that SOURCE-scope grants (per-source RBAC,
    /// NAN-1799 / NAN-2043) must resolve against.
    ///
    /// For an interactive session this is the caller's `user_id`, so their
    /// group source-grants apply. For an API key it is the KEY id
    /// (`api_key_id`), NOT the key owner: an API key is its own authorization
    /// principal and must not silently inherit its owner's group source-grants.
    /// `claims.sub` on an api-key context is the OWNER's user_id (kept by
    /// [`user_id`](Self::user_id) for FK / audit attribution), so resolving
    /// scope against it would let a key WITHOUT `source_scopes:view_all` read
    /// restricted sources that the search service correctly hides — the search
    /// service resolves against the key id, which has no group memberships and
    /// therefore denies all restricted sources. This method makes the main API
    /// resolve the same principal. `source_scopes:view_all` on the key's OWN
    /// permission set still produces the positive unrestricted bypass inside
    /// `SourceScopeResolver::resolve`.
    pub fn source_scope_principal(&self) -> Uuid {
        if self.is_api_key {
            // `api_key_id` is always `Some` for an api-key context; the
            // `unwrap_or` is a defensive fallback, never taken in practice.
            self.api_key_id.unwrap_or(self.claims.sub)
        } else {
            self.claims.sub
        }
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

/// Reject API-key-authenticated callers from human, interactive-session-only
/// routes (NAN-2040 / NAN-2041). An API key's `sub` is its owner user id, so a
/// "self-service" ownership check would otherwise treat the key as the human
/// owner. Use this on notification / recent-activity / session self feeds and any
/// future human self-service endpoint so the owner-subject mistake can't recur.
pub fn ensure_interactive_session(auth: &AuthContext) -> Result<(), ApiError> {
    if auth.is_api_key {
        Err(ApiError::Forbidden(
            "This endpoint requires an interactive session; API keys are not permitted."
                .to_string(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nanosiem_core::auth::ApiKeyInfo;

    #[test]
    fn ensure_interactive_session_rejects_api_keys() {
        let user_id = Uuid::now_v7();
        // API key → rejected (its subject is its owner, not a human session).
        let key = AuthContext::from_api_key(&ApiKeyInfo {
            id: Uuid::now_v7(),
            name: "k".to_string(),
            permissions: vec![],
            user_id: Some(user_id),
        });
        assert!(matches!(
            ensure_interactive_session(&key),
            Err(ApiError::Forbidden(_))
        ));
        // Interactive (JWT) session → allowed.
        let human = AuthContext::from_jwt(TokenClaims {
            iss: "t".to_string(),
            aud: "t".to_string(),
            sub: user_id,
            roles: vec![],
            permissions: vec![],
            exp: i64::MAX,
            iat: 0,
            jti: Uuid::nil(),
            purpose: "access".to_string(),
        });
        assert!(ensure_interactive_session(&human).is_ok());
    }

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

    /// NAN-2043: an API key resolves SOURCE-scope against the KEY id (its own
    /// authorization principal), never the owner's user_id — otherwise a key
    /// without `source_scopes:view_all` would inherit the owner's group
    /// source-grants. `user_id()` must still return the OWNER for FK / audit.
    #[test]
    fn test_api_key_scope_principal_is_key_not_owner() {
        let owner_id = Uuid::now_v7();
        let key_id = Uuid::now_v7();
        let info = ApiKeyInfo {
            id: key_id,
            name: "restricted-key".to_string(),
            permissions: vec!["search:execute".to_string()],
            user_id: Some(owner_id),
        };

        let context = AuthContext::from_api_key(&info);

        // Scope resolves against the key, NOT the owner (the fix).
        assert_eq!(context.source_scope_principal(), key_id);
        assert_ne!(context.source_scope_principal(), owner_id);
        // Owner identity is preserved for FK / audit attribution.
        assert_eq!(context.user_id(), owner_id);
    }

    /// An orphaned key (owner deleted) still resolves scope against the key id
    /// and never falls back to some other principal.
    #[test]
    fn test_orphaned_api_key_scope_principal_is_key_id() {
        let key_id = Uuid::now_v7();
        let info = ApiKeyInfo {
            id: key_id,
            name: "orphan-key".to_string(),
            permissions: vec!["search:execute".to_string()],
            user_id: None,
        };

        let context = AuthContext::from_api_key(&info);

        assert_eq!(context.source_scope_principal(), key_id);
        // `user_id()` falls back to the key id for orphaned keys (existing
        // `from_api_key` behaviour), so scope and attribution coincide here.
        assert_eq!(context.user_id(), key_id);
    }

    /// An interactive session resolves scope against the caller's own user_id,
    /// so their group source-grants continue to apply.
    #[test]
    fn test_session_scope_principal_is_user_id() {
        use nanosiem_core::auth::token::{DEFAULT_TOKEN_AUDIENCE, DEFAULT_TOKEN_ISSUER};

        let user_id = Uuid::now_v7();
        let claims = TokenClaims {
            iss: DEFAULT_TOKEN_ISSUER.to_string(),
            aud: DEFAULT_TOKEN_AUDIENCE.to_string(),
            sub: user_id,
            roles: vec!["Analyst".to_string()],
            permissions: vec!["search:execute".to_string()],
            exp: i64::MAX,
            iat: 0,
            jti: Uuid::now_v7(),
            purpose: "access".to_string(),
        };

        let context = AuthContext::from_jwt(claims);

        assert!(!context.is_api_key);
        assert_eq!(context.source_scope_principal(), user_id);
        assert_eq!(context.user_id(), user_id);
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

    #[test]
    fn effective_viewer_scope_unions_the_audit_gate_onto_the_source_deny_set() {
        // NAN-2055: this composition was hand-inlined in a growing number of
        // log-reading handlers, and the `audit` half was the part that kept
        // getting forgotten — `/api/source-types` returned `audit` event counts
        // to callers without `audit:view`. Pin both halves in one place.
        let mut auth = jwt_auth(vec!["search:execute".to_string()]);
        auth.denied_sources = nanosiem_core::auth::ScopeSet::from_denied(
            ["windows_sysmon".to_string()].into_iter().collect(),
        );

        // No `audit:view` → the audit source is denied on top of RBAC's deny set.
        let scope = auth.effective_viewer_scope();
        assert!(scope.deny_set().contains("audit"));
        assert!(scope.deny_set().contains("windows_sysmon"));
        assert!(scope.is_restricted());

        // Holding `audit:view` drops only the audit half.
        let mut with_audit = jwt_auth(vec![
            "search:execute".to_string(),
            "audit:view".to_string(),
        ]);
        with_audit.denied_sources = nanosiem_core::auth::ScopeSet::from_denied(
            ["windows_sysmon".to_string()].into_iter().collect(),
        );
        let scope = with_audit.effective_viewer_scope();
        assert!(!scope.deny_set().contains("audit"));
        assert!(scope.deny_set().contains("windows_sysmon"));
    }

    #[test]
    fn effective_viewer_scope_is_empty_only_for_an_unrestricted_audit_viewer() {
        // An EMPTY deny set is the contract every caller relies on to keep its
        // SQL byte-identical to the pre-scoping form. It must require BOTH an
        // unrestricted source scope and `audit:view` — a caller missing
        // `audit:view` is restricted even with no per-source denials.
        let unrestricted = jwt_auth(vec!["audit:view".to_string()]);
        assert!(!unrestricted.effective_viewer_scope().is_restricted());

        let no_audit_view = jwt_auth(vec![]);
        assert!(no_audit_view.effective_viewer_scope().is_restricted());
    }

    /// The `ScopeSet` form and the raw `BTreeSet` form must never disagree —
    /// handlers pick whichever their downstream takes.
    #[test]
    fn effective_viewer_scope_agrees_with_effective_source_deny_set() {
        let auth = jwt_auth(vec!["search:execute".to_string()]);
        assert_eq!(
            auth.effective_viewer_scope().deny_set(),
            &auth.effective_source_deny_set()
        );
    }
}
