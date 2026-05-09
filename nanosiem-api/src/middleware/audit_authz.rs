// SPDX-License-Identifier: AGPL-3.0-or-later

//! Audit middleware for authorization denials.
//!
//! Captures every 403 response from authenticated callers and emits an
//! `auth_denied` audit event via the modern audit pipeline. This closes a gap
//! where the synchronous `check_permission()` helper (used in 600+ call sites)
//! returns 403 silently, leaving no trail of authorization probing by
//! compromised low-privilege credentials.
//!
//! Layer placement: must run AFTER `auth_middleware` (so `AuthContext` is set
//! on the request) and BEFORE handler-side guards like `api_write_guard` and
//! `demo_guard` (so we capture their 403s as well as handler 403s).
//!
//! Tier-limit / plan-gate 403s are filtered out — they are billing signal,
//! not security signal, and shouldn't flood the audit log.
//!
//! Linear: NAN-687

use axum::{
    body::{Body, Bytes},
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use nanosiem_core::audit::{AuditEvent, AuditSource, ClientContext, AUTH_DENIED};
use serde_json::json;

use crate::handlers::AuditExt;
use crate::middleware::AuthContext;
use crate::state::AppState;

/// Maximum body bytes we'll buffer to extract the failure reason. 403 error
/// bodies are tiny JSON payloads; this is just defensive.
const MAX_BODY_BYTES: usize = 4096;

/// Tier-limit / plan-gate 403 prefixes from `ApiError::TierLimitExceeded` and
/// the explicit `Forbidden` mappings in `error.rs`. These are billing signals
/// (caller exceeded their plan quota), not authorization denials, and would
/// generate noisy audit events on every blocked write attempt.
///
/// Compared after stripping a leading `"Forbidden: "` — `ApiError::Forbidden`
/// uses `#[error("Forbidden: {0}")]`, so the on-the-wire body always carries
/// that prefix. Forgetting to strip it lets every tier-limit 403 leak into
/// the audit log.
const TIER_LIMIT_PREFIXES: &[&str] = &[
    "Tier limit exceeded",
    "Feature not available on your plan",
    "API access restricted",
    "AI model not available",
];

/// Strip the leading `"Forbidden: "` that `thiserror` prepends to every
/// `ApiError::Forbidden` body, so prefix matching works against the raw
/// inner message.
fn strip_forbidden_prefix(reason: &str) -> &str {
    reason.strip_prefix("Forbidden: ").unwrap_or(reason)
}

pub async fn audit_authz_failures(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let auth = request.extensions().get::<AuthContext>().cloned();
    let client = request
        .extensions()
        .get::<ClientContext>()
        .cloned()
        .unwrap_or_default();

    let response = next.run(request).await;

    if response.status() != StatusCode::FORBIDDEN {
        return response;
    }

    // No actor → can't audit usefully (and `auth_middleware` already returned
    // 401 for unauthenticated callers, so 403 without AuthContext is rare).
    let Some(auth) = auth else {
        return response;
    };

    let (parts, body) = response.into_parts();
    let body_bytes = match axum::body::to_bytes(body, MAX_BODY_BYTES).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to read 403 body for audit emission");
            return Response::from_parts(parts, Body::empty());
        }
    };

    let reason = parse_failure_reason(&body_bytes);

    if reason
        .as_deref()
        .map(is_tier_limit_message)
        .unwrap_or(false)
    {
        return Response::from_parts(parts, Body::from(body_bytes));
    }

    state.emit_audit(build_auth_denied_event(
        &auth,
        method.as_str(),
        &path,
        &client,
        reason.as_deref(),
    ));

    Response::from_parts(parts, Body::from(body_bytes))
}

fn build_auth_denied_event(
    auth: &AuthContext,
    method: &str,
    path: &str,
    client: &ClientContext,
    reason: Option<&str>,
) -> AuditEvent {
    let actor_id = if auth.is_api_key {
        None
    } else {
        Some(auth.user_id())
    };

    AuditEvent::builder(AuditSource::Auth, AUTH_DENIED)
        .actor(actor_id, None)
        .api_key(auth.api_key_id, auth.api_key_name.clone())
        .resource("endpoint", None, Some(format!("{} {}", method, path)))
        .client(client.ip_address.clone(), client.user_agent.clone())
        .success(false)
        .details(json!({
            "method": method,
            "path": path,
            "reason": reason,
            "user_permissions": auth.claims.permissions,
        }))
        .build()
}

fn parse_failure_reason(body: &Bytes) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;

    // AuthErrorResponse: { error, message }
    if let Some(msg) = value.get("message").and_then(|m| m.as_str()) {
        return Some(msg.to_string());
    }
    // ApiError ErrorResponse: { error: { code, message, details } }
    if let Some(msg) = value
        .get("error")
        .and_then(|e| e.get("message"))
        .and_then(|m| m.as_str())
    {
        return Some(msg.to_string());
    }

    None
}

fn is_tier_limit_message(reason: &str) -> bool {
    let stripped = strip_forbidden_prefix(reason);
    TIER_LIMIT_PREFIXES
        .iter()
        .any(|p| stripped.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nanosiem_core::auth::TokenClaims;
    use uuid::Uuid;

    fn api_key_auth_context(key_id: Uuid, key_owner: Uuid) -> AuthContext {
        let claims = TokenClaims {
            iss: "nanosiem".to_string(),
            aud: "nanosiem-api".to_string(),
            sub: key_owner,
            roles: vec![],
            permissions: vec!["detections:view".to_string(), "audit:view".to_string()],
            exp: 0,
            iat: 0,
            jti: Uuid::now_v7(),
            purpose: "access".to_string(),
        };
        AuthContext {
            claims,
            is_api_key: true,
            api_key_id: Some(key_id),
            api_key_name: Some("ci-bot".to_string()),
        }
    }

    #[test]
    fn parses_auth_error_response_shape() {
        let body = Bytes::from(
            r#"{"error":"forbidden","message":"Missing required permission: detections:create"}"#,
        );
        assert_eq!(
            parse_failure_reason(&body).as_deref(),
            Some("Missing required permission: detections:create"),
        );
    }

    #[test]
    fn parses_api_error_response_shape() {
        let body = Bytes::from(
            r#"{"error":{"code":"FORBIDDEN","message":"Access denied to this case","details":null}}"#,
        );
        assert_eq!(
            parse_failure_reason(&body).as_deref(),
            Some("Access denied to this case"),
        );
    }

    #[test]
    fn returns_none_for_non_json_body() {
        let body = Bytes::from("plain text");
        assert!(parse_failure_reason(&body).is_none());
    }

    #[test]
    fn detects_tier_limit_messages() {
        // Bare prefix (e.g. ApiError::TierLimitExceeded variant whose
        // #[error("Tier limit exceeded")] has no inner placeholder).
        assert!(is_tier_limit_message(
            "Tier limit exceeded: maximum 50 detection rules"
        ));
        assert!(is_tier_limit_message(
            "Feature not available on your plan: agentless"
        ));
        assert!(is_tier_limit_message("API access restricted"));
        assert!(is_tier_limit_message(
            "AI model not available on your tier"
        ));
    }

    #[test]
    fn detects_tier_limit_messages_with_forbidden_prefix() {
        // Production wire format: From<TierError> for ApiError lifts every tier
        // failure into ApiError::Forbidden(format!("...")), and thiserror's
        // #[error("Forbidden: {0}")] prepends "Forbidden: " in the body.
        // Without stripping that prefix, all four flavors leak into the audit
        // log as auth_denied — the original bug this regression test pins.
        assert!(is_tier_limit_message(
            "Forbidden: Tier limit exceeded: maximum 50 detection rules"
        ));
        assert!(is_tier_limit_message(
            "Forbidden: Feature not available on your plan: agentless"
        ));
        assert!(is_tier_limit_message("Forbidden: API access restricted"));
        assert!(is_tier_limit_message(
            "Forbidden: AI model not available on your tier"
        ));
    }

    #[test]
    fn does_not_match_authz_denial_messages() {
        // Both naked (AuthErrorResponse path) and Forbidden-prefixed
        // (ApiError::Forbidden path) wire formats must NOT be silenced.
        assert!(!is_tier_limit_message(
            "Missing required permission: detections:create"
        ));
        assert!(!is_tier_limit_message(
            "Forbidden: Missing permission: detections:create"
        ));
        assert!(!is_tier_limit_message("Access denied to this case"));
        assert!(!is_tier_limit_message(
            "Forbidden: Access denied to this case"
        ));
        assert!(!is_tier_limit_message(
            "API keys may only manage themselves. Use a session to manage other keys."
        ));
    }

    #[test]
    fn builds_auth_denied_event_for_api_key_caller() {
        let key_id = Uuid::now_v7();
        let key_owner = Uuid::now_v7();
        let auth = api_key_auth_context(key_id, key_owner);
        let client = ClientContext::new(
            Some("203.0.113.7".to_string()),
            Some("Caido/1.0".to_string()),
        );

        let event = build_auth_denied_event(
            &auth,
            "POST",
            "/api/rules",
            &client,
            Some("Missing required permission: detections:create"),
        );

        assert_eq!(event.action, AUTH_DENIED);
        assert!(matches!(event.source, AuditSource::Auth));
        assert!(!event.success);
        // API key callers don't populate actor_id (avoids implying a human acted).
        assert!(event.actor_id.is_none());
        assert_eq!(event.api_key_id, Some(key_id));
        assert_eq!(event.api_key_name.as_deref(), Some("ci-bot"));
        assert_eq!(event.resource_type.as_deref(), Some("endpoint"));
        assert_eq!(
            event.resource_name.as_deref(),
            Some("POST /api/rules"),
        );
        assert_eq!(event.ip_address.as_deref(), Some("203.0.113.7"));
        assert_eq!(event.user_agent.as_deref(), Some("Caido/1.0"));

        let details = event.details.expect("details set");
        assert_eq!(details["method"], "POST");
        assert_eq!(details["path"], "/api/rules");
        assert_eq!(
            details["reason"],
            "Missing required permission: detections:create",
        );
        assert_eq!(
            details["user_permissions"],
            serde_json::json!(["detections:view", "audit:view"]),
        );
    }

    #[test]
    fn builds_auth_denied_event_for_session_caller() {
        let key_owner = Uuid::now_v7();
        let mut auth = api_key_auth_context(Uuid::now_v7(), key_owner);
        // Flip to a session-authenticated caller.
        auth.is_api_key = false;
        auth.api_key_id = None;
        auth.api_key_name = None;

        let event = build_auth_denied_event(
            &auth,
            "DELETE",
            "/api/users/abc",
            &ClientContext::default(),
            None,
        );

        // Session callers populate actor_id from the JWT subject.
        assert_eq!(event.actor_id, Some(key_owner));
        assert!(event.api_key_id.is_none());
        assert!(event.api_key_name.is_none());
        assert!(event.details.unwrap()["reason"].is_null());
    }
}
