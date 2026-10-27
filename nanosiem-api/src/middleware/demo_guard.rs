// SPDX-License-Identifier: AGPL-3.0-or-later

//! Demo mode guard middleware
//!
//! Blocks admin/settings endpoints for demo users. Must be layered after
//! auth_middleware so AuthContext is available in request extensions.
//! Only active when DEPLOYMENT_MODE=demo.

use axum::{
    body::HttpBody as _,
    extract::{Request, State},
    http::{Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};

use super::auth::AuthContext;
use crate::config::DeploymentMode;
use crate::error::{ErrorDetail, ErrorResponse};

/// Path prefixes that are completely blocked for demo users (any HTTP method).
const BLOCKED_PREFIXES: &[&str] = &[
    "/api/settings",
    "/api/users",
    "/api/groups",
    "/api/roles",
    "/api/api-keys",
    "/api/sessions",
    "/api/credentials",
    "/api/automation-keys",
    "/api/ip-allowlist",
    "/api/gdpr",
    "/api/system",
    "/api/auth/oidc/admin",
];

/// Specific paths blocked for demo users (write methods only).
const BLOCKED_WRITE_PATHS: &[&str] = &[
    "/api/parsers",        // Can view, not create/edit
    "/api/feeds",          // Can view, not create/edit
    "/api/log-sources",    // Can view, not manage
    "/api/source-configs", // Can view, not manage
    "/api/enrichments",    // Can view, not configure
    "/api/upload",         // No file uploads
    "/api/scheduler",      // No job management
    "/api/identity",       // No identity provider management
    "/api/marketplace",    // No marketplace installs
];

/// Paths that demo users CAN write to (exceptions within blocked prefixes).
const ALLOWED_SELF_PATHS: &[&str] = &[
    "/api/users/me/preferences",
    "/api/auth/password",
    "/api/auth/logout",
    "/api/auth/refresh",
    "/api/auth/me",
    "/api/auth/validate",
];

/// Settings reads that demo users are allowed to access.
///
/// Demo users have `settings:ai` so the search UI can detect whether meloD is
/// configured and enable natural-language query building. Keep this list tight:
/// read-only probes only, not general settings access.
const ALLOWED_SAFE_PATHS: &[&str] = &["/api/settings/ai-availability"];

/// Middleware that blocks admin endpoints for demo users.
///
/// Must be layered **after** auth_middleware (inner to it) so that
/// `AuthContext` is available in request extensions.
pub async fn demo_guard(
    State(mode): State<DeploymentMode>,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    // Only apply in demo mode
    if !mode.is_demo() {
        return Ok(next.run(request).await);
    }

    // Check if request has an auth context with demo role
    let is_demo_user = request
        .extensions()
        .get::<AuthContext>()
        .map(|auth| auth.claims.roles.iter().any(|role| role.trim().eq_ignore_ascii_case("demo_analyst")))
        .unwrap_or(false);

    if !is_demo_user {
        return Ok(next.run(request).await);
    }
    if nanosiem_core::demo_outbound::soar_read_path(request.method().as_str(), request.uri().path()) == Some(false) {
        return Err(normalize_empty_demo_not_found(StatusCode::NOT_FOUND.into_response()));
    }

    let path = request.uri().path().to_string();
    let method = request.method().clone();

    // Always allow self-service paths
    for allowed in ALLOWED_SELF_PATHS {
        if path == *allowed || path.starts_with(allowed) {
            return Ok(normalize_empty_demo_not_found(next.run(request).await));
        }
    }

    // Allow specific read-only endpoints needed for the demo analyst workflow.
    if is_allowed_safe_path(&path, &method) {
        return Ok(normalize_empty_demo_not_found(next.run(request).await));
    }

    // Block completely restricted prefixes
    for prefix in BLOCKED_PREFIXES {
        if path.starts_with(prefix) {
            return Err(demo_forbidden(&path));
        }
    }

    // Block writes to partially restricted paths (GET is allowed)
    if !is_safe_method(&method) {
        for prefix in BLOCKED_WRITE_PATHS {
            if path.starts_with(prefix) {
                return Err(demo_forbidden(&path));
            }
        }
    }

    Ok(normalize_empty_demo_not_found(next.run(request).await))
}

// Matched routes receive Content-Length from Axum's MethodRouter, while
// an unmatched fallback may not. Canonicalize empty demo 404s in both paths.
fn normalize_empty_demo_not_found(mut response: Response) -> Response {
    if response.status()==StatusCode::NOT_FOUND && response.body().size_hint().exact()==Some(0) {
        response.headers_mut().insert(axum::http::header::CONTENT_LENGTH,axum::http::HeaderValue::from_static("0"));
    }
    response
}

fn is_safe_method(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

fn is_allowed_safe_path(path: &str, method: &Method) -> bool {
    is_safe_method(method)
        && ALLOWED_SAFE_PATHS
            .iter()
            .any(|allowed| path == *allowed)
}

fn demo_forbidden(path: &str) -> Response {
    let body = ErrorResponse {
        error: ErrorDetail {
            code: "DEMO_RESTRICTED".to_string(),
            message: "This action is not available in demo mode. Sign up for full access."
                .to_string(),
            details: Some(serde_json::json!({
                "path": path,
                "demo": true,
            })),
        },
    };
    (StatusCode::FORBIDDEN, Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request, middleware::from_fn_with_state, routing::get, Router};
    use tower::ServiceExt;

    use nanosiem_core::auth::token::{DEFAULT_TOKEN_AUDIENCE, DEFAULT_TOKEN_ISSUER};
    use nanosiem_core::auth::TokenClaims;
    use uuid::Uuid;

    fn demo_auth_context() -> AuthContext {
        AuthContext::from_jwt(TokenClaims {
            iss: DEFAULT_TOKEN_ISSUER.to_string(),
            aud: DEFAULT_TOKEN_AUDIENCE.to_string(),
            sub: Uuid::now_v7(),
            roles: vec!["demo_analyst".to_string()],
            permissions: vec![],
            exp: chrono::Utc::now().timestamp() + 3600,
            iat: chrono::Utc::now().timestamp(),
            jti: Uuid::now_v7(),
            purpose: "access".to_string(),
        })
    }

    fn app() -> Router {
        Router::new()
            .route("/api/settings/ai-availability", get(|| async { "ok" }))
            .route("/api/settings/search", get(|| async { "ok" }))
            .layer(from_fn_with_state(DeploymentMode::Demo, demo_guard))
    }

    #[test]
    fn allows_demo_read_for_ai_availability_probe() {
        assert!(is_allowed_safe_path(
            "/api/settings/ai-availability",
            &Method::GET
        ));
    }

    #[test]
    fn blocks_demo_writes_for_ai_provider_settings() {
        assert!(!is_allowed_safe_path(
            "/api/settings/ai-providers",
            &Method::POST
        ));
        assert!(!is_allowed_safe_path(
            "/api/settings/ai-providers",
            &Method::GET
        ));
        assert!(!is_allowed_safe_path("/api/settings/ai-providers/openai", &Method::GET));
    }

    #[test]
    fn keeps_other_settings_paths_blocked() {
        assert!(!is_allowed_safe_path("/api/settings/search", &Method::GET));
        assert!(!is_allowed_safe_path(
            "/api/settings/organizational-context",
            &Method::GET
        ));
    }

    #[tokio::test]
    async fn demo_user_can_read_ai_availability_probe() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/api/settings/ai-availability")
                    .method(Method::GET)
                    .extension(demo_auth_context())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn demo_user_cannot_read_other_settings_paths() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/api/settings/search")
                    .method(Method::GET)
                    .extension(demo_auth_context())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn demo_soar_production_guard_route_matrix() {
        // Use the actual legacy middleware/typed deployment wiring. Handler
        // stubs distinguish guard refusal from downstream authorization.
        let spec=<nanosiem_enterprise::handlers::soar::SoarApiDoc as utoipa::OpenApi>::openapi();
        let spec:serde_json::Value=serde_json::from_str(&spec.to_json().unwrap()).unwrap();
        let mut routes=Router::new();
        for path in spec["paths"].as_object().unwrap().keys().filter(|path|path.starts_with("/api/soar")) {
            routes=routes.route(path,axum::routing::any(||async{StatusCode::OK}));
        }
        let routes=routes.layer(from_fn_with_state(DeploymentMode::Demo,demo_guard));
        let unknown=routes.clone().oneshot(Request::builder().uri("/api/unknown-demo-route")
            .extension(demo_auth_context()).body(Body::empty()).unwrap()).await.unwrap();
        let headers=unknown.headers().clone();
        let bytes=axum::body::to_bytes(unknown.into_body(),4096).await.unwrap();
        for (path,methods) in spec["paths"].as_object().unwrap() {
            if !path.starts_with("/api/soar"){continue;}
            let path=path.replace("{id}","11111111-1111-4111-8111-111111111111").replace("{name}","okta");
            for method in methods.as_object().unwrap().keys() {
                let method=method.to_uppercase();
                let response=routes.clone().oneshot(Request::builder().method(method.as_str()).uri(&path)
                    .extension(demo_auth_context()).body(Body::empty()).unwrap()).await.unwrap();
                if nanosiem_core::demo_outbound::soar_read_path(&method,&path)==Some(true) {
                    assert_eq!(response.status(),StatusCode::OK,"{method} {path}");
                } else {
                    assert_eq!(response.status(),StatusCode::NOT_FOUND,"{method} {path}");
                    assert_eq!(response.headers(),&headers);
                    assert_eq!(axum::body::to_bytes(response.into_body(),4096).await.unwrap(),bytes);
                }
                let mut admin=demo_auth_context();admin.claims.roles=vec!["admin".into()];
                let response=routes.clone().oneshot(Request::builder().method(method.as_str()).uri(&path)
                    .extension(admin).body(Body::empty()).unwrap()).await.unwrap();
                assert_eq!(response.status(),StatusCode::OK,"normal administrator control: {method} {path}");
            }
        }
    }

}
