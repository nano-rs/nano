// SPDX-License-Identifier: AGPL-3.0-or-later

//! Path selectors constrain authenticated authority; they never grant it.

use axum::{
    extract::Request,
    http::{StatusCode, Uri},
    response::{IntoResponse, Response},
    Router,
};
use nanosiem_core::auth::TrustedTenantContext;
use tower::ServiceExt;

#[derive(Clone, Debug)]
pub struct RequestedTenantSlug(pub String);

pub fn canonical_slug(slug: &str) -> bool {
    !slug.is_empty()
        && slug.len() <= 63
        && slug
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && slug.as_bytes()[0].is_ascii_alphanumeric()
        && slug.as_bytes()[slug.len() - 1].is_ascii_alphanumeric()
}

/// Called after authentication, before any tenant handler or write guard.
pub fn require_matching_tenant(request: &Request) -> Result<(), StatusCode> {
    if let Some(requested) = request.extensions().get::<RequestedTenantSlug>() {
        let trusted = request.extensions().get::<TrustedTenantContext>();
        if !trusted.is_some_and(|tenant| tenant.tenant_slug == requested.0) {
            return Err(StatusCode::FORBIDDEN);
        }
    }
    Ok(())
}

/// Re-dispatch before axum matches a route, preserving query/body/headers.
/// Only /api is aliased. Internal paths cannot be prefixed; existing API
/// admission policy continues to fence platform endpoints.
pub fn scoped_api_router(app: Router) -> Router {
    Router::new().fallback(move |mut request: Request| {
        let app = app.clone();
        async move {
            let path = request.uri().path().to_owned();
            if let Some(scoped) = path.strip_prefix("/t/") {
                let Some((slug, rest)) = scoped.split_once('/') else {
                    return StatusCode::NOT_FOUND.into_response();
                };
                if !canonical_slug(slug) {
                    return StatusCode::NOT_FOUND.into_response();
                }
                if rest == "api" || rest.starts_with("api/") {
                    // Tenant-prefixed API calls require explicit credentials. Browser
                    // cookies from other tenant tabs must not select authority here.
                    if !request.headers().contains_key("authorization")
                        && !request.headers().contains_key("x-api-key")
                    {
                        return StatusCode::UNAUTHORIZED.into_response();
                    }
                    request.headers_mut().remove(axum::http::header::COOKIE);
                    let mut target = format!("/{rest}");
                    if let Some(query) = request.uri().query() {
                        target.push('?');
                        target.push_str(query);
                    }
                    let Ok(uri) = target.parse::<Uri>() else {
                        return StatusCode::BAD_REQUEST.into_response();
                    };
                    *request.uri_mut() = uri;
                    request
                        .extensions_mut()
                        .insert(RequestedTenantSlug(slug.to_owned()));
                } else if !(rest == "swagger-ui"
                    || rest.starts_with("swagger-ui/")
                    || rest == "api-docs/openapi.json")
                {
                    return StatusCode::NOT_FOUND.into_response();
                }
            }
            app.oneshot(request)
                .await
                .unwrap_or_else(|never| match never {})
        }
    })
}

pub async fn enforce_tenant_path(request: Request, next: axum::middleware::Next) -> Response {
    match require_matching_tenant(&request) {
        Ok(()) => next.run(request).await,
        Err(status) => {
            tracing::warn!(
                requested_tenant = request
                    .extensions()
                    .get::<RequestedTenantSlug>()
                    .map(|slug| slug.0.as_str()),
                "Authenticated tenant does not match URL"
            );
            status.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::Request as HttpRequest,
        routing::get,
    };

    #[tokio::test]
    async fn tenant_alias_preserves_query_and_refuses_cross_tenant_credentials() {
        // Mock credential verification; exercise the real router and fence.
        let app = Router::new()
            .route(
                "/api/probe",
                get(|request: Request| async move {
                    assert!(!request.headers().contains_key("cookie"));
                    request.uri().to_string()
                }),
            )
            .layer(axum::middleware::from_fn(enforce_tenant_path))
            .layer(axum::middleware::from_fn(
                |mut request: Request, next: axum::middleware::Next| async move {
                    let slug = request
                        .headers()
                        .get("x-api-key")
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_owned();
                    request.extensions_mut().insert(TrustedTenantContext {
                        tenant_id: uuid::Uuid::nil(),
                        tenant_slug: slug,
                    });
                    next.run(request).await
                },
            ));
        let app = scoped_api_router(app);
        for (key, status) in [("acme", StatusCode::OK), ("other", StatusCode::FORBIDDEN)] {
            let response = app
                .clone()
                .oneshot(
                    HttpRequest::builder()
                        .uri("/t/acme/api/probe?limit=5")
                        .header("x-api-key", key)
                        .header("cookie", "access_token=other-session")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), status);
            if status == StatusCode::OK {
                assert_eq!(
                    to_bytes(response.into_body(), usize::MAX).await.unwrap(),
                    "/api/probe?limit=5"
                );
            }
        }
    }

    #[tokio::test]
    async fn tenant_alias_preserves_post_body() {
        let app = Router::new()
            .route(
                "/api/probe",
                axum::routing::post(|request: Request| async move {
                    assert_eq!(request.uri(), "/api/probe?limit=5");
                    to_bytes(request.into_body(), 1024).await.unwrap()
                }),
            )
            .layer(axum::middleware::from_fn(enforce_tenant_path))
            .layer(axum::Extension(TrustedTenantContext {
                tenant_id: uuid::Uuid::nil(),
                tenant_slug: "acme".into(),
            }));
        let response = scoped_api_router(app)
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/t/acme/api/probe?limit=5")
                    .header("x-api-key", "fixture")
                    .body(Body::from("query body"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(response.into_body(), 1024).await.unwrap(),
            "query body"
        );
    }

    #[tokio::test]
    async fn aliases_never_admit_sessions_or_internal_paths() {
        let app = scoped_api_router(Router::new().fallback(|| async { StatusCode::OK }));
        for (path, status) in [
            ("/t/acme/api/rules", StatusCode::UNAUTHORIZED),
            ("/t/ACME/api/rules", StatusCode::NOT_FOUND),
            ("/t/%61cme/api/rules", StatusCode::NOT_FOUND),
            ("/t/acme/internal/hosted-config", StatusCode::NOT_FOUND),
            ("/t/acme/metrics", StatusCode::NOT_FOUND),
            ("/health", StatusCode::OK),
        ] {
            let response = app
                .clone()
                .oneshot(
                    HttpRequest::builder()
                        .uri(path)
                        .header("cookie", "access_token=session")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), status, "{path}");
        }
    }

    #[test]
    fn unverified_selector_is_never_authority() {
        let mut request = Request::new(Body::empty());
        request
            .extensions_mut()
            .insert(RequestedTenantSlug("acme".into()));
        assert_eq!(
            require_matching_tenant(&request),
            Err(StatusCode::FORBIDDEN)
        );
        for slug in ["", "-acme", "acme-", "ACME", "%61cme", "acme/other"] {
            assert!(!canonical_slug(slug));
        }
    }
}
