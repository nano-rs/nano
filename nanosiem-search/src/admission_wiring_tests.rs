// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4664 / NAN-4703: the HTTP side of fair admission. The production
//! middleware (as `lib.rs` layers it) sets each request's wait budget and
//! query class, and an admission refusal is a retryable 429.

use axum::{
    body::Body,
    extract::Request,
    middleware::{self, Next},
    response::IntoResponse,
    routing::post,
    Router,
};
use nanosiem_core::auth::{ApiKeyInfo, TokenClaims};
use nanosiem_core::search::admission;
use tower::ServiceExt;
use uuid::Uuid;

use crate::middleware::{admission_wait_budget_middleware, AuthContext};

async fn report() -> String {
    format!(
        "{}|{}",
        admission::current_query_class().label(),
        admission::current_wait_budget()
            .map(|budget| budget.as_millis().min(u128::from(u64::MAX)).to_string())
            .unwrap_or_else(|| "none".into())
    )
}

async fn call(app: Router, headers: &[(&str, &str)]) -> String {
    let mut request = Request::builder().method("POST").uri("/api/search");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = app
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), 1 << 10)
        .await
        .unwrap();
    String::from_utf8(body.to_vec()).unwrap()
}

#[tokio::test]
async fn middleware_sets_class_and_budget_from_headers() {
    let app = Router::new()
        .route("/api/search", post(report))
        .layer(middleware::from_fn(admission_wait_budget_middleware));
    for (headers, expected) in [
        (vec![], "human|60000"),
        (vec![(admission::QUERY_CLASS_HEADER, "agent")], "agent|60000"),
        (vec![(admission::QUERY_CLASS_HEADER, "AGENT")], "agent|60000"),
        (vec![(admission::QUERY_CLASS_HEADER, "robot")], "human|60000"),
        (vec![(admission::ADMISSION_WAIT_HEADER, "120000")], "human|120000"),
        (vec![(admission::ADMISSION_WAIT_HEADER, "0")], "human|0"),
    ] {
        assert_eq!(call(app.clone(), &headers).await, expected, "{headers:?}");
    }
    // An atomic caller without its own budget keeps the full configured wait.
    let atomic = call(app, &[("x-nano-accept-async", "0")]).await;
    assert!(atomic.starts_with("human|") && atomic != "human|60000", "{atomic}");
}

#[tokio::test]
async fn agent_credentials_are_always_the_agent_class() {
    let key = |name: &str| ApiKeyInfo {
        id: Uuid::now_v7(),
        name: name.to_string(),
        permissions: vec!["search:execute".to_string()],
        user_id: Some(Uuid::now_v7()),
    };
    for (name, header, expected) in [
        ("nano Desktop \u{2014} agent tools (mbp)", None, "agent"),
        ("nano Desktop \u{2014} hunt sweep (mbp)", Some("human"), "agent"),
        ("ci export", None, "human"),
        ("ci export", Some("agent"), "agent"),
    ] {
        let context = AuthContext::from_api_key(&key(name));
        let app = Router::new()
            .route("/api/search", post(report))
            .layer(middleware::from_fn(admission_wait_budget_middleware))
            .layer(middleware::from_fn(move |mut request: Request, next: Next| {
                let context = context.clone();
                async move {
                    request.extensions_mut().insert(context);
                    next.run(request).await
                }
            }));
        let headers: Vec<(&str, &str)> = header
            .map(|value| vec![(admission::QUERY_CLASS_HEADER, value)])
            .unwrap_or_default();
        let body = call(app, &headers).await;
        assert!(body.starts_with(expected), "{name} {header:?}: {body}");
    }
    // A session (JWT) is never an agent credential.
    assert!(
        !AuthContext::from_jwt(TokenClaims {
            iss: "t".into(),
            aud: "t".into(),
            sub: Uuid::now_v7(),
            roles: vec![],
            permissions: vec![],
            exp: i64::MAX,
            iat: 0,
            jti: Uuid::now_v7(),
            purpose: "access".into(),
        })
        .agent_credential
    );
}

/// An admission refusal (wait budget ended, queue full) is a 429 that tells
/// the caller when to retry.
#[tokio::test]
async fn admission_refusal_is_429_with_retry_after() {
    let response =
        crate::SearchError::AdmissionDenied("Search queue timeout after 5000ms".into())
            .into_response();
    assert_eq!(response.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers()[axum::http::header::RETRY_AFTER], "2");
}

/// NAN-4928 review P1: admission counts against the OWNING user, so two keys
/// of one user share one budget; a key with no owner is refused.
#[test]
fn admission_keys_on_the_owning_user() {
    let owner = Uuid::now_v7();
    let key = |id: Uuid, owner: Option<Uuid>| {
        AuthContext::from_api_key(&ApiKeyInfo {
            id,
            name: "ci export".into(),
            permissions: vec!["search:execute".into()],
            user_id: owner,
        })
    };
    let (k1, k2) = (key(Uuid::now_v7(), Some(owner)), key(Uuid::now_v7(), Some(owner)));
    assert_ne!(k1.claims.sub, k2.claims.sub, "two credentials");
    assert_eq!(crate::handlers::admission_user(&k1).unwrap(), owner);
    assert_eq!(crate::handlers::admission_user(&k2).unwrap(), owner, "one budget");
    let orphan = key(Uuid::now_v7(), None);
    assert!(matches!(
        crate::handlers::admission_user(&orphan),
        Err(crate::SearchError::Forbidden(_))
    ));
    let session = AuthContext::from_jwt(TokenClaims {
        iss: "t".into(),
        aud: "t".into(),
        sub: owner,
        roles: vec![],
        permissions: vec![],
        exp: i64::MAX,
        iat: 0,
        jti: Uuid::now_v7(),
        purpose: "access".into(),
    });
    assert_eq!(crate::handlers::admission_user(&session).unwrap(), owner, "sessions and keys share it");
}
