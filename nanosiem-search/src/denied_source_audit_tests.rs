// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use axum::{
    body::{to_bytes, Body},
    routing::post,
    Extension, Json, Router,
};
use nanosiem_core::auth::{ScopeSet, TokenClaims};
use std::collections::BTreeSet;
use std::sync::Mutex;
use tower::ServiceExt;
use uuid::Uuid;

#[derive(Default)]
struct Capture(Mutex<Vec<DeniedSourceAuditRecord>>);
impl DeniedSourceAuditSink for Capture {
    fn submit(&self, record: DeniedSourceAuditRecord) {
        self.0.lock().unwrap().push(record);
    }
}

fn restricted_member(user: u128) -> AuthContext {
    let mut auth = AuthContext::from_jwt(TokenClaims {
        iss: "iss".into(),
        aud: "aud".into(),
        sub: Uuid::from_u128(user),
        roles: vec!["analyst".into()],
        permissions: vec!["search:execute".into()],
        exp: i64::MAX,
        iat: 0,
        jti: Uuid::from_u128(99),
        purpose: "access".into(),
    });
    auth.denied_sources = ScopeSet::from_denied(BTreeSet::from([
        "insider_threat".to_string(),
        "payroll".to_string(),
    ]));
    auth
}

/// Stands in for a search handler: gates the caller's query exactly as
/// the services do (inline and in an `inherit`ed task) and returns the
/// gated text as the "result".
async fn fake_search(
    Extension(auth): Extension<AuthContext>,
    body: String,
) -> Json<serde_json::Value> {
    let deny = auth.denied_sources.deny_set().clone();
    let inline =
        nanosiem_core::search::query_processing::enforce_source_scope(&body, &deny).unwrap();
    let spawned = tokio::spawn(nanosiem_core::search::request_actor::inherit(async move {
        nanosiem_core::search::query_processing::enforce_source_scope(&body, &deny).unwrap()
    }))
    .await
    .unwrap();
    Json(serde_json::json!({ "rows": [], "inline": inline, "spawned": spawned }))
}

async fn call(
    audited: Option<Arc<dyn DeniedSourceAuditSink>>,
    auth: AuthContext,
    path: &str,
    query: &str,
) -> (u16, Vec<u8>) {
    let mut router = Router::new().route(path, post(fake_search));
    if let Some(sink) = audited {
        router = router.layer(axum::middleware::from_fn_with_state(
            sink,
            denied_source_audit_middleware,
        ));
    }
    let response = router
        .layer(Extension(auth))
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(path)
                .header("x-request-id", "req-nan3222")
                .body(Body::from(query.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status().as_u16();
    (
        status,
        to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap()
            .to_vec(),
    )
}

#[tokio::test]
async fn response_is_byte_identical_and_one_row_is_audited() {
    let capture = Arc::new(Capture::default());
    let sink: Arc<dyn DeniedSourceAuditSink> = capture.clone();
    let query = "metadata.log_source=insider_threat | stats count";
    let plain = call(None, restricted_member(0x3222_0001), "/api/search", query).await;
    let audited = call(
        Some(sink),
        restricted_member(0x3222_0001),
        "/api/search",
        query,
    )
    .await;
    assert_eq!(plain, audited, "the user response must not change");
    let rows = capture.0.lock().unwrap().clone();
    assert_eq!(
        rows.len(),
        1,
        "inline + spawned gate in one request = one rate-limited row"
    );
    assert_eq!(rows[0].labels, vec!["insider_threat".to_string()]);
    assert_eq!(rows[0].entry_point, "search");
    assert_eq!(rows[0].actor_id, Uuid::from_u128(0x3222_0001));
}

#[tokio::test]
async fn broad_search_and_unrestricted_callers_write_nothing() {
    let capture = Arc::new(Capture::default());
    let sink: Arc<dyn DeniedSourceAuditSink> = capture.clone();
    let plain = call(
        None,
        restricted_member(0x3222_0002),
        "/api/search/stream",
        "error | stats count",
    )
    .await;
    let audited = call(
        Some(sink.clone()),
        restricted_member(0x3222_0002),
        "/api/search/stream",
        "error | stats count",
    )
    .await;
    assert_eq!(plain, audited);
    let mut admin = restricted_member(0x3222_0003);
    admin.denied_sources = ScopeSet::default();
    call(
        Some(sink),
        admin,
        "/api/search",
        "metadata.log_source=insider_threat",
    )
    .await;
    assert!(capture.0.lock().unwrap().is_empty());
}

/// NAN-4928 review P1: a member with no per-source restrictions but without
/// `audit:view` probing the audit source is audited (the gate withholds the
/// rows through the composed scope); an `audit:view` holder is not.
#[tokio::test]
async fn implicit_audit_denial_is_audited() {
    let capture = Arc::new(Capture::default());
    let sink: Arc<dyn DeniedSourceAuditSink> = capture.clone();
    let mut member = restricted_member(0x4928_0001);
    member.denied_sources = ScopeSet::default();
    // The fake handler gates with the caller's per-source deny set; use the
    // composed scope like the real services do.
    async fn gated(Extension(auth): Extension<AuthContext>, body: String) -> Json<serde_json::Value> {
        let deny = crate::handlers::effective_scope(&auth).deny_set().clone();
        let gated = nanosiem_core::search::query_processing::enforce_source_scope(&body, &deny).unwrap();
        Json(serde_json::json!({ "rows": [], "gated": gated }))
    }
    async fn send(sink: Arc<dyn DeniedSourceAuditSink>, auth: AuthContext) {
        Router::new()
            .route("/api/search", post(gated))
            .layer(axum::middleware::from_fn_with_state(sink, denied_source_audit_middleware))
            .layer(Extension(auth))
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/api/search")
                    .body(Body::from("source_type=audit | stats count"))
                    .unwrap(),
            )
            .await
            .unwrap();
    }
    send(sink.clone(), member.clone()).await;
    let rows = capture.0.lock().unwrap().clone();
    assert_eq!(rows.len(), 1, "the implicit audit denial is audited");
    assert_eq!(rows[0].labels, vec!["audit".to_string()]);

    let mut auditor = member;
    auditor.claims.permissions.push("audit:view".into());
    auditor.claims.sub = Uuid::from_u128(0x4928_0002);
    send(sink, auditor).await;
    assert_eq!(capture.0.lock().unwrap().len(), 1, "an audit:view holder is not denied audit");
}
