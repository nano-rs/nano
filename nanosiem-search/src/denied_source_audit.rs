// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-3222: install the denied-source audit scope around every authenticated
//! Search request and deliver its records.
//!
//! The scope (actor, tenant, the caller's per-source RBAC deny set, entry
//! point, request id) is a task-local the core source gate consults; see
//! `nanosiem_core::search::denied_source_audit`. Delivery never touches the
//! response: dedicated deployments enqueue onto the Search audit queue,
//! enterprise-shared deployments append through a signed tenant transaction
//! in a spawned task.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::Next;
use axum::response::Response;
use nanosiem_core::audit::ClientContext;
use nanosiem_core::search::denied_source_audit::{
    with_scope, DeniedSourceAuditRecord, DeniedSourceAuditScope, DeniedSourceAuditSink,
};

use crate::{AuthContext, RequestId, SearchState};

/// Shared appends compete with tenant lookups for the small RLS runtime
/// pool; never hold more than this many at once (excess is dropped loudly).
static SHARED_APPENDS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);

/// Routes Search's denied-source records to the right audit ledger.
pub struct SearchDeniedSourceAuditSink {
    state: SearchState,
}

impl SearchDeniedSourceAuditSink {
    pub fn new(state: SearchState) -> Arc<dyn DeniedSourceAuditSink> {
        Arc::new(Self { state })
    }
}

impl DeniedSourceAuditSink for SearchDeniedSourceAuditSink {
    fn submit(&self, record: DeniedSourceAuditRecord) {
        let event = record.to_audit_event();
        let Some(tenant) = record.tenant.clone() else {
            self.state.emit_audit(event);
            return;
        };
        #[cfg(feature = "enterprise")]
        if let Some(runtime) = self.state.tenant_lookup_runtime.clone() {
            let Ok(permit) = SHARED_APPENDS.try_acquire() else {
                ::metrics::counter!("nanosiem_search_denied_source_audit_dropped_total", "reason" => "saturated").increment(1);
                tracing::error!(event = %serde_json::to_string(&event).unwrap_or_default(), "denied-source audit dropped: tenant audit appends saturated");
                return;
            };
            let actor = record.actor_id;
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(error) = runtime
                    .tenant_authorization_audit()
                    .record_source_scope_denied(&tenant, actor, &event)
                    .await
                {
                    ::metrics::counter!("nanosiem_search_denied_source_audit_dropped_total", "reason" => "append_failed").increment(1);
                    tracing::error!(%error, event = %serde_json::to_string(&event).unwrap_or_default(), "denied-source tenant audit could not commit");
                }
            });
            return;
        }
        let _ = (&SHARED_APPENDS, tenant);
        ::metrics::counter!("nanosiem_search_denied_source_audit_dropped_total", "reason" => "no_tenant_runtime").increment(1);
        tracing::error!(event = %serde_json::to_string(&event).unwrap_or_default(), "denied-source audit dropped: no tenant RLS runtime");
    }
}

/// Build the request's scope from the authenticated context. `None` for an
/// unrestricted caller (nothing can be withheld, nothing to audit).
pub fn scope_for_request(
    request: &Request,
    sink: &Arc<dyn DeniedSourceAuditSink>,
) -> Option<DeniedSourceAuditScope> {
    let auth = request.extensions().get::<AuthContext>()?;
    let denied = auth.denied_sources.deny_set();
    if denied.is_empty() {
        return None;
    }
    let tenant = auth
        .shared_request_authority
        .as_ref()
        .map(|authority| authority.tenant.clone());
    // Shared: the signed tenant transaction is opened as the member (an
    // automation key acts as its owner). Dedicated: the key owner when there
    // is one, with the key itself named on the event.
    let (actor, api_key_id) = match tenant {
        Some(_) => (auth.ownership_user_id()?, None),
        None => (
            auth.ownership_user_id().unwrap_or(auth.claims.sub),
            auth.api_key_id,
        ),
    };
    let connect_info = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|value| value.0);
    let client = ClientContext::new(
        crate::middleware::extract_ip_address(request, connect_info.as_ref()),
        request
            .headers()
            .get(axum::http::header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.chars().take(512).collect()),
    );
    DeniedSourceAuditScope::new(
        tenant,
        actor,
        api_key_id,
        denied,
        request.uri().path(),
        request
            .extensions()
            .get::<RequestId>()
            .map(|id| id.0.as_str()),
        client,
        sink.clone(),
    )
}

/// Layer inside `auth_middleware` (it needs `AuthContext`).
pub async fn denied_source_audit_middleware(
    State(sink): State<Arc<dyn DeniedSourceAuditSink>>,
    request: Request,
    next: Next,
) -> Response {
    match scope_for_request(&request, &sink) {
        Some(scope) => with_scope(Arc::new(scope), next.run(request)).await,
        None => next.run(request).await,
    }
}

#[cfg(test)]
mod tests {
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
        let inline = nanosiem_core::search::query_processing::enforce_source_scope_with_field(
            &body,
            &deny,
            "metadata.log_source",
        )
        .unwrap();
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
        assert!(rows[0].tenant.is_none());
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
}
