// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-3222: install the denied-source audit scope around every authenticated
//! Search request and deliver its records to the Search audit queue.
//!
//! The scope (actor, the caller's effective deny set, entry point,
//! request id) is a task-local the core source gate consults; see
//! `nanosiem_core::search::denied_source_audit`. Delivery never touches the
//! response.

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

/// Routes Search's denied-source records to the Search audit queue.
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
        self.state.emit_audit(record.to_audit_event());
    }
}

/// Build the request's scope from the authenticated context. `None` for an
/// unrestricted caller (nothing can be withheld, nothing to audit).
pub fn scope_for_request(
    request: &Request,
    sink: &Arc<dyn DeniedSourceAuditSink>,
) -> Option<DeniedSourceAuditScope> {
    let auth = request.extensions().get::<AuthContext>()?;
    // NAN-4928 review P1: the SAME composed scope the query gate enforces,
    // including the implicit `audit` denial of a caller without
    // `audit:view` (so probing the audit source is audited too).
    let scope = crate::handlers::effective_scope(auth);
    let denied = scope.deny_set();
    if denied.is_empty() {
        return None;
    }
    // The key owner when there is one, with the key itself named on the event.
    let actor = auth.ownership_user_id().unwrap_or(auth.claims.sub);
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
        actor,
        auth.api_key_id,
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
#[path = "denied_source_audit_tests.rs"]
mod tests;
