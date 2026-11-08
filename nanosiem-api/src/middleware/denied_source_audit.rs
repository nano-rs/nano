// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-3222: the API-side half of the denied-source search audit.
//!
//! The API runs nPL on behalf of members too (dashboard panels, hunts,
//! prevalence / entity lookups, pivt search tools, reports run now). Every
//! one of those goes through the core source gate, which consults the
//! task-local scope this layer installs. Delivery never touches the
//! response: records go to the platform audit pipeline.
//!
//! Layer placement: inside `auth_middleware` (needs `AuthContext`), next to
//! `audit_authz_failures`.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use nanosiem_core::audit::ClientContext;
use nanosiem_core::search::denied_source_audit::{
    with_scope, DeniedSourceAuditRecord, DeniedSourceAuditScope, DeniedSourceAuditSink,
};

use crate::handlers::AuditExt;
use crate::middleware::{AuthContext, RequestId};
use crate::state::AppState;

struct ApiDeniedSourceAuditSink {
    state: AppState,
}

impl DeniedSourceAuditSink for ApiDeniedSourceAuditSink {
    fn submit(&self, record: DeniedSourceAuditRecord) {
        self.state.emit_audit(record.to_audit_event());
    }
}

/// The sink the router hands to [`denied_source_audit_middleware`].
pub fn sink(state: AppState) -> Arc<dyn DeniedSourceAuditSink> {
    Arc::new(ApiDeniedSourceAuditSink { state })
}

fn scope_for_request(
    request: &Request,
    sink: &Arc<dyn DeniedSourceAuditSink>,
) -> Option<DeniedSourceAuditScope> {
    let auth = request.extensions().get::<AuthContext>()?;
    // NAN-4928 review P1: the same composed scope the query gate enforces,
    // including the implicit `audit` denial without `audit:view`.
    let scope = auth.effective_viewer_scope();
    let denied = scope.deny_set();
    if denied.is_empty() {
        return None;
    }
    // `user_id()` is the session user or the API key's owner (audit
    // attribution); the key itself is named on the event.
    DeniedSourceAuditScope::new(
        auth.user_id(),
        auth.api_key_id,
        denied,
        request.uri().path(),
        request
            .extensions()
            .get::<RequestId>()
            .map(|id| id.0.as_str()),
        request
            .extensions()
            .get::<ClientContext>()
            .cloned()
            .unwrap_or_default(),
        sink.clone(),
    )
}

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
