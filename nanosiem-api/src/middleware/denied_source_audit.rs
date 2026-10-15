// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-3222: the API-side half of the denied-source search audit.
//!
//! The API runs nPL on behalf of members too (dashboard panels, hunts,
//! prevalence / entity lookups, pivt search tools, reports run now). Every
//! one of those goes through the core source gate, which consults the
//! task-local scope this layer installs. Delivery never touches the
//! response: dedicated deployments use the platform audit pipeline,
//! enterprise-shared deployments append through a signed tenant transaction
//! in a spawned task.
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

/// Shared appends compete with other tenant ledgers for the RLS runtime
/// pool; never hold more than this many at once (excess is dropped loudly).
#[cfg(feature = "enterprise")]
static SHARED_APPENDS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);

struct ApiDeniedSourceAuditSink {
    state: AppState,
}

impl DeniedSourceAuditSink for ApiDeniedSourceAuditSink {
    fn submit(&self, record: DeniedSourceAuditRecord) {
        let event = record.to_audit_event();
        let Some(tenant) = record.tenant.clone() else {
            self.state.emit_audit(event);
            return;
        };
        #[cfg(feature = "enterprise")]
        if let Some(runtime) = self.state.tenant_ai_rls_runtime.clone() {
            let Ok(permit) = SHARED_APPENDS.try_acquire() else {
                ::metrics::counter!("nanosiem_api_denied_source_audit_dropped_total", "reason" => "saturated").increment(1);
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
                    ::metrics::counter!("nanosiem_api_denied_source_audit_dropped_total", "reason" => "append_failed").increment(1);
                    tracing::error!(%error, event = %serde_json::to_string(&event).unwrap_or_default(), "denied-source tenant audit could not commit");
                }
            });
            return;
        }
        let _ = tenant;
        ::metrics::counter!("nanosiem_api_denied_source_audit_dropped_total", "reason" => "no_tenant_runtime").increment(1);
        tracing::error!(event = %serde_json::to_string(&event).unwrap_or_default(), "denied-source audit dropped: no tenant RLS runtime");
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
    let denied = auth.denied_sources.deny_set();
    if denied.is_empty() {
        return None;
    }
    let tenant = request
        .extensions()
        .get::<nanosiem_core::auth::TrustedTenantContext>()
        .cloned();
    // `user_id()` is the session user or the API key's owner (audit
    // attribution). The shared append is signed as that member, so the key
    // is named only on dedicated events.
    let api_key_id = if tenant.is_some() {
        None
    } else {
        auth.api_key_id
    };
    DeniedSourceAuditScope::new(
        tenant,
        auth.user_id(),
        api_key_id,
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
