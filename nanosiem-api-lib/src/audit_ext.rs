// SPDX-License-Identifier: AGPL-3.0-or-later

//! [`AuditExt`] — convenience trait for fire-and-forget audit-event emission
//! from request handlers.
//!
//! Lives in `nanosiem-api-lib` (not `nanosiem-api`) so that enterprise handler
//! modules in the enterprise crate can import it directly. Before this lift
//! the trait sat in `nanosiem-api/src/handlers/mod.rs` and the OIDC
//! `OidcAppState::emit_audit` impl had to use a fully-qualified call as a
//! workaround. With the trait here, every per-module `*AppState` trait can
//! simply require `Self: AuditExt` (or expose `emit_audit` directly) and
//! handler code uses the natural `state.emit_audit(...)` method-call style.
//!
//! The implementation continues to live on `AppState` in `nanosiem-api`; this
//! crate just defines the trait surface.

use nanosiem_core::audit::AuditEvent;
use nanosiem_core::auth::TrustedTenantContext;

/// Extension trait for convenient audit event emission from handlers.
///
/// Usage:
/// ```ignore
/// state.emit_audit(
///     AuditEvent::builder(AuditSource::Detection, audit_actions::RULE_CREATED)
///         .actor(Some(auth.user_id()), None) // Actor name omitted (JWT no longer contains PII)
///         .resource("detection_rule", Some(rule.id), Some(rule.name.clone()))
///         .client_context(&client)
///         .build()
/// );
/// ```
pub trait AuditExt {
    /// Emit an audit event (fire-and-forget, non-blocking).
    ///
    /// Implementations should be cheap — typically a `tokio::spawn` of the
    /// async write — so the calling handler can return its response without
    /// waiting on the audit pipeline. When no audit emitter is configured
    /// (open-core / no-ClickHouse mode), the event drops on the floor.
    fn emit_audit(&self, event: AuditEvent);

    /// Emit auth events that `actor` completed in `tenant` (fire-and-forget).
    ///
    /// NAN-3790: on the hosted shared deployment `emit_audit` cannot persist
    /// anything (the shared emitter refuses tenantless writes), so auth flows
    /// that know their tenant and verified account call this instead. The
    /// `nanosiem-api` implementation writes the events together in one signed
    /// tenant + actor transaction there; elsewhere, and by default, each
    /// event goes through [`Self::emit_audit`] unchanged.
    fn emit_tenant_auth_audit(
        &self,
        tenant: TrustedTenantContext,
        actor: uuid::Uuid,
        events: Vec<AuditEvent>,
    ) {
        let _ = (tenant, actor);
        for event in events {
            self.emit_audit(event);
        }
    }
}
