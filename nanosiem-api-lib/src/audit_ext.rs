//! [`AuditExt`] — convenience trait for fire-and-forget audit-event emission
//! from request handlers.
//!
//! Lives in `nanosiem-api-lib` (not `nanosiem-api`) so that enterprise handler
//! modules in `nanosiem-enterprise` can import it directly. Before this lift
//! the trait sat in `nanosiem-api/src/handlers/mod.rs` and the OIDC
//! `OidcAppState::emit_audit` impl had to use a fully-qualified call as a
//! workaround. With the trait here, every per-module `*AppState` trait can
//! simply require `Self: AuditExt` (or expose `emit_audit` directly) and
//! handler code uses the natural `state.emit_audit(...)` method-call style.
//!
//! The implementation continues to live on `AppState` in `nanosiem-api`; this
//! crate just defines the trait surface.

use nanosiem_core::audit::AuditEvent;

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
}
