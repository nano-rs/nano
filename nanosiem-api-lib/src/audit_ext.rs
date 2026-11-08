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

    /// Emit an audit event, and for a SECURITY-CRITICAL event (see
    /// [`nanosiem_core::audit::is_security_critical`]) do not return until it is
    /// durably recorded (NAN-4954).
    ///
    /// The production implementation awaits the PostgreSQL outbox write before
    /// returning and detaches only the ClickHouse delivery, so a process crash
    /// after the handler responds can no longer lose the event. Routine events
    /// stay fire-and-forget. Handlers emitting a security-critical action must
    /// `.await` this instead of calling [`Self::emit_audit`] (enforced by the
    /// `audit_durability_callsites_tests` source guard).
    ///
    /// The default implementation (test states) is the fire-and-forget path.
    fn emit_audit_durable(&self, event: AuditEvent) -> impl std::future::Future<Output = ()> + Send {
        self.emit_audit(event);
        std::future::ready(())
    }

    /// Hand an event that the caller ALREADY recorded in the PostgreSQL outbox
    /// inside its own transaction (`SecurityAuditOutbox::enqueue_tx`) to the
    /// ClickHouse delivery path, detached. The default (test states) falls back
    /// to [`Self::emit_audit`].
    fn deliver_recorded_audit(&self, event: AuditEvent) {
        self.emit_audit(event);
    }
}
