// SPDX-License-Identifier: AGPL-3.0-or-later

//! `ShadowInvestigationHook` — extension point for autonomous case investigation.
//!
//! When a new case is created in enterprise builds, shadow investigation kicks
//! off: entity extraction → structured queries → autonomous hunting → narrative
//! synthesis. Open core does not have cases, so this hook is a no-op there.
//!
//! Currently held in detection services as
//! `Option<Arc<ShadowInvestigationService>>` in `signal_processor.rs`,
//! `service/mod.rs`, `service/alerts.rs`, and `realtime/evaluator.rs`. Phase 2
//! replaces those with `Arc<dyn ShadowInvestigationHook>`.

use async_trait::async_trait;
use uuid::Uuid;

use crate::extensions::ExtensionError;
use crate::models::Alert;

#[async_trait]
pub trait ShadowInvestigationHook: Send + Sync {
    /// Invoked when a new case is created from an alert. The hook decides
    /// internally whether to spawn an investigation (settings gate, AI credit
    /// gate, concurrency cap). Returns immediately — the actual investigation
    /// runs in a detached task. Errors here are advisory; call sites log and
    /// continue.
    async fn on_case_created(
        &self,
        case_id: Uuid,
        alert: &Alert,
        notebook_id: Option<Uuid>,
    ) -> Result<(), ExtensionError>;

    /// Invoked when one or more alerts are added to an EXISTING case (manual
    /// add via API, or auto-grouping). The implementation is expected to
    /// coalesce bursts (multiple adds within a short window become one
    /// investigation) and is gated by the same settings/credit checks as
    /// `on_case_created`. Default impl is a no-op so open-core builds and
    /// other hook impls don't have to know about this.
    async fn on_alerts_added(
        &self,
        _case_id: Uuid,
        _new_alert_ids: Vec<Uuid>,
    ) -> Result<(), ExtensionError> {
        Ok(())
    }
}

/// No-op hook used by open-core builds.
pub struct NoopShadowInvestigationHook;

#[async_trait]
impl ShadowInvestigationHook for NoopShadowInvestigationHook {
    async fn on_case_created(
        &self,
        _case_id: Uuid,
        _alert: &Alert,
        _notebook_id: Option<Uuid>,
    ) -> Result<(), ExtensionError> {
        Ok(())
    }
}
