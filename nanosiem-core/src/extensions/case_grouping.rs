// SPDX-License-Identifier: AGPL-3.0-or-later

//! `CaseGroupingHook` — extension point for grouping detection signals into cases.
//!
//! Open core does not have cases. The enterprise crate provides a real impl
//! that wraps `cases::CaseService::process_alert_for_grouping` and returns the
//! four fields the detection engine actually reads (case id, case number,
//! is_new_case, notebook_id).

use async_trait::async_trait;
use uuid::Uuid;

use crate::extensions::ExtensionError;
use crate::models::Alert;

/// Case visibility / routing settings inherited from the firing detection rule.
/// Mirrors enterprise `cases::CasePermissionSettings` but lives in core so the
/// detection engine can build it without depending on the cases module.
#[derive(Debug, Clone, Default)]
pub struct AlertCasePermissions {
    /// "public" | "group" | "private"
    pub visibility: String,
    pub group_ids: Option<Vec<Uuid>>,
    pub assigned_group: Option<Uuid>,
    /// "none" | "specific" | "adaptive"
    pub playbook_selector_mode: String,
    pub playbook_id: Option<Uuid>,
}

/// Outcome of grouping an alert into a case. Only fields the detection engine
/// reads are exposed.
#[derive(Debug, Clone)]
pub struct AlertGrouped {
    pub case_id: Uuid,
    pub case_number: i64,
    pub is_new_case: bool,
    pub notebook_id: Option<Uuid>,
}

#[async_trait]
pub trait CaseGroupingHook: Send + Sync {
    /// Group a freshly-created alert into a case. Returns `Ok(None)` when
    /// grouping is unavailable in the current build (open core).
    async fn group_alert(
        &self,
        alert: &Alert,
        rule_name: Option<&str>,
        permissions: Option<AlertCasePermissions>,
    ) -> Result<Option<AlertGrouped>, ExtensionError>;
}

/// No-op hook used by open-core builds.
pub struct NoopCaseGroupingHook;

#[async_trait]
impl CaseGroupingHook for NoopCaseGroupingHook {
    async fn group_alert(
        &self,
        _alert: &Alert,
        _rule_name: Option<&str>,
        _permissions: Option<AlertCasePermissions>,
    ) -> Result<Option<AlertGrouped>, ExtensionError> {
        Ok(None)
    }
}
