// SPDX-License-Identifier: AGPL-3.0-or-later

//! Playbooks API handlers.
//!
//! Endpoints for the main `playbooks` table (the SOC-managed library).
//! External repo syncing lives in [`crate::handlers::playbook_repositories`].

mod crud;
// NAN-473: dry-resolve preview endpoint (Review-phase wizard).
mod dry_resolve;
// NAN-445: Phase 4 — suggest + attach-to-case + finish-run endpoints.
mod suggest;
pub mod types;

pub use crud::*;
pub use dry_resolve::*;
pub use suggest::*;
pub use types::*;

// Note: `From<PlaybookError> for ApiError` lifted to nanosiem-api-lib in
// NAN-752 (orphan rule — `ApiError` lives there now).

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_playbooks,
        get_playbook,
        create_playbook,
        update_playbook,
        archive_playbook,
        // NAN-456: hard delete
        delete_playbook_permanent,
        fork_playbook,
        list_versions,
        list_runs,
        list_permissions,
        list_approvals,
        // NAN-445: suggest + runs
        suggest_for_rule,
        attach_to_case,
        finish_run,
        list_runs_for_case,
        // NAN-462: resolve run against its run_context snapshot
        resolve_run,
        // NAN-463: active-run per-step completion
        update_step_completion,
        // NAN-446: adaptive → library promote
        promote_playbook,
        // NAN-447: approval workflow + permissions
        submit_for_review,
        approve_playbook,
        reject_playbook,
        set_permission,
        delete_permission,
        // NAN-448: analytics
        get_analytics,
        // NAN-449: adaptive composition from case
        compose_adaptive_from_case,
        // NAN-473: dry-resolve preview against a recent alert
        dry_resolve,
    ),
    components(schemas(
        ListPlaybooksResponse,
        VersionsResponse,
        RunsResponse,
        PermissionsResponse,
        ApprovalsResponse,
        // NAN-445
        nanosiem_core::playbooks::PlaybookSuggestion,
        nanosiem_core::playbooks::AttachToCaseRequest,
        nanosiem_core::playbooks::FinishRunRequest,
        // NAN-447
        nanosiem_core::playbooks::SubmitForReviewRequest,
        nanosiem_core::playbooks::ApprovalResponseRequest,
        nanosiem_core::playbooks::SetPermissionRequest,
        // NAN-448
        nanosiem_core::playbooks::PlaybookAnalytics,
        // NAN-462
        nanosiem_core::playbooks::ResolvedRunResponse,
        // NAN-463
        nanosiem_core::playbooks::UpdateStepCompletionRequest,
        // NAN-473
        DryResolveRequest,
        DryResolveResponse,
        // NAN-474: typed sample_alert
        DryResolveSampleAlert,
    ))
)]
pub struct PlaybooksApiDoc;
