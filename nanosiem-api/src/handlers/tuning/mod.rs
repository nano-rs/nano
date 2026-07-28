// SPDX-License-Identifier: AGPL-3.0-or-later

//! AI Detection Auto-Tuning API Handlers
//!
//! Split into focused submodules by domain:
//! - `types` — request/response types
//! - `baselines` — baseline statistics, metrics, threshold breaches
//! - `proposals` — proposal listing, approval, rejection
//! - `versions` — version history, activation, revert
//! - `logs` — tuning audit logs
//! - `notifications` — tuning notification management
//! - `settings` — per-rule tuning configuration

mod baselines;
mod logs;
mod notifications;
mod proposals;
mod settings;
mod types;
mod versions;

pub use baselines::*;
pub use logs::*;
pub use notifications::*;
pub use proposals::*;
pub use settings::*;
pub use types::*;
pub use versions::*;

// =============================================================================
// SHARED HELPERS
// =============================================================================

/// NAN-2085 / NAN-2088: the reader's effective per-source deny scope for AI
/// tuning artifacts, from the canonical
/// `AuthContext::effective_viewer_scope()`.
///
/// Every route that can surface source-derived tuning data resolves the scope
/// through this single helper: metrics, baselines, breach history, proposal
/// list/detail/mutations, and logs that nest a proposal. That keeps current
/// source restrictions authoritative for every persisted artifact.
/// Background/system callers — the orchestrator, PR recovery, and scheduler —
/// instead use `TuningScope::system()`; their execution scope is never a
/// viewer's authorization.
///
/// NAN-2219: `TuningScope` IS `ArtifactScope`, and tuning proposals/baselines/
/// breaches are gated on `source_types_complete`. `from_scope` therefore reads
/// the scope's per-source RBAC half only. Folding the `audit:view` gate in here
/// made every non-Admin "restricted" and blanked `/api/tuning/*` on tenants
/// with no source scoping configured, because that column ships `DEFAULT FALSE`
/// and was never backfilled.
pub(crate) fn effective_tuning_scope(
    auth: &crate::middleware::AuthContext,
) -> nanosiem_core::tuning::scope::TuningScope {
    nanosiem_core::tuning::scope::TuningScope::from_scope(&auth.effective_viewer_scope())
}

// =============================================================================
// OPENAPI DOCUMENTATION
// =============================================================================

/// OpenAPI documentation for tuning endpoints
pub struct TuningApiDoc;

impl utoipa::OpenApi for TuningApiDoc {
    fn openapi() -> utoipa::openapi::OpenApi {
        use utoipa::OpenApi;

        #[derive(OpenApi)]
        #[openapi(
            paths(
                get_baseline,
                get_metrics,
                get_breaches,
                list_proposals,
                get_proposal,
                approve_proposal,
                reject_proposal,
                list_versions,
                get_version,
                activate_version,
                list_logs,
                get_log,
                revert_tuning,
                list_tuning_notifications,
                mark_tuning_notification_read,
                mark_all_tuning_notifications_read,
                get_tuning_settings,
                update_tuning_settings,
                get_rule_versions,
                revert_to_version,
            ),
            components(schemas(
                ApproveProposalRequest,
                RejectProposalRequest,
                RevertRequest,
                MarkReadRequest,
                TuningSettings,
                ApprovalOutcome,
                ApprovalResponse,
                RejectionResponse,
                RuleVersionResponse,
            )),
            tags(
                (name = "tuning", description = "AI Detection Auto-Tuning API")
            )
        )]
        struct ApiDoc;

        ApiDoc::openapi()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_and_rollback_routes_publish_complete_failure_contracts() {
        let document = serde_json::to_value(<TuningApiDoc as utoipa::OpenApi>::openapi()).unwrap();
        let expected = [
            (
                "/api/tuning/proposals/{id}/approve",
                &["200", "403", "404", "409", "422", "500"][..],
            ),
            (
                "/api/tuning/versions/{rule_id}/{version_id}/activate",
                &["200", "403", "404", "409", "422", "503", "500"][..],
            ),
            (
                "/api/rules/{id}/versions/{version_id}/revert",
                &["200", "403", "404", "409", "422", "503", "500"][..],
            ),
            (
                "/api/tuning/logs/{id}/revert",
                &["200", "400", "403", "404", "409", "422", "503", "500"][..],
            ),
        ];

        for (path, statuses) in expected {
            let responses = &document["paths"][path]["post"]["responses"];
            assert!(responses.is_object(), "missing POST operation for {path}");
            for status in statuses {
                assert!(
                    responses.get(status).is_some(),
                    "{path} does not document response {status}"
                );
            }
        }
    }
}
