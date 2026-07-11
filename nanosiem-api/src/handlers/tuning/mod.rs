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
