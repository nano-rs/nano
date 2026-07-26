// SPDX-License-Identifier: AGPL-3.0-or-later

//! SIEM Health Check API handlers
//!
//! Provides endpoints for listing, retrieving, and triggering SIEM health check reports.
//! Reports are AI-driven analyses of ingestion, parsing, and detection quality.

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::AuthContext;
use crate::state::AppState;
use nanosiem_core::auth::ScopeSet;
use nanosiem_core::siem_health::types::CollectedMetrics;
use nanosiem_core::siem_health::{SiemHealthReport, SiemHealthReportSummary, SiemHealthRepository};

/// NAN-1801: post-fetch source-scope filter for precomputed health reports.
///
/// Scheduled health reports are generated with an unrestricted SYSTEM scope.
/// Their typed source partitions are therefore re-filtered against the reader's
/// current effective scope (per-source RBAC ∪ the `audit` gate) before the
/// report leaves the API. This also covers grant revocation after generation.
///
/// Filtered paths (every `source_type`-keyed vector in `CollectedMetrics`):
/// - `ingestion.source_volumes`      (`SourceVolumeMetric.source_type`)
/// - `ingestion.silent_sources`      (bare `Vec<String>` of source types)
/// - `parsing.field_coverage`        (`FieldCoverageMetric.source_type`)
/// - `parsing.high_ext_sources`      (`ExtUsageMetric.source_type`)
/// - `enrichment.per_source_coverage` (`EnrichmentCoverageMetric.source_type`)
///
/// Exact ingestion totals are recomputed from the retained source-volume rows.
/// Other cluster-wide/global fields (insert-integrity probes, per-column
/// lowercase violations, rule/alert stats, scores) have no complete persisted
/// source partition and remain unchanged for NAN-2089's narrative/score policy.
///
/// An EMPTY deny set returns immediately — the report stays byte-identical
/// for unrestricted viewers. Comparison is lowercase-on-both-sides, mirroring
/// the F1 SQL predicate builder. A restricted viewer gets no metrics if the
/// stored JSON cannot be deserialized into the typed partition contract.
fn filter_report_for_viewer(report: &mut SiemHealthReport, scope: &ScopeSet) {
    if !scope.is_restricted() {
        return;
    }

    let Ok(mut metrics) = serde_json::from_value::<CollectedMetrics>(report.metrics.clone()) else {
        report.metrics = serde_json::json!({});
        return;
    };
    metrics.retain_source_partitions(scope);
    report.metrics = serde_json::to_value(metrics).unwrap_or_else(|_| serde_json::json!({}));
}

/// Query parameters for listing health reports
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ListReportsParams {
    /// Maximum number of reports to return (default: 20, max: 100)
    #[serde(default = "default_limit")]
    pub limit: i64,
    /// Offset for pagination (default: 0)
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    20
}

/// Paginated list of health report summaries
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ListReportsResponse {
    pub reports: Vec<SiemHealthReportSummary>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Response from triggering a health check
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TriggerResponse {
    /// The ID of the newly created report, if successful
    pub report_id: Option<Uuid>,
    /// Human-readable status message
    pub message: String,
}

/// List SIEM health report summaries (paginated)
///
/// Returns a paginated list of health report summaries, ordered by most recent first.
/// Summaries omit the full metrics and dimension details for efficiency.
///
/// Requires the `settings:system` permission (NAN-1801 — health reports carry
/// fleet-wide per-source telemetry).
///
/// GET /api/siem-health/reports
#[utoipa::path(
    get,
    path = "/api/siem-health/reports",
    tag = "siem_health",
    params(ListReportsParams),
    responses(
        (status = 200, description = "Paginated list of health report summaries", body = ListReportsResponse),
        (status = 403, description = "Insufficient permissions"),
    ),
    security(("api_key" = []))
)]
pub async fn list_reports(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(params): Query<ListReportsParams>,
) -> Result<Json<ListReportsResponse>, ApiError> {
    crate::middleware::ensure_permission(&auth, nanosiem_core::auth::permissions::SETTINGS_SYSTEM)?;

    let limit = params.limit.clamp(1, 100);
    let offset = params.offset.max(0);

    let repo = SiemHealthRepository::new(state.pool.clone());
    let (reports, total) = repo
        .list_summaries(limit, offset)
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    Ok(Json(ListReportsResponse {
        reports,
        total,
        limit,
        offset,
    }))
}

/// Get the most recent SIEM health report
///
/// Returns the latest full health report including metrics, recommendations,
/// and dimension details. Returns 404 if no reports exist yet.
///
/// Requires the `settings:system` permission; per-source telemetry inside the
/// report is filtered to the viewer's source scope (NAN-1801).
///
/// GET /api/siem-health/reports/latest
#[utoipa::path(
    get,
    path = "/api/siem-health/reports/latest",
    tag = "siem_health",
    responses(
        (status = 200, description = "The most recent health report", body = SiemHealthReport),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "No health reports exist yet"),
    ),
    security(("api_key" = []))
)]
pub async fn get_latest_report(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<SiemHealthReport>, ApiError> {
    crate::middleware::ensure_permission(&auth, nanosiem_core::auth::permissions::SETTINGS_SYSTEM)?;

    let repo = SiemHealthRepository::new(state.pool.clone());
    let mut report = repo
        .get_latest()
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?
        .ok_or_else(|| ApiError::NotFound("No health reports exist yet".to_string()))?;

    filter_report_for_viewer(&mut report, &auth.effective_viewer_scope());

    Ok(Json(report))
}

/// Get a specific SIEM health report by ID
///
/// Returns the full health report including metrics, recommendations,
/// and dimension details.
///
/// Requires the `settings:system` permission; per-source telemetry inside the
/// report is filtered to the viewer's source scope (NAN-1801).
///
/// GET /api/siem-health/reports/{id}
#[utoipa::path(
    get,
    path = "/api/siem-health/reports/{id}",
    tag = "siem_health",
    params(
        ("id" = Uuid, Path, description = "Report UUID"),
    ),
    responses(
        (status = 200, description = "The requested health report", body = SiemHealthReport),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "Report not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_report(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<SiemHealthReport>, ApiError> {
    crate::middleware::ensure_permission(&auth, nanosiem_core::auth::permissions::SETTINGS_SYSTEM)?;

    let repo = SiemHealthRepository::new(state.pool.clone());
    let mut report = repo.get_by_id(id).await.map_err(|e| match e {
        nanosiem_core::siem_health::SiemHealthRepositoryError::NotFound(msg) => {
            ApiError::NotFound(msg)
        }
        other => ApiError::DatabaseError(other.to_string()),
    })?;

    filter_report_for_viewer(&mut report, &auth.effective_viewer_scope());

    Ok(Json(report))
}

/// Manually trigger a SIEM health check (admin only)
///
/// Runs the full health check pipeline: collect metrics from ClickHouse and PostgreSQL,
/// analyze with AI (or fallback scoring), and store the report. This is the same pipeline
/// that runs automatically every 12 hours.
///
/// Requires the `settings:system` permission.
///
/// POST /api/siem-health/reports/trigger
#[utoipa::path(
    post,
    path = "/api/siem-health/reports/trigger",
    tag = "siem_health",
    responses(
        (status = 200, description = "Health check triggered successfully", body = TriggerResponse),
        (status = 403, description = "Insufficient permissions"),
    ),
    security(("api_key" = []))
)]
pub async fn trigger_health_check(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<TriggerResponse>, ApiError> {
    // Require admin permission
    crate::middleware::ensure_permission(&auth, nanosiem_core::auth::permissions::SETTINGS_SYSTEM)?;

    let repo = SiemHealthRepository::new(state.pool.clone());

    let ch_client = state.dual_pool().clickhouse().clone();
    let is_clustered = state.dual_pool().table_names().is_clustered();

    // Construct the SiemHealthAiAnalyzer for this trigger. Enterprise builds
    // wrap the live meloD AI client; open-core builds use the noop analyzer,
    // which returns `Unavailable` and lets the scheduler fall through to the
    // rules-based `analyzer::fallback_report`.
    #[cfg(not(feature = "enterprise"))]
    use nanosiem_core::extensions::NoopSiemHealthAiAnalyzer;
    use nanosiem_core::extensions::SiemHealthAiAnalyzer;
    use std::sync::Arc;

    #[cfg(feature = "enterprise")]
    let ai_analyzer: Arc<dyn SiemHealthAiAnalyzer> = {
        use nanosiem_core::extensions::{AiClient, NoopAiClient};
        let ai_client: Arc<dyn AiClient> = state
            .melod_service
            .read()
            .await
            .as_ref()
            .map(|s| s.ai_client_arc())
            .map(|shared| {
                Arc::new(nanosiem_enterprise::melod::MelodAiClientBridge::new(shared))
                    as Arc<dyn AiClient>
            })
            .unwrap_or_else(|| Arc::new(NoopAiClient));
        Arc::new(nanosiem_enterprise::siem_health::AiPoweredSiemHealthAnalyzer::new(ai_client))
    };
    #[cfg(not(feature = "enterprise"))]
    let ai_analyzer: Arc<dyn SiemHealthAiAnalyzer> = Arc::new(NoopSiemHealthAiAnalyzer);

    let collection_scope = auth.effective_viewer_scope();
    let report_id = nanosiem_core::siem_health::scheduler::run_health_check_with_trigger(
        &state.pool,
        &ch_client,
        is_clustered,
        ai_analyzer.as_ref(),
        &repo,
        &collection_scope,
        Some(auth.user_id()),
    )
    .await;

    match report_id {
        Some(id) => Ok(Json(TriggerResponse {
            report_id: Some(id),
            message: "Health check completed successfully".to_string(),
        })),
        None => Err(ApiError::InternalError(
            "Health check failed to produce a report".to_string(),
        )),
    }
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(list_reports, get_latest_report, get_report, trigger_health_check),
    components(schemas(
        ListReportsResponse,
        TriggerResponse,
        SiemHealthReport,
        SiemHealthReportSummary,
    ))
)]
pub struct SiemHealthApiDoc;

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chrono::Utc;
    use nanosiem_core::siem_health::types::InsertIntegrityMetrics;
    use serde_json::{json, Value};

    use super::*;

    fn scope(denied: &[&str]) -> ScopeSet {
        ScopeSet::from_denied(
            denied
                .iter()
                .map(|source_type| source_type.to_string())
                .collect::<BTreeSet<_>>(),
        )
    }

    fn metrics_fixture() -> Value {
        json!({
            "ingestion": {
                "source_volumes": [
                    {
                        "source_type": "apache",
                        "count_24h": 10,
                        "count_prior_24h": 7,
                        "change_pct": 42.8
                    },
                    {
                        "source_type": "Insider_Threat",
                        "count_24h": 3,
                        "count_prior_24h": 2,
                        "change_pct": 50.0
                    },
                    {
                        "source_type": "",
                        "count_24h": 99,
                        "count_prior_24h": 99,
                        "change_pct": 0.0
                    }
                ],
                "total_events_24h": 112,
                "total_events_prior_24h": 108,
                "silent_sources": ["apache", "INSIDER_THREAT", ""],
                "insert_integrity": serde_json::to_value(InsertIntegrityMetrics::default())
                    .expect("serialize default integrity metrics")
            },
            "parsing": {
                "field_coverage": [
                    {
                        "source_type": "apache",
                        "total_events": 10,
                        "src_ip_filled_pct": 90.0,
                        "user_filled_pct": 80.0,
                        "event_type_filled_pct": 100.0,
                        "message_filled_pct": 100.0
                    },
                    {
                        "source_type": "insider_threat",
                        "total_events": 3,
                        "src_ip_filled_pct": 1.0,
                        "user_filled_pct": 1.0,
                        "event_type_filled_pct": 1.0,
                        "message_filled_pct": 1.0
                    }
                ],
                "high_ext_sources": [
                    {
                        "source_type": "insider_threat",
                        "total_events": 3,
                        "ext_usage_pct": 99.0
                    }
                ],
                "lowercase_invariant_violations": []
            },
            "enrichment": {
                "total_events_24h": 13,
                "geoip_fill_pct": 50.0,
                "asn_fill_pct": 50.0,
                "ioc_hit_pct": 1.0,
                "identity_fill_pct": 10.0,
                "identity_fill_prior_pct": 9.0,
                "per_source_coverage": [
                    {
                        "source_type": "apache",
                        "total_events": 10,
                        "geoip_pct": 50.0,
                        "ioc_pct": 1.0,
                        "identity_pct": 10.0
                    },
                    {
                        "source_type": "insider_threat",
                        "total_events": 3,
                        "geoip_pct": 0.0,
                        "ioc_pct": 0.0,
                        "identity_pct": 0.0
                    }
                ],
                "providers": []
            },
            "detection": {
                "total_enabled_rules": 1,
                "total_matches_24h": 2,
                "rules_by_mode": [],
                "stale_rules": [],
                "noisy_rules": [],
                "alerts_24h_by_severity": []
            },
            "alerting": {
                "total_alerts_24h": 2,
                "total_alerts_prior_24h": 1,
                "by_status": [],
                "mean_mtta_minutes": null,
                "active_webhooks": 0,
                "webhook_deliveries_24h": 0,
                "webhook_success_pct": null,
                "active_routing_rules": 0
            },
            "collected_at": Utc::now()
        })
    }

    fn report(metrics: Value) -> SiemHealthReport {
        SiemHealthReport {
            id: Uuid::now_v7(),
            overall_score: 75,
            overall_status: "warning".to_string(),
            ingestion_score: 75,
            parsing_score: 75,
            detection_score: 75,
            enrichment_score: Some(75),
            alerting_score: Some(75),
            summary: "NAN-2089 owns scoped narrative".to_string(),
            metrics,
            recommendations: json!([]),
            dimension_details: json!({}),
            triggered_by: None,
            created_at: Utc::now(),
            duration_ms: Some(1),
            source_types: vec!["apache".to_string(), "insider_threat".to_string()],
            source_types_complete: false,
        }
    }

    #[test]
    fn persisted_typed_partitions_are_filtered_and_ingestion_totals_recomputed() {
        let mut report = report(metrics_fixture());

        filter_report_for_viewer(&mut report, &scope(&["insider_threat"]));

        assert_eq!(
            report.metrics["ingestion"]["source_volumes"],
            json!([{
                "source_type": "apache",
                "count_24h": 10,
                "count_prior_24h": 7,
                "change_pct": 42.8
            }])
        );
        assert_eq!(report.metrics["ingestion"]["total_events_24h"], 10);
        assert_eq!(report.metrics["ingestion"]["total_events_prior_24h"], 7);
        assert_eq!(
            report.metrics["ingestion"]["silent_sources"],
            json!(["apache"])
        );
        assert_eq!(
            report.metrics["parsing"]["field_coverage"]
                .as_array()
                .expect("typed field coverage")
                .len(),
            1
        );
        assert!(report.metrics["parsing"]["high_ext_sources"]
            .as_array()
            .expect("typed ext usage")
            .is_empty());
        assert_eq!(
            report.metrics["enrichment"]["per_source_coverage"]
                .as_array()
                .expect("typed enrichment coverage")
                .len(),
            1
        );
        assert_eq!(
            report.metrics["enrichment"]["total_events_24h"], 13,
            "non-exact global fields remain for NAN-2089's fail-closed policy"
        );
    }

    #[test]
    fn restricted_viewer_gets_no_metrics_when_stored_contract_is_malformed() {
        let mut report = report(json!({
            "ingestion": {
                "source_volumes": [{
                    "source_type": "insider_threat",
                    "count_24h": 1
                }]
            }
        }));

        filter_report_for_viewer(&mut report, &scope(&["insider_threat"]));

        assert_eq!(report.metrics, json!({}));
    }

    #[test]
    fn unrestricted_viewer_keeps_legacy_metrics_byte_identical() {
        let legacy = json!({
            "arbitrary_legacy_shape": {
                "source_type": "insider_threat",
                "count_24h": 1
            }
        });
        let mut report = report(legacy.clone());

        filter_report_for_viewer(&mut report, &ScopeSet::unrestricted());

        assert_eq!(report.metrics, legacy);
    }
}
