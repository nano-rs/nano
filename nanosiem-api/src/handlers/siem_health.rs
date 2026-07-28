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
use nanosiem_core::auth::{ArtifactScope, ScopeSet};
use nanosiem_core::siem_health::{SiemHealthReport, SiemHealthReportSummary, SiemHealthRepository};

/// NAN-1801 / NAN-2153 / NAN-2222: typed defense-in-depth for a health report
/// leaving the API.
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
/// The unattributable narrative (summary, recommendations, dimension details)
/// is withheld unless the stored provenance proves the report disjoint from the
/// deny set — NAN-2089's classifier, applied to the part of the artifact it
/// truthfully describes rather than to the row's existence.
///
/// The repository applies exactly this reduction already; running it again here
/// is idempotent and keeps the guarantee at the HTTP boundary where the DTO is
/// serialized, so a future repository path cannot ship an unreduced report.
///
/// An EMPTY deny set returns immediately — the report stays byte-identical for
/// unrestricted viewers. Comparison is lowercase-on-both-sides. A restricted
/// viewer gets no metrics if the stored JSON cannot be deserialized into the
/// typed partition contract.
///
/// NAN-2219: this takes the scope's ROW-FILTER half, explicitly — NOT
/// `ArtifactScope::from_scope`, which reads the derived-artifact half. Both
/// halves of what this reduction touches are per-source data: the pruned
/// partitions carry each source's exact event volume and coverage, and the
/// withheld narrative is free prose that can name any contributing source. A
/// reader without `audit:view` must get neither for `audit`, so the audit gate
/// has to be in the deny set here. See [`report_reduction_scope`].
fn filter_report_for_viewer(report: &mut SiemHealthReport, scope: &ScopeSet) {
    report.apply_artifact_scope(&report_reduction_scope(scope));
}

/// The scope that decides what a reader may see INSIDE a health report
/// (NAN-2222 reduction) — the caller's ROW-FILTER deny set (NAN-2219).
///
/// # Why the row half, when this builds an `ArtifactScope`
///
/// NAN-2219 split [`ScopeSet`] because NAN-2053/NAN-2137's fail-closed
/// whole-artifact gates were denying every non-Admin outright, on tenants with
/// no source scoping at all, over a `source_types_complete` column that ships
/// `DEFAULT FALSE` and was never backfilled. For SIEM health that symptom is
/// gone for a different and better reason: NAN-2222 deleted the row-existence
/// gate entirely, so no report is withheld from anyone. What survives is a
/// per-part REDUCTION of a report that is always delivered.
///
/// That reduction is per-source data end to end, so it belongs on the row half:
///
/// * the pruned partitions are keyed by `source_type` and carry that source's
///   exact 24h volume, field coverage and enrichment coverage — the shape
///   NAN-1801 closed on `/api/source-types`;
/// * the withheld narrative is unattributed free prose that can name a denied
///   source and quote its figures. NAN-2219's accepted disclosure covers
///   AGGREGATE audit-derived facts (a score computed over audit volume) and
///   explicitly does NOT extend to per-source audit counts — which is exactly
///   what a sentence like "audit ingestion fell 40%" would be.
///
/// So `audit` stays denied here for a caller without `audit:view`, and the
/// NAN-2219 split contributes nothing to this surface: it is
/// [`super::siem_health_suppressions`] — whose rows carry no source provenance
/// at all — where the split actually changes the answer.
fn report_reduction_scope(scope: &ScopeSet) -> ArtifactScope {
    ArtifactScope::from_denied(scope.deny_set())
}

/// List-view counterpart of [`filter_report_for_viewer`], for the same
/// defense-in-depth reason: the policy that decides whether a summary row keeps
/// its narrative is re-applied at the boundary that serializes it.
fn filter_summaries_for_viewer(summaries: &mut [SiemHealthReportSummary], scope: &ArtifactScope) {
    for summary in summaries.iter_mut() {
        summary.apply_artifact_scope(scope);
    }
}

/// One canonical conversion for JWT and API-key request paths.
///
/// Drives the LIST view, whose only scope-dependent decision is whether a
/// summary row keeps its narrative (NAN-2222 — rows are never dropped, so page
/// size and `total` cannot become an oracle). Same policy, same input, as the
/// detail path: [`report_reduction_scope`], i.e. the ROW-FILTER half. A summary
/// narrative can name a denied source exactly as the detail narrative can.
fn effective_artifact_scope(auth: &AuthContext) -> ArtifactScope {
    report_reduction_scope(&auth.effective_viewer_scope())
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
/// Returns a paginated list of health report summaries, ordered by most recent
/// first. No row is hidden — a source-restricted reader receives the same page
/// and `total` as an unrestricted one, with the narrative column withheld on
/// every row whose provenance is not provably disjoint from their deny set.
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
    let artifact_scope = effective_artifact_scope(&auth);

    let repo = SiemHealthRepository::new(state.pool.clone());
    let (mut reports, total) = repo
        .list_summaries_for_scope(limit, offset, &artifact_scope)
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    filter_summaries_for_viewer(&mut reports, &artifact_scope);

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
/// Requires the `settings:system` permission. Restricted viewers see the latest
/// report with their denied `source_type` partitions pruned; the AI narrative,
/// recommendations, and dimension details are withheld unless the stored
/// provenance proves the report disjoint from their deny set. A 404 therefore
/// means what it says: no report has ever been generated.
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
    let viewer_scope = auth.effective_viewer_scope();
    let artifact_scope = ArtifactScope::from_scope(&viewer_scope);
    let mut report = repo
        .get_latest_for_scope(&artifact_scope)
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?
        .ok_or_else(|| ApiError::NotFound("No health reports exist yet".to_string()))?;

    filter_report_for_viewer(&mut report, &viewer_scope);

    Ok(Json(report))
}

/// Get a specific SIEM health report by ID
///
/// Returns the full health report including metrics, recommendations,
/// and dimension details.
///
/// Requires the `settings:system` permission. A restricted viewer receives the
/// report with denied `source_type` partitions pruned and the unattributable
/// narrative withheld; 404 means the report id does not exist.
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
    let viewer_scope = auth.effective_viewer_scope();
    let artifact_scope = ArtifactScope::from_scope(&viewer_scope);
    let mut report = repo
        .get_by_id_for_scope(id, &artifact_scope)
        .await
        .map_err(|e| match e {
            nanosiem_core::siem_health::SiemHealthRepositoryError::NotFound(msg) => {
                ApiError::NotFound(msg)
            }
            other => ApiError::DatabaseError(other.to_string()),
        })?;

    filter_report_for_viewer(&mut report, &viewer_scope);

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
    use nanosiem_core::auth::api_key::ApiKeyInfo;
    use nanosiem_core::auth::permissions;
    use nanosiem_core::auth::token::{DEFAULT_TOKEN_AUDIENCE, DEFAULT_TOKEN_ISSUER};
    use nanosiem_core::auth::TokenClaims;
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

    fn jwt_auth(denied: &[&str]) -> AuthContext {
        let mut auth = AuthContext::from_jwt(TokenClaims {
            iss: DEFAULT_TOKEN_ISSUER.to_string(),
            aud: DEFAULT_TOKEN_AUDIENCE.to_string(),
            sub: Uuid::now_v7(),
            roles: Vec::new(),
            permissions: vec![
                permissions::SETTINGS_SYSTEM.to_string(),
                permissions::AUDIT_VIEW.to_string(),
            ],
            exp: i64::MAX,
            iat: 0,
            jti: Uuid::now_v7(),
            purpose: "access".to_string(),
        });
        auth.denied_sources = scope(denied);
        auth
    }

    fn api_key_auth(denied: &[&str]) -> AuthContext {
        let mut auth = AuthContext::from_api_key(&ApiKeyInfo {
            id: Uuid::now_v7(),
            name: "NAN-2089 parity".to_string(),
            permissions: vec![
                permissions::SETTINGS_SYSTEM.to_string(),
                permissions::AUDIT_VIEW.to_string(),
            ],
            user_id: Some(Uuid::now_v7()),
        });
        auth.denied_sources = scope(denied);
        auth
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

    /// The archetypal NAN-2222 victim: a monitoring credential holding
    /// `settings:system` and nothing else. Neither Editor nor ReadOnly holds
    /// `settings:system`, and no migration grants `audit:view` alongside it, so
    /// this is the shape of every custom role / API key built to poll /health.
    fn monitoring_auth() -> AuthContext {
        AuthContext::from_api_key(&ApiKeyInfo {
            id: Uuid::now_v7(),
            name: "health-check integration".to_string(),
            permissions: vec![permissions::SETTINGS_SYSTEM.to_string()],
            user_id: Some(Uuid::now_v7()),
        })
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
        // NAN-2222: this used to assert the fleet rollup stayed at 13. It is
        // `count()` over the same logs/window/predicate the ingestion group-by
        // sums, so `13 - 10` published insider_threat's exact 24h volume — the
        // one datum the pruning above exists to hide. It is now re-denominated
        // over the partitions that survived.
        assert_eq!(report.metrics["enrichment"]["total_events_24h"], 10);
        assert_eq!(
            report.metrics["enrichment"]["total_events_24h"],
            report.metrics["ingestion"]["total_events_24h"],
            "the two totals must not differ by the denied sources' volume"
        );
        // Ratios over a population the reader cannot see are still NAN-2089's:
        // they carry no denominator, so they are not invertible on their own.
        assert_eq!(report.metrics["enrichment"]["geoip_fill_pct"], 50.0);
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

    /// NAN-2222: a `settings:system` caller WITHOUT `audit:view` must receive a
    /// usable report.
    ///
    /// Its effective scope is `{audit}` (plus the unresolved sentinel), and
    /// every real deployment's health report lists `audit` among its source
    /// volumes — audit events are ordinary `source_type = 'audit'` rows in the
    /// logs table. Under the old gate that combination could never satisfy
    /// `source_types_complete AND NOT (source_types && deny)`, so this caller
    /// got `404 "No health reports exist yet"` forever and concluded the SIEM
    /// was healthy. It now gets the report: scores, status, and every partition
    /// it is entitled to.
    #[test]
    fn settings_system_without_audit_view_still_receives_the_report() {
        let auth = monitoring_auth();
        let viewer_scope = auth.effective_viewer_scope();

        // Precondition: this principal IS source-restricted. That is the state
        // the unsatisfiable gate keyed on.
        assert!(viewer_scope.deny_set().contains("audit"));
        assert!(!effective_artifact_scope(&auth).is_unrestricted());

        let mut report = report(json!({
            "ingestion": {
                "source_volumes": [
                    {"source_type": "apache", "count_24h": 10, "count_prior_24h": 7, "change_pct": 42.8},
                    {"source_type": "audit", "count_24h": 4, "count_prior_24h": 4, "change_pct": 0.0}
                ],
                "total_events_24h": 14,
                "total_events_prior_24h": 11,
                "silent_sources": [],
                "insert_integrity": serde_json::to_value(InsertIntegrityMetrics::default())
                    .expect("serialize default integrity metrics")
            },
            "parsing": {"field_coverage": [], "high_ext_sources": [], "lowercase_invariant_violations": []},
            "enrichment": {
                "total_events_24h": 14, "geoip_fill_pct": 0.0, "asn_fill_pct": 0.0,
                "ioc_hit_pct": 0.0, "identity_fill_pct": 0.0, "identity_fill_prior_pct": 0.0,
                "per_source_coverage": [], "providers": []
            },
            "detection": {
                "total_enabled_rules": 3, "total_matches_24h": 2, "rules_by_mode": [],
                "stale_rules": [], "noisy_rules": [], "alerts_24h_by_severity": []
            },
            "alerting": {
                "total_alerts_24h": 2, "total_alerts_prior_24h": 1, "by_status": [],
                "mean_mtta_minutes": null, "active_webhooks": 0, "webhook_deliveries_24h": 0,
                "webhook_success_pct": null, "active_routing_rules": 0
            },
            "collected_at": Utc::now()
        }));
        let report_id = report.id;

        filter_report_for_viewer(&mut report, &viewer_scope);

        // The report survives — this is the whole bug.
        assert_eq!(report.id, report_id);
        assert_eq!(report.overall_score, 75);
        assert_eq!(report.overall_status, "warning");
        assert_eq!(report.ingestion_score, 75);
        assert_eq!(report.alerting_score, Some(75));
        // …and stays useful: the partitions it may see are intact, with exact
        // totals recomputed over them.
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
        assert_eq!(report.metrics["alerting"]["total_alerts_24h"], 2);
    }

    /// The other half of the contract: restoring availability must not restore
    /// the leak. Every mention of a denied source — partitioned metric, silent
    /// source, AI narrative, recommendation, or dimension detail — must be gone
    /// from the serialized DTO.
    #[test]
    fn denied_source_data_is_absent_from_the_serialized_report() {
        let mut report = report(metrics_fixture());
        report.summary = "insider_threat volume fell 40% overnight".to_string();
        report.recommendations = json!([{
            "title": "Investigate insider_threat ingestion",
            "description": "insider_threat stopped reporting",
            "priority": "high"
        }]);
        report.dimension_details = json!({
            "ingestion": "insider_threat is the second largest source",
            "parsing": "insider_threat field coverage is 1%",
            "enrichment": "n/a",
            "detection": "n/a",
            "alerting": "n/a"
        });

        filter_report_for_viewer(&mut report, &scope(&["insider_threat"]));

        let serialized = serde_json::to_string(&report)
            .expect("serialize filtered report")
            .to_lowercase();
        assert!(
            !serialized.contains("insider_threat"),
            "denied source leaked into the response: {serialized}"
        );
        // The narrative is withheld rather than silently blanked, so the caller
        // can tell "nothing to report" from "not yours to read".
        assert_eq!(
            report.summary,
            nanosiem_core::siem_health::types::WITHHELD_NARRATIVE_NOTICE
        );
        assert_eq!(report.recommendations, json!([]));
        assert_eq!(report.dimension_details, json!({}));
        // Non-source-derived scores survive: withholding them would leave the
        // monitoring caller with nothing to poll.
        assert_eq!(report.overall_score, 75);
    }

    /// The list view applies the same narrative policy as the detail view, and
    /// — unlike the old SQL gate — never drops a row, so page size and `total`
    /// stay identical to what a SYSTEM caller sees.
    #[test]
    fn list_summaries_withhold_narrative_without_dropping_rows() {
        fn summary(source_types: &[&str], complete: bool) -> SiemHealthReportSummary {
            SiemHealthReportSummary {
                id: Uuid::now_v7(),
                overall_score: 75,
                overall_status: "warning".to_string(),
                ingestion_score: 75,
                parsing_score: 75,
                detection_score: 75,
                enrichment_score: Some(75),
                alerting_score: Some(75),
                summary: "insider_threat ingestion stalled".to_string(),
                triggered_by: None,
                created_at: Utc::now(),
                duration_ms: Some(1),
                source_types: source_types.iter().map(|s| s.to_string()).collect(),
                source_types_complete: complete,
            }
        }

        let mut rows = vec![
            summary(&["apache", "insider_threat"], true), // overlapping
            summary(&["apache"], false),                  // incomplete stamp
            summary(&[], false),                          // legacy row
            summary(&["apache"], true),                   // provably disjoint
        ];
        let ids: Vec<Uuid> = rows.iter().map(|row| row.id).collect();

        filter_summaries_for_viewer(
            &mut rows,
            &ArtifactScope::from_scope(&scope(&["insider_threat"])),
        );

        assert_eq!(rows.len(), 4, "no row may be dropped");
        assert_eq!(rows.iter().map(|row| row.id).collect::<Vec<_>>(), ids);
        for row in &rows[..3] {
            assert_eq!(
                row.summary,
                nanosiem_core::siem_health::types::WITHHELD_NARRATIVE_NOTICE
            );
            assert_eq!(row.overall_score, 75, "scores survive on every row");
        }
        assert_eq!(rows[3].summary, "insider_threat ingestion stalled");

        // Unrestricted readers are untouched.
        let mut unrestricted = vec![summary(&[], false)];
        filter_summaries_for_viewer(&mut unrestricted, &ArtifactScope::system());
        assert_eq!(unrestricted[0].summary, "insider_threat ingestion stalled");
    }

    /// A report whose provenance IS provably complete and disjoint keeps its
    /// narrative. Without this, the completeness bit would be decorative and
    /// NAN-2089's eventual attribution work would change nothing.
    #[test]
    fn provably_disjoint_complete_report_keeps_its_narrative() {
        let mut report = report(metrics_fixture());
        report.source_types = vec!["apache".to_string()];
        report.source_types_complete = true;
        report.summary = "apache ingestion is healthy".to_string();

        filter_report_for_viewer(&mut report, &scope(&["insider_threat"]));

        assert_eq!(report.summary, "apache ingestion is healthy");
        // Partition pruning still runs — the two policies are independent.
        assert_eq!(
            report.metrics["ingestion"]["silent_sources"],
            json!(["apache"])
        );
    }

    #[test]
    fn jwt_and_api_key_principals_use_the_same_report_artifact_scope() {
        for auth in [
            jwt_auth(&["insider_threat"]),
            api_key_auth(&["insider_threat"]),
        ] {
            let artifact_scope = effective_artifact_scope(&auth);
            assert!(!artifact_scope.is_unrestricted());
            assert!(artifact_scope.allows(&["apache".to_string()], true));
            assert!(!artifact_scope.allows(&["insider_threat".to_string()], true));
            assert!(!artifact_scope.allows(&["apache".to_string()], false));
        }

        for auth in [jwt_auth(&[]), api_key_auth(&[])] {
            assert!(effective_artifact_scope(&auth).is_unrestricted());
        }
    }

    /// NAN-2219: a principal with `settings:system` but no `audit:view` and no
    /// per-source grants restricting them — the archetypal monitoring
    /// credential from NAN-2222, and the population NAN-2219 is about.
    fn jwt_auth_without_audit_view(denied: &[&str]) -> AuthContext {
        let mut auth = AuthContext::from_jwt(TokenClaims {
            iss: DEFAULT_TOKEN_ISSUER.to_string(),
            aud: DEFAULT_TOKEN_AUDIENCE.to_string(),
            sub: Uuid::now_v7(),
            roles: Vec::new(),
            permissions: vec![permissions::SETTINGS_SYSTEM.to_string()],
            exp: i64::MAX,
            iat: 0,
            jti: Uuid::now_v7(),
            purpose: "access".to_string(),
        });
        auth.denied_sources = scope(denied);
        auth
    }

    /// NAN-2219 x NAN-2222: the report REDUCTION runs on the scope's
    /// ROW-FILTER half, so a reader without `audit:view` still loses every
    /// `audit` partition.
    ///
    /// NAN-2219 split `ScopeSet` so that `ArtifactScope::from_scope` reads the
    /// derived-artifact half (per-source RBAC only), which for this principal
    /// is EMPTY. `apply_artifact_scope` short-circuits on an unrestricted
    /// scope, so building this scope with `from_scope` would hand them the
    /// `audit` source's exact 24h volume and the unattributed narrative that
    /// can name it. `report_reduction_scope` therefore uses `from_denied(
    /// scope.deny_set())` — this test is what fails if someone "simplifies" it
    /// back to `from_scope`.
    ///
    /// The other half of NAN-2219's symptom on this surface — the report being
    /// withheld ENTIRELY from this caller — is fixed by NAN-2222 deleting the
    /// unsatisfiable row-existence gate, and is pinned by
    /// `settings_system_without_audit_view_still_receives_the_report` above.
    #[test]
    fn the_report_reduction_runs_on_the_row_filter_half_not_the_artifact_half() {
        let auth = jwt_auth_without_audit_view(&[]);
        let viewer_scope = auth.effective_viewer_scope();

        // The two halves genuinely disagree for this principal — otherwise
        // this test would pass for the wrong reason.
        assert!(viewer_scope.deny_set().contains("audit"));
        assert!(viewer_scope.artifact_deny_set().is_empty());
        assert!(
            ArtifactScope::from_scope(&viewer_scope).is_unrestricted(),
            "precondition: the artifact half alone would not restrict anything"
        );

        // The reduction scope — and the list-view scope built from it — must
        // still deny `audit`.
        assert!(!report_reduction_scope(&viewer_scope).is_unrestricted());
        assert!(!effective_artifact_scope(&auth).is_unrestricted());

        let mut metrics = metrics_fixture();
        metrics["ingestion"]["source_volumes"]
            .as_array_mut()
            .expect("source volumes")
            .push(json!({
                "source_type": "audit",
                "count_24h": 500,
                "count_prior_24h": 400,
                "change_pct": 25.0
            }));
        metrics["ingestion"]["total_events_24h"] = json!(612);
        let mut report = report(metrics);

        filter_report_for_viewer(&mut report, &viewer_scope);

        let volumes = report.metrics["ingestion"]["source_volumes"]
            .as_array()
            .expect("typed source volumes");
        assert!(
            !volumes
                .iter()
                .any(|entry| entry["source_type"] == json!("audit")),
            "a caller without audit:view must not see the audit source's event volume"
        );
        // apache survives; insider_threat is not denied for this principal;
        // the blank-source row fails closed.
        assert_eq!(volumes.len(), 2);
        assert_eq!(report.metrics["ingestion"]["total_events_24h"], 13);

        // The unattributed narrative can name a denied source, so it is
        // withheld for exactly the same reason.
        assert_eq!(
            report.summary,
            nanosiem_core::siem_health::types::WITHHELD_NARRATIVE_NOTICE
        );
    }

    /// A registry-configured `audit` restriction is a real per-source boundary
    /// and is denied in BOTH halves, so it survives regardless of which half a
    /// future edit picks here.
    #[test]
    fn registry_restricted_audit_is_denied_in_both_halves() {
        for auth in [
            jwt_auth(&["audit"]),
            jwt_auth_without_audit_view(&["audit"]),
        ] {
            let viewer_scope = auth.effective_viewer_scope();
            assert!(viewer_scope.deny_set().contains("audit"));
            assert!(viewer_scope.artifact_deny_set().contains("audit"));

            for artifact_scope in [
                effective_artifact_scope(&auth),
                ArtifactScope::from_scope(&viewer_scope),
            ] {
                assert!(!artifact_scope.is_unrestricted());
                assert!(!artifact_scope.allows(&["audit".to_string()], true));
            }
        }
    }
}
