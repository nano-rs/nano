// SPDX-License-Identifier: AGPL-3.0-or-later

//! Metric-monitor CRUD for the Observability console (NAN-1540).
//!
//! A metric monitor is a saved metrics-v2 query (`metric_name` + `agg` +
//! optional `group_by` + tag `filters`) plus a `comparator`/`threshold` and an
//! evaluation cadence. Definitions are PostgreSQL-backed
//! (`observability_metric_monitors`, migration 211); their breach *state* is
//! NOT stored — the panic-safe jobs runner ([`crate::bin::jobs`]) evaluates due
//! enabled monitors over the trailing `window_secs` window and raises through
//! the existing alert store on breach (mirrors the SLO definition store).
//!
//! Read endpoints require `search:view` (the console is search-adjacent);
//! mutations require `settings:system` (monitors are configuration).

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};

use crate::error::{ApiError, ErrorResponse};
use crate::middleware::{AuthContext, ensure_permission};
use crate::state::AppState;
use nanosiem_core::auth::permissions;
use nanosiem_core::observability::{
    MetricMonitor, MetricMonitorRepository, MetricMonitorRepositoryError, MonitorComparator,
    MonitorTagFilter,
};
use nanosiem_core::query::{MetricAgg, valid_tag_key};
use nanosiem_core::typeid::TypeIdParam;

const NAME_MAX_LEN: usize = 200;
const WINDOW_SECS_MAX: i32 = 86_400;
const EVAL_INTERVAL_MIN: i32 = 30;
const EVAL_INTERVAL_MAX: i32 = 3600;
const MAX_FILTERS: usize = 32;

/// Response for the metric-monitor list.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ListMetricMonitorsResponse {
    pub monitors: Vec<MetricMonitor>,
}

/// Request body for creating / updating a metric monitor.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct MetricMonitorRequest {
    /// Human label (e.g. "p95 checkout latency > 500ms").
    pub name: String,
    /// OTLP metric_name the monitor evaluates.
    pub metric_name: String,
    /// Aggregate: `avg`|`sum`|`min`|`max`|`count`|`rate`|`p50`|`p95`|`p99`.
    pub agg: String,
    /// Optional tag/attribute key to split into per-series evaluation.
    #[serde(default)]
    pub group_by: Option<String>,
    /// Tag filters ANDed over the metric's attributes/resource_attributes.
    #[serde(default)]
    pub filters: Vec<MonitorTagFilter>,
    /// Breach test (`gt`|`gte`|`lt`|`lte`).
    pub comparator: MonitorComparator,
    /// Threshold compared against the per-series aggregate.
    pub threshold: f64,
    /// Trailing window (seconds) the aggregate is computed over (1..=86400).
    pub window_secs: i32,
    /// Runner cadence in seconds (30..=3600).
    pub eval_interval_secs: i32,
    /// Whether the runner evaluates this monitor.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

/// Validated, normalized fields ready for the repository.
struct ValidatedMonitor {
    name: String,
    metric_name: String,
    agg: String,
    group_by: Option<String>,
    filters: Vec<MonitorTagFilter>,
}

impl MetricMonitorRequest {
    /// Validate + normalize. Aggregate is checked against the metrics-v2
    /// allowlist; `group_by` and every filter key against [`valid_tag_key`].
    fn validate(&self) -> Result<ValidatedMonitor, ApiError> {
        let name = self.name.trim().to_string();
        let metric_name = self.metric_name.trim().to_string();
        if name.is_empty() {
            return Err(ApiError::BadRequest("name must not be empty".to_string()));
        }
        if name.len() > NAME_MAX_LEN {
            return Err(ApiError::BadRequest(format!(
                "name exceeds {NAME_MAX_LEN} chars"
            )));
        }
        if metric_name.is_empty() {
            return Err(ApiError::BadRequest(
                "metric_name must not be empty".to_string(),
            ));
        }

        // Aggregate allowlist — canonicalize via MetricAgg::from_str.
        let agg = MetricAgg::from_str(&self.agg)
            .ok_or_else(|| ApiError::BadRequest(format!("unknown agg: {}", self.agg)))?
            .as_str()
            .to_string();

        // group_by: empty -> None; otherwise must be a valid tag key.
        let group_by = match self.group_by.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            None => None,
            Some(key) => {
                if !valid_tag_key(key) {
                    return Err(ApiError::BadRequest(format!(
                        "invalid group_by key: {key}"
                    )));
                }
                Some(key.to_string())
            }
        };

        if self.filters.len() > MAX_FILTERS {
            return Err(ApiError::BadRequest(format!(
                "at most {MAX_FILTERS} filters allowed"
            )));
        }
        let mut filters = Vec::with_capacity(self.filters.len());
        for f in &self.filters {
            if !valid_tag_key(&f.key) {
                return Err(ApiError::BadRequest(format!(
                    "invalid filter key: {}",
                    f.key
                )));
            }
            filters.push(MonitorTagFilter {
                key: f.key.clone(),
                value: f.value.clone(),
            });
        }

        if !self.threshold.is_finite() {
            return Err(ApiError::BadRequest(
                "threshold must be a finite number".to_string(),
            ));
        }
        if !(1..=WINDOW_SECS_MAX).contains(&self.window_secs) {
            return Err(ApiError::BadRequest(format!(
                "window_secs must be in 1..={WINDOW_SECS_MAX}"
            )));
        }
        if !(EVAL_INTERVAL_MIN..=EVAL_INTERVAL_MAX).contains(&self.eval_interval_secs) {
            return Err(ApiError::BadRequest(format!(
                "eval_interval_secs must be in {EVAL_INTERVAL_MIN}..={EVAL_INTERVAL_MAX}"
            )));
        }

        Ok(ValidatedMonitor {
            name,
            metric_name,
            agg,
            group_by,
            filters,
        })
    }
}

fn map_repo_err(e: MetricMonitorRepositoryError) -> ApiError {
    match e {
        MetricMonitorRepositoryError::NotFound(_) => {
            ApiError::NotFound("Metric monitor not found".to_string())
        }
        MetricMonitorRepositoryError::Invalid(msg) => ApiError::BadRequest(msg),
        MetricMonitorRepositoryError::DatabaseError(db) => ApiError::DatabaseError(db.to_string()),
    }
}

/// List all metric monitors.
#[utoipa::path(
    get,
    path = "/api/observability/metric-monitors",
    tag = "observability",
    responses(
        (status = 200, description = "Metric monitor definitions", body = ListMetricMonitorsResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn list_metric_monitors(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<ListMetricMonitorsResponse>, ApiError> {
    ensure_permission(&auth, permissions::SEARCH_VIEW)?;

    let repo = MetricMonitorRepository::new(state.pool.clone());
    let monitors = repo.list().await.map_err(map_repo_err)?;
    Ok(Json(ListMetricMonitorsResponse { monitors }))
}

/// Create a new metric monitor.
#[utoipa::path(
    post,
    path = "/api/observability/metric-monitors",
    tag = "observability",
    request_body = MetricMonitorRequest,
    responses(
        (status = 201, description = "Metric monitor created", body = MetricMonitor),
        (status = 400, description = "Invalid input", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn create_metric_monitor(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<MetricMonitorRequest>,
) -> Result<(StatusCode, Json<MetricMonitor>), ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;

    let v = req.validate()?;

    let repo = MetricMonitorRepository::new(state.pool.clone());

    // NAN-1544: tier-cap the number of metric monitors before insert.
    let tier_settings = nanosiem_core::TierSettings::new(state.pool.clone());
    let tier_limits = tier_settings.get_tier_limits().await?;
    if tier_limits.is_enforced() {
        let current = repo.list().await.map_err(map_repo_err)?.len() as u32;
        nanosiem_core::check_limit(
            "metric monitors",
            current,
            tier_limits.max_metric_monitors,
            tier_limits.tier,
            "Upgrade your plan for more metric monitors.",
        )?;
    }

    let monitor = repo
        .create(
            &v.name,
            &v.metric_name,
            &v.agg,
            v.group_by.as_deref(),
            &v.filters,
            req.comparator,
            req.threshold,
            req.window_secs,
            req.eval_interval_secs,
            req.enabled,
            Some(auth.user_id()),
        )
        .await
        .map_err(map_repo_err)?;

    Ok((StatusCode::CREATED, Json(monitor)))
}

/// Update an existing metric monitor.
#[utoipa::path(
    put,
    path = "/api/observability/metric-monitors/{id}",
    tag = "observability",
    params(("id" = String, Path, description = "Monitor typeid (mon_<base32>) or bare UUID")),
    request_body = MetricMonitorRequest,
    responses(
        (status = 200, description = "Metric monitor updated", body = MetricMonitor),
        (status = 400, description = "Invalid input", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
        (status = 404, description = "Monitor not found", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn update_metric_monitor(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
    Json(req): Json<MetricMonitorRequest>,
) -> Result<Json<MetricMonitor>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;

    let v = req.validate()?;

    let repo = MetricMonitorRepository::new(state.pool.clone());
    let monitor = repo
        .update(
            *id,
            &v.name,
            &v.metric_name,
            &v.agg,
            v.group_by.as_deref(),
            &v.filters,
            req.comparator,
            req.threshold,
            req.window_secs,
            req.eval_interval_secs,
            req.enabled,
        )
        .await
        .map_err(map_repo_err)?;

    Ok(Json(monitor))
}

/// Delete a metric monitor.
#[utoipa::path(
    delete,
    path = "/api/observability/metric-monitors/{id}",
    tag = "observability",
    params(("id" = String, Path, description = "Monitor typeid (mon_<base32>) or bare UUID")),
    responses(
        (status = 204, description = "Monitor deleted"),
        (status = 403, description = "Forbidden", body = ErrorResponse),
        (status = 404, description = "Monitor not found", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn delete_metric_monitor(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<StatusCode, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;

    let repo = MetricMonitorRepository::new(state.pool.clone());
    let deleted = repo.delete(*id).await.map_err(map_repo_err)?;
    if !deleted {
        return Err(ApiError::NotFound("Metric monitor not found".to_string()));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_metric_monitors,
        create_metric_monitor,
        update_metric_monitor,
        delete_metric_monitor
    ),
    components(schemas(
        ListMetricMonitorsResponse,
        MetricMonitorRequest,
        MetricMonitor,
        MonitorComparator,
        MonitorTagFilter
    ))
)]
pub struct ObservabilityMetricMonitorsApiDoc;
