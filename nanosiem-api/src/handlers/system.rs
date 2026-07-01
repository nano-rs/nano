// SPDX-License-Identifier: AGPL-3.0-or-later

//! System metrics and dashboard data handlers

use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};
use axum::{
    extract::{Query, State},
    Extension, Json,
};
use chrono::{DateTime, Duration, Utc};
use clickhouse::Client as ClickhouseClient;
use nanosiem_core::auth::permissions;
use nanosiem_core::models::detection_rule::RuleMode;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use tokio::time::{timeout, Duration as TokioDuration};
use utoipa::{IntoParams, ToSchema};

/// Default timeout for dashboard ClickHouse queries (60 seconds)
const DASHBOARD_QUERY_TIMEOUT_SECS: u64 = 60;

/// Query parameters for system metrics
#[derive(Debug, Deserialize, IntoParams)]
pub struct SystemMetricsQuery {
    /// Number of hours to look back (default: 24)
    pub hours: Option<i32>,
}

/// System activity data point
#[derive(Debug, Serialize, ToSchema)]
pub struct ActivityPoint {
    pub time: String,
    pub event_count: i64,
    pub alert_count: i64,
}

/// System overview metrics
#[derive(Debug, Serialize, ToSchema)]
pub struct SystemOverview {
    /// Total events in the last 24 hours
    pub events_24h: i64,
    /// Total events in the last hour
    pub events_1h: i64,
    /// Event volume trend (percentage change from previous period)
    pub events_trend: f64,
    /// Total alerts in the last 24 hours
    pub alerts_24h: i64,
    /// Total alerts in the last hour
    pub alerts_1h: i64,
    /// Alert trend (percentage change from previous period)
    pub alerts_trend: f64,
    /// Critical alerts in the last 24 hours
    pub critical_alerts_24h: i64,
    /// Critical alert trend (percentage change from previous period)
    pub critical_alerts_trend: f64,
    /// Active detection rules count
    pub active_rules: i64,
    /// Total detection rules count
    pub total_rules: i64,
    /// Active rules trend (percentage change from previous period)
    pub active_rules_trend: f64,
    /// Activity timeline (hourly buckets)
    pub activity: Vec<ActivityPoint>,
}

/// Get system overview metrics for the dashboard
///
/// GET /api/system/overview
#[utoipa::path(
    get,
    path = "/api/system/overview",
    tag = "system",
    params(SystemMetricsQuery),
    responses(
        (status = 200, description = "System overview retrieved successfully", body = SystemOverview),
        (status = 403, description = "Missing permission: settings:view"),
    ),
    security(("api_key" = []))
)]
pub async fn get_system_overview(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(params): Query<SystemMetricsQuery>,
) -> Result<Json<SystemOverview>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_VIEW)?;

    let hours = params.hours.unwrap_or(24);
    let now = Utc::now();
    let start_time = now - Duration::hours(hours as i64);

    // Get event counts for current and previous periods
    let events_current = get_event_count(&state, start_time, now).await?;
    let events_previous = get_event_count(
        &state,
        start_time - Duration::hours(hours as i64),
        start_time,
    )
    .await?;

    // Get event counts for last hour
    let events_1h = get_event_count(&state, now - Duration::hours(1), now).await?;

    // Calculate trend
    let events_trend = if events_previous > 0 {
        ((events_current as f64 - events_previous as f64) / events_previous as f64) * 100.0
    } else if events_current > 0 {
        100.0
    } else {
        0.0
    };

    // Get alert counts
    let alerts_current = get_alert_count(&state, start_time, now).await?;
    let alerts_previous = get_alert_count(
        &state,
        start_time - Duration::hours(hours as i64),
        start_time,
    )
    .await?;
    let alerts_1h = get_alert_count(&state, now - Duration::hours(1), now).await?;

    let alerts_trend = if alerts_previous > 0 {
        ((alerts_current as f64 - alerts_previous as f64) / alerts_previous as f64) * 100.0
    } else if alerts_current > 0 {
        100.0
    } else {
        0.0
    };

    // Get critical alert counts
    let critical_alerts_current = get_critical_alert_count(&state, start_time, now).await?;
    let critical_alerts_previous = get_critical_alert_count(
        &state,
        start_time - Duration::hours(hours as i64),
        start_time,
    )
    .await?;

    let critical_alerts_trend = if critical_alerts_previous > 0 {
        ((critical_alerts_current as f64 - critical_alerts_previous as f64)
            / critical_alerts_previous as f64)
            * 100.0
    } else if critical_alerts_current > 0 {
        100.0
    } else {
        0.0
    };

    // Get detection rule counts (current and previous for trend)
    let detections = state.detection_service.list_rules().await?;
    let active_rules_current = detections
        .iter()
        .filter(|r| r.mode != RuleMode::Staging && r.mode != RuleMode::Paused)
        .count() as i64;
    let total_rules = detections.len() as i64;

    // For active rules trend, we'll compare against the same time yesterday
    // This is a simple approach - in a real system you might want to track rule changes over time
    let active_rules_previous =
        get_active_rules_count_at_time(&state, start_time - Duration::hours(hours as i64)).await?;

    let active_rules_trend = if active_rules_previous > 0 {
        ((active_rules_current as f64 - active_rules_previous as f64)
            / active_rules_previous as f64)
            * 100.0
    } else if active_rules_current > 0 {
        100.0
    } else {
        0.0
    };

    // Get activity timeline (hourly buckets for the last 24 hours)
    let activity = get_activity_timeline(&state, now - Duration::hours(24), now).await?;

    tracing::debug!(
        events_24h = events_current,
        activity_points = activity.len(),
        "System overview metrics"
    );

    Ok(Json(SystemOverview {
        events_24h: events_current,
        events_1h,
        events_trend,
        alerts_24h: alerts_current,
        alerts_1h,
        alerts_trend,
        critical_alerts_24h: critical_alerts_current,
        critical_alerts_trend,
        active_rules: active_rules_current,
        total_rules,
        active_rules_trend,
        activity,
    }))
}

/// Get event count for a time range
async fn get_event_count(
    state: &AppState,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<i64, ApiError> {
    get_event_count_clickhouse(state.dual_pool.clickhouse(), start, end).await
}

/// Get event count from ClickHouse using system.parts for fast approximate counts
///
/// Uses partition-level row counts from system.parts instead of scanning the logs table.
/// This is nearly instant regardless of data volume. For 24h counts, we include
/// today's and yesterday's partitions which slightly over-counts but is close enough
/// for dashboard metrics.
async fn get_event_count_clickhouse(
    client: &ClickhouseClient,
    start: DateTime<Utc>,
    _end: DateTime<Utc>,
) -> Result<i64, ApiError> {
    // Calculate partition boundaries (daily partitions as YYYYMMDD)
    let start_partition = start.format("%Y%m%d").to_string();

    // Query system.parts for fast row count - nearly instant regardless of volume.
    // NAN-1241: count the active ingested-events table (ocsf_logs under OCSF).
    let logs_table = nanosiem_core::schema::active_logs_table();
    let sql = format!(
        r#"
        SELECT sum(rows) as count
        FROM system.parts
        WHERE database = 'nanosiem'
          AND table = '{logs_table}'
          AND active
          AND partition >= ?
    "#
    );

    // Wrap with timeout to prevent hanging on ClickHouse issues
    let count: u64 = timeout(
        TokioDuration::from_secs(DASHBOARD_QUERY_TIMEOUT_SECS),
        client.query(&sql).bind(start_partition).fetch_one::<u64>(),
    )
    .await
    .map_err(|_| ApiError::Timeout("Dashboard log count query timed out".to_string()))?
    .unwrap_or(0); // Return 0 if no parts exist yet

    Ok(count as i64)
}

/// Get alert count for a time range
async fn get_alert_count(
    state: &AppState,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<i64, ApiError> {
    let sql = r#"
        SELECT COUNT(*) as count
        FROM alerts 
        WHERE created_at >= $1 AND created_at < $2
    "#;

    let row = sqlx::query(sql)
        .bind(start)
        .bind(end)
        .fetch_one(&state.pool)
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    let count: i64 = row.get("count");
    Ok(count)
}

/// Get critical alert count for a time range
async fn get_critical_alert_count(
    state: &AppState,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<i64, ApiError> {
    let sql = r#"
        SELECT COUNT(*) as count
        FROM alerts 
        WHERE created_at >= $1 AND created_at < $2 AND severity = 'critical'
    "#;

    let row = sqlx::query(sql)
        .bind(start)
        .bind(end)
        .fetch_one(&state.pool)
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    let count: i64 = row.get("count");
    Ok(count)
}

/// Get active rules count at a specific time (simplified - just returns current count)
/// In a real system, you'd track rule state changes over time
async fn get_active_rules_count_at_time(
    state: &AppState,
    _time: DateTime<Utc>,
) -> Result<i64, ApiError> {
    // Simplified: just return current active rules count
    // In production, you'd want to track rule enable/disable events over time
    let detections = state
        .detection_service
        .list_rules()
        .await
        .map_err(|e| ApiError::InternalError(e.to_string()))?;
    let active_count = detections
        .iter()
        .filter(|r| r.mode != RuleMode::Staging && r.mode != RuleMode::Paused)
        .count() as i64;
    Ok(active_count)
}
async fn get_activity_timeline(
    state: &AppState,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<Vec<ActivityPoint>, ApiError> {
    // Read from the per-source 5-minute rollup (NAN-736). Replaces an
    // un-scoped `count(*) * 10 SAMPLE 0.1 FROM logs` per page load with a
    // fixed-cost rollup read. The dashboard timeline is always a recent window
    // (24h max for the dashboard call site), well within the rollup's 7-day TTL.
    let window_hours = (end - start).num_hours().max(1);
    let points = timeout(
        TokioDuration::from_secs(DASHBOARD_QUERY_TIMEOUT_SECS),
        state
            .log_telemetry_service
            .buckets_all(window_hours, nanosiem_core::LogTelemetryBucketSize::Hour),
    )
    .await
    .map_err(|_| {
        ApiError::Timeout("Dashboard activity timeline query timed out".to_string())
    })?
    .map_err(|e| ApiError::InternalError(e.to_string()))?;

    Ok(points
        .into_iter()
        .map(|p| ActivityPoint {
            time: p.bucket_start.to_rfc3339(),
            event_count: p.events as i64,
            alert_count: 0,
        })
        .collect())
}

/// OpenAPI documentation for system endpoints
/// System configuration (deployment mode, feature locks)
#[derive(Debug, Serialize, ToSchema)]
pub struct SystemConfig {
    pub deployment_mode: String,
    pub settings_editable: bool,
    pub api_keys_editable: bool,
    pub ai_providers_editable: bool,
    /// True when this install runs air-gapped (no outbound internet, `AIRGAP_MODE`).
    /// The marketplace UI uses this to badge connectivity-required items, hide
    /// egress actions (live sync / add-repository), and promote import-from-file.
    pub air_gap: bool,
}

/// Get system configuration including deployment mode
#[utoipa::path(
    get,
    path = "/api/system/config",
    tag = "system",
    responses(
        (status = 200, description = "System configuration", body = SystemConfig),
        (status = 403, description = "Missing permission: settings:view"),
    ),
    security(("api_key" = []))
)]
pub async fn get_system_config(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<SystemConfig>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_VIEW)?;

    let is_managed = state.config.deployment_mode.is_managed();

    // Derive api_keys_editable from tier limits, not deployment mode. As of
    // NAN-1472 all tiers grant Full API access, so this is effectively always
    // true for enforced tiers; kept tier-driven in case gating ever returns.
    // Fall back to true if tier lookup fails (fail open).
    let api_keys_editable = match nanosiem_core::TierSettings::new(state.pool.clone())
        .get_tier_limits()
        .await
    {
        Ok(limits) if limits.is_enforced() => {
            limits.api_access == nanosiem_core::ApiAccessLevel::Full
        }
        _ => true,
    };

    Ok(Json(SystemConfig {
        deployment_mode: if is_managed {
            "managed".to_string()
        } else {
            "self-hosted".to_string()
        },
        settings_editable: !is_managed,
        api_keys_editable,
        ai_providers_editable: !is_managed,
        air_gap: state.config.airgap,
    }))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_system_overview, get_system_config),
    components(schemas(ActivityPoint, SystemOverview, SystemConfig))
)]
pub struct SystemApiDoc;
