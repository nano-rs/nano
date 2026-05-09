// SPDX-License-Identifier: AGPL-3.0-or-later

//! Detection statistics, trigger, matches, and realtime reload

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, REALTIME_RULES_RELOADED, RULE_TRIGGERED,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::typeid::TypeIdParam;
use uuid::Uuid;

use super::types::*;
use super::AuditExt;
use crate::middleware::{check_permission, AuthContext};
use crate::{
    error::{ApiError, ErrorResponse},
    state::AppState,
};

/// Manually trigger a detection rule to run now
#[utoipa::path(
    post,
    path = "/api/rules/{id}/trigger",
    tag = "detections",
    params(
        ("id" = String, Path, description = "Detection rule ID")
    ),
    responses(
        (status = 200, description = "Rule triggered successfully", body = inline(Object)),
        (status = 403, description = "Missing permission: detections:promote", body = ErrorResponse),
        (status = 404, description = "Rule not found", body = ErrorResponse),
        (status = 500, description = "Scheduler not running or failed to trigger", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn trigger_detection(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_permission(&auth, permissions::DETECTIONS_PROMOTE)
        .map_err(|_| ApiError::Forbidden("Missing permission: detections:promote".to_string()))?;

    let rule = state.detection_service.get_rule(*id).await?;

    // Calculate lookback window
    let end = chrono::Utc::now();
    let lookback_minutes = rule.lookback_minutes.map(|m| m as i64).unwrap_or(15);
    let start = end - chrono::Duration::minutes(lookback_minutes);
    let time_range = nanosiem_core::search::TimeRangeInput::new(start, end);

    state
        .detection_service
        .execute_rule(&rule, Some(time_range))
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to trigger rule: {}", e)))?;

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::Detection, RULE_TRIGGERED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("detection_rule", Some(*id), Some(rule.name.clone()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(serde_json::json!({"triggered": true, "rule_id": *id})))
}

/// Get daily stats for all detection rules (for sparkline charts)
#[utoipa::path(
    get,
    path = "/api/rules/stats",
    tag = "detections",
    params(StatsQuery),
    responses(
        (status = 200, description = "Daily stats for all rules", body = inline(Object)),
        (status = 403, description = "Missing permission: detections:view", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_detection_stats(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(params): Query<StatsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_permission(&auth, permissions::DETECTIONS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: detections:view".to_string()))?;

    let days = params.days.unwrap_or(28);
    let stats = state.detection_service.get_all_daily_stats(days).await?;

    // Convert to JSON-friendly format
    let result: std::collections::HashMap<String, Vec<serde_json::Value>> = stats
        .into_iter()
        .map(|(rule_id, daily_stats)| {
            let stats_json: Vec<serde_json::Value> = daily_stats
                .into_iter()
                .map(|s| {
                    serde_json::json!({
                        "date": s.date.to_string(),
                        "match_count": s.match_count,
                        "alert_count": s.alert_count,
                    })
                })
                .collect();
            (nanosiem_core::typeid::encode("rule", &rule_id), stats_json)
        })
        .collect();

    Ok(Json(serde_json::json!(result)))
}

/// Get today's match counts for all detection rules
/// Returns the actual match counts from when rules were executed (from daily_stats table)
/// This shows real detection activity, not arbitrary query results
#[utoipa::path(
    get,
    path = "/api/rules/today-counts",
    tag = "detections",
    responses(
        (status = 200, description = "Today's match counts per rule", body = inline(HashMap<String, i64>)),
        (status = 403, description = "Missing permission: detections:view", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_today_counts(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<std::collections::HashMap<String, i64>>, ApiError> {
    check_permission(&auth, permissions::DETECTIONS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: detections:view".to_string()))?;

    use chrono::Utc;

    // Get today's date
    let today = Utc::now().date_naive();

    // Query the daily_stats table for today's actual match counts
    // This shows what the detection system actually detected, not arbitrary query results
    let rows = sqlx::query_as::<_, (uuid::Uuid, i64)>(
        r#"
        SELECT rule_id, match_count
        FROM detection_daily_stats
        WHERE date = $1
        "#,
    )
    .bind(today)
    .fetch_all(&state.pool)
    .await?;

    let mut counts: std::collections::HashMap<String, i64> = std::collections::HashMap::new();

    for (rule_id, match_count) in rows {
        counts.insert(nanosiem_core::typeid::encode("rule", &rule_id), match_count);
    }

    Ok(Json(counts))
}

/// Get actual detection matches for a rule
///
/// Returns matches that were stored when the rule was actively running,
/// NOT results from re-running the query against historical data.
///
/// This shows what ACTUALLY matched when the rule was live/alerting.
/// Works for all rule modes (live, alerting) since matches are stored separately.
#[utoipa::path(
    get,
    path = "/api/rules/{id}/matches",
    tag = "detections",
    params(
        ("id" = String, Path, description = "Detection rule ID"),
        DetectionMatchesQuery
    ),
    responses(
        (status = 200, description = "Detection matches with pagination", body = DetectionMatchesResponse),
        (status = 403, description = "Missing permission: detections:view", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_detection_matches(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
    Query(query): Query<DetectionMatchesQuery>,
) -> Result<Json<DetectionMatchesResponse>, ApiError> {
    check_permission(&auth, permissions::DETECTIONS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: detections:view".to_string()))?;

    // Build the base query from detection_matches table.
    // LEFT JOIN match_reviews so the UI can show a "reviewed" chip without an
    // extra round-trip per row (NAN-494).
    let mut sql = String::from(
        r#"
        SELECT
            dm.id,
            dm.detected_at,
            dm.severity,
            'open' as status,
            dm.matched_events,
            mr.reviewed_at
        FROM detection_matches dm
        LEFT JOIN match_reviews mr ON mr.match_id = dm.id
        WHERE dm.rule_id = $1
        "#,
    );

    let mut param_count = 1;

    // Add time filters if provided
    if query.start_time.is_some() {
        param_count += 1;
        sql.push_str(&format!(" AND dm.detected_at >= ${}", param_count));
    }

    if query.end_time.is_some() {
        param_count += 1;
        sql.push_str(&format!(" AND dm.detected_at <= ${}", param_count));
    }

    // Order by most recent first
    sql.push_str(" ORDER BY dm.detected_at DESC");

    // Add pagination
    param_count += 1;
    sql.push_str(&format!(" LIMIT ${}", param_count));
    param_count += 1;
    sql.push_str(&format!(" OFFSET ${}", param_count));

    // Build the query
    let mut query_builder = sqlx::query_as::<
        _,
        (
            Uuid,
            chrono::DateTime<chrono::Utc>,
            String,
            String,
            serde_json::Value,
            Option<chrono::DateTime<chrono::Utc>>,
        ),
    >(&sql)
    .bind(*id);

    if let Some(start) = query.start_time {
        query_builder = query_builder.bind(start);
    }

    if let Some(end) = query.end_time {
        query_builder = query_builder.bind(end);
    }

    query_builder = query_builder.bind(query.limit).bind(query.offset);

    // Execute the query
    let rows = query_builder.fetch_all(&state.pool).await?;

    // Get total count
    let mut count_sql = String::from("SELECT COUNT(*) FROM detection_matches WHERE rule_id = $1");

    let mut count_param = 1;
    if query.start_time.is_some() {
        count_param += 1;
        count_sql.push_str(&format!(" AND detected_at >= ${}", count_param));
    }

    if query.end_time.is_some() {
        count_param += 1;
        count_sql.push_str(&format!(" AND detected_at <= ${}", count_param));
    }

    let mut count_query = sqlx::query_scalar::<_, i64>(&count_sql).bind(*id);

    if let Some(start) = query.start_time {
        count_query = count_query.bind(start);
    }

    if let Some(end) = query.end_time {
        count_query = count_query.bind(end);
    }

    let total = count_query.fetch_one(&state.pool).await?;

    // Convert rows to response format
    let matches: Vec<DetectionMatch> = rows
        .into_iter()
        .map(
            |(match_id, detected_at, severity, status, matched_events, reviewed_at)| {
                let events = if let serde_json::Value::Array(arr) = matched_events {
                    arr
                } else {
                    vec![]
                };

                DetectionMatch {
                    id: match_id,
                    detected_at,
                    severity,
                    status,
                    event_count: events.len() as i32,
                    events,
                    reviewed: Some(reviewed_at.is_some()),
                    reviewed_at,
                }
            },
        )
        .collect();

    Ok(Json(DetectionMatchesResponse { total, matches }))
}

/// Reload all detection rules in the real-time evaluator
/// This is useful after bulk imports or if the cache gets out of sync
#[utoipa::path(
    post,
    path = "/api/rules/reload-realtime",
    tag = "detections",
    responses(
        (status = 200, description = "Rules reloaded successfully", body = inline(Object)),
        (status = 403, description = "Missing permission: detections:edit", body = ErrorResponse),
        (status = 500, description = "Failed to reload rules", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn reload_realtime_rules(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_permission(&auth, permissions::DETECTIONS_EDIT)
        .map_err(|_| ApiError::Forbidden("Missing permission: detections:edit".to_string()))?;

    state
        .realtime_evaluator
        .load_rules()
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to reload rules: {}", e)))?;

    let count = state.realtime_evaluator.rule_count().await;
    tracing::info!("Reloaded {} rules into real-time evaluator", count);

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::Detection, REALTIME_RULES_RELOADED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .client_context(&client)
            .details(serde_json::json!({
                "rules_loaded": count,
            }))
            .build(),
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "rules_loaded": count
    })))
}
